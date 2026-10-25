//go:build integration

package accountstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plystra/authn/passwordhash"
	"github.com/plystra/data/database"
	"github.com/plystra/data/declaration"
	"github.com/plystra/data/postgres"
	compiler "github.com/plystra/data/postgres/compiler"
	"github.com/plystra/kernel/configuration"
)

// This test executes Data compiler artifacts through the real public Resource.
// It supplies no SQL, raw connection, pool, Tx or handwritten account provider.
// Use only a disposable database; migrations and test records are retained.
func TestAccountsPostgresAtomicRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resolver, err := configuration.NewResolver(configuration.ResolverOptions{MaximumValueBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := configuration.NewEnvironmentReference("AUTHN_ACCOUNTSTORE_TEST_DATABASE_URL")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := resolver.Resolve(ctx, reference)
	if err != nil {
		t.Fatal("disposable AUTHN_ACCOUNTSTORE_TEST_DATABASE_URL is required")
	}
	provider, err := postgres.New(postgres.Config{URL: secret, MaxConnections: 4, HealthTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := provider.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	model := modelFor(t)
	members := []compiler.SchemaMember{schemaMember(model)}
	const identity = "data/f1ea98fb38bf"
	migrations, err := compiler.CompileMigrations(members, identity, compiler.MigrationHistory{})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := provider.MigrationPlan(ctx, identity, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ApplyMigrations(ctx, identity, approval.PlanDigest, migrations); err != nil {
		t.Fatal(err)
	}
	after, err := provider.MigrationPlan(ctx, identity, migrations)
	if err != nil || len(after.Pending) != 0 || len(after.Applied) != 1 {
		t.Fatalf("migration did not converge: %v", err)
	}
	artifacts, err := compiler.CompilePlans(members)
	if err != nil {
		t.Fatal(err)
	}
	template := artifacts[0].Plan
	counts := accountCounts(t, ctx, provider, model)

	hasher, err := passwordhash.New(passwordhash.Options{})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("public integration test password; never a deployment secret")
	phc, err := hasher.Hash(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.ToLower(rand.Text())
	email := prefix + "+tag@example.test"
	inputs := func(suffix, address string) map[string]database.Argument {
		return map[string]database.Argument{
			"account-id":       database.StringArgument(prefix + "-account-" + suffix),
			"operation-id":     database.StringArgument(prefix + "-operation-" + suffix),
			"normalized-email": database.StringArgument(address),
			"password-phc":     database.StringArgument(phc),
			"request-digest":   database.BytesArgument(bytes.Repeat([]byte{8}, 32)),
			"now-unix":         database.Int64Argument(time.Now().Unix()),
		}
	}
	execute := func(plan database.Plan, request map[string]database.Argument) (database.Result, error) {
		plan.Inputs = request
		return provider.Exec(ctx, plan)
	}
	first := inputs("first", email)
	result, err := execute(template, first)
	if err != nil || len(result.Statements) != 5 {
		t.Fatalf("registration did not commit: %v", err)
	}
	assertCountDelta(t, accountCounts(t, ctx, provider, model), counts, 1)
	rows := accountQuery(t, ctx, provider, model, "find-registration", first["operation-id"])
	if len(rows) != 1 || rows[0][2].String != "pending" || rows[0][3].String != "pending-provisioning" || rows[0][4].Int64 != 1 || !bytes.Equal(rows[0][5].Bytes, first["request-digest"].Bytes) {
		t.Fatal("reconciliation read lost safe state or operation binding")
	}
	rows = accountQuery(t, ctx, provider, model, "password-for-email", database.StringArgument(email))
	if len(rows) != 1 || rows[0][4].Bool || rows[0][6].Int64 != 1 {
		t.Fatal("password lookup lost unverified-contact or credential revision facts")
	}
	match, err := hasher.Verify(ctx, password, rows[0][5].String)
	if err != nil || !match.Match {
		t.Fatal("stored PHC does not verify")
	}

	// A duplicate canonical contact fails after the account insert, rolling it
	// back along with every later required record. No ON CONFLICT success path.
	duplicate := inputs("duplicate", email)
	result, err = execute(template, duplicate)
	if !errors.Is(err, database.ErrConflict) || len(result.Statements) != 0 {
		t.Fatal("duplicate email did not reject the complete plan")
	}
	if len(accountQuery(t, ctx, provider, model, "find-registration", duplicate["operation-id"])) != 0 {
		t.Fatal("contact conflict left an orphan account")
	}
	result, err = execute(template, first)
	if !errors.Is(err, database.ErrConflict) || len(result.Statements) != 0 {
		t.Fatal("operation replay silently succeeded")
	}
	assertCountDelta(t, accountCounts(t, ctx, provider, model), counts, 1)

	// Force the last assertion to fail after all five inserts have executed.
	// This is a compiler/runtime failure probe, not a second product plan.
	broken := template
	broken.Statements = append([]database.Statement(nil), template.Statements...)
	broken.Statements[4].Affected = database.ExactAffectedRows(2)
	failed := inputs("rollback", prefix+"-rollback@example.test")
	result, err = execute(broken, failed)
	if !errors.Is(err, database.ErrBackend) || len(result.Statements) != 0 {
		t.Fatal("required outbox assertion did not roll back")
	}
	assertCountDelta(t, accountCounts(t, ctx, provider, model), counts, 1)
	if len(accountQuery(t, ctx, provider, model, "find-registration", failed["operation-id"])) != 0 {
		t.Fatal("failed outbox left a registration")
	}

	// Two independent operations race for exactly the same canonical email.
	start := make(chan struct{})
	type outcome struct {
		result database.Result
		err    error
	}
	outcomes := make(chan outcome, 2)
	for _, suffix := range []string{"race-a", "race-b"} {
		go func() {
			<-start
			result, err := execute(template, inputs(suffix, prefix+"-race@example.test"))
			outcomes <- outcome{result, err}
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		outcome := <-outcomes
		if outcome.err == nil {
			successes++
			if len(outcome.result.Statements) != 5 {
				t.Fatal("partial race success")
			}
		} else if (!errors.Is(outcome.err, database.ErrConflict) && !errors.Is(outcome.err, database.ErrConcurrent)) || len(outcome.result.Statements) != 0 {
			t.Fatal("unexpected concurrent result")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent unique winners = %d", successes)
	}
	assertCountDelta(t, accountCounts(t, ctx, provider, model), counts, 2)

	cancelled, stop := context.WithCancel(ctx)
	stop()
	plan := template
	plan.Inputs = inputs("cancelled", prefix+"-cancelled@example.test")
	if result, err := provider.Exec(cancelled, plan); err == nil || len(result.Statements) != 0 {
		t.Fatal("cancelled plan published a result")
	}
	assertCountDelta(t, accountCounts(t, ctx, provider, model), counts, 2)
}

func accountCounts(t *testing.T, ctx context.Context, resource database.Resource, model declaration.Model) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	for _, table := range model.Tables {
		probe := model
		probe.Queries = append(append([]declaration.Query(nil), model.Queries...), declaration.Query{
			ID: "count-probe", Operation: declaration.OperationSelect, Table: declaration.Ref{Symbol: table.ID},
			Projection: []declaration.Projection{{Aggregate: declaration.AggregateCount, Alias: "total"}},
			Results:    []declaration.ResultField{{ID: "total", Source: "total", Type: declaration.TypeInt64}},
		})
		rows := accountQuery(t, ctx, resource, probe, "count-probe")
		if len(rows) != 1 {
			t.Fatal("count probe cardinality")
		}
		counts[table.ID] = rows[0][0].Int64
	}
	return counts
}

func assertCountDelta(t *testing.T, actual, before map[string]int64, delta int64) {
	t.Helper()
	for table, count := range before {
		if actual[table] != count+delta {
			t.Fatalf("table %s has unexpected committed row delta", table)
		}
	}
}

func accountQuery(t *testing.T, ctx context.Context, resource database.Resource, model declaration.Model, id string, args ...database.Argument) [][]database.Value {
	t.Helper()
	queries, err := compiler.CompileQueries([]compiler.SchemaMember{schemaMember(model)})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range queries {
		if !strings.HasSuffix(query.Path, "/"+id+".sql") {
			continue
		}
		columns := make([]database.ResultColumn, len(query.Results))
		for i, field := range query.Results {
			columns[i] = database.ResultColumn{Kind: database.ValueKind(field.Type), Nullable: field.Nullable}
		}
		result, err := resource.Exec(ctx, database.Plan{Statements: []database.Statement{{
			ID: "read", SQL: query.SQL, Args: args, ReturnsRows: true, Cardinality: database.CardinalityMany, ResultColumns: columns,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return result.Statements[0].Rows
	}
	t.Fatal("missing compiled read")
	return nil
}
