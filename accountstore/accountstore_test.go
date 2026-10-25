package accountstore_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/plystra/authn/accountstore"
	"github.com/plystra/data/analyzer"
	"github.com/plystra/data/database"
	"github.com/plystra/data/declaration"
	postgres "github.com/plystra/data/postgres/compiler"
)

const memberID = "authn.accounts/v1"

func TestAccountsDeclaration(t *testing.T) {
	model := modelFor(t)
	if model.Namespace != "authn_accounts" || len(model.Tables) != 5 || len(model.Plans) != 1 || len(model.Imports) != 0 {
		t.Fatal("unexpected storage ownership or inventory")
	}
	var unique bool
	for _, table := range model.Tables {
		for _, constraint := range table.Constraints {
			if table.ID == "normalized-contacts" && constraint.Kind == declaration.ConstraintUnique && reflect.DeepEqual(constraint.Columns, []string{"kind", "normalized-value"}) {
				unique = true
			}
		}
	}
	if !unique {
		t.Fatal("canonical contact uniqueness must be enforced by the database")
	}
	account := queryFor(t, model, "insert-account")
	for column, want := range map[string]declaration.Value{
		"status": declaration.String("pending"), "provisioning-state": declaration.String("pending-provisioning"), "subject-revision": declaration.Int64(1),
	} {
		found := false
		for _, assignment := range account.Assignments {
			if assignment.Column == column && assignment.Value == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("registration must fix safe initial %s", column)
		}
	}
	contact := queryFor(t, model, "insert-contact")
	var unverified bool
	for _, assignment := range contact.Assignments {
		if assignment.Column == "verified" && assignment.Value == declaration.Bool(false) {
			unverified = true
		}
	}
	if !unverified {
		t.Fatal("registration cannot prove contact ownership")
	}
	for _, query := range model.Queries {
		if query.Operation != declaration.OperationSelect && (query.Method != "" || query.Conflict.Action != "") {
			t.Fatal("no individual write or conflict-ignore may escape the atomic plan")
		}
	}
	digest, err := accountstore.Accounts.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			got, err := accountstore.Accounts.Digest()
			if err != nil || got != digest {
				t.Error("concurrent normalization changed the authored declaration")
			}
		})
	}
	wg.Wait()
}

func TestAccountsRegistrationPlan(t *testing.T) {
	members := []postgres.SchemaMember{schemaMember(modelFor(t))}
	artifacts, err := postgres.CompilePlans(members)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("compile plans: %v", err)
	}
	artifact := artifacts[0]
	if len(artifact.Plan.Statements) != 5 || artifact.Definition.Method != "StageRegistration" || len(artifact.Definition.Outputs) != 3 {
		t.Fatal("registration must retain one complete five-write plan")
	}
	if !errors.Is(artifact.Plan.Validate(), database.ErrInvalidPlan) {
		t.Fatal("unbound template must not execute with invented zero-valued inputs")
	}
	bound := artifact.Plan
	const hostile = "canary'; DROP TABLE accounts; --"
	bound.Inputs = map[string]database.Argument{
		"account-id": database.StringArgument(hostile), "operation-id": database.StringArgument("op-canary"),
		"normalized-email": database.StringArgument("alice+tag@example.test"), "password-phc": database.StringArgument("phc-canary"),
		"request-digest": database.BytesArgument(bytes.Repeat([]byte{7}, 32)), "now-unix": database.Int64Argument(1800000000),
	}
	if err := bound.Validate(); err != nil {
		t.Fatal(err)
	}
	for i, statement := range bound.Statements {
		if statement.Affected != database.ExactAffectedRows(1) || strings.Contains(statement.SQL, hostile) || strings.Contains(statement.SQL, "phc-canary") {
			t.Fatal("required write assertion or parameterization lost")
		}
		if i == 0 {
			if !statement.ReturnsRows || statement.Cardinality != database.CardinalityExactlyOne {
				t.Fatal("account result must be exactly one")
			}
		} else {
			if statement.ReturnsRows || statement.Cardinality != database.CardinalityNone {
				t.Fatal("nonreturning mutation cardinality changed")
			}
			var chained bool
			for _, argument := range statement.Args {
				if argument.FromResult != nil && argument.FromResult.Statement == "account" {
					chained = true
				}
			}
			if !chained {
				t.Fatal("dependent write must bind the actual inserted account/operation")
			}
		}
	}
	for _, test := range []struct {
		name   string
		change func(*declaration.Model)
	}{
		{"missing binding", func(m *declaration.Model) { m.Plans[0].Statements[1].Bindings = nil }},
		{"forward result", func(m *declaration.Model) { m.Plans[0].Statements[1].Bindings[0].FromStatement = "outbox" }},
		{"missing affected assertion", func(m *declaration.Model) { m.Plans[0].Statements[4].Affected = declaration.AffectedRows{} }},
		{"wrong parameter type", func(m *declaration.Model) { m.Plans[0].Parameters[0].Type = declaration.TypeBool }},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := modelFor(t)
			test.change(&model)
			if _, err := postgres.CompilePlans([]postgres.SchemaMember{schemaMember(model)}); err == nil {
				t.Fatal("unsafe declaration compiled")
			}
		})
	}
}

func TestAccountsMigrationSnapshot(t *testing.T) {
	model := modelFor(t)
	artifacts, err := postgres.CompileMigrations([]postgres.SchemaMember{schemaMember(model)}, "data/f1ea98fb38bf", postgres.MigrationHistory{})
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("compile migration: %v", err)
	}
	initial := artifacts[0]
	if strings.Count(initial.SQL, "CREATE TABLE ") != 5 || !strings.Contains(initial.SQL, `UNIQUE ("kind", "normalized-value")`) || initial.Definition.ArtifactDigest != postgres.DigestSQL(initial.SQL) {
		t.Fatal("migration must carry the complete initial schema and checksum")
	}
	if initial.Definition.LogicalDigest != "sha256:3033f5bfd2c97d87ae16ad0ebb1c07020479f8836a41fcc13b00596359e95db3" {
		t.Fatalf("frozen initial migration changed: %s", initial.Definition.LogicalDigest)
	}
	model.Namespace = "future_accounts"
	model.Tables[0].Columns = append(model.Tables[0].Columns, declaration.Column{ID: "later-field", Type: "string", Nullable: true})
	later, err := postgres.CompileMigrations([]postgres.SchemaMember{schemaMember(model)}, "data/f1ea98fb38bf", postgres.MigrationHistory{})
	if err != nil || !reflect.DeepEqual(later, artifacts) {
		t.Fatalf("historical snapshot followed today's schema: %v", err)
	}
	model.Migrations[0].Snapshot = nil
	if _, err := postgres.CompileMigrations([]postgres.SchemaMember{schemaMember(model)}, "data/f1ea98fb38bf", postgres.MigrationHistory{}); err == nil {
		t.Fatal("missing frozen snapshot accepted")
	}
}

func TestAccountsAnalyzer(t *testing.T) {
	snapshot := sourceSnapshot(t)
	result, err := analyzer.Analyze(snapshot)
	if err != nil || !result.Valid || len(result.Roots) != 1 {
		t.Fatalf("analyze actual sources: %v, %v", err, result.Diagnostics)
	}
	root := result.Roots[0]
	if root.MemberID != memberID || root.AccessID != "authn.accounts.access/v1" || len(root.QueryMethods) != 2 || len(root.PlanMethods) != 1 {
		t.Fatalf("wrong typed Resource mapping: %v", root)
	}
	if !reflect.DeepEqual(root.Model, modelFor(t)) {
		t.Fatal("static analysis and public declaration disagree")
	}
	providers, err := postgres.CompileAccessProviders([]postgres.SchemaMember{schemaMember(root.Model)}, result.Roots)
	if err != nil || len(providers) != 1 {
		t.Fatalf("generate complete typed access provider: %v", err)
	}
	if providers[0].Digest != postgres.DigestSQL(providers[0].Source) {
		t.Fatal("provider source digest does not bind the emitted bytes")
	}
	other, err := postgres.CompileAccessProviders([]postgres.SchemaMember{schemaMember(root.Model)}, result.Roots)
	if err != nil || !reflect.DeepEqual(providers, other) {
		t.Fatal("typed provider generation is not deterministic")
	}
	for _, test := range []struct{ name, from, to string }{
		{"method", "PasswordForEmail(context.Context", "RenamedPassword(context.Context"},
		{"field", "PasswordPHC", "UnexpectedPHC"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Copy source bytes, leaving the accepted snapshot and files untouched.
			changed := snapshot
			changed.Packages = append([]analyzer.Package(nil), snapshot.Packages...)
			for i, pkg := range changed.Packages {
				if pkg.ImportPath != "github.com/plystra/authn/accountstore" {
					continue
				}
				changed.Packages[i].Files = append([]analyzer.SourceFile(nil), pkg.Files...)
				for j, file := range pkg.Files {
					if strings.HasSuffix(file.Path, "/resource.go") {
						changed.Packages[i].Files[j].Content = bytes.ReplaceAll(file.Content, []byte(test.from), []byte(test.to))
					}
				}
			}
			bad, err := analyzer.Analyze(changed)
			if err != nil || bad.Valid {
				t.Fatalf("contract drift accepted: %v", err)
			}
			var mismatch bool
			for _, diagnostic := range bad.Diagnostics {
				if diagnostic.Code == analyzer.CodeAccessContractMismatch {
					mismatch = true
				}
			}
			if !mismatch {
				t.Fatalf("expected exact contract diagnostic: %v", bad.Diagnostics)
			}
		})
	}
}

func TestAccountsRedaction(t *testing.T) {
	const canary = "accountstore-private-canary"
	values := []any{
		accountstore.StageRegistrationRequest{AccountID: canary, OperationID: canary, NormalizedEmail: canary, PasswordPHC: canary, RequestDigest: []byte(canary)},
		accountstore.StageRegistrationResult{AccountID: canary, OperationID: canary},
		accountstore.FindRegistrationRequest{OperationID: canary},
		accountstore.Registration{AccountID: canary, OperationID: canary, RequestDigest: []byte(canary)},
		accountstore.PasswordForEmailRequest{NormalizedEmail: canary},
		accountstore.PasswordRecord{AccountID: canary, PasswordPHC: canary},
	}
	for _, value := range values {
		pointer := reflect.New(reflect.TypeOf(value))
		pointer.Elem().Set(reflect.ValueOf(value))
		for _, candidate := range []any{value, pointer.Interface()} {
			var outputs []string
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
				outputs = append(outputs, fmt.Sprintf(verb, candidate))
			}
			encoded, err := json.Marshal(struct{ Value any }{candidate})
			if err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, string(encoded))
			encoded, err = candidate.(encoding.TextMarshaler).MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, string(encoded))
			var log bytes.Buffer
			slog.New(slog.NewJSONHandler(&log, nil)).Info("storage", "value", candidate)
			outputs = append(outputs, log.String())
			for _, output := range outputs {
				if strings.Contains(output, canary) || !strings.Contains(output, "REDACTED") {
					t.Fatalf("storage value escaped redaction: %s", output)
				}
			}
		}
	}
}

func modelFor(t *testing.T) declaration.Model {
	t.Helper()
	model, err := accountstore.Accounts.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func schemaMember(model declaration.Model) postgres.SchemaMember {
	return postgres.SchemaMember{MemberID: memberID, Resource: "database.authn", Model: model}
}

func queryFor(t *testing.T, model declaration.Model, id string) declaration.Query {
	t.Helper()
	for _, query := range model.Queries {
		if query.ID == id {
			return query
		}
	}
	t.Fatalf("missing query %s", id)
	return declaration.Query{}
}

// Use actual pinned module sources and the selected Go toolchain's exports.
// No handwritten declaration types, Resource facsimile or fake backend is used.
func sourceSnapshot(t *testing.T) analyzer.Snapshot {
	t.Helper()
	command := exec.Command("go", "list", "-deps", "-export", "-json", ".")
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list source snapshot: %v", err)
	}
	snapshot := analyzer.Snapshot{Resources: []analyzer.ResourceContract{{ImportPath: "github.com/plystra/authn/accountstore", TypeName: "Resource", ID: "authn.accounts.access/v1"}}}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg struct {
			ImportPath, Dir, Export string
			Standard                bool
			GoFiles                 []string
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if pkg.Standard {
			if pkg.Export != "" {
				content, err := os.ReadFile(pkg.Export)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.StandardExports = append(snapshot.StandardExports, analyzer.StandardExport{ImportPath: pkg.ImportPath, Content: content})
			}
			continue
		}
		item := analyzer.Package{ImportPath: pkg.ImportPath, RootEligibility: analyzer.RootSupport}
		if pkg.ImportPath == "github.com/plystra/authn/accountstore" {
			item.RootEligibility = analyzer.RootEligible
		}
		for _, name := range pkg.GoFiles {
			content, err := os.ReadFile(filepath.Join(pkg.Dir, name))
			if err != nil {
				t.Fatal(err)
			}
			item.Files = append(item.Files, analyzer.SourceFile{Path: filepath.Base(pkg.ImportPath) + "/" + name, Content: content})
		}
		snapshot.Packages = append(snapshot.Packages, item)
	}
	return snapshot
}
