//go:build integration

package accountstore_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/plystra/data/analyzer"
	compiler "github.com/plystra/data/postgres/compiler"
)

func TestAccountsGeneratedProviderPostgres(t *testing.T) {
	result, err := analyzer.Analyze(sourceSnapshot(t))
	if err != nil || !result.Valid || len(result.Roots) != 1 {
		t.Fatalf("analyze actual account storage: %v, %v", err, result.Diagnostics)
	}
	providers, err := compiler.CompileAccessProviders([]compiler.SchemaMember{schemaMember(result.Roots[0].Model)}, result.Roots)
	if err != nil || len(providers) != 1 {
		t.Fatalf("generate typed account provider: %v", err)
	}
	directory := t.TempDir()
	providerFile := filepath.Join(directory, "provider.go")
	if err := os.WriteFile(providerFile, []byte(providers[0].Source), 0600); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/generated_provider_test.go.txt")
	if err != nil {
		t.Fatal(err)
	}
	testFile := filepath.Join(directory, "provider_test.go")
	if err := os.WriteFile(testFile, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	// Explicit files retain this module's real dependency graph and imports.
	// There is no fixture module, local replace, fake backend or nested suite.
	for _, race := range []bool{false, true} {
		args := []string{"test", "-mod=readonly"}
		if race {
			args = append(args, "-race")
		}
		args = append(args, "-run", "^TestGeneratedAccountsPostgres$", "-count=1", "-timeout=45s", "-v", providerFile, testFile)
		command := exec.Command("go", args...)
		command.Env = append(os.Environ(), "GOWORK=off")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("generated public PG test (race=%v): %v\n%s", race, err, output)
		}
		t.Logf("generated public PG test (race=%v):\n%s", race, output)
	}
}
