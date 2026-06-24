package sourcegen

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wireRegistryFixture = `package sourceregistry

import (
	sourcecdk "github.com/writer/cerebro/sources/internal/cdk"

	alphasource "github.com/writer/cerebro/sources/alpha"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
)

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "alpha",
		load: func() (sourcecdk.Source, error) {
			return alphasource.New()
		},
	},
	{
		name: "vulnview",
		load: func() (sourcecdk.Source, error) {
			return vulnviewsource.New()
		},
	},
}

// Builtin constructs the in-process source registry.
func Builtin() (*sourcecdk.Registry, error) {
	return nil, nil
}
`

func wireRegistryForSource(t *testing.T, sourceID string) string {
	t.Helper()
	canonical, err := format.Source([]byte(wireRegistryFixture))
	if err != nil {
		t.Fatalf("fixture is not valid Go: %v", err)
	}
	path := filepath.Join(t.TempDir(), "registry.go")
	if err := os.WriteFile(path, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	importAlias := sourceIDToImportAlias(sourceID)
	importPath := "github.com/writer/cerebro/sources/" + sourceID
	loaderEntry := fmt.Sprintf("\t{\n\t\tname: %q,\n\t\tload: func() (sourcecdk.Source, error) {\n\t\t\treturn %s.New()\n\t\t},\n\t},\n", sourceID, importAlias)
	if err := wireSourceRegistry(path, importAlias, importPath, sourceID, loaderEntry); err != nil {
		t.Fatalf("wireSourceRegistry() error = %v", err)
	}
	out, err := os.ReadFile(path) // #nosec G304 -- test temp path.
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func expectedLoaderEntry(sourceID string) string {
	return fmt.Sprintf("\t{\n\t\tname: %q,\n\t\tload: func() (sourcecdk.Source, error) {\n\t\t\treturn %s.New()\n\t\t},\n\t},", sourceID, sourceIDToImportAlias(sourceID))
}

// TestWireSourceRegistryAppendsWhenAlphabeticallyLast covers the end-fallback
// path: a sourceID that sorts after every existing entry must land at the
// builtinSourceLoaders slice close (not the file's last brace, which would put
// it inside func Builtin and break compilation) with single-tab indentation.
func TestWireSourceRegistryAppendsWhenAlphabeticallyLast(t *testing.T) {
	out := wireRegistryForSource(t, "zscaler")
	if _, err := format.Source([]byte(out)); err != nil {
		t.Fatalf("generated registry is not valid Go (entry placed wrong?): %v\n%s", err, out)
	}
	if entry := expectedLoaderEntry("zscaler"); !strings.Contains(out, entry) {
		t.Fatalf("zscaler loader entry missing or mis-indented; want:\n%s\ngot:\n%s", entry, out)
	}
	// The entry must sit inside the slice, before the slice's closing brace and
	// the Builtin function, not after the function's return.
	if idx := strings.Index(out, `name: "zscaler"`); idx < 0 || idx > strings.Index(out, "func Builtin(") {
		t.Fatalf("zscaler entry not inside builtinSourceLoaders slice:\n%s", out)
	}
}

// TestProjectionFuncNameMatchesGeneratorNaming guards the wire/generator
// contract: the projector function names wire references in the projection
// registry must be the exact unexported names the generator defines. A prior
// bug derived PascalCase names (e.g. ConjurResourceProjections) which are
// undefined and fail to compile.
func TestProjectionFuncNameMatchesGeneratorNaming(t *testing.T) {
	cases := []struct {
		sourceID string
		kind     string
		want     string
	}{
		{"conjur", "conjur.resource", "conjurResourceProjections"},
		{"conjur", "conjur.resource_2", "conjurResource2Projections"},
		{"conjur", "conjur.authenticator", "conjurAuthenticatorProjections"},
		{"hashicorp_vault", "hashicorp_vault.secret", "hashicorpVaultSecretProjections"},
	}
	for _, tc := range cases {
		got := projectionFuncName(tc.sourceID, tc.kind)
		if got != tc.want {
			t.Errorf("projectionFuncName(%q, %q) = %q, want %q", tc.sourceID, tc.kind, got, tc.want)
		}
		if r := []rune(got)[0]; r < 'a' || r > 'z' {
			t.Errorf("projectionFuncName(%q, %q) = %q must start lowercase to match the generator", tc.sourceID, tc.kind, got)
		}
		family := strings.TrimPrefix(tc.kind, tc.sourceID+".")
		if want := lowerCamelIdentifier(tc.sourceID + "_" + family + "_projections"); got != want {
			t.Errorf("projectionFuncName(%q, %q) = %q diverged from generator formula %q", tc.sourceID, tc.kind, got, want)
		}
	}
}

// TestWireSourceRegistryInsertsAlphabetically covers the in-order path so both
// insertion branches stay consistent and correctly indented.
func TestWireSourceRegistryInsertsAlphabetically(t *testing.T) {
	out := wireRegistryForSource(t, "beta")
	if _, err := format.Source([]byte(out)); err != nil {
		t.Fatalf("generated registry is not valid Go: %v\n%s", err, out)
	}
	if entry := expectedLoaderEntry("beta"); !strings.Contains(out, entry) {
		t.Fatalf("beta loader entry missing or mis-indented; want:\n%s\ngot:\n%s", entry, out)
	}
	alphaIdx := strings.Index(out, `name: "alpha"`)
	betaIdx := strings.Index(out, `name: "beta"`)
	vulnIdx := strings.Index(out, `name: "vulnview"`)
	if alphaIdx < 0 || betaIdx <= alphaIdx || vulnIdx <= betaIdx {
		t.Fatalf("beta not inserted in alphabetical order (alpha=%d beta=%d vulnview=%d):\n%s", alphaIdx, betaIdx, vulnIdx, out)
	}
}
