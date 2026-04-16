package sync

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureTableUsesIdempotentDDL(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(currentFile)

	checks := map[string][]string{
		"engine.go": {`EnsureVariantTable(`},
		"k8s.go":    {`EnsureVariantTable(`},
		"gcp.go":    {`EnsureVariantTable(`},
		"azure.go": {
			`IgnoreLookupError:     true`,
			`IgnoreAddColumnErrors: true`,
		},
		filepath.Join("..", "snowflake", "tableops", "tableops.go"): {`ADD COLUMN IF NOT EXISTS`},
	}

	for name, expectedSnippets := range checks {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)

		for _, expectedSnippet := range expectedSnippets {
			if !strings.Contains(text, expectedSnippet) {
				t.Fatalf("expected %q in %s", expectedSnippet, name)
			}
		}
		if strings.Contains(text, ".Query(ctx, createQuery)") {
			t.Fatalf("expected create-table DDL to use Exec in %s", name)
		}
	}
}
