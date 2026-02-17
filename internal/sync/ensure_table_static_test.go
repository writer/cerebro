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

	for _, name := range []string{"k8s.go", "gcp.go"} {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)

		if !strings.Contains(text, "ADD COLUMN IF NOT EXISTS") {
			t.Fatalf("expected idempotent ALTER TABLE in %s", name)
		}
		if strings.Contains(text, "e.sf.Query(ctx, createQuery)") {
			t.Fatalf("expected create-table DDL to use Exec in %s", name)
		}
	}
}
