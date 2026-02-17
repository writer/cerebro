package sync

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRelationshipCleanupUsesRunSyncTimeGuardrails(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	path := filepath.Join(filepath.Dir(currentFile), "relationships.go")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read relationships.go: %v", err)
	}
	text := string(content)

	checks := []string{
		"cleanupStaleRelationships(ctx, runSyncTime)",
		"column8::TIMESTAMP_TZ",
		"r.sf.Exec(ctx, query, cutoff.UTC())",
	}
	for _, check := range checks {
		if !strings.Contains(text, check) {
			t.Fatalf("expected relationships.go to contain %q", check)
		}
	}
}
