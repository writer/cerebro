package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/app"
)

func TestBuildFilesystemAnalyzerFallsBackWhenVulnDBOpenFails(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocker, []byte("not-a-directory"), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", blocker, err)
	}

	analyzer, closer, err := buildFilesystemAnalyzer(&app.Config{
		VulnDBStateFile: filepath.Join(blocker, "nested", "vulndb.db"),
	}, "trivy")
	if err != nil {
		t.Fatalf("buildFilesystemAnalyzer: %v", err)
	}
	if analyzer == nil {
		t.Fatal("expected filesystem analyzer fallback")
	}
	if closer == nil {
		t.Fatal("expected fallback closer")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("fallback closer.Close(): %v", err)
	}
}
