package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

func TestBuildReviewReportFallsBackWhenRuntimeDepthUnavailable(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing")

	result, err := buildReviewReport(connectorcatalog.Analysis{}, missingRoot, true, false)
	if err != nil {
		t.Fatalf("buildReviewReport() error = %v", err)
	}
	if result.RuntimeDepthWarning == nil {
		t.Fatal("runtime depth warning = nil, want warning")
	}
	if result.Report.Summary.RuntimeDepth != nil {
		t.Fatalf("runtime depth summary = %#v, want nil fallback report", result.Report.Summary.RuntimeDepth)
	}
}

func TestBuildReviewReportRequiresRuntimeDepthWhenConfigured(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing")

	_, err := buildReviewReport(connectorcatalog.Analysis{}, missingRoot, true, true)
	if err == nil {
		t.Fatal("buildReviewReport() error = nil, want runtime depth error")
	}
	if !strings.Contains(err.Error(), "discover runtime depth") {
		t.Fatalf("buildReviewReport() error = %v, want discover runtime depth context", err)
	}
}

func TestBuildReviewReportIncludesRuntimeDepthWhenAvailable(t *testing.T) {
	result, err := buildReviewReport(connectorcatalog.Analysis{}, t.TempDir(), true, false)
	if err != nil {
		t.Fatalf("buildReviewReport() error = %v", err)
	}
	if result.RuntimeDepthWarning != nil {
		t.Fatalf("runtime depth warning = %v, want nil", result.RuntimeDepthWarning)
	}
	if result.Report.Summary.RuntimeDepth == nil {
		t.Fatal("runtime depth summary = nil, want runtime depth summary")
	}
}

func TestWriteFileDoesNotChmodExistingParentDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	path := filepath.Join(dir, "review.json")
	if err := writeFile(path, []byte("{}\n")); err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent dir mode = %#o, want 0755", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("output file mode = %#o, want 0600", got)
	}
}
