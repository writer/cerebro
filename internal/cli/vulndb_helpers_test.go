package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

func TestBuildMalwareScannerUnconfiguredDoesNotPanicFilesystemAnalyzer(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'ok';"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	analyzer := filesystemanalyzer.New(filesystemanalyzer.Options{
		MalwareScanner: buildMalwareScanner(nil, ""),
	})

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected unconfigured malware scanner to behave as nil, got panic: %v", recovered)
		}
	}()

	report, err := analyzer.Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(report.Malware) != 0 {
		t.Fatalf("expected no malware findings, got %#v", report.Malware)
	}
}

func TestBuildMalwareScannerReturnsConfiguredScanner(t *testing.T) {
	malwareScanner := buildMalwareScanner(&app.Config{MalwareScanVirusTotalAPIKey: "test-api-key"}, "")
	if malwareScanner == nil {
		t.Fatal("expected configured malware scanner")
		return
	}
}
