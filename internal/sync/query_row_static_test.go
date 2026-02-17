package sync

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestNoUppercaseQueryRowKeyAccessInCriticalSyncFiles(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(currentFile)

	files := []string{"engine.go", "gcp.go", "k8s.go", "azure.go", "relationships.go", "sync_time.go"}
	pattern := regexp.MustCompile(`(?:row|result\.Rows\[[^\]]+\])\["[A-Z_][A-Z0-9_]*"\]`)

	for _, name := range files {
		path := filepath.Join(dir, name)
		content, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}

		scanner := bufio.NewScanner(content)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			if strings.Contains(line, "//") {
				line = strings.SplitN(line, "//", 2)[0]
			}
			if pattern.MatchString(line) {
				_ = content.Close()
				t.Fatalf("uppercase query-row key access found in %s:%d: %s", name, lineNo, strings.TrimSpace(scanner.Text()))
			}
		}
		if err := scanner.Err(); err != nil {
			_ = content.Close()
			t.Fatalf("scan %s: %v", name, err)
		}
		if err := content.Close(); err != nil {
			t.Fatalf("close %s: %v", name, err)
		}
	}
}
