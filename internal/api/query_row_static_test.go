package api

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestNoUppercaseQueryRowKeyAccessInAPIServer(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(currentFile)

	path := filepath.Join(dir, "server.go")
	content, err := os.Open(path)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}

	pattern := regexp.MustCompile(`(?:row|result\.Rows\[[^\]]+\])\["[A-Z_][A-Z0-9_]*"\]`)
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
			t.Fatalf("uppercase query-row key access found in server.go:%d: %s", lineNo, strings.TrimSpace(scanner.Text()))
		}
	}
	if err := scanner.Err(); err != nil {
		_ = content.Close()
		t.Fatalf("scan server.go: %v", err)
	}
	if err := content.Close(); err != nil {
		t.Fatalf("close server.go: %v", err)
	}
}
