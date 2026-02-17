package graph

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fixedQuerySource struct {
	result *QueryResult
	err    error
}

func (f *fixedQuerySource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &QueryResult{Rows: []map[string]any{}}, nil
}

func TestQueryRowHelpers_UppercaseMapCompatibility(t *testing.T) {
	row := map[string]any{
		"TABLE_NAME": "AWS_IAM_USERS",
		"LATEST":     "2026-02-17T00:00:00Z",
	}

	if got := queryRowString(row, "table_name"); got != "AWS_IAM_USERS" {
		t.Fatalf("expected uppercase fallback for table_name, got %q", got)
	}
	if got := toString(queryRow(row, "latest")); got != "2026-02-17T00:00:00Z" {
		t.Fatalf("expected uppercase fallback for latest, got %q", got)
	}
}

func TestHasChanges_HandlesUppercaseLatestKey(t *testing.T) {
	base := time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC)

	t.Run("older latest returns false", func(t *testing.T) {
		source := &fixedQuerySource{result: &QueryResult{Rows: []map[string]any{{"LATEST": base.Add(-time.Minute)}}}}
		builder := NewBuilder(source, nil)
		builder.lastBuildTime = base

		if changed := builder.HasChanges(context.Background()); changed {
			t.Fatal("expected no changes when latest is older")
		}
	})

	t.Run("newer latest returns true", func(t *testing.T) {
		source := &fixedQuerySource{result: &QueryResult{Rows: []map[string]any{{"LATEST": base.Add(time.Minute)}}}}
		builder := NewBuilder(source, nil)
		builder.lastBuildTime = base

		if changed := builder.HasChanges(context.Background()); !changed {
			t.Fatal("expected changes when latest is newer")
		}
	})
}

func TestNoUppercaseQueryRowKeyAccessInGraphBuilder(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(currentFile)

	path := filepath.Join(dir, "builder.go")
	content, err := os.Open(path)
	if err != nil {
		t.Fatalf("open builder.go: %v", err)
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
			t.Fatalf("uppercase query-row key access found in builder.go:%d: %s", lineNo, strings.TrimSpace(scanner.Text()))
		}
	}
	if err := scanner.Err(); err != nil {
		_ = content.Close()
		t.Fatalf("scan builder.go: %v", err)
	}
	if err := content.Close(); err != nil {
		t.Fatalf("close builder.go: %v", err)
	}
}
