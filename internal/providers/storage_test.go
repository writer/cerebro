package providers

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

type fakeSnowflakeResult struct{}

func (fakeSnowflakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeSnowflakeResult) RowsAffected() (int64, error) { return 0, nil }

type fakeSnowflakeClient struct {
	execErr    error
	queryErr   error
	queryReply *snowflake.QueryResult
}

func (f *fakeSnowflakeClient) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if f.execErr != nil {
		return nil, f.execErr
	}
	return fakeSnowflakeResult{}, nil
}

func (f *fakeSnowflakeClient) Query(ctx context.Context, query string, args ...interface{}) (*snowflake.QueryResult, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	if f.queryReply != nil {
		return f.queryReply, nil
	}
	return &snowflake.QueryResult{Rows: []map[string]interface{}{}}, nil
}

func TestEnsureProviderTable_PropagatesColumnError(t *testing.T) {
	client := &fakeSnowflakeClient{queryErr: errors.New("query failed")}

	err := ensureProviderTable(context.Background(), client, "okta_users", []string{"id"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get existing columns") {
		t.Fatalf("error = %q, want get existing columns", err.Error())
	}
}

func TestGetProviderTableColumns_UppercaseKeyFallback(t *testing.T) {
	client := &fakeSnowflakeClient{queryReply: &snowflake.QueryResult{Rows: []map[string]interface{}{
		{"COLUMN_NAME": "ID"},
		{"column_name": []byte("display_name")},
	}}}

	columns, err := getProviderTableColumns(context.Background(), client, "okta_users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(columns))
	}
	if columns[0] != "ID" {
		t.Fatalf("expected first column ID, got %q", columns[0])
	}
	if columns[1] != "display_name" {
		t.Fatalf("expected second column display_name, got %q", columns[1])
	}
}

func TestNoUppercaseQueryRowKeyAccessInProviderStorage(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(currentFile)

	path := filepath.Join(dir, "storage.go")
	content, err := os.Open(path)
	if err != nil {
		t.Fatalf("open storage.go: %v", err)
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
			t.Fatalf("uppercase query-row key access found in storage.go:%d: %s", lineNo, strings.TrimSpace(scanner.Text()))
		}
	}
	if err := scanner.Err(); err != nil {
		_ = content.Close()
		t.Fatalf("scan storage.go: %v", err)
	}
	if err := content.Close(); err != nil {
		t.Fatalf("close storage.go: %v", err)
	}
}
