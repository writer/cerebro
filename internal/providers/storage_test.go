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

	"github.com/writer/cerebro/internal/snowflake"
)

type fakeSnowflakeResult struct{}

func (fakeSnowflakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeSnowflakeResult) RowsAffected() (int64, error) { return 0, nil }

type fakeSnowflakeClient struct {
	execErr     error
	queryErr    error
	queryReply  *snowflake.QueryResult
	execQueries []string
}

func (f *fakeSnowflakeClient) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	f.execQueries = append(f.execQueries, query)
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
		return
	}
	if !strings.Contains(err.Error(), "get existing columns") {
		t.Fatalf("error = %q, want get existing columns", err.Error())
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

func TestEnsureProviderTable_UsesIdempotentAlter(t *testing.T) {
	client := &fakeSnowflakeClient{queryReply: &snowflake.QueryResult{Rows: []map[string]interface{}{
		{"column_name": "_CQ_ID"},
	}}}

	if err := ensureProviderTable(context.Background(), client, "okta_users", []string{"id"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundIDAlter := false
	for _, query := range client.execQueries {
		if strings.Contains(query, "ALTER TABLE okta_users ADD COLUMN IF NOT EXISTS ID VARIANT") {
			foundIDAlter = true
			break
		}
	}
	if !foundIDAlter {
		t.Fatalf("expected idempotent ID alter query, got %v", client.execQueries)
	}
}

func TestEnsureProviderTable_SkipsExistingColumnsCaseInsensitive(t *testing.T) {
	client := &fakeSnowflakeClient{queryReply: &snowflake.QueryResult{Rows: []map[string]interface{}{
		{"COLUMN_NAME": "ID"},
		{"column_name": "_CQ_HASH"},
	}}}

	if err := ensureProviderTable(context.Background(), client, "okta_users", []string{"id"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, query := range client.execQueries {
		if strings.Contains(query, "ALTER TABLE okta_users ADD COLUMN IF NOT EXISTS ID VARIANT") {
			t.Fatalf("did not expect alter for existing column, queries: %v", client.execQueries)
		}
	}
}

func TestBuildProviderCDCEvents(t *testing.T) {
	prepared := []map[string]interface{}{
		{"_cq_id": "new-row", "_cq_hash": "hash-new", "site_id": "site-1", "id": "new-row"},
		{"_cq_id": "changed-row", "_cq_hash": "hash-changed", "site_id": "site-1", "id": "changed-row"},
		{"_cq_id": "same-row", "_cq_hash": "hash-same", "site_id": "site-1", "id": "same-row"},
	}
	existing := map[string]providerExistingRow{
		"changed-row": {Hash: "hash-old"},
		"same-row":    {Hash: "hash-same"},
		"removed-row": {Hash: "hash-removed"},
	}
	newIDs := providerRowIDSet(prepared)

	events := buildProviderCDCEvents("sentinelone_agents", "sentinelone", prepared, existing, newIDs)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3: %#v", len(events), events)
	}

	byResource := make(map[string]string, len(events))
	for _, event := range events {
		if event.Provider != "sentinelone" {
			t.Fatalf("provider = %q, want sentinelone", event.Provider)
		}
		if event.TableName != "sentinelone_agents" {
			t.Fatalf("table = %q, want sentinelone_agents", event.TableName)
		}
		byResource[event.ResourceID] = event.ChangeType
	}

	if byResource["new-row"] != "added" {
		t.Fatalf("new-row change = %q, want added", byResource["new-row"])
	}
	if byResource["changed-row"] != "modified" {
		t.Fatalf("changed-row change = %q, want modified", byResource["changed-row"])
	}
	if byResource["removed-row"] != "removed" {
		t.Fatalf("removed-row change = %q, want removed", byResource["removed-row"])
	}
	if _, ok := byResource["same-row"]; ok {
		t.Fatal("same-row should not emit a CDC event")
	}
}
