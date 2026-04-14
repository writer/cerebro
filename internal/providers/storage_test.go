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
	"github.com/writer/cerebro/internal/warehouse"
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

	err := ensureProviderTable(context.Background(), client, "okta_users", []ColumnSchema{{Name: "id", Type: "string"}})
	if err == nil {
		t.Fatal("expected error")
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

	if err := ensureProviderTable(context.Background(), client, "okta_users", []ColumnSchema{{Name: "id", Type: "string"}}); err != nil {
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

	if err := ensureProviderTable(context.Background(), client, "okta_users", []ColumnSchema{{Name: "id", Type: "string"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, query := range client.execQueries {
		if strings.Contains(query, "ALTER TABLE okta_users ADD COLUMN IF NOT EXISTS ID VARIANT") {
			t.Fatalf("did not expect alter for existing column, queries: %v", client.execQueries)
		}
	}
}

func TestBaseProviderSyncTable_UsesConfiguredWarehouse(t *testing.T) {
	provider := NewBaseProvider("okta", ProviderTypeIdentity)
	provider.SetWarehouse(&warehouse.MemoryWarehouse{
		DialectValue: warehouse.SQLDialectPostgres,
		QueryFunc: func(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
			return &snowflake.QueryResult{Rows: []map[string]interface{}{
				{"column_name": "_CQ_ID"},
				{"column_name": "_CQ_HASH"},
				{"column_name": "ID"},
				{"column_name": "EMAIL"},
				{"column_name": "ACCOUNT_ENABLED"},
			}}, nil
		},
	})

	result, err := provider.syncTable(context.Background(), TableSchema{
		Name: "okta_users",
		Columns: []ColumnSchema{
			{Name: "id", Type: "string"},
			{Name: "email", Type: "string"},
			{Name: "account_enabled", Type: "boolean"},
		},
		PrimaryKey: []string{"id"},
	}, []map[string]interface{}{
		{"id": "user-1", "email": "user@example.com", "account_enabled": true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Inserted != 1 {
		t.Fatalf("Inserted = %d, want 1", result.Inserted)
	}

	mem, ok := provider.getWarehouse().(*warehouse.MemoryWarehouse)
	if !ok {
		t.Fatal("expected configured memory warehouse")
	}
	foundUpsert := false
	foundTypedCreate := false
	foundNativeBoolArg := false
	for _, call := range mem.Execs {
		if strings.Contains(call.Statement, "ON CONFLICT (_CQ_ID) DO UPDATE") {
			foundUpsert = true
		}
		if strings.Contains(call.Statement, "ACCOUNT_ENABLED BOOLEAN") {
			foundTypedCreate = true
		}
		for _, arg := range call.Args {
			if typed, ok := arg.(bool); ok && typed {
				foundNativeBoolArg = true
			}
		}
	}
	if !foundUpsert {
		t.Fatalf("expected postgres upsert query, got %#v", mem.Execs)
	}
	if !foundTypedCreate {
		t.Fatalf("expected typed boolean provider column, got %#v", mem.Execs)
	}
	if !foundNativeBoolArg {
		t.Fatalf("expected native bool argument, got %#v", mem.Execs)
	}
}

func TestBaseProviderSyncTable_StoresTypedProviderColumnsInSQLite(t *testing.T) {
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "providers.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	provider := NewBaseProvider("entra", ProviderTypeIdentity)
	provider.SetWarehouse(store)

	_, err = provider.syncTable(context.Background(), TableSchema{
		Name: "entra_users",
		Columns: []ColumnSchema{
			{Name: "id", Type: "string"},
			{Name: "account_enabled", Type: "boolean"},
			{Name: "display_name", Type: "string"},
		},
		PrimaryKey: []string{"id"},
	}, []map[string]interface{}{
		{"id": "user-1", "account_enabled": true, "display_name": "User One"},
	})
	if err != nil {
		t.Fatalf("syncTable() error = %v", err)
	}

	result, err := store.Query(context.Background(), "SELECT id FROM entra_users WHERE account_enabled = true")
	if err != nil {
		t.Fatalf("query typed provider column: %v", err)
	}
	if result.Count != 1 || result.Rows[0]["id"] != "user-1" {
		t.Fatalf("expected native boolean query to match synced row, got %#v", result.Rows)
	}
}

func TestDeleteProviderRowsByIDUsesDialectAwarePlaceholders(t *testing.T) {
	tests := []struct {
		name      string
		dialect   warehouse.SQLDialect
		wantQuery string
	}{
		{name: "postgres", dialect: warehouse.SQLDialectPostgres, wantQuery: "DELETE FROM okta_users WHERE _CQ_ID IN ($1,$2)"},
		{name: "sqlite", dialect: warehouse.SQLDialectSQLite, wantQuery: "DELETE FROM okta_users WHERE _CQ_ID IN (?,?)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &warehouse.MemoryWarehouse{DialectValue: tt.dialect}
			if err := deleteProviderRowsByID(context.Background(), store, "okta_users", map[string]struct{}{
				"user-1": {},
				"user-2": {},
			}); err != nil {
				t.Fatalf("deleteProviderRowsByID() error = %v", err)
			}
			if len(store.Execs) != 1 {
				t.Fatalf("expected one delete exec, got %#v", store.Execs)
			}
			if store.Execs[0].Statement != tt.wantQuery {
				t.Fatalf("delete query = %q, want %q", store.Execs[0].Statement, tt.wantQuery)
			}
		})
	}
}
