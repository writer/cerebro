package warehouse

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
)

func TestSQLiteWarehouseQueryAndDiscovery(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.Exec(ctx, `CREATE TABLE aws_iam_users (arn TEXT, account_id TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := store.Exec(ctx, `INSERT INTO aws_iam_users (arn, account_id) VALUES ('arn:aws:iam::123:user/alice', '123')`); err != nil {
		t.Fatalf("insert row: %v", err)
	}

	infoResult, err := store.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'RAW' AND row_count > 0`)
	if err != nil {
		t.Fatalf("information_schema query: %v", err)
	}
	if infoResult.Count != 1 || infoResult.Rows[0]["table_name"] != "aws_iam_users" {
		t.Fatalf("unexpected info schema result: %#v", infoResult.Rows)
	}

	queryResult, err := store.Query(ctx, `SELECT arn, account_id FROM aws_iam_users`)
	if err != nil {
		t.Fatalf("select rows: %v", err)
	}
	if queryResult.Count != 1 || queryResult.Rows[0]["arn"] != "arn:aws:iam::123:user/alice" {
		t.Fatalf("unexpected query result: %#v", queryResult.Rows)
	}

	columns, err := store.DescribeColumns(ctx, "aws_iam_users")
	if err != nil {
		t.Fatalf("describe columns: %v", err)
	}
	if len(columns) != 2 || columns[0] != "arn" || columns[1] != "account_id" {
		t.Fatalf("unexpected columns: %#v", columns)
	}
}

func TestSQLiteWarehouseInsertCDCEvents(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	event := snowflake.CDCEvent{
		TableName:  "aws_iam_users",
		ResourceID: "arn:aws:iam::123:user/alice",
		ChangeType: "upsert",
		Provider:   "aws",
		AccountID:  "123",
		Payload:    map[string]any{"arn": "arn:aws:iam::123:user/alice"},
		EventTime:  time.Date(2026, 3, 13, 8, 0, 0, 0, time.UTC),
	}
	if err := store.InsertCDCEvents(ctx, []snowflake.CDCEvent{event, event}); err != nil {
		t.Fatalf("insert cdc events: %v", err)
	}

	result, err := store.Query(ctx, `SELECT event_id, table_name, resource_id FROM cdc_events`)
	if err != nil {
		t.Fatalf("query cdc events: %v", err)
	}
	if result.Count != 1 {
		t.Fatalf("expected idempotent cdc insert, got %#v", result.Rows)
	}
}

func TestSQLiteWarehouseRestrictsFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warehouse.db")
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{Path: path})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat sqlite warehouse file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected sqlite warehouse mode 0600, got %04o", got)
	}
}

func TestSQLiteWarehouseRejectsNonAssetTables(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.Exec(ctx, `CREATE TABLE cdc_events (id TEXT)`); err != nil {
		t.Fatalf("create internal table: %v", err)
	}
	if _, err := store.GetAssets(ctx, "cdc_events", snowflake.AssetFilter{Limit: 1}); err == nil {
		t.Fatal("expected non-asset table to be rejected")
		return
	}
}
