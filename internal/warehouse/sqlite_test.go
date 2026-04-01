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
	}
}

func TestSQLiteWarehouseGetAssetsAppliesIncrementalFiltersAndAddsCQTable(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.Exec(ctx, `
		CREATE TABLE aws_s3_buckets (
			_cq_id TEXT,
			_cq_sync_time TEXT,
			id TEXT,
			type TEXT,
			name TEXT
		)
	`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	rows := []struct {
		id   string
		at   string
		name string
	}{
		{id: "bucket-a", at: "2026-03-27T10:00:00Z", name: "bucket-a-older"},
		{id: "bucket-a", at: "2026-03-27T11:00:00Z", name: "bucket-a-latest"},
		{id: "bucket-b", at: "2026-03-27T11:00:00Z", name: "bucket-b"},
		{id: "bucket-c", at: "2026-03-27T12:00:00Z", name: "bucket-c"},
	}
	for _, row := range rows {
		if _, err := store.Exec(
			ctx,
			`INSERT INTO aws_s3_buckets (_cq_id, _cq_sync_time, id, type, name) VALUES (?, ?, ?, ?, ?)`,
			row.id,
			row.at,
			row.id,
			"aws::s3::bucket",
			row.name,
		); err != nil {
			t.Fatalf("insert row %s: %v", row.id, err)
		}
	}

	assets, err := store.GetAssets(ctx, "aws_s3_buckets", snowflake.AssetFilter{
		Since:   time.Date(2026, 3, 27, 11, 0, 0, 0, time.UTC),
		SinceID: "bucket-a",
		Limit:   10,
		Columns: []string{"_cq_id", "_cq_sync_time", "name"},
	})
	if err != nil {
		t.Fatalf("get assets: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 incremental assets, got %#v", assets)
	}
	if got := assets[0]["_cq_id"]; got != "bucket-b" {
		t.Fatalf("expected first asset bucket-b, got %#v", got)
	}
	if got := assets[1]["_cq_id"]; got != "bucket-c" {
		t.Fatalf("expected second asset bucket-c, got %#v", got)
	}
	if got := assets[0]["_cq_table"]; got != "aws_s3_buckets" {
		t.Fatalf("expected _cq_table to be added, got %#v", got)
	}
	if _, ok := assets[0]["_cq_latest_rank"]; ok {
		t.Fatalf("expected helper rank column to be stripped, got %#v", assets[0])
	}
}

func TestSQLiteWarehouseGetAssetsAppliesCursorPagination(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.Exec(ctx, `
		CREATE TABLE aws_s3_buckets (
			_cq_id TEXT,
			_cq_sync_time TEXT,
			id TEXT,
			type TEXT,
			name TEXT
		)
	`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	rows := []struct {
		id   string
		at   string
		name string
	}{
		{id: "bucket-a", at: "2026-03-27T10:00:00Z", name: "bucket-a"},
		{id: "bucket-b", at: "2026-03-27T11:00:00Z", name: "bucket-b"},
		{id: "bucket-c", at: "2026-03-27T12:00:00Z", name: "bucket-c"},
	}
	for _, row := range rows {
		if _, err := store.Exec(
			ctx,
			`INSERT INTO aws_s3_buckets (_cq_id, _cq_sync_time, id, type, name) VALUES (?, ?, ?, ?, ?)`,
			row.id,
			row.at,
			row.id,
			"aws::s3::bucket",
			row.name,
		); err != nil {
			t.Fatalf("insert row %s: %v", row.id, err)
		}
	}

	assets, err := store.GetAssets(ctx, "aws_s3_buckets", snowflake.AssetFilter{
		CursorSyncTime: time.Date(2026, 3, 27, 11, 0, 0, 0, time.UTC),
		CursorID:       "bucket-b",
		Limit:          10,
		Columns:        []string{"_cq_id", "_cq_sync_time", "name"},
	})
	if err != nil {
		t.Fatalf("get assets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 paged asset, got %#v", assets)
	}
	if got := assets[0]["_cq_id"]; got != "bucket-c" {
		t.Fatalf("expected paged asset bucket-c, got %#v", got)
	}
}

func TestSQLiteWarehouseGetAssetByIDUsesCQIDAndReturnsNotFound(t *testing.T) {
	store, err := NewSQLiteWarehouse(SQLiteWarehouseConfig{
		Path: filepath.Join(t.TempDir(), "warehouse.db"),
	})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.Exec(ctx, `
		CREATE TABLE aws_s3_buckets (
			_cq_id TEXT,
			id TEXT,
			name TEXT
		)
	`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := store.Exec(ctx, `INSERT INTO aws_s3_buckets (_cq_id, id, name) VALUES (?, ?, ?)`, "bucket-cq-id", "bucket-natural-id", "bucket-1"); err != nil {
		t.Fatalf("insert row: %v", err)
	}

	asset, err := store.GetAssetByID(ctx, "aws_s3_buckets", "bucket-cq-id")
	if err != nil {
		t.Fatalf("GetAssetByID() error = %v", err)
	}
	if got := asset["_cq_id"]; got != "bucket-cq-id" {
		t.Fatalf("expected _cq_id match, got %#v", got)
	}

	if _, err := store.GetAssetByID(ctx, "aws_s3_buckets", "bucket-natural-id"); err == nil || err.Error() != "asset not found" {
		t.Fatalf("expected asset not found for natural id lookup, got %v", err)
	}
}
