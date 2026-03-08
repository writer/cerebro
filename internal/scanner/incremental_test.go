package scanner

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestWatermarkStore(t *testing.T) {
	store := NewWatermarkStore(nil) // No DB

	// Initially no watermark
	wm := store.GetWatermark("aws_s3_buckets")
	if wm != nil {
		t.Error("expected nil watermark")
	}

	// Set watermark
	now := time.Now()
	store.SetWatermark("aws_s3_buckets", now, "id-1", 100)

	wm = store.GetWatermark("aws_s3_buckets")
	if wm == nil {
		t.Fatal("expected watermark")
	}
	if wm.RowsScanned != 100 {
		t.Errorf("got %d rows, want 100", wm.RowsScanned)
	}
	if wm.LastScanID != "id-1" {
		t.Errorf("got %q id, want id-1", wm.LastScanID)
	}
}

func TestShouldFullScan(t *testing.T) {
	store := NewWatermarkStore(nil)

	// No watermark - should full scan
	if !store.ShouldFullScan("aws_s3_buckets", 24*time.Hour) {
		t.Error("expected full scan for missing watermark")
	}

	// Fresh watermark - should not full scan
	store.SetWatermark("aws_s3_buckets", time.Now(), "id-1", 100)
	if store.ShouldFullScan("aws_s3_buckets", 24*time.Hour) {
		t.Error("expected incremental scan for fresh watermark")
	}

	// Old watermark - should full scan
	store.SetWatermark("aws_ec2_instances", time.Now().Add(-48*time.Hour), "id-2", 50)
	if !store.ShouldFullScan("aws_ec2_instances", 24*time.Hour) {
		t.Error("expected full scan for old watermark")
	}
}

func TestGetIncrementalQuery(t *testing.T) {
	// Full scan (no watermark)
	query, err := GetIncrementalQuery("aws_s3_buckets", nil, "", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "SELECT * FROM aws_s3_buckets LIMIT 1000"
	if query != expected {
		t.Errorf("got %q, want %q", query, expected)
	}

	// Incremental scan
	lastScan := time.Date(2026, 1, 13, 10, 0, 0, 0, time.UTC)
	query, err = GetIncrementalQuery("aws_s3_buckets", &lastScan, "", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query == expected {
		t.Error("incremental query should differ from full scan")
	}
	if query == "" {
		t.Error("query should not be empty")
	}

	query, err = GetIncrementalQuery("aws_s3_buckets", &lastScan, "asset-1", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "_cq_id > 'asset-1'") {
		t.Errorf("expected last_scan_id filter in query, got %q", query)
	}

	query, err = GetIncrementalQuery("aws_s3_buckets", &lastScan, "asset'1", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "_cq_id > 'asset''1'") {
		t.Errorf("expected escaped last_scan_id in query, got %q", query)
	}

	// Invalid table name - should return error
	_, err = GetIncrementalQuery("table; DROP TABLE users", nil, "", 1000)
	if err == nil {
		t.Error("expected error for SQL injection attempt")
	}
}

func TestWatermarkStats(t *testing.T) {
	store := NewWatermarkStore(nil)

	// Empty stats
	stats := store.Stats()
	if stats.TablesWithWatermarks != 0 {
		t.Errorf("expected 0 tables, got %d", stats.TablesWithWatermarks)
	}

	// Add some watermarks
	now := time.Now()
	store.SetWatermark("aws_s3_buckets", now, "id-1", 100)
	store.SetWatermark("aws_ec2_instances", now.Add(-time.Hour), "id-2", 200)

	stats = store.Stats()
	if stats.TablesWithWatermarks != 2 {
		t.Errorf("expected 2 tables, got %d", stats.TablesWithWatermarks)
	}
	if stats.TotalRowsScanned != 300 {
		t.Errorf("expected 300 rows, got %d", stats.TotalRowsScanned)
	}
}

func TestDefaultIncrementalConfig(t *testing.T) {
	cfg := DefaultIncrementalConfig()

	if cfg.ForceFullScan {
		t.Error("ForceFullScan should be false by default")
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize should be 1000, got %d", cfg.BatchSize)
	}
	if cfg.MaxAge != 7*24*time.Hour {
		t.Errorf("MaxAge should be 7 days, got %v", cfg.MaxAge)
	}
}

func TestWatermarkStoreSetDBResetsSchemaState(t *testing.T) {
	store := NewWatermarkStore(nil)
	store.schemaReady = true

	db := &sql.DB{}
	store.SetDB(db)

	if store.db != db {
		t.Fatal("expected watermark store db handle to be updated")
	}
	if store.schemaReady {
		t.Fatal("expected schema readiness to be reset after db update")
	}
}
