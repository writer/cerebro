package scanner

import (
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
	store.SetWatermark("aws_s3_buckets", now, 100)

	wm = store.GetWatermark("aws_s3_buckets")
	if wm == nil {
		t.Fatal("expected watermark")
	}
	if wm.RowsScanned != 100 {
		t.Errorf("got %d rows, want 100", wm.RowsScanned)
	}
}

func TestShouldFullScan(t *testing.T) {
	store := NewWatermarkStore(nil)

	// No watermark - should full scan
	if !store.ShouldFullScan("aws_s3_buckets", 24*time.Hour) {
		t.Error("expected full scan for missing watermark")
	}

	// Fresh watermark - should not full scan
	store.SetWatermark("aws_s3_buckets", time.Now(), 100)
	if store.ShouldFullScan("aws_s3_buckets", 24*time.Hour) {
		t.Error("expected incremental scan for fresh watermark")
	}

	// Old watermark - should full scan
	store.SetWatermark("aws_ec2_instances", time.Now().Add(-48*time.Hour), 50)
	if !store.ShouldFullScan("aws_ec2_instances", 24*time.Hour) {
		t.Error("expected full scan for old watermark")
	}
}

func TestGetIncrementalQuery(t *testing.T) {
	// Full scan (no watermark)
	query := GetIncrementalQuery("aws_s3_buckets", nil, 1000)
	expected := "SELECT * FROM aws_s3_buckets LIMIT 1000"
	if query != expected {
		t.Errorf("got %q, want %q", query, expected)
	}

	// Incremental scan
	lastScan := time.Date(2026, 1, 13, 10, 0, 0, 0, time.UTC)
	query = GetIncrementalQuery("aws_s3_buckets", &lastScan, 1000)
	if query == expected {
		t.Error("incremental query should differ from full scan")
	}
	if query == "" {
		t.Error("query should not be empty")
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
	store.SetWatermark("aws_s3_buckets", now, 100)
	store.SetWatermark("aws_ec2_instances", now.Add(-time.Hour), 200)

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
