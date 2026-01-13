package cloudquery

import (
	"testing"
	"time"
)

func TestSyncConfig_Fields(t *testing.T) {
	cfg := SyncConfig{
		CloudQueryURL:     "https://api.cloudquery.io",
		SnowflakeDatabase: "CEREBRO",
		SnowflakeSchema:   "RAW",
		SyncInterval:      1 * time.Hour,
		Tables:            []string{"aws_iam_users", "aws_s3_buckets"},
	}

	if cfg.CloudQueryURL != "https://api.cloudquery.io" {
		t.Error("CloudQueryURL field incorrect")
	}

	if cfg.SnowflakeDatabase != "CEREBRO" {
		t.Error("SnowflakeDatabase field incorrect")
	}

	if cfg.SnowflakeSchema != "RAW" {
		t.Error("SnowflakeSchema field incorrect")
	}

	if cfg.SyncInterval != 1*time.Hour {
		t.Error("SyncInterval field incorrect")
	}

	if len(cfg.Tables) != 2 {
		t.Error("Tables count incorrect")
	}
}

func TestSyncResult_Fields(t *testing.T) {
	now := time.Now()
	result := SyncResult{
		Table:      "aws_iam_users",
		RowsSynced: 100,
		Duration:   5.5,
		SyncedAt:   now,
		Error:      "",
	}

	if result.Table != "aws_iam_users" {
		t.Error("Table field incorrect")
	}

	if result.RowsSynced != 100 {
		t.Error("RowsSynced field incorrect")
	}

	if result.Duration != 5.5 {
		t.Error("Duration field incorrect")
	}

	if result.SyncedAt.IsZero() {
		t.Error("SyncedAt field should not be zero")
	}

	if result.Error != "" {
		t.Error("Error should be empty")
	}
}

func TestTableStats_Fields(t *testing.T) {
	now := time.Now()
	stats := &TableStats{
		Table:          "aws_s3_buckets",
		RowCount:       500,
		LastSync:       &now,
		UniqueAccounts: 3,
	}

	if stats.Table != "aws_s3_buckets" {
		t.Error("Table field incorrect")
	}

	if stats.RowCount != 500 {
		t.Error("RowCount field incorrect")
	}

	if stats.LastSync == nil {
		t.Error("LastSync should not be nil")
	}

	if stats.UniqueAccounts != 3 {
		t.Error("UniqueAccounts field incorrect")
	}
}

func TestBuildInsertParams(t *testing.T) {
	row := map[string]interface{}{
		"id":    "123",
		"name":  "test",
		"count": 42,
	}

	cols, vals := buildInsertParams(row)

	if len(cols) != 3 {
		t.Errorf("expected 3 columns, got %d", len(cols))
	}

	if len(vals) != 3 {
		t.Errorf("expected 3 values, got %d", len(vals))
	}

	// Check that cols and vals match
	colSet := make(map[string]bool)
	for _, c := range cols {
		colSet[c] = true
	}

	if !colSet["id"] || !colSet["name"] || !colSet["count"] {
		t.Error("missing expected columns")
	}
}

func TestBuildInsertParams_Empty(t *testing.T) {
	row := map[string]interface{}{}

	cols, vals := buildInsertParams(row)

	if len(cols) != 0 {
		t.Error("expected 0 columns for empty row")
	}

	if len(vals) != 0 {
		t.Error("expected 0 values for empty row")
	}
}
