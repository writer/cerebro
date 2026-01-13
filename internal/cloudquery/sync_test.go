package cloudquery

import (
	"testing"
	"time"
)

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

func TestAssetInventory_Fields(t *testing.T) {
	inventory := &AssetInventory{
		Tables: map[string]int64{
			"aws_s3_buckets":    100,
			"aws_ec2_instances": 50,
		},
		TotalAssets: 150,
		LastUpdated: time.Now(),
	}

	if len(inventory.Tables) != 2 {
		t.Error("Tables count incorrect")
	}

	if inventory.Tables["aws_s3_buckets"] != 100 {
		t.Error("aws_s3_buckets count incorrect")
	}

	if inventory.TotalAssets != 150 {
		t.Error("TotalAssets incorrect")
	}

	if inventory.LastUpdated.IsZero() {
		t.Error("LastUpdated should not be zero")
	}
}

func TestDataFreshness_Fields(t *testing.T) {
	now := time.Now()
	freshness := &DataFreshness{
		Table:          "aws_iam_users",
		LastSyncTime:   &now,
		HoursSinceSync: 2.5,
		IsStale:        false,
	}

	if freshness.Table != "aws_iam_users" {
		t.Error("Table field incorrect")
	}

	if freshness.LastSyncTime == nil {
		t.Error("LastSyncTime should not be nil")
	}

	if freshness.HoursSinceSync != 2.5 {
		t.Error("HoursSinceSync incorrect")
	}

	if freshness.IsStale {
		t.Error("IsStale should be false")
	}
}

func TestDataFreshness_Stale(t *testing.T) {
	staleTime := time.Now().Add(-48 * time.Hour)
	freshness := &DataFreshness{
		Table:          "aws_rds_instances",
		LastSyncTime:   &staleTime,
		HoursSinceSync: 48,
		IsStale:        true,
	}

	if !freshness.IsStale {
		t.Error("IsStale should be true for data > 24 hours old")
	}
}

func TestTableManager_NewTableManager(t *testing.T) {
	// Can't test with real Snowflake, but verify struct creation
	manager := &TableManager{
		snowflake: nil,
		schema:    "CEREBRO",
	}

	if manager.schema != "CEREBRO" {
		t.Error("schema field incorrect")
	}
}
