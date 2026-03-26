package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/app"
)

func TestResolveLocalScanDataset_FromFixture(t *testing.T) {
	t.Setenv("CEREBRO_SCAN_FIXTURE", "")
	t.Setenv("CEREBRO_SCAN_SNAPSHOT_DIR", "")

	fixturePath := filepath.Join(t.TempDir(), "fixture.json")
	fixture := map[string]interface{}{
		"tables": map[string]interface{}{
			"aws_s3_buckets": []map[string]interface{}{{"id": "b1"}},
		},
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(fixturePath, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	prevFixture, prevSnapshot := scanLocalFixture, scanSnapshotDir
	scanLocalFixture = fixturePath
	scanSnapshotDir = ""
	t.Cleanup(func() {
		scanLocalFixture = prevFixture
		scanSnapshotDir = prevSnapshot
	})

	dataset, err := resolveLocalScanDataset()
	if err != nil {
		t.Fatalf("resolveLocalScanDataset error: %v", err)
	}
	if dataset == nil {
		t.Fatal("expected dataset")
	}
	if len(dataset.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(dataset.Tables))
	}
	if len(dataset.Tables["aws_s3_buckets"]) != 1 {
		t.Fatalf("expected 1 asset in aws_s3_buckets, got %d", len(dataset.Tables["aws_s3_buckets"]))
	}
}

func TestResolveLocalScanDataset_FromSnapshotDir(t *testing.T) {
	t.Setenv("CEREBRO_SCAN_FIXTURE", "")
	t.Setenv("CEREBRO_SCAN_SNAPSHOT_DIR", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "aws_iam_users.json")
	if err := os.WriteFile(path, []byte(`{"assets":[{"id":"u1"}]}`), 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	prevFixture, prevSnapshot := scanLocalFixture, scanSnapshotDir
	scanLocalFixture = ""
	scanSnapshotDir = dir
	t.Cleanup(func() {
		scanLocalFixture = prevFixture
		scanSnapshotDir = prevSnapshot
	})

	dataset, err := resolveLocalScanDataset()
	if err != nil {
		t.Fatalf("resolveLocalScanDataset error: %v", err)
	}
	if dataset == nil {
		t.Fatal("expected dataset")
	}
	if len(dataset.Tables["aws_iam_users"]) != 1 {
		t.Fatalf("expected 1 asset in aws_iam_users, got %d", len(dataset.Tables["aws_iam_users"]))
	}
}

func TestEvaluateScanPreflight_WithLocalDataset(t *testing.T) {
	application := &app.App{Config: &app.Config{}}
	dataset := &localScanDataset{Tables: map[string][]map[string]interface{}{"aws_s3_buckets": {{"id": "b1"}}}, Source: "fixture:test"}

	result := evaluateScanPreflight(application, dataset)
	if !result.Ready {
		t.Fatalf("expected preflight ready, got not ready: %+v", result)
	}
	if result.Mode != "local-dataset" {
		t.Fatalf("expected mode local-dataset, got %s", result.Mode)
	}
}

func TestEvaluateScanPreflight_MissingWarehouse(t *testing.T) {
	application := &app.App{Config: &app.Config{}}

	result := evaluateScanPreflight(application, nil)
	if result.Ready {
		t.Fatalf("expected preflight not ready, got ready: %+v", result)
	}
	if len(result.MissingWarehouseEnv) != 1 || result.MissingWarehouseEnv[0] != "WAREHOUSE_BACKEND" {
		t.Fatalf("expected missing warehouse backend, got %v", result.MissingWarehouseEnv)
	}
}
