package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/findings"
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
		return
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
		return
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

func TestRunScan_LocalModePersistsFindingsAndWatermarksAcrossRestart(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	tempDir := t.TempDir()
	policyDir := filepath.Join(tempDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}

	policyJSON := `{
		"id": "local-public-bucket",
		"name": "Local public bucket",
		"description": "Public buckets should be flagged",
		"effect": "forbid",
		"resource": "aws::s3::bucket",
		"condition_format": "cel",
		"conditions": ["resource.public == true"],
		"severity": "high"
	}`
	if err := os.WriteFile(filepath.Join(policyDir, "local-public-bucket.json"), []byte(policyJSON), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	scanTime := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	fixturePath := filepath.Join(tempDir, "fixture.json")
	fixture := map[string]interface{}{
		"tables": map[string]interface{}{
			"aws_s3_buckets": []map[string]interface{}{
				{
					"_cq_id":        "bucket-1",
					"_cq_table":     "aws_s3_buckets",
					"_cq_sync_time": scanTime.Format(time.RFC3339),
					"type":          "aws::s3::bucket",
					"id":            "bucket-1",
					"name":          "public-bucket",
					"public":        true,
				},
			},
		},
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(fixturePath, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeDirect))
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("API_AUTH_ENABLED", "false")
	t.Setenv("API_KEYS", "")
	t.Setenv("WAREHOUSE_BACKEND", "sqlite")
	t.Setenv("WAREHOUSE_SQLITE_PATH", filepath.Join(tempDir, "warehouse.db"))
	t.Setenv("EXECUTION_STORE_FILE", filepath.Join(tempDir, "executions.db"))
	t.Setenv("GRAPH_SNAPSHOT_PATH", filepath.Join(tempDir, "graph-snapshots"))
	t.Setenv("PLATFORM_REPORT_RUN_STATE_FILE", filepath.Join(tempDir, "report-runs.json"))
	t.Setenv("PLATFORM_REPORT_SNAPSHOT_PATH", filepath.Join(tempDir, "report-snapshots"))
	t.Setenv("CEREBRO_DB_PATH", filepath.Join(tempDir, "findings.db"))
	t.Setenv("POLICIES_PATH", policyDir)

	scanTables = []string{"aws_s3_buckets"}
	scanLimit = 10
	scanDryRun = false
	scanOutput = FormatJSON
	scanFull = false
	scanToxicCombos = false
	scanUseGraph = false
	scanExtractRelationships = false
	scanPreflight = false
	scanLocalFixture = fixturePath
	scanSnapshotDir = ""

	_ = captureStdout(t, func() {
		if err := runScan(scanCmd, nil); err != nil {
			t.Fatalf("runScan failed: %v", err)
		}
	})

	restarted, err := app.New(context.Background())
	if err != nil {
		t.Fatalf("restart app: %v", err)
	}
	defer func() { _ = restarted.Close() }()

	if got := restarted.Findings.Stats().Total; got != 1 {
		t.Fatalf("expected 1 persisted finding after restart, got %d", got)
	}
	persisted := restarted.Findings.List(findings.FindingFilter{})
	if len(persisted) != 1 || persisted[0].PolicyID != "local-public-bucket" {
		t.Fatalf("unexpected persisted findings after restart: %#v", persisted)
	}

	wm := restarted.ScanWatermarks.GetWatermark("aws_s3_buckets")
	if wm == nil {
		t.Fatal("expected persisted scan watermark after restart")
		return
	}
	if !wm.LastScanTime.Equal(scanTime) {
		t.Fatalf("expected watermark time %s, got %s", scanTime, wm.LastScanTime)
	}
	if wm.LastScanID != "bucket-1" {
		t.Fatalf("expected watermark id bucket-1, got %q", wm.LastScanID)
	}
	if wm.RowsScanned != 1 {
		t.Fatalf("expected watermark rows 1, got %d", wm.RowsScanned)
	}
}
