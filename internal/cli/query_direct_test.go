package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/warehouse"
)

func TestRunQueryDirect_UsesConfiguredWarehouse(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	tempDir := t.TempDir()
	warehousePath := filepath.Join(tempDir, "warehouse.db")
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{Path: warehousePath})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Exec(context.Background(), `
		CREATE TABLE aws_s3_buckets (
			id TEXT,
			name TEXT
		)
	`); err != nil {
		t.Fatalf("create warehouse table: %v", err)
	}
	if _, err := store.Exec(context.Background(), `INSERT INTO aws_s3_buckets (id, name) VALUES (?, ?)`, "bucket-1", "bucket-a"); err != nil {
		t.Fatalf("insert warehouse row: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded warehouse: %v", err)
	}

	policyDir := filepath.Join(tempDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir policy dir: %v", err)
	}

	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("API_AUTH_ENABLED", "false")
	t.Setenv("API_KEYS", "")
	t.Setenv("WAREHOUSE_BACKEND", "sqlite")
	t.Setenv("WAREHOUSE_SQLITE_PATH", warehousePath)
	t.Setenv("EXECUTION_STORE_FILE", filepath.Join(tempDir, "executions.db"))
	t.Setenv("GRAPH_SNAPSHOT_PATH", filepath.Join(tempDir, "graph-snapshots"))
	t.Setenv("PLATFORM_REPORT_RUN_STATE_FILE", filepath.Join(tempDir, "report-runs.json"))
	t.Setenv("PLATFORM_REPORT_SNAPSHOT_PATH", filepath.Join(tempDir, "report-snapshots"))
	t.Setenv("CEREBRO_DB_PATH", filepath.Join(tempDir, "findings.db"))
	t.Setenv("POLICIES_PATH", policyDir)

	queryFormat = FormatJSON
	queryLimit = 10

	output := captureStdout(t, func() {
		if err := runQueryDirect(queryCmd, []string{"SELECT name FROM aws_s3_buckets"}); err != nil {
			t.Fatalf("runQueryDirect failed: %v", err)
		}
	})

	if !strings.Contains(output, "bucket-a") {
		t.Fatalf("expected warehouse query output to include bucket-a, got %s", output)
	}
}
