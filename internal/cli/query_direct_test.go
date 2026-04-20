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

func TestRunQueryDirect_SupportsShowTables(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	tempDir := t.TempDir()
	warehousePath := filepath.Join(tempDir, "warehouse.db")
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{Path: warehousePath})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Exec(context.Background(), `CREATE TABLE aws_s3_buckets (id TEXT)`); err != nil {
		t.Fatalf("create warehouse table: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded warehouse: %v", err)
	}

	configureDirectQuerySQLiteEnv(t, tempDir, warehousePath)
	queryFormat = FormatJSON
	queryLimit = 10

	output := captureStdout(t, func() {
		if err := runQueryDirect(queryCmd, []string{"SHOW", "TABLES"}); err != nil {
			t.Fatalf("runQueryDirect failed: %v", err)
		}
	})

	if !strings.Contains(output, "aws_s3_buckets") {
		t.Fatalf("expected SHOW TABLES output to include aws_s3_buckets, got %s", output)
	}
}

func TestRunQueryDirect_AllowsReadOnlyPragmaMetadata(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	tempDir := t.TempDir()
	warehousePath := filepath.Join(tempDir, "warehouse.db")
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{Path: warehousePath})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Exec(context.Background(), `CREATE TABLE aws_s3_buckets (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("create warehouse table: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded warehouse: %v", err)
	}

	configureDirectQuerySQLiteEnv(t, tempDir, warehousePath)
	queryFormat = FormatJSON
	queryLimit = 10

	output := captureStdout(t, func() {
		if err := runQueryDirect(queryCmd, []string{"PRAGMA", "table_info(aws_s3_buckets)"}); err != nil {
			t.Fatalf("runQueryDirect failed: %v", err)
		}
	})

	if !strings.Contains(output, `"name": "id"`) || !strings.Contains(output, `"name": "name"`) {
		t.Fatalf("expected PRAGMA output to include table columns, got %s", output)
	}
}

func TestRunQueryDirect_SupportsDescribeTable(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	tempDir := t.TempDir()
	warehousePath := filepath.Join(tempDir, "warehouse.db")
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{Path: warehousePath})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Exec(context.Background(), `CREATE TABLE aws_s3_buckets (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("create warehouse table: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded warehouse: %v", err)
	}

	configureDirectQuerySQLiteEnv(t, tempDir, warehousePath)
	queryFormat = FormatJSON
	queryLimit = 10

	output := captureStdout(t, func() {
		if err := runQueryDirect(queryCmd, []string{"DESCRIBE", "TABLE", "aws_s3_buckets"}); err != nil {
			t.Fatalf("runQueryDirect failed: %v", err)
		}
	})

	if !strings.Contains(output, `"column_name": "id"`) || !strings.Contains(output, `"column_name": "name"`) {
		t.Fatalf("expected DESCRIBE TABLE output to include table columns, got %s", output)
	}
}

func TestRunQueryDirect_PreservesExplicitLimit(t *testing.T) {
	state := snapshotQueryCLIState()
	t.Cleanup(func() { restoreQueryCLIState(state) })

	tempDir := t.TempDir()
	warehousePath := filepath.Join(tempDir, "warehouse.db")
	store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{Path: warehousePath})
	if err != nil {
		t.Fatalf("new sqlite warehouse: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.Exec(context.Background(), `CREATE TABLE aws_s3_buckets (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("create warehouse table: %v", err)
	}
	if _, err := store.Exec(context.Background(), `INSERT INTO aws_s3_buckets (id, name) VALUES (?, ?)`, "bucket-1", "bucket-a"); err != nil {
		t.Fatalf("insert warehouse row: %v", err)
	}
	if _, err := store.Exec(context.Background(), `INSERT INTO aws_s3_buckets (id, name) VALUES (?, ?)`, "bucket-2", "bucket-b"); err != nil {
		t.Fatalf("insert warehouse row: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded warehouse: %v", err)
	}

	configureDirectQuerySQLiteEnv(t, tempDir, warehousePath)
	queryFormat = FormatJSON
	queryLimit = 1

	output := captureStdout(t, func() {
		if err := runQueryDirect(queryCmd, []string{"SELECT", "name", "FROM", "aws_s3_buckets", "LIMIT", "2"}); err != nil {
			t.Fatalf("runQueryDirect failed: %v", err)
		}
	})

	if !strings.Contains(output, `"count": 2`) {
		t.Fatalf("expected direct query to preserve explicit limit, got %s", output)
	}
}

func TestPrepareDirectMetadataQuery_RejectsMutatingPragma(t *testing.T) {
	if _, _, _, err := prepareDirectMetadataQuery("PRAGMA journal_mode=WAL"); err == nil || !strings.Contains(err.Error(), "read-only PRAGMA") {
		t.Fatalf("expected read-only PRAGMA rejection, got %v", err)
	}
}

func configureDirectQuerySQLiteEnv(t *testing.T, tempDir, warehousePath string) {
	t.Helper()

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
}
