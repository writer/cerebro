package app

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestMigrateAppStateMigratesLegacyPostgresFindingsWithoutSnowflake(t *testing.T) {
	ctx := context.Background()

	warehouseDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open warehouse sqlite: %v", err)
	}
	t.Cleanup(func() { _ = warehouseDB.Close() })

	if _, err := warehouseDB.Exec(`ATTACH DATABASE ':memory:' AS cerebro`); err != nil {
		t.Fatalf("attach legacy postgres schema: %v", err)
	}
	if _, err := warehouseDB.Exec(`
CREATE TABLE "cerebro"."findings" (
	id TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	policy_name TEXT NOT NULL,
	severity TEXT NOT NULL,
	status TEXT NOT NULL,
	resource_id TEXT,
	resource_type TEXT,
	resource_data TEXT,
	description TEXT,
	metadata TEXT,
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL,
	resolved_at TIMESTAMP
)`); err != nil {
		t.Fatalf("create legacy findings table: %v", err)
	}

	firstSeen := time.Now().UTC().Add(-2 * time.Hour)
	lastSeen := time.Now().UTC().Add(-time.Hour)
	if _, err := warehouseDB.Exec(`
INSERT INTO "cerebro"."findings" (
	id, policy_id, policy_name, severity, status,
	resource_id, resource_type, resource_data, description,
	metadata, first_seen, last_seen, resolved_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-postgres-finding",
		"policy-legacy",
		"Legacy finding",
		"high",
		"OPEN",
		"bucket-1",
		"s3_bucket",
		`{"name":"bucket-1"}`,
		"legacy postgres finding",
		`{"tenant_id":"tenant-a","signal_type":"security","domain":"infra"}`,
		firstSeen,
		lastSeen,
		nil,
	); err != nil {
		t.Fatalf("insert legacy finding: %v", err)
	}

	appStateDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open app-state sqlite: %v", err)
	}
	t.Cleanup(func() { _ = appStateDB.Close() })

	store := findings.NewPostgresStore(appStateDB)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure app-state findings schema: %v", err)
	}

	a := &App{
		Config: &Config{
			WarehouseBackend: "postgres",
		},
		Findings:   store,
		Warehouse:  &warehouse.MemoryWarehouse{DBFunc: func() *sql.DB { return warehouseDB }, AppSchemaValue: "cerebro"},
		appStateDB: appStateDB,
	}

	if err := a.migrateAppState(ctx); err != nil {
		t.Fatalf("migrateAppState() error = %v", err)
	}

	finding, ok := store.Get("legacy-postgres-finding")
	if !ok {
		t.Fatal("expected legacy postgres finding to migrate without snowflake")
	}
	if finding.PolicyID != "policy-legacy" {
		t.Fatalf("PolicyID = %q, want policy-legacy", finding.PolicyID)
	}
	if finding.TenantID != "tenant-a" {
		t.Fatalf("TenantID = %q, want tenant-a", finding.TenantID)
	}

	var count int
	if err := appStateDB.QueryRow(`SELECT COUNT(*) FROM cerebro_findings WHERE id = ?`, "legacy-postgres-finding").Scan(&count); err != nil {
		t.Fatalf("count migrated findings: %v", err)
	}
	if count != 1 {
		t.Fatalf("migrated finding rows = %d, want 1", count)
	}
}
