package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	sf "github.com/snowflakedb/gosnowflake"
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
	remediation TEXT,
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
	remediation, metadata, first_seen, last_seen, resolved_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-postgres-finding",
		"policy-legacy",
		"Legacy finding",
		"high",
		"OPEN",
		"bucket-1",
		"s3_bucket",
		`{"name":"bucket-1"}`,
		"legacy postgres finding",
		"lock down bucket policy",
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
	if finding.Remediation != "lock down bucket policy" {
		t.Fatalf("Remediation = %q, want lock down bucket policy", finding.Remediation)
	}

	var count int
	if err := appStateDB.QueryRow(`SELECT COUNT(*) FROM cerebro_findings WHERE id = ?`, "legacy-postgres-finding").Scan(&count); err != nil {
		t.Fatalf("count migrated findings: %v", err)
	}
	if count != 1 {
		t.Fatalf("migrated finding rows = %d, want 1", count)
	}
}

func TestAppStateDatabaseURLUsesWarehousePostgresDSNAcrossBackends(t *testing.T) {
	testCases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "snowflake backend still uses warehouse postgres dsn for app state",
			cfg: &Config{
				WarehouseBackend:     "snowflake",
				WarehousePostgresDSN: "postgres://app-state",
			},
			want: "postgres://app-state",
		},
		{
			name: "job database url does not drive app state",
			cfg: &Config{
				WarehouseBackend: "snowflake",
				JobDatabaseURL:   "postgres://jobs",
			},
			want: "",
		},
		{
			name: "warehouse postgres dsn wins over job database url",
			cfg: &Config{
				WarehouseBackend:     "postgres",
				WarehousePostgresDSN: "postgres://app-state",
				JobDatabaseURL:       "postgres://jobs",
			},
			want: "postgres://app-state",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{Config: tc.cfg}
			if got := a.appStateDatabaseURL(); got != tc.want {
				t.Fatalf("appStateDatabaseURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsMissingSnowflakeTableErr(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "wrapped app state table lookup failure",
			err: fmt.Errorf("query failed: %w", &sf.SnowflakeError{
				Number:  snowflakeErrObjectNotExist,
				Message: "Object 'DB.SCHEMA.CEREBRO_FINDINGS' does not exist.",
			}),
			want: true,
		},
		{
			name: "not authorized responses are not swallowed",
			err: &sf.SnowflakeError{
				Number:  sf.ErrObjectNotExistOrAuthorized,
				Message: "Object 'DB.SCHEMA.AGENT_SESSIONS' does not exist or not authorized.",
			},
			want: false,
		},
		{
			name: "driver object missing code matches known tables",
			err: &sf.SnowflakeError{
				Number:  sf.ErrObjectNotExistOrAuthorized,
				Message: "Object 'DB.SCHEMA.AGENT_SESSIONS' does not exist.",
			},
			want: true,
		},
		{
			name: "non table object failures are not swallowed",
			err: &sf.SnowflakeError{
				Number:  snowflakeErrObjectNotExist,
				Message: "Database 'DB' does not exist.",
			},
			want: false,
		},
		{
			name: "other snowflake error codes are not treated as missing tables",
			err: &sf.SnowflakeError{
				Number:  sf.ErrRoleNotExist,
				Message: "Role 'ANALYST' does not exist.",
			},
			want: false,
		},
		{
			name: "plain string errors are ignored",
			err:  errors.New("SQL compilation error: unknown table FOO"),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMissingSnowflakeTableErr(tc.err); got != tc.want {
				t.Fatalf("isMissingSnowflakeTableErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
