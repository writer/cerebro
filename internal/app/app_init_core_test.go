package app

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

var registerPostgresStubDriverOnce sync.Once

type postgresStubDriver struct{}

type postgresStubConn struct{}

type postgresStubRows struct{}

func (postgresStubDriver) Open(string) (driver.Conn, error) { return postgresStubConn{}, nil }

func (postgresStubConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }

func (postgresStubConn) Close() error { return nil }

func (postgresStubConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }

func (postgresStubConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

func (postgresStubConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return postgresStubRows{}, nil
}

func (postgresStubConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func (postgresStubRows) Columns() []string { return nil }

func (postgresStubRows) Close() error { return nil }

func (postgresStubRows) Next([]driver.Value) error { return io.EOF }

func openPostgresStubDB(t *testing.T) *sql.DB {
	t.Helper()
	registerPostgresStubDriverOnce.Do(func() {
		sql.Register("app-init-postgres-stub", postgresStubDriver{})
	})
	db, err := sql.Open("app-init-postgres-stub", "")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInitFindings_FallsBackToConfiguredWarehouseMetadata(t *testing.T) {
	a := &App{
		Config: &Config{
			WarehouseBackend:  "snowflake",
			SnowflakeDatabase: "RAW",
			SnowflakeSchema:   "PUBLIC",
		},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{DBFunc: func() *sql.DB { return &sql.DB{} }},
	}

	a.initFindings()

	if a.SnowflakeFindings == nil {
		t.Fatal("expected snowflake findings store to be initialized")
	}

	schema := reflect.ValueOf(a.SnowflakeFindings).Elem().FieldByName("schema").String()
	if schema != "RAW.PUBLIC" {
		t.Fatalf("expected schema RAW.PUBLIC, got %q", schema)
	}
}

func TestInitFindings_FallsBackToSQLiteWhenWarehouseHasNoDB(t *testing.T) {
	a := &App{
		Config:    &Config{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{},
	}
	t.Setenv("CEREBRO_DB_PATH", filepath.Join(t.TempDir(), "findings.db"))

	a.initFindings()

	if a.SnowflakeFindings != nil {
		t.Fatal("expected no snowflake findings store when warehouse DB is nil")
	}
	if _, ok := a.Findings.(*findings.SQLiteStore); !ok {
		t.Fatalf("expected sqlite findings store fallback, got %T", a.Findings)
	}
}

func TestInitFindings_UsesPostgresStoreForPostgresWarehouse(t *testing.T) {
	db := openPostgresStubDB(t)
	a := &App{
		Config: &Config{
			WarehouseBackend:             "postgres",
			FindingsSemanticDedupEnabled: false,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{
			DBFunc:         func() *sql.DB { return db },
			SchemaValue:    "public",
			AppSchemaValue: "cerebro",
		},
	}

	a.initFindings()

	store, ok := a.Findings.(*findings.PostgresStore)
	if !ok {
		t.Fatalf("expected postgres findings store, got %T", a.Findings)
	}
	if a.SnowflakeFindings != nil {
		t.Fatal("expected snowflake findings store to remain nil for postgres warehouse backend")
	}
	if store == nil {
		t.Fatal("expected postgres findings store to be initialized")
	}
}

func TestInitFindings_UsesPostgresStoreWhenAppStateDatabaseConfigured(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := findings.NewPostgresStore(db).EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema() error = %v", err)
	}

	a := &App{
		Config: &Config{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)

	a.initFindings()

	if _, ok := a.Findings.(*findings.PostgresStore); !ok {
		t.Fatalf("expected postgres findings store, got %T", a.Findings)
	}
	if a.SnowflakeFindings != nil {
		t.Fatal("expected legacy snowflake findings store to stay nil when app-state postgres is configured")
	}
}

func TestNewInMemoryFindingsStore_UsesConfiguredBounds(t *testing.T) {
	var logs bytes.Buffer
	a := &App{
		Config: &Config{
			FindingsMaxInMemory:          42,
			FindingsResolvedRetention:    12 * time.Hour,
			FindingsSemanticDedupEnabled: false,
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	store := a.newInMemoryFindingsStore()
	cfg := store.Config()
	if cfg.MaxFindings != 42 {
		t.Fatalf("expected max findings 42, got %d", cfg.MaxFindings)
	}
	if cfg.ResolvedRetention != 12*time.Hour {
		t.Fatalf("expected resolved retention 12h, got %s", cfg.ResolvedRetention)
	}
	if cfg.SemanticDedup {
		t.Fatal("expected semantic dedup to follow config and be disabled")
	}
	if !strings.Contains(logs.String(), "using in-memory findings store") {
		t.Fatalf("expected in-memory store log, got %q", logs.String())
	}
}

func TestNewInMemoryFindingsStore_WarnsOnExplicitUnlimitedConfig(t *testing.T) {
	var logs bytes.Buffer
	a := &App{
		Config: &Config{
			FindingsMaxInMemory:       0,
			FindingsResolvedRetention: 0,
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	_ = a.newInMemoryFindingsStore()

	if !strings.Contains(logs.String(), "configured without size or retention bounds") {
		t.Fatalf("expected unlimited findings warning, got %q", logs.String())
	}
}

func TestInitWarehouse_UsesSQLiteBackend(t *testing.T) {
	a := &App{
		Config: &Config{
			WarehouseBackend:    "sqlite",
			WarehouseSQLitePath: filepath.Join(t.TempDir(), "warehouse.db"),
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := a.initWarehouse(context.Background()); err != nil {
		t.Fatalf("init warehouse: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if a.Warehouse == nil {
		t.Fatal("expected sqlite warehouse to be initialized")
	}
	if a.Snowflake != nil {
		t.Fatal("expected snowflake client to stay nil for sqlite backend")
	}
	if got := a.Warehouse.Database(); got != "sqlite" {
		t.Fatalf("expected sqlite warehouse database label, got %q", got)
	}
}

func TestInitLegacySnowflake_UsesSeparateClientForNonSnowflakeWarehouse(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return new(snowflake.Client), nil
	}
	pingSnowflake = func(context.Context, *snowflake.Client) error { return nil }
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	a := &App{
		Config: &Config{
			WarehouseBackend:     "postgres",
			SnowflakeAccount:     "acct",
			SnowflakeUser:        "user",
			SnowflakePrivateKey:  "key",
			WarehousePostgresDSN: "postgres://warehouse",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := a.initLegacySnowflake(context.Background()); err != nil {
		t.Fatalf("initLegacySnowflake() error = %v", err)
	}

	if a.LegacySnowflake == nil {
		t.Fatal("expected legacy snowflake client to be initialized")
	}
	if a.Snowflake != nil {
		t.Fatalf("expected active snowflake warehouse client to stay nil, got %T", a.Snowflake)
	}
	if a.Warehouse != nil {
		t.Fatalf("expected warehouse selection to remain unchanged, got %T", a.Warehouse)
	}
}

func TestAppStateMigrationSnowflakePrefersLegacyClient(t *testing.T) {
	active := new(snowflake.Client)
	legacy := new(snowflake.Client)
	a := &App{Snowflake: active, LegacySnowflake: legacy}

	if got := a.appStateMigrationSnowflake(); got != legacy {
		t.Fatalf("expected legacy snowflake migration source, got %p want %p", got, legacy)
	}
}

func TestRotateSnowflakeClientPreservesWarehouseWhenUsingLegacySource(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return new(snowflake.Client), nil
	}
	pingSnowflake = func(context.Context, *snowflake.Client) error { return nil }
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	existingWarehouse := &warehouse.MemoryWarehouse{}
	oldLegacy := new(snowflake.Client)
	a := &App{
		Config: &Config{
			WarehouseBackend:    "postgres",
			SnowflakeAccount:    "acct",
			SnowflakeUser:       "user",
			SnowflakePrivateKey: "key",
		},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse:       existingWarehouse,
		LegacySnowflake: oldLegacy,
	}

	if err := a.rotateSnowflakeClient(context.Background(), a.Config); err != nil {
		t.Fatalf("rotateSnowflakeClient() error = %v", err)
	}

	if a.Warehouse != existingWarehouse {
		t.Fatalf("expected warehouse selection to stay unchanged, got %T", a.Warehouse)
	}
	if a.Snowflake != nil {
		t.Fatalf("expected active snowflake client to remain nil, got %T", a.Snowflake)
	}
	if a.LegacySnowflake == nil || a.LegacySnowflake == oldLegacy {
		t.Fatal("expected legacy snowflake client to rotate independently")
	}
}

func TestInitFindings_UsesSQLiteStoreForSQLiteWarehouse(t *testing.T) {
	a := &App{
		Config: &Config{
			WarehouseBackend:    "sqlite",
			WarehouseSQLitePath: filepath.Join(t.TempDir(), "warehouse.db"),
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := a.initWarehouse(context.Background()); err != nil {
		t.Fatalf("init warehouse: %v", err)
	}
	t.Setenv("CEREBRO_DB_PATH", filepath.Join(t.TempDir(), "findings.db"))

	a.initFindings()

	if _, ok := a.Findings.(*findings.SQLiteStore); !ok {
		t.Fatalf("expected sqlite findings store for sqlite warehouse, got %T", a.Findings)
	}
	if a.SnowflakeFindings != nil {
		t.Fatal("expected no snowflake findings store for sqlite warehouse backend")
	}
}

func TestInitIdentityGraphResolverUsesTenantReadScope(t *testing.T) {
	a := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	now := time.Now().UTC()
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now.Add(-24 * time.Hour),
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:tenant-a",
		Kind:      graph.NodeKindBucket,
		Name:      "tenant-a",
		Provider:  "aws",
		Account:   "123456789012",
		TenantID:  "tenant-a",
		Risk:      graph.RiskHigh,
		CreatedAt: now.Add(-48 * time.Hour),
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:tenant-b",
		Kind:      graph.NodeKindBucket,
		Name:      "tenant-b",
		Provider:  "aws",
		Account:   "123456789012",
		TenantID:  "tenant-b",
		Risk:      graph.RiskHigh,
		CreatedAt: now.Add(-48 * time.Hour),
	})
	g.AddEdge(&graph.Edge{ID: "alice-tenant-a", Source: "user:alice", Target: "bucket:tenant-a", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "alice-tenant-b", Source: "user:alice", Target: "bucket:tenant-b", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	a.setSecurityGraph(g)
	a.initIdentity()

	review, err := a.Identity.CreateReview(graph.WithTenantScope(context.Background(), "tenant-a"), &identity.AccessReview{
		Name:             "Tenant scoped review",
		CreatedBy:        "secops@example.com",
		GenerationSource: "graph",
	})
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if len(review.Items) != 1 {
		t.Fatalf("expected one tenant-scoped item, got %d", len(review.Items))
	}
	if got := review.Items[0].Metadata["resource_id"]; got != "bucket:tenant-a" {
		t.Fatalf("expected tenant-a resource only, got %#v", got)
	}
}

func TestInitIdentityGraphResolverUsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	a := &App{
		Config: &Config{
			GraphTenantShardIdleTTL:         10 * time.Minute,
			GraphTenantWarmShardTTL:         time.Hour,
			GraphTenantWarmShardMaxRetained: 1,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	now := time.Now().UTC()
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now.Add(-24 * time.Hour),
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:tenant-a",
		Kind:      graph.NodeKindBucket,
		Name:      "tenant-a",
		Provider:  "aws",
		Account:   "123456789012",
		TenantID:  "tenant-a",
		Risk:      graph.RiskHigh,
		CreatedAt: now.Add(-48 * time.Hour),
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:tenant-b",
		Kind:      graph.NodeKindBucket,
		Name:      "tenant-b",
		Provider:  "aws",
		Account:   "123456789012",
		TenantID:  "tenant-b",
		Risk:      graph.RiskHigh,
		CreatedAt: now.Add(-48 * time.Hour),
	})
	g.AddEdge(&graph.Edge{ID: "alice-tenant-a", Source: "user:alice", Target: "bucket:tenant-a", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "alice-tenant-b", Source: "user:alice", Target: "bucket:tenant-b", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	setConfiguredSnapshotGraphFromGraph(t, a, g)
	a.initIdentity()

	if a.currentLiveSecurityGraph() != nil {
		t.Fatalf("expected no hot security graph, got %p", a.currentLiveSecurityGraph())
	}

	review, err := a.Identity.CreateReview(graph.WithTenantScope(context.Background(), "tenant-a"), &identity.AccessReview{
		Name:             "Tenant scoped review",
		CreatedBy:        "secops@example.com",
		GenerationSource: "graph",
	})
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if len(review.Items) != 1 {
		t.Fatalf("expected one tenant-scoped item, got %d", len(review.Items))
	}
	if got := review.Items[0].Metadata["resource_id"]; got != "bucket:tenant-a" {
		t.Fatalf("expected tenant-a resource only, got %#v", got)
	}
}
