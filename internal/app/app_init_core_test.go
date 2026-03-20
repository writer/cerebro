package app

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/warehouse"
)

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

func TestInitIdentityGraphResolverUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
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
	a.GraphSnapshots = mustPersistToolGraph(t, g)
	a.initIdentity()

	if a.CurrentSecurityGraph() != nil {
		t.Fatalf("expected no live security graph, got %p", a.CurrentSecurityGraph())
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
