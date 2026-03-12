package app

import (
	"bytes"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestInitFindings_FallsBackToConfiguredWarehouseMetadata(t *testing.T) {
	a := &App{
		Config: &Config{
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
