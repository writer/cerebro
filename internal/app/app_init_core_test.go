package app

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"testing"

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
