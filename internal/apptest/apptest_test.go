package apptest

import (
	"testing"

	"github.com/writer/cerebro/internal/testutil"
)

func TestNewAppProvidesReportPaths(t *testing.T) {
	app := NewApp(t)
	if app == nil {
		t.Fatal("expected app")
	}
	if app.Config == nil {
		t.Fatal("expected config")
	}
	if app.Config.PlatformReportRunStateFile == "" {
		t.Fatal("expected report state file")
	}
	if app.Config.PlatformReportSnapshotPath == "" {
		t.Fatal("expected report snapshot path")
	}
}

func TestNewAppWithWarehouseUsesInjectedWarehouse(t *testing.T) {
	store := testutil.NewMemoryWarehouse()
	app := NewAppWithWarehouse(t, store)
	if app.Warehouse != store {
		t.Fatal("expected injected warehouse")
	}
}
