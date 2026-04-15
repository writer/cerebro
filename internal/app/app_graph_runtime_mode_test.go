package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestConfigAllowMissingGraphStoreEndpoint_LocalSQLite(t *testing.T) {
	cfg := &Config{
		WarehouseBackend:          "sqlite",
		GraphStoreBackend:         string(graph.StoreBackendNeptune),
		GraphStoreNeptuneEndpoint: "",
	}
	if !cfg.allowMissingGraphStoreEndpoint() {
		t.Fatal("expected local sqlite mode to allow a missing Neptune endpoint")
	}

	cfg.WarehouseBackend = "postgres"
	if cfg.allowMissingGraphStoreEndpoint() {
		t.Fatal("expected postgres warehouse mode to require a Neptune endpoint")
	}
}

func TestInitConfiguredSecurityGraphStoreSkipsNeptuneWhenEndpointMissingInLocalSQLiteMode(t *testing.T) {
	app := &App{
		Config: &Config{
			WarehouseBackend:          "sqlite",
			GraphStoreBackend:         string(graph.StoreBackendNeptune),
			GraphStoreNeptuneEndpoint: "",
		},
		configuredSecurityGraphStore: graph.New(),
		configuredSecurityGraphClose: func() error { return nil },
		configuredSecurityGraphReady: true,
	}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err != nil {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v", err)
	}
	if app.configuredSecurityGraphStore != nil {
		t.Fatal("expected configured graph store to be skipped in local sqlite mode")
	}
	if app.configuredSecurityGraphClose != nil {
		t.Fatal("expected configured graph store closer to be cleared in local sqlite mode")
	}
	if app.configuredSecurityGraphReady {
		t.Fatal("expected configured graph store readiness to be false in local sqlite mode")
	}
}
