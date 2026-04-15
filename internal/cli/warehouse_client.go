package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/warehouse"
)

func cliRunningUnderGoTest() bool {
	if flag.Lookup("test.v") != nil {
		return true
	}
	return strings.HasSuffix(strings.TrimSpace(os.Args[0]), ".test")
}

func noopClose() error {
	return nil
}

func openCLIWarehouse() (warehouse.DataWarehouse, func() error, error) {
	cfg := app.LoadConfig()
	if cfg == nil {
		return nil, noopClose, fmt.Errorf("warehouse not configured: set WAREHOUSE_BACKEND")
	}

	backend := strings.ToLower(strings.TrimSpace(cfg.WarehouseBackend))
	if cliRunningUnderGoTest() && strings.TrimSpace(os.Getenv("WAREHOUSE_BACKEND")) == "" && backend == "sqlite" {
		backend = ""
	}
	if backend == "" {
		return nil, noopClose, fmt.Errorf("warehouse not configured: set WAREHOUSE_BACKEND")
	}

	switch backend {
	case "sqlite":
		store, err := warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{
			Path:      strings.TrimSpace(cfg.WarehouseSQLitePath),
			Database:  "sqlite",
			Schema:    "RAW",
			AppSchema: "CEREBRO",
		})
		if err != nil {
			return nil, noopClose, err
		}
		return store, store.Close, nil
	case "postgres":
		store, err := warehouse.NewPostgresWarehouse(warehouse.PostgresWarehouseConfig{
			DSN:       strings.TrimSpace(cfg.WarehousePostgresDSN),
			AppSchema: "cerebro",
		})
		if err != nil {
			return nil, noopClose, err
		}
		return store, store.Close, nil
	default:
		return nil, noopClose, fmt.Errorf("unsupported warehouse backend %q", backend)
	}
}
