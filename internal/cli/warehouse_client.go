package cli

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/warehouse"
)

type scheduledSyncStore interface {
	warehouse.QueryWarehouse
	warehouse.ExecWarehouse
}

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

func openScheduleStore() (scheduledSyncStore, func() error, error) {
	cfg := app.LoadConfig()
	if cfg == nil {
		return nil, noopClose, fmt.Errorf("schedule database not configured: set JOB_DATABASE_URL or DATABASE_URL")
	}

	databaseURL := strings.TrimSpace(cfg.JobDatabaseURL)
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(cfg.DatabaseURL)
	}
	if databaseURL == "" {
		return nil, noopClose, fmt.Errorf("schedule database not configured: set JOB_DATABASE_URL or DATABASE_URL")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, noopClose, fmt.Errorf("open schedule database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, noopClose, fmt.Errorf("ping schedule database: %w", err)
	}

	store := postgres.NewPostgresClient(db, "cerebro", "cerebro")
	return store, store.Close, nil
}
