package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

var openSyncWarehouseFn = openSyncWarehouse

func openSyncWarehouse(ctx context.Context) (warehouse.DataWarehouse, error) {
	return app.OpenWarehouse(ctx, app.LoadConfig(), nil)
}

func createSyncWarehouse() (warehouse.DataWarehouse, error) {
	cfg := app.LoadConfig()
	backend := strings.ToLower(strings.TrimSpace(cfg.WarehouseBackend))
	if backend == "" {
		backend = "snowflake"
	}
	switch backend {
	case "snowflake":
		snowflakeCfg := snowflake.DSNConfigFromEnv()
		if missing := snowflakeCfg.MissingFields(); len(missing) > 0 {
			return nil, fmt.Errorf("warehouse not configured: set %s", strings.Join(missing, ", "))
		}
		return snowflake.NewClient(snowflake.ClientConfig{
			Account:    snowflakeCfg.Account,
			User:       snowflakeCfg.User,
			PrivateKey: snowflakeCfg.PrivateKey,
			Database:   snowflakeCfg.Database,
			Schema:     snowflakeCfg.Schema,
			Warehouse:  snowflakeCfg.Warehouse,
			Role:       snowflakeCfg.Role,
		})
	case "postgres":
		dsn := cfg.WarehousePostgresDSN
		if dsn == "" {
			dsn = cfg.JobDatabaseURL
		}
		return warehouse.NewPostgresWarehouse(warehouse.PostgresWarehouseConfig{
			DSN:       dsn,
			AppSchema: "cerebro",
		})
	case "sqlite":
		return warehouse.NewSQLiteWarehouse(warehouse.SQLiteWarehouseConfig{
			Path:      cfg.WarehouseSQLitePath,
			Database:  "sqlite",
			Schema:    "RAW",
			AppSchema: "CEREBRO",
		})
	default:
		return nil, fmt.Errorf("unsupported warehouse backend %q", cfg.WarehouseBackend)
	}
}

func closeSyncWarehouse(store warehouse.DataWarehouse) error {
	if closer, ok := store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
