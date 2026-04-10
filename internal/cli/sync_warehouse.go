package cli

import (
	"context"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/warehouse"
)

var openSyncWarehouseFn = openSyncWarehouse

func openSyncWarehouse(ctx context.Context) (warehouse.DataWarehouse, error) {
	return app.OpenWarehouse(ctx, app.LoadConfig())
}

func closeSyncWarehouse(store warehouse.DataWarehouse) error {
	if closer, ok := store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
