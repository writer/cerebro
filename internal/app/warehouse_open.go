package app

import (
	"context"
	"io"
	"log/slog"

	"github.com/writer/cerebro/internal/warehouse"
)

// OpenWarehouse initializes only the configured warehouse backend without wiring the full app.
func OpenWarehouse(ctx context.Context, cfg *Config, logger *slog.Logger) (warehouse.DataWarehouse, error) {
	if cfg == nil {
		cfg = LoadConfig()
	}
	cfg.RefreshProviderAwareConfig()

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	instance := &App{
		Config: cfg,
		Logger: logger,
	}
	if err := instance.initWarehouse(ctx); err != nil {
		return nil, err
	}
	return instance.Warehouse, nil
}
