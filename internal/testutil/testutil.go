package testutil

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/writer/cerebro/internal/warehouse"
)

// Logger returns a discard-backed logger for tests that need structured logging.
func Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Context returns a cancellable context and registers cancellation with t.Cleanup.
func Context(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// NewMemoryWarehouse returns a warehouse test double with stable metadata defaults.
func NewMemoryWarehouse() *warehouse.MemoryWarehouse {
	return &warehouse.MemoryWarehouse{
		DatabaseValue:  "TEST_DB",
		SchemaValue:    "PUBLIC",
		AppSchemaValue: "CEREBRO_APP",
	}
}
