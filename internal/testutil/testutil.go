package testutil

import (
	"context"
	"io"
	"log/slog"
	"testing"
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
