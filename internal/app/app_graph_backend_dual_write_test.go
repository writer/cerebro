package app

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestObserveGraphStoreDualWriteMutationDoesNotWarnPrimaryOnlySuccess(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	app := &App{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	app.observeGraphStoreDualWriteMutation(context.Background(), graph.DualWriteMutationOutcome{
		Mode:               graph.DualWriteModePrimaryOnly,
		Operation:          graph.DualWriteMutationUpsertNode,
		Identifiers:        []string{"service:payments"},
		PrimarySucceeded:   true,
		SecondaryAttempted: false,
	})

	if logs.Len() != 0 {
		t.Fatalf("expected no warn log for successful primary_only mutation, got %q", logs.String())
	}
}

func TestSecondaryGraphStoreConfigRemainsDisabled(t *testing.T) {
	t.Parallel()

	cfg := (&Config{
		GraphStoreBackend:                     string(graph.StoreBackendNeptune),
		GraphStoreSecondaryBackend:            string(graph.StoreBackendNeptune),
		GraphStoreSecondaryNeptuneEndpoint:    "https://example.neptune.amazonaws.com",
		GraphStoreSecondaryNeptuneRegion:      "us-east-1",
		GraphStoreSecondaryNeptunePoolSize:    2,
		GraphStoreSecondarySpannerDatabase:    "projects/test/instances/dev/databases/secondary",
		GraphStoreDualWriteMode:               string(graph.DualWriteModeBestEffort),
		GraphStoreDualWriteReconciliationPath: "/tmp/queue.json",
		GraphStoreDualWriteReplayEnabled:      true,
		GraphStoreDualWriteReplayInterval:     1,
		GraphStoreDualWriteReplayBatchSize:    10,
	}).secondaryGraphStoreConfig()

	if cfg == nil {
		t.Fatal("secondaryGraphStoreConfig() returned nil")
	}
	if got := cfg.graphStoreBackend(); got != graph.StoreBackendNeptune {
		t.Fatalf("graphStoreBackend() = %q, want %q", got, graph.StoreBackendNeptune)
	}
	if got := cfg.graphStoreSecondaryBackend(); got != "" {
		t.Fatalf("graphStoreSecondaryBackend() = %q, want empty", got)
	}
	if cfg.dualWriteGraphStoreEnabled() {
		t.Fatal("expected dual-write to remain disabled")
	}
	if got := cfg.graphStoreDualWriteMode(); got != graph.DualWriteModePrimaryOnly {
		t.Fatalf("graphStoreDualWriteMode() = %q, want %q", got, graph.DualWriteModePrimaryOnly)
	}
}

func TestInitConfiguredSecurityGraphStoreDoesNotWrapDualWrite(t *testing.T) {
	t.Parallel()

	primaryProvider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendNeptune,
		handle: graphStoreBackendHandle{
			Store: graph.New(),
			Close: func() error { return nil },
		},
	}
	secondaryProvider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendNeptune,
		handle: graphStoreBackendHandle{
			Store: graph.New(),
			Close: func() error { return nil },
		},
	}

	app := &App{
		Config: &Config{
			GraphStoreBackend:                          string(graph.StoreBackendNeptune),
			GraphStoreNeptuneEndpoint:                  "https://example.neptune.amazonaws.com",
			GraphStoreSecondaryBackend:                 string(graph.StoreBackendNeptune),
			GraphStoreSecondaryNeptuneEndpoint:         "https://example.neptune.amazonaws.com",
			GraphStoreSecondaryNeptuneRegion:           "us-east-1",
			GraphStoreSecondaryNeptunePoolSize:         1,
			GraphStoreSecondaryNeptunePoolDrainTimeout: 1,
			GraphStoreDualWriteMode:                    string(graph.DualWriteModeBestEffort),
		},
	}
	app.graphStoreBackendProviderFactory = func(_ *App, backend graph.StoreBackend) (graphStoreBackendProvider, error) {
		if backend != graph.StoreBackendNeptune {
			t.Fatalf("backend = %q, want %q", backend, graph.StoreBackendNeptune)
		}
		if primaryProvider.opened == 0 {
			return primaryProvider, nil
		}
		return secondaryProvider, nil
	}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err != nil {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v", err)
	}
	if _, ok := app.configuredSecurityGraphStore.(*graph.DualWriteGraphStore); ok {
		t.Fatalf("configuredSecurityGraphStore = %T, want direct neptune store", app.configuredSecurityGraphStore)
	}
	if secondaryProvider.opened != 0 {
		t.Fatalf("expected secondary provider to remain unused, opened=%d", secondaryProvider.opened)
	}
}
