package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type failingMutationGraphStore struct {
	graph.GraphStore
	upsertNodeErr error
}

func (s *failingMutationGraphStore) UpsertNode(context.Context, *graph.Node) error {
	return s.upsertNodeErr
}

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

func TestSecondaryGraphStoreConfigClearsDualWriteFields(t *testing.T) {
	t.Parallel()

	cfg := (&Config{
		GraphStoreBackend:                     string(graph.StoreBackendSpanner),
		GraphStoreSpannerDatabase:             "projects/test/instances/dev/databases/primary",
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
		t.Fatalf("secondary graphStoreBackend() = %q, want %q", got, graph.StoreBackendNeptune)
	}
	if got := cfg.graphStoreSecondaryBackend(); got != "" {
		t.Fatalf("secondary graphStoreSecondaryBackend() = %q, want empty", got)
	}
	if cfg.dualWriteGraphStoreEnabled() {
		t.Fatal("expected projected secondary config to disable nested dual-write")
	}
	if strings.TrimSpace(cfg.GraphStoreDualWriteMode) != "" {
		t.Fatalf("projected GraphStoreDualWriteMode = %q, want empty", cfg.GraphStoreDualWriteMode)
	}
	if strings.TrimSpace(cfg.GraphStoreDualWriteReconciliationPath) != "" {
		t.Fatalf("projected GraphStoreDualWriteReconciliationPath = %q, want empty", cfg.GraphStoreDualWriteReconciliationPath)
	}
	if cfg.GraphStoreDualWriteReplayEnabled {
		t.Fatal("expected projected GraphStoreDualWriteReplayEnabled to be false")
	}
}

func TestWrapConfiguredSecurityGraphStoreWithDualWriteBestEffortWithoutQueuePathDoesNotPanic(t *testing.T) {
	t.Parallel()

	primaryStore := graph.New()
	primaryProvider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendSpanner,
		handle: graphStoreBackendHandle{
			Store: primaryStore,
			Close: func() error { return nil },
		},
	}
	secondaryProvider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendNeptune,
		handle: graphStoreBackendHandle{
			Store: &failingMutationGraphStore{
				GraphStore:    graph.New(),
				upsertNodeErr: errors.New("secondary write failed"),
			},
			Close: func() error { return nil },
		},
	}

	app := &App{
		Config: &Config{
			GraphStoreBackend:                          string(graph.StoreBackendSpanner),
			GraphStoreSpannerDatabase:                  "projects/test/instances/dev/databases/primary",
			GraphStoreSecondaryBackend:                 string(graph.StoreBackendNeptune),
			GraphStoreSecondaryNeptuneEndpoint:         "https://example.neptune.amazonaws.com",
			GraphStoreSecondaryNeptuneRegion:           "us-east-1",
			GraphStoreSecondaryNeptunePoolSize:         1,
			GraphStoreSecondaryNeptunePoolDrainTimeout: time.Second,
			GraphStoreDualWriteMode:                    string(graph.DualWriteModeBestEffort),
		},
		graphStoreBackendProviderFactory: func(_ *App, backend graph.StoreBackend) (graphStoreBackendProvider, error) {
			switch backend {
			case graph.StoreBackendSpanner:
				return primaryProvider, nil
			case graph.StoreBackendNeptune:
				return secondaryProvider, nil
			default:
				return nil, errors.New("unexpected backend")
			}
		},
	}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err != nil {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v", err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected best-effort write without queue path to avoid panic, got %v", recovered)
		}
	}()

	if err := app.configuredSecurityGraphStore.UpsertNode(context.Background(), &graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "payments",
	}); err != nil {
		t.Fatalf("UpsertNode() error = %v, want nil in best-effort mode", err)
	}
	if _, ok := primaryStore.GetNode("service:payments"); !ok {
		t.Fatal("expected primary store to persist node despite secondary failure")
	}
}
