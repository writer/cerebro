package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type fakeGraphStoreBackendProvider struct {
	backend graph.StoreBackend
	handle  graphStoreBackendHandle
	err     error
	opened  int
}

func (p *fakeGraphStoreBackendProvider) Backend() graph.StoreBackend {
	return p.backend
}

func (p *fakeGraphStoreBackendProvider) Open(_ context.Context, _ *App) (graphStoreBackendHandle, error) {
	p.opened++
	if p.err != nil {
		return graphStoreBackendHandle{}, p.err
	}
	return p.handle, nil
}

func (p *fakeGraphStoreBackendProvider) LogFields(_ *App) []any {
	return nil
}

func TestInitConfiguredSecurityGraphStoreUsesResolvedProvider(t *testing.T) {
	t.Parallel()

	backing := graph.New()
	backing.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})

	closeCalls := 0
	provider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendNeptune,
		handle: graphStoreBackendHandle{
			Store: backing,
			Close: func() error {
				closeCalls++
				return nil
			},
		},
	}

	app := &App{
		Config: &Config{GraphStoreBackend: string(graph.StoreBackendNeptune)},
		graphStoreBackendProviderFactory: func(_ *App, backend graph.StoreBackend) (graphStoreBackendProvider, error) {
			if backend != graph.StoreBackendNeptune {
				t.Fatalf("provider factory backend = %q, want %q", backend, graph.StoreBackendNeptune)
			}
			return provider, nil
		},
	}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err != nil {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v", err)
	}
	if provider.opened != 1 {
		t.Fatalf("provider opened %d times, want 1", provider.opened)
	}
	if app.configuredSecurityGraphStore == nil {
		t.Fatal("expected configuredSecurityGraphStore to be set")
	}
	if !app.configuredSecurityGraphReady {
		t.Fatal("expected configuredSecurityGraphReady to be true")
	}
	if app.configuredSecurityGraphClose == nil {
		t.Fatal("expected configuredSecurityGraphClose to be set")
	}
	if err := app.configuredSecurityGraphClose(); err != nil {
		t.Fatalf("configuredSecurityGraphClose() error = %v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestInitConfiguredSecurityGraphStoreSkipsNeptuneWhenEndpointMissingInTests(t *testing.T) {
	t.Parallel()

	app := &App{
		Config:                       &Config{GraphStoreBackend: string(graph.StoreBackendNeptune)},
		configuredSecurityGraphStore: graph.New(),
		configuredSecurityGraphClose: func() error { return nil },
		configuredSecurityGraphReady: true,
	}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err != nil {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v", err)
	}
	if app.configuredSecurityGraphStore != nil {
		t.Fatal("expected configuredSecurityGraphStore to be cleared")
	}
	if app.configuredSecurityGraphClose != nil {
		t.Fatal("expected configuredSecurityGraphClose to be cleared")
	}
	if app.configuredSecurityGraphReady {
		t.Fatal("expected configuredSecurityGraphReady to be false")
	}
}

func TestInitConfiguredSecurityGraphStoreReturnsProviderErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("provider unavailable")
	app := &App{
		Config: &Config{GraphStoreBackend: string(graph.StoreBackendNeptune)},
		graphStoreBackendProviderFactory: func(_ *App, backend graph.StoreBackend) (graphStoreBackendProvider, error) {
			if backend != graph.StoreBackendNeptune {
				t.Fatalf("provider factory backend = %q, want %q", backend, graph.StoreBackendNeptune)
			}
			return nil, wantErr
		},
	}

	err := app.initConfiguredSecurityGraphStore(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("initConfiguredSecurityGraphStore() error = %v, want %v", err, wantErr)
	}
}

func TestInitConfiguredSecurityGraphStoreRejectsUnsupportedBackend(t *testing.T) {
	t.Parallel()

	app := &App{Config: &Config{GraphStoreBackend: "unknown"}}

	if err := app.initConfiguredSecurityGraphStore(context.Background()); err == nil {
		t.Fatal("expected initConfiguredSecurityGraphStore() to reject unsupported backend")
	}
}

func TestInitConfiguredSecurityGraphStoreIgnoresDualWriteSettings(t *testing.T) {
	t.Parallel()

	primaryCloseCalls := 0
	primaryProvider := &fakeGraphStoreBackendProvider{
		backend: graph.StoreBackendNeptune,
		handle: graphStoreBackendHandle{
			Store: graph.New(),
			Close: func() error {
				primaryCloseCalls++
				return nil
			},
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
			GraphStoreSecondaryNeptunePoolDrainTimeout: time.Second,
			GraphStoreDualWriteMode:                    string(graph.DualWriteModeBestEffort),
			GraphStoreDualWriteReconciliationPath:      filepath.Join(t.TempDir(), "dual-write-queue.json"),
		},
	}

	app.graphStoreBackendProviderFactory = func(_ *App, backend graph.StoreBackend) (graphStoreBackendProvider, error) {
		if backend != graph.StoreBackendNeptune {
			return nil, errors.New("unexpected backend")
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
	if err := app.configuredSecurityGraphClose(); err != nil {
		t.Fatalf("configuredSecurityGraphClose() error = %v", err)
	}
	if primaryCloseCalls != 1 {
		t.Fatalf("close calls primary=%d, want 1", primaryCloseCalls)
	}
	if secondaryProvider.opened != 0 {
		t.Fatalf("expected secondary provider to remain unused, opened=%d", secondaryProvider.opened)
	}
}
