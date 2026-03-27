package app

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

type fakeEntitySearchBackend struct{}

func (fakeEntitySearchBackend) Backend() graph.EntitySearchBackendType {
	return graph.EntitySearchBackendOpenSearch
}

func (fakeEntitySearchBackend) Search(context.Context, string, graph.EntitySearchOptions) (graph.EntitySearchCollection, error) {
	return graph.EntitySearchCollection{}, nil
}

func (fakeEntitySearchBackend) Suggest(context.Context, string, graph.EntitySuggestOptions) (graph.EntitySuggestCollection, error) {
	return graph.EntitySuggestCollection{}, nil
}

type fakeEntitySearchBackendProvider struct {
	backend graph.EntitySearchBackendType
	handle  entitySearchBackendHandle
	err     error
	opened  int
}

func (p *fakeEntitySearchBackendProvider) Backend() graph.EntitySearchBackendType {
	return p.backend
}

func (p *fakeEntitySearchBackendProvider) Open(_ context.Context, _ *App) (entitySearchBackendHandle, error) {
	p.opened++
	if p.err != nil {
		return entitySearchBackendHandle{}, p.err
	}
	return p.handle, nil
}

func (p *fakeEntitySearchBackendProvider) LogFields(_ *App) []any {
	return nil
}

func TestInitEntitySearchBackendUsesResolvedProvider(t *testing.T) {
	t.Parallel()

	closeCalls := 0
	provider := &fakeEntitySearchBackendProvider{
		backend: graph.EntitySearchBackendOpenSearch,
		handle: entitySearchBackendHandle{
			Backend: fakeEntitySearchBackend{},
			Close: func() error {
				closeCalls++
				return nil
			},
		},
	}

	app := &App{
		Config: &Config{GraphSearchBackend: string(graph.EntitySearchBackendOpenSearch)},
		entitySearchBackendProviderFactory: func(_ *App, backend graph.EntitySearchBackendType) (entitySearchBackendProvider, error) {
			if backend != graph.EntitySearchBackendOpenSearch {
				t.Fatalf("provider factory backend = %q, want %q", backend, graph.EntitySearchBackendOpenSearch)
			}
			return provider, nil
		},
	}

	if err := app.initEntitySearchBackend(context.Background()); err != nil {
		t.Fatalf("initEntitySearchBackend() error = %v", err)
	}
	if provider.opened != 1 {
		t.Fatalf("provider opened %d times, want 1", provider.opened)
	}
	if app.CurrentEntitySearchBackend() == nil {
		t.Fatal("expected configured entity search backend to be set")
	}
	if app.configuredEntitySearchClose == nil {
		t.Fatal("expected configured entity search close hook to be set")
	}
	if err := app.configuredEntitySearchClose(); err != nil {
		t.Fatalf("configuredEntitySearchClose() error = %v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestInitEntitySearchBackendSkipsGraphFallback(t *testing.T) {
	t.Parallel()

	app := &App{
		Config:                        &Config{GraphSearchBackend: string(graph.EntitySearchBackendGraph)},
		configuredEntitySearchBackend: fakeEntitySearchBackend{},
		configuredEntitySearchClose:   func() error { return nil },
	}

	if err := app.initEntitySearchBackend(context.Background()); err != nil {
		t.Fatalf("initEntitySearchBackend() error = %v", err)
	}
	if app.CurrentEntitySearchBackend() != nil {
		t.Fatal("expected configured entity search backend to be cleared")
	}
	if app.configuredEntitySearchClose != nil {
		t.Fatal("expected configured entity search close hook to be cleared")
	}
}

func TestInitEntitySearchBackendReturnsProviderErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("provider unavailable")
	app := &App{
		Config: &Config{GraphSearchBackend: string(graph.EntitySearchBackendOpenSearch)},
		entitySearchBackendProviderFactory: func(_ *App, backend graph.EntitySearchBackendType) (entitySearchBackendProvider, error) {
			if backend != graph.EntitySearchBackendOpenSearch {
				t.Fatalf("provider factory backend = %q, want %q", backend, graph.EntitySearchBackendOpenSearch)
			}
			return nil, wantErr
		},
	}

	err := app.initEntitySearchBackend(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("initEntitySearchBackend() error = %v, want %v", err, wantErr)
	}
}
