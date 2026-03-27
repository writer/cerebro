package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

type fakeEntitySearchBackend struct {
	checkErr error
	checked  int32
}

func (b *fakeEntitySearchBackend) Backend() graph.EntitySearchBackendType {
	return graph.EntitySearchBackendOpenSearch
}

func (b *fakeEntitySearchBackend) Search(context.Context, string, graph.EntitySearchOptions) (graph.EntitySearchCollection, error) {
	return graph.EntitySearchCollection{}, nil
}

func (b *fakeEntitySearchBackend) Suggest(context.Context, string, graph.EntitySuggestOptions) (graph.EntitySuggestCollection, error) {
	return graph.EntitySuggestCollection{}, nil
}

func (b *fakeEntitySearchBackend) Check(context.Context) error {
	atomic.AddInt32(&b.checked, 1)
	return b.checkErr
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
	backend := &fakeEntitySearchBackend{}
	provider := &fakeEntitySearchBackendProvider{
		backend: graph.EntitySearchBackendOpenSearch,
		handle: entitySearchBackendHandle{
			Backend: backend,
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
	if got := atomic.LoadInt32(&backend.checked); got != 1 {
		t.Fatalf("backend readiness checks = %d, want 1", got)
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
		configuredEntitySearchBackend: &fakeEntitySearchBackend{},
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

func TestInitEntitySearchBackendAllowsBootstrapPendingReadiness(t *testing.T) {
	t.Parallel()

	closeCalls := 0
	provider := &fakeEntitySearchBackendProvider{
		backend: graph.EntitySearchBackendOpenSearch,
		handle: entitySearchBackendHandle{
			Backend: &fakeEntitySearchBackend{
				checkErr: &graph.EntitySearchBootstrapPendingError{
					Backend: graph.EntitySearchBackendOpenSearch,
					Reason:  "index bootstrap pending",
				},
			},
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
	if app.CurrentEntitySearchBackend() == nil {
		t.Fatal("expected bootstrap-pending backend to remain configured")
	}
	if closeCalls != 0 {
		t.Fatalf("close calls = %d, want 0", closeCalls)
	}
}

func TestInitEntitySearchBackendReturnsNonBootstrapReadinessErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("opensearch unavailable")
	closeCalls := 0
	provider := &fakeEntitySearchBackendProvider{
		backend: graph.EntitySearchBackendOpenSearch,
		handle: entitySearchBackendHandle{
			Backend: &fakeEntitySearchBackend{checkErr: wantErr},
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

	err := app.initEntitySearchBackend(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("initEntitySearchBackend() error = %v, want %v", err, wantErr)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

type snapshotCountingHydrationStore struct {
	graph.GraphStore
	snapshotCount atomic.Int32
}

func (s *snapshotCountingHydrationStore) Snapshot(ctx context.Context) (*graph.Snapshot, error) {
	s.snapshotCount.Add(1)
	return s.GraphStore.Snapshot(ctx)
}

func TestResolveCurrentEntitySearchGraphUsesConfiguredView(t *testing.T) {
	t.Parallel()

	backing := graph.New()
	backing.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", TenantID: "tenant-a"})
	backing.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "Shared"})
	backing.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	backing.AddEdge(&graph.Edge{
		ID:     "service:payments->service:shared:depends_on",
		Source: "service:payments",
		Target: "service:shared",
		Kind:   graph.EdgeKindDependsOn,
		Effect: graph.EdgeEffectAllow,
	})

	store := &snapshotCountingHydrationStore{GraphStore: backing}
	app := &App{
		configuredSecurityGraphStore: store,
		configuredSecurityGraphReady: true,
	}

	view, err := app.resolveCurrentEntitySearchGraph(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("resolveCurrentEntitySearchGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("expected tenant-scoped graph view")
	}
	if _, ok := view.GetNode("service:payments"); !ok {
		t.Fatal("expected tenant node in resolved view")
	}
	if _, ok := view.GetNode("service:shared"); !ok {
		t.Fatal("expected shared node in resolved view")
	}
	if _, ok := view.GetNode("service:tenant-b"); ok {
		t.Fatal("expected foreign tenant node to be excluded from resolved view")
	}
	if got := store.snapshotCount.Load(); got != 1 {
		t.Fatalf("expected one configured snapshot per graph resolution, got %d", got)
	}
}

func TestResolveCurrentEntitySearchGraphAllowsSharedOnlyTenantData(t *testing.T) {
	t.Parallel()

	backing := graph.New()
	backing.AddNode(&graph.Node{ID: "service:shared", Kind: graph.NodeKindService, Name: "Shared"})

	app := &App{
		configuredSecurityGraphStore: backing,
		configuredSecurityGraphReady: true,
	}

	view, err := app.resolveCurrentEntitySearchGraph(context.Background(), "tenant-missing")
	if err != nil {
		t.Fatalf("resolveCurrentEntitySearchGraph() error = %v", err)
	}
	if view == nil {
		t.Fatal("expected shared-only graph view for tenant-scoped request")
	}
	if _, ok := view.GetNode("service:shared"); !ok {
		t.Fatal("expected shared entity in resolved graph view")
	}
}
