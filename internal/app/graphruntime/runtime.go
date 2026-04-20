package graphruntime

import (
	"context"
	"log/slog"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type Config struct {
	GraphSnapshotPath          string
	GraphSnapshotMaxRetained   int
	GraphFreshnessDefaultSLA   time.Duration
	GraphFreshnessProviderSLAs map[string]time.Duration
	AuditRetentionDays         int
	SessionRetentionDays       int
	GraphRetentionDays         int
	AccessReviewRetentionDays  int
}

type BuildSnapshotState struct {
	State       GraphBuildState
	LastBuildAt time.Time
	LastError   string
}

type TenantShardManager interface {
	GraphForTenant(source *graph.Graph, tenantID string) *graph.Graph
}

type Dependencies struct {
	Logger                              func() *slog.Logger
	Config                              func() *Config
	SetGraphSnapshots                   func(*graph.GraphPersistenceStore)
	GraphSnapshots                      func() *graph.GraphPersistenceStore
	BackgroundContext                   func() context.Context
	CurrentLiveSecurityGraph            func() *graph.Graph
	CurrentConfiguredSecurityGraphStore func(context.Context) (graph.GraphStore, error)
	WaitForGraph                        func(context.Context) bool
	HasGraphReadySignal                 func() bool
	EnsureTenantSecurityGraphShards     func() TenantShardManager
	RetainHotSecurityGraph              func() bool
	BuildSnapshotState                  func() BuildSnapshotState
}

type Runtime struct {
	deps Dependencies
}

func NewRuntime(deps Dependencies) *Runtime {
	return &Runtime{deps: deps}
}

func (a *Runtime) logger() *slog.Logger {
	if a == nil || a.deps.Logger == nil {
		return nil
	}
	return a.deps.Logger()
}

func (a *Runtime) config() *Config {
	if a == nil || a.deps.Config == nil {
		return nil
	}
	return a.deps.Config()
}

func (a *Runtime) setGraphSnapshots(store *graph.GraphPersistenceStore) {
	if a == nil || a.deps.SetGraphSnapshots == nil {
		return
	}
	a.deps.SetGraphSnapshots(store)
}

func (a *Runtime) graphSnapshots() *graph.GraphPersistenceStore {
	if a == nil || a.deps.GraphSnapshots == nil {
		return nil
	}
	return a.deps.GraphSnapshots()
}

func (a *Runtime) backgroundContext() context.Context {
	if a == nil || a.deps.BackgroundContext == nil {
		return context.Background()
	}
	if ctx := a.deps.BackgroundContext(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func (a *Runtime) currentLiveSecurityGraph() *graph.Graph {
	if a == nil || a.deps.CurrentLiveSecurityGraph == nil {
		return nil
	}
	return a.deps.CurrentLiveSecurityGraph()
}

func (a *Runtime) currentConfiguredSecurityGraphStore(ctx context.Context) (graph.GraphStore, error) {
	if a == nil || a.deps.CurrentConfiguredSecurityGraphStore == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return a.deps.CurrentConfiguredSecurityGraphStore(ctx)
}

func (a *Runtime) waitForGraph(ctx context.Context) bool {
	if a == nil || a.deps.WaitForGraph == nil {
		return false
	}
	return a.deps.WaitForGraph(ctx)
}

func (a *Runtime) hasGraphReadySignal() bool {
	if a == nil || a.deps.HasGraphReadySignal == nil {
		return false
	}
	return a.deps.HasGraphReadySignal()
}

func (a *Runtime) ensureTenantSecurityGraphShards() TenantShardManager {
	if a == nil || a.deps.EnsureTenantSecurityGraphShards == nil {
		return nil
	}
	return a.deps.EnsureTenantSecurityGraphShards()
}

func (a *Runtime) retainHotSecurityGraph() bool {
	if a == nil || a.deps.RetainHotSecurityGraph == nil {
		return false
	}
	return a.deps.RetainHotSecurityGraph()
}

func (a *Runtime) buildSnapshotState() BuildSnapshotState {
	if a == nil || a.deps.BuildSnapshotState == nil {
		return BuildSnapshotState{}
	}
	return a.deps.BuildSnapshotState()
}
