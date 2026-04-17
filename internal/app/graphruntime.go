package app

import (
	"context"
	"log/slog"
	"time"

	appgraphruntime "github.com/writer/cerebro/internal/app/graphruntime"
	"github.com/writer/cerebro/internal/graph"
)

func (a *App) graphRuntime() *appgraphruntime.Runtime {
	if a == nil {
		return nil
	}
	if a.GraphRuntime == nil {
		a.GraphRuntime = a.newGraphRuntime()
	}
	return a.GraphRuntime
}

func (a *App) newGraphRuntime() *appgraphruntime.Runtime {
	if a == nil {
		return nil
	}
	return appgraphruntime.NewRuntime(appgraphruntime.Dependencies{
		Logger:                              func() *slog.Logger { return a.Logger },
		Config:                              a.graphRuntimeConfig,
		SetGraphSnapshots:                   func(store *graph.GraphPersistenceStore) { a.GraphSnapshots = store },
		CurrentLiveSecurityGraph:            a.currentLiveSecurityGraph,
		CurrentConfiguredSecurityGraphStore: a.currentConfiguredSecurityGraphStore,
		WaitForGraph:                        a.WaitForGraph,
		HasGraphReadySignal:                 func() bool { return a.graphReady != nil },
		EnsureTenantSecurityGraphShards:     func() appgraphruntime.TenantShardManager { return a.ensureTenantSecurityGraphShards() },
		RetainHotSecurityGraph:              a.retainHotSecurityGraph,
		BuildSnapshotState: func() appgraphruntime.BuildSnapshotState {
			if a == nil {
				return appgraphruntime.BuildSnapshotState{}
			}
			a.graphBuildMu.RLock()
			defer a.graphBuildMu.RUnlock()
			return appgraphruntime.BuildSnapshotState{
				State:       a.graphBuildState,
				LastBuildAt: a.graphBuildLastAt,
				LastError:   a.graphBuildErr,
			}
		},
	})
}

func (a *App) graphRuntimeConfig() *appgraphruntime.Config {
	if a == nil || a.Config == nil {
		return nil
	}
	providerSLAs := make(map[string]time.Duration, len(a.Config.GraphFreshnessProviderSLAs))
	for provider, duration := range a.Config.GraphFreshnessProviderSLAs {
		providerSLAs[provider] = duration
	}
	return &appgraphruntime.Config{
		GraphSnapshotPath:          a.Config.GraphSnapshotPath,
		GraphSnapshotMaxRetained:   a.Config.GraphSnapshotMaxRetained,
		GraphFreshnessDefaultSLA:   a.Config.GraphFreshnessDefaultSLA,
		GraphFreshnessProviderSLAs: providerSLAs,
		AuditRetentionDays:         a.Config.AuditRetentionDays,
		SessionRetentionDays:       a.Config.SessionRetentionDays,
		GraphRetentionDays:         a.Config.GraphRetentionDays,
		AccessReviewRetentionDays:  a.Config.AccessReviewRetentionDays,
	}
}

func (a *App) initGraphPersistenceStore() {
	if runtime := a.graphRuntime(); runtime != nil {
		runtime.InitGraphPersistenceStore()
	}
}

func (a *App) CurrentSecurityGraph() *graph.Graph {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentSecurityGraph()
	}
	return nil
}

func (a *App) CurrentSecurityGraphForTenant(tenantID string) *graph.Graph {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentSecurityGraphForTenant(tenantID)
	}
	return nil
}

func (a *App) GraphBuildSnapshot() GraphBuildSnapshot {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.GraphBuildSnapshot()
	}
	return GraphBuildSnapshot{}
}

func (a *App) CurrentRetentionStatus() RetentionStatus {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentRetentionStatus()
	}
	return RetentionStatus{}
}

func (a *App) currentOrStoredSecurityGraphView() (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentOrStoredSecurityGraphView()
	}
	return nil, nil
}

func (a *App) currentOrStoredPassiveSecurityGraphView() (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentOrStoredPassiveSecurityGraphView()
	}
	return nil, nil
}

func (a *App) storedSecurityGraphViewWithSnapshotLoader(loader func(store *graph.GraphPersistenceStore) (*graph.Snapshot, error)) (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.StoredSecurityGraphViewWithSnapshotLoader(loader)
	}
	return nil, nil
}

func (a *App) currentOrStoredPassiveGraphSnapshotRecord() (*graph.GraphSnapshotRecord, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentOrStoredPassiveGraphSnapshotRecord()
	}
	return nil, nil
}

func (a *App) currentOrStoredSecurityGraphViewForTenant(tenantID string) (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentOrStoredSecurityGraphViewForTenant(tenantID)
	}
	return nil, nil
}

func (a *App) requireReadableSecurityGraph() (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.RequireReadableSecurityGraph()
	}
	return nil, context.Canceled
}

func (a *App) WaitForReadableSecurityGraph(ctx context.Context) *graph.Graph {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.WaitForReadableSecurityGraph(ctx)
	}
	return nil
}

func (a *App) currentConfiguredSecurityGraphSnapshot(ctx context.Context) (*graph.Snapshot, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentConfiguredSecurityGraphSnapshot(ctx)
	}
	return nil, nil
}

func (a *App) currentConfiguredSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.CurrentConfiguredSecurityGraphView(ctx)
	}
	return nil, nil
}

func (a *App) GraphFreshnessStatusSnapshot(now time.Time) GraphFreshnessStatus {
	if runtime := a.graphRuntime(); runtime != nil {
		return runtime.GraphFreshnessStatusSnapshot(now)
	}
	return GraphFreshnessStatus{}
}
