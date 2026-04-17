package app

import (
	"log/slog"

	"github.com/writer/cerebro/internal/agents"
	apptools "github.com/writer/cerebro/internal/app/tools"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/policy"
	appRuntime "github.com/writer/cerebro/internal/runtime"
)

func (a *App) ToolsRuntime() *apptools.Runtime {
	return a.toolsRuntime()
}

func (a *App) toolsRuntime() *apptools.Runtime {
	if a == nil {
		return nil
	}
	if a.Tools == nil {
		a.Tools = a.newToolsRuntime()
	}
	return a.Tools
}

func (a *App) newToolsRuntime() *apptools.Runtime {
	if a == nil {
		return nil
	}
	return apptools.NewRuntime(apptools.Dependencies{
		Logger:                           func() *slog.Logger { return a.Logger },
		Config:                           a.toolsConfig,
		Agents:                           func() *agents.AgentRegistry { return a.Agents },
		CurrentSecurityGraph:             a.CurrentSecurityGraph,
		RequireReadableSecurityGraph:     a.requireReadableSecurityGraph,
		CurrentOrStoredSecurityGraphView: a.currentOrStoredSecurityGraphView,
		CurrentOrStoredPassiveGraphSnapshotRecord: a.currentOrStoredPassiveGraphSnapshotRecord,
		MutateSecurityGraph:                       a.MutateSecurityGraph,
		ExecutionStore:                            func() executionstore.Store { return a.ExecutionStore },
		Findings:                                  func() findings.FindingStore { return a.Findings },
		GraphSnapshots:                            func() *graph.GraphPersistenceStore { return a.GraphSnapshots },
		Policy:                                    func() *policy.Engine { return a.Policy },
		Identity:                                  func() *identity.Service { return a.Identity },
		RemoteTools:                               func() *agents.RemoteToolProvider { return a.RemoteTools },
		RuntimeRespond:                            func() *appRuntime.ResponseEngine { return a.RuntimeRespond },
		NewSharedActionExecutor:                   a.newSharedActionExecutor,
	})
}

func (a *App) toolsConfig() *apptools.Config {
	if a == nil || a.Config == nil {
		return nil
	}
	return &apptools.Config{
		CerebroSimulateNeedsApproval:     a.Config.CerebroSimulateNeedsApproval,
		CerebroAccessReviewNeedsApproval: a.Config.CerebroAccessReviewNeedsApproval,
		ExecutionStoreFile:               a.Config.ExecutionStoreFile,
		GraphSnapshotPath:                a.Config.GraphSnapshotPath,
		GraphSnapshotMaxRetained:         a.Config.GraphSnapshotMaxRetained,
	}
}

func (a *App) cerebroTools() []agents.Tool {
	if runtime := a.toolsRuntime(); runtime != nil {
		return runtime.Catalog()
	}
	return nil
}
