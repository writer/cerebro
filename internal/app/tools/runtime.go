package tools

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/policy"
	appRuntime "github.com/writer/cerebro/internal/runtime"
)

type Config struct {
	CerebroSimulateNeedsApproval     bool
	CerebroAccessReviewNeedsApproval bool
	ExecutionStoreFile               string
	GraphSnapshotPath                string
	GraphSnapshotMaxRetained         int
}

type Dependencies struct {
	Logger                                    func() *slog.Logger
	Config                                    func() *Config
	Agents                                    func() *agents.AgentRegistry
	CurrentSecurityGraph                      func() *graph.Graph
	RequireReadableSecurityGraph              func() (*graph.Graph, error)
	CurrentOrStoredSecurityGraphView          func() (*graph.Graph, error)
	CurrentOrStoredPassiveGraphSnapshotRecord func() (*graph.GraphSnapshotRecord, error)
	MutateSecurityGraph                       func(context.Context, func(*graph.Graph) error) (*graph.Graph, error)
	ExecutionStore                            func() executionstore.Store
	Findings                                  func() findings.FindingStore
	GraphSnapshots                            func() *graph.GraphPersistenceStore
	Policy                                    func() *policy.Engine
	Identity                                  func() *identity.Service
	RemoteTools                               func() *agents.RemoteToolProvider
	RuntimeRespond                            func() *appRuntime.ResponseEngine
	NewSharedActionExecutor                   func() *actionengine.Executor
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

func (a *Runtime) agents() *agents.AgentRegistry {
	if a == nil || a.deps.Agents == nil {
		return nil
	}
	return a.deps.Agents()
}

func (a *Runtime) CurrentSecurityGraph() *graph.Graph {
	if a == nil || a.deps.CurrentSecurityGraph == nil {
		return nil
	}
	return a.deps.CurrentSecurityGraph()
}

func (a *Runtime) requireReadableSecurityGraph() (*graph.Graph, error) {
	if a == nil || a.deps.RequireReadableSecurityGraph == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return a.deps.RequireReadableSecurityGraph()
}

func (a *Runtime) currentOrStoredSecurityGraphView() (*graph.Graph, error) {
	if a == nil || a.deps.CurrentOrStoredSecurityGraphView == nil {
		return nil, nil
	}
	return a.deps.CurrentOrStoredSecurityGraphView()
}

func (a *Runtime) currentOrStoredPassiveGraphSnapshotRecord() (*graph.GraphSnapshotRecord, error) {
	if a == nil || a.deps.CurrentOrStoredPassiveGraphSnapshotRecord == nil {
		return nil, nil
	}
	return a.deps.CurrentOrStoredPassiveGraphSnapshotRecord()
}

func (a *Runtime) MutateSecurityGraph(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	if a == nil || a.deps.MutateSecurityGraph == nil {
		return nil, fmt.Errorf("security graph not initialized")
	}
	return a.deps.MutateSecurityGraph(ctx, mutate)
}

func (a *Runtime) executionStore() executionstore.Store {
	if a == nil || a.deps.ExecutionStore == nil {
		return nil
	}
	return a.deps.ExecutionStore()
}

func (a *Runtime) findings() findings.FindingStore {
	if a == nil || a.deps.Findings == nil {
		return nil
	}
	return a.deps.Findings()
}

func (a *Runtime) graphSnapshots() *graph.GraphPersistenceStore {
	if a == nil || a.deps.GraphSnapshots == nil {
		return nil
	}
	return a.deps.GraphSnapshots()
}

func (a *Runtime) policy() *policy.Engine {
	if a == nil || a.deps.Policy == nil {
		return nil
	}
	return a.deps.Policy()
}

func (a *Runtime) identity() *identity.Service {
	if a == nil || a.deps.Identity == nil {
		return nil
	}
	return a.deps.Identity()
}

func (a *Runtime) remoteTools() *agents.RemoteToolProvider {
	if a == nil || a.deps.RemoteTools == nil {
		return nil
	}
	return a.deps.RemoteTools()
}

func (a *Runtime) runtimeRespond() *appRuntime.ResponseEngine {
	if a == nil || a.deps.RuntimeRespond == nil {
		return nil
	}
	return a.deps.RuntimeRespond()
}

func (a *Runtime) newSharedActionExecutor() *actionengine.Executor {
	if a == nil || a.deps.NewSharedActionExecutor == nil {
		return nil
	}
	return a.deps.NewSharedActionExecutor()
}
