package app

import (
	"context"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

// ApplySecurityGraphChanges applies CDC-backed graph mutations and falls back to
// a copy-on-write full rebuild only when incremental mutation fails.
func (a *App) ApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, error) {
	if a == nil || a.SecurityGraphBuilder == nil {
		return graph.GraphMutationSummary{}, errGraphNotInitialized()
	}

	a.graphUpdateMu.Lock()
	defer a.graphUpdateMu.Unlock()

	return a.applySecurityGraphChangesLocked(ctx, trigger)
}

// TryApplySecurityGraphChanges attempts a non-blocking graph update. It returns
// applied=false when another graph update already owns the mutation lock.
func (a *App) TryApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, bool, error) {
	if a == nil || a.SecurityGraphBuilder == nil {
		return graph.GraphMutationSummary{}, false, errGraphNotInitialized()
	}
	if !a.graphUpdateMu.TryLock() {
		return graph.GraphMutationSummary{}, false, nil
	}
	defer a.graphUpdateMu.Unlock()

	summary, err := a.applySecurityGraphChangesLocked(ctx, trigger)
	return summary, true, err
}

func (a *App) applySecurityGraphChangesLocked(ctx context.Context, trigger string) (graph.GraphMutationSummary, error) {
	start := time.Now()
	summary, err := a.SecurityGraphBuilder.ApplyChanges(ctx, time.Time{})
	if err != nil {
		a.Logger.Warn("incremental graph apply failed, falling back to full rebuild",
			"trigger", trigger,
			"error", err,
		)
		a.setGraphBuildState(GraphBuildBuilding, time.Time{}, nil)
		if buildErr := a.SecurityGraphBuilder.Build(ctx); buildErr != nil {
			a.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), buildErr)
			return graph.GraphMutationSummary{}, buildErr
		}

		securityGraph := a.SecurityGraphBuilder.Graph()
		meta, activateErr := a.activateBuiltSecurityGraph(ctx, securityGraph)
		if activateErr != nil {
			return graph.GraphMutationSummary{}, activateErr
		}

		summary = a.SecurityGraphBuilder.LastMutation()
		duration := time.Since(start)
		a.Logger.Info("security graph rebuilt after incremental apply failure",
			"trigger", trigger,
			"nodes", meta.NodeCount,
			"edges", meta.EdgeCount,
			"duration", duration,
		)
		a.emitGraphRebuiltEvent(ctx, meta, duration)
		a.emitGraphMutationEvent(ctx, summary, trigger)
		return summary, nil
	}

	if summary.EventsProcessed == 0 {
		currentGraph := a.CurrentSecurityGraph()
		if currentGraph != nil {
			a.setGraphBuildState(GraphBuildSuccess, currentGraph.Metadata().BuiltAt, nil)
		}
		a.Logger.Info("security graph incremental update skipped - no CDC events found", "trigger", trigger)
		return summary, nil
	}

	securityGraph := a.SecurityGraphBuilder.Graph()
	meta, activateErr := a.activateBuiltSecurityGraph(ctx, securityGraph)
	if activateErr != nil {
		return graph.GraphMutationSummary{}, activateErr
	}

	a.Logger.Info("security graph incrementally updated",
		"trigger", trigger,
		"events", summary.EventsProcessed,
		"nodes_added", summary.NodesAdded,
		"nodes_updated", summary.NodesUpdated,
		"nodes_removed", summary.NodesRemoved,
		"nodes", meta.NodeCount,
		"edges", meta.EdgeCount,
		"duration", summary.Duration,
	)
	a.emitGraphMutationEvent(ctx, summary, trigger)
	a.maybeStartGraphConsistencyCheck(trigger, summary)
	return summary, nil
}

func (a *App) maybeStartGraphConsistencyCheck(trigger string, summary graph.GraphMutationSummary) {
	if a == nil || a.SecurityGraphBuilder == nil || a.Config == nil {
		return
	}
	if !a.Config.GraphConsistencyCheckEnabled || summary.Mode != graph.GraphMutationModeIncremental || !summary.HasChanges() {
		return
	}

	now := time.Now().UTC()
	interval := a.Config.GraphConsistencyCheckInterval

	a.graphConsistencyMu.Lock()
	if a.graphConsistencyRun {
		a.graphConsistencyMu.Unlock()
		return
	}
	if interval > 0 && !a.graphConsistencyLast.IsZero() && now.Sub(a.graphConsistencyLast) < interval {
		a.graphConsistencyMu.Unlock()
		return
	}
	a.graphConsistencyRun = true
	a.graphConsistencyLast = now
	a.graphConsistencyWG.Add(1)
	baseCtx := a.graphCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	// #nosec G118 -- cancel is stored for shutdown coordination and also deferred inside the check goroutine.
	checkCtx, cancel := context.WithTimeout(baseCtx, 30*time.Minute)
	a.graphConsistencyCancel = cancel
	a.graphConsistencyMu.Unlock()

	go func() {
		defer a.graphConsistencyWG.Done()
		defer func() {
			a.graphConsistencyMu.Lock()
			a.graphConsistencyCancel = nil
			a.graphConsistencyRun = false
			a.graphConsistencyMu.Unlock()
		}()
		defer cancel()

		candidate, _, err := a.SecurityGraphBuilder.BuildCandidate(checkCtx)
		if err != nil {
			a.Logger.Warn("graph consistency check failed to build candidate",
				"trigger", trigger,
				"error", err,
			)
			return
		}

		live := a.CurrentSecurityGraph()
		if live == nil || candidate == nil {
			return
		}

		diff := graph.DiffSnapshots(graph.CreateSnapshot(live), graph.CreateSnapshot(candidate))
		if !graphDiffHasChanges(diff) {
			a.Logger.Info("graph consistency check passed",
				"trigger", trigger,
				"interval", interval,
				"tables", summary.Tables,
			)
			return
		}

		a.Logger.Warn("graph consistency drift detected",
			"trigger", trigger,
			"interval", interval,
			"tables", summary.Tables,
			"nodes_added", len(diff.NodesAdded),
			"nodes_removed", len(diff.NodesRemoved),
			"nodes_modified", len(diff.NodesModified),
			"edges_added", len(diff.EdgesAdded),
			"edges_removed", len(diff.EdgesRemoved),
		)
	}()
}

func graphDiffHasChanges(diff *graph.GraphDiff) bool {
	if diff == nil {
		return false
	}
	return len(diff.NodesAdded) > 0 ||
		len(diff.NodesRemoved) > 0 ||
		len(diff.NodesModified) > 0 ||
		len(diff.EdgesAdded) > 0 ||
		len(diff.EdgesRemoved) > 0
}

func errGraphNotInitialized() error {
	return fmt.Errorf("security graph not initialized")
}
