package app

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

func (a *App) materializePersistedWorkloadScans(ctx context.Context, g *graph.Graph) (workloadscan.GraphMaterializationResult, error) {
	if a == nil || a.Config == nil || g == nil {
		return workloadscan.GraphMaterializationResult{}, nil
	}
	storePath := a.Config.WorkloadScanStateFile
	if storePath == "" {
		return workloadscan.GraphMaterializationResult{}, nil
	}
	var (
		store workloadscan.RunStore
		err   error
	)
	if shared := a.executionStoreForPath(storePath); shared != nil {
		store = workloadscan.NewSQLiteRunStoreWithExecutionStore(shared)
	} else {
		store, err = workloadscan.NewSQLiteRunStore(storePath)
		if err != nil {
			return workloadscan.GraphMaterializationResult{}, err
		}
	}
	defer func() { _ = store.Close() }()

	const pageSize = 200
	runs := make([]workloadscan.RunRecord, 0)
	for offset := 0; ; offset += pageSize {
		page, err := store.ListRuns(ctx, workloadscan.RunListOptions{
			Statuses:           []workloadscan.RunStatus{workloadscan.RunStatusSucceeded},
			Limit:              pageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return workloadscan.GraphMaterializationResult{}, err
		}
		runs = append(runs, page...)
		if len(page) < pageSize {
			break
		}
	}
	return workloadscan.MaterializeRunsIntoGraph(g, runs, time.Now().UTC()), nil
}

func (a *App) buildGraphConsistencyCandidate(ctx context.Context) (*graph.Graph, error) {
	if a == nil || a.SecurityGraphBuilder == nil {
		return nil, nil
	}
	candidate, _, err := a.SecurityGraphBuilder.BuildCandidate(ctx)
	if err != nil {
		return nil, err
	}
	if candidate == nil {
		return nil, nil
	}
	if _, err := a.materializePersistedWorkloadScans(ctx, candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}
