package app

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/repohistoryscan"
)

func (a *App) materializePersistedRepositoryHistoryScans(ctx context.Context, g *graph.Graph) (repohistoryscan.GraphMaterializationResult, error) {
	if a == nil || g == nil || a.ExecutionStore == nil {
		return repohistoryscan.GraphMaterializationResult{}, nil
	}
	store := repohistoryscan.NewSQLiteRunStoreWithExecutionStore(a.ExecutionStore)

	const pageSize = 200
	runs := make([]repohistoryscan.RunRecord, 0)
	for offset := 0; ; offset += pageSize {
		page, err := store.ListRuns(ctx, repohistoryscan.RunListOptions{
			Statuses:           []repohistoryscan.RunStatus{repohistoryscan.RunStatusSucceeded},
			Limit:              pageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return repohistoryscan.GraphMaterializationResult{}, err
		}
		runs = append(runs, page...)
		if len(page) < pageSize {
			break
		}
	}
	return repohistoryscan.MaterializeRunsIntoGraph(g, runs, a.Lineage, time.Now().UTC()), nil
}
