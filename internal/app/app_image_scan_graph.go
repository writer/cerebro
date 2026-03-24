package app

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/imagescan"
)

func (a *App) materializePersistedImageScans(ctx context.Context, g *graph.Graph) (imagescan.GraphMaterializationResult, error) {
	if a == nil || a.Config == nil || g == nil {
		return imagescan.GraphMaterializationResult{}, nil
	}
	storePath := a.Config.ImageScanStateFile
	if storePath == "" {
		return imagescan.GraphMaterializationResult{}, nil
	}
	var (
		store imagescan.RunStore
		err   error
	)
	if shared := a.executionStoreForPath(storePath); shared != nil {
		store = imagescan.NewSQLiteRunStoreWithExecutionStore(shared)
	} else {
		store, err = imagescan.NewSQLiteRunStore(storePath)
		if err != nil {
			return imagescan.GraphMaterializationResult{}, err
		}
	}
	defer func() { _ = store.Close() }()

	const pageSize = 200
	runs := make([]imagescan.RunRecord, 0)
	for offset := 0; ; offset += pageSize {
		page, err := store.ListRuns(ctx, imagescan.RunListOptions{
			Statuses:           []imagescan.RunStatus{imagescan.RunStatusSucceeded},
			Limit:              pageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return imagescan.GraphMaterializationResult{}, err
		}
		runs = append(runs, page...)
		if len(page) < pageSize {
			break
		}
	}
	return imagescan.MaterializeRunsIntoGraph(g, a.Lineage, runs, time.Now().UTC()), nil
}
