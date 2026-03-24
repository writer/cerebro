package app

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/graph"
)

func (a *App) materializePersistedForensics(ctx context.Context, g *graph.Graph) (forensics.GraphMaterializationResult, error) {
	if a == nil || a.Config == nil || g == nil {
		return forensics.GraphMaterializationResult{}, nil
	}
	storePath := strings.TrimSpace(a.Config.ExecutionStoreFile)
	if storePath == "" {
		storePath = strings.TrimSpace(a.Config.WorkloadScanStateFile)
	}
	if storePath == "" && a.ExecutionStore == nil {
		return forensics.GraphMaterializationResult{}, nil
	}

	var (
		store forensics.Store
		err   error
	)
	if a.ExecutionStore != nil {
		store = forensics.NewSQLiteStoreWithExecutionStore(a.ExecutionStore)
	} else {
		store, err = forensics.NewSQLiteStore(storePath)
		if err != nil {
			return forensics.GraphMaterializationResult{}, err
		}
		defer func() { _ = store.Close() }()
	}

	captures, err := store.ListCaptures(ctx, forensics.CaptureListOptions{Limit: 500})
	if err != nil {
		return forensics.GraphMaterializationResult{}, err
	}
	evidence, err := store.ListEvidence(ctx, forensics.EvidenceListOptions{Limit: 500})
	if err != nil {
		return forensics.GraphMaterializationResult{}, err
	}
	return forensics.MaterializeIntoGraph(g, captures, evidence, time.Now().UTC()), nil
}
