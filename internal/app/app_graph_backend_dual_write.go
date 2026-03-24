package app

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) wrapConfiguredSecurityGraphStoreWithDualWrite(ctx context.Context, primaryHandle graphStoreBackendHandle) (graphStoreBackendHandle, []any, error) {
	if a == nil || a.Config == nil || !a.Config.dualWriteGraphStoreEnabled() {
		return primaryHandle, nil, nil
	}

	secondaryApp := &App{
		Config:                           a.Config.secondaryGraphStoreConfig(),
		Logger:                           a.Logger,
		graphStoreBackendProviderFactory: a.graphStoreBackendProviderFactory,
	}

	secondaryProvider, err := secondaryApp.resolveGraphStoreBackendProvider(secondaryApp.Config.graphStoreBackend())
	if err != nil {
		return primaryHandle, nil, err
	}
	secondaryHandle, err := secondaryProvider.Open(ctx, secondaryApp)
	if err != nil {
		return primaryHandle, nil, err
	}

	var (
		queue      graphStoreDualWriteReplayQueue
		replayStop = func() error { return nil }
	)
	if path := strings.TrimSpace(a.Config.GraphStoreDualWriteReconciliationPath); path != "" {
		replayQueue, err := newGraphStoreDualWriteReconciliationQueue(path)
		if err != nil {
			_ = secondaryHandle.Close()
			return primaryHandle, nil, err
		}
		queue = replayQueue
		if a.Config.GraphStoreDualWriteReplayEnabled {
			replayStop = startGraphStoreDualWriteReplayLoop(ctx, a.Logger, replayQueue, secondaryHandle.Store, a.Config.GraphStoreDualWriteReplayInterval, a.Config.GraphStoreDualWriteReplayBatchSize)
		}
	}
	a.graphStoreDualWriteReplayQueue = queue

	store := graph.NewDualWriteGraphStore(primaryHandle.Store, secondaryHandle.Store, graph.DualWriteGraphStoreOptions{
		Mode:             a.Config.graphStoreDualWriteMode(),
		SecondaryBackend: secondaryProvider.Backend(),
		Queue:            queue,
		Observe:          a.observeGraphStoreDualWriteMutation,
	})
	queueClose := func() error {
		if queue == nil {
			return nil
		}
		return queue.Close()
	}

	return graphStoreBackendHandle{
			Store: store,
			Close: combineGraphStoreClosers(replayStop, queueClose, secondaryHandle.Close, primaryHandle.Close),
		}, []any{
			"secondary_backend", secondaryProvider.Backend(),
			"dual_write_mode", a.Config.graphStoreDualWriteMode(),
			"reconciliation_path", strings.TrimSpace(a.Config.GraphStoreDualWriteReconciliationPath),
			"replay_enabled", a.Config.GraphStoreDualWriteReplayEnabled,
		}, nil
}

func (a *App) observeGraphStoreDualWriteMutation(_ context.Context, outcome graph.DualWriteMutationOutcome) {
	if a == nil || a.Logger == nil {
		return
	}
	if outcome.PrimarySucceeded && (!outcome.SecondaryAttempted || outcome.SecondarySucceeded) {
		a.Logger.Debug("graph dual-write mutation succeeded",
			"operation", outcome.Operation,
			"mode", outcome.Mode,
			"secondary_backend", outcome.SecondaryBackend,
			"identifiers", outcome.Identifiers,
			"primary_latency", outcome.PrimaryLatency,
			"secondary_attempted", outcome.SecondaryAttempted,
			"secondary_latency", outcome.SecondaryLatency,
		)
		return
	}
	a.Logger.Warn("graph dual-write mutation divergence",
		"operation", outcome.Operation,
		"mode", outcome.Mode,
		"secondary_backend", outcome.SecondaryBackend,
		"identifiers", outcome.Identifiers,
		"primary_succeeded", outcome.PrimarySucceeded,
		"primary_error", outcome.PrimaryError,
		"secondary_attempted", outcome.SecondaryAttempted,
		"secondary_succeeded", outcome.SecondarySucceeded,
		"secondary_error", outcome.SecondaryError,
		"secondary_retryable", outcome.SecondaryRetryable,
		"reconciliation_enqueued", outcome.ReconciliationEnqueued,
		"reconciliation_error", outcome.ReconciliationError,
	)
}

func combineGraphStoreClosers(closers ...func() error) func() error {
	return func() error {
		var err error
		for _, closeFn := range closers {
			if closeFn == nil {
				continue
			}
			err = errors.Join(err, closeFn())
		}
		return err
	}
}
