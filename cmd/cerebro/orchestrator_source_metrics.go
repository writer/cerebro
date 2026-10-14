package main

import (
	"context"

	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/sourcehealth"
)

const (
	orchestratorSyncSkipBackoff          = "backoff"
	orchestratorSyncSkipLeaseNotAcquired = "lease_not_acquired"
	orchestratorSyncFailureLeaseError    = "lease_error"
)

// orchestratorSourceSyncMetricState carries metric-only context that the
// serialized runtime result does not expose.
type orchestratorSourceSyncMetricState struct {
	skipReason string
	// failureClass overrides the backoff failure class for failures that
	// happen before a sync is attempted.
	failureClass string
	// scheduleObserved is set when the backoff fields reflect the stored sync
	// schedule, so a zero failure count is a real value and not missing data.
	scheduleObserved bool
}

func recordOrchestratorSourceSyncMetrics(ctx context.Context, result *orchestratorRuntimeResult, health sourcehealth.Record) {
	if result == nil {
		return
	}
	failureClass := result.FailureClass
	if result.syncMetrics.failureClass != "" {
		failureClass = result.syncMetrics.failureClass
	}
	observability.RecordSourceSync(ctx, observability.SourceSyncMetrics{
		SourceID:               result.SourceID,
		Outcome:                result.Sync,
		FailureClass:           failureClass,
		SkipReason:             result.syncMetrics.skipReason,
		ConsecutiveFailures:    result.ConsecutiveFailures,
		HasConsecutiveFailures: result.syncMetrics.scheduleObserved,
		CircuitOpen:            result.CircuitOpen,
		SyncLagSeconds:         health.SyncLagSeconds,
		WatermarkLagSeconds:    health.WatermarkLagSeconds,
		GraphLagSeconds:        health.GraphLagSeconds,
	})
}
