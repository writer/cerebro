package main

import (
	"context"
	"math"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	orchestratorSyncScheduleStorePresent = "present"
	orchestratorSyncScheduleStoreAbsent  = "absent"
	orchestratorSyncScheduleWriteTimeout = 5 * time.Second
)

// orchestratorSyncBackoffResult is embedded in orchestratorRuntimeResult so
// its fields serialize at the top level of each runtime result.
type orchestratorSyncBackoffResult struct {
	FailureClass        string `json:"failure_class,omitempty"`
	NextAttemptAt       string `json:"next_attempt_at,omitempty"`
	ConsecutiveFailures uint32 `json:"consecutive_failures,omitempty"`
	CircuitOpen         bool   `json:"circuit_open,omitempty"`
}

type orchestratorSyncScheduler struct {
	store  ports.SourceRuntimeSyncScheduleStore
	policy sourceruntime.SyncRetryPolicy
	now    func() time.Time
}

type orchestratorSyncScheduleCheck struct {
	schedule ports.SourceRuntimeSyncSchedule
	found    bool
	err      error
	backoff  bool
	bypassed bool
}

func newOrchestratorSyncScheduler(leaser ports.SourceRuntimeLeaseStore) orchestratorSyncScheduler {
	store, _ := leaser.(ports.SourceRuntimeSyncScheduleStore)
	return orchestratorSyncScheduler{
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

func (s orchestratorSyncScheduler) storeState() string {
	if s.store == nil {
		return orchestratorSyncScheduleStoreAbsent
	}
	return orchestratorSyncScheduleStorePresent
}

// orchestratorExplicitRuntimeRun reports runs where an operator named the
// runtimes to sync; those runs ignore backoff but still record outcomes.
func orchestratorExplicitRuntimeRun(filter ports.SourceRuntimeFilter) bool {
	if strings.TrimSpace(filter.RuntimeID) != "" {
		return true
	}
	for _, id := range filter.RuntimeIDs {
		if strings.TrimSpace(id) != "" {
			return true
		}
	}
	return false
}

func (s orchestratorSyncScheduler) check(ctx context.Context, runtimeID string, explicit bool) orchestratorSyncScheduleCheck {
	if s.store == nil {
		return orchestratorSyncScheduleCheck{}
	}
	schedule, found, err := s.store.GetSourceRuntimeSyncSchedule(ctx, runtimeID)
	if err != nil {
		return orchestratorSyncScheduleCheck{err: err}
	}
	due := !found || !s.now().Before(schedule.NextAttemptAt)
	return orchestratorSyncScheduleCheck{
		schedule: schedule,
		found:    found,
		backoff:  !due && !explicit,
		bypassed: !due && explicit,
	}
}

func (c orchestratorSyncScheduleCheck) result() orchestratorSyncBackoffResult {
	if !c.found {
		return orchestratorSyncBackoffResult{}
	}
	return orchestratorSyncBackoffResult{
		FailureClass:        c.schedule.LastFailureClass,
		NextAttemptAt:       c.schedule.NextAttemptAt.UTC().Format(time.RFC3339),
		ConsecutiveFailures: c.schedule.ConsecutiveFailures,
		CircuitOpen:         c.schedule.CircuitOpen,
	}
}

// recordFailure classifies syncErr and stores the next attempt. The returned
// result always carries the failure class, even when no store is configured.
func (s orchestratorSyncScheduler) recordFailure(ctx context.Context, runtime *cerebrov1.SourceRuntime, prior orchestratorSyncScheduleCheck, syncErr error) (orchestratorSyncBackoffResult, error) {
	failure := sourceruntime.ClassifySyncFailure(syncErr)
	result := orchestratorSyncBackoffResult{FailureClass: string(failure.Class)}
	if s.store == nil || failure.Class == sourceruntime.SyncFailureCancelled {
		return result, nil
	}
	now := s.now()
	// The lease serializes writers for this runtime, so the pre-lease read is
	// a close estimate; the store's atomic increment remains authoritative.
	expected := uint32(1)
	if prior.found && prior.schedule.ConsecutiveFailures < math.MaxUint32 {
		expected = prior.schedule.ConsecutiveFailures + 1
	}
	decision := s.policy.Decide(failure.Class, expected, failure.RetryAfter, now)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orchestratorSyncScheduleWriteTimeout)
	defer cancel()
	stored, err := s.store.RecordSourceRuntimeSyncFailure(writeCtx, ports.SourceRuntimeSyncFailure{
		RuntimeID:        runtime.GetId(),
		TenantID:         runtime.GetTenantId(),
		FailureClass:     string(failure.Class),
		NextAttemptAt:    decision.NextAttemptAt,
		CircuitOpenAfter: sourceruntime.SyncCircuitOpenAfter(failure.Class),
		ObservedAt:       now,
	})
	if err != nil {
		return result, err
	}
	result.ConsecutiveFailures = stored.ConsecutiveFailures
	result.CircuitOpen = stored.CircuitOpen
	if stored.NextAttemptAt.After(now) {
		result.NextAttemptAt = stored.NextAttemptAt.UTC().Format(time.RFC3339)
	}
	return result, nil
}

// recordSuccess clears stored backoff. It skips the write when the pre-lease
// read proved there was nothing to clear.
func (s orchestratorSyncScheduler) recordSuccess(ctx context.Context, runtimeID string, prior orchestratorSyncScheduleCheck) error {
	if s.store == nil || (!prior.found && prior.err == nil) {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orchestratorSyncScheduleWriteTimeout)
	defer cancel()
	return s.store.RecordSourceRuntimeSyncSuccess(writeCtx, runtimeID)
}

func orchestratorSyncBackoffAttrs(attrs telemetry.Attributes, backoff orchestratorSyncBackoffResult) telemetry.Attributes {
	if backoff.FailureClass != "" {
		attrs = withTelemetryField(attrs, "failure_class", backoff.FailureClass)
	}
	if backoff.ConsecutiveFailures > 0 {
		attrs = withTelemetryField(attrs, "consecutive_failures", backoff.ConsecutiveFailures)
	}
	if backoff.NextAttemptAt != "" {
		attrs = withTelemetryField(attrs, "next_attempt_at", backoff.NextAttemptAt)
	}
	if backoff.CircuitOpen {
		attrs = withTelemetryField(attrs, "circuit_open", true)
	}
	return attrs
}
