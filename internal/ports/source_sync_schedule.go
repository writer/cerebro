package ports

import (
	"context"
	"time"
)

// SourceRuntimeSyncSchedule is the current retry schedule for one source
// runtime's scheduled sync. It is scheduling metadata only: it is never
// projected to the graph and is not replayed from the append log.
type SourceRuntimeSyncSchedule struct {
	RuntimeID           string
	TenantID            string
	ConsecutiveFailures uint32
	LastFailureClass    string
	NextAttemptAt       time.Time
	CircuitOpen         bool
	// ConfigDigest identifies the operator-owned runtime config that produced
	// the last failure, so a config change can lift the hold.
	ConfigDigest string
	UpdatedAt    time.Time
}

// SourceRuntimeSyncFailure describes one failed scheduled sync attempt.
type SourceRuntimeSyncFailure struct {
	RuntimeID     string
	TenantID      string
	FailureClass  string
	NextAttemptAt time.Time
	// CircuitOpenAfter is the consecutive-failure count at which the stored
	// schedule reports an open circuit. Zero disables the circuit flag.
	CircuitOpenAfter uint32
	ConfigDigest     string
	ObservedAt       time.Time
}

// SourceRuntimeSyncScheduleStore persists per-runtime sync retry state so
// the orchestrator can back off failing runtimes across process restarts.
type SourceRuntimeSyncScheduleStore interface {
	GetSourceRuntimeSyncSchedule(ctx context.Context, runtimeID string) (SourceRuntimeSyncSchedule, bool, error)
	// RecordSourceRuntimeSyncFailure atomically increments the consecutive
	// failure count and returns the updated schedule.
	RecordSourceRuntimeSyncFailure(ctx context.Context, failure SourceRuntimeSyncFailure) (SourceRuntimeSyncSchedule, error)
	RecordSourceRuntimeSyncSuccess(ctx context.Context, runtimeID string) error
}
