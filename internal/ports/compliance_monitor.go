package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrComplianceMonitorNotFound = errors.New("compliance monitor not found")
	ErrComplianceMonitorConflict = errors.New("compliance monitor conflict")
	ErrComplianceMonitorOverlap  = errors.New("compliance assessment already running for plan revision")
)

const (
	ComplianceTriggerTime   = "time"
	ComplianceTriggerChange = "change"
)

// ComplianceMonitor defines when one exact assessment plan revision should run.
// Current execution state is kept separate from the immutable plan revision.
type ComplianceMonitor struct {
	ID                  string
	TenantID            string
	ProgramID           string
	PlanRevisionID      string
	TriggerKind         string
	IntervalSeconds     int64
	ExpectedCoverage    string
	MaximumEvidenceAge  time.Duration
	GracePeriod         time.Duration
	EscalationOwner     string
	Enabled             bool
	Version             uint64
	NextRunAt           time.Time
	LastSuccessAt       time.Time
	ConsecutiveFailures uint32
	ClaimOwner          string
	ClaimExpiresAt      time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type ComplianceMonitorFilter struct {
	TenantID string
	AfterID  string
	Limit    uint32
}

// ComplianceMonitorStore owns monitor definitions, due claims, and per-plan
// overlap leases. Advancing a monitor is an acknowledgement after durable job
// creation, never part of claiming the occurrence.
type ComplianceMonitorStore interface {
	PutComplianceMonitor(context.Context, *ComplianceMonitor, uint64) (*ComplianceMonitor, error)
	GetComplianceMonitor(context.Context, string, string) (*ComplianceMonitor, error)
	ListComplianceMonitors(context.Context, ComplianceMonitorFilter) ([]*ComplianceMonitor, error)
	ClaimDueComplianceMonitors(context.Context, time.Time, string, time.Duration, uint32) ([]*ComplianceMonitor, error)
	CompleteComplianceMonitorClaim(context.Context, string, string, string, time.Time, time.Time) error
	ReleaseComplianceMonitorClaim(context.Context, string, string, string) error
	AcquireCompliancePlanLease(context.Context, string, string, string, string, time.Time, time.Duration) error
	ReleaseCompliancePlanLease(context.Context, string, string, string) error
	RecordComplianceMonitorOutcome(context.Context, string, string, bool, time.Time) error
}
