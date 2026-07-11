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
	DebounceWindow      time.Duration
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

// ComplianceChangeSignal is a bounded notification that an assessment input
// changed. ScopeDigest identifies the affected canonical scope without copying
// resource or evidence contents into scheduler state.
type ComplianceChangeSignal struct {
	EventID     string
	TenantID    string
	MonitorID   string
	SignalKind  string
	ScopeDigest string
	ObservedAt  time.Time
}

// ComplianceChangeWindow is the coalesced, claimable unit for one change
// monitor. Version changes whenever another signal joins the window.
type ComplianceChangeWindow struct {
	TenantID       string
	MonitorID      string
	ProgramID      string
	PlanRevisionID string
	Version        uint64
	OpenedAt       time.Time
	LastSignalAt   time.Time
	ReadyAt        time.Time
	SignalCount    uint64
	ScopeDigest    string
	ClaimOwner     string
	ClaimExpiresAt time.Time
}

// ComplianceMonitorStore owns monitor definitions, due claims, and per-plan
// overlap leases. Advancing a monitor is an acknowledgement after durable job
// creation, never part of claiming the occurrence.
type ComplianceMonitorStore interface {
	// ProjectComplianceMonitor applies one already-appended aggregate version to
	// current state. Application writes must use the compliancemonitor service.
	ProjectComplianceMonitor(context.Context, *ComplianceMonitor, uint64) (*ComplianceMonitor, error)
	GetComplianceMonitor(context.Context, string, string) (*ComplianceMonitor, error)
	ListComplianceMonitors(context.Context, ComplianceMonitorFilter) ([]*ComplianceMonitor, error)
	ClaimDueComplianceMonitors(context.Context, time.Time, string, time.Duration, uint32) ([]*ComplianceMonitor, error)
	CompleteComplianceMonitorClaim(context.Context, string, string, string, time.Time, time.Time) error
	ReleaseComplianceMonitorClaim(context.Context, string, string, string) error
	AcquireCompliancePlanLease(context.Context, string, string, string, string, time.Time, time.Duration) error
	ReleaseCompliancePlanLease(context.Context, string, string, string) error
	RecordComplianceMonitorOutcome(context.Context, string, string, bool, time.Time) error
}

// ComplianceChangeMonitorStore owns idempotent signal ingestion and durable
// debounce windows. Completing a claim is an acknowledgement after job
// creation; a signal that arrives while claimed creates a newer version that
// cannot be deleted by the older acknowledgement.
type ComplianceChangeMonitorStore interface {
	ComplianceMonitorStore
	RecordComplianceChangeSignal(context.Context, ComplianceChangeSignal) (bool, error)
	ClaimDueComplianceChangeWindows(context.Context, time.Time, string, time.Duration, uint32) ([]*ComplianceChangeWindow, error)
	CompleteComplianceChangeWindow(context.Context, string, string, string, uint64) error
	ReleaseComplianceChangeWindow(context.Context, string, string, string) error
}
