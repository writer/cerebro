package ports

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ErrReportRunNotFound indicates that a persisted report run does not exist.
var ErrReportRunNotFound = errors.New("report run not found")

// ErrReportScheduleNotFound indicates that a persisted report schedule does not exist.
var ErrReportScheduleNotFound = errors.New("report schedule not found")

// ReportStore persists durable report runs in the state store.
type ReportStore interface {
	StateStore
	PutReportRun(context.Context, *cerebrov1.ReportRun) error
	GetReportRun(context.Context, string) (*cerebrov1.ReportRun, error)
}

// ReportRunFilter scopes a durable report-run listing.
type ReportRunFilter struct {
	TenantID string
	ReportID string
	Limit    uint32
}

// ReportRunLister lists recent durable report runs for a tenant. State stores
// implement it as an optional capability discovered via type assertion.
type ReportRunLister interface {
	ListReportRuns(context.Context, ReportRunFilter) ([]*cerebrov1.ReportRun, error)
}

// ReportSchedule is a saved fixed-interval report schedule that the background
// scheduler uses to enqueue recurring report runs.
type ReportSchedule struct {
	ID              string
	TenantID        string
	ReportID        string
	Parameters      map[string]string
	IntervalSeconds int64
	Enabled         bool
	NextRunAt       time.Time
	LastRunAt       time.Time
	ClaimOwner      string
	ClaimExpiresAt  time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ReportScheduleFilter scopes a report-schedule listing.
type ReportScheduleFilter struct {
	TenantID string
	Limit    uint32
}

// ReportScheduleStore persists saved report schedules and claims due schedules
// for the background scheduler. State stores implement it as an optional
// capability discovered via type assertion.
type ReportScheduleStore interface {
	PutReportSchedule(context.Context, *ReportSchedule) error
	GetReportSchedule(context.Context, string) (*ReportSchedule, error)
	ListReportSchedules(context.Context, ReportScheduleFilter) ([]*ReportSchedule, error)
	DeleteReportSchedule(context.Context, string) error
	ClaimDueReportSchedules(context.Context, time.Time, string, time.Duration, uint32) ([]*ReportSchedule, error)
	CompleteReportScheduleClaim(context.Context, string, string, time.Time, time.Time) error
	ReleaseReportScheduleClaim(context.Context, string, string) error
}
