package ports

import (
	"context"
	"errors"
	"time"
)

// ErrJobNotFound indicates that a platform job does not exist.
var ErrJobNotFound = errors.New("platform job not found")

// ErrJobUpdateConflict indicates that a conditional job state update lost a race.
var ErrJobUpdateConflict = errors.New("platform job update conflict")

// ErrJobLeaseConflict indicates that a worker no longer owns a job lease.
var ErrJobLeaseConflict = errors.New("platform job lease conflict")

// ErrJobIdempotencyConflict indicates reuse of a key for a different request.
var ErrJobIdempotencyConflict = errors.New("platform job idempotency conflict")

const (
	JobStatusQueued    = "queued"
	JobStatusRunning   = "running"
	JobStatusCompleted = "completed"
	JobStatusFailed    = "failed"
	JobStatusCancelled = "cancelled"
)

// Job is the shared execution resource for long-running platform work.
type Job struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	Status          string            `json:"status"`
	TenantID        string            `json:"tenant_id,omitempty"`
	SubjectType     string            `json:"subject_type,omitempty"`
	SubjectID       string            `json:"subject_id,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key,omitempty"`
	RequestHash     string            `json:"-"`
	Progress        uint32            `json:"progress_percent,omitempty"`
	Message         string            `json:"message,omitempty"`
	Error           string            `json:"error,omitempty"`
	Payload         map[string]any    `json:"payload,omitempty"`
	Result          map[string]any    `json:"result,omitempty"`
	ResultRefs      map[string]string `json:"result_refs,omitempty"`
	CancelRequested bool              `json:"cancel_requested,omitempty"`
	Attempt         uint32            `json:"attempt,omitempty"`
	LeaseOwner      string            `json:"-"`
	LeaseExpiresAt  time.Time         `json:"lease_expires_at,omitempty"`
	HeartbeatAt     time.Time         `json:"heartbeat_at,omitempty"`
	FailureClass    string            `json:"failure_class,omitempty"`
	CreatedAt       time.Time         `json:"created_at,omitempty"`
	StartedAt       time.Time         `json:"started_at,omitempty"`
	FinishedAt      time.Time         `json:"finished_at,omitempty"`
	UpdatedAt       time.Time         `json:"updated_at,omitempty"`
}

// JobEvent records an append-only job timeline entry.
type JobEvent struct {
	JobID     string         `json:"job_id"`
	Sequence  uint64         `json:"sequence"`
	Type      string         `json:"type"`
	Status    string         `json:"status,omitempty"`
	Message   string         `json:"message,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
}

// CreateJobRequest scopes durable job creation.
type CreateJobRequest struct {
	Kind           string
	TenantID       string
	SubjectType    string
	SubjectID      string
	IdempotencyKey string
	RequestHash    string
	Payload        map[string]any
}

// JobFilter scopes job listing.
type JobFilter struct {
	TenantID string
	Kind     string
	Status   string
	Limit    uint32
}

// JobUpdate describes a partial job state update.
type JobUpdate struct {
	Status              string
	Progress            *uint32
	Message             string
	Error               string
	FailureClass        string
	Result              map[string]any
	ResultRefs          map[string]string
	StartedAt           *time.Time
	FinishedAt          *time.Time
	CancelRequested     *bool
	AllowedStatuses     []string
	ExpectedLeaseOwner  string
	RequireNotCancelled bool
	ClearLease          bool
}

// JobClaimRequest atomically claims queued or expired work for one worker.
type JobClaimRequest struct {
	JobID string
	Owner string
	Now   time.Time
	TTL   time.Duration
}

// JobLeaseRenewRequest extends one running job lease.
type JobLeaseRenewRequest struct {
	JobID string
	Owner string
	Now   time.Time
	TTL   time.Duration
}

// JobRecoveryRequest resets expired work and returns queued jobs for startup.
type JobRecoveryRequest struct {
	Now   time.Time
	Limit uint32
}

// JobStore persists platform jobs and their timeline events.
type JobStore interface {
	StateStore
	CreateJob(context.Context, CreateJobRequest) (*Job, bool, error)
	GetJob(context.Context, string) (*Job, error)
	ListJobs(context.Context, JobFilter) ([]*Job, error)
	CountJobs(context.Context, JobFilter) (uint64, error)
	UpdateJob(context.Context, string, JobUpdate) (*Job, error)
	AppendJobEvent(context.Context, JobEvent) (*JobEvent, error)
	ListJobEvents(context.Context, string, uint32) ([]*JobEvent, error)
}

// JobLeaseStore is the durable execution capability used by platform workers.
// It is separate from JobStore so read-only test and integration stores do not
// accidentally claim to provide recoverable execution.
type JobLeaseStore interface {
	ClaimJob(context.Context, JobClaimRequest) (*Job, error)
	RenewJobLease(context.Context, JobLeaseRenewRequest) (*Job, error)
	RecoverJobs(context.Context, JobRecoveryRequest) ([]*Job, error)
}
