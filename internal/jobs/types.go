package jobs

import "time"

type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
)

func (s Status) Terminal() bool {
	return s == StatusSucceeded || s == StatusFailed
}

type JobType string

const (
	JobTypeInspectResource JobType = "inspect_resource"
	JobTypeNativeSync      JobType = "native_sync"
)

type Job struct {
	ID             string  `json:"id"`
	Type           JobType `json:"type"`
	Status         Status  `json:"status"`
	Payload        string  `json:"payload"`
	Result         string  `json:"result,omitempty"`
	Error          string  `json:"error,omitempty"`
	Attempt        int     `json:"attempt"`
	MaxAttempts    int     `json:"max_attempts"`
	GroupID        string  `json:"group_id,omitempty"`
	WorkerID       string  `json:"worker_id,omitempty"`
	LeaseExpiresAt int64   `json:"lease_expires_at,omitempty"`
	CreatedAt      int64   `json:"created_at"`
	UpdatedAt      int64   `json:"updated_at"`

	// Tracing fields
	CorrelationID string `json:"correlation_id,omitempty"`
	ParentID      string `json:"parent_id,omitempty"`
}

type JobMessage struct {
	JobID         string `json:"job_id"`
	GroupID       string `json:"group_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	// Attempt number for retry tracking (used in deduplication ID generation)
	Attempt int `json:"attempt,omitempty"`
	// DeduplicationID is optional; if empty, the queue generates a stable identifier.
	DeduplicationID string `json:"deduplication_id,omitempty"`
}

type ResourceRef struct {
	Provider     string `json:"provider"`
	Service      string `json:"service,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Identifier   string `json:"identifier"`
	Resource     string `json:"resource"`
	File         string `json:"file,omitempty"`
	Line         int    `json:"line,omitempty"`
	Snippet      string `json:"snippet,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
}

type InspectOverrides struct {
	AWSRegion  string `json:"aws_region,omitempty"`
	AWSAccount string `json:"aws_account,omitempty"`
	GCPProject string `json:"gcp_project,omitempty"`
	GCPZone    string `json:"gcp_zone,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
}

type InspectResourcePayload struct {
	Resource  ResourceRef      `json:"resource"`
	Overrides InspectOverrides `json:"overrides,omitempty"`
}

type NativeSyncPayload struct {
	Provider     string `json:"provider"`
	Table        string `json:"table,omitempty"`
	ScheduleName string `json:"schedule_name,omitempty"`
}

type JobBatch struct {
	GroupID      string    `json:"group_id"`
	JobIDs       []string  `json:"job_ids"`
	QueuedAt     time.Time `json:"queued_at"`
	TotalJobs    int       `json:"total_jobs"`
	MaxAttempts  int       `json:"max_attempts"`
	RepoURL      string    `json:"repo_url,omitempty"`
	FilesScanned int       `json:"files_scanned,omitempty"`
	Truncated    bool      `json:"truncated"`
}
