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
)

type Job struct {
	ID             string  `json:"id" dynamodbav:"job_id"`
	Type           JobType `json:"type" dynamodbav:"type"`
	Status         Status  `json:"status" dynamodbav:"status"`
	Payload        string  `json:"payload" dynamodbav:"payload"`
	Result         string  `json:"result,omitempty" dynamodbav:"result,omitempty"`
	Error          string  `json:"error,omitempty" dynamodbav:"error,omitempty"`
	Attempt        int     `json:"attempt" dynamodbav:"attempt"`
	MaxAttempts    int     `json:"max_attempts" dynamodbav:"max_attempts"`
	GroupID        string  `json:"group_id,omitempty" dynamodbav:"group_id,omitempty"`
	WorkerID       string  `json:"worker_id,omitempty" dynamodbav:"worker_id,omitempty"`
	LeaseExpiresAt int64   `json:"lease_expires_at,omitempty" dynamodbav:"lease_expires_at,omitempty"`
	CreatedAt      int64   `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt      int64   `json:"updated_at" dynamodbav:"updated_at"`
}

type JobMessage struct {
	JobID   string `json:"job_id"`
	GroupID string `json:"group_id,omitempty"`
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
	GCPProject string `json:"gcp_project,omitempty"`
	GCPZone    string `json:"gcp_zone,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
}

type InspectResourcePayload struct {
	Resource  ResourceRef      `json:"resource"`
	Overrides InspectOverrides `json:"overrides,omitempty"`
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
