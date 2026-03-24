package repohistoryscan

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

type RunStatus string

const (
	RunStatusQueued    RunStatus = "queued"
	RunStatusRunning   RunStatus = "running"
	RunStatusSucceeded RunStatus = "succeeded"
	RunStatusFailed    RunStatus = "failed"
)

func (s RunStatus) Terminal() bool {
	return s == RunStatusSucceeded || s == RunStatusFailed
}

type RunStage string

const (
	RunStageQueued    RunStage = "queued"
	RunStageClone     RunStage = "clone"
	RunStageScan      RunStage = "scan"
	RunStageCleanup   RunStage = "cleanup"
	RunStageCompleted RunStage = "completed"
	RunStageFailed    RunStage = "failed"
)

type ScanTarget struct {
	RepoURL     string `json:"repo_url"`
	Repository  string `json:"repository,omitempty"`
	Ref         string `json:"ref,omitempty"`
	SinceCommit string `json:"since_commit,omitempty"`
}

func (t ScanTarget) Identity() string {
	for _, candidate := range []string{t.Repository, t.RepoURL} {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

type RepositoryDescriptor struct {
	RepoURL      string `json:"repo_url"`
	Repository   string `json:"repository,omitempty"`
	RequestedRef string `json:"requested_ref,omitempty"`
	ResolvedRef  string `json:"resolved_ref,omitempty"`
	CommitSHA    string `json:"commit_sha,omitempty"`
}

type CheckoutArtifact struct {
	Path           string         `json:"path"`
	MaterializedAt time.Time      `json:"materialized_at"`
	CleanedUpAt    *time.Time     `json:"cleaned_up_at,omitempty"`
	Retained       bool           `json:"retained,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type AnalysisReport struct {
	Engine           string                                 `json:"engine"`
	Findings         []filesystemanalyzer.GitHistoryFinding `json:"findings,omitempty"`
	TotalFindings    int                                    `json:"total_findings,omitempty"`
	VerifiedFindings int                                    `json:"verified_findings,omitempty"`
	Metadata         map[string]any                         `json:"metadata,omitempty"`
}

type ScanRequest struct {
	ID           string            `json:"id"`
	RequestedBy  string            `json:"requested_by,omitempty"`
	Target       ScanTarget        `json:"target"`
	DryRun       bool              `json:"dry_run,omitempty"`
	KeepCheckout bool              `json:"keep_checkout,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	SubmittedAt  time.Time         `json:"submitted_at"`
}

type RunEvent struct {
	Sequence   int64          `json:"sequence"`
	Status     RunStatus      `json:"status"`
	Stage      RunStage       `json:"stage"`
	Message    string         `json:"message,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	RecordedAt time.Time      `json:"recorded_at"`
}

type RunRecord struct {
	ID           string                `json:"id"`
	Status       RunStatus             `json:"status"`
	Stage        RunStage              `json:"stage"`
	Target       ScanTarget            `json:"target"`
	RequestedBy  string                `json:"requested_by,omitempty"`
	DryRun       bool                  `json:"dry_run,omitempty"`
	KeepCheckout bool                  `json:"keep_checkout,omitempty"`
	Metadata     map[string]string     `json:"metadata,omitempty"`
	SubmittedAt  time.Time             `json:"submitted_at"`
	StartedAt    *time.Time            `json:"started_at,omitempty"`
	CompletedAt  *time.Time            `json:"completed_at,omitempty"`
	UpdatedAt    time.Time             `json:"updated_at"`
	Error        string                `json:"error,omitempty"`
	Descriptor   *RepositoryDescriptor `json:"descriptor,omitempty"`
	Checkout     *CheckoutArtifact     `json:"checkout,omitempty"`
	Analysis     *AnalysisReport       `json:"analysis,omitempty"`
}

type RunListOptions struct {
	Statuses           []RunStatus
	ActiveOnly         bool
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}
