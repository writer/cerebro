package reposcan

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
	RunStageAnalyze   RunStage = "analyze"
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

type AnalysisInput struct {
	RunID        string               `json:"run_id"`
	Target       ScanTarget           `json:"target"`
	Descriptor   RepositoryDescriptor `json:"descriptor"`
	Checkout     *CheckoutArtifact    `json:"checkout,omitempty"`
	Metadata     map[string]string    `json:"metadata,omitempty"`
	SinceCommit  string               `json:"since_commit,omitempty"`
	ChangedPaths []string             `json:"changed_paths,omitempty"`
}

type AnalysisReport struct {
	Analyzer              string                     `json:"analyzer"`
	Catalog               *filesystemanalyzer.Report `json:"catalog,omitempty"`
	IaCArtifactCount      int                        `json:"iac_artifact_count,omitempty"`
	MisconfigurationCount int                        `json:"misconfiguration_count,omitempty"`
	IncrementalBaseCommit string                     `json:"incremental_base_commit,omitempty"`
	ChangedPaths          []string                   `json:"changed_paths,omitempty"`
	Skipped               bool                       `json:"skipped,omitempty"`
	GraphIntegration      *GraphIntegration          `json:"graph_integration,omitempty"`
	Metadata              map[string]any             `json:"metadata,omitempty"`
}

type GraphIntegration struct {
	LinkedResources  int         `json:"linked_resources,omitempty"`
	ObservationCount int         `json:"observation_count,omitempty"`
	Links            []GraphLink `json:"links,omitempty"`
}

type GraphLink struct {
	AssetID       string `json:"asset_id"`
	AssetType     string `json:"asset_type,omitempty"`
	AssetName     string `json:"asset_name,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Region        string `json:"region,omitempty"`
	MatchedBy     string `json:"matched_by,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
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
