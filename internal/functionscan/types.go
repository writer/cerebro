package functionscan

import (
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/filesystemanalyzer"
	"github.com/evalops/cerebro/internal/scanner"
)

type ProviderKind string

const (
	ProviderAWS   ProviderKind = "aws"
	ProviderGCP   ProviderKind = "gcp"
	ProviderAzure ProviderKind = "azure"
)

type ArtifactKind string

const (
	ArtifactFunctionCode ArtifactKind = "function_code"
	ArtifactLayer        ArtifactKind = "layer"
)

type ArchiveFormat string

const (
	ArchiveFormatZIP ArchiveFormat = "zip"
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
	RunStageQueued      RunStage = "queued"
	RunStageDescribe    RunStage = "describe"
	RunStageMaterialize RunStage = "materialize"
	RunStageAnalyze     RunStage = "analyze"
	RunStageCleanup     RunStage = "cleanup"
	RunStageCompleted   RunStage = "completed"
	RunStageFailed      RunStage = "failed"
)

type FunctionTarget struct {
	Provider       ProviderKind `json:"provider"`
	AccountID      string       `json:"account_id,omitempty"`
	Region         string       `json:"region,omitempty"`
	FunctionName   string       `json:"function_name,omitempty"`
	FunctionARN    string       `json:"function_arn,omitempty"`
	ProjectID      string       `json:"project_id,omitempty"`
	Location       string       `json:"location,omitempty"`
	SubscriptionID string       `json:"subscription_id,omitempty"`
	ResourceGroup  string       `json:"resource_group,omitempty"`
	AppName        string       `json:"app_name,omitempty"`
}

func (t FunctionTarget) Identity() string {
	switch t.Provider {
	case ProviderAWS:
		if strings.TrimSpace(t.FunctionARN) != "" {
			return strings.TrimSpace(t.FunctionARN)
		}
	case ProviderGCP:
		if strings.TrimSpace(t.ProjectID) != "" && strings.TrimSpace(t.Location) != "" && strings.TrimSpace(t.FunctionName) != "" {
			return "projects/" + strings.TrimSpace(t.ProjectID) + "/locations/" + strings.TrimSpace(t.Location) + "/functions/" + strings.TrimSpace(t.FunctionName)
		}
	case ProviderAzure:
		if strings.TrimSpace(t.SubscriptionID) != "" && strings.TrimSpace(t.ResourceGroup) != "" && strings.TrimSpace(t.AppName) != "" {
			return "/subscriptions/" + strings.TrimSpace(t.SubscriptionID) + "/resourceGroups/" + strings.TrimSpace(t.ResourceGroup) + "/providers/Microsoft.Web/sites/" + strings.TrimSpace(t.AppName)
		}
	}
	for _, candidate := range []string{t.FunctionName, t.FunctionARN, t.AppName} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}

type ArtifactRef struct {
	ID       string         `json:"id"`
	Kind     ArtifactKind   `json:"kind"`
	Format   ArchiveFormat  `json:"format"`
	Name     string         `json:"name,omitempty"`
	Size     int64          `json:"size,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type FunctionLayer struct {
	ARN           string         `json:"arn,omitempty"`
	Name          string         `json:"name,omitempty"`
	Version       int64          `json:"version,omitempty"`
	CodeSize      int64          `json:"code_size,omitempty"`
	Architectures []string       `json:"architectures,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type FunctionDescriptor struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Runtime            string            `json:"runtime,omitempty"`
	EntryPoint         string            `json:"entry_point,omitempty"`
	PackageType        string            `json:"package_type,omitempty"`
	ImageURI           string            `json:"image_uri,omitempty"`
	CodeSHA256         string            `json:"code_sha256,omitempty"`
	CodeSize           int64             `json:"code_size,omitempty"`
	Role               string            `json:"role,omitempty"`
	ServiceAccount     string            `json:"service_account,omitempty"`
	TimeoutSeconds     int32             `json:"timeout_seconds,omitempty"`
	MemoryMB           int64             `json:"memory_mb,omitempty"`
	Architectures      []string          `json:"architectures,omitempty"`
	Environment        map[string]string `json:"environment,omitempty"`
	BuildEnvironment   map[string]string `json:"build_environment,omitempty"`
	RuntimeEnvironment string            `json:"runtime_environment,omitempty"`
	SourceRevision     string            `json:"source_revision,omitempty"`
	UpdatedAt          *time.Time        `json:"updated_at,omitempty"`
	VpcConfig          map[string]any    `json:"vpc_config,omitempty"`
	EventSources       []string          `json:"event_sources,omitempty"`
	Layers             []FunctionLayer   `json:"layers,omitempty"`
	Artifacts          []ArtifactRef     `json:"artifacts,omitempty"`
	Metadata           map[string]any    `json:"metadata,omitempty"`
}

type AppliedArtifact struct {
	ID           string        `json:"id"`
	Kind         ArtifactKind  `json:"kind"`
	Format       ArchiveFormat `json:"format"`
	DownloadedAt *time.Time    `json:"downloaded_at,omitempty"`
	AppliedAt    *time.Time    `json:"applied_at,omitempty"`
	Size         int64         `json:"size,omitempty"`
}

type FilesystemArtifact struct {
	Path           string         `json:"path"`
	MaterializedAt time.Time      `json:"materialized_at"`
	CleanedUpAt    *time.Time     `json:"cleaned_up_at,omitempty"`
	FileCount      int64          `json:"file_count,omitempty"`
	ByteSize       int64          `json:"byte_size,omitempty"`
	Retained       bool           `json:"retained,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type AnalysisInput struct {
	RunID      string              `json:"run_id"`
	Target     FunctionTarget      `json:"target"`
	Descriptor FunctionDescriptor  `json:"descriptor"`
	Filesystem *FilesystemArtifact `json:"filesystem,omitempty"`
	Metadata   map[string]string   `json:"metadata,omitempty"`
}

type AnalysisReport struct {
	Analyzer                     string                      `json:"analyzer"`
	FilesystemVulnerabilityCount int                         `json:"filesystem_vulnerability_count,omitempty"`
	EnvironmentSecretCount       int                         `json:"environment_secret_count,omitempty"`
	CodeSecretCount              int                         `json:"code_secret_count,omitempty"`
	RuntimeDeprecated            bool                        `json:"runtime_deprecated,omitempty"`
	Catalog                      *filesystemanalyzer.Report  `json:"catalog,omitempty"`
	Result                       scanner.ContainerScanResult `json:"result"`
	Metadata                     map[string]any              `json:"metadata,omitempty"`
}

type ScanRequest struct {
	ID             string            `json:"id"`
	RequestedBy    string            `json:"requested_by,omitempty"`
	Target         FunctionTarget    `json:"target"`
	DryRun         bool              `json:"dry_run,omitempty"`
	KeepFilesystem bool              `json:"keep_filesystem,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	SubmittedAt    time.Time         `json:"submitted_at"`
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
	ID               string              `json:"id"`
	Provider         ProviderKind        `json:"provider"`
	Status           RunStatus           `json:"status"`
	Stage            RunStage            `json:"stage"`
	Target           FunctionTarget      `json:"target"`
	RequestedBy      string              `json:"requested_by,omitempty"`
	DryRun           bool                `json:"dry_run,omitempty"`
	KeepFilesystem   bool                `json:"keep_filesystem,omitempty"`
	Metadata         map[string]string   `json:"metadata,omitempty"`
	SubmittedAt      time.Time           `json:"submitted_at"`
	StartedAt        *time.Time          `json:"started_at,omitempty"`
	CompletedAt      *time.Time          `json:"completed_at,omitempty"`
	UpdatedAt        time.Time           `json:"updated_at"`
	Error            string              `json:"error,omitempty"`
	Descriptor       *FunctionDescriptor `json:"descriptor,omitempty"`
	AppliedArtifacts []AppliedArtifact   `json:"applied_artifacts,omitempty"`
	Filesystem       *FilesystemArtifact `json:"filesystem,omitempty"`
	Analysis         *AnalysisReport     `json:"analysis,omitempty"`
}

type RunListOptions struct {
	Statuses           []RunStatus
	ActiveOnly         bool
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}
