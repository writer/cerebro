package imagescan

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
)

type RegistryKind string

const (
	RegistryDockerHub RegistryKind = "dockerhub"
	RegistryECR       RegistryKind = "ecr"
	RegistryGCR       RegistryKind = "gcr"
	RegistryACR       RegistryKind = "acr"
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
	RunStageManifest    RunStage = "manifest"
	RunStageMaterialize RunStage = "materialize"
	RunStageAnalyze     RunStage = "analyze"
	RunStageCleanup     RunStage = "cleanup"
	RunStageCompleted   RunStage = "completed"
	RunStageFailed      RunStage = "failed"
)

type ScanTarget struct {
	Registry     RegistryKind `json:"registry"`
	RegistryHost string       `json:"registry_host,omitempty"`
	Repository   string       `json:"repository"`
	Tag          string       `json:"tag,omitempty"`
	Digest       string       `json:"digest,omitempty"`
}

func (t ScanTarget) Reference() string {
	repo := strings.TrimSpace(t.Repository)
	switch {
	case strings.TrimSpace(t.Digest) != "":
		return repo + "@" + strings.TrimSpace(t.Digest)
	case strings.TrimSpace(t.Tag) != "":
		return repo + ":" + strings.TrimSpace(t.Tag)
	default:
		return repo
	}
}

func (t ScanTarget) ManifestReference() string {
	if digest := strings.TrimSpace(t.Digest); digest != "" {
		return digest
	}
	return strings.TrimSpace(t.Tag)
}

func (t ScanTarget) NativeVulnerabilityReference() string {
	if digest := strings.TrimSpace(t.Digest); digest != "" {
		return digest
	}
	return strings.TrimSpace(t.Tag)
}

type ScanRequest struct {
	ID             string            `json:"id"`
	RequestedBy    string            `json:"requested_by,omitempty"`
	Target         ScanTarget        `json:"target"`
	DryRun         bool              `json:"dry_run,omitempty"`
	KeepFilesystem bool              `json:"keep_filesystem,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	SubmittedAt    time.Time         `json:"submitted_at"`
}

type LayerArtifact struct {
	Digest       string     `json:"digest"`
	MediaType    string     `json:"media_type,omitempty"`
	Size         int64      `json:"size,omitempty"`
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"`
	AppliedAt    *time.Time `json:"applied_at,omitempty"`
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
	RunID      string                `json:"run_id"`
	Target     ScanTarget            `json:"target"`
	Manifest   scanner.ImageManifest `json:"manifest"`
	Filesystem *FilesystemArtifact   `json:"filesystem,omitempty"`
	Metadata   map[string]string     `json:"metadata,omitempty"`
}

type AnalysisReport struct {
	Analyzer                     string                      `json:"analyzer"`
	NativeVulnerabilityCount     int                         `json:"native_vulnerability_count,omitempty"`
	FilesystemVulnerabilityCount int                         `json:"filesystem_vulnerability_count,omitempty"`
	Catalog                      *filesystemanalyzer.Report  `json:"catalog,omitempty"`
	Result                       scanner.ContainerScanResult `json:"result"`
	Metadata                     map[string]any              `json:"metadata,omitempty"`
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
	ID             string                 `json:"id"`
	Registry       RegistryKind           `json:"registry"`
	Status         RunStatus              `json:"status"`
	Stage          RunStage               `json:"stage"`
	Target         ScanTarget             `json:"target"`
	RequestedBy    string                 `json:"requested_by,omitempty"`
	DryRun         bool                   `json:"dry_run,omitempty"`
	KeepFilesystem bool                   `json:"keep_filesystem,omitempty"`
	Metadata       map[string]string      `json:"metadata,omitempty"`
	SubmittedAt    time.Time              `json:"submitted_at"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Error          string                 `json:"error,omitempty"`
	Manifest       *scanner.ImageManifest `json:"manifest,omitempty"`
	Layers         []LayerArtifact        `json:"layers,omitempty"`
	Filesystem     *FilesystemArtifact    `json:"filesystem,omitempty"`
	Analysis       *AnalysisReport        `json:"analysis,omitempty"`
}

type RunListOptions struct {
	Statuses           []RunStatus
	ActiveOnly         bool
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}
