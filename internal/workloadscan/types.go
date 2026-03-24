package workloadscan

import (
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

type ProviderKind string

const (
	ProviderAWS   ProviderKind = "aws"
	ProviderGCP   ProviderKind = "gcp"
	ProviderAzure ProviderKind = "azure"
)

type SnapshotScope string

const (
	SnapshotScopeSource     SnapshotScope = "source"
	SnapshotScopeInspection SnapshotScope = "inspection"
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
	RunStageQueued       RunStage = "queued"
	RunStageInventory    RunStage = "inventory"
	RunStageSnapshot     RunStage = "snapshot"
	RunStageShare        RunStage = "share"
	RunStageVolumeCreate RunStage = "volume_create"
	RunStageAttach       RunStage = "attach"
	RunStageMount        RunStage = "mount"
	RunStageAnalyze      RunStage = "analyze"
	RunStageCleanup      RunStage = "cleanup"
	RunStageReconcile    RunStage = "reconcile"
	RunStageCompleted    RunStage = "completed"
	RunStageFailed       RunStage = "failed"
)

type ScanPriority string

const (
	ScanPriorityCritical ScanPriority = "critical"
	ScanPriorityHigh     ScanPriority = "high"
	ScanPriorityMedium   ScanPriority = "medium"
	ScanPriorityLow      ScanPriority = "low"
)

type PrioritySignal struct {
	Category string `json:"category"`
	Weight   int    `json:"weight"`
	Summary  string `json:"summary"`
}

type PriorityAssessment struct {
	Score            int              `json:"score"`
	Priority         ScanPriority     `json:"priority"`
	Eligible         bool             `json:"eligible"`
	Source           string           `json:"source,omitempty"`
	Reasons          []string         `json:"reasons,omitempty"`
	Exposure         string           `json:"exposure,omitempty"`
	Privilege        string           `json:"privilege,omitempty"`
	Criticality      string           `json:"criticality,omitempty"`
	ComplianceScopes []string         `json:"compliance_scopes,omitempty"`
	Staleness        string           `json:"staleness,omitempty"`
	LastScannedAt    *time.Time       `json:"last_scanned_at,omitempty"`
	Signals          []PrioritySignal `json:"signals,omitempty"`
}

type TargetPriority struct {
	NodeID      string             `json:"node_id"`
	DisplayName string             `json:"display_name"`
	Provider    ProviderKind       `json:"provider"`
	Target      VMTarget           `json:"target"`
	Assessment  PriorityAssessment `json:"assessment"`
}

type ScanRequest struct {
	ID                     string              `json:"id"`
	RequestedBy            string              `json:"requested_by,omitempty"`
	Target                 VMTarget            `json:"target"`
	ScannerHost            ScannerHost         `json:"scanner_host"`
	MaxConcurrentSnapshots int                 `json:"max_concurrent_snapshots,omitempty"`
	DryRun                 bool                `json:"dry_run,omitempty"`
	Metadata               map[string]string   `json:"metadata,omitempty"`
	Priority               *PriorityAssessment `json:"priority,omitempty"`
	SubmittedAt            time.Time           `json:"submitted_at"`
}

type VMTarget struct {
	Provider       ProviderKind `json:"provider"`
	AccountID      string       `json:"account_id,omitempty"`
	ProjectID      string       `json:"project_id,omitempty"`
	SubscriptionID string       `json:"subscription_id,omitempty"`
	ResourceGroup  string       `json:"resource_group,omitempty"`
	Region         string       `json:"region"`
	Zone           string       `json:"zone,omitempty"`
	InstanceID     string       `json:"instance_id,omitempty"`
	InstanceName   string       `json:"instance_name,omitempty"`
}

func (t VMTarget) Identity() string {
	switch t.Provider {
	case ProviderAWS:
		if t.InstanceID != "" {
			return t.InstanceID
		}
	case ProviderGCP:
		if t.InstanceName != "" {
			return t.ProjectID + "/" + t.Zone + "/" + t.InstanceName
		}
	case ProviderAzure:
		if t.InstanceName != "" {
			return t.SubscriptionID + "/" + t.ResourceGroup + "/" + t.InstanceName
		}
	}
	if t.InstanceID != "" {
		return t.InstanceID
	}
	return t.InstanceName
}

type ScannerHost struct {
	HostID         string `json:"host_id"`
	AccountID      string `json:"account_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	ResourceGroup  string `json:"resource_group,omitempty"`
	Region         string `json:"region"`
	Zone           string `json:"zone,omitempty"`
}

type SourceVolume struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	DeviceName string         `json:"device_name,omitempty"`
	Region     string         `json:"region,omitempty"`
	Zone       string         `json:"zone,omitempty"`
	SizeGiB    int64          `json:"size_gib"`
	Encrypted  bool           `json:"encrypted,omitempty"`
	KMSKeyID   string         `json:"kms_key_id,omitempty"`
	Boot       bool           `json:"boot,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type SnapshotArtifact struct {
	ID               string               `json:"id"`
	VolumeID         string               `json:"volume_id"`
	AccountID        string               `json:"account_id,omitempty"`
	ProjectID        string               `json:"project_id,omitempty"`
	Region           string               `json:"region,omitempty"`
	Zone             string               `json:"zone,omitempty"`
	SizeGiB          int64                `json:"size_gib"`
	Encrypted        bool                 `json:"encrypted,omitempty"`
	KMSKeyID         string               `json:"kms_key_id,omitempty"`
	Scope            SnapshotScope        `json:"scope,omitempty"`
	Shared           bool                 `json:"shared,omitempty"`
	CleanupSnapshots []SnapshotCleanupRef `json:"cleanup_snapshots,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	ReadyAt          *time.Time           `json:"ready_at,omitempty"`
	DeletedAt        *time.Time           `json:"deleted_at,omitempty"`
	Metadata         map[string]any       `json:"metadata,omitempty"`
}

type SnapshotCleanupRef struct {
	ID        string        `json:"id"`
	Scope     SnapshotScope `json:"scope,omitempty"`
	AccountID string        `json:"account_id,omitempty"`
	Region    string        `json:"region,omitempty"`
}

type InspectionVolume struct {
	ID         string         `json:"id"`
	SnapshotID string         `json:"snapshot_id"`
	Region     string         `json:"region,omitempty"`
	Zone       string         `json:"zone,omitempty"`
	SizeGiB    int64          `json:"size_gib"`
	CreatedAt  time.Time      `json:"created_at"`
	ReadyAt    *time.Time     `json:"ready_at,omitempty"`
	DeletedAt  *time.Time     `json:"deleted_at,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type VolumeAttachment struct {
	VolumeID   string         `json:"volume_id"`
	HostID     string         `json:"host_id"`
	DeviceName string         `json:"device_name,omitempty"`
	ReadOnly   bool           `json:"read_only,omitempty"`
	AttachedAt time.Time      `json:"attached_at"`
	DetachedAt *time.Time     `json:"detached_at,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type MountedVolume struct {
	VolumeID    string         `json:"volume_id"`
	DevicePath  string         `json:"device_path,omitempty"`
	MountPath   string         `json:"mount_path"`
	MountedAt   time.Time      `json:"mounted_at"`
	UnmountedAt *time.Time     `json:"unmounted_at,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type AnalysisInput struct {
	RunID       string            `json:"run_id"`
	Target      VMTarget          `json:"target"`
	ScannerHost ScannerHost       `json:"scanner_host"`
	Volume      SourceVolume      `json:"volume"`
	Mount       MountedVolume     `json:"mount"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type AnalysisReport struct {
	FindingCount int64                      `json:"finding_count"`
	SBOMRef      string                     `json:"sbom_ref,omitempty"`
	Catalog      *filesystemanalyzer.Report `json:"catalog,omitempty"`
	Metadata     map[string]any             `json:"metadata,omitempty"`
}

type DistributedRunState struct {
	GroupID    string     `json:"group_id,omitempty"`
	DedupKey   string     `json:"dedup_key,omitempty"`
	AssignedAt *time.Time `json:"assigned_at,omitempty"`
	ClaimedAt  *time.Time `json:"claimed_at,omitempty"`
	ClaimedBy  string     `json:"claimed_by,omitempty"`
}

type CostBreakdown struct {
	SnapshotGiBHours float64 `json:"snapshot_gib_hours,omitempty"`
	VolumeGiBHours   float64 `json:"volume_gib_hours,omitempty"`
}

type CleanupState struct {
	Unmounted       bool       `json:"unmounted,omitempty"`
	Detached        bool       `json:"detached,omitempty"`
	DeletedVolume   bool       `json:"deleted_volume,omitempty"`
	DeletedSnapshot bool       `json:"deleted_snapshot,omitempty"`
	LastAttemptAt   *time.Time `json:"last_attempt_at,omitempty"`
	Error           string     `json:"error,omitempty"`
	Reconciled      bool       `json:"reconciled,omitempty"`
}

type VolumeScanRecord struct {
	Source      SourceVolume      `json:"source"`
	Status      RunStatus         `json:"status"`
	Stage       RunStage          `json:"stage"`
	StartedAt   time.Time         `json:"started_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	Snapshot    *SnapshotArtifact `json:"snapshot,omitempty"`
	Inspection  *InspectionVolume `json:"inspection,omitempty"`
	Attachment  *VolumeAttachment `json:"attachment,omitempty"`
	Mount       *MountedVolume    `json:"mount,omitempty"`
	Analysis    *AnalysisReport   `json:"analysis,omitempty"`
	Cleanup     CleanupState      `json:"cleanup,omitempty"`
	Cost        CostBreakdown     `json:"cost,omitempty"`
}

type RunSummary struct {
	VolumeCount       int     `json:"volume_count"`
	SucceededVolumes  int     `json:"succeeded_volumes"`
	FailedVolumes     int     `json:"failed_volumes"`
	Findings          int64   `json:"findings"`
	SnapshotGiBHours  float64 `json:"snapshot_gib_hours"`
	VolumeGiBHours    float64 `json:"volume_gib_hours"`
	ReconciledVolumes int     `json:"reconciled_volumes"`
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
	ID                     string               `json:"id"`
	Provider               ProviderKind         `json:"provider"`
	Status                 RunStatus            `json:"status"`
	Stage                  RunStage             `json:"stage"`
	Target                 VMTarget             `json:"target"`
	ScannerHost            ScannerHost          `json:"scanner_host"`
	RequestedBy            string               `json:"requested_by,omitempty"`
	DryRun                 bool                 `json:"dry_run,omitempty"`
	MaxConcurrentSnapshots int                  `json:"max_concurrent_snapshots,omitempty"`
	Metadata               map[string]string    `json:"metadata,omitempty"`
	Priority               *PriorityAssessment  `json:"priority,omitempty"`
	SubmittedAt            time.Time            `json:"submitted_at"`
	StartedAt              *time.Time           `json:"started_at,omitempty"`
	CompletedAt            *time.Time           `json:"completed_at,omitempty"`
	UpdatedAt              time.Time            `json:"updated_at"`
	Error                  string               `json:"error,omitempty"`
	Summary                RunSummary           `json:"summary"`
	Volumes                []VolumeScanRecord   `json:"volumes,omitempty"`
	Distributed            *DistributedRunState `json:"distributed,omitempty"`
}

type RunListOptions struct {
	Statuses           []RunStatus
	ActiveOnly         bool
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}
