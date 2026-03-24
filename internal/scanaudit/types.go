package scanaudit

import (
	"encoding/json"
	"time"
)

type Config struct {
	RetentionDays int
	Now           func() time.Time
}

type ListOptions struct {
	Namespaces         []string
	Statuses           []string
	ExcludeStatuses    []string
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}

type Record struct {
	Namespace     string          `json:"namespace"`
	RunID         string          `json:"run_id"`
	Kind          string          `json:"kind"`
	Status        string          `json:"status"`
	Stage         string          `json:"stage"`
	SubmittedAt   time.Time       `json:"submitted_at"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
	RequestedBy   string          `json:"requested_by,omitempty"`
	Provider      string          `json:"provider,omitempty"`
	Target        string          `json:"target,omitempty"`
	Configuration map[string]any  `json:"configuration,omitempty"`
	Results       map[string]any  `json:"results,omitempty"`
	Exceptions    []Exception     `json:"exceptions,omitempty"`
	Events        []Event         `json:"events,omitempty"`
	Retention     RetentionPolicy `json:"retention"`
}

type Event struct {
	Sequence   int64          `json:"sequence"`
	Status     string         `json:"status,omitempty"`
	Stage      string         `json:"stage,omitempty"`
	Message    string         `json:"message,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	RecordedAt time.Time      `json:"recorded_at"`
}

type Exception struct {
	Source     string    `json:"source"`
	Status     string    `json:"status,omitempty"`
	Stage      string    `json:"stage,omitempty"`
	Message    string    `json:"message"`
	RecordedAt time.Time `json:"recorded_at"`
}

type ArtifactRetention struct {
	Type     string `json:"type"`
	Count    int    `json:"count,omitempty"`
	Retained bool   `json:"retained"`
}

type RetentionPolicy struct {
	StorageClass  string              `json:"storage_class,omitempty"`
	RetentionTier string              `json:"retention_tier,omitempty"`
	RetentionDays int                 `json:"retention_days,omitempty"`
	RetainUntil   *time.Time          `json:"retain_until,omitempty"`
	Artifacts     []ArtifactRetention `json:"artifacts,omitempty"`
}

type ExportManifest struct {
	Namespace   string `json:"namespace"`
	RunID       string `json:"run_id"`
	Kind        string `json:"kind,omitempty"`
	GeneratedAt string `json:"generated_at"`
	GeneratedBy string `json:"generated_by"`
}

type SBOMArtifact struct {
	Format      string          `json:"format"`
	Filename    string          `json:"filename"`
	ContentType string          `json:"content_type"`
	Document    json.RawMessage `json:"document"`
}

type ExportPackage struct {
	Manifest   ExportManifest `json:"manifest"`
	Record     Record         `json:"record"`
	Events     []Event        `json:"events,omitempty"`
	Exceptions []Exception    `json:"exceptions,omitempty"`
	SBOMs      []SBOMArtifact `json:"sboms,omitempty"`
}
