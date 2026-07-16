package policycandidate

import (
	"context"
	"time"
)

const (
	ExperimentStatusQueued    = "queued"
	ExperimentStatusRunning   = "running"
	ExperimentStatusCompleted = "completed"
	ExperimentStatusFailed    = "failed"
	ExperimentStatusBlocked   = "blocked"

	DefaultExperimentListLimit            = 25
	MaxExperimentListLimit                = 100
	DefaultExperimentObservationListLimit = 100
	MaxExperimentObservationListLimit     = 500
	MaxExperimentCheckpoints              = 64
	MaxExperimentObservations             = 500
	MaxExperimentMetrics                  = 32
	MaxExperimentStatusReasonBytes        = 512
	MaxExperimentLabelBytes               = 256
)

// PolicyExperimentCheckpoint pins the exact graph checkpoint evaluated by a
// run. Complete and Current are observations made when the run is created;
// changing graph state requires a new experiment instead of mutating the pin.
type PolicyExperimentCheckpoint struct {
	RuntimeID string `json:"runtime_id"`
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Complete  bool   `json:"complete"`
	Current   bool   `json:"current"`
}

type ExperimentCheckpointStatus struct {
	RuntimeID         string
	TenantID          string
	CheckpointID      string
	Found             bool
	Completed         bool
	CheckpointCurrent bool
}

type ExperimentCheckpointStatusReader interface {
	PolicyExperimentCheckpointStatus(context.Context, string) (ExperimentCheckpointStatus, error)
}

// PolicyExperimentPins make a run reproducible even after its candidate,
// catalog, dataset, or graph state advances.
type PolicyExperimentPins struct {
	CandidateRevision int64                        `json:"candidate_revision"`
	PolicyDigest      string                       `json:"policy_digest"`
	TestDigest        string                       `json:"test_digest"`
	CatalogDigest     string                       `json:"catalog_digest"`
	DatasetDigest     string                       `json:"dataset_digest"`
	Checkpoints       []PolicyExperimentCheckpoint `json:"checkpoints"`
}

type PolicyExperiment struct {
	ID               string               `json:"id"`
	CandidateID      string               `json:"candidate_id"`
	TenantID         string               `json:"tenant_id"`
	Status           string               `json:"status"`
	Revision         int64                `json:"revision"`
	Pins             PolicyExperimentPins `json:"pins"`
	StatusReason     string               `json:"status_reason,omitempty"`
	ObservationCount int64                `json:"observation_count"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	StartedAt        time.Time            `json:"started_at,omitempty"`
	FinishedAt       time.Time            `json:"finished_at,omitempty"`
}

// PolicyExperimentObservation is append-only evidence produced by one run.
// It stores bounded metrics and digests, not raw graph rows.
type PolicyExperimentObservation struct {
	ID             string             `json:"id"`
	ExperimentID   string             `json:"experiment_id"`
	TenantID       string             `json:"tenant_id"`
	Sequence       int64              `json:"sequence"`
	Kind           string             `json:"kind"`
	CheckpointID   string             `json:"checkpoint_id,omitempty"`
	DatasetCaseID  string             `json:"dataset_case_id,omitempty"`
	ReceiptDigest  string             `json:"receipt_digest"`
	IdempotencyKey string             `json:"-"`
	Metrics        map[string]float64 `json:"metrics,omitempty"`
	ObservedAt     time.Time          `json:"observed_at"`
	CreatedAt      time.Time          `json:"created_at"`
}

type CreateExperimentRequest struct {
	CandidateID    string
	IdempotencyKey string
	DatasetDigest  string
	Checkpoints    []PolicyExperimentCheckpoint
}

type ListExperimentsRequest struct {
	TenantID    string
	CandidateID string
	Status      string
	Limit       int
}

type TransitionExperimentRequest struct {
	ExperimentID     string
	ExpectedRevision int64
	Status           string
	Reason           string
}

type AppendExperimentObservationRequest struct {
	ExperimentID   string
	Kind           string
	CheckpointID   string
	DatasetCaseID  string
	ReceiptDigest  string
	IdempotencyKey string
	Metrics        map[string]float64
	ObservedAt     time.Time
}

type ListExperimentObservationsRequest struct {
	ExperimentID string
	Limit        int
}

type ExperimentStore interface {
	CreatePolicyExperiment(context.Context, *PolicyExperiment) error
	GetPolicyExperiment(context.Context, string) (*PolicyExperiment, error)
	ListPolicyExperiments(context.Context, ListExperimentsRequest) ([]*PolicyExperiment, error)
	SavePolicyExperiment(context.Context, *PolicyExperiment, int64) error
	AppendPolicyExperimentObservation(context.Context, *PolicyExperimentObservation) (*PolicyExperimentObservation, error)
	ListPolicyExperimentObservations(context.Context, ListExperimentObservationsRequest) ([]*PolicyExperimentObservation, error)
}
