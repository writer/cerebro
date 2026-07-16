// Package securitypathdelta derives deterministic, fail-closed changes between
// observed attack-path snapshots. It does not predict provider behavior or claim
// that a candidate relationship can be changed safely.
package securitypathdelta

import (
	"errors"
	"time"

	"github.com/writer/cerebro/internal/attackpath"
)

var ErrInvalidInput = errors.New("invalid security path delta input")

type CompletenessState string

const (
	CompletenessComplete   CompletenessState = "complete"
	CompletenessIncomplete CompletenessState = "incomplete"
)

type Completeness struct {
	State   CompletenessState `json:"state"`
	Reasons []string          `json:"reasons,omitempty"`
}

type OwnerRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type OwnershipProof struct {
	Owner OwnerRef  `json:"owner"`
	Edge  ProofEdge `json:"edge"`
}

type ProvenanceRef struct {
	SourceID   string    `json:"source_id,omitempty"`
	RuntimeID  string    `json:"runtime_id,omitempty"`
	EventID    string    `json:"event_id,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
}

// ObservedPath binds one concrete attack-path observation to operator context
// that is not yet carried by attackpath.Path itself.
type ObservedPath struct {
	Path       attackpath.Path
	Provenance []ProvenanceRef
}

// CollectionSourceReceipt identifies the source state used by one collection.
type CollectionSourceReceipt struct {
	SourceRuntimeID string `json:"source_runtime_id,omitempty"`
	SourceID        string `json:"source_id,omitempty"`
	// ProviderFamily identifies the normalized provider collection family.
	ProviderFamily string `json:"provider_family,omitempty"`
	// ConfigRevision is a stable non-secret revision; callers must not pass raw configuration.
	ConfigRevision   string    `json:"config_revision,omitempty"`
	RuntimeWatermark time.Time `json:"runtime_watermark,omitempty"`
	LastSyncedAt     time.Time `json:"last_synced_at,omitempty"`
	CollectionMode   string    `json:"collection_mode"`
}

// CollectionSourceProjectionReceipt records source-side collection volume.
type CollectionSourceProjectionReceipt struct {
	SourcePagesRead         int `json:"source_pages_read,omitempty"`
	SourceEventsAppended    int `json:"source_events_appended,omitempty"`
	SourceEntitiesProjected int `json:"source_entities_projected,omitempty"`
	SourceLinksProjected    int `json:"source_links_projected,omitempty"`
}

// CollectionGraphProjectionReceipt records graph-side collection volume.
type CollectionGraphProjectionReceipt struct {
	GraphPagesRead                 int `json:"graph_pages_read,omitempty"`
	GraphEventsRead                int `json:"graph_events_read,omitempty"`
	GraphEntitiesProjected         int `json:"graph_entities_projected,omitempty"`
	GraphLinksProjected            int `json:"graph_links_projected,omitempty"`
	GraphStaleMaterialLinksDeleted int `json:"graph_stale_material_links_deleted,omitempty"`
}

// CollectionGraphReceipt records the graph checkpoint and projection state.
type CollectionGraphReceipt struct {
	GraphCheckpointID                        string    `json:"graph_checkpoint_id,omitempty"`
	GraphRunID                               string    `json:"graph_run_id,omitempty"`
	GraphRunStartedAt                        time.Time `json:"graph_run_started_at,omitempty"`
	GraphRunFinishedAt                       time.Time `json:"graph_run_finished_at,omitempty"`
	GraphPagesRead                           int       `json:"graph_pages_read,omitempty"`
	GraphEventsRead                          int       `json:"graph_events_read,omitempty"`
	GraphEntitiesProjected                   int       `json:"graph_entities_projected,omitempty"`
	GraphLinksProjected                      int       `json:"graph_links_projected,omitempty"`
	GraphMaterialLinkReconciliationRequested bool      `json:"graph_material_link_reconciliation_requested,omitempty"`
	GraphMaterialLinkReconciliationSupported bool      `json:"graph_material_link_reconciliation_supported,omitempty"`
	GraphMaterialLinkReconciliationCompleted bool      `json:"graph_material_link_reconciliation_completed,omitempty"`
	GraphStaleMaterialLinksDeleted           int       `json:"graph_stale_material_links_deleted,omitempty"`
	GraphCheckpointComplete                  bool      `json:"graph_checkpoint_complete"`
	GraphCheckpointCurrent                   bool      `json:"graph_checkpoint_current"`
}

// CollectionPathReceipt records the observed path coverage and collection limits.
type CollectionPathReceipt struct {
	ObservedPathCount int      `json:"observed_path_count"`
	TotalPathCount    int      `json:"total_path_count"`
	LeaseHeld         bool     `json:"lease_held"`
	Limitations       []string `json:"limitations,omitempty"`
}

type CollectionReceiptInput struct {
	SourceRuntimeID string
	SourceID        string
	// ProviderFamily identifies the normalized provider collection family.
	ProviderFamily string
	// ConfigRevision is a stable non-secret revision; callers must not pass raw configuration.
	ConfigRevision   string
	RuntimeWatermark time.Time
	LastSyncedAt     time.Time
	CollectionMode   string
	CollectionSourceProjectionReceipt
	GraphCheckpointID  string
	GraphRunID         string
	GraphRunStartedAt  time.Time
	GraphRunFinishedAt time.Time
	CollectionGraphProjectionReceipt
	GraphMaterialLinkReconciliationRequested bool
	GraphMaterialLinkReconciliationSupported bool
	GraphMaterialLinkReconciliationCompleted bool
	GraphCheckpointComplete                  bool
	GraphCheckpointCurrent                   bool
	ObservedPathCount                        int
	TotalPathCount                           int
	LeaseHeld                                bool
	Limitations                              []string
	RuntimeReceipts                          []RuntimeCollectionReceiptInput
}

// RuntimeCollectionReceiptInput records the latest source and graph state for
// one runtime that contributed proof to an observed path.
type RuntimeCollectionReceiptInput struct {
	SourceRuntimeID string
	SourceID        string
	// ProviderFamily identifies the normalized provider collection family.
	ProviderFamily string
	// ConfigRevision is a stable non-secret revision; callers must not pass raw configuration.
	ConfigRevision          string
	RuntimeWatermark        time.Time
	LastSyncedAt            time.Time
	GraphCheckpointID       string
	GraphRunID              string
	GraphRunStartedAt       time.Time
	GraphRunFinishedAt      time.Time
	GraphCheckpointComplete bool
	GraphCheckpointCurrent  bool
	Limitations             []string
}

type RuntimeCollectionReceipt struct {
	SourceRuntimeID         string    `json:"source_runtime_id"`
	SourceID                string    `json:"source_id,omitempty"`
	ProviderFamily          string    `json:"provider_family,omitempty"`
	ConfigRevision          string    `json:"config_revision,omitempty"`
	RuntimeWatermark        time.Time `json:"runtime_watermark,omitempty"`
	LastSyncedAt            time.Time `json:"last_synced_at,omitempty"`
	GraphCheckpointID       string    `json:"graph_checkpoint_id,omitempty"`
	GraphRunID              string    `json:"graph_run_id,omitempty"`
	GraphRunStartedAt       time.Time `json:"graph_run_started_at,omitempty"`
	GraphRunFinishedAt      time.Time `json:"graph_run_finished_at,omitempty"`
	GraphCheckpointComplete bool      `json:"graph_checkpoint_complete"`
	GraphCheckpointCurrent  bool      `json:"graph_checkpoint_current"`
	Limitations             []string  `json:"limitations,omitempty"`
}

type CollectionReceipt struct {
	ID string `json:"id"`
	CollectionSourceReceipt
	CollectionSourceProjectionReceipt
	CollectionGraphReceipt
	CollectionPathReceipt
	ProofRuntimeIDs []string                   `json:"proof_runtime_ids,omitempty"`
	RuntimeReceipts []RuntimeCollectionReceipt `json:"runtime_receipts,omitempty"`
	Digest          string                     `json:"digest"`
}

type SnapshotInput struct {
	TenantID                string
	ScopeID                 string
	DetectorID              string
	DetectorRevision        string
	ObservationID           string
	ObservedAt              time.Time
	Receipt                 CollectionReceiptInput
	IncompleteReasons       []string
	RequiredProofRuntimeIDs []string
	Paths                   []ObservedPath
}

type NodeRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type,omitempty"`
	Label      string `json:"label,omitempty"`
}

type ProofEdge struct {
	ID                  string    `json:"id"`
	From                NodeRef   `json:"from"`
	Relation            string    `json:"relation"`
	To                  NodeRef   `json:"to"`
	Direction           string    `json:"direction"`
	SourceID            string    `json:"source_id,omitempty"`
	SourceRuntimeID     string    `json:"source_runtime_id,omitempty"`
	AssertionRuntimeIDs []string  `json:"assertion_runtime_ids,omitempty"`
	SourceEventID       string    `json:"source_event_id,omitempty"`
	ObservedAt          time.Time `json:"observed_at,omitempty"`
}

type SecurityPath struct {
	ID              string           `json:"id"`
	RouteID         string           `json:"route_id"`
	ProofDigest     string           `json:"proof_digest"`
	Materiality     string           `json:"materiality"`
	ReasonCodes     []string         `json:"reason_codes"`
	PublicPrincipal NodeRef          `json:"public_principal"`
	ExposedResource NodeRef          `json:"exposed_resource"`
	CloudAccount    NodeRef          `json:"cloud_account"`
	Principal       NodeRef          `json:"principal"`
	Permission      NodeRef          `json:"permission"`
	ProofEdges      []ProofEdge      `json:"proof_edges"`
	OwnershipState  string           `json:"ownership_state"`
	Ownerships      []OwnershipProof `json:"ownerships,omitempty"`
	Provenance      []ProvenanceRef  `json:"provenance,omitempty"`
}

type Snapshot struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	ScopeID          string            `json:"scope_id"`
	DetectorID       string            `json:"detector_id"`
	DetectorRevision string            `json:"detector_revision"`
	ObservationID    string            `json:"observation_id"`
	ObservedAt       time.Time         `json:"observed_at"`
	Receipt          CollectionReceipt `json:"collection_receipt"`
	Completeness     Completeness      `json:"completeness"`
	Paths            []SecurityPath    `json:"paths"`
	PathSetDigest    string            `json:"path_set_digest"`
	Digest           string            `json:"digest"`
}

type SnapshotRef struct {
	ID           string       `json:"id,omitempty"`
	Digest       string       `json:"digest,omitempty"`
	ObservedAt   time.Time    `json:"observed_at,omitempty"`
	Completeness Completeness `json:"completeness"`
}

type DeltaState string

const (
	DeltaStateInitial       DeltaState = "initial_observation"
	DeltaStateCompared      DeltaState = "compared"
	DeltaStateIndeterminate DeltaState = "indeterminate"
)

type ProofChange struct {
	RouteID     string         `json:"route_id"`
	BeforePaths []SecurityPath `json:"before_paths"`
	AfterPaths  []SecurityPath `json:"after_paths"`
}

type CandidateEdgeCut struct {
	Rank            int       `json:"rank"`
	State           string    `json:"state"`
	Edge            ProofEdge `json:"edge"`
	CoveredRouteIDs []string  `json:"covered_route_ids"`
	CoveredPathIDs  []string  `json:"covered_path_ids"`
	RouteCoverage   int       `json:"route_coverage"`
	PathCoverage    int       `json:"path_coverage"`
}

type Delta struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	ScopeID           string             `json:"scope_id"`
	DetectorID        string             `json:"detector_id"`
	DetectorRevision  string             `json:"detector_revision"`
	State             DeltaState         `json:"state"`
	Before            SnapshotRef        `json:"before"`
	After             SnapshotRef        `json:"after"`
	NewlyObserved     []SecurityPath     `json:"newly_observed,omitempty"`
	NoLongerObserved  []SecurityPath     `json:"no_longer_observed,omitempty"`
	ProofChanged      []ProofChange      `json:"proof_changed,omitempty"`
	UnchangedRoutes   int                `json:"unchanged_routes"`
	CandidateEdgeCuts []CandidateEdgeCut `json:"candidate_edge_cuts,omitempty"`
	Digest            string             `json:"digest"`
}

type VerificationState string

const (
	VerificationObservedAbsent VerificationState = "observed_absent"
	VerificationStillObserved  VerificationState = "still_observed"
	VerificationIndeterminate  VerificationState = "indeterminate"
)

type Verification struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	ScopeID           string             `json:"scope_id"`
	DetectorID        string             `json:"detector_id"`
	DetectorRevision  string             `json:"detector_revision"`
	Reference         SnapshotRef        `json:"reference"`
	After             SnapshotRef        `json:"after"`
	RequestedPathIDs  []string           `json:"requested_path_ids"`
	RequestedRouteIDs []string           `json:"requested_route_ids"`
	State             VerificationState  `json:"state"`
	Reasons           []string           `json:"reasons,omitempty"`
	StillObserved     []SecurityPath     `json:"still_observed,omitempty"`
	CandidateEdgeCuts []CandidateEdgeCut `json:"candidate_edge_cuts,omitempty"`
	Digest            string             `json:"digest"`
}
