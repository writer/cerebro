use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Declares whether an observation is authoritative enough for absence claims.
pub struct Completeness {
    /// Machine-readable state; only `complete` can support conclusive comparison.
    #[serde(default)]
    pub state: String,
    /// Stable reason codes explaining every limitation on completeness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Stable identity and display metadata for one node in an exposure proof.
pub struct NodeRef {
    /// Canonical resource identifier used for equality and correlation.
    #[serde(default)]
    pub urn: String,
    /// Provider-neutral node kind, such as principal, resource, or permission.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entity_type: String,
    /// Human-readable name; never used as proof identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// One directed, source-attributed assertion in a security path.
pub struct ProofEdge {
    /// Stable assertion identifier, unique within a path.
    #[serde(default)]
    pub id: String,
    /// Node from which the directed relation originates.
    #[serde(default)]
    pub from: NodeRef,
    /// Provider-neutral relation asserted between the nodes.
    #[serde(default)]
    pub relation: String,
    /// Node at which the directed relation terminates.
    #[serde(default)]
    pub to: NodeRef,
    /// Traversal direction used when constructing the proof.
    #[serde(default)]
    pub direction: String,
    /// Logical collector source that supplied the assertion.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Concrete source runtime that supplied the assertion.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_runtime_id: String,
    /// All source runtimes whose assertions support this edge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_runtime_ids: Vec<String>,
    /// Immutable source event from which the assertion was projected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_event_id: String,
    /// RFC 3339 time at which the source assertion was observed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Stable identity and display name for an accountable owner.
pub struct OwnerRef {
    /// Canonical owner identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Human-readable owner name; never used as identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// An owner assignment together with the graph edge that proves it.
pub struct OwnershipProof {
    /// Owner identified by the proof.
    #[serde(default)]
    pub owner: OwnerRef,
    /// Source-attributed assertion connecting the owner to the path.
    #[serde(default)]
    pub edge: ProofEdge,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Compact pointer to the source observation behind a projected fact.
pub struct ProvenanceRef {
    /// Logical collector source.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Concrete collector runtime.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_id: String,
    /// Immutable event within that runtime.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_id: String,
    /// RFC 3339 time at which the event was observed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// A fully attributed route from public reachability to an effective permission.
///
/// `route_id` groups alternative proofs for the same effective route, while `id`
/// identifies one exact proof. Consequently, a changed path identifier under an
/// unchanged route is a proof change rather than a new or removed exposure.
pub struct SecurityPath {
    /// Stable identifier for this exact proof.
    #[serde(default)]
    pub id: String,
    /// Stable identifier for the effective exposure route.
    #[serde(default)]
    pub route_id: String,
    /// Content digest of the ordered proof material.
    #[serde(default)]
    pub proof_digest: String,
    /// Severity or impact classification supplied by the detector.
    #[serde(default)]
    pub materiality: String,
    /// Stable detector reason codes supporting materiality.
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub reason_codes: Vec<String>,
    /// Externally reachable principal or origin of the path.
    #[serde(default)]
    pub public_principal: NodeRef,
    /// Resource exposed by the public leg of the route.
    #[serde(default)]
    pub exposed_resource: NodeRef,
    /// Cloud account or equivalent administrative boundary.
    #[serde(default)]
    pub cloud_account: NodeRef,
    /// Principal that acquires the effective permission.
    #[serde(default)]
    pub principal: NodeRef,
    /// Effective permission reached by the route.
    #[serde(default)]
    pub permission: NodeRef,
    /// Ordered graph assertions proving the route.
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub proof_edges: Vec<ProofEdge>,
    /// Machine-readable ownership resolution state.
    #[serde(default)]
    pub ownership_state: String,
    /// Owner assignments and the edges that prove them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ownerships: Vec<OwnershipProof>,
    /// Source observations relevant to the path as a whole.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Collection authority for one concrete source runtime.
///
/// Absence verification uses these receipts to prove that every runtime which
/// supported the reference path was collected again under compatible provider
/// and configuration identity.
pub struct RuntimeCollectionReceipt {
    /// Stable identity of the collector deployment or account integration.
    #[serde(default)]
    pub source_runtime_id: String,
    /// Logical source implemented by the runtime.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Provider family whose semantics define the collected facts.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_family: String,
    /// Immutable revision of the runtime's collection configuration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_revision: String,
    /// Highest source time or cursor conclusively processed by this runtime.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_watermark: String,
    /// RFC 3339 time at which this runtime last completed source synchronization.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    /// Durable graph checkpoint produced from the collected events.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_checkpoint_id: String,
    /// Graph projection run that produced the checkpoint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_id: String,
    /// RFC 3339 start time for the graph projection run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_started_at: String,
    /// RFC 3339 completion time for the graph projection run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_finished_at: String,
    /// Whether the projection run reached its declared end without truncation.
    #[serde(default)]
    pub graph_checkpoint_complete: bool,
    /// Whether the checkpoint is still the active projection for this runtime.
    #[serde(default)]
    pub graph_checkpoint_current: bool,
    /// Stable reason codes that prevent this receipt from proving completeness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Auditable evidence that a snapshot's collection and projection completed.
///
/// A receipt records both source ingestion and graph projection. Boolean fields
/// are independent assertions; for example, requesting reconciliation does not
/// prove that the provider supported it or that it completed.
pub struct CollectionReceipt {
    /// Stable receipt identifier.
    #[serde(default)]
    pub id: String,
    /// Primary runtime associated with the collection.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_runtime_id: String,
    /// Logical source associated with the collection.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Provider family governing source semantics.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_family: String,
    /// Immutable collection-configuration revision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_revision: String,
    /// Highest source time or cursor conclusively processed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_watermark: String,
    /// RFC 3339 time of the last completed source synchronization.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    /// Collection strategy; absence verification requires `graph_reset_full_scan`.
    #[serde(default)]
    pub collection_mode: String,
    /// Number of source API pages read.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_pages_read: usize,
    /// Number of immutable source events appended.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_events_appended: usize,
    /// Number of source entities projected into the graph.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_entities_projected: usize,
    /// Number of source relationships projected into the graph.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_links_projected: usize,
    /// Durable checkpoint containing the evaluated graph state.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_checkpoint_id: String,
    /// Projection run that produced the checkpoint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_id: String,
    /// RFC 3339 start time of the projection run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_started_at: String,
    /// RFC 3339 completion time of the projection run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_finished_at: String,
    /// Number of event or storage pages read during graph projection.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_pages_read: usize,
    /// Number of source events consumed during graph projection.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_events_read: usize,
    /// Number of entities written during graph projection.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_entities_projected: usize,
    /// Number of relationships written during graph projection.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_links_projected: usize,
    /// Whether stale material-link reconciliation was requested for the run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_requested: bool,
    /// Whether the graph backend could perform the requested reconciliation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_supported: bool,
    /// Whether requested reconciliation finished successfully.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_completed: bool,
    /// Number of stale material relationships removed by reconciliation.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_stale_material_links_deleted: usize,
    /// Whether the checkpoint contains the complete declared projection scope.
    #[serde(default)]
    pub graph_checkpoint_complete: bool,
    /// Whether this checkpoint remains current for its declared projection scope.
    #[serde(default)]
    pub graph_checkpoint_current: bool,
    /// Number of paths emitted into this snapshot.
    #[serde(default)]
    pub observed_path_count: usize,
    /// Total paths expected for the completed detector scope.
    #[serde(default)]
    pub total_path_count: usize,
    /// Whether the collector held the exclusive lease while producing the snapshot.
    #[serde(default)]
    pub lease_held: bool,
    /// Stable reason codes limiting the receipt's authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    /// Source runtimes whose evidence is within the verification scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_runtime_ids: Vec<String>,
    /// Per-runtime receipts used to establish fresh, compatible recollection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_receipts: Vec<RuntimeCollectionReceipt>,
    /// Content digest binding the receipt fields.
    #[serde(default)]
    pub digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Immutable detector output for one tenant, scope, revision, and observation.
///
/// Snapshot identity and time are mandatory. Completeness is evaluated from both
/// [`Completeness`] and [`CollectionReceipt`]; a caller cannot make an absence
/// authoritative merely by setting one state string to `complete`.
pub struct Snapshot {
    /// Stable snapshot identifier.
    #[serde(default)]
    pub id: String,
    /// Tenant whose evidence is represented.
    #[serde(default)]
    pub tenant_id: String,
    /// Provider-neutral boundary evaluated by the detector.
    #[serde(default)]
    pub scope_id: String,
    /// Detector implementation that emitted the paths.
    #[serde(default)]
    pub detector_id: String,
    /// Detector revision whose semantics must match across comparison snapshots.
    #[serde(default)]
    pub detector_revision: String,
    /// Source observation correlated with this detector run.
    #[serde(default)]
    pub observation_id: String,
    /// RFC 3339 time at which the snapshot was observed.
    #[serde(default)]
    pub observed_at: String,
    /// Evidence that collection and graph projection covered the declared scope.
    #[serde(default)]
    pub collection_receipt: CollectionReceipt,
    /// Explicit completeness state and any limiting reasons.
    #[serde(default)]
    pub completeness: Completeness,
    /// Deterministically identified exposure proofs in the snapshot.
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub paths: Vec<SecurityPath>,
    /// Content digest of the normalized path set.
    #[serde(default)]
    pub path_set_digest: String,
    /// SHA-256 digest binding the complete snapshot.
    #[serde(default)]
    pub digest: String,
}

/// Current schema identifier for content-bound decision requests and responses.
pub const DECISION_INPUT_V1: &str = "security-path-decision-input/v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Content-bound envelope accepted by [`crate::evaluate`].
pub struct EvaluationRequest {
    /// Decision schema; currently must equal [`DECISION_INPUT_V1`].
    pub schema_version: String,
    /// Canonical SHA-256 digest calculated over the complete [`DecisionRequest`].
    pub input_digest: String,
    /// Operation and all evidence on which the decision depends.
    pub request: DecisionRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
/// Supported deterministic security-path operations.
pub enum DecisionRequest {
    /// Compare a later snapshot with an optional earlier observation.
    Compare {
        /// Earlier snapshot, or `None` for an initial observation.
        #[serde(default)]
        before: Option<Snapshot>,
        /// Later snapshot to classify.
        after: Snapshot,
    },
    /// Verify that selected reference paths are absent after fresh collection.
    VerifyObservedAbsent {
        /// Snapshot in which every requested path was observed.
        reference: Snapshot,
        /// Strictly later snapshot used to test route absence.
        after: Snapshot,
        /// Exact reference path identifiers whose routes must be checked.
        #[serde(default)]
        requested_path_ids: Vec<String>,
    },
    /// Rank shared proof edges without authorizing any remediation.
    RankCandidateCuts {
        /// Paths whose distinct route and path coverage will be counted.
        #[serde(default, deserialize_with = "deserialize_default_on_null")]
        paths: Vec<SecurityPath>,
    },
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
/// Deterministic result envelope bound to its source snapshots and input.
pub struct EvaluationResponse {
    /// Decision schema used to interpret the result.
    pub schema_version: String,
    /// Digest copied from the successfully verified request envelope.
    pub input_digest: String,
    /// Sorted snapshot digests on which the decision depends.
    pub source_snapshot_digests: Vec<String>,
    /// Operation-specific decision.
    pub response: DecisionResponse,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
/// Operation-specific result returned by the kernel.
pub enum DecisionResponse {
    /// Result of comparing two snapshots or recording an initial observation.
    Compare {
        /// Comparison decision and its content digest.
        result: ComparisonDecision,
    },
    /// Result of testing requested routes for authoritative absence.
    VerifyObservedAbsent {
        /// Verification state, reasons, remaining paths, and content digest.
        result: VerificationDecision,
    },
    /// Deterministically ordered proof-edge candidates.
    RankCandidateCuts {
        /// Ranked candidates; every entry remains `candidate_only`.
        result: Vec<CandidateEdgeCut>,
    },
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
/// Records alternative proof identities for one unchanged exposure route.
pub struct ProofChange {
    /// Route whose effective exposure persisted while its proof changed.
    pub route_id: String,
    /// Sorted proof identifiers present before the change.
    pub before_path_ids: Vec<String>,
    /// Sorted proof identifiers present after the change.
    pub after_path_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
/// One proof edge ranked as a possible intervention point.
///
/// This record deliberately expresses coverage, not safety, feasibility, desired
/// access, or authorization. Those judgments belong to the remediation owner.
pub struct CandidateEdgeCut {
    /// One-based position in the deterministic candidate ordering.
    pub rank: usize,
    /// Authority state; currently always `candidate_only`.
    pub state: String,
    /// Source-attributed proof edge shared by the covered paths.
    pub edge: ProofEdge,
    /// Sorted identifiers of distinct routes containing the edge.
    pub covered_route_ids: Vec<String>,
    /// Sorted identifiers of distinct paths containing the edge.
    pub covered_path_ids: Vec<String>,
    /// Number of distinct covered routes.
    pub route_coverage: usize,
    /// Number of distinct covered paths.
    pub path_coverage: usize,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
/// Classification of path changes between two snapshots.
pub struct ComparisonDecision {
    /// `initial_observation`, `indeterminate`, or `compared`.
    pub state: String,
    /// Sorted paths belonging to routes absent from the earlier snapshot.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub newly_observed_path_ids: Vec<String>,
    /// Sorted paths belonging to routes absent from the later snapshot.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_longer_observed_path_ids: Vec<String>,
    /// Routes that persist under different exact proof identifiers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_changed: Vec<ProofChange>,
    /// Number of routes whose exact path identifiers did not change.
    pub unchanged_routes: usize,
    /// Candidate cuts for newly observed paths only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_edge_cuts: Vec<CandidateEdgeCut>,
    /// Canonical digest binding every decision field except itself.
    pub digest: String,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
/// Result of checking requested reference routes against a later snapshot.
pub struct VerificationDecision {
    /// Normalized, sorted reference path identifiers supplied by the caller.
    pub requested_path_ids: Vec<String>,
    /// Normalized, sorted routes derived from those reference paths.
    pub requested_route_ids: Vec<String>,
    /// `observed_absent`, `still_observed`, or `indeterminate`.
    pub state: String,
    /// Stable reasons preventing an authoritative absence decision.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Later path identifiers proving that a requested route remains observed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub still_observed_path_ids: Vec<String>,
    /// Candidate cuts for paths that remain observed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_edge_cuts: Vec<CandidateEdgeCut>,
    /// Canonical digest binding every decision field except itself.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Rejected input at the deterministic kernel boundary.
pub enum KernelError {
    /// The request schema is not supported by this kernel build.
    UnsupportedSchemaVersion,
    /// The supplied request digest differs from the canonical input digest.
    InputDigestMismatch,
    /// Snapshot identity, digest, or another snapshot invariant is invalid.
    InvalidSnapshot(&'static str),
    /// An operation-specific bound or structural invariant is invalid.
    InvalidInput(&'static str),
    /// A requested path does not exist in the reference snapshot.
    InvalidRequestedPath(String),
    /// An observation or receipt time is not valid RFC 3339.
    InvalidTime,
}

impl fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion => formatter.write_str("unsupported schema version"),
            Self::InputDigestMismatch => formatter.write_str("input digest does not match request"),
            Self::InvalidSnapshot(reason) => write!(formatter, "invalid snapshot: {reason}"),
            Self::InvalidInput(reason) => write!(formatter, "invalid input: {reason}"),
            Self::InvalidRequestedPath(path_id) => {
                write!(
                    formatter,
                    "requested path is absent from reference: {path_id}"
                )
            }
            Self::InvalidTime => formatter.write_str("invalid RFC3339 observation time"),
        }
    }
}

impl Error for KernelError {}

const fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::{CollectionReceipt, KernelError};

    #[test]
    fn kernel_errors_have_stable_messages() {
        let cases = [
            (
                KernelError::InvalidSnapshot("missing id"),
                "invalid snapshot: missing id",
            ),
            (
                KernelError::InvalidInput("missing paths"),
                "invalid input: missing paths",
            ),
            (
                KernelError::InvalidRequestedPath("path-a".to_owned()),
                "requested path is absent from reference: path-a",
            ),
            (KernelError::InvalidTime, "invalid RFC3339 observation time"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn receipt_serialization_omits_only_zero_counts() {
        let empty = serde_json::to_value(CollectionReceipt::default()).expect("serialize receipt");
        assert!(empty.get("source_pages_read").is_none());

        let populated = serde_json::to_value(CollectionReceipt {
            source_pages_read: 1,
            ..CollectionReceipt::default()
        })
        .expect("serialize receipt");
        assert_eq!(populated["source_pages_read"], 1);
    }
}
