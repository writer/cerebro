use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    #[serde(default)]
    pub state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeRef {
    #[serde(default)]
    pub urn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entity_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProofEdge {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub from: NodeRef,
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub to: NodeRef,
    #[serde(default)]
    pub direction: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_runtime_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_runtime_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_event_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OwnerRef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipProof {
    #[serde(default)]
    pub owner: OwnerRef,
    #[serde(default)]
    pub edge: ProofEdge,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityPath {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub route_id: String,
    #[serde(default)]
    pub proof_digest: String,
    #[serde(default)]
    pub materiality: String,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub public_principal: NodeRef,
    #[serde(default)]
    pub exposed_resource: NodeRef,
    #[serde(default)]
    pub cloud_account: NodeRef,
    #[serde(default)]
    pub principal: NodeRef,
    #[serde(default)]
    pub permission: NodeRef,
    #[serde(default)]
    pub proof_edges: Vec<ProofEdge>,
    #[serde(default)]
    pub ownership_state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ownerships: Vec<OwnershipProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCollectionReceipt {
    #[serde(default)]
    pub source_runtime_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_revision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_watermark: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_checkpoint_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_started_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_finished_at: String,
    #[serde(default)]
    pub graph_checkpoint_complete: bool,
    #[serde(default)]
    pub graph_checkpoint_current: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectionReceipt {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_runtime_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_revision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_watermark: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_synced_at: String,
    #[serde(default)]
    pub collection_mode: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_pages_read: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_events_appended: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_entities_projected: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_links_projected: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_checkpoint_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_started_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub graph_run_finished_at: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_pages_read: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_events_read: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_entities_projected: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_links_projected: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_requested: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_supported: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph_material_link_reconciliation_completed: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graph_stale_material_links_deleted: usize,
    #[serde(default)]
    pub graph_checkpoint_complete: bool,
    #[serde(default)]
    pub graph_checkpoint_current: bool,
    #[serde(default)]
    pub observed_path_count: usize,
    #[serde(default)]
    pub total_path_count: usize,
    #[serde(default)]
    pub lease_held: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_runtime_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_receipts: Vec<RuntimeCollectionReceipt>,
    #[serde(default)]
    pub digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub scope_id: String,
    #[serde(default)]
    pub detector_id: String,
    #[serde(default)]
    pub detector_revision: String,
    #[serde(default)]
    pub observation_id: String,
    #[serde(default)]
    pub observed_at: String,
    #[serde(default)]
    pub collection_receipt: CollectionReceipt,
    #[serde(default)]
    pub completeness: Completeness,
    #[serde(default)]
    pub paths: Vec<SecurityPath>,
    #[serde(default)]
    pub path_set_digest: String,
    #[serde(default)]
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationRequest {
    Compare {
        #[serde(default)]
        before: Option<Snapshot>,
        after: Snapshot,
    },
    VerifyObservedAbsent {
        reference: Snapshot,
        after: Snapshot,
        #[serde(default)]
        requested_path_ids: Vec<String>,
    },
    RankCandidateCuts {
        #[serde(default)]
        paths: Vec<SecurityPath>,
    },
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum EvaluationResponse {
    Compare { result: ComparisonDecision },
    VerifyObservedAbsent { result: VerificationDecision },
    RankCandidateCuts { result: Vec<CandidateEdgeCut> },
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ProofChange {
    pub route_id: String,
    pub before_path_ids: Vec<String>,
    pub after_path_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct CandidateEdgeCut {
    pub rank: usize,
    pub state: String,
    pub edge: ProofEdge,
    pub covered_route_ids: Vec<String>,
    pub covered_path_ids: Vec<String>,
    pub route_coverage: usize,
    pub path_coverage: usize,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ComparisonDecision {
    pub state: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub newly_observed_path_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_longer_observed_path_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proof_changed: Vec<ProofChange>,
    pub unchanged_routes: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_edge_cuts: Vec<CandidateEdgeCut>,
    pub digest: String,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct VerificationDecision {
    pub requested_path_ids: Vec<String>,
    pub requested_route_ids: Vec<String>,
    pub state: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub still_observed_path_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_edge_cuts: Vec<CandidateEdgeCut>,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelError {
    InvalidSnapshot(&'static str),
    InvalidInput(&'static str),
    InvalidRequestedPath(String),
    InvalidTime,
}

impl fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
