//! Evidence-bearing summaries for projection recovery verification.
//!
//! Recovery reports compare durable and projected state at a point in time.
//! These transport types carry check outcomes; they do not run checks, repair
//! projections, select an authoritative store, or authorize replay.

use serde::Serialize;

use crate::{ContentDigest, GraphRevision, TenantId};

/// Three-valued outcome of a recovery check or complete report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    /// Available evidence satisfied the check.
    Passed,
    /// Available evidence established a failed invariant.
    Failed,
    /// Available evidence could not establish either pass or failure.
    Indeterminate,
}

/// Named recovery invariant and the evidence supplied for its outcome.
///
/// Digests and reason codes are optional because different checks expose
/// different evidence. This type does not infer state from digest presence or
/// equality; the component executing the check owns that interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryCheck {
    /// Stable human-readable check name used for deterministic ordering.
    pub name: String,
    /// Caller-assigned outcome of the check.
    pub state: RecoveryState,
    /// Expected content digest, when the check compares content.
    pub expected_digest: Option<ContentDigest>,
    /// Observed content digest, when the check compares content.
    pub observed_digest: Option<ContentDigest>,
    /// Optional machine-readable explanation for the outcome.
    pub reason_code: Option<String>,
}

/// Content-addressed summary of one tenant's recovery verification.
///
/// The platform engine derives the aggregate state and digest from sorted
/// checks. The SDK structure itself is publicly constructible and performs no
/// independent consistency or digest validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryReport {
    /// Tenant whose durable and projected state was compared.
    pub tenant_id: TenantId,
    /// Durable append-log position covered by the verification.
    pub append_log_sequence: u64,
    /// Non-zero revision reported by the Postgres state boundary.
    pub postgres_revision: GraphRevision,
    /// Non-zero revision reported by the Neo4j projection boundary.
    pub neo4j_revision: GraphRevision,
    /// Checks in deterministic name order.
    pub checks: Vec<RecoveryCheck>,
    /// Aggregate outcome derived from checks and revision agreement.
    pub state: RecoveryState,
    /// Canonical digest of every preceding report field.
    pub report_digest: ContentDigest,
}
