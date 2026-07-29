use serde::Serialize;

use crate::{GraphRevision, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Healthy,
    Degraded,
    Blocked,
    Rebuilding,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityHealth {
    pub capability: String,
    pub state: CapabilityState,
    pub reason_code: Option<String>,
    pub observed_at_unix_millis: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectionLag {
    pub graph_revision: GraphRevision,
    pub pending_outbox_records: u64,
    pub oldest_pending_age_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationalDiagnostics {
    pub tenant_id: TenantId,
    pub append_log_sequence: u64,
    pub graph_revision: GraphRevision,
    pub projection_lag: ProjectionLag,
    pub rejected_deltas: u64,
    pub parity_mismatches: u64,
    pub budget_exhaustions: u64,
    pub capabilities: Vec<CapabilityHealth>,
}
