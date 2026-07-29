use serde::Serialize;

use crate::{ContentDigest, GraphRevision, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Passed,
    Failed,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryCheck {
    pub name: String,
    pub state: RecoveryState,
    pub expected_digest: Option<ContentDigest>,
    pub observed_digest: Option<ContentDigest>,
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryReport {
    pub tenant_id: TenantId,
    pub append_log_sequence: u64,
    pub postgres_revision: GraphRevision,
    pub neo4j_revision: GraphRevision,
    pub checks: Vec<RecoveryCheck>,
    pub state: RecoveryState,
    pub report_digest: ContentDigest,
}
