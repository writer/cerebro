use serde::Serialize;

use crate::{AssertionDefinitionId, ContentDigest, FactQuery, GraphRevision, SdkError, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationTrigger {
    GraphChange,
    EvidenceFreshness,
    ScheduledReconciliation,
    Manual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionState {
    Satisfied,
    Violated,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionDefinition {
    pub assertion_id: AssertionDefinitionId,
    pub tenant_id: TenantId,
    pub name: String,
    pub query: FactQuery,
    pub triggers: Vec<EvaluationTrigger>,
    pub evidence_max_age_seconds: u64,
    pub enabled: bool,
    pub definition_digest: ContentDigest,
}

impl AssertionDefinition {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.name.trim() != self.name || self.name.is_empty() {
            return Err(SdkError::Invalid("assertion name"));
        }
        if self.name.len() > 256 {
            return Err(SdkError::TooLong("assertion name"));
        }
        if self.triggers.is_empty() {
            return Err(SdkError::Empty("assertion triggers"));
        }
        if self.evidence_max_age_seconds == 0 {
            return Err(SdkError::OutOfRange("assertion evidence max age"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionEvaluation {
    pub assertion_id: AssertionDefinitionId,
    pub graph_revision: GraphRevision,
    pub state: AssertionState,
    pub evaluated_at_unix_millis: i64,
    pub matching_paths: u32,
    pub reason_codes: Vec<String>,
    pub evidence_digest: ContentDigest,
}
