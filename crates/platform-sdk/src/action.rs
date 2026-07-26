use serde::Serialize;

use crate::{
    ActionOperationId, ContentDigest, GraphRevision, OpaqueId, SdkError, TenantId,
    VerificationReceipt,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Proposed,
    Simulated,
    WaitingForApproval,
    Claimed,
    Executing,
    OutcomeUnknown,
    Completed,
    Reconciled,
    Verified,
    Failed,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Pending,
    Verified,
    Rejected,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionEffect {
    pub target_id: OpaqueId,
    pub effect_kind: String,
    pub expected_state_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionProposal {
    pub operation_id: ActionOperationId,
    pub tenant_id: TenantId,
    pub graph_revision: GraphRevision,
    pub action_kind: String,
    pub target_id: OpaqueId,
    pub expected_effects: Vec<ActionEffect>,
    pub rollback_ref: OpaqueId,
    pub idempotency_key: OpaqueId,
    pub simulation_digest: ContentDigest,
    pub proposal_digest: ContentDigest,
}

impl ActionProposal {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.action_kind.trim() != self.action_kind || self.action_kind.is_empty() {
            return Err(SdkError::Invalid("action kind"));
        }
        if self.action_kind.len() > 128 {
            return Err(SdkError::TooLong("action kind"));
        }
        if self.expected_effects.is_empty() || self.expected_effects.len() > 100 {
            return Err(SdkError::OutOfRange("action expected effects"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionOperation {
    pub proposal: ActionProposal,
    pub state: ActionState,
    pub version: u64,
    pub claimed_by: Option<OpaqueId>,
    pub external_receipt_ref: Option<OpaqueId>,
    pub observed_effect_digest: Option<ContentDigest>,
    pub verification_state: VerificationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionReceipt {
    pub operation_id: ActionOperationId,
    pub state: ActionState,
    pub version: u64,
    pub execution_receipt_digest: ContentDigest,
    pub verification_receipt: Option<VerificationReceipt>,
}
