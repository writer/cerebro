use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    ActionOperationId, ActorId, ContentDigest, DecisionReceipt, GraphRevision, OpaqueId, SdkError,
    TenantId, VerificationReceipt,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Proposed,
    Simulated,
    WaitingForApproval,
    Approved,
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
    pub finding_id: OpaqueId,
    pub finding_revision_digest: ContentDigest,
    pub finding_validation_receipt_digest: ContentDigest,
    pub graph_revision: GraphRevision,
    pub action_kind: String,
    pub action_definition_digest: ContentDigest,
    pub target_id: OpaqueId,
    pub expected_effects: Vec<ActionEffect>,
    pub rollback_ref: OpaqueId,
    pub idempotency_key: OpaqueId,
    pub simulation_digest: ContentDigest,
    pub verification_plan_digest: ContentDigest,
    pub proposed_by: ActorId,
    pub proposed_at_unix_ms: u64,
    pub proposal_expires_at_unix_ms: u64,
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
        if self.proposed_at_unix_ms == 0
            || self.proposal_expires_at_unix_ms <= self.proposed_at_unix_ms
        {
            return Err(SdkError::OutOfRange("action proposal validity"));
        }
        let mut effects = BTreeSet::new();
        for effect in &self.expected_effects {
            if effect.effect_kind.is_empty()
                || effect.effect_kind.len() > 128
                || effect.effect_kind.trim() != effect.effect_kind
                || !effect
                    .effect_kind
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
            {
                return Err(SdkError::Invalid("action effect kind"));
            }
            if !effects.insert((&effect.target_id, effect.effect_kind.as_str())) {
                return Err(SdkError::Conflict(
                    "duplicate action expected effect".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionOperation {
    pub proposal: ActionProposal,
    pub state: ActionState,
    pub version: u64,
    pub approval_receipt: Option<DecisionReceipt>,
    pub claimed_by: Option<OpaqueId>,
    pub claimed_at_unix_ms: Option<u64>,
    pub executor_actor_id: Option<ActorId>,
    pub executed_at_unix_ms: Option<u64>,
    pub external_receipt_ref: Option<OpaqueId>,
    pub observed_effect_digest: Option<ContentDigest>,
    pub verification_state: VerificationState,
    pub verification_receipt: Option<ActionVerificationReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionVerificationReceipt {
    pub operation_id: ActionOperationId,
    pub proposal_digest: ContentDigest,
    pub observed_effect_digest: ContentDigest,
    pub receipt: VerificationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionReceipt {
    pub operation_id: ActionOperationId,
    pub state: ActionState,
    pub version: u64,
    pub execution_receipt_digest: ContentDigest,
    pub verification_receipt: Option<ActionVerificationReceipt>,
}
