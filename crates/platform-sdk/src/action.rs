use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    ActionOperationId, ActorId, ContentDigest, DecisionReceipt, GraphRevision, OpaqueId, SdkError,
    TenantId, VerificationReceipt,
};

const ACTION_PROPOSAL_DIGEST_SCHEMA: &str = "cerebro.action-proposal.v1";

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
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            operation_id: &'a ActionOperationId,
            tenant_id: &'a TenantId,
            finding_id: &'a OpaqueId,
            finding_revision_digest: &'a ContentDigest,
            finding_validation_receipt_digest: &'a ContentDigest,
            graph_revision: &'a GraphRevision,
            action_kind: &'a str,
            action_definition_digest: &'a ContentDigest,
            target_id: &'a OpaqueId,
            expected_effects: &'a [ActionEffect],
            rollback_ref: &'a OpaqueId,
            idempotency_key: &'a OpaqueId,
            simulation_digest: &'a ContentDigest,
            verification_plan_digest: &'a ContentDigest,
            proposed_by: &'a ActorId,
            proposed_at_unix_ms: u64,
            proposal_expires_at_unix_ms: u64,
        }

        let material = DigestMaterial {
            schema: ACTION_PROPOSAL_DIGEST_SCHEMA,
            operation_id: &self.operation_id,
            tenant_id: &self.tenant_id,
            finding_id: &self.finding_id,
            finding_revision_digest: &self.finding_revision_digest,
            finding_validation_receipt_digest: &self.finding_validation_receipt_digest,
            graph_revision: &self.graph_revision,
            action_kind: &self.action_kind,
            action_definition_digest: &self.action_definition_digest,
            target_id: &self.target_id,
            expected_effects: &self.expected_effects,
            rollback_ref: &self.rollback_ref,
            idempotency_key: &self.idempotency_key,
            simulation_digest: &self.simulation_digest,
            verification_plan_digest: &self.verification_plan_digest,
            proposed_by: &self.proposed_by,
            proposed_at_unix_ms: self.proposed_at_unix_ms,
            proposal_expires_at_unix_ms: self.proposal_expires_at_unix_ms,
        };
        serde_json::to_vec(&material)
            .map(ContentDigest::of_bytes)
            .map_err(|error| {
                SdkError::Backend(format!("action proposal serialization failed: {error}"))
            })
    }

    pub fn bind_computed_digest(&mut self) -> Result<(), SdkError> {
        self.proposal_digest = self.computed_digest()?;
        Ok(())
    }

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
        if self.proposal_digest != self.computed_digest()? {
            return Err(SdkError::Invalid("action proposal digest"));
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
