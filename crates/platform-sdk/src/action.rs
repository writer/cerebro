use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::BTreeSet;

use crate::{
    ActionOperationId, ActorId, ContentDigest, DecisionId, DecisionReceipt, GraphRevision,
    OpaqueId, SdkError, TenantId, VerificationId, VerificationReceipt,
};

const ACTION_PROPOSAL_DIGEST_SCHEMA: &str = "cerebro.action-proposal.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

impl ActionOperation {
    pub fn validate(&self) -> Result<(), SdkError> {
        self.proposal.validate()?;
        if self.version == 0 {
            return Err(SdkError::OutOfRange("action operation version"));
        }
        let has_approval = if let Some(approval) = self.approval_receipt.as_ref() {
            if !approval_authorizes(self, approval) {
                return Err(SdkError::Invalid("action approval receipt"));
            }
            true
        } else {
            false
        };
        let has_claim = match (&self.claimed_by, self.claimed_at_unix_ms) {
            (None, None) => false,
            (Some(_), Some(claimed_at)) => {
                let Some(approval) = self.approval_receipt.as_ref() else {
                    return Err(SdkError::Invalid("action operation claimant"));
                };
                if claimed_at < approval.decided_at_unix_ms
                    || claimed_at >= self.proposal.proposal_expires_at_unix_ms
                {
                    return Err(SdkError::Invalid("action operation claimant"));
                }
                true
            }
            _ => return Err(SdkError::Invalid("action operation claimant")),
        };
        let has_execution = match (
            &self.executor_actor_id,
            self.executed_at_unix_ms,
            &self.observed_effect_digest,
        ) {
            (None, None, None) => false,
            (Some(_), Some(executed_at), Some(_)) => {
                if self
                    .claimed_at_unix_ms
                    .is_none_or(|claimed_at| executed_at < claimed_at)
                {
                    return Err(SdkError::Invalid("action execution receipt"));
                }
                true
            }
            _ => return Err(SdkError::Invalid("action execution receipt")),
        };
        if self.external_receipt_ref.is_some() && !has_execution {
            return Err(SdkError::Invalid("action execution receipt"));
        }
        let has_verification = if let Some(receipt) = self.verification_receipt.as_ref() {
            if !verification_confirms(self, receipt) {
                return Err(SdkError::Invalid("action verification receipt"));
            }
            true
        } else {
            false
        };
        let exact = |approval, claim, execution, external, verification, verification_state| {
            has_approval == approval
                && has_claim == claim
                && has_execution == execution
                && self.external_receipt_ref.is_some() == external
                && has_verification == verification
                && self.verification_state == verification_state
        };
        let valid_state = match self.state {
            ActionState::Proposed | ActionState::Simulated | ActionState::WaitingForApproval => {
                exact(
                    false,
                    false,
                    false,
                    false,
                    false,
                    VerificationState::Pending,
                )
            }
            ActionState::Approved => {
                exact(true, false, false, false, false, VerificationState::Pending)
            }
            ActionState::Claimed | ActionState::Executing | ActionState::OutcomeUnknown => {
                exact(true, true, false, false, false, VerificationState::Pending)
            }
            ActionState::Completed => {
                exact(true, true, true, true, false, VerificationState::Pending)
            }
            ActionState::Reconciled => {
                exact(true, true, true, false, false, VerificationState::Pending)
            }
            ActionState::Verified => {
                exact(true, true, true, true, true, VerificationState::Verified)
                    || exact(true, true, true, false, true, VerificationState::Verified)
            }
            ActionState::Failed => {
                !has_verification
                    && self.verification_state != VerificationState::Verified
                    && self.verification_state != VerificationState::Stale
            }
            ActionState::RolledBack => {
                self.verification_state == VerificationState::Stale
                    && (!has_verification || has_execution)
            }
        };
        if !valid_state {
            return Err(SdkError::Invalid("action operation state"));
        }
        Ok(())
    }
}

pub(crate) fn approval_authorizes(operation: &ActionOperation, receipt: &DecisionReceipt) -> bool {
    receipt.authorizes(operation.proposal.proposal_digest.as_str())
        && receipt.decided_by != operation.proposal.proposed_by
        && receipt.decided_at_unix_ms >= operation.proposal.proposed_at_unix_ms
        && receipt.decided_at_unix_ms < operation.proposal.proposal_expires_at_unix_ms
}

pub(crate) fn verification_confirms(
    operation: &ActionOperation,
    receipt: &ActionVerificationReceipt,
) -> bool {
    receipt.operation_id == operation.proposal.operation_id
        && receipt.proposal_digest == operation.proposal.proposal_digest
        && Some(&receipt.observed_effect_digest) == operation.observed_effect_digest.as_ref()
        && Some(&receipt.receipt.executor_actor_id) == operation.executor_actor_id.as_ref()
        && receipt.receipt.verifier_actor_id != operation.proposal.proposed_by
        && operation
            .approval_receipt
            .as_ref()
            .is_some_and(|approval| receipt.receipt.verifier_actor_id != approval.decided_by)
        && operation
            .executed_at_unix_ms
            .is_some_and(|executed_at| receipt.receipt.verified_at_unix_ms > executed_at)
        && receipt.receipt.independently_confirms_effect()
}

#[derive(Deserialize)]
struct StoredActionEffect {
    target_id: String,
    effect_kind: String,
    expected_state_digest: String,
}

#[derive(Deserialize)]
struct StoredActionProposal {
    operation_id: String,
    tenant_id: String,
    finding_id: String,
    finding_revision_digest: String,
    finding_validation_receipt_digest: String,
    graph_revision: u64,
    action_kind: String,
    action_definition_digest: String,
    target_id: String,
    expected_effects: Vec<StoredActionEffect>,
    rollback_ref: String,
    idempotency_key: String,
    simulation_digest: String,
    verification_plan_digest: String,
    proposed_by: String,
    proposed_at_unix_ms: u64,
    proposal_expires_at_unix_ms: u64,
    proposal_digest: String,
}

#[derive(Deserialize)]
struct StoredDecisionReceipt {
    decision_id: String,
    proposal_digest: String,
    approved: bool,
    decided_by: String,
    decided_at_unix_ms: u64,
}

#[derive(Deserialize)]
struct StoredVerificationReceipt {
    verification_id: String,
    executor_actor_id: String,
    verifier_actor_id: String,
    previous_source_revision: String,
    observed_source_revision: String,
    effective: bool,
    evidence_urns: Vec<String>,
    verified_at_unix_ms: u64,
}

#[derive(Deserialize)]
struct StoredActionVerificationReceipt {
    operation_id: String,
    proposal_digest: String,
    observed_effect_digest: String,
    receipt: StoredVerificationReceipt,
}

#[derive(Deserialize)]
struct StoredActionOperation {
    proposal: StoredActionProposal,
    state: ActionState,
    version: u64,
    approval_receipt: Option<StoredDecisionReceipt>,
    claimed_by: Option<String>,
    claimed_at_unix_ms: Option<u64>,
    executor_actor_id: Option<String>,
    executed_at_unix_ms: Option<u64>,
    external_receipt_ref: Option<String>,
    observed_effect_digest: Option<String>,
    verification_state: VerificationState,
    verification_receipt: Option<StoredActionVerificationReceipt>,
}

impl TryFrom<StoredActionOperation> for ActionOperation {
    type Error = SdkError;

    fn try_from(stored: StoredActionOperation) -> Result<Self, Self::Error> {
        let operation = Self {
            proposal: stored.proposal.try_into()?,
            state: stored.state,
            version: stored.version,
            approval_receipt: stored.approval_receipt.map(TryInto::try_into).transpose()?,
            claimed_by: stored.claimed_by.map(OpaqueId::parse).transpose()?,
            claimed_at_unix_ms: stored.claimed_at_unix_ms,
            executor_actor_id: stored.executor_actor_id.map(parse_actor_id).transpose()?,
            executed_at_unix_ms: stored.executed_at_unix_ms,
            external_receipt_ref: stored
                .external_receipt_ref
                .map(OpaqueId::parse)
                .transpose()?,
            observed_effect_digest: stored
                .observed_effect_digest
                .map(ContentDigest::parse)
                .transpose()?,
            verification_state: stored.verification_state,
            verification_receipt: stored
                .verification_receipt
                .map(TryInto::try_into)
                .transpose()?,
        };
        operation.validate()?;
        Ok(operation)
    }
}

impl TryFrom<StoredActionProposal> for ActionProposal {
    type Error = SdkError;

    fn try_from(stored: StoredActionProposal) -> Result<Self, Self::Error> {
        let proposal = Self {
            operation_id: ActionOperationId::parse(stored.operation_id)?,
            tenant_id: TenantId::parse(stored.tenant_id)
                .map_err(|_| SdkError::Invalid("action tenant id"))?,
            finding_id: OpaqueId::parse(stored.finding_id)?,
            finding_revision_digest: ContentDigest::parse(stored.finding_revision_digest)?,
            finding_validation_receipt_digest: ContentDigest::parse(
                stored.finding_validation_receipt_digest,
            )?,
            graph_revision: GraphRevision::new(stored.graph_revision)?,
            action_kind: stored.action_kind,
            action_definition_digest: ContentDigest::parse(stored.action_definition_digest)?,
            target_id: OpaqueId::parse(stored.target_id)?,
            expected_effects: stored
                .expected_effects
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            rollback_ref: OpaqueId::parse(stored.rollback_ref)?,
            idempotency_key: OpaqueId::parse(stored.idempotency_key)?,
            simulation_digest: ContentDigest::parse(stored.simulation_digest)?,
            verification_plan_digest: ContentDigest::parse(stored.verification_plan_digest)?,
            proposed_by: parse_actor_id(stored.proposed_by)?,
            proposed_at_unix_ms: stored.proposed_at_unix_ms,
            proposal_expires_at_unix_ms: stored.proposal_expires_at_unix_ms,
            proposal_digest: ContentDigest::parse(stored.proposal_digest)?,
        };
        proposal.validate()?;
        Ok(proposal)
    }
}

impl TryFrom<StoredActionEffect> for ActionEffect {
    type Error = SdkError;

    fn try_from(stored: StoredActionEffect) -> Result<Self, Self::Error> {
        Ok(Self {
            target_id: OpaqueId::parse(stored.target_id)?,
            effect_kind: stored.effect_kind,
            expected_state_digest: ContentDigest::parse(stored.expected_state_digest)?,
        })
    }
}

impl TryFrom<StoredDecisionReceipt> for DecisionReceipt {
    type Error = SdkError;

    fn try_from(stored: StoredDecisionReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            decision_id: DecisionId::parse(stored.decision_id)
                .map_err(|_| SdkError::Invalid("action decision id"))?,
            proposal_digest: stored.proposal_digest,
            approved: stored.approved,
            decided_by: parse_actor_id(stored.decided_by)?,
            decided_at_unix_ms: stored.decided_at_unix_ms,
        })
    }
}

impl TryFrom<StoredActionVerificationReceipt> for ActionVerificationReceipt {
    type Error = SdkError;

    fn try_from(stored: StoredActionVerificationReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            operation_id: ActionOperationId::parse(stored.operation_id)?,
            proposal_digest: ContentDigest::parse(stored.proposal_digest)?,
            observed_effect_digest: ContentDigest::parse(stored.observed_effect_digest)?,
            receipt: stored.receipt.try_into()?,
        })
    }
}

impl TryFrom<StoredVerificationReceipt> for VerificationReceipt {
    type Error = SdkError;

    fn try_from(stored: StoredVerificationReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            verification_id: VerificationId::parse(stored.verification_id)
                .map_err(|_| SdkError::Invalid("action verification id"))?,
            executor_actor_id: parse_actor_id(stored.executor_actor_id)?,
            verifier_actor_id: parse_actor_id(stored.verifier_actor_id)?,
            previous_source_revision: stored.previous_source_revision,
            observed_source_revision: stored.observed_source_revision,
            effective: stored.effective,
            evidence_urns: stored.evidence_urns,
            verified_at_unix_ms: stored.verified_at_unix_ms,
        })
    }
}

fn parse_actor_id(value: String) -> Result<ActorId, SdkError> {
    ActorId::parse(value).map_err(|_| SdkError::Invalid("action actor id"))
}

impl<'de> Deserialize<'de> for ActionOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StoredActionOperation::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_actions_round_trip_only_through_validated_domain_values() {
        let initial_operation = operation();
        let value = serde_json::to_value(&initial_operation).expect("serialize operation");
        assert_eq!(
            serde_json::from_value::<ActionOperation>(value.clone()).expect("decode operation"),
            initial_operation
        );

        for (field, tampered) in [
            ("tenant", set(&value, &["proposal", "tenant_id"], " tenant")),
            (
                "actor",
                set(&value, &["proposal", "proposed_by"], "actor\nadmin"),
            ),
            (
                "proposal digest",
                set(
                    &value,
                    &["proposal", "action_kind"],
                    "attacker_selected_action",
                ),
            ),
        ] {
            assert!(
                serde_json::from_value::<ActionOperation>(tampered).is_err(),
                "{field} bypassed Action admission"
            );
        }

        let mut zero_revision = value.clone();
        zero_revision["proposal"]["graph_revision"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ActionOperation>(zero_revision).is_err());

        let mut zero_version = value.clone();
        zero_version["version"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ActionOperation>(zero_version).is_err());

        let mut forged_approval = value;
        forged_approval["state"] = serde_json::json!("approved");
        assert!(serde_json::from_value::<ActionOperation>(forged_approval).is_err());

        let mut dormant_claim = serde_json::to_value(operation()).expect("serialize operation");
        dormant_claim["claimed_by"] = serde_json::json!("worker:attacker");
        dormant_claim["claimed_at_unix_ms"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ActionOperation>(dormant_claim).is_err());
    }

    fn operation() -> ActionOperation {
        let mut proposal = ActionProposal {
            operation_id: ActionOperationId::parse("operation:stored").expect("operation"),
            tenant_id: TenantId::parse("tenant:stored").expect("tenant"),
            finding_id: OpaqueId::parse("finding:stored").expect("finding"),
            finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
            finding_validation_receipt_digest: ContentDigest::of_bytes("finding-validation"),
            graph_revision: GraphRevision::new(1).expect("revision"),
            action_kind: "revoke_access".to_owned(),
            action_definition_digest: ContentDigest::of_bytes("action-definition"),
            target_id: OpaqueId::parse("grant:stored").expect("target"),
            expected_effects: vec![ActionEffect {
                target_id: OpaqueId::parse("grant:stored").expect("effect target"),
                effect_kind: "access_removed".to_owned(),
                expected_state_digest: ContentDigest::of_bytes("expected"),
            }],
            rollback_ref: OpaqueId::parse("rollback:stored").expect("rollback"),
            idempotency_key: OpaqueId::parse("idempotency:stored").expect("idempotency"),
            simulation_digest: ContentDigest::of_bytes("simulation"),
            verification_plan_digest: ContentDigest::of_bytes("verification-plan"),
            proposed_by: ActorId::parse("proposer:stored").expect("actor"),
            proposed_at_unix_ms: 1,
            proposal_expires_at_unix_ms: 100,
            proposal_digest: ContentDigest::of_bytes("placeholder"),
        };
        proposal.bind_computed_digest().expect("bind digest");
        ActionOperation {
            proposal,
            state: ActionState::Proposed,
            version: 1,
            approval_receipt: None,
            claimed_by: None,
            claimed_at_unix_ms: None,
            executor_actor_id: None,
            executed_at_unix_ms: None,
            external_receipt_ref: None,
            observed_effect_digest: None,
            verification_state: VerificationState::Pending,
            verification_receipt: None,
        }
    }

    fn set(value: &serde_json::Value, path: &[&str], replacement: &str) -> serde_json::Value {
        let mut value = value.clone();
        let mut current = &mut value;
        for segment in &path[..path.len() - 1] {
            current = &mut current[*segment];
        }
        current[path[path.len() - 1]] = serde_json::json!(replacement);
        value
    }
}
