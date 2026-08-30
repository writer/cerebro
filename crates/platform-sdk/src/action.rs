//! Content-addressed action proposals, durable operation snapshots, and receipts.
//!
//! Action contracts bind a finding and approval to an exact proposed external
//! effect, then track claim, provider observation, execution, reconciliation,
//! and independent verification evidence. The SDK validates stored shape and
//! cross-field authority invariants; adapters still own actor authorization,
//! provider authenticity, durable transitions, idempotency, and execution.

use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::BTreeSet;

use crate::{
    ActionOperationId, ActorId, ContentDigest, DecisionId, DecisionReceipt, GraphRevision,
    OpaqueId, SdkError, TenantId, VerificationId, VerificationReceipt,
};

// Domain-separate proposal JSON from other SHA-256-addressed platform values.
const ACTION_PROPOSAL_DIGEST_SCHEMA: &str = "cerebro.action-proposal.v1";

/// Maximum duration of one action-executor claim lease: five minutes.
pub const MAX_ACTION_CLAIM_LEASE_MS: u64 = 5 * 60 * 1_000;

/// Durable lifecycle state of an action operation.
///
/// This enum names observable snapshots, not a transition graph. The platform
/// engine owns allowed forward transitions; [`ActionOperation::validate`] checks
/// that evidence present in a stored snapshot is compatible with its state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    /// Proposal is admitted but has no approval or execution evidence.
    Proposed,
    /// Proposal has completed pre-execution simulation without approval evidence.
    Simulated,
    /// Proposal is awaiting an independent approval decision.
    WaitingForApproval,
    /// Exact proposal digest has an independent approval receipt.
    Approved,
    /// An executor holds a bounded claim lease.
    Claimed,
    /// Claimed executor is preparing or performing provider work.
    Executing,
    /// Provider accepted the operation and returned current observation evidence.
    Dispatched,
    /// Dispatch may have occurred but its outcome cannot yet be established.
    OutcomeUnknown,
    /// Expected effect was observed after dispatch.
    Completed,
    /// Expected effect was established through reconciliation without current dispatch evidence.
    Reconciled,
    /// Independent verification confirmed the observed effect.
    Verified,
    /// Operation reached a definite failure state without successful verification.
    Failed,
    /// Effect was rolled back and any earlier verification is stale.
    RolledBack,
}

/// Independent verification status attached to an action operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    /// No terminal independent verification outcome is attached.
    Pending,
    /// Attached receipt independently confirms the intended effect.
    Verified,
    /// Verification rejected the intended effect.
    Rejected,
    /// Earlier verification no longer represents current state.
    Stale,
}

/// One expected post-action state used for execution verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionEffect {
    /// Stable identity of the resource expected to change.
    pub target_id: OpaqueId,
    /// Bounded machine-readable effect kind.
    pub effect_kind: String,
    /// Digest of the authoritative state expected after execution.
    pub expected_state_digest: ContentDigest,
}

/// Immutable, content-addressed proposal for one external action.
///
/// The proposal binds the exact finding validation, graph revision, action
/// definition, ordered expected effects, rollback reference, idempotency key,
/// simulation, verification plan, proposer, and validity interval. Expected
/// effect order contributes to the digest even though duplicate target/kind
/// pairs are rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionProposal {
    /// Stable identity shared by every snapshot and receipt for the operation.
    pub operation_id: ActionOperationId,
    /// Tenant whose finding and action target are in scope.
    pub tenant_id: TenantId,
    /// Finding that motivates the action.
    pub finding_id: OpaqueId,
    /// Exact finding revision admitted for action.
    pub finding_revision_digest: ContentDigest,
    /// Digest of the independent finding-validation receipt.
    pub finding_validation_receipt_digest: ContentDigest,
    /// Non-zero graph revision on which the proposal is based.
    pub graph_revision: GraphRevision,
    /// Non-empty action kind, preserved exactly after validation.
    pub action_kind: String,
    /// Digest of the executable action definition.
    pub action_definition_digest: ContentDigest,
    /// Primary provider or graph target of the action.
    pub target_id: OpaqueId,
    /// Non-empty ordered expected effects, bounded to 100 entries.
    pub expected_effects: Vec<ActionEffect>,
    /// Stable reference to the separately authorized rollback operation.
    pub rollback_ref: OpaqueId,
    /// Caller-selected key used by durable execution to suppress duplicate effects.
    pub idempotency_key: OpaqueId,
    /// Digest of the successful pre-execution simulation.
    pub simulation_digest: ContentDigest,
    /// Digest of the independent verification plan.
    pub verification_plan_digest: ContentDigest,
    /// Actor that proposed the action.
    pub proposed_by: ActorId,
    /// Non-zero Unix-millisecond proposal time.
    pub proposed_at_unix_ms: u64,
    /// Exclusive Unix-millisecond expiration time for approval and claim.
    pub proposal_expires_at_unix_ms: u64,
    /// Schema-tagged digest of every preceding proposal field.
    pub proposal_digest: ContentDigest,
}

impl ActionProposal {
    /// Computes the schema-tagged digest of the proposal's semantic fields.
    ///
    /// [`Self::proposal_digest`] is excluded to avoid recursive content
    /// addressing. Vector order is preserved. This method serializes fields as
    /// supplied and does not validate action kind, effects, or timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JSON serialization fails.
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        // A dedicated material type freezes serialized field order and excludes
        // the digest field from its own hash input.
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

    /// Replaces the stored proposal digest with [`Self::computed_digest`].
    ///
    /// This helper does not call [`Self::validate`]; callers must validate the
    /// resulting proposal before using it as durable authority.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if digest serialization fails.
    pub fn bind_computed_digest(&mut self) -> Result<(), SdkError> {
        self.proposal_digest = self.computed_digest()?;
        Ok(())
    }

    /// Validates proposal bounds, effect identity, timing, and content digest.
    ///
    /// `action_kind` must be non-empty, unpadded, and at most 128 bytes.
    /// `effect_kind` additionally permits only ASCII alphanumerics plus
    /// `-`, `_`, `.`, `:`, and `/`. Expected effects contain one to 100 entries
    /// and cannot repeat a target/kind pair. The expiration is exclusive and
    /// must be later than the non-zero proposal time.
    ///
    /// This check does not authorize the proposer, validate the referenced
    /// finding receipt, prove the action/simulation/verification definitions,
    /// or reserve the idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] for malformed kinds or a mismatched digest,
    /// [`SdkError::TooLong`] for an action kind over 128 bytes,
    /// [`SdkError::OutOfRange`] for invalid effect count or validity interval,
    /// [`SdkError::Conflict`] for a duplicate effect target/kind pair, or
    /// [`SdkError::Backend`] if digest serialization fails.
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

/// Validated durable snapshot of one action operation.
///
/// Optional fields form evidence groups rather than independent flags: claims,
/// current provider receipts, execution observations, and verification receipts
/// must be internally complete and compatible with [`Self::state`]. Historical
/// terminal records may carry only `external_receipt_ref` for provider evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionOperation {
    /// Immutable proposal whose digest approvals and receipts bind.
    pub proposal: ActionProposal,
    /// Observable lifecycle state for this snapshot.
    pub state: ActionState,
    /// Non-zero optimistic-concurrency version.
    pub version: u64,
    /// Independent approval bound to the exact proposal digest.
    pub approval_receipt: Option<DecisionReceipt>,
    /// Worker identity holding the current claim lease.
    pub claimed_by: Option<OpaqueId>,
    /// Inclusive Unix-millisecond claim start.
    pub claimed_at_unix_ms: Option<u64>,
    /// Exclusive Unix-millisecond claim expiration.
    pub claim_expires_at_unix_ms: Option<u64>,
    /// Actor attributed to provider dispatch or observed execution.
    pub executor_actor_id: Option<ActorId>,
    /// Digest of current provider receipt content.
    pub provider_receipt_digest: Option<ContentDigest>,
    /// Bounded machine-readable provider status.
    pub provider_status: Option<String>,
    /// Unix-millisecond time at which current provider state was observed.
    pub provider_observed_at_unix_ms: Option<u64>,
    /// Unix-millisecond time at which the intended effect was observed.
    pub executed_at_unix_ms: Option<u64>,
    /// Stable provider receipt reference, including the historical-only form.
    pub external_receipt_ref: Option<OpaqueId>,
    /// Digest of authoritative state observed after execution.
    pub observed_effect_digest: Option<ContentDigest>,
    /// Current independent-verification classification.
    pub verification_state: VerificationState,
    /// Independent receipt attached only when verified evidence is present.
    pub verification_receipt: Option<ActionVerificationReceipt>,
}

/// Operation-bound wrapper around an independent verification receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionVerificationReceipt {
    /// Operation whose effect was verified.
    pub operation_id: ActionOperationId,
    /// Exact immutable proposal that authorized execution.
    pub proposal_digest: ContentDigest,
    /// Exact observed-effect digest being verified.
    pub observed_effect_digest: ContentDigest,
    /// Independent actor and source-revision evidence.
    pub receipt: VerificationReceipt,
}

/// Compact action state receipt returned by reconciliation.
///
/// This structure has no standalone validator. The producing adapter must bind
/// its execution digest and optional verification receipt to a validated durable
/// operation snapshot before returning it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionReceipt {
    /// Stable operation identity.
    pub operation_id: ActionOperationId,
    /// Durable operation state represented by the receipt.
    pub state: ActionState,
    /// Non-zero operation version represented by the receipt.
    pub version: u64,
    /// Digest of the execution receipt or reconciled execution material.
    pub execution_receipt_digest: ContentDigest,
    /// Independent verification evidence, when present.
    pub verification_receipt: Option<ActionVerificationReceipt>,
}

impl ActionOperation {
    /// Validates proposal authority evidence and the operation-state snapshot.
    ///
    /// Validation enforces a non-zero version, independent in-window approval,
    /// all-or-none claim fields with a lease no longer than five minutes,
    /// coherent current or historical provider evidence, ordered execution
    /// timestamps, and operation-bound independent verification. It then applies
    /// the exact evidence matrix documented by [`ActionState`].
    ///
    /// `Failed` intentionally admits any otherwise coherent pre-verification
    /// evidence combination with `Pending` or `Rejected` verification. A
    /// `RolledBack` snapshot requires `Stale`; when it retains a verification
    /// receipt, execution evidence must also remain present. Historical external
    /// receipt references are readable only in `Completed`, `Verified`, `Failed`,
    /// or `RolledBack` states.
    ///
    /// This is snapshot validation, not a transition check. It does not verify
    /// provider receipt content, authorize actors, compare `claimed_by` with the
    /// executor actor, or prove that the version follows a previous snapshot.
    ///
    /// # Errors
    ///
    /// Returns proposal validation errors, [`SdkError::OutOfRange`] for version
    /// zero, or [`SdkError::Invalid`] for incompatible approval, claim, provider,
    /// execution, verification, or state evidence.
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

        // Claim metadata is one atomic evidence group. Its interval begins no
        // earlier than approval and stays within proposal validity and lease cap.
        let has_claim = match (
            &self.claimed_by,
            self.claimed_at_unix_ms,
            self.claim_expires_at_unix_ms,
        ) {
            (None, None, None) => false,
            (Some(_), Some(claimed_at), Some(claim_expires_at)) => {
                let Some(approval) = self.approval_receipt.as_ref() else {
                    return Err(SdkError::Invalid("action operation claimant"));
                };
                if claimed_at < approval.decided_at_unix_ms
                    || claimed_at >= self.proposal.proposal_expires_at_unix_ms
                    || claim_expires_at <= claimed_at
                    || claim_expires_at > self.proposal.proposal_expires_at_unix_ms
                    || claim_expires_at - claimed_at > MAX_ACTION_CLAIM_LEASE_MS
                {
                    return Err(SdkError::Invalid("action operation claimant"));
                }
                true
            }
            _ => return Err(SdkError::Invalid("action operation claimant")),
        };

        // Current provider evidence is all-or-none with the stable external
        // reference. A lone reference is accepted only as a legacy durable form.
        let (has_provider_receipt, has_legacy_external_receipt) = match (
            &self.external_receipt_ref,
            &self.provider_receipt_digest,
            &self.provider_status,
            self.provider_observed_at_unix_ms,
        ) {
            (None, None, None, None) => (false, false),
            // Actions completed before provider observations became explicit
            // stored only the provider receipt reference. Keep those durable
            // records readable without treating them as new provider evidence.
            (Some(_), None, None, None) => (false, true),
            (Some(_), Some(_), Some(status), Some(observed_at)) => {
                if self.executor_actor_id.is_none()
                    || self
                        .claimed_at_unix_ms
                        .is_none_or(|claimed_at| observed_at < claimed_at)
                    || !valid_provider_status(status)
                {
                    return Err(SdkError::Invalid("action provider receipt"));
                }
                (true, false)
            }
            _ => return Err(SdkError::Invalid("action provider receipt")),
        };

        // Execution time and observed effect digest are inseparable and cannot
        // predate either the claim or a current provider observation.
        let has_execution = match (self.executed_at_unix_ms, &self.observed_effect_digest) {
            (None, None) => false,
            (Some(executed_at), Some(_)) => {
                if self
                    .claimed_at_unix_ms
                    .is_none_or(|claimed_at| executed_at < claimed_at)
                    || self
                        .provider_observed_at_unix_ms
                        .is_some_and(|provider_observed_at| executed_at < provider_observed_at)
                {
                    return Err(SdkError::Invalid("action execution receipt"));
                }
                true
            }
            _ => return Err(SdkError::Invalid("action execution receipt")),
        };
        if has_execution && self.executor_actor_id.is_none() {
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

        // Compare presence groups exactly for normal states. Fields outside the
        // groups, such as executor_actor_id, retain their separately checked role.
        let exact =
            |approval, claim, provider_receipt, execution, verification, verification_state| {
                has_approval == approval
                    && has_claim == claim
                    && has_provider_receipt == provider_receipt
                    && has_execution == execution
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
            ActionState::Dispatched => {
                exact(true, true, true, false, false, VerificationState::Pending)
            }
            ActionState::Completed => {
                exact(true, true, true, true, false, VerificationState::Pending)
                    || (has_legacy_external_receipt
                        && exact(true, true, false, true, false, VerificationState::Pending))
            }
            ActionState::Reconciled => {
                exact(true, true, false, true, false, VerificationState::Pending)
            }
            ActionState::Verified => {
                exact(true, true, true, true, true, VerificationState::Verified)
                    || exact(true, true, false, true, true, VerificationState::Verified)
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

        // Legacy receipt references must never appear on pre-execution states;
        // this prevents the compatibility path from admitting new authority.
        let legacy_external_receipt_allowed = !has_legacy_external_receipt
            || matches!(
                self.state,
                ActionState::Completed
                    | ActionState::Verified
                    | ActionState::Failed
                    | ActionState::RolledBack
            );
        if !valid_state || !legacy_external_receipt_allowed {
            return Err(SdkError::Invalid("action operation state"));
        }
        Ok(())
    }
}

/// Checks the bounded provider-status vocabulary admitted into durable state.
///
/// Status is non-empty, unpadded, at most 64 bytes, and limited to ASCII
/// alphanumerics plus `-`, `_`, and `.`.
fn valid_provider_status(status: &str) -> bool {
    !status.is_empty()
        && status.len() <= 64
        && status.trim() == status
        && status
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

/// Checks approval binding, actor separation, and proposal-validity timing.
///
/// [`DecisionReceipt::authorizes`] supplies the affirmative decision, non-zero
/// decision time, and exact proposal-digest comparison. This helper additionally
/// rejects self-approval and requires the decision in the inclusive-proposal,
/// exclusive-expiration interval. It does not establish approver authorization
/// or receipt authenticity.
pub(crate) fn approval_authorizes(operation: &ActionOperation, receipt: &DecisionReceipt) -> bool {
    receipt.authorizes(operation.proposal.proposal_digest.as_str())
        && receipt.decided_by != operation.proposal.proposed_by
        && receipt.decided_at_unix_ms >= operation.proposal.proposed_at_unix_ms
        && receipt.decided_at_unix_ms < operation.proposal.proposal_expires_at_unix_ms
}

/// Checks that independent verification confirms this operation's exact effect.
///
/// The wrapper must bind operation, proposal, and observed-effect digests. The
/// nested receipt must name the recorded executor, use a verifier distinct from
/// proposer and approver, occur strictly after execution, and independently
/// confirm an effective source-revision change with evidence. Authenticity and
/// verifier authorization remain importing-boundary responsibilities.
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

/// Strict wire form for one expected effect before typed-ID parsing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredActionEffect {
    target_id: String,
    effect_kind: String,
    expected_state_digest: String,
}

/// Strict wire form for an action proposal before digest-valid domain admission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Strict nested approval form used to reject unknown unsigned fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDecisionReceipt {
    decision_id: String,
    proposal_digest: String,
    approved: bool,
    decided_by: String,
    decided_at_unix_ms: u64,
}

/// Strict nested independent-verification form before actor and ID parsing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Strict operation-bound verification wrapper used during admission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredActionVerificationReceipt {
    operation_id: String,
    proposal_digest: String,
    observed_effect_digest: String,
    receipt: StoredVerificationReceipt,
}

/// Strict wire form for a complete durable operation snapshot.
///
/// Keeping every nested form under `deny_unknown_fields` prevents unbound wire
/// extensions from being ignored before proposal digest and state validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredActionOperation {
    proposal: StoredActionProposal,
    state: ActionState,
    version: u64,
    approval_receipt: Option<StoredDecisionReceipt>,
    claimed_by: Option<String>,
    claimed_at_unix_ms: Option<u64>,
    claim_expires_at_unix_ms: Option<u64>,
    executor_actor_id: Option<String>,
    provider_receipt_digest: Option<String>,
    provider_status: Option<String>,
    provider_observed_at_unix_ms: Option<u64>,
    executed_at_unix_ms: Option<u64>,
    external_receipt_ref: Option<String>,
    observed_effect_digest: Option<String>,
    verification_state: VerificationState,
    verification_receipt: Option<StoredActionVerificationReceipt>,
}

impl TryFrom<StoredActionOperation> for ActionOperation {
    type Error = SdkError;

    /// Parses every optional evidence group, then validates the complete snapshot.
    fn try_from(stored: StoredActionOperation) -> Result<Self, Self::Error> {
        let operation = Self {
            proposal: stored.proposal.try_into()?,
            state: stored.state,
            version: stored.version,
            approval_receipt: stored.approval_receipt.map(TryInto::try_into).transpose()?,
            claimed_by: stored.claimed_by.map(OpaqueId::parse).transpose()?,
            claimed_at_unix_ms: stored.claimed_at_unix_ms,
            claim_expires_at_unix_ms: stored.claim_expires_at_unix_ms,
            executor_actor_id: stored.executor_actor_id.map(parse_actor_id).transpose()?,
            provider_receipt_digest: stored
                .provider_receipt_digest
                .map(ContentDigest::parse)
                .transpose()?,
            provider_status: stored.provider_status,
            provider_observed_at_unix_ms: stored.provider_observed_at_unix_ms,
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

    /// Parses typed proposal fields and admits only a digest-valid proposal.
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

    /// Parses effect identity and expected-state digest.
    ///
    /// Effect-kind syntax is validated by the enclosing proposal so duplicate
    /// detection can run over the complete collection.
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

    /// Parses approval identities while retaining fields for proposal binding.
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

    /// Parses the operation-bound verification wrapper.
    ///
    /// Cross-field and independence checks run when the enclosing operation is
    /// validated rather than during construction of this nested value.
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

    /// Parses typed verification identities while preserving source evidence.
    ///
    /// [`VerificationReceipt::independently_confirms_effect`] is evaluated by
    /// [`verification_confirms`] after operation bindings are available.
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

/// Parses an actor ID and maps its lower-level error to the action wire contract.
fn parse_actor_id(value: String) -> Result<ActorId, SdkError> {
    ActorId::parse(value).map_err(|_| SdkError::Invalid("action actor id"))
}

impl<'de> Deserialize<'de> for ActionOperation {
    /// Decodes only strict, typed, state-valid operation snapshots.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StoredActionOperation::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ActionProposal {
    /// Decodes only strict, typed, digest-valid proposals.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StoredActionProposal::deserialize(deserializer)?
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
        assert_eq!(
            serde_json::from_value::<ActionProposal>(value["proposal"].clone())
                .expect("decode proposal"),
            initial_operation.proposal
        );
        let mut proposal_with_unknown_field = value["proposal"].clone();
        proposal_with_unknown_field["requested_role"] = serde_json::json!("admin");
        assert!(serde_json::from_value::<ActionProposal>(proposal_with_unknown_field).is_err());

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
        dormant_claim["claim_expires_at_unix_ms"] = serde_json::json!(3);
        assert!(serde_json::from_value::<ActionOperation>(dormant_claim).is_err());

        let dispatched = dispatched_operation();
        let dispatched_value =
            serde_json::to_value(&dispatched).expect("serialize dispatched operation");
        assert_eq!(
            serde_json::from_value::<ActionOperation>(dispatched_value.clone())
                .expect("decode dispatched operation"),
            dispatched
        );
        for (field, tampered) in [
            (
                "missing provider digest",
                clear(&dispatched_value, "provider_receipt_digest"),
            ),
            (
                "missing provider status",
                clear(&dispatched_value, "provider_status"),
            ),
            (
                "missing provider observation time",
                clear(&dispatched_value, "provider_observed_at_unix_ms"),
            ),
            (
                "invalid provider status",
                replace(
                    &dispatched_value,
                    "provider_status",
                    serde_json::json!("queued with whitespace"),
                ),
            ),
            (
                "provider observation before claim",
                replace(
                    &dispatched_value,
                    "provider_observed_at_unix_ms",
                    serde_json::json!(2),
                ),
            ),
        ] {
            assert!(
                serde_json::from_value::<ActionOperation>(tampered).is_err(),
                "{field} bypassed provider receipt admission"
            );
        }

        let mut completed_too_early = dispatched_value;
        completed_too_early["state"] = serde_json::json!("completed");
        completed_too_early["executed_at_unix_ms"] = serde_json::json!(3);
        completed_too_early["observed_effect_digest"] =
            serde_json::json!(ContentDigest::of_bytes("effect").to_string());
        assert!(
            serde_json::from_value::<ActionOperation>(completed_too_early).is_err(),
            "effect completion cannot predate the latest provider observation"
        );
    }

    #[test]
    fn legacy_completed_actions_without_provider_observation_fields_remain_readable() {
        let mut completed = serde_json::to_value(dispatched_operation()).expect("serialize Action");
        completed["state"] = serde_json::json!("completed");
        completed["version"] = serde_json::json!(8);
        completed["executed_at_unix_ms"] = serde_json::json!(5);
        completed["observed_effect_digest"] =
            serde_json::json!(ContentDigest::of_bytes("legacy effect").to_string());
        let object = completed.as_object_mut().expect("Action object");
        object.remove("provider_receipt_digest");
        object.remove("provider_status");
        object.remove("provider_observed_at_unix_ms");

        let decoded =
            serde_json::from_value::<ActionOperation>(completed).expect("decode legacy Action");
        assert_eq!(decoded.state, ActionState::Completed);
        assert!(decoded.external_receipt_ref.is_some());
        assert!(decoded.provider_receipt_digest.is_none());
        assert!(decoded.provider_status.is_none());
        assert!(decoded.provider_observed_at_unix_ms.is_none());

        let mut forged = serde_json::to_value(operation()).expect("serialize proposed Action");
        forged["external_receipt_ref"] = serde_json::json!("receipt:forged");
        assert!(
            serde_json::from_value::<ActionOperation>(forged).is_err(),
            "legacy receipt compatibility must not admit receipts before execution"
        );
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
            claim_expires_at_unix_ms: None,
            executor_actor_id: None,
            provider_receipt_digest: None,
            provider_status: None,
            provider_observed_at_unix_ms: None,
            executed_at_unix_ms: None,
            external_receipt_ref: None,
            observed_effect_digest: None,
            verification_state: VerificationState::Pending,
            verification_receipt: None,
        }
    }

    fn dispatched_operation() -> ActionOperation {
        let mut operation = operation();
        operation.state = ActionState::Dispatched;
        operation.version = 7;
        operation.approval_receipt = Some(DecisionReceipt {
            decision_id: DecisionId::parse("decision:stored").expect("decision"),
            proposal_digest: operation.proposal.proposal_digest.to_string(),
            approved: true,
            decided_by: ActorId::parse("approver:stored").expect("approver"),
            decided_at_unix_ms: 2,
        });
        operation.claimed_by = Some(OpaqueId::parse("executor:stored").expect("worker"));
        operation.claimed_at_unix_ms = Some(3);
        operation.claim_expires_at_unix_ms = Some(50);
        operation.executor_actor_id = Some(ActorId::parse("executor:stored").expect("executor"));
        operation.external_receipt_ref =
            Some(OpaqueId::parse("receipt:stored").expect("provider receipt"));
        operation.provider_receipt_digest = Some(ContentDigest::of_bytes("provider receipt"));
        operation.provider_status = Some("queued".to_owned());
        operation.provider_observed_at_unix_ms = Some(4);
        operation.validate().expect("dispatched operation");
        operation
    }

    fn clear(value: &serde_json::Value, field: &str) -> serde_json::Value {
        replace(value, field, serde_json::Value::Null)
    }

    fn replace(
        value: &serde_json::Value,
        field: &str,
        replacement: serde_json::Value,
    ) -> serde_json::Value {
        let mut value = value.clone();
        value[field] = replacement;
        value
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
