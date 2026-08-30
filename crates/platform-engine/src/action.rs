//! Pure forward state transitions for validated action-operation snapshots.
//!
//! The engine applies one command to a clone, increments its optimistic version,
//! and validates the resulting evidence matrix. It does not authorize the caller,
//! read a clock, reserve an idempotency key, contact a provider, execute rollback,
//! or atomically persist the returned snapshot.

use cerebro_platform_sdk::{
    ActionOperation, ActionState, ActionVerificationReceipt, ActorId, ContentDigest,
    DecisionReceipt, MAX_ACTION_CLAIM_LEASE_MS, OpaqueId, SdkError, VerificationState,
};
use serde::Serialize;

/// Requested state-machine event and the evidence supplied with it.
///
/// Commands are transition inputs, not authority records. The surrounding
/// service must authenticate the actor, validate provider evidence, and commit
/// the resulting version atomically before exposing the new state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ActionCommand {
    /// Records completion of the proposal's already-bound simulation.
    RecordSimulation,
    /// Moves a simulated proposal into the approval queue.
    RequestApproval,
    /// Attaches an independent decision receipt to the exact proposal digest.
    RecordApproval {
        /// Approval receipt validated with the resulting operation snapshot.
        receipt: DecisionReceipt,
    },
    /// Acquires the first bounded execution lease for an approved operation.
    Claim {
        /// Worker identity that owns dispatch coordination for the lease.
        worker_id: OpaqueId,
        /// Inclusive Unix-millisecond lease start.
        claimed_at_unix_ms: u64,
        /// Exclusive Unix-millisecond lease expiration.
        claim_expires_at_unix_ms: u64,
    },
    /// Extends the dispatch lease before execution starts. Once execution
    /// starts, uncertain outcomes must use reconciliation instead of takeover.
    RenewClaim {
        /// Observation time, before current expiry, at which renewal is requested.
        renewed_at_unix_ms: u64,
        /// Later exclusive expiry, still inside proposal and absolute lease bounds.
        claim_expires_at_unix_ms: u64,
    },
    /// Returns an unstarted Action to the approved queue after its dispatch
    /// lease expires so another executor can claim it.
    ReleaseExpiredClaim {
        /// Caller-supplied time proving the current lease has expired.
        observed_at_unix_ms: u64,
    },
    /// Marks the point after which an expired claim cannot be reassigned safely.
    StartExecution {
        /// Caller-supplied start time inside the active claim interval.
        started_at_unix_ms: u64,
    },
    /// Attaches the first complete provider-dispatch observation.
    RecordProviderReceipt {
        /// Stable provider receipt identity.
        external_receipt_ref: OpaqueId,
        /// Digest of exact provider receipt content.
        provider_receipt_digest: ContentDigest,
        /// Bounded machine-readable provider status.
        provider_status: String,
        /// Actor attributed to provider dispatch.
        executor_actor_id: ActorId,
        /// Unix-millisecond provider observation time.
        observed_at_unix_ms: u64,
    },
    /// Replaces mutable provider observation fields with a strictly newer sample.
    ObserveProviderReceipt {
        /// Digest of the newer provider receipt content.
        provider_receipt_digest: ContentDigest,
        /// Bounded machine-readable status in the newer sample.
        provider_status: String,
        /// Actor that obtained the observation; currently not retained in state.
        reconciler_actor_id: ActorId,
        /// Unix-millisecond sample time, strictly later than the previous sample.
        observed_at_unix_ms: u64,
    },
    /// Records that execution may have escaped without a trustworthy outcome.
    MarkOutcomeUnknown,
    /// Records an observed effect and complete successful provider evidence.
    Complete {
        /// Stable provider receipt identity.
        external_receipt_ref: OpaqueId,
        /// Digest of final provider receipt content.
        provider_receipt_digest: ContentDigest,
        /// Digest of authoritative state observed after the effect.
        observed_effect_digest: ContentDigest,
        /// Actor attributed to execution.
        executor_actor_id: ActorId,
        /// Unix-millisecond effect observation time.
        executed_at_unix_ms: u64,
    },
    /// Resolves an uncertain outcome from authoritative observed state.
    Reconcile {
        /// Digest of authoritative state observed during reconciliation.
        observed_effect_digest: ContentDigest,
        /// Actor attributed to the original or reconciled execution.
        executor_actor_id: ActorId,
        /// Unix-millisecond effect observation time.
        executed_at_unix_ms: u64,
    },
    /// Attaches independent verification of a completed or reconciled effect.
    Verify {
        /// Operation-bound independent verification evidence.
        receipt: ActionVerificationReceipt,
    },
    /// Records a terminal negative verification without attaching a positive receipt.
    RejectVerification,
    /// Marks an eligible unverified operation failed while preserving evidence.
    Fail,
    /// Marks a completed or terminal operation rolled back and verification stale.
    ///
    /// This command records state only; it does not execute or validate the
    /// rollback operation referenced by the proposal.
    RollBack,
}

/// Applies one allowed command to an immutable operation snapshot.
///
/// The input is validated before optimistic-version comparison. On success the
/// command changes a cloned snapshot, increments its version exactly once with
/// overflow protection, validates the full resulting state, and returns it. The
/// caller-owned input is unchanged on every path.
///
/// Claim acquisition begins no earlier than approval, ends inside proposal
/// validity, and lasts at most [`MAX_ACTION_CLAIM_LEASE_MS`]. Renewal must occur
/// before current expiry and extend it, while final snapshot validation also
/// keeps total time from the original claim start within that maximum. Starting
/// execution must occur before lease expiry; later provider observation and
/// completion may outlive the lease because takeover is no longer safe.
///
/// Timestamps are caller-supplied and compared only with stored action times.
/// This function has no clock and cannot establish that a command occurred "now."
/// `expected_version` is an optimistic token, not an atomic write: persistence
/// must compare-and-store the returned version in one durable operation.
///
/// # Errors
///
/// Returns input or resulting-operation validation errors,
/// [`SdkError::Conflict`] for a stale version, timing conflict, or unsupported
/// state/command pair, [`SdkError::Invalid`] for malformed command evidence, or
/// [`SdkError::OutOfRange`] if the version increment overflows.
pub fn transition_action(
    operation: &ActionOperation,
    expected_version: u64,
    command: ActionCommand,
) -> Result<ActionOperation, SdkError> {
    operation.validate()?;
    if operation.version != expected_version {
        return Err(SdkError::Conflict(
            "stale action operation version".to_owned(),
        ));
    }

    // Work on a private clone so a rejected command cannot leak partial evidence
    // into the caller's durable snapshot.
    let mut next = operation.clone();
    match (&operation.state, command) {
        (ActionState::Proposed, ActionCommand::RecordSimulation) => {
            next.state = ActionState::Simulated;
        }
        (ActionState::Simulated, ActionCommand::RequestApproval) => {
            next.state = ActionState::WaitingForApproval;
        }
        (ActionState::WaitingForApproval, ActionCommand::RecordApproval { receipt }) => {
            next.state = ActionState::Approved;
            next.approval_receipt = Some(receipt);
        }
        (
            ActionState::Approved,
            ActionCommand::Claim {
                worker_id,
                claimed_at_unix_ms,
                claim_expires_at_unix_ms,
            },
        ) => {
            let approval = operation
                .approval_receipt
                .as_ref()
                .ok_or(SdkError::Invalid("action approval receipt"))?;
            if claimed_at_unix_ms < approval.decided_at_unix_ms
                || claimed_at_unix_ms >= operation.proposal.proposal_expires_at_unix_ms
                || claim_expires_at_unix_ms <= claimed_at_unix_ms
                || claim_expires_at_unix_ms > operation.proposal.proposal_expires_at_unix_ms
                || claim_expires_at_unix_ms - claimed_at_unix_ms > MAX_ACTION_CLAIM_LEASE_MS
            {
                return Err(SdkError::Invalid("action execution claim"));
            }
            next.state = ActionState::Claimed;
            next.claimed_by = Some(worker_id);
            next.claimed_at_unix_ms = Some(claimed_at_unix_ms);
            next.claim_expires_at_unix_ms = Some(claim_expires_at_unix_ms);
        }
        (
            ActionState::Claimed,
            ActionCommand::RenewClaim {
                renewed_at_unix_ms,
                claim_expires_at_unix_ms,
            },
        ) => {
            let current_expiry = operation
                .claim_expires_at_unix_ms
                .ok_or(SdkError::Invalid("action execution claim"))?;
            if renewed_at_unix_ms < operation.claimed_at_unix_ms.unwrap_or(u64::MAX)
                || renewed_at_unix_ms >= current_expiry
                || claim_expires_at_unix_ms <= current_expiry
                || claim_expires_at_unix_ms <= renewed_at_unix_ms
                || claim_expires_at_unix_ms > operation.proposal.proposal_expires_at_unix_ms
                || claim_expires_at_unix_ms - renewed_at_unix_ms > MAX_ACTION_CLAIM_LEASE_MS
            {
                return Err(SdkError::Invalid("action claim renewal"));
            }
            next.claim_expires_at_unix_ms = Some(claim_expires_at_unix_ms);
        }
        (
            ActionState::Claimed,
            ActionCommand::ReleaseExpiredClaim {
                observed_at_unix_ms,
            },
        ) => {
            if operation
                .claim_expires_at_unix_ms
                .is_none_or(|claim_expires_at| observed_at_unix_ms < claim_expires_at)
            {
                return Err(SdkError::Conflict(
                    "action execution claim has not expired".to_owned(),
                ));
            }
            next.state = ActionState::Approved;
            next.claimed_by = None;
            next.claimed_at_unix_ms = None;
            next.claim_expires_at_unix_ms = None;
        }
        (ActionState::Claimed, ActionCommand::StartExecution { started_at_unix_ms }) => {
            if started_at_unix_ms < operation.claimed_at_unix_ms.unwrap_or(u64::MAX)
                || operation
                    .claim_expires_at_unix_ms
                    .is_none_or(|claim_expires_at| started_at_unix_ms >= claim_expires_at)
            {
                return Err(SdkError::Conflict(
                    "action execution claim expired before execution started".to_owned(),
                ));
            }

            // The start time is a transition precondition rather than durable
            // evidence; subsequent observations are ordered from the claim.
            next.state = ActionState::Executing;
        }
        (ActionState::Executing, ActionCommand::MarkOutcomeUnknown) => {
            next.state = ActionState::OutcomeUnknown;
        }
        (
            ActionState::Executing,
            ActionCommand::RecordProviderReceipt {
                external_receipt_ref,
                provider_receipt_digest,
                provider_status,
                executor_actor_id,
                observed_at_unix_ms,
            },
        ) => {
            next.state = ActionState::Dispatched;
            next.executor_actor_id = Some(executor_actor_id);
            next.external_receipt_ref = Some(external_receipt_ref);
            next.provider_receipt_digest = Some(provider_receipt_digest);
            next.provider_status = Some(provider_status);
            next.provider_observed_at_unix_ms = Some(observed_at_unix_ms);
        }
        (
            ActionState::Dispatched,
            ActionCommand::ObserveProviderReceipt {
                provider_receipt_digest,
                provider_status,
                observed_at_unix_ms,
                ..
            },
        ) => {
            if operation
                .provider_observed_at_unix_ms
                .is_none_or(|previous| observed_at_unix_ms <= previous)
            {
                return Err(SdkError::Conflict(
                    "action provider observation did not advance".to_owned(),
                ));
            }

            // The reconciler actor is deliberately not persisted by the current
            // operation contract; service audit records must retain that actor.
            next.provider_receipt_digest = Some(provider_receipt_digest);
            next.provider_status = Some(provider_status);
            next.provider_observed_at_unix_ms = Some(observed_at_unix_ms);
        }
        (
            ActionState::Executing,
            ActionCommand::Complete {
                external_receipt_ref,
                provider_receipt_digest,
                observed_effect_digest,
                executor_actor_id,
                executed_at_unix_ms,
            },
        ) => {
            if Some(executed_at_unix_ms) < operation.claimed_at_unix_ms {
                return Err(SdkError::Invalid("action execution receipt"));
            }

            // A synchronous provider path may return dispatch and effect evidence
            // together, so this arm constructs the full current receipt group.
            next.state = ActionState::Completed;
            next.executor_actor_id = Some(executor_actor_id);
            next.provider_receipt_digest = Some(provider_receipt_digest);
            next.provider_status = Some("succeeded".to_owned());
            next.provider_observed_at_unix_ms = Some(executed_at_unix_ms);
            next.executed_at_unix_ms = Some(executed_at_unix_ms);
            next.external_receipt_ref = Some(external_receipt_ref);
            next.observed_effect_digest = Some(observed_effect_digest);
        }
        (
            ActionState::Dispatched,
            ActionCommand::Complete {
                external_receipt_ref,
                provider_receipt_digest,
                observed_effect_digest,
                executor_actor_id,
                executed_at_unix_ms,
            },
        ) => {
            if operation.external_receipt_ref.as_ref() != Some(&external_receipt_ref)
                || operation.executor_actor_id.as_ref() != Some(&executor_actor_id)
                || operation
                    .provider_observed_at_unix_ms
                    .is_none_or(|observed_at| executed_at_unix_ms < observed_at)
            {
                return Err(SdkError::Invalid("action execution receipt"));
            }

            // Completion cannot switch provider receipt identity or executor; it
            // may update receipt content to the final successful observation.
            next.state = ActionState::Completed;
            next.provider_receipt_digest = Some(provider_receipt_digest);
            next.provider_status = Some("succeeded".to_owned());
            next.provider_observed_at_unix_ms = Some(executed_at_unix_ms);
            next.executed_at_unix_ms = Some(executed_at_unix_ms);
            next.observed_effect_digest = Some(observed_effect_digest);
        }
        (
            ActionState::OutcomeUnknown,
            ActionCommand::Reconcile {
                observed_effect_digest,
                executor_actor_id,
                executed_at_unix_ms,
            },
        ) => {
            if Some(executed_at_unix_ms) < operation.claimed_at_unix_ms {
                return Err(SdkError::Invalid("action execution receipt"));
            }

            // Reconciliation records authoritative effect evidence without
            // fabricating provider receipt fields that were never observed.
            next.state = ActionState::Reconciled;
            next.executor_actor_id = Some(executor_actor_id);
            next.executed_at_unix_ms = Some(executed_at_unix_ms);
            next.observed_effect_digest = Some(observed_effect_digest);
        }
        (ActionState::Completed | ActionState::Reconciled, ActionCommand::Verify { receipt }) => {
            next.state = ActionState::Verified;
            next.verification_state = VerificationState::Verified;
            next.verification_receipt = Some(receipt);
        }
        (ActionState::Completed | ActionState::Reconciled, ActionCommand::RejectVerification) => {
            next.state = ActionState::Failed;
            next.verification_state = VerificationState::Rejected;
        }
        (
            ActionState::Proposed
            | ActionState::Simulated
            | ActionState::WaitingForApproval
            | ActionState::Approved
            | ActionState::Claimed
            | ActionState::Executing
            | ActionState::Dispatched
            | ActionState::OutcomeUnknown
            | ActionState::Completed
            | ActionState::Reconciled,
            ActionCommand::Fail,
        ) => {
            // Failure preserves every coherent evidence group accumulated so far
            // for diagnosis and later rollback decisions.
            next.state = ActionState::Failed;
        }
        (
            ActionState::Completed
            | ActionState::Reconciled
            | ActionState::Verified
            | ActionState::Failed,
            ActionCommand::RollBack,
        ) => {
            // Rollback execution and authorization occur outside this pure state
            // marker; retaining receipts preserves the historical audit trail.
            next.state = ActionState::RolledBack;
            next.verification_state = VerificationState::Stale;
        }
        _ => {
            return Err(SdkError::Conflict(
                "invalid action state transition".to_owned(),
            ));
        }
    }

    // Version changes even for same-state commands such as claim renewal and a
    // newer provider observation, giving persistence one concurrency token.
    next.version = next
        .version
        .checked_add(1)
        .ok_or(SdkError::OutOfRange("action operation version"))?;

    // Central snapshot validation closes partial-evidence gaps left by individual
    // transition arms and checks receipt bindings before the result can escape.
    next.validate()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{
        ActionEffect, ActionOperationId, ActionProposal, GraphRevision, TenantId,
    };

    use super::*;

    fn proposed_operation() -> ActionOperation {
        let mut proposal = ActionProposal {
            operation_id: ActionOperationId::parse("operation:inline-test").unwrap(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            finding_id: OpaqueId::parse("finding:inline-test").unwrap(),
            finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
            finding_validation_receipt_digest: ContentDigest::of_bytes("finding-validation"),
            graph_revision: GraphRevision::new(1).unwrap(),
            action_kind: "revoke_access".to_owned(),
            action_definition_digest: ContentDigest::of_bytes("action-definition"),
            target_id: OpaqueId::parse("grant:inline-test").unwrap(),
            expected_effects: vec![ActionEffect {
                target_id: OpaqueId::parse("grant:inline-test").unwrap(),
                effect_kind: "access_removed".to_owned(),
                expected_state_digest: ContentDigest::of_bytes("expected-state"),
            }],
            rollback_ref: OpaqueId::parse("rollback:inline-test").unwrap(),
            idempotency_key: OpaqueId::parse("idempotency:inline-test").unwrap(),
            simulation_digest: ContentDigest::of_bytes("simulation"),
            verification_plan_digest: ContentDigest::of_bytes("verification-plan"),
            proposed_by: ActorId::parse("actor:inline-test").unwrap(),
            proposed_at_unix_ms: 1,
            proposal_expires_at_unix_ms: 100,
            proposal_digest: ContentDigest::of_bytes("unbound"),
        };
        proposal.bind_computed_digest().unwrap();
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

    #[test]
    fn transition_rejects_a_stale_operation_version_without_mutating_state() {
        let operation = proposed_operation();

        assert_eq!(
            transition_action(&operation, 2, ActionCommand::RecordSimulation),
            Err(SdkError::Conflict(
                "stale action operation version".to_owned()
            ))
        );
        assert_eq!(operation.state, ActionState::Proposed);
        assert_eq!(operation.version, 1);
    }
}
