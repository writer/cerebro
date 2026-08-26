use cerebro_platform_sdk::{
    ActionOperation, ActionState, ActionVerificationReceipt, ActorId, ContentDigest,
    DecisionReceipt, MAX_ACTION_CLAIM_LEASE_MS, OpaqueId, SdkError, VerificationState,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ActionCommand {
    RecordSimulation,
    RequestApproval,
    RecordApproval {
        receipt: DecisionReceipt,
    },
    Claim {
        worker_id: OpaqueId,
        claimed_at_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    },
    /// Extends the dispatch lease before execution starts. Once execution
    /// starts, uncertain outcomes must use reconciliation instead of takeover.
    RenewClaim {
        renewed_at_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    },
    /// Returns an unstarted Action to the approved queue after its dispatch
    /// lease expires so another executor can claim it.
    ReleaseExpiredClaim {
        observed_at_unix_ms: u64,
    },
    StartExecution {
        started_at_unix_ms: u64,
    },
    RecordProviderReceipt {
        external_receipt_ref: OpaqueId,
        provider_receipt_digest: ContentDigest,
        provider_status: String,
        executor_actor_id: ActorId,
        observed_at_unix_ms: u64,
    },
    ObserveProviderReceipt {
        provider_receipt_digest: ContentDigest,
        provider_status: String,
        reconciler_actor_id: ActorId,
        observed_at_unix_ms: u64,
    },
    MarkOutcomeUnknown,
    Complete {
        external_receipt_ref: OpaqueId,
        provider_receipt_digest: ContentDigest,
        observed_effect_digest: ContentDigest,
        executor_actor_id: ActorId,
        executed_at_unix_ms: u64,
    },
    Reconcile {
        observed_effect_digest: ContentDigest,
        executor_actor_id: ActorId,
        executed_at_unix_ms: u64,
    },
    Verify {
        receipt: ActionVerificationReceipt,
    },
    RejectVerification,
    Fail,
    RollBack,
}

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
            next.state = ActionState::Failed;
        }
        (
            ActionState::Completed
            | ActionState::Reconciled
            | ActionState::Verified
            | ActionState::Failed,
            ActionCommand::RollBack,
        ) => {
            next.state = ActionState::RolledBack;
            next.verification_state = VerificationState::Stale;
        }
        _ => {
            return Err(SdkError::Conflict(
                "invalid action state transition".to_owned(),
            ));
        }
    }
    next.version = next
        .version
        .checked_add(1)
        .ok_or(SdkError::OutOfRange("action operation version"))?;
    next.validate()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::valid_provider_status;

    #[test]
    fn provider_status_is_a_bounded_machine_token() {
        for status in ["queued", "in-progress", "succeeded.v1", "retry_2"] {
            assert!(
                valid_provider_status(status),
                "expected valid status: {status}"
            );
        }
        for status in ["", " queued", "queued ", "provider status", "queued/2"] {
            assert!(
                !valid_provider_status(status),
                "expected rejected status: {status:?}"
            );
        }
        assert!(!valid_provider_status(&"x".repeat(65)));
    }
}
