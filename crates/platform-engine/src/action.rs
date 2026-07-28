use cerebro_platform_sdk::{
    ActionOperation, ActionState, ActionVerificationReceipt, ActorId, ContentDigest,
    DecisionReceipt, OpaqueId, SdkError, VerificationState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionCommand {
    RecordSimulation,
    RequestApproval,
    RecordApproval {
        receipt: DecisionReceipt,
    },
    Claim {
        worker_id: OpaqueId,
        claimed_at_unix_ms: u64,
    },
    StartExecution,
    MarkOutcomeUnknown,
    Complete {
        external_receipt_ref: OpaqueId,
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
    operation.proposal.validate()?;
    if operation.version == 0 {
        return Err(SdkError::OutOfRange("action operation version"));
    }
    if matches!(
        operation.state,
        ActionState::Approved
            | ActionState::Claimed
            | ActionState::Executing
            | ActionState::OutcomeUnknown
            | ActionState::Completed
            | ActionState::Reconciled
            | ActionState::Verified
    ) {
        let Some(approval) = operation.approval_receipt.as_ref() else {
            return Err(SdkError::Invalid("action approval receipt"));
        };
        if !approval_authorizes(operation, approval) {
            return Err(SdkError::Invalid("action approval receipt"));
        }
    }
    if matches!(
        operation.state,
        ActionState::Claimed
            | ActionState::Executing
            | ActionState::OutcomeUnknown
            | ActionState::Completed
            | ActionState::Reconciled
            | ActionState::Verified
    ) && (operation.claimed_by.is_none() || operation.claimed_at_unix_ms.is_none())
    {
        return Err(SdkError::Invalid("action operation claimant"));
    }
    if matches!(
        operation.state,
        ActionState::Completed | ActionState::Reconciled | ActionState::Verified
    ) && (operation.executor_actor_id.is_none()
        || operation.executed_at_unix_ms.is_none()
        || operation.external_receipt_ref.is_none() && operation.state == ActionState::Completed
        || operation.observed_effect_digest.is_none())
    {
        return Err(SdkError::Invalid("action execution receipt"));
    }
    if operation.state == ActionState::Verified {
        if operation.verification_state != VerificationState::Verified {
            return Err(SdkError::Invalid("action verification state"));
        }
        let Some(receipt) = operation.verification_receipt.as_ref() else {
            return Err(SdkError::Invalid("action verification receipt"));
        };
        if !verification_confirms(operation, receipt) {
            return Err(SdkError::Invalid("action verification receipt"));
        }
    } else if operation.verification_state == VerificationState::Verified {
        return Err(SdkError::Invalid("action verification state"));
    }
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
            if !approval_authorizes(operation, &receipt) {
                return Err(SdkError::Invalid("action approval receipt"));
            }
            next.state = ActionState::Approved;
            next.approval_receipt = Some(receipt);
        }
        (
            ActionState::Approved,
            ActionCommand::Claim {
                worker_id,
                claimed_at_unix_ms,
            },
        ) => {
            let approval = operation
                .approval_receipt
                .as_ref()
                .ok_or(SdkError::Invalid("action approval receipt"))?;
            if claimed_at_unix_ms < approval.decided_at_unix_ms
                || claimed_at_unix_ms >= operation.proposal.proposal_expires_at_unix_ms
            {
                return Err(SdkError::Invalid("action execution claim"));
            }
            next.state = ActionState::Claimed;
            next.claimed_by = Some(worker_id);
            next.claimed_at_unix_ms = Some(claimed_at_unix_ms);
        }
        (ActionState::Claimed, ActionCommand::StartExecution) => {
            next.state = ActionState::Executing;
        }
        (ActionState::Executing, ActionCommand::MarkOutcomeUnknown) => {
            next.state = ActionState::OutcomeUnknown;
        }
        (
            ActionState::Executing,
            ActionCommand::Complete {
                external_receipt_ref,
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
            next.executed_at_unix_ms = Some(executed_at_unix_ms);
            next.external_receipt_ref = Some(external_receipt_ref);
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
            if !verification_confirms(operation, &receipt) {
                return Err(SdkError::Invalid("action verification receipt"));
            }
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
    Ok(next)
}

fn approval_authorizes(operation: &ActionOperation, receipt: &DecisionReceipt) -> bool {
    receipt.authorizes(operation.proposal.proposal_digest.as_str())
        && receipt.decided_by != operation.proposal.proposed_by
        && receipt.decided_at_unix_ms >= operation.proposal.proposed_at_unix_ms
        && receipt.decided_at_unix_ms < operation.proposal.proposal_expires_at_unix_ms
}

fn verification_confirms(operation: &ActionOperation, receipt: &ActionVerificationReceipt) -> bool {
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
