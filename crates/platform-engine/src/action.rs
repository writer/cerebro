use cerebro_platform_sdk::{
    ActionOperation, ActionState, ContentDigest, OpaqueId, SdkError, VerificationState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionCommand {
    RecordSimulation,
    RequestApproval,
    Claim {
        worker_id: OpaqueId,
    },
    StartExecution,
    MarkOutcomeUnknown,
    Complete {
        external_receipt_ref: OpaqueId,
        observed_effect_digest: ContentDigest,
    },
    Reconcile {
        observed_effect_digest: ContentDigest,
    },
    Verify,
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
        ActionState::Claimed
            | ActionState::Executing
            | ActionState::OutcomeUnknown
            | ActionState::Completed
            | ActionState::Reconciled
            | ActionState::Verified
    ) && operation.claimed_by.is_none()
    {
        return Err(SdkError::Invalid("action operation claimant"));
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
        (ActionState::WaitingForApproval, ActionCommand::Claim { worker_id }) => {
            next.state = ActionState::Claimed;
            next.claimed_by = Some(worker_id);
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
            },
        ) => {
            next.state = ActionState::Completed;
            next.external_receipt_ref = Some(external_receipt_ref);
            next.observed_effect_digest = Some(observed_effect_digest);
        }
        (
            ActionState::OutcomeUnknown,
            ActionCommand::Reconcile {
                observed_effect_digest,
            },
        ) => {
            next.state = ActionState::Reconciled;
            next.observed_effect_digest = Some(observed_effect_digest);
        }
        (ActionState::Completed | ActionState::Reconciled, ActionCommand::Verify) => {
            next.state = ActionState::Verified;
            next.verification_state = VerificationState::Verified;
        }
        (ActionState::Completed | ActionState::Reconciled, ActionCommand::RejectVerification) => {
            next.state = ActionState::Failed;
            next.verification_state = VerificationState::Rejected;
        }
        (
            ActionState::Proposed
            | ActionState::Simulated
            | ActionState::WaitingForApproval
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
