use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, CommitmentId, DecisionId, GrantId, PlanId};

const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentState {
    Proposed,
    WaitingOnApproval,
    Ready,
    Executing,
    WaitingOnVerification,
    Fulfilled,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitmentInput {
    pub commitment_id: CommitmentId,
    pub plan_id: PlanId,
    pub plan_revision: u64,
    pub step_id: String,
    pub actor_id: ActorId,
    pub capability: String,
    pub resource_urn: String,
    pub expected_effect: String,
    pub rollback_reference: Option<String>,
    pub requires_decision: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Commitment {
    pub commitment_id: CommitmentId,
    pub revision: u64,
    pub plan_id: PlanId,
    pub plan_revision: u64,
    pub step_id: String,
    pub actor_id: ActorId,
    pub capability: String,
    pub resource_urn: String,
    pub expected_effect: String,
    pub rollback_reference: Option<String>,
    pub state: CommitmentState,
    pub grant_id: Option<GrantId>,
    pub decision_id: Option<DecisionId>,
    pub receipt_urns: Vec<String>,
    pub last_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitmentTransition {
    pub expected_revision: u64,
    pub to: CommitmentState,
    pub grant_id: Option<GrantId>,
    pub decision_id: Option<DecisionId>,
    pub receipt_urns: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitmentError {
    InvalidInput,
    InvalidTransition,
    MissingAuthority,
    MissingReceipt,
    RevisionConflict { expected: u64, actual: u64 },
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("commitment input is invalid"),
            Self::InvalidTransition => formatter.write_str("commitment transition is invalid"),
            Self::MissingAuthority => formatter.write_str("commitment authority is missing"),
            Self::MissingReceipt => formatter.write_str("commitment receipt is missing"),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "commitment revision conflict: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl Error for CommitmentError {}

impl Commitment {
    pub fn propose(input: CommitmentInput) -> Result<Self, CommitmentError> {
        if input.plan_revision == 0 {
            return Err(CommitmentError::InvalidInput);
        }
        for value in [
            &input.step_id,
            &input.capability,
            &input.resource_urn,
            &input.expected_effect,
        ] {
            validate_text(value).map_err(|_| CommitmentError::InvalidInput)?;
        }
        if let Some(reference) = &input.rollback_reference {
            validate_text(reference).map_err(|_| CommitmentError::InvalidInput)?;
        }
        let initial_state = if input.requires_decision {
            CommitmentState::WaitingOnApproval
        } else {
            CommitmentState::Ready
        };
        Ok(Self {
            commitment_id: input.commitment_id,
            revision: 1,
            plan_id: input.plan_id,
            plan_revision: input.plan_revision,
            step_id: input.step_id,
            actor_id: input.actor_id,
            capability: input.capability,
            resource_urn: input.resource_urn,
            expected_effect: input.expected_effect,
            rollback_reference: input.rollback_reference,
            state: initial_state,
            grant_id: None,
            decision_id: None,
            receipt_urns: vec![],
            last_reason: "commitment proposed".into(),
        })
    }

    pub fn transition(&self, transition: CommitmentTransition) -> Result<Self, CommitmentError> {
        if transition.expected_revision != self.revision {
            return Err(CommitmentError::RevisionConflict {
                expected: transition.expected_revision,
                actual: self.revision,
            });
        }
        validate_text(&transition.reason).map_err(|_| CommitmentError::InvalidInput)?;
        if !transition_allowed(self.state, transition.to) {
            return Err(CommitmentError::InvalidTransition);
        }
        if transition.to == CommitmentState::Ready
            && self.state == CommitmentState::WaitingOnApproval
            && transition.decision_id.is_none()
        {
            return Err(CommitmentError::MissingAuthority);
        }
        if transition.to == CommitmentState::Executing && transition.grant_id.is_none() {
            return Err(CommitmentError::MissingAuthority);
        }
        if matches!(
            transition.to,
            CommitmentState::WaitingOnVerification | CommitmentState::Fulfilled
        ) && transition.receipt_urns.is_empty()
        {
            return Err(CommitmentError::MissingReceipt);
        }
        let mut receipt_urns = transition.receipt_urns;
        receipt_urns.sort();
        receipt_urns.dedup();
        if receipt_urns
            .iter()
            .any(|value| validate_text(value).is_err())
        {
            return Err(CommitmentError::InvalidInput);
        }
        let mut next = self.clone();
        next.revision += 1;
        next.state = transition.to;
        if transition.grant_id.is_some() {
            next.grant_id = transition.grant_id;
        }
        if transition.decision_id.is_some() {
            next.decision_id = transition.decision_id;
        }
        next.receipt_urns.extend(receipt_urns);
        next.receipt_urns.sort();
        next.receipt_urns.dedup();
        next.last_reason = transition.reason;
        Ok(next)
    }
}

fn transition_allowed(from: CommitmentState, to: CommitmentState) -> bool {
    use CommitmentState::*;
    matches!(
        (from, to),
        (Proposed, WaitingOnApproval | Ready | Cancelled)
            | (WaitingOnApproval, Ready | Cancelled)
            | (Ready, Executing | Cancelled)
            | (Executing, WaitingOnVerification | Failed)
            | (WaitingOnVerification, Fulfilled | Failed | Ready)
            | (Failed, Ready | Cancelled)
    )
}

fn validate_text(value: &str) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment() -> Commitment {
        Commitment::propose(CommitmentInput {
            commitment_id: CommitmentId::parse("commitment-1").unwrap(),
            plan_id: PlanId::parse("plan-1").unwrap(),
            plan_revision: 1,
            step_id: "remove-access".into(),
            actor_id: ActorId::parse("executor").unwrap(),
            capability: "identity.access.revoke".into(),
            resource_urn: "urn:identity:1".into(),
            expected_effect: "Production access is removed".into(),
            rollback_reference: Some("runbook:restore-access".into()),
            requires_decision: true,
        })
        .unwrap()
    }

    #[test]
    fn execution_requires_a_decision_and_grant() {
        let commitment = commitment();
        assert_eq!(commitment.state, CommitmentState::WaitingOnApproval);
        assert_eq!(
            commitment.transition(CommitmentTransition {
                expected_revision: 1,
                to: CommitmentState::Ready,
                grant_id: None,
                decision_id: None,
                receipt_urns: vec![],
                reason: "approved".into(),
            }),
            Err(CommitmentError::MissingAuthority)
        );

        let ready = commitment
            .transition(CommitmentTransition {
                expected_revision: 1,
                to: CommitmentState::Ready,
                grant_id: None,
                decision_id: Some(DecisionId::parse("decision-1").unwrap()),
                receipt_urns: vec![],
                reason: "operator approved the exact effect".into(),
            })
            .unwrap();
        assert_eq!(
            ready.transition(CommitmentTransition {
                expected_revision: 2,
                to: CommitmentState::Executing,
                grant_id: None,
                decision_id: None,
                receipt_urns: vec![],
                reason: "execute".into(),
            }),
            Err(CommitmentError::MissingAuthority)
        );
    }
}
