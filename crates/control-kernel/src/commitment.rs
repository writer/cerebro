use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, CommitmentId, DecisionId, GrantId, PlanId};

const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Lifecycle state of one planned, authorized, executed, and verified effect.
pub enum CommitmentState {
    /// Proposed from a plan but not yet accepted for execution.
    Proposed,
    /// An exact approval decision is required before the effect can become ready.
    WaitingOnApproval,
    /// Preconditions are satisfied and an execution grant may be attached.
    Ready,
    /// An authorized executor has begun the external effect.
    Executing,
    /// Execution produced receipts but independent outcome verification is pending.
    WaitingOnVerification,
    /// Independent evidence establishes the expected effect.
    Fulfilled,
    /// Execution or verification established a terminal unsuccessful attempt.
    Failed,
    /// Work was intentionally ended before fulfillment.
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Validated inputs for proposing a commitment from one immutable plan revision.
pub struct CommitmentInput {
    /// Stable identifier for the new commitment.
    pub commitment_id: CommitmentId,
    /// Plan that owns the proposed effect.
    pub plan_id: PlanId,
    /// Non-zero immutable revision of that plan.
    pub plan_revision: u64,
    /// Stable plan-local step identifier producing the commitment.
    pub step_id: String,
    /// Actor expected to execute the effect.
    pub actor_id: ActorId,
    /// Exact capability required for execution.
    pub capability: String,
    /// Canonical resource the effect targets.
    pub resource_urn: String,
    /// Observable source-state change expected after execution.
    pub expected_effect: String,
    /// Runbook or action reference for reversing the effect, when available.
    pub rollback_reference: Option<String>,
    /// Whether readiness requires a separately recorded approval decision.
    pub requires_decision: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Durable state machine for one concrete external-effect obligation.
///
/// A commitment binds an immutable plan revision, executor, capability, target,
/// and expected result. State changes must go through [`Self::transition`] so
/// approval, execution authority, receipts, and optimistic revision checks cannot
/// be skipped by callers.
pub struct Commitment {
    /// Stable identity preserved across every revision.
    pub commitment_id: CommitmentId,
    /// Current optimistic-concurrency revision, starting at one.
    pub revision: u64,
    /// Plan that created this commitment.
    pub plan_id: PlanId,
    /// Immutable plan revision whose step and expected effect are being executed.
    pub plan_revision: u64,
    /// Stable step identifier within the owning plan revision.
    pub step_id: String,
    /// Actor designated to perform the effect.
    pub actor_id: ActorId,
    /// Exact capability the executor must be granted.
    pub capability: String,
    /// Canonical resource targeted by the effect.
    pub resource_urn: String,
    /// Observable result that later verification must establish.
    pub expected_effect: String,
    /// Recovery reference retained with the effect record.
    pub rollback_reference: Option<String>,
    /// Current lifecycle state.
    pub state: CommitmentState,
    /// Capability grant used to enter execution, once attached.
    pub grant_id: Option<GrantId>,
    /// Approval decision used to leave `WaitingOnApproval`, once attached.
    pub decision_id: Option<DecisionId>,
    /// Deduplicated execution and verification receipt references accumulated so far.
    pub receipt_urns: Vec<String>,
    /// Bounded explanation supplied with the most recent transition.
    pub last_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Requested optimistic transition for an existing [`Commitment`].
pub struct CommitmentTransition {
    /// Revision the caller read; stale values fail without mutating state.
    pub expected_revision: u64,
    /// Requested next lifecycle state.
    pub to: CommitmentState,
    /// Execution grant to attach when entering `Executing`.
    pub grant_id: Option<GrantId>,
    /// Approval receipt to attach when leaving `WaitingOnApproval`.
    pub decision_id: Option<DecisionId>,
    /// Execution or verification receipts required by evidence-bearing states.
    pub receipt_urns: Vec<String>,
    /// Bounded factual reason for the transition.
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Reason a commitment proposal or transition was rejected.
pub enum CommitmentError {
    /// Text, revision, or receipt input violates the bounded contract.
    InvalidInput,
    /// The requested state edge is absent from the lifecycle graph.
    InvalidTransition,
    /// A required approval decision or capability grant was not supplied.
    MissingAuthority,
    /// A state claiming execution or verification did not supply evidence receipts.
    MissingReceipt,
    /// The caller attempted a transition from a stale aggregate revision.
    RevisionConflict {
        /// Revision supplied by the caller.
        expected: u64,
        /// Current commitment revision.
        actual: u64,
    },
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
    /// Creates revision one of a commitment after validating its immutable bindings.
    ///
    /// Decision-gated commitments begin in `WaitingOnApproval`; all others begin
    /// `Ready`. Proposal does not authorize execution, attach receipts, or validate
    /// that the named actor currently owns the requested capability.
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

    /// Applies one legal state transition and returns a new aggregate revision.
    ///
    /// The transition fails closed on stale revisions, illegal edges, missing
    /// decisions or grants, and missing receipts. New receipt URNs are validated,
    /// sorted, and deduplicated with prior receipts. This method validates structural
    /// evidence presence; adapters must separately authenticate the referenced
    /// approval, grant, execution, and verification records.
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
