use serde::{Deserialize, Serialize};

use crate::{Commitment, CommitmentId, CommitmentState, MissionState, WakeConditionId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupervisorSnapshot {
    pub mission_state: MissionState,
    pub has_current_plan: bool,
    pub commitments: Vec<Commitment>,
    pub armed_wake_condition_ids: Vec<WakeConditionId>,
    pub satisfied_wake_condition_ids: Vec<WakeConditionId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "directive", rename_all = "snake_case")]
pub enum MissionDirective {
    ResolveScope,
    RevisePlan,
    RequestDecision {
        commitment_id: CommitmentId,
    },
    Execute {
        commitment_id: CommitmentId,
    },
    Verify {
        commitment_id: CommitmentId,
    },
    Wait {
        wake_condition_ids: Vec<WakeConditionId>,
    },
    ReplanFromWake {
        wake_condition_ids: Vec<WakeConditionId>,
    },
    Blocked {
        code: String,
    },
    Close,
    NoAction,
}

pub fn next_directive(snapshot: &SupervisorSnapshot) -> MissionDirective {
    match snapshot.mission_state {
        MissionState::Open | MissionState::ResolvingScope => MissionDirective::ResolveScope,
        MissionState::Planning => {
            if snapshot.has_current_plan {
                next_commitment_directive(&snapshot.commitments)
                    .unwrap_or_else(|| blocked("plan_has_no_active_commitment"))
            } else {
                MissionDirective::RevisePlan
            }
        }
        MissionState::WaitingOnEvidence | MissionState::Blocked => {
            if !snapshot.satisfied_wake_condition_ids.is_empty() {
                MissionDirective::ReplanFromWake {
                    wake_condition_ids: snapshot.satisfied_wake_condition_ids.clone(),
                }
            } else if !snapshot.armed_wake_condition_ids.is_empty() {
                MissionDirective::Wait {
                    wake_condition_ids: snapshot.armed_wake_condition_ids.clone(),
                }
            } else {
                blocked("no_wake_condition")
            }
        }
        MissionState::WaitingOnApproval => snapshot
            .commitments
            .iter()
            .find(|commitment| commitment.state == CommitmentState::WaitingOnApproval)
            .map(|commitment| MissionDirective::RequestDecision {
                commitment_id: commitment.commitment_id.clone(),
            })
            .unwrap_or_else(|| blocked("no_pending_decision")),
        MissionState::ReadyToAct | MissionState::Acting => {
            next_commitment_directive(&snapshot.commitments)
                .unwrap_or_else(|| blocked("no_executable_commitment"))
        }
        MissionState::Verifying => snapshot
            .commitments
            .iter()
            .find(|commitment| {
                commitment.state == CommitmentState::WaitingOnVerification
                    || commitment.state == CommitmentState::Executing
            })
            .map(|commitment| MissionDirective::Verify {
                commitment_id: commitment.commitment_id.clone(),
            })
            .unwrap_or_else(|| blocked("no_commitment_to_verify")),
        MissionState::Verified => MissionDirective::Close,
        MissionState::Closed => MissionDirective::NoAction,
    }
}

fn blocked(code: &str) -> MissionDirective {
    MissionDirective::Blocked { code: code.into() }
}

fn next_commitment_directive(commitments: &[Commitment]) -> Option<MissionDirective> {
    commitments
        .iter()
        .find(|commitment| commitment.state == CommitmentState::WaitingOnApproval)
        .map(|commitment| MissionDirective::RequestDecision {
            commitment_id: commitment.commitment_id.clone(),
        })
        .or_else(|| {
            commitments
                .iter()
                .find(|commitment| commitment.state == CommitmentState::Ready)
                .map(|commitment| MissionDirective::Execute {
                    commitment_id: commitment.commitment_id.clone(),
                })
        })
        .or_else(|| {
            commitments
                .iter()
                .find(|commitment| {
                    commitment.state == CommitmentState::WaitingOnVerification
                        || commitment.state == CommitmentState::Executing
                })
                .map(|commitment| MissionDirective::Verify {
                    commitment_id: commitment.commitment_id.clone(),
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActorId, CommitmentInput, PlanId};

    #[test]
    fn supervisor_interrupts_only_for_the_pending_decision() {
        let commitment = Commitment::propose(CommitmentInput {
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
        .unwrap();
        assert_eq!(
            next_directive(&SupervisorSnapshot {
                mission_state: MissionState::WaitingOnApproval,
                has_current_plan: true,
                commitments: vec![commitment],
                armed_wake_condition_ids: vec![],
                satisfied_wake_condition_ids: vec![],
            }),
            MissionDirective::RequestDecision {
                commitment_id: CommitmentId::parse("commitment-1").unwrap()
            }
        );
    }
}
