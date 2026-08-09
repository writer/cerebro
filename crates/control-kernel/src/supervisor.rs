use serde::{Deserialize, Serialize};

use crate::{Commitment, CommitmentId, CommitmentState, MissionState, WakeConditionId};

/// Minimal durable projection required to choose the mission's next action.
///
/// The supervisor is intentionally pure: callers assemble this snapshot from
/// the authoritative mission, plan, commitment, and wake-condition records,
/// then persist any resulting transition outside this module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupervisorSnapshot {
    /// Current state of the mission lifecycle.
    pub mission_state: MissionState,
    /// Whether the mission has a current plan revision eligible for execution.
    pub has_current_plan: bool,
    /// Commitments in their deterministic plan order. When several records
    /// share a state, the first record wins.
    pub commitments: Vec<Commitment>,
    /// Wake conditions that remain armed for the mission.
    pub armed_wake_condition_ids: Vec<WakeConditionId>,
    /// Wake conditions whose predicates have been durably satisfied.
    pub satisfied_wake_condition_ids: Vec<WakeConditionId>,
}

/// One bounded instruction emitted by the pure mission supervisor.
///
/// A directive describes the next control-plane action; it is not proof that
/// the action ran. Hosts must still apply authorization, fencing, execution,
/// persistence, and verification at their owning boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "directive", rename_all = "snake_case")]
pub enum MissionDirective {
    /// Resolve the mandate and subject before planning.
    ResolveScope,
    /// Produce or revise the current plan.
    RevisePlan,
    /// Obtain a durable decision for the named commitment.
    RequestDecision {
        /// Commitment whose authority is incomplete.
        commitment_id: CommitmentId,
    },
    /// Execute the named ready commitment.
    Execute {
        /// Commitment selected for bounded execution.
        commitment_id: CommitmentId,
    },
    /// Verify the named executing or verification-pending commitment.
    Verify {
        /// Commitment whose expected effect requires fresh evidence.
        commitment_id: CommitmentId,
    },
    /// Remain idle until at least one named armed condition is satisfied.
    Wait {
        /// Exact conditions the host should continue observing.
        wake_condition_ids: Vec<WakeConditionId>,
    },
    /// Re-enter planning using newly satisfied wake evidence.
    ReplanFromWake {
        /// Conditions whose satisfaction triggered reconsideration.
        wake_condition_ids: Vec<WakeConditionId>,
    },
    /// Stop automatic progress because the snapshot violates a supervisor
    /// invariant or lacks the record required by its mission state.
    Blocked {
        /// Stable machine-readable reason code.
        code: String,
    },
    /// Close a verified mission.
    Close,
    /// Perform no work for an already closed mission.
    NoAction,
}

/// Selects exactly one next directive from a mission projection.
///
/// Selection is deterministic. Satisfied wake conditions take precedence over
/// armed conditions, and commitment work is ordered as approval, execution,
/// then verification. Missing records fail closed through a stable `Blocked`
/// code instead of guessing a recovery action.
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
    // Approval always wins so an executable sibling cannot let the mission
    // run past an unresolved authority boundary. Ready work precedes
    // verification only after no pending decision remains.
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

    fn commitment(state: CommitmentState) -> Commitment {
        let mut commitment = Commitment::propose(CommitmentInput {
            commitment_id: CommitmentId::parse(format!("commitment-{state:?}")).unwrap(),
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
        commitment.state = state;
        commitment
    }

    fn snapshot(state: MissionState) -> SupervisorSnapshot {
        SupervisorSnapshot {
            mission_state: state,
            has_current_plan: true,
            commitments: vec![],
            armed_wake_condition_ids: vec![],
            satisfied_wake_condition_ids: vec![],
        }
    }

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

    #[test]
    fn supervisor_emits_a_bounded_directive_for_every_mission_state() {
        assert_eq!(
            next_directive(&snapshot(MissionState::Open)),
            MissionDirective::ResolveScope
        );
        assert_eq!(
            next_directive(&snapshot(MissionState::ResolvingScope)),
            MissionDirective::ResolveScope
        );

        let mut planning = snapshot(MissionState::Planning);
        planning.has_current_plan = false;
        assert_eq!(next_directive(&planning), MissionDirective::RevisePlan);
        planning.has_current_plan = true;
        assert_eq!(
            next_directive(&planning),
            blocked("plan_has_no_active_commitment")
        );
        planning.commitments = vec![commitment(CommitmentState::WaitingOnApproval)];
        assert!(matches!(
            next_directive(&planning),
            MissionDirective::RequestDecision { .. }
        ));
        planning.commitments = vec![commitment(CommitmentState::Ready)];
        assert!(matches!(
            next_directive(&planning),
            MissionDirective::Execute { .. }
        ));
        planning.commitments = vec![commitment(CommitmentState::Executing)];
        assert!(matches!(
            next_directive(&planning),
            MissionDirective::Verify { .. }
        ));

        for state in [MissionState::WaitingOnEvidence, MissionState::Blocked] {
            let mut waiting = snapshot(state);
            assert_eq!(next_directive(&waiting), blocked("no_wake_condition"));
            waiting.armed_wake_condition_ids = vec![WakeConditionId::parse("wake-1").unwrap()];
            assert!(matches!(
                next_directive(&waiting),
                MissionDirective::Wait { .. }
            ));
            waiting.satisfied_wake_condition_ids = vec![WakeConditionId::parse("wake-2").unwrap()];
            assert!(matches!(
                next_directive(&waiting),
                MissionDirective::ReplanFromWake { .. }
            ));
        }

        let mut approval = snapshot(MissionState::WaitingOnApproval);
        assert_eq!(next_directive(&approval), blocked("no_pending_decision"));
        approval.commitments = vec![commitment(CommitmentState::WaitingOnApproval)];
        assert!(matches!(
            next_directive(&approval),
            MissionDirective::RequestDecision { .. }
        ));

        for state in [MissionState::ReadyToAct, MissionState::Acting] {
            let mut acting = snapshot(state);
            assert_eq!(next_directive(&acting), blocked("no_executable_commitment"));
            acting.commitments = vec![commitment(CommitmentState::Ready)];
            assert!(matches!(
                next_directive(&acting),
                MissionDirective::Execute { .. }
            ));
        }

        let mut verifying = snapshot(MissionState::Verifying);
        assert_eq!(
            next_directive(&verifying),
            blocked("no_commitment_to_verify")
        );
        verifying.commitments = vec![commitment(CommitmentState::WaitingOnVerification)];
        assert!(matches!(
            next_directive(&verifying),
            MissionDirective::Verify { .. }
        ));
        assert_eq!(
            next_directive(&snapshot(MissionState::Verified)),
            MissionDirective::Close
        );
        assert_eq!(
            next_directive(&snapshot(MissionState::Closed)),
            MissionDirective::NoAction
        );
    }
}
