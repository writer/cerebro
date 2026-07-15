use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, MandateId, MissionId, TenantId, VerificationReceipt};

const MAX_SUBJECT_URNS: usize = 256;
const MAX_REASON_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionState {
    Open,
    ResolvingScope,
    Planning,
    WaitingOnEvidence,
    WaitingOnApproval,
    ReadyToAct,
    Acting,
    Verifying,
    Verified,
    Blocked,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionInput {
    pub tenant_id: TenantId,
    pub mission_id: MissionId,
    pub mandate_id: MandateId,
    pub mandate_revision: u64,
    pub objective: String,
    pub subject_urns: Vec<String>,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Mission {
    pub tenant_id: TenantId,
    pub mission_id: MissionId,
    pub mandate_id: MandateId,
    pub mandate_revision: u64,
    pub revision: u64,
    pub state: MissionState,
    pub objective: String,
    pub subject_urns: Vec<String>,
    pub changed_by: ActorId,
    pub last_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionTransition {
    pub expected_revision: u64,
    pub to: MissionState,
    pub actor_id: ActorId,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissionError {
    InvalidObjective,
    InvalidSubjects,
    InvalidMandateRevision,
    InvalidReason,
    InvalidVerification,
    RevisionConflict {
        expected: u64,
        actual: u64,
    },
    InvalidTransition {
        from: MissionState,
        to: MissionState,
    },
}

impl fmt::Display for MissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObjective => formatter.write_str("mission objective is invalid"),
            Self::InvalidSubjects => formatter.write_str("mission subjects are invalid"),
            Self::InvalidMandateRevision => {
                formatter.write_str("mission mandate revision must be positive")
            }
            Self::InvalidReason => formatter.write_str("mission transition reason is invalid"),
            Self::InvalidVerification => {
                formatter.write_str("mission verification receipt is invalid")
            }
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "mission revision conflict: expected {expected}, actual {actual}"
            ),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid mission transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl Error for MissionError {}

impl Mission {
    pub fn open(input: MissionInput) -> Result<Self, MissionError> {
        validate_text(&input.objective).map_err(|_| MissionError::InvalidObjective)?;
        if input.mandate_revision == 0 {
            return Err(MissionError::InvalidMandateRevision);
        }
        let subject_urns = normalize_subjects(input.subject_urns)?;
        Ok(Self {
            tenant_id: input.tenant_id,
            mission_id: input.mission_id,
            mandate_id: input.mandate_id,
            mandate_revision: input.mandate_revision,
            revision: 1,
            state: MissionState::Open,
            objective: input.objective,
            subject_urns,
            changed_by: input.actor_id,
            last_reason: "mission opened".into(),
        })
    }

    pub fn transition(&self, transition: MissionTransition) -> Result<Self, MissionError> {
        if transition.expected_revision != self.revision {
            return Err(MissionError::RevisionConflict {
                expected: transition.expected_revision,
                actual: self.revision,
            });
        }
        validate_text(&transition.reason).map_err(|_| MissionError::InvalidReason)?;
        if !transition_allowed(self.state, transition.to) {
            return Err(MissionError::InvalidTransition {
                from: self.state,
                to: transition.to,
            });
        }
        let mut next = self.clone();
        next.revision += 1;
        next.state = transition.to;
        next.changed_by = transition.actor_id;
        next.last_reason = transition.reason;
        Ok(next)
    }

    pub fn verify(
        &self,
        expected_revision: u64,
        receipt: &VerificationReceipt,
        reason: String,
    ) -> Result<Self, MissionError> {
        if expected_revision != self.revision {
            return Err(MissionError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if self.state != MissionState::Verifying {
            return Err(MissionError::InvalidTransition {
                from: self.state,
                to: MissionState::Verified,
            });
        }
        validate_text(&reason).map_err(|_| MissionError::InvalidReason)?;
        if !receipt.independently_confirms_effect() {
            return Err(MissionError::InvalidVerification);
        }
        let mut next = self.clone();
        next.revision += 1;
        next.state = MissionState::Verified;
        next.changed_by = receipt.verifier_actor_id.clone();
        next.last_reason = reason;
        Ok(next)
    }
}

fn transition_allowed(from: MissionState, to: MissionState) -> bool {
    use MissionState::*;
    matches!(
        (from, to),
        (Open, ResolvingScope)
            | (ResolvingScope, Planning | WaitingOnEvidence | Blocked)
            | (
                Planning,
                WaitingOnEvidence | WaitingOnApproval | ReadyToAct | Blocked
            )
            | (WaitingOnEvidence, Planning | Blocked)
            | (WaitingOnApproval, ReadyToAct | Planning | Blocked)
            | (ReadyToAct, Acting | Planning | Blocked)
            | (Acting, Verifying | Blocked)
            | (Verifying, Planning | WaitingOnEvidence | Blocked)
            | (Verified, Closed | ResolvingScope)
            | (
                Blocked,
                ResolvingScope | Planning | WaitingOnEvidence | WaitingOnApproval
            )
            | (Closed, ResolvingScope)
    )
}

fn validate_text(value: &str) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_REASON_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

fn normalize_subjects(mut subjects: Vec<String>) -> Result<Vec<String>, MissionError> {
    if subjects.is_empty() || subjects.len() > MAX_SUBJECT_URNS {
        return Err(MissionError::InvalidSubjects);
    }
    for subject in &subjects {
        if subject.trim().is_empty()
            || subject.trim() != subject
            || subject.len() > 1_024
            || subject.chars().any(char::is_control)
        {
            return Err(MissionError::InvalidSubjects);
        }
    }
    subjects.sort();
    subjects.dedup();
    Ok(subjects)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mission() -> Mission {
        Mission::open(MissionInput {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            mission_id: MissionId::parse("mission-1").unwrap(),
            mandate_id: MandateId::parse("mandate-1").unwrap(),
            mandate_revision: 1,
            objective: "Remove effective access for a terminated identity".into(),
            subject_urns: vec!["urn:identity:1".into()],
            actor_id: ActorId::parse("kernel").unwrap(),
        })
        .unwrap()
    }

    fn advance(mission: &Mission, to: MissionState) -> Mission {
        mission
            .transition(MissionTransition {
                expected_revision: mission.revision,
                to,
                actor_id: ActorId::parse("kernel").unwrap(),
                reason: format!("advance to {to:?}"),
            })
            .unwrap()
    }

    fn verification() -> VerificationReceipt {
        VerificationReceipt {
            verification_id: crate::VerificationId::parse("verification-1").unwrap(),
            executor_actor_id: ActorId::parse("worker-1").unwrap(),
            verifier_actor_id: ActorId::parse("observer-1").unwrap(),
            previous_source_revision: "revision-1".into(),
            observed_source_revision: "revision-2".into(),
            effective: true,
            evidence_urns: vec!["urn:evidence:1".into()],
            verified_at_unix_ms: 20,
        }
    }

    #[test]
    fn mission_happy_path_requires_verification_before_closure() {
        let mission = mission();
        let mission = advance(&mission, MissionState::ResolvingScope);
        let mission = advance(&mission, MissionState::Planning);
        let mission = advance(&mission, MissionState::WaitingOnApproval);
        let mission = advance(&mission, MissionState::ReadyToAct);
        let mission = advance(&mission, MissionState::Acting);
        let mission = advance(&mission, MissionState::Verifying);

        assert!(matches!(
            mission.transition(MissionTransition {
                expected_revision: mission.revision,
                to: MissionState::Closed,
                actor_id: ActorId::parse("kernel").unwrap(),
                reason: "close".into(),
            }),
            Err(MissionError::InvalidTransition { .. })
        ));

        let mission = mission
            .verify(mission.revision, &verification(), "effect observed".into())
            .unwrap();
        assert_eq!(
            advance(&mission, MissionState::Closed).state,
            MissionState::Closed
        );
    }

    #[test]
    fn closed_missions_reopen_in_scope_resolution() {
        let mission = mission();
        let mission = advance(&mission, MissionState::ResolvingScope);
        let mission = advance(&mission, MissionState::Planning);
        let mission = advance(&mission, MissionState::ReadyToAct);
        let mission = advance(&mission, MissionState::Acting);
        let mission = advance(&mission, MissionState::Verifying);
        let mission = mission
            .verify(mission.revision, &verification(), "effect observed".into())
            .unwrap();
        let mission = advance(&mission, MissionState::Closed);
        let reopened = advance(&mission, MissionState::ResolvingScope);

        assert_eq!(reopened.state, MissionState::ResolvingScope);
        assert_eq!(reopened.revision, mission.revision + 1);
    }

    #[test]
    fn stale_workers_cannot_advance_a_mission() {
        let mission = mission();
        let next = advance(&mission, MissionState::ResolvingScope);

        assert!(matches!(
            next.transition(MissionTransition {
                expected_revision: 1,
                to: MissionState::Planning,
                actor_id: ActorId::parse("stale-worker").unwrap(),
                reason: "stale plan".into(),
            }),
            Err(MissionError::RevisionConflict { .. })
        ));
    }
}
