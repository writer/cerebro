use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, Belief, BeliefError, BeliefId, BeliefInput, BeliefRevision, Commitment,
    CommitmentError, CommitmentId, CommitmentInput, CommitmentTransition, Mission, MissionError,
    MissionId, MissionInput, MissionState, MissionTransition, PlanError, PlanRevision, TenantId,
    VerificationReceipt, WakeCondition, WakeConditionError, WakeConditionId, WakeConditionKind,
    WakeSignal,
};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionEventEnvelope {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub mission_id: MissionId,
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub actor_id: ActorId,
    pub idempotency_key: String,
    pub event: MissionEvent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MissionEvent {
    Opened {
        input: MissionInput,
    },
    Transitioned {
        from: MissionState,
        to: MissionState,
        reason: String,
    },
    Verified {
        from: MissionState,
        reason: String,
        receipt: VerificationReceipt,
    },
    BeliefRecorded {
        input: BeliefInput,
    },
    BeliefRevised {
        belief_id: BeliefId,
        revision: BeliefRevision,
    },
    PlanRevised {
        revision: PlanRevision,
    },
    CommitmentProposed {
        input: CommitmentInput,
    },
    CommitmentTransitioned {
        commitment_id: CommitmentId,
        transition: CommitmentTransition,
    },
    WakeConditionArmed {
        wake_condition_id: WakeConditionId,
        kind: WakeConditionKind,
        reason: String,
    },
    WakeConditionSatisfied {
        wake_condition_id: WakeConditionId,
        signal: WakeSignal,
    },
    WakeConditionCancelled {
        wake_condition_id: WakeConditionId,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAggregate {
    pub mission: Mission,
    pub last_sequence: u64,
    pub beliefs: BTreeMap<BeliefId, Belief>,
    pub plan_revisions: Vec<PlanRevision>,
    pub commitments: BTreeMap<CommitmentId, Commitment>,
    pub wake_conditions: BTreeMap<WakeConditionId, WakeCondition>,
    seen_idempotency_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    Empty,
    InvalidSequence { expected: u64, actual: u64 },
    InvalidEnvelope,
    DuplicateIdempotencyKey,
    IdentityMismatch,
    StateMismatch,
    DuplicateRecord,
    MissingRecord,
    ClosureBlocked,
    Mission(MissionError),
    Belief(BeliefError),
    Plan(PlanError),
    Commitment(CommitmentError),
    WakeCondition(WakeConditionError),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("mission event stream is empty"),
            Self::InvalidSequence { expected, actual } => {
                write!(
                    formatter,
                    "invalid mission sequence: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidEnvelope => formatter.write_str("mission event envelope is invalid"),
            Self::DuplicateIdempotencyKey => {
                formatter.write_str("mission idempotency key is duplicated")
            }
            Self::IdentityMismatch => {
                formatter.write_str("mission event identity does not match stream")
            }
            Self::StateMismatch => {
                formatter.write_str("mission event state does not match aggregate")
            }
            Self::DuplicateRecord => formatter.write_str("mission record is duplicated"),
            Self::MissingRecord => formatter.write_str("mission record is missing"),
            Self::ClosureBlocked => formatter.write_str(
                "mission verification is blocked by active commitments or wake conditions",
            ),
            Self::Mission(error) => write!(formatter, "mission event is invalid: {error}"),
            Self::Belief(error) => write!(formatter, "mission belief is invalid: {error}"),
            Self::Plan(error) => write!(formatter, "mission plan is invalid: {error}"),
            Self::Commitment(error) => write!(formatter, "mission commitment is invalid: {error}"),
            Self::WakeCondition(error) => {
                write!(formatter, "mission wake condition is invalid: {error}")
            }
        }
    }
}

impl Error for ReplayError {}

impl From<MissionError> for ReplayError {
    fn from(value: MissionError) -> Self {
        Self::Mission(value)
    }
}

impl From<BeliefError> for ReplayError {
    fn from(value: BeliefError) -> Self {
        Self::Belief(value)
    }
}

impl From<PlanError> for ReplayError {
    fn from(value: PlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<CommitmentError> for ReplayError {
    fn from(value: CommitmentError) -> Self {
        Self::Commitment(value)
    }
}

impl From<WakeConditionError> for ReplayError {
    fn from(value: WakeConditionError) -> Self {
        Self::WakeCondition(value)
    }
}

impl MissionAggregate {
    pub fn replay(events: &[MissionEventEnvelope]) -> Result<Self, ReplayError> {
        let first = events.first().ok_or(ReplayError::Empty)?;
        validate_envelope(first, 1)?;
        let MissionEvent::Opened { input } = &first.event else {
            return Err(ReplayError::StateMismatch);
        };
        if input.tenant_id != first.tenant_id
            || input.mission_id != first.mission_id
            || input.actor_id != first.actor_id
        {
            return Err(ReplayError::IdentityMismatch);
        }
        let mission = Mission::open(input.clone())?;
        let mut aggregate = Self {
            mission,
            last_sequence: 1,
            beliefs: BTreeMap::new(),
            plan_revisions: vec![],
            commitments: BTreeMap::new(),
            wake_conditions: BTreeMap::new(),
            seen_idempotency_keys: BTreeSet::from([first.idempotency_key.clone()]),
        };
        for event in &events[1..] {
            aggregate.apply(event)?;
        }
        Ok(aggregate)
    }

    pub fn apply(&mut self, envelope: &MissionEventEnvelope) -> Result<(), ReplayError> {
        let expected_sequence = self.last_sequence + 1;
        validate_envelope(envelope, expected_sequence)?;
        if envelope.tenant_id != self.mission.tenant_id
            || envelope.mission_id != self.mission.mission_id
        {
            return Err(ReplayError::IdentityMismatch);
        }
        if self
            .seen_idempotency_keys
            .contains(&envelope.idempotency_key)
        {
            return Err(ReplayError::DuplicateIdempotencyKey);
        }
        match &envelope.event {
            MissionEvent::Opened { .. } => return Err(ReplayError::StateMismatch),
            MissionEvent::Transitioned { from, to, reason } => {
                if *from != self.mission.state {
                    return Err(ReplayError::StateMismatch);
                }
                self.mission = self.mission.transition(MissionTransition {
                    expected_revision: self.mission.revision,
                    to: *to,
                    actor_id: envelope.actor_id.clone(),
                    reason: reason.clone(),
                })?;
            }
            MissionEvent::Verified {
                from,
                reason,
                receipt,
            } => {
                if *from != self.mission.state {
                    return Err(ReplayError::StateMismatch);
                }
                if envelope.actor_id != receipt.verifier_actor_id
                    || self.commitments.values().any(|commitment| {
                        !matches!(
                            commitment.state,
                            crate::CommitmentState::Fulfilled | crate::CommitmentState::Cancelled
                        )
                    })
                    || self
                        .wake_conditions
                        .values()
                        .any(|condition| condition.state == crate::WakeConditionState::Armed)
                {
                    return Err(ReplayError::ClosureBlocked);
                }
                self.mission =
                    self.mission
                        .verify(self.mission.revision, receipt, reason.clone())?;
            }
            MissionEvent::BeliefRecorded { input } => {
                if input.actor_id != envelope.actor_id {
                    return Err(ReplayError::IdentityMismatch);
                }
                if self.beliefs.contains_key(&input.belief_id) {
                    return Err(ReplayError::DuplicateRecord);
                }
                let belief = Belief::record(input.clone())?;
                self.beliefs.insert(belief.belief_id.clone(), belief);
            }
            MissionEvent::BeliefRevised {
                belief_id,
                revision,
            } => {
                if revision.actor_id != envelope.actor_id {
                    return Err(ReplayError::IdentityMismatch);
                }
                let belief = self
                    .beliefs
                    .get(belief_id)
                    .ok_or(ReplayError::MissingRecord)?
                    .revise(revision.clone())?;
                self.beliefs.insert(belief_id.clone(), belief);
            }
            MissionEvent::PlanRevised { revision } => {
                if revision.created_by != envelope.actor_id {
                    return Err(ReplayError::IdentityMismatch);
                }
                if revision
                    .hypothesis_ids
                    .iter()
                    .any(|belief_id| !self.beliefs.contains_key(belief_id))
                {
                    return Err(ReplayError::MissingRecord);
                }
                revision.validate(self.plan_revisions.last())?;
                self.plan_revisions.push(revision.clone());
            }
            MissionEvent::CommitmentProposed { input } => {
                if self.commitments.contains_key(&input.commitment_id) {
                    return Err(ReplayError::DuplicateRecord);
                }
                let plan = self
                    .plan_revisions
                    .iter()
                    .find(|plan| {
                        plan.plan_id == input.plan_id && plan.revision == input.plan_revision
                    })
                    .ok_or(ReplayError::MissingRecord)?;
                if !plan.steps.iter().any(|step| step.step_id == input.step_id) {
                    return Err(ReplayError::MissingRecord);
                }
                let commitment = Commitment::propose(input.clone())?;
                self.commitments
                    .insert(commitment.commitment_id.clone(), commitment);
            }
            MissionEvent::CommitmentTransitioned {
                commitment_id,
                transition,
            } => {
                let commitment = self
                    .commitments
                    .get(commitment_id)
                    .ok_or(ReplayError::MissingRecord)?
                    .transition(transition.clone())?;
                self.commitments.insert(commitment_id.clone(), commitment);
            }
            MissionEvent::WakeConditionArmed {
                wake_condition_id,
                kind,
                reason,
            } => {
                if self.wake_conditions.contains_key(wake_condition_id) {
                    return Err(ReplayError::DuplicateRecord);
                }
                let condition = WakeCondition::arm(
                    wake_condition_id.clone(),
                    kind.clone(),
                    envelope.observed_at_unix_ms,
                    reason.clone(),
                )?;
                self.wake_conditions
                    .insert(wake_condition_id.clone(), condition);
            }
            MissionEvent::WakeConditionSatisfied {
                wake_condition_id,
                signal,
            } => {
                let condition = self
                    .wake_conditions
                    .get(wake_condition_id)
                    .ok_or(ReplayError::MissingRecord)?
                    .satisfy(signal, envelope.observed_at_unix_ms)?;
                self.wake_conditions
                    .insert(wake_condition_id.clone(), condition);
            }
            MissionEvent::WakeConditionCancelled {
                wake_condition_id,
                reason,
            } => {
                let condition = self
                    .wake_conditions
                    .get(wake_condition_id)
                    .ok_or(ReplayError::MissingRecord)?
                    .cancel(reason.clone())?;
                self.wake_conditions
                    .insert(wake_condition_id.clone(), condition);
            }
        }
        self.last_sequence = envelope.sequence;
        self.seen_idempotency_keys
            .insert(envelope.idempotency_key.clone());
        Ok(())
    }
}

fn validate_envelope(
    event: &MissionEventEnvelope,
    expected_sequence: u64,
) -> Result<(), ReplayError> {
    if event.sequence != expected_sequence {
        return Err(ReplayError::InvalidSequence {
            expected: expected_sequence,
            actual: event.sequence,
        });
    }
    if event.schema_version != crate::SCHEMA_VERSION
        || event.observed_at_unix_ms == 0
        || event.idempotency_key.trim().is_empty()
        || event.idempotency_key.trim() != event.idempotency_key
        || event.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || event.idempotency_key.chars().any(char::is_control)
    {
        return Err(ReplayError::InvalidEnvelope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MandateId;

    fn opened() -> MissionEventEnvelope {
        let tenant_id = TenantId::parse("tenant-1").unwrap();
        let mission_id = MissionId::parse("mission-1").unwrap();
        MissionEventEnvelope {
            schema_version: crate::SCHEMA_VERSION.into(),
            tenant_id: tenant_id.clone(),
            mission_id: mission_id.clone(),
            sequence: 1,
            observed_at_unix_ms: 10,
            actor_id: ActorId::parse("kernel").unwrap(),
            idempotency_key: "open-1".into(),
            event: MissionEvent::Opened {
                input: MissionInput {
                    tenant_id,
                    mission_id,
                    mandate_id: MandateId::parse("mandate-1").unwrap(),
                    mandate_revision: 1,
                    objective: "Remove stale access".into(),
                    subject_urns: vec!["urn:identity:1".into()],
                    actor_id: ActorId::parse("kernel").unwrap(),
                },
            },
        }
    }

    fn transition(sequence: u64, from: MissionState, to: MissionState) -> MissionEventEnvelope {
        MissionEventEnvelope {
            schema_version: crate::SCHEMA_VERSION.into(),
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            mission_id: MissionId::parse("mission-1").unwrap(),
            sequence,
            observed_at_unix_ms: 10 + sequence,
            actor_id: ActorId::parse("worker-1").unwrap(),
            idempotency_key: format!("event-{sequence}"),
            event: MissionEvent::Transitioned {
                from,
                to,
                reason: format!("advance to {to:?}"),
            },
        }
    }

    #[test]
    fn replay_is_deterministic() {
        let events = vec![
            opened(),
            transition(2, MissionState::Open, MissionState::ResolvingScope),
            transition(3, MissionState::ResolvingScope, MissionState::Planning),
        ];
        let first = MissionAggregate::replay(&events).unwrap();
        let second = MissionAggregate::replay(&events).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.mission.state, MissionState::Planning);
    }

    #[test]
    fn replay_rejects_gaps_and_duplicate_keys() {
        let gap = vec![
            opened(),
            transition(3, MissionState::Open, MissionState::ResolvingScope),
        ];
        assert!(matches!(
            MissionAggregate::replay(&gap),
            Err(ReplayError::InvalidSequence { .. })
        ));

        let mut duplicate = transition(2, MissionState::Open, MissionState::ResolvingScope);
        duplicate.idempotency_key = "open-1".into();
        assert_eq!(
            MissionAggregate::replay(&[opened(), duplicate]),
            Err(ReplayError::DuplicateIdempotencyKey)
        );
    }
}
