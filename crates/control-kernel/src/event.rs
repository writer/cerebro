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
/// Sequenced, tenant-bound envelope for one immutable mission aggregate event.
pub struct MissionEventEnvelope {
    /// Must equal the crate's [`crate::SCHEMA_VERSION`].
    pub schema_version: String,
    /// Tenant boundary shared by the complete stream.
    pub tenant_id: TenantId,
    /// Mission identity shared by the complete stream.
    pub mission_id: MissionId,
    /// Contiguous one-based stream position.
    pub sequence: u64,
    /// Non-zero Unix-millisecond time at which the event was observed.
    pub observed_at_unix_ms: u64,
    /// Actor responsible for the recorded transition or input.
    pub actor_id: ActorId,
    /// Stream-unique key used to reject duplicate application.
    pub idempotency_key: String,
    /// Domain fact to apply to the aggregate.
    pub event: MissionEvent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
/// Immutable domain fact accepted into a mission event stream.
pub enum MissionEvent {
    /// Creates revision one and must be the first stream event.
    Opened {
        /// Exact validated mission creation input.
        input: MissionInput,
    },
    /// Applies a legal non-verification mission lifecycle edge.
    Transitioned {
        /// State expected before the transition.
        from: MissionState,
        /// Requested next state.
        to: MissionState,
        /// Bounded reason recorded on the mission revision.
        reason: String,
    },
    /// Moves a verifying mission to verified using independent evidence.
    Verified {
        /// State expected before verification.
        from: MissionState,
        /// Bounded verification conclusion.
        reason: String,
        /// Independent post-effect observation.
        receipt: VerificationReceipt,
    },
    /// Creates one evidence-bounded belief.
    BeliefRecorded {
        /// Exact initial belief input whose actor must match the envelope.
        input: BeliefInput,
    },
    /// Replaces the evidence judgment for an existing belief.
    BeliefRevised {
        /// Existing belief to revise.
        belief_id: BeliefId,
        /// Optimistic replacement snapshot.
        revision: BeliefRevision,
    },
    /// Appends a validated contiguous plan revision.
    PlanRevised {
        /// Plan revision whose beliefs must already exist in the aggregate.
        revision: PlanRevision,
    },
    /// Creates a commitment bound to an existing plan step.
    CommitmentProposed {
        /// Exact immutable commitment bindings.
        input: CommitmentInput,
    },
    /// Applies a legal transition to an existing commitment.
    CommitmentTransitioned {
        /// Existing commitment to update.
        commitment_id: CommitmentId,
        /// Optimistic authority- and receipt-bearing transition.
        transition: CommitmentTransition,
    },
    /// Creates a future-observation condition in the armed state.
    WakeConditionArmed {
        /// Stable wake-condition identity.
        wake_condition_id: WakeConditionId,
        /// Exact signal predicate.
        kind: WakeConditionKind,
        /// Bounded reason for waiting.
        reason: String,
    },
    /// Records the exact signal that satisfied an armed wake condition.
    WakeConditionSatisfied {
        /// Existing armed condition.
        wake_condition_id: WakeConditionId,
        /// Signal evaluated by the condition predicate.
        signal: WakeSignal,
    },
    /// Terminally cancels an armed wake condition.
    WakeConditionCancelled {
        /// Existing armed condition.
        wake_condition_id: WakeConditionId,
        /// Bounded cancellation reason.
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Materialized mission state reconstructed from a validated event prefix.
pub struct MissionAggregate {
    /// Current mission revision and lifecycle state.
    pub mission: Mission,
    /// Sequence of the last applied event.
    pub last_sequence: u64,
    /// Current belief revisions keyed by stable identity.
    pub beliefs: BTreeMap<BeliefId, Belief>,
    /// Ordered plan history retained for lineage and commitment lookup.
    pub plan_revisions: Vec<PlanRevision>,
    /// Current commitment revisions keyed by stable identity.
    pub commitments: BTreeMap<CommitmentId, Commitment>,
    /// Current wake-condition revisions keyed by stable identity.
    pub wake_conditions: BTreeMap<WakeConditionId, WakeCondition>,
    seen_idempotency_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Reason deterministic mission event replay stopped.
pub enum ReplayError {
    /// A mission cannot be reconstructed from an empty stream.
    Empty,
    /// Event sequence was not contiguous.
    InvalidSequence {
        /// Next required sequence.
        expected: u64,
        /// Sequence supplied by the envelope.
        actual: u64,
    },
    /// Schema, timestamp, or idempotency key was malformed.
    InvalidEnvelope,
    /// An idempotency key already appeared in the stream.
    DuplicateIdempotencyKey,
    /// Tenant, mission, or actor identity disagreed with its bound record.
    IdentityMismatch,
    /// Event's declared prior state disagreed with the materialized aggregate.
    StateMismatch,
    /// Event attempted to create an already-existing child record.
    DuplicateRecord,
    /// Event referenced a belief, plan, commitment, or wake condition not yet recorded.
    MissingRecord,
    /// Verification was attempted while commitments or wake conditions remained active.
    ClosureBlocked,
    /// Mission lifecycle validation failed.
    Mission(MissionError),
    /// Belief validation failed.
    Belief(BeliefError),
    /// Plan validation failed.
    Plan(PlanError),
    /// Commitment validation failed.
    Commitment(CommitmentError),
    /// Wake-condition validation failed.
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
    /// Reconstructs an aggregate from a complete contiguous event prefix.
    ///
    /// The first event must be `Opened` at sequence one. Every later event is
    /// applied through [`Self::apply`], so replay and live append share identical
    /// identity, lineage, lifecycle, and closure invariants.
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

    /// Applies one next event after validating all cross-record invariants.
    ///
    /// Application requires the next contiguous sequence and a new idempotency key.
    /// Child records must already exist when referenced, plans must cite recorded
    /// beliefs, and commitments must name real plan steps. Verification fails while
    /// any commitment is unresolved or any wake condition remains armed.
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
