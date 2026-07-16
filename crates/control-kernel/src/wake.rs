use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ConversationId, DecisionId, WakeConditionId};

const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WakeConditionKind {
    SourceRevisionChanged {
        source_urn: String,
        baseline_revision: String,
    },
    EventObserved {
        event_type: String,
        subject_urn: String,
    },
    DeadlineReached {
        not_before_unix_ms: u64,
    },
    ConversationAdvanced {
        conversation_id: ConversationId,
        after_sequence: u64,
    },
    DecisionRecorded {
        decision_id: DecisionId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum WakeSignal {
    SourceRevision {
        source_urn: String,
        revision: String,
    },
    Event {
        event_type: String,
        subject_urn: String,
    },
    Clock {
        observed_at_unix_ms: u64,
    },
    Conversation {
        conversation_id: ConversationId,
        sequence: u64,
    },
    Decision {
        decision_id: DecisionId,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeConditionState {
    Armed,
    Satisfied,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WakeCondition {
    pub wake_condition_id: WakeConditionId,
    pub kind: WakeConditionKind,
    pub state: WakeConditionState,
    pub armed_at_unix_ms: u64,
    pub satisfied_at_unix_ms: Option<u64>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeConditionError {
    InvalidCondition,
    AlreadyTerminal,
    SignalMismatch,
}

impl fmt::Display for WakeConditionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCondition => formatter.write_str("wake condition is invalid"),
            Self::AlreadyTerminal => formatter.write_str("wake condition is already terminal"),
            Self::SignalMismatch => formatter.write_str("wake signal does not satisfy condition"),
        }
    }
}

impl Error for WakeConditionError {}

impl WakeCondition {
    pub fn arm(
        wake_condition_id: WakeConditionId,
        kind: WakeConditionKind,
        armed_at_unix_ms: u64,
        reason: String,
    ) -> Result<Self, WakeConditionError> {
        if armed_at_unix_ms == 0 || !kind.is_valid() || validate_text(&reason).is_err() {
            return Err(WakeConditionError::InvalidCondition);
        }
        Ok(Self {
            wake_condition_id,
            kind,
            state: WakeConditionState::Armed,
            armed_at_unix_ms,
            satisfied_at_unix_ms: None,
            reason,
        })
    }

    pub fn satisfy(
        &self,
        signal: &WakeSignal,
        observed_at_unix_ms: u64,
    ) -> Result<Self, WakeConditionError> {
        if self.state != WakeConditionState::Armed {
            return Err(WakeConditionError::AlreadyTerminal);
        }
        if observed_at_unix_ms < self.armed_at_unix_ms || !self.kind.matches(signal) {
            return Err(WakeConditionError::SignalMismatch);
        }
        let mut next = self.clone();
        next.state = WakeConditionState::Satisfied;
        next.satisfied_at_unix_ms = Some(observed_at_unix_ms);
        Ok(next)
    }

    pub fn cancel(&self, reason: String) -> Result<Self, WakeConditionError> {
        if self.state != WakeConditionState::Armed {
            return Err(WakeConditionError::AlreadyTerminal);
        }
        validate_text(&reason).map_err(|_| WakeConditionError::InvalidCondition)?;
        let mut next = self.clone();
        next.state = WakeConditionState::Cancelled;
        next.reason = reason;
        Ok(next)
    }
}

impl WakeConditionKind {
    fn is_valid(&self) -> bool {
        match self {
            Self::SourceRevisionChanged {
                source_urn,
                baseline_revision,
            } => validate_text(source_urn).is_ok() && validate_text(baseline_revision).is_ok(),
            Self::EventObserved {
                event_type,
                subject_urn,
            } => validate_text(event_type).is_ok() && validate_text(subject_urn).is_ok(),
            Self::DeadlineReached { not_before_unix_ms } => *not_before_unix_ms > 0,
            Self::ConversationAdvanced { after_sequence, .. } => *after_sequence > 0,
            Self::DecisionRecorded { .. } => true,
        }
    }

    fn matches(&self, signal: &WakeSignal) -> bool {
        match (self, signal) {
            (
                Self::SourceRevisionChanged {
                    source_urn,
                    baseline_revision,
                },
                WakeSignal::SourceRevision {
                    source_urn: observed_source,
                    revision,
                },
            ) => source_urn == observed_source && baseline_revision != revision,
            (
                Self::EventObserved {
                    event_type,
                    subject_urn,
                },
                WakeSignal::Event {
                    event_type: observed_type,
                    subject_urn: observed_subject,
                },
            ) => event_type == observed_type && subject_urn == observed_subject,
            (
                Self::DeadlineReached { not_before_unix_ms },
                WakeSignal::Clock {
                    observed_at_unix_ms,
                },
            ) => observed_at_unix_ms >= not_before_unix_ms,
            (
                Self::ConversationAdvanced {
                    conversation_id,
                    after_sequence,
                },
                WakeSignal::Conversation {
                    conversation_id: observed_conversation,
                    sequence,
                },
            ) => conversation_id == observed_conversation && sequence > after_sequence,
            (
                Self::DecisionRecorded { decision_id },
                WakeSignal::Decision {
                    decision_id: observed_decision,
                },
            ) => decision_id == observed_decision,
            _ => false,
        }
    }
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

    fn arm(id: &str, kind: WakeConditionKind) -> WakeCondition {
        WakeCondition::arm(
            WakeConditionId::parse(id).unwrap(),
            kind,
            10,
            "wait for a durable signal".into(),
        )
        .unwrap()
    }

    #[test]
    fn source_wake_requires_a_different_revision() {
        let condition = WakeCondition::arm(
            WakeConditionId::parse("wake-1").unwrap(),
            WakeConditionKind::SourceRevisionChanged {
                source_urn: "urn:source:identity".into(),
                baseline_revision: "rev-1".into(),
            },
            10,
            "wait for authoritative access state".into(),
        )
        .unwrap();
        let unchanged = WakeSignal::SourceRevision {
            source_urn: "urn:source:identity".into(),
            revision: "rev-1".into(),
        };
        assert_eq!(
            condition.satisfy(&unchanged, 11),
            Err(WakeConditionError::SignalMismatch)
        );
        let changed = WakeSignal::SourceRevision {
            source_urn: "urn:source:identity".into(),
            revision: "rev-2".into(),
        };
        assert_eq!(
            condition.satisfy(&changed, 12).unwrap().state,
            WakeConditionState::Satisfied
        );
    }

    #[test]
    fn every_wake_kind_matches_only_its_bound_signal() {
        let event = arm(
            "wake-event",
            WakeConditionKind::EventObserved {
                event_type: "identity.offboarded".into(),
                subject_urn: "urn:identity:1".into(),
            },
        );
        assert_eq!(
            event
                .satisfy(
                    &WakeSignal::Event {
                        event_type: "identity.offboarded".into(),
                        subject_urn: "urn:identity:1".into(),
                    },
                    11,
                )
                .unwrap()
                .state,
            WakeConditionState::Satisfied
        );

        let deadline = arm(
            "wake-deadline",
            WakeConditionKind::DeadlineReached {
                not_before_unix_ms: 20,
            },
        );
        assert_eq!(
            deadline.satisfy(
                &WakeSignal::Clock {
                    observed_at_unix_ms: 19
                },
                19
            ),
            Err(WakeConditionError::SignalMismatch)
        );
        assert!(
            deadline
                .satisfy(
                    &WakeSignal::Clock {
                        observed_at_unix_ms: 20
                    },
                    20
                )
                .is_ok()
        );

        let conversation_id = ConversationId::parse("conversation-1").unwrap();
        let conversation = arm(
            "wake-conversation",
            WakeConditionKind::ConversationAdvanced {
                conversation_id: conversation_id.clone(),
                after_sequence: 4,
            },
        );
        assert!(
            conversation
                .satisfy(
                    &WakeSignal::Conversation {
                        conversation_id,
                        sequence: 5,
                    },
                    12,
                )
                .is_ok()
        );

        let decision_id = DecisionId::parse("decision-1").unwrap();
        let decision = arm(
            "wake-decision",
            WakeConditionKind::DecisionRecorded {
                decision_id: decision_id.clone(),
            },
        );
        assert!(
            decision
                .satisfy(&WakeSignal::Decision { decision_id }, 13)
                .is_ok()
        );
        assert_eq!(
            decision.satisfy(
                &WakeSignal::Clock {
                    observed_at_unix_ms: 100
                },
                13
            ),
            Err(WakeConditionError::SignalMismatch)
        );
    }

    #[test]
    fn wake_conditions_reject_invalid_or_terminal_changes() {
        assert_eq!(
            WakeCondition::arm(
                WakeConditionId::parse("wake-invalid").unwrap(),
                WakeConditionKind::DeadlineReached {
                    not_before_unix_ms: 0
                },
                10,
                "wait".into(),
            ),
            Err(WakeConditionError::InvalidCondition)
        );
        assert_eq!(
            WakeCondition::arm(
                WakeConditionId::parse("wake-invalid-time").unwrap(),
                WakeConditionKind::DecisionRecorded {
                    decision_id: DecisionId::parse("decision-1").unwrap(),
                },
                0,
                "wait".into(),
            ),
            Err(WakeConditionError::InvalidCondition)
        );
        assert_eq!(
            WakeCondition::arm(
                WakeConditionId::parse("wake-invalid-text").unwrap(),
                WakeConditionKind::SourceRevisionChanged {
                    source_urn: "".into(),
                    baseline_revision: "rev-1".into(),
                },
                10,
                "wait".into(),
            ),
            Err(WakeConditionError::InvalidCondition)
        );
        assert_eq!(
            WakeCondition::arm(
                WakeConditionId::parse("wake-invalid-event").unwrap(),
                WakeConditionKind::EventObserved {
                    event_type: "identity.offboarded".into(),
                    subject_urn: " urn:identity:1".into(),
                },
                10,
                "wait".into(),
            ),
            Err(WakeConditionError::InvalidCondition)
        );
        assert_eq!(
            WakeCondition::arm(
                WakeConditionId::parse("wake-invalid-conversation").unwrap(),
                WakeConditionKind::ConversationAdvanced {
                    conversation_id: ConversationId::parse("conversation-1").unwrap(),
                    after_sequence: 0,
                },
                10,
                "wait".into(),
            ),
            Err(WakeConditionError::InvalidCondition)
        );

        let condition = arm(
            "wake-cancel",
            WakeConditionKind::DecisionRecorded {
                decision_id: DecisionId::parse("decision-1").unwrap(),
            },
        );
        assert_eq!(
            condition.cancel("".into()),
            Err(WakeConditionError::InvalidCondition)
        );
        assert_eq!(
            condition.satisfy(
                &WakeSignal::Decision {
                    decision_id: DecisionId::parse("decision-1").unwrap(),
                },
                9,
            ),
            Err(WakeConditionError::SignalMismatch)
        );
        let cancelled = condition.cancel("mission retired".into()).unwrap();
        assert_eq!(cancelled.state, WakeConditionState::Cancelled);
        assert_eq!(
            cancelled.cancel("cancel again".into()),
            Err(WakeConditionError::AlreadyTerminal)
        );
        assert_eq!(
            cancelled.satisfy(
                &WakeSignal::Decision {
                    decision_id: DecisionId::parse("decision-1").unwrap(),
                },
                12,
            ),
            Err(WakeConditionError::AlreadyTerminal)
        );
    }
}
