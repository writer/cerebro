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
}
