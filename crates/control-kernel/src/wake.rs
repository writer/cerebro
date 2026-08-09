use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ConversationId, DecisionId, WakeConditionId};

const MAX_TEXT_BYTES: usize = 4_096;

/// A durable predicate that can make a waiting mission eligible for replanning.
///
/// Each variant names both the authority surface to observe and the exact
/// baseline that must change. The kernel stores the predicate; a host adapter
/// remains responsible for observing sources, clocks, conversations, and
/// decisions and for presenting the corresponding [`WakeSignal`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WakeConditionKind {
    /// Wake after one authoritative source reports a revision other than the
    /// revision recorded when the condition was armed.
    SourceRevisionChanged {
        /// Stable URN of the source whose revision is authoritative.
        source_urn: String,
        /// Exact revision already incorporated into the mission.
        baseline_revision: String,
    },
    /// Wake after a specific event type is observed for a specific subject.
    EventObserved {
        /// Canonical event type, such as `identity.offboarded`.
        event_type: String,
        /// Stable URN of the subject to which the event must apply.
        subject_urn: String,
    },
    /// Wake no earlier than an absolute Unix timestamp.
    DeadlineReached {
        /// Inclusive lower bound, in Unix epoch milliseconds.
        not_before_unix_ms: u64,
    },
    /// Wake after a durable conversation advances beyond a known sequence.
    ConversationAdvanced {
        /// Conversation whose ordered record is being observed.
        conversation_id: ConversationId,
        /// Last sequence already incorporated into the mission; a signal must
        /// carry a strictly greater sequence.
        after_sequence: u64,
    },
    /// Wake after the exact requested decision has been recorded.
    DecisionRecorded {
        /// Decision identity bound to the pending authorization question.
        decision_id: DecisionId,
    },
}

/// One observation offered to an armed [`WakeCondition`].
///
/// Signals are facts, not commands: presenting one cannot mutate a condition
/// unless its variant and bound identifiers satisfy the stored predicate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum WakeSignal {
    /// Current revision reported by an authoritative source.
    SourceRevision {
        /// Stable URN of the reporting source.
        source_urn: String,
        /// Revision observed at evaluation time.
        revision: String,
    },
    /// Event observed for a subject.
    Event {
        /// Canonical observed event type.
        event_type: String,
        /// Stable URN of the observed subject.
        subject_urn: String,
    },
    /// Trusted clock observation.
    Clock {
        /// Time observed by the host, in Unix epoch milliseconds.
        observed_at_unix_ms: u64,
    },
    /// Durable conversation sequence observation.
    Conversation {
        /// Conversation that advanced.
        conversation_id: ConversationId,
        /// Latest durably recorded sequence.
        sequence: u64,
    },
    /// Durable authorization-decision observation.
    Decision {
        /// Decision that was recorded.
        decision_id: DecisionId,
    },
}

/// Lifecycle state of a wake condition.
///
/// `Satisfied` and `Cancelled` are terminal. A terminal condition must never
/// be rearmed or reinterpreted in place; create a new condition identity for a
/// new wait.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeConditionState {
    /// The condition may accept one matching signal or be cancelled.
    Armed,
    /// A matching signal was observed after the condition was armed.
    Satisfied,
    /// The wait was explicitly retired without a matching signal.
    Cancelled,
}

/// Durable record of one bounded reason for resuming a waiting mission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WakeCondition {
    /// Stable identity used by mission events and supervisor directives.
    pub wake_condition_id: WakeConditionId,
    /// Predicate that a host observation must satisfy.
    pub kind: WakeConditionKind,
    /// Current lifecycle state.
    pub state: WakeConditionState,
    /// Trusted creation time, in Unix epoch milliseconds.
    pub armed_at_unix_ms: u64,
    /// Trusted matching-observation time. Present exactly when `state` is
    /// [`WakeConditionState::Satisfied`].
    pub satisfied_at_unix_ms: Option<u64>,
    /// Bounded operator-readable reason for arming or cancelling the wait.
    pub reason: String,
}

/// Rejection returned when a wake-condition transition would violate its
/// durable predicate or lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeConditionError {
    /// The condition contains a zero timestamp, empty or ambiguous text, an
    /// invalid predicate bound, or another malformed input.
    InvalidCondition,
    /// A caller attempted to satisfy or cancel a terminal condition.
    AlreadyTerminal,
    /// The signal does not match the stored predicate, or its observation time
    /// predates the condition.
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
    /// Creates an armed condition after validating all predicate bounds.
    ///
    /// `armed_at_unix_ms` must be non-zero. Text fields are trimmed, bounded,
    /// and free of control characters. Construction performs no observation;
    /// only [`Self::satisfy`] can move the condition to `Satisfied`.
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

    /// Returns a satisfied copy when `signal` matches this armed condition.
    ///
    /// The original value is unchanged. `observed_at_unix_ms` is the durable
    /// transition time and cannot precede `armed_at_unix_ms`. For deadline
    /// conditions the clock carried inside the signal must also meet the
    /// stored deadline.
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

    /// Returns a cancelled copy with a replacement operator-readable reason.
    ///
    /// Cancellation is available only while armed and deliberately leaves
    /// `satisfied_at_unix_ms` empty so cancellation cannot masquerade as
    /// evidence that the predicate became true.
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
    /// Validates bounds that are specific to each predicate variant.
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

    /// Applies the stored identity and monotonicity constraints to one signal.
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
