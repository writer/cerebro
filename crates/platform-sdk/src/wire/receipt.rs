//! Bounded admission outcomes for external wire events.
//!
//! A receipt reports whether one stable event identity was appended, previously
//! accepted, or rejected. Structural validation does not authenticate the
//! receiver, prove persistence, or bind the observation time to a trusted clock.

use serde::{Deserialize, Serialize};

use crate::SdkError;

use super::validation::{validate_digest, validate_id};

/// Terminal admission classification for one delivery attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestOutcome {
    /// Event was newly admitted and has a durable event digest.
    Accepted,
    /// Exact event was already admitted and resolves to its existing digest.
    Duplicate,
    /// Event was not admitted and has no accepted event digest.
    Rejected,
}

/// Machine-readable explanation constrained by [`WireIngestOutcome`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestReason {
    /// New event passed admission.
    Accepted,
    /// Same event identity and content were admitted previously.
    EventAlreadyAccepted,
    /// Event identity was previously bound to different content.
    EventIdCollision,
    /// Envelope or payload schema is not in the closed catalog.
    UnsupportedSchema,
    /// Common envelope fields failed validation.
    InvalidEnvelope,
    /// Family-specific payload failed decoding or validation.
    InvalidPayload,
    /// Detached signature could not be verified by the trusted host.
    SignatureVerificationFailed,
    /// Payload violated an admission safety policy beyond shape validation.
    UnsafePayload,
    /// Producer sequence was missing, repeated, or out of order.
    SequenceGapOrReordering,
    /// Previous-event digest did not match the admitted producer chain.
    EventChainMismatch,
    /// Durable admission could not be completed.
    PersistenceUnavailable,
}

/// Strict receipt for one external-event admission decision.
///
/// Accepted and duplicate outcomes carry the canonical admitted event digest.
/// Rejections deliberately omit it so rejected bytes cannot be mistaken for a
/// durable event identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireIngestReceipt {
    /// Stable event identity supplied by the producer.
    pub event_id: String,
    /// Canonical digest of the admitted event, present only on success or duplicate.
    pub event_digest: Option<String>,
    /// Accepted, duplicate, or rejected classification.
    pub outcome: WireIngestOutcome,
    /// Reason permitted for the selected outcome.
    pub reason: WireIngestReason,
    /// Non-zero Unix-millisecond time assigned by the admission host.
    pub received_at_unix_ms: u64,
}

impl WireIngestReceipt {
    /// Validates receipt consistency without claiming persistence or signature authority.
    ///
    /// Event identity and optional digest receive syntax checks. The outcome
    /// matrix admits only `Accepted/Accepted/digest`,
    /// `Duplicate/EventAlreadyAccepted/digest`, or one of the declared rejection
    /// reasons with no digest.
    ///
    /// # Errors
    ///
    /// Returns identifier or digest validation errors, [`SdkError::OutOfRange`]
    /// for a zero receipt time, or [`SdkError::Invalid`] for an inconsistent
    /// outcome, reason, and digest-presence tuple.
    pub fn validate(&self) -> Result<(), SdkError> {
        validate_id(&self.event_id, "wire receipt event id")?;
        if self.received_at_unix_ms == 0 {
            return Err(SdkError::OutOfRange("wire receipt time"));
        }
        if let Some(digest) = self.event_digest.as_deref() {
            validate_digest(digest, "wire receipt event digest")?;
        }
        match (self.outcome, self.reason, self.event_digest.is_some()) {
            (WireIngestOutcome::Accepted, WireIngestReason::Accepted, true)
            | (WireIngestOutcome::Duplicate, WireIngestReason::EventAlreadyAccepted, true)
            | (
                WireIngestOutcome::Rejected,
                WireIngestReason::EventIdCollision
                | WireIngestReason::UnsupportedSchema
                | WireIngestReason::InvalidEnvelope
                | WireIngestReason::InvalidPayload
                | WireIngestReason::SignatureVerificationFailed
                | WireIngestReason::UnsafePayload
                | WireIngestReason::SequenceGapOrReordering
                | WireIngestReason::EventChainMismatch
                | WireIngestReason::PersistenceUnavailable,
                false,
            ) => Ok(()),
            _ => Err(SdkError::Invalid("wire receipt outcome")),
        }
    }
}
