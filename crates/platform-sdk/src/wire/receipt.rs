use serde::{Deserialize, Serialize};

use crate::SdkError;

use super::validation::{validate_digest, validate_id};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestOutcome {
    Accepted,
    Duplicate,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestReason {
    Accepted,
    EventAlreadyAccepted,
    EventIdCollision,
    UnsupportedSchema,
    InvalidEnvelope,
    InvalidPayload,
    SignatureVerificationFailed,
    UnsafePayload,
    SequenceGapOrReordering,
    EventChainMismatch,
    PersistenceUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireIngestReceipt {
    pub event_id: String,
    pub event_digest: Option<String>,
    pub outcome: WireIngestOutcome,
    pub reason: WireIngestReason,
    pub received_at_unix_ms: u64,
}

impl WireIngestReceipt {
    /// Validates receipt consistency without claiming persistence or signature authority.
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
