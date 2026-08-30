//! Fail-closed quality labels attached to every external event.
//!
//! These labels are producer claims carried into payload policy checks. They do
//! not prove collection scope or observation time; the admission host must bind
//! them to authenticated producer behavior and source-specific evidence.

use serde::{Deserialize, Serialize};

/// Whether the producer observed its complete declared population.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    /// Producer observed the complete population declared by its operation.
    Complete,
    /// Producer observed only part of the declared population.
    Partial,
    /// A bound stopped collection before the declared population was exhausted.
    Truncated,
}

/// Whether the observation is current enough for the declared decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    /// Evidence is within the decision's declared freshness window.
    Fresh,
    /// Evidence is known to be outside that freshness window.
    Stale,
    /// Freshness could not be established.
    Unknown,
}

/// Fail-closed evidence quality carried by every external producer.
///
/// Unknown fields are rejected. Missing envelope evidence defaults to
/// `Partial` and `Unknown`, ensuring legacy or incomplete producers do not gain
/// authoritative-decision status by omission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvidenceState {
    /// Producer claim about population coverage.
    pub completeness: EvidenceCompleteness,
    /// Producer claim about decision-time freshness.
    pub freshness: EvidenceFreshness,
}

impl Default for WireEvidenceState {
    /// Returns the conservative state used when an envelope omits evidence.
    fn default() -> Self {
        Self {
            completeness: EvidenceCompleteness::Partial,
            freshness: EvidenceFreshness::Unknown,
        }
    }
}

impl WireEvidenceState {
    /// Returns true only for fresh evidence over a complete population.
    ///
    /// This predicate does not assess producer authority, conflicts, identity
    /// confidence, or authenticity; callers must apply those separate gates.
    pub const fn supports_authoritative_decision(self) -> bool {
        matches!(self.completeness, EvidenceCompleteness::Complete)
            && matches!(self.freshness, EvidenceFreshness::Fresh)
    }
}
