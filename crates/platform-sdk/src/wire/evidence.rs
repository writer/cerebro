use serde::{Deserialize, Serialize};

/// Whether the producer observed its complete declared population.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    Truncated,
}

/// Whether the observation is current enough for the declared decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Fresh,
    Stale,
    Unknown,
}

/// Fail-closed evidence quality carried by every external producer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvidenceState {
    pub completeness: EvidenceCompleteness,
    pub freshness: EvidenceFreshness,
}

impl Default for WireEvidenceState {
    fn default() -> Self {
        Self {
            completeness: EvidenceCompleteness::Partial,
            freshness: EvidenceFreshness::Unknown,
        }
    }
}

impl WireEvidenceState {
    /// Returns true only for fresh evidence over a complete population.
    pub const fn supports_authoritative_decision(self) -> bool {
        matches!(self.completeness, EvidenceCompleteness::Complete)
            && matches!(self.freshness, EvidenceFreshness::Fresh)
    }
}
