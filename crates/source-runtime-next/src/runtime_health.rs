//! Portable source-runtime readiness classification.

/// Secret-free evidence used to classify one source-runtime observation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeHealthEvidence {
    /// `Some(true)` when enabled, `Some(false)` when disabled, and `None` when unknown.
    pub enabled: Option<bool>,
    /// Whether the runtime has a current failure category.
    pub failure_observed: bool,
    /// Whether the last-sync timestamp was present and valid.
    pub sync_observed: bool,
    /// Whether the valid last-sync timestamp exceeds its freshness bound.
    pub sync_stale: bool,
    /// Whether a collected continuation has not been durably cleared.
    pub cursor_pending: bool,
    /// Whether the latest collection was observed and completed.
    pub collection_complete: Option<bool>,
    /// Number of records rejected by the latest observed collection.
    pub rejected_records: u64,
}

/// Operational readiness derived from Rust-owned runtime evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeReadiness {
    /// The runtime is explicitly disabled.
    Disabled,
    /// Required runtime evidence is absent or invalid.
    Unknown,
    /// Collection failed, remained incomplete, or rejected records.
    Attention,
    /// The runtime is stale or has an uncommitted continuation.
    NeedsRefresh,
    /// Every required observed signal is current and successful.
    Healthy,
}

impl RuntimeReadiness {
    /// Stable wire value used by Rust API and agent-tool views.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
            Self::Attention => "attention",
            Self::NeedsRefresh => "needs_refresh",
            Self::Healthy => "healthy",
        }
    }
}

/// Classifies current runtime evidence without consulting credentials or host configuration.
pub const fn evaluate_runtime_readiness(evidence: RuntimeHealthEvidence) -> RuntimeReadiness {
    match evidence.enabled {
        Some(false) => RuntimeReadiness::Disabled,
        None => RuntimeReadiness::Unknown,
        Some(true) if evidence.failure_observed => RuntimeReadiness::Attention,
        Some(true) if matches!(evidence.collection_complete, Some(false)) => {
            RuntimeReadiness::Attention
        }
        Some(true) if evidence.rejected_records > 0 => RuntimeReadiness::Attention,
        Some(true) if !evidence.sync_observed => RuntimeReadiness::Unknown,
        Some(true) if evidence.collection_complete.is_none() => RuntimeReadiness::Unknown,
        Some(true) if evidence.sync_stale || evidence.cursor_pending => {
            RuntimeReadiness::NeedsRefresh
        }
        Some(true) => RuntimeReadiness::Healthy,
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeHealthEvidence, RuntimeReadiness, evaluate_runtime_readiness};

    #[test]
    fn readiness_requires_current_complete_runtime_evidence() {
        let healthy = RuntimeHealthEvidence {
            enabled: Some(true),
            sync_observed: true,
            collection_complete: Some(true),
            ..RuntimeHealthEvidence::default()
        };
        assert_eq!(
            evaluate_runtime_readiness(healthy),
            RuntimeReadiness::Healthy
        );
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                cursor_pending: true,
                ..healthy
            }),
            RuntimeReadiness::NeedsRefresh
        );
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                collection_complete: Some(false),
                ..healthy
            }),
            RuntimeReadiness::Attention
        );
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                rejected_records: 1,
                ..healthy
            }),
            RuntimeReadiness::Attention
        );
    }

    #[test]
    fn missing_or_disabled_evidence_never_becomes_healthy() {
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence::default()),
            RuntimeReadiness::Unknown
        );
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                enabled: Some(false),
                sync_observed: true,
                collection_complete: Some(true),
                ..RuntimeHealthEvidence::default()
            }),
            RuntimeReadiness::Disabled
        );
    }
}
