//! Portable source-runtime readiness classification.

/// Secret-free operational signals for one source runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHealthEvidence<'a> {
    /// Enabled, disabled, or unknown lifecycle state.
    pub enabled_state: &'a str,
    /// Healthy, stale, failing, or unknown source-sync state.
    pub source_status: &'a str,
    /// Current, behind, running, failed, not_observed, or unknown graph state.
    pub graph_state: &'a str,
    /// Whether a collected continuation has not been durably cleared.
    pub cursor_pending: bool,
    /// Whether a cadence or staleness threshold is configured.
    pub schedule_context_configured: bool,
    /// Passing, failure, not_configured, or unknown contract-probe state.
    pub contract_probe_state: &'a str,
    /// Current, running, failed, not_observed, or unknown finding-evaluation state.
    pub finding_evaluation_state: &'a str,
}

/// Stable readiness values returned by Rust runtime APIs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimeReadiness {
    /// A required source, graph, contract, or finding stage failed.
    Bad,
    /// The runtime or graph needs a forward refresh.
    NeedsRefresh,
    /// Required evidence is incomplete, disabled, running, or unknown.
    Poor,
    /// Every required operational signal is current.
    Healthy,
}

impl RuntimeReadiness {
    /// Stable wire value used by Rust API and agent-tool views.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bad => "bad",
            Self::NeedsRefresh => "needs_refresh",
            Self::Poor => "poor",
            Self::Healthy => "healthy",
        }
    }
}

/// Stable operator actions returned with readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeNextAction {
    /// Repair the failing connection stage.
    FixConnection,
    /// Inspect a failed finding evaluation.
    InspectFindingEvaluation,
    /// Resume or refresh source collection.
    RunSync,
    /// Run or backfill graph projection.
    RunGraphIngest,
    /// Inspect incomplete runtime evidence.
    InspectConnection,
    /// Continue monitoring a healthy connection.
    Monitor,
}

impl RuntimeNextAction {
    /// Stable wire value used by Rust API and agent-tool views.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixConnection => "fix_connection",
            Self::InspectFindingEvaluation => "inspect_finding_evaluation",
            Self::RunSync => "run_sync",
            Self::RunGraphIngest => "run_graph_ingest",
            Self::InspectConnection => "inspect_connection",
            Self::Monitor => "monitor",
        }
    }
}

/// One authoritative readiness decision and its next operator action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeReadinessDecision {
    /// Classified operational readiness.
    pub readiness: RuntimeReadiness,
    /// First bounded action that addresses the decisive signal.
    pub next_action: RuntimeNextAction,
}

/// Classifies all portable runtime stages without credentials or host topology.
pub fn evaluate_runtime_readiness(evidence: RuntimeHealthEvidence<'_>) -> RuntimeReadinessDecision {
    let enabled = normalized(evidence.enabled_state);
    let source = normalized(evidence.source_status);
    let graph = normalized(evidence.graph_state);
    let probe = normalized(evidence.contract_probe_state);
    let finding = normalized(evidence.finding_evaluation_state);

    let active = enabled == "enabled";
    if (active && (failed(&source) || failed(&graph))) || failed(&finding) || probe == "failure" {
        return decision(
            RuntimeReadiness::Bad,
            if failed(&finding) {
                RuntimeNextAction::InspectFindingEvaluation
            } else {
                RuntimeNextAction::FixConnection
            },
        );
    }
    if active && matches!(graph.as_str(), "behind" | "not_observed" | "missing") {
        return decision(
            RuntimeReadiness::NeedsRefresh,
            RuntimeNextAction::RunGraphIngest,
        );
    }
    if evidence.cursor_pending
        || (active && source == "stale")
        || !evidence.schedule_context_configured
    {
        return decision(RuntimeReadiness::NeedsRefresh, RuntimeNextAction::RunSync);
    }
    if active && source == "healthy" && graph == "current" {
        return decision(RuntimeReadiness::Healthy, RuntimeNextAction::Monitor);
    }
    decision(RuntimeReadiness::Poor, RuntimeNextAction::InspectConnection)
}

const fn decision(
    readiness: RuntimeReadiness,
    next_action: RuntimeNextAction,
) -> RuntimeReadinessDecision {
    RuntimeReadinessDecision {
        readiness,
        next_action,
    }
}

fn normalized(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn failed(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("fail") || value.contains("error") || value.contains("cancel")
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeHealthEvidence, RuntimeNextAction, RuntimeReadiness, evaluate_runtime_readiness,
    };

    fn healthy() -> RuntimeHealthEvidence<'static> {
        RuntimeHealthEvidence {
            enabled_state: "enabled",
            source_status: "healthy",
            graph_state: "current",
            cursor_pending: false,
            schedule_context_configured: true,
            contract_probe_state: "passing",
            finding_evaluation_state: "current",
        }
    }

    #[test]
    fn original_three_record_rollup_has_one_healthy_and_two_attention() {
        let records = [
            healthy(),
            RuntimeHealthEvidence {
                cursor_pending: true,
                ..healthy()
            },
            RuntimeHealthEvidence {
                finding_evaluation_state: "failed",
                ..healthy()
            },
        ];
        let decisions = records.map(evaluate_runtime_readiness);
        assert_eq!(decisions[0].readiness, RuntimeReadiness::Healthy);
        assert_eq!(decisions[1].readiness, RuntimeReadiness::NeedsRefresh);
        assert_eq!(decisions[1].next_action, RuntimeNextAction::RunSync);
        assert_eq!(decisions[2].readiness, RuntimeReadiness::Bad);
        assert_eq!(
            decisions[2].next_action,
            RuntimeNextAction::InspectFindingEvaluation
        );
    }

    #[test]
    fn graph_schedule_and_probe_states_are_authoritative() {
        for (evidence, readiness, action) in [
            (
                RuntimeHealthEvidence {
                    graph_state: "failed",
                    ..healthy()
                },
                RuntimeReadiness::Bad,
                RuntimeNextAction::FixConnection,
            ),
            (
                RuntimeHealthEvidence {
                    graph_state: "behind",
                    ..healthy()
                },
                RuntimeReadiness::NeedsRefresh,
                RuntimeNextAction::RunGraphIngest,
            ),
            (
                RuntimeHealthEvidence {
                    schedule_context_configured: false,
                    ..healthy()
                },
                RuntimeReadiness::NeedsRefresh,
                RuntimeNextAction::RunSync,
            ),
            (
                RuntimeHealthEvidence {
                    contract_probe_state: "failure",
                    ..healthy()
                },
                RuntimeReadiness::Bad,
                RuntimeNextAction::FixConnection,
            ),
            (
                RuntimeHealthEvidence {
                    graph_state: "running",
                    ..healthy()
                },
                RuntimeReadiness::Poor,
                RuntimeNextAction::InspectConnection,
            ),
        ] {
            let decision = evaluate_runtime_readiness(evidence);
            assert_eq!(decision.readiness, readiness);
            assert_eq!(decision.next_action, action);
        }
    }

    #[test]
    fn wire_inputs_are_case_insensitive_and_unknown_enablement_fails_closed() {
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                enabled_state: " ENABLED ",
                source_status: "HEALTHY",
                graph_state: "CURRENT",
                contract_probe_state: "PASSING",
                finding_evaluation_state: "CURRENT",
                ..healthy()
            }),
            super::RuntimeReadinessDecision {
                readiness: RuntimeReadiness::Healthy,
                next_action: RuntimeNextAction::Monitor,
            }
        );
        assert_eq!(
            evaluate_runtime_readiness(RuntimeHealthEvidence {
                enabled_state: "unknown",
                ..healthy()
            })
            .readiness,
            RuntimeReadiness::Poor
        );
    }
}
