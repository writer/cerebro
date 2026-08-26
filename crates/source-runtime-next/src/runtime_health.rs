//! Portable source-runtime readiness classification.

use std::collections::BTreeMap;

use serde::Serialize;

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

/// Secret-free inputs for the Go-parity runtime freshness derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFreshnessEvidence<'a> {
    /// Enabled, disabled, or unknown lifecycle state.
    pub enabled_state: &'a str,
    /// Healthy, stale, failing, or unknown source-sync status.
    pub source_status: &'a str,
    /// Last recorded source-sync failure category; empty when none.
    pub last_failure_category: &'a str,
    /// Current, behind, running, failed, or not_observed graph-ingest state.
    pub graph_ingest_state: &'a str,
    /// Current, running, failed, or not_observed finding-evaluation state.
    pub finding_evaluation_state: &'a str,
    /// Whether a cadence or staleness threshold is configured.
    pub schedule_context_configured: bool,
}

/// Full freshness classification for one source runtime, mirroring the Go
/// `sourcehealth.Evaluate` derivation field for field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFreshnessState {
    /// Active or disabled runtime lifecycle.
    pub lifecycle_state: &'static str,
    /// Configured or unknown schedule context.
    pub schedule_state: &'static str,
    /// Decisive freshness classification for the runtime.
    pub freshness_state: &'static str,
    /// Current, stale, failed, or unknown source-sync state.
    pub source_sync_state: &'static str,
    /// Normalized graph-ingest state echoed with the decision.
    pub graph_ingest_state: String,
    /// Normalized finding-evaluation state echoed with the decision.
    pub finding_evaluation_state: String,
    /// Failure classification; empty when the runtime is healthy.
    pub failure_class: String,
    /// Bounded failure explanation; empty when the runtime is healthy.
    pub failure_reason: &'static str,
    /// Whether a graph backfill is indicated.
    pub backfill_eligible: bool,
    /// Why the runtime is or is not backfill-eligible.
    pub backfill_eligibility_reason: &'static str,
    /// First bounded operator action for the decisive signal.
    pub next_action: &'static str,
    /// Recommended remediation workflow name; empty when none applies.
    pub recommended_workflow: &'static str,
}

/// Classifies runtime freshness exactly as the Go `sourcehealth.Evaluate`
/// derivation behind `GET /platform/runtime-freshness` does.
pub fn evaluate_runtime_freshness(evidence: RuntimeFreshnessEvidence<'_>) -> RuntimeFreshnessState {
    let lifecycle_state = if normalized(evidence.enabled_state) == "disabled" {
        "disabled"
    } else {
        "active"
    };
    let schedule_state = if evidence.schedule_context_configured {
        "configured"
    } else {
        "unknown"
    };
    let failure_category = evidence.last_failure_category.trim();
    let source_sync_state = source_sync_state(failure_category, evidence.source_status);
    let graph_ingest_state = normalized(evidence.graph_ingest_state);
    let finding_evaluation_state = normalized(evidence.finding_evaluation_state);
    let (freshness_state, failure_class, failure_reason, next_action) = freshness_decision(
        failure_category,
        lifecycle_state,
        source_sync_state,
        &graph_ingest_state,
    );
    let (backfill_eligible, backfill_eligibility_reason) =
        backfill_eligibility(lifecycle_state, source_sync_state, &graph_ingest_state);
    let recommended_workflow = if backfill_eligible {
        "source-runtime-backfill"
    } else {
        ""
    };
    RuntimeFreshnessState {
        lifecycle_state,
        schedule_state,
        freshness_state,
        source_sync_state,
        graph_ingest_state,
        finding_evaluation_state,
        failure_class,
        failure_reason,
        backfill_eligible,
        backfill_eligibility_reason,
        next_action,
        recommended_workflow,
    }
}

fn source_sync_state(failure_category: &str, source_status: &str) -> &'static str {
    if !failure_category.is_empty() {
        return "failed";
    }
    match normalized(source_status).as_str() {
        "failing" => "failed",
        "stale" => "stale",
        "healthy" => "current",
        _ => "unknown",
    }
}

fn freshness_decision(
    failure_category: &str,
    lifecycle_state: &str,
    source_sync_state: &str,
    graph_ingest_state: &str,
) -> (&'static str, String, &'static str, &'static str) {
    if lifecycle_state != "active" {
        return (
            "disabled",
            "disabled".to_owned(),
            "runtime is disabled",
            "review_runtime_enablement",
        );
    }
    if source_sync_state == "failed" {
        let failure_class = if failure_category.is_empty() {
            "source_sync_failed".to_owned()
        } else {
            failure_category.to_owned()
        };
        return (
            "source_failed",
            failure_class,
            "source sync is failing",
            "fix_source_sync",
        );
    }
    match graph_ingest_state {
        "failed" => {
            return (
                "graph_failed",
                "graph_ingest_failed".to_owned(),
                "latest graph ingest failed",
                "inspect_graph_ingest",
            );
        }
        "not_observed" => {
            return (
                "graph_missing",
                "graph_ingest_missing".to_owned(),
                "no graph ingest run has been observed",
                "plan_backfill",
            );
        }
        "behind" => {
            return (
                "graph_behind",
                "graph_ingest_behind".to_owned(),
                "graph ingest is older than the configured freshness window",
                "plan_backfill",
            );
        }
        _ => {}
    }
    if source_sync_state == "stale" {
        return (
            "source_stale",
            "source_sync_stale".to_owned(),
            "source runtime is older than the configured freshness window",
            "run_source_sync",
        );
    }
    if source_sync_state == "current" && matches!(graph_ingest_state, "current" | "running") {
        return ("healthy", String::new(), "", "monitor");
    }
    (
        "unknown",
        "insufficient_signal".to_owned(),
        "source or graph freshness signal is unavailable",
        "inspect_runtime",
    )
}

fn backfill_eligibility(
    lifecycle_state: &str,
    source_sync_state: &str,
    graph_ingest_state: &str,
) -> (bool, &'static str) {
    if lifecycle_state != "active" {
        return (false, "runtime is disabled");
    }
    if source_sync_state == "failed" {
        return (false, "source sync must succeed before graph backfill");
    }
    if matches!(graph_ingest_state, "failed" | "not_observed" | "behind") {
        (true, "graph ingest is missing, failed, or behind")
    } else {
        (false, "graph ingest backfill is not indicated")
    }
}

/// Per-runtime freshness digest used for source-level rollups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFreshnessDigest<'a> {
    /// Source whose runtimes are aggregated; empty maps to `unknown`.
    pub source_id: &'a str,
    /// Decisive freshness classification for the runtime.
    pub freshness_state: &'a str,
    /// Whether a graph backfill is indicated for the runtime.
    pub backfill_eligible: bool,
}

/// One aggregated source-level freshness rollup mirroring the Go summaries.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RuntimeFreshnessRollup {
    /// Source whose runtimes are aggregated.
    pub source_id: String,
    /// Total runtimes observed for the source.
    pub total: usize,
    /// Runtimes whose freshness state is healthy.
    pub healthy: usize,
    /// Runtimes in any non-healthy freshness state.
    pub needs_attention: usize,
    /// Runtimes whose source sync is failing.
    pub source_failed: usize,
    /// Runtimes whose source sync is stale.
    pub source_stale: usize,
    /// Runtimes with no observed graph ingest run.
    pub graph_missing: usize,
    /// Runtimes whose latest graph ingest failed.
    pub graph_failed: usize,
    /// Runtimes whose graph ingest is behind the freshness window.
    pub graph_behind: usize,
    /// Runtimes eligible for a graph backfill.
    pub backfill_eligible: usize,
    /// Runtimes quarantined or disabled.
    pub quarantined_or_disabled: usize,
}

/// Aggregates per-runtime freshness digests into Go-parity source summaries,
/// ordered by attention need, then total, then source identifier.
pub fn summarize_runtime_freshness(
    records: &[RuntimeFreshnessDigest<'_>],
) -> Vec<RuntimeFreshnessRollup> {
    let mut by_source = BTreeMap::<&str, RuntimeFreshnessRollup>::new();
    for record in records {
        let source_id = if record.source_id.is_empty() {
            "unknown"
        } else {
            record.source_id
        };
        let summary = by_source
            .entry(source_id)
            .or_insert_with(|| RuntimeFreshnessRollup {
                source_id: source_id.to_owned(),
                ..RuntimeFreshnessRollup::default()
            });
        summary.total += 1;
        if record.freshness_state == "healthy" {
            summary.healthy += 1;
        } else {
            summary.needs_attention += 1;
        }
        match record.freshness_state {
            "source_failed" => summary.source_failed += 1,
            "source_stale" => summary.source_stale += 1,
            "graph_missing" => summary.graph_missing += 1,
            "graph_failed" => summary.graph_failed += 1,
            "graph_behind" => summary.graph_behind += 1,
            "disabled" => summary.quarantined_or_disabled += 1,
            _ => {}
        }
        summary.backfill_eligible += usize::from(record.backfill_eligible);
    }
    let mut summaries: Vec<_> = by_source.into_values().collect();
    summaries.sort_by(|left, right| {
        right
            .needs_attention
            .cmp(&left.needs_attention)
            .then(right.total.cmp(&left.total))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    summaries
}

/// Rolls individual freshness states into the Go-parity overall status:
/// `healthy` only when every runtime is healthy, otherwise `degraded`.
pub fn runtime_freshness_status<'a>(states: impl IntoIterator<Item = &'a str>) -> &'static str {
    if states.into_iter().all(|state| state == "healthy") {
        "healthy"
    } else {
        "degraded"
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
        RuntimeFreshnessDigest, RuntimeFreshnessEvidence, RuntimeHealthEvidence, RuntimeNextAction,
        RuntimeReadiness, evaluate_runtime_freshness, evaluate_runtime_readiness,
        runtime_freshness_status, summarize_runtime_freshness,
    };

    fn fresh() -> RuntimeFreshnessEvidence<'static> {
        RuntimeFreshnessEvidence {
            enabled_state: "enabled",
            source_status: "healthy",
            last_failure_category: "",
            graph_ingest_state: "current",
            finding_evaluation_state: "current",
            schedule_context_configured: true,
        }
    }

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

    #[test]
    fn healthy_runtime_freshness_matches_go_evaluate() {
        let state = evaluate_runtime_freshness(fresh());
        assert_eq!(state.lifecycle_state, "active");
        assert_eq!(state.schedule_state, "configured");
        assert_eq!(state.freshness_state, "healthy");
        assert_eq!(state.source_sync_state, "current");
        assert_eq!(state.graph_ingest_state, "current");
        assert_eq!(state.finding_evaluation_state, "current");
        assert_eq!(state.failure_class, "");
        assert_eq!(state.failure_reason, "");
        assert!(!state.backfill_eligible);
        assert_eq!(
            state.backfill_eligibility_reason,
            "graph ingest backfill is not indicated"
        );
        assert_eq!(state.next_action, "monitor");
        assert_eq!(state.recommended_workflow, "");
    }

    #[test]
    fn running_graph_with_current_sync_stays_healthy() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            graph_ingest_state: "running",
            ..fresh()
        });
        assert_eq!(state.freshness_state, "healthy");
        assert_eq!(state.next_action, "monitor");
        assert!(!state.backfill_eligible);
    }

    #[test]
    fn disabled_runtime_is_quarantined_and_never_backfill_eligible() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            enabled_state: " DISABLED ",
            graph_ingest_state: "not_observed",
            ..fresh()
        });
        assert_eq!(state.lifecycle_state, "disabled");
        assert_eq!(state.freshness_state, "disabled");
        assert_eq!(state.failure_class, "disabled");
        assert_eq!(state.failure_reason, "runtime is disabled");
        assert_eq!(state.next_action, "review_runtime_enablement");
        assert!(!state.backfill_eligible);
        assert_eq!(state.backfill_eligibility_reason, "runtime is disabled");
        assert_eq!(state.recommended_workflow, "");
    }

    #[test]
    fn failure_category_dominates_and_names_the_failure_class() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            source_status: "healthy",
            last_failure_category: " rate_limited ",
            graph_ingest_state: "failed",
            ..fresh()
        });
        assert_eq!(state.source_sync_state, "failed");
        assert_eq!(state.freshness_state, "source_failed");
        assert_eq!(state.failure_class, "rate_limited");
        assert_eq!(state.failure_reason, "source sync is failing");
        assert_eq!(state.next_action, "fix_source_sync");
        assert!(!state.backfill_eligible);
        assert_eq!(
            state.backfill_eligibility_reason,
            "source sync must succeed before graph backfill"
        );
    }

    #[test]
    fn failing_status_without_category_uses_default_failure_class() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            source_status: "FAILING",
            ..fresh()
        });
        assert_eq!(state.source_sync_state, "failed");
        assert_eq!(state.freshness_state, "source_failed");
        assert_eq!(state.failure_class, "source_sync_failed");
    }

    #[test]
    fn graph_states_map_to_backfill_eligible_freshness() {
        for (graph_state, freshness, failure_class, next_action) in [
            (
                "failed",
                "graph_failed",
                "graph_ingest_failed",
                "inspect_graph_ingest",
            ),
            (
                "not_observed",
                "graph_missing",
                "graph_ingest_missing",
                "plan_backfill",
            ),
            (
                " BEHIND ",
                "graph_behind",
                "graph_ingest_behind",
                "plan_backfill",
            ),
        ] {
            let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
                graph_ingest_state: graph_state,
                ..fresh()
            });
            assert_eq!(state.freshness_state, freshness);
            assert_eq!(state.failure_class, failure_class);
            assert_eq!(state.next_action, next_action);
            assert!(state.backfill_eligible);
            assert_eq!(
                state.backfill_eligibility_reason,
                "graph ingest is missing, failed, or behind"
            );
            assert_eq!(state.recommended_workflow, "source-runtime-backfill");
        }
    }

    #[test]
    fn stale_source_with_current_graph_is_source_stale() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            source_status: "stale",
            ..fresh()
        });
        assert_eq!(state.source_sync_state, "stale");
        assert_eq!(state.freshness_state, "source_stale");
        assert_eq!(state.failure_class, "source_sync_stale");
        assert_eq!(state.next_action, "run_source_sync");
        assert!(!state.backfill_eligible);
    }

    #[test]
    fn unknown_signals_and_missing_schedule_fail_open_to_unknown() {
        let state = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
            source_status: "mystery",
            schedule_context_configured: false,
            ..fresh()
        });
        assert_eq!(state.schedule_state, "unknown");
        assert_eq!(state.source_sync_state, "unknown");
        assert_eq!(state.freshness_state, "unknown");
        assert_eq!(state.failure_class, "insufficient_signal");
        assert_eq!(
            state.failure_reason,
            "source or graph freshness signal is unavailable"
        );
        assert_eq!(state.next_action, "inspect_runtime");
    }

    #[test]
    fn summaries_bucket_states_and_sort_by_attention_total_then_source() {
        let digests = [
            RuntimeFreshnessDigest {
                source_id: "github",
                freshness_state: "healthy",
                backfill_eligible: false,
            },
            RuntimeFreshnessDigest {
                source_id: "github",
                freshness_state: "graph_behind",
                backfill_eligible: true,
            },
            RuntimeFreshnessDigest {
                source_id: "okta",
                freshness_state: "source_failed",
                backfill_eligible: false,
            },
            RuntimeFreshnessDigest {
                source_id: "okta",
                freshness_state: "disabled",
                backfill_eligible: false,
            },
            RuntimeFreshnessDigest {
                source_id: "",
                freshness_state: "graph_missing",
                backfill_eligible: true,
            },
        ];
        let summaries = summarize_runtime_freshness(&digests);
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0].source_id, "okta");
        assert_eq!(summaries[0].total, 2);
        assert_eq!(summaries[0].needs_attention, 2);
        assert_eq!(summaries[0].source_failed, 1);
        assert_eq!(summaries[0].quarantined_or_disabled, 1);
        assert_eq!(summaries[1].source_id, "github");
        assert_eq!(summaries[1].healthy, 1);
        assert_eq!(summaries[1].needs_attention, 1);
        assert_eq!(summaries[1].graph_behind, 1);
        assert_eq!(summaries[1].backfill_eligible, 1);
        assert_eq!(summaries[2].source_id, "unknown");
        assert_eq!(summaries[2].graph_missing, 1);
        assert_eq!(summaries[2].backfill_eligible, 1);
    }

    #[test]
    fn stale_and_failed_graph_states_are_counted_in_summaries() {
        let digests = [
            RuntimeFreshnessDigest {
                source_id: "pagerduty",
                freshness_state: "source_stale",
                backfill_eligible: false,
            },
            RuntimeFreshnessDigest {
                source_id: "pagerduty",
                freshness_state: "graph_failed",
                backfill_eligible: true,
            },
        ];
        let summaries = summarize_runtime_freshness(&digests);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].source_stale, 1);
        assert_eq!(summaries[0].graph_failed, 1);
        assert_eq!(summaries[0].healthy, 0);
        assert_eq!(summaries[0].needs_attention, 2);
    }

    #[test]
    fn overall_status_degrades_on_any_unhealthy_runtime() {
        assert_eq!(runtime_freshness_status([]), "healthy");
        assert_eq!(runtime_freshness_status(["healthy", "healthy"]), "healthy");
        assert_eq!(
            runtime_freshness_status(["healthy", "graph_behind"]),
            "degraded"
        );
    }
}
