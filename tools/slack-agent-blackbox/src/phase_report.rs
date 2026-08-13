use std::{collections::BTreeMap, error::Error, fs, path::Path};

use cerebro_slack_agent_eval_wire::{ExecutionPhaseV2, PhaseOutcomeV2};
use serde::Serialize;

use crate::execution_v2::{
    EndpointPhaseTelemetryV2, SupervisorExecutionOutputV2, TrustedEndpointKindV2,
};

const PHASE_REPORT_V2: &str = "slack-agent-phase-report/v2";

#[derive(Debug, Eq, PartialEq, Serialize)]
struct PhaseReportV2 {
    schema_version: &'static str,
    receipt_count: usize,
    endpoint_exchanges: Vec<EndpointExchangeSummaryV2>,
    phases: Vec<PhaseSummaryV2>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct EndpointExchangeSummaryV2 {
    endpoint: &'static str,
    exchange_count: usize,
    end_to_end_ms: PercentilesV2,
    unaccounted_overhead_ms: PercentilesV2,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct PhaseSummaryV2 {
    endpoint: &'static str,
    phase: &'static str,
    sample_count: usize,
    duration_ms: PercentilesV2,
    budget_utilization_bps: PercentilesV2,
    model_call_count: usize,
    tool_call_count: usize,
    repair_count: usize,
    outcome_counts: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct PercentilesV2 {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

#[derive(Default)]
struct EndpointSamples {
    end_to_end_ms: Vec<u64>,
    unaccounted_overhead_ms: Vec<u64>,
}

#[derive(Default)]
struct PhaseSamples {
    duration_ms: Vec<u64>,
    budget_utilization_bps: Vec<u64>,
    model_call_count: usize,
    tool_call_count: usize,
    repair_count: usize,
    outcome_counts: BTreeMap<&'static str, usize>,
}

pub fn write_report(input_paths: &[String], output_path: &str) -> Result<(), Box<dyn Error>> {
    let outputs = input_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<SupervisorExecutionOutputV2>, _>>()?;
    let report = summarize(&outputs)?;
    if let Some(parent) = Path::new(output_path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn summarize(outputs: &[SupervisorExecutionOutputV2]) -> Result<PhaseReportV2, Box<dyn Error>> {
    if outputs.is_empty() {
        return Err("at least one V2 execution receipt is required".into());
    }
    let mut endpoints: BTreeMap<&'static str, EndpointSamples> = BTreeMap::new();
    let mut phases: BTreeMap<(&'static str, &'static str), PhaseSamples> = BTreeMap::new();

    for output in outputs {
        for endpoint_telemetry in &output.phase_telemetry {
            endpoint_telemetry.telemetry.validate_accounting()?;
            record_endpoint(&mut endpoints, endpoint_telemetry);
            for phase in &endpoint_telemetry.telemetry.phases {
                let samples = phases
                    .entry((
                        endpoint_name(endpoint_telemetry.endpoint),
                        phase_name(phase.phase),
                    ))
                    .or_default();
                samples.duration_ms.push(phase.duration_ms);
                samples
                    .budget_utilization_bps
                    .push(phase.duration_ms.saturating_mul(10_000) / phase.budget_ms);
                samples.model_call_count += phase.model_call_count;
                samples.tool_call_count += phase.tool_call_count;
                samples.repair_count += phase.repair_count;
                *samples
                    .outcome_counts
                    .entry(outcome_name(phase.outcome))
                    .or_default() += 1;
            }
        }
    }

    Ok(PhaseReportV2 {
        schema_version: PHASE_REPORT_V2,
        receipt_count: outputs.len(),
        endpoint_exchanges: endpoints
            .into_iter()
            .map(|(endpoint, samples)| EndpointExchangeSummaryV2 {
                endpoint,
                exchange_count: samples.end_to_end_ms.len(),
                end_to_end_ms: percentiles(samples.end_to_end_ms),
                unaccounted_overhead_ms: percentiles(samples.unaccounted_overhead_ms),
            })
            .collect(),
        phases: phases
            .into_iter()
            .map(|((endpoint, phase), samples)| PhaseSummaryV2 {
                endpoint,
                phase,
                sample_count: samples.duration_ms.len(),
                duration_ms: percentiles(samples.duration_ms),
                budget_utilization_bps: percentiles(samples.budget_utilization_bps),
                model_call_count: samples.model_call_count,
                tool_call_count: samples.tool_call_count,
                repair_count: samples.repair_count,
                outcome_counts: samples.outcome_counts,
            })
            .collect(),
    })
}

fn record_endpoint(
    endpoints: &mut BTreeMap<&'static str, EndpointSamples>,
    telemetry: &EndpointPhaseTelemetryV2,
) {
    let samples = endpoints
        .entry(endpoint_name(telemetry.endpoint))
        .or_default();
    samples
        .end_to_end_ms
        .push(telemetry.telemetry.end_to_end_ms);
    samples
        .unaccounted_overhead_ms
        .push(telemetry.telemetry.unaccounted_overhead_ms);
}

fn percentiles(mut samples: Vec<u64>) -> PercentilesV2 {
    samples.sort_unstable();
    PercentilesV2 {
        p50: nearest_rank(&samples, 50),
        p95: nearest_rank(&samples, 95),
        p99: nearest_rank(&samples, 99),
        max: samples.last().copied().unwrap_or_default(),
    }
}

fn nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let rank = samples.len().saturating_mul(percentile).div_ceil(100);
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

fn endpoint_name(endpoint: TrustedEndpointKindV2) -> &'static str {
    match endpoint {
        TrustedEndpointKindV2::Transport => "transport",
        TrustedEndpointKindV2::World => "world",
        TrustedEndpointKindV2::Lifecycle => "lifecycle",
        TrustedEndpointKindV2::Operator => "operator",
    }
}

fn phase_name(phase: ExecutionPhaseV2) -> &'static str {
    match phase {
        ExecutionPhaseV2::Ingress => "ingress",
        ExecutionPhaseV2::SessionLoad => "session_load",
        ExecutionPhaseV2::LeaseAcquire => "lease_acquire",
        ExecutionPhaseV2::Route => "route",
        ExecutionPhaseV2::Operate => "operate",
        ExecutionPhaseV2::Tool => "tool",
        ExecutionPhaseV2::Critique => "critique",
        ExecutionPhaseV2::Present => "present",
        ExecutionPhaseV2::Journal => "journal",
        ExecutionPhaseV2::Render => "render",
        ExecutionPhaseV2::Deliver => "deliver",
        ExecutionPhaseV2::RestartRecovery => "restart_recovery",
        ExecutionPhaseV2::Operator => "operator",
    }
}

fn outcome_name(outcome: PhaseOutcomeV2) -> &'static str {
    match outcome {
        PhaseOutcomeV2::Completed => "completed",
        PhaseOutcomeV2::TimedOut => "timed_out",
        PhaseOutcomeV2::Failed => "failed",
        PhaseOutcomeV2::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use cerebro_slack_agent_eval_wire::{ExchangePhaseTelemetryV2, PhaseTimingReceiptV2};

    use super::*;

    #[test]
    fn aggregates_phase_tail_latency_and_budget_utilization() {
        let telemetry = vec![
            endpoint_telemetry(1, 10, 7, 3),
            endpoint_telemetry(2, 20, 15, 5),
            endpoint_telemetry(3, 30, 27, 3),
        ];
        let mut endpoints = BTreeMap::new();
        let mut phases: BTreeMap<(&'static str, &'static str), PhaseSamples> = BTreeMap::new();
        for item in &telemetry {
            item.telemetry
                .validate_accounting()
                .expect("valid accounting");
            record_endpoint(&mut endpoints, item);
            for phase in &item.telemetry.phases {
                let samples = phases.entry(("transport", "route")).or_default();
                samples.duration_ms.push(phase.duration_ms);
                samples
                    .budget_utilization_bps
                    .push(phase.duration_ms * 10_000 / phase.budget_ms);
            }
        }

        assert_eq!(
            percentiles(endpoints.remove("transport").unwrap().end_to_end_ms),
            PercentilesV2 {
                p50: 20,
                p95: 30,
                p99: 30,
                max: 30
            }
        );
        let phase = phases.remove(&("transport", "route")).unwrap();
        assert_eq!(
            percentiles(phase.duration_ms),
            PercentilesV2 {
                p50: 15,
                p95: 27,
                p99: 27,
                max: 27
            }
        );
        assert_eq!(
            percentiles(phase.budget_utilization_bps),
            PercentilesV2 {
                p50: 5_000,
                p95: 9_000,
                p99: 9_000,
                max: 9_000
            }
        );
    }

    #[test]
    fn names_every_endpoint_phase_and_outcome_and_handles_empty_samples() {
        assert_eq!(
            percentiles(Vec::new()),
            PercentilesV2 {
                p50: 0,
                p95: 0,
                p99: 0,
                max: 0,
            }
        );
        assert_eq!(
            [
                TrustedEndpointKindV2::Transport,
                TrustedEndpointKindV2::World,
                TrustedEndpointKindV2::Lifecycle,
                TrustedEndpointKindV2::Operator,
            ]
            .map(endpoint_name),
            ["transport", "world", "lifecycle", "operator"]
        );
        assert_eq!(
            [
                ExecutionPhaseV2::Ingress,
                ExecutionPhaseV2::SessionLoad,
                ExecutionPhaseV2::LeaseAcquire,
                ExecutionPhaseV2::Route,
                ExecutionPhaseV2::Operate,
                ExecutionPhaseV2::Tool,
                ExecutionPhaseV2::Critique,
                ExecutionPhaseV2::Present,
                ExecutionPhaseV2::Journal,
                ExecutionPhaseV2::Render,
                ExecutionPhaseV2::Deliver,
                ExecutionPhaseV2::RestartRecovery,
                ExecutionPhaseV2::Operator,
            ]
            .map(phase_name),
            [
                "ingress",
                "session_load",
                "lease_acquire",
                "route",
                "operate",
                "tool",
                "critique",
                "present",
                "journal",
                "render",
                "deliver",
                "restart_recovery",
                "operator",
            ]
        );
        assert_eq!(
            [
                PhaseOutcomeV2::Completed,
                PhaseOutcomeV2::TimedOut,
                PhaseOutcomeV2::Failed,
                PhaseOutcomeV2::Cancelled,
            ]
            .map(outcome_name),
            ["completed", "timed_out", "failed", "cancelled"]
        );
    }

    fn endpoint_telemetry(
        sequence: usize,
        end_to_end_ms: u64,
        duration_ms: u64,
        overhead_ms: u64,
    ) -> EndpointPhaseTelemetryV2 {
        EndpointPhaseTelemetryV2 {
            endpoint: TrustedEndpointKindV2::Transport,
            telemetry: ExchangePhaseTelemetryV2 {
                exchange_sequence: sequence,
                end_to_end_ms,
                accounted_phase_ms: duration_ms,
                unaccounted_overhead_ms: overhead_ms,
                phases: vec![PhaseTimingReceiptV2 {
                    exchange_sequence: sequence,
                    phase: ExecutionPhaseV2::Route,
                    attempt: 1,
                    started_at: "2026-08-12T00:00:00Z".into(),
                    completed_at: "2026-08-12T00:00:01Z".into(),
                    duration_ms,
                    budget_ms: 30,
                    input_digest: "sha256:input".into(),
                    output_digest: Some("sha256:output".into()),
                    outcome: PhaseOutcomeV2::Completed,
                    model_call_count: 0,
                    tool_call_count: 0,
                    repair_count: 0,
                }],
            },
        }
    }
}
