use std::{
    env,
    error::Error,
    sync::{Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
use cerebro_agent_runtime::{
    AGENT_TURN_REQUEST_V1, AgentModel, AgentRuntimeError, AgentTools, AgentTurnOutcome,
    AgentTurnRequest, ConversationMessage, ConversationRole, CritiqueDecision, CritiqueTurn,
    DECISION_MAX_TOKENS, ExecutionLane, HARD_MAX_GENERATION_TOKENS, ModelDecision, ModelTurn,
    ROUTER_MAX_TOKENS, RouteDecision, RouteTurn, ToolAuthorityClass, ToolDescriptor,
    ToolEffectClass, ToolResult, ToolResultState, WorkingOutcome, WorkingState, run_turn,
};
use serde::Serialize;
use serde_json::json;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::slack_agent::ConfiguredModel;

const SCHEMA_VERSION: &str = "cerebro-rust-slack-agent-hillclimb/v1";
const EXPECTED_CASES_PER_PARTITION: usize = 8;
const MAX_P95_CASE_LATENCY_MS: u128 = 60_000;

#[derive(Clone, Copy)]
struct EvalCase {
    case_ref: &'static str,
    partition: &'static str,
    message: &'static str,
    history: &'static str,
    working_request: Option<&'static str>,
    expected_route: ExecutionLane,
    expected_lane: ExecutionLane,
    false_converse: bool,
}

#[derive(Serialize)]
struct EvalCaseReceipt {
    case_ref: &'static str,
    partition: &'static str,
    expected_route: ExecutionLane,
    actual_route: Option<ExecutionLane>,
    expected_lane: ExecutionLane,
    actual_lane: Option<ExecutionLane>,
    route_attempt_count: usize,
    operating_step_count: usize,
    critic_attempt_count: usize,
    operating_repair_feedback: Vec<Vec<String>>,
    latency_ms: u128,
    false_converse: bool,
    passed: bool,
    terminal_state: String,
}

#[derive(Serialize)]
struct EvalReceipt {
    schema_version: &'static str,
    commit_sha: String,
    evaluated_at: String,
    provider: &'static str,
    model_id: String,
    sampling_parameters: &'static str,
    budgets: EvalBudgets,
    goal: EvalGoal,
    held_out_case_count: usize,
    shadow_case_count: usize,
    case_count: usize,
    route_accuracy: f64,
    false_converse_rate: f64,
    loop_completion_rate: f64,
    p95_latency_ms: u128,
    promotion_ready: bool,
    blockers: Vec<String>,
    results: Vec<EvalCaseReceipt>,
}

#[derive(Serialize)]
struct EvalBudgets {
    router_max_tokens: i32,
    operating_max_tokens: i32,
    critic_max_tokens: i32,
    hard_per_completion_max_tokens: i32,
}

#[derive(Serialize)]
struct EvalGoal {
    minimum_route_accuracy: f64,
    minimum_false_converse_rate: f64,
    minimum_loop_completion_rate: f64,
    maximum_p95_case_latency_ms: u128,
    required_case_pass_rate: f64,
}

struct MeasuredModel {
    inner: Arc<ConfiguredModel>,
    routes: Mutex<Vec<ExecutionLane>>,
    route_attempts: Mutex<usize>,
    operating_steps: Mutex<usize>,
    critic_attempts: Mutex<usize>,
    operating_repair_feedback: Mutex<Vec<Vec<String>>>,
}

impl MeasuredModel {
    fn new(inner: Arc<ConfiguredModel>) -> Self {
        Self {
            inner,
            routes: Mutex::new(Vec::new()),
            route_attempts: Mutex::new(0),
            operating_steps: Mutex::new(0),
            critic_attempts: Mutex::new(0),
            operating_repair_feedback: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl AgentModel for MeasuredModel {
    async fn route(&self, turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        *self.route_attempts.lock().expect("route counter poisoned") += 1;
        let decision = self.inner.route(turn).await?;
        self.routes
            .lock()
            .expect("route receipt poisoned")
            .push(decision.lane);
        Ok(decision)
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        *self
            .operating_steps
            .lock()
            .expect("operating counter poisoned") += 1;
        if !turn.revision_feedback.is_empty() {
            self.operating_repair_feedback
                .lock()
                .expect("operating repair receipt poisoned")
                .push(turn.revision_feedback.clone());
        }
        self.inner.next(turn).await
    }

    async fn critique(&self, turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        *self
            .critic_attempts
            .lock()
            .expect("critic counter poisoned") += 1;
        self.inner.critique(turn).await
    }
}

struct EvalTools;

#[async_trait]
impl AgentTools for EvalTools {
    fn catalog(&self) -> Vec<ToolDescriptor> {
        vec![
            descriptor(
                "source_runtime.inspect",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            descriptor(
                "graph.search",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            descriptor(
                "graph.expand",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            descriptor(
                "runtime_config_update",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
        ]
    }

    async fn invoke(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let observed_at = OffsetDateTime::parse(&request.assessment_at, &Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        let fresh_until = observed_at
            .checked_add(Duration::minutes(5))
            .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
        Ok(ToolResult {
            state: ToolResultState::Succeeded,
            summary: "The tenant-scoped evaluation source returned a current observation.".into(),
            data: json!({
                "tenant_id": request.tenant_id,
                "current": true,
                "bounded": true,
                "tool_id": call.tool_id,
            }),
            evidence: vec![cerebro_agent_runtime::EvidenceRecord {
                evidence_ref: format!(
                    "evidence://rust-hillclimb/{}/{}",
                    request.request_id, call.call_id
                ),
                statement:
                    "The tenant-scoped evaluation source returned a current, complete observation."
                        .into(),
                observed_at: request.assessment_at.clone(),
                fresh_until: Some(
                    fresh_until
                        .format(&Rfc3339)
                        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
                ),
                complete: true,
            }],
            blocker: None,
        })
    }
}

fn descriptor(
    tool_id: &str,
    authority_class: ToolAuthorityClass,
    effect_class: ToolEffectClass,
) -> ToolDescriptor {
    ToolDescriptor {
        tool_id: tool_id.into(),
        title: tool_id.replace(['.', '_'], " "),
        summary: "Return one bounded tenant-scoped evaluation observation.".into(),
        authority_class,
        effect_class,
        input_schema_ref: format!("schema://evaluation/{tool_id}/input/v1"),
        result_schema_ref: format!("schema://evaluation/{tool_id}/result/v1"),
    }
}

pub async fn run() -> Result<(), Box<dyn Error>> {
    let commit_sha = required_commit_sha()?;
    let compiled_commit_sha = option_env!("CEREBRO_BUILD_COMMIT_SHA")
        .ok_or("the hillclimb binary is missing its compile-time commit binding")?;
    if compiled_commit_sha != commit_sha {
        return Err("the runtime and compile-time hillclimb commit bindings differ".into());
    }
    let model_id = env::var("CEREBRO_SLACK_AGENT_MODEL")?;
    if !model_id.contains(".anthropic.claude-opus-") {
        return Err("the Rust Slack agent hillclimb requires AWS-hosted Claude Opus".into());
    }
    if env::var("CEREBRO_SLACK_AGENT_MODEL_PROVIDER")?.trim() != "amazon-bedrock" {
        return Err("the Rust Slack agent hillclimb requires the amazon-bedrock adapter".into());
    }
    let model = Arc::new(ConfiguredModel::from_env().await?);
    let tools = EvalTools;
    let evaluated_at = OffsetDateTime::now_utc();
    let evaluated_at_text = evaluated_at.format(&Rfc3339)?;
    let mut results = Vec::new();

    for (index, eval_case) in eval_cases().into_iter().enumerate() {
        let measured = MeasuredModel::new(model.clone());
        let request = eval_request(index, eval_case, &evaluated_at_text);
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            run_turn(&measured, &tools, request),
        )
        .await;
        let latency_ms = started.elapsed().as_millis();
        let routes = measured
            .routes
            .lock()
            .expect("route receipt poisoned")
            .clone();
        let actual_route = routes.first().copied();
        let (actual_lane, terminal_state, loop_completed) = match outcome {
            Ok(Ok(AgentTurnOutcome::Delivered {
                lane, final_state, ..
            })) => (Some(lane), format!("delivered:{final_state:?}"), true),
            Ok(Ok(AgentTurnOutcome::ApprovalRequired { lane, .. })) => {
                (Some(lane), "approval_required".into(), true)
            }
            Ok(Ok(AgentTurnOutcome::Ignored { .. })) => {
                (Some(ExecutionLane::Ignore), "ignored".into(), false)
            }
            Ok(Err(error)) => (None, format!("error:{error}"), false),
            Err(_) => (None, "timed_out".into(), false),
        };
        let route_passed = actual_route == Some(eval_case.expected_route);
        let lane_passed = actual_lane == Some(eval_case.expected_lane);
        let false_converse_passed =
            !eval_case.false_converse || actual_route != Some(ExecutionLane::Converse);
        results.push(EvalCaseReceipt {
            case_ref: eval_case.case_ref,
            partition: eval_case.partition,
            expected_route: eval_case.expected_route,
            actual_route,
            expected_lane: eval_case.expected_lane,
            actual_lane,
            route_attempt_count: *measured
                .route_attempts
                .lock()
                .expect("route counter poisoned"),
            operating_step_count: *measured
                .operating_steps
                .lock()
                .expect("operating counter poisoned"),
            critic_attempt_count: *measured
                .critic_attempts
                .lock()
                .expect("critic counter poisoned"),
            operating_repair_feedback: measured
                .operating_repair_feedback
                .lock()
                .expect("operating repair receipt poisoned")
                .clone(),
            latency_ms,
            false_converse: eval_case.false_converse,
            passed: route_passed && lane_passed && false_converse_passed && loop_completed,
            terminal_state,
        });
    }

    let case_count = results.len();
    let held_out_case_count = results
        .iter()
        .filter(|result| result.partition == "held_out")
        .count();
    let shadow_case_count = results
        .iter()
        .filter(|result| result.partition == "shadow")
        .count();
    let route_accuracy = rate(
        results
            .iter()
            .filter(|result| result.actual_route == Some(result.expected_route))
            .count(),
        case_count,
    );
    let false_converse_cases = results
        .iter()
        .filter(|result| result.false_converse)
        .collect::<Vec<_>>();
    let false_converse_rate = rate(
        false_converse_cases
            .iter()
            .filter(|result| result.actual_route != Some(ExecutionLane::Converse))
            .count(),
        false_converse_cases.len(),
    );
    let loop_completion_rate = rate(
        results
            .iter()
            .filter(|result| {
                !result.terminal_state.starts_with("error:")
                    && result.terminal_state != "timed_out"
                    && result.terminal_state != "ignored"
            })
            .count(),
        case_count,
    );
    let mut latencies = results
        .iter()
        .map(|result| result.latency_ms)
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    let p95_latency_ms = percentile_95(&latencies);
    let mut blockers = Vec::new();
    if held_out_case_count < EXPECTED_CASES_PER_PARTITION {
        blockers.push("held-out partition has fewer than eight cases".into());
    }
    if shadow_case_count < EXPECTED_CASES_PER_PARTITION {
        blockers.push("shadow partition has fewer than eight cases".into());
    }
    if route_accuracy < 1.0 {
        blockers.push("semantic route accuracy is below 100%".into());
    }
    if false_converse_rate < 1.0 {
        blockers.push("a current-work case routed to conversation".into());
    }
    if loop_completion_rate < 1.0 {
        blockers
            .push("one or more Rust operating loops did not reach a safe terminal state".into());
    }
    if results.iter().any(|result| !result.passed) {
        blockers.push("one or more held-out or shadow cases failed".into());
    }
    if p95_latency_ms > MAX_P95_CASE_LATENCY_MS {
        blockers.push("p95 hosted Rust loop latency exceeds 60 seconds".into());
    }
    let receipt = EvalReceipt {
        schema_version: SCHEMA_VERSION,
        commit_sha,
        evaluated_at: evaluated_at_text,
        provider: "aws_bedrock",
        model_id,
        sampling_parameters: "provider_default",
        budgets: EvalBudgets {
            router_max_tokens: ROUTER_MAX_TOKENS,
            operating_max_tokens: DECISION_MAX_TOKENS,
            critic_max_tokens: cerebro_agent_runtime::CRITIC_MAX_TOKENS,
            hard_per_completion_max_tokens: HARD_MAX_GENERATION_TOKENS,
        },
        goal: EvalGoal {
            minimum_route_accuracy: 1.0,
            minimum_false_converse_rate: 1.0,
            minimum_loop_completion_rate: 1.0,
            maximum_p95_case_latency_ms: MAX_P95_CASE_LATENCY_MS,
            required_case_pass_rate: 1.0,
        },
        held_out_case_count,
        shadow_case_count,
        case_count,
        route_accuracy,
        false_converse_rate,
        loop_completion_rate,
        p95_latency_ms,
        promotion_ready: blockers.is_empty(),
        blockers,
        results,
    };
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    if receipt.promotion_ready {
        Ok(())
    } else {
        Err("the exact-head Rust Slack agent hillclimb did not meet its promotion goal".into())
    }
}

fn eval_request(index: usize, eval_case: EvalCase, assessment_at: &str) -> AgentTurnRequest {
    AgentTurnRequest {
        schema_version: AGENT_TURN_REQUEST_V1.into(),
        tenant_id: "rust-hillclimb-tenant".into(),
        request_id: format!("rust-hillclimb-{index:02}"),
        thread_ref: format!("slack-thread://rust-hillclimb/{index:02}"),
        actor_ref: "slack-user://rust-hillclimb".into(),
        assessment_at: assessment_at.into(),
        message: eval_case.message.into(),
        history: vec![ConversationMessage {
            role: ConversationRole::User,
            content: eval_case.history.into(),
        }],
        working_state: eval_case
            .working_request
            .map(|current_request| WorkingState {
                mission_ref: Some(format!("mission://rust-hillclimb/{index:02}")),
                current_request: current_request.into(),
                last_outcome: WorkingOutcome::Blocked,
                last_blocker: Some("The prior evidence read timed out.".into()),
            }),
        effect_authorizations: vec![],
    }
}

fn required_commit_sha() -> Result<String, Box<dyn Error>> {
    let value = env::var("CEREBRO_SLACK_AGENT_EVAL_COMMIT_SHA")?;
    validate_commit_sha(&value)
}

fn validate_commit_sha(value: &str) -> Result<String, Box<dyn Error>> {
    let value = value.trim();
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("CEREBRO_SLACK_AGENT_EVAL_COMMIT_SHA must be an exact 40-character SHA".into());
    }
    Ok(value.into())
}

fn rate(passed: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    }
}

fn percentile_95(sorted: &[u128]) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn eval_cases() -> Vec<EvalCase> {
    vec![
        EvalCase {
            case_ref: "case://held-out/self-work-today",
            partition: "held_out",
            message: "what can you tell me about yourself and your work today?",
            history: "The user is asking about this agent and work within a current time period.",
            working_request: None,
            expected_route: ExecutionLane::Investigate,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/current-source-status",
            partition: "held_out",
            message: "What is the current connector status?",
            history: "The connector is a governed source runtime.",
            working_request: None,
            expected_route: ExecutionLane::Lookup,
            expected_lane: ExecutionLane::Lookup,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/diagnose-source",
            partition: "held_out",
            message: "Figure out why the connector keeps failing end to end.",
            history: "Several sync attempts were discussed, but none is current evidence.",
            working_request: None,
            expected_route: ExecutionLane::Investigate,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/resume-newest",
            partition: "held_out",
            message: "Keep going.",
            history: "An older completed request discussed a different control.",
            working_request: Some("Investigate the newest connector failure."),
            expected_route: ExecutionLane::Continue,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/action",
            partition: "held_out",
            message: "Fix the connector configuration and verify the deployed result.",
            history: "No effect authorization is present.",
            working_request: None,
            expected_route: ExecutionLane::Act,
            expected_lane: ExecutionLane::Act,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/newest-request-wins",
            partition: "held_out",
            message: "Start a separate current assessment of Source B.",
            history: "The earlier thread requested work on Source A.",
            working_request: Some("Investigate Source A."),
            expected_route: ExecutionLane::Investigate,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://held-out/pure-conversation",
            partition: "held_out",
            message: "Hello. What kinds of security questions can you help explain?",
            history: "No current system state was requested.",
            working_request: None,
            expected_route: ExecutionLane::Converse,
            expected_lane: ExecutionLane::Converse,
            false_converse: false,
        },
        EvalCase {
            case_ref: "case://held-out/timeless-explanation",
            partition: "held_out",
            message: "Explain the difference between a control owner and an evidence owner.",
            history: "The user wants a timeless conceptual distinction.",
            working_request: None,
            expected_route: ExecutionLane::Converse,
            expected_lane: ExecutionLane::Converse,
            false_converse: false,
        },
        EvalCase {
            case_ref: "case://shadow/verified-day-log",
            partition: "shadow",
            message: "Describe your role, then list only the work from today you can verify.",
            history: "The second clause asks for current time-bounded work evidence.",
            working_request: None,
            expected_route: ExecutionLane::Investigate,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/feed-health",
            partition: "shadow",
            message: "Is Feed B healthy right now?",
            history: "Feed B is a tenant-scoped source runtime.",
            working_request: None,
            expected_route: ExecutionLane::Lookup,
            expected_lane: ExecutionLane::Lookup,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/root-cause",
            partition: "shadow",
            message: "Trace the repeated collection failures to a supported cause.",
            history: "Prior messages are hypotheses, not evidence.",
            working_request: None,
            expected_route: ExecutionLane::Investigate,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/carry-on",
            partition: "shadow",
            message: "Carry on until the evidence boundary is clear.",
            history: "The newest durable mission is retained separately.",
            working_request: Some("Map the unresolved policy gaps for this workload."),
            expected_route: ExecutionLane::Continue,
            expected_lane: ExecutionLane::Investigate,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/change-and-check",
            partition: "shadow",
            message: "Apply the approved runtime correction and independently check the outcome.",
            history: "The request asks for an external effect and verification.",
            working_request: None,
            expected_route: ExecutionLane::Act,
            expected_lane: ExecutionLane::Act,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/graph-isolation",
            partition: "shadow",
            message: "Search the current graph for this tenant; do not use another tenant's records.",
            history: "Tenant boundaries are authoritative.",
            working_request: None,
            expected_route: ExecutionLane::Lookup,
            expected_lane: ExecutionLane::Lookup,
            false_converse: true,
        },
        EvalCase {
            case_ref: "case://shadow/capability-chat",
            partition: "shadow",
            message: "In general, what can Cerebro help a security operator understand?",
            history: "No current work log or live state is requested.",
            working_request: None,
            expected_route: ExecutionLane::Converse,
            expected_lane: ExecutionLane::Converse,
            false_converse: false,
        },
        EvalCase {
            case_ref: "case://shadow/concept-chat",
            partition: "shadow",
            message: "What does evidence freshness mean in a control program?",
            history: "The user asks for a general explanation.",
            working_request: None,
            expected_route: ExecutionLane::Converse,
            expected_lane: ExecutionLane::Converse,
            false_converse: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_has_independent_partitions_and_false_converse_negatives() {
        let cases = eval_cases();
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.partition == "held_out")
                .count(),
            EXPECTED_CASES_PER_PARTITION
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.partition == "shadow")
                .count(),
            EXPECTED_CASES_PER_PARTITION
        );
        assert!(
            cases
                .iter()
                .any(|case| case.message
                    == "what can you tell me about yourself and your work today?")
        );
        assert!(
            cases
                .iter()
                .filter(|case| case.false_converse)
                .all(|case| case.expected_route != ExecutionLane::Converse)
        );
    }

    #[test]
    fn hosted_command_rejects_a_non_exact_commit() {
        assert!(validate_commit_sha("not-a-sha").is_err());
        assert!(validate_commit_sha(&"a".repeat(40)).is_ok());
    }
}
