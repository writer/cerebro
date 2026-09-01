use std::{
    env,
    error::Error,
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use cerebro_agent_runtime::{
    AgentDeliveryReceipt, AgentRuntimeError, AgentTurnOutcome, AgentTurnRequest,
};
use cerebro_slack_authority::{
    AnswerAuthorityError, AnswerCandidate, AnswerDecision, AnswerDisposition,
    QuestionAuthorityError, QuestionCandidate, QuestionDecision, QuestionExecutionLane,
    QuestionPolicy, authorize_question, validate_answer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    slack_agent::{
        AgentTurnProgress, AgentWakeDeliveryReceipt, AgentWakeTurn, SlackAgentModelAttestation,
        SlackAgentService,
    },
    slack_agent_session::AgentPendingWakeDelivery,
};

const DEFAULT_BIND: &str = "127.0.0.1:8091";
const MAX_REQUEST_BYTES: usize = 96 * 1024;
const TURN_RUNTIME_BOUNDARY: &str = "rust_agent_runtime";
const TURN_RUNTIME_PHASE: &str = "runtime_execution";
const AGENT_RUNTIME_TOKEN_ENV: &str = "CEREBRO_SLACK_AGENT_RUNTIME_TOKEN";

#[derive(Clone)]
struct AgentRuntimeTokenDigest([u8; 32]);

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WakeRunRequest {
    worker_ref: String,
}

#[derive(Serialize)]
struct WakeRunResponse {
    wake: Option<AgentWakeTurn>,
}

#[derive(Serialize)]
struct WakeDeliveryClaimResponse {
    delivery: Option<AgentPendingWakeDelivery>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnProgressQuery {
    thread_ref: String,
    request_id: String,
    #[serde(default)]
    after_sequence: u64,
}

struct TurnBoundaryReceipt {
    request_ref: String,
    started_at: Instant,
    terminal_emitted: bool,
}

impl TurnBoundaryReceipt {
    fn start(request_id: &str) -> Self {
        let request_ref = turn_request_ref(request_id);
        println!("{}", turn_boundary_event(&request_ref, "started", 0, None));
        Self {
            request_ref,
            started_at: Instant::now(),
            terminal_emitted: false,
        }
    }

    fn finish(&mut self, state: &'static str) {
        self.emit_terminal(state);
    }

    fn emit_terminal(&mut self, state: &'static str) {
        if self.terminal_emitted {
            return;
        }
        self.terminal_emitted = true;
        println!(
            "{}",
            turn_boundary_event(
                &self.request_ref,
                state,
                self.started_at
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                Some(TURN_RUNTIME_BOUNDARY),
            )
        );
    }
}

impl Drop for TurnBoundaryReceipt {
    fn drop(&mut self) {
        self.emit_terminal("interrupted");
    }
}

fn turn_request_ref(request_id: &str) -> String {
    format!(
        "slack-agent-turn://sha256/{}",
        Sha256::digest(request_id.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn turn_boundary_event(
    request_ref: &str,
    state: &'static str,
    phase_elapsed_ms: u64,
    terminal_boundary: Option<&'static str>,
) -> serde_json::Value {
    serde_json::json!({
        "authority": "rust",
        "component": "slack-answer-authority",
        "operation": "turn_run",
        "phase": TURN_RUNTIME_PHASE,
        "phase_elapsed_ms": phase_elapsed_ms,
        "request_ref": request_ref,
        "schema_version": "slack-agent-turn-boundary-receipt/v1",
        "state": state,
        "terminal_boundary": terminal_boundary,
    })
}

struct AuthorityRuntime {
    agent: Option<SlackAgentService>,
    agent_tool_calls_total: AtomicU64,
    agent_turn_failures_total: AtomicU64,
    agent_turns_total: AtomicU64,
    question_authorized_total: AtomicU64,
    question_rejected_total: AtomicU64,
    question_policy: QuestionPolicy,
    grounded_total: AtomicU64,
    model_attestation: Option<SlackAgentModelAttestation>,
    rejected_total: AtomicU64,
    runtime_instance_ref: &'static str,
    safe_refusal_total: AtomicU64,
    started_at: Instant,
}

#[derive(Serialize)]
struct AuthorityStatus {
    actuate_dispatch_total: u64,
    actuate_outcome_unknown_total: u64,
    agent_ready: bool,
    agent_tool_calls_total: u64,
    agent_turn_failures_total: u64,
    agent_turns_total: u64,
    authority: &'static str,
    build_commit_sha: &'static str,
    build_tree_clean: bool,
    component: &'static str,
    grounded_total: u64,
    model_config_sha256: Option<String>,
    model_id: Option<String>,
    model_provider: Option<&'static str>,
    question_authorized_total: u64,
    question_rejected_total: u64,
    rejected_total: u64,
    requests_total: u64,
    runtime_instance_ref: &'static str,
    safe_refusal_total: u64,
    schema_version: &'static str,
    session_schema_version: &'static str,
    status: &'static str,
    uptime_ms: u64,
    version: &'static str,
}

impl AuthorityRuntime {
    fn new(question_policy: QuestionPolicy, agent: Option<SlackAgentService>) -> Self {
        let model_attestation = agent.as_ref().map(SlackAgentService::model_attestation);
        Self {
            agent,
            agent_tool_calls_total: AtomicU64::new(0),
            agent_turn_failures_total: AtomicU64::new(0),
            agent_turns_total: AtomicU64::new(0),
            question_authorized_total: AtomicU64::new(0),
            question_rejected_total: AtomicU64::new(0),
            grounded_total: AtomicU64::new(0),
            model_attestation,
            rejected_total: AtomicU64::new(0),
            runtime_instance_ref: runtime_instance_ref(),
            safe_refusal_total: AtomicU64::new(0),
            started_at: Instant::now(),
            question_policy,
        }
    }

    fn status(&self) -> AuthorityStatus {
        let (actuate_dispatch_total, actuate_outcome_unknown_total) = self
            .agent
            .as_ref()
            .map_or((0, 0), SlackAgentService::actuation_metrics);
        let grounded_total = self.grounded_total.load(Ordering::Relaxed);
        let rejected_total = self.rejected_total.load(Ordering::Relaxed);
        let safe_refusal_total = self.safe_refusal_total.load(Ordering::Relaxed);
        let question_authorized_total = self.question_authorized_total.load(Ordering::Relaxed);
        let question_rejected_total = self.question_rejected_total.load(Ordering::Relaxed);
        let agent_turns_total = self.agent_turns_total.load(Ordering::Relaxed);
        let agent_turn_failures_total = self.agent_turn_failures_total.load(Ordering::Relaxed);
        AuthorityStatus {
            actuate_dispatch_total,
            actuate_outcome_unknown_total,
            agent_ready: self.agent.is_some(),
            agent_tool_calls_total: self.agent_tool_calls_total.load(Ordering::Relaxed),
            agent_turn_failures_total,
            agent_turns_total,
            authority: "rust",
            build_commit_sha: env!("CEREBRO_GIT_COMMIT_SHA"),
            build_tree_clean: env!("CEREBRO_GIT_TREE_CLEAN") == "1",
            component: "slack-answer-authority",
            grounded_total,
            model_config_sha256: self
                .model_attestation
                .as_ref()
                .map(|attestation| attestation.model_config_sha256.clone()),
            model_id: self
                .model_attestation
                .as_ref()
                .map(|attestation| attestation.model_id.clone()),
            model_provider: self
                .model_attestation
                .as_ref()
                .map(|attestation| attestation.model_provider),
            question_authorized_total,
            question_rejected_total,
            rejected_total,
            requests_total: grounded_total
                .saturating_add(rejected_total)
                .saturating_add(safe_refusal_total)
                .saturating_add(question_authorized_total)
                .saturating_add(question_rejected_total)
                .saturating_add(agent_turns_total)
                .saturating_add(agent_turn_failures_total),
            safe_refusal_total,
            runtime_instance_ref: self.runtime_instance_ref,
            schema_version: "slack-answer-authority-status/v3",
            session_schema_version: cerebro_agent_runtime::session::AGENT_SESSION_V2,
            status: "ready",
            uptime_ms: self
                .started_at
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

fn runtime_instance_ref() -> &'static str {
    static RUNTIME_INSTANCE_REF: OnceLock<String> = OnceLock::new();

    RUNTIME_INSTANCE_REF.get_or_init(|| {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let identity = format!("{}:{started_at}", std::process::id());
        let digest = Sha256::digest(identity.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("slack-authority-instance://sha256/{digest}")
    })
}

pub async fn serve() -> Result<(), Box<dyn Error>> {
    let bind = env::var("CEREBRO_SLACK_AUTHORITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let address: SocketAddr = bind.parse()?;
    require_loopback(address)?;
    let tenant_id = env::var("CEREBRO_SLACK_AUTHORITY_TENANT_ID")
        .map_err(|_| "CEREBRO_SLACK_AUTHORITY_TENANT_ID is required")?;
    let question_policy = QuestionPolicy::new(tenant_id.clone())?;
    let agent_runtime_token = env::var(AGENT_RUNTIME_TOKEN_ENV)
        .map_err(|_| "CEREBRO_SLACK_AGENT_RUNTIME_TOKEN is required")?;
    validate_agent_runtime_token(&agent_runtime_token)?;
    let agent = SlackAgentService::from_env(tenant_id).await?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!(
        "{}",
        serde_json::json!({
            "authority": "rust",
            "bind": address.to_string(),
            "component": "slack-answer-authority",
            "operation": "listen",
            "schema_version": "slack-answer-authority-runtime/v1",
            "state": "ready",
            "version": env!("CARGO_PKG_VERSION"),
        })
    );
    axum::serve(
        listener,
        router(
            question_policy,
            agent,
            Some(AgentRuntimeTokenDigest(
                Sha256::digest(agent_runtime_token.as_bytes()).into(),
            )),
        ),
    )
    .await?;
    Ok(())
}

fn router(
    question_policy: QuestionPolicy,
    agent: Option<SlackAgentService>,
    agent_runtime_token: Option<AgentRuntimeTokenDigest>,
) -> Router {
    let protected = Router::new()
        .route("/v1/turns/run", post(run_turn_route))
        .route("/v1/turns/progress", get(turn_progress_route))
        .route("/v1/turns/deliveries", post(record_delivery_route))
        .route("/v1/wakes/run", post(run_due_wake_route))
        .route(
            "/v1/wakes/pending-deliveries/claim",
            post(claim_pending_wake_delivery_route),
        )
        .route("/v1/wakes/deliveries", post(record_wake_delivery_route));
    let protected = match agent_runtime_token {
        Some(expected) => protected.route_layer(middleware::from_fn_with_state(
            expected,
            require_agent_runtime_bearer,
        )),
        None => protected,
    };
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/status", get(authority_status_route))
        .route("/v1/questions/authorize", post(authorize_question_route))
        .route("/v1/answers/validate", post(validate_answer_route))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(AuthorityRuntime::new(question_policy, agent)))
}

async fn require_agent_runtime_bearer(
    State(expected): State<AgentRuntimeTokenDigest>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(token) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !constant_time_digest_eq(&actual, &expected.0) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

fn constant_time_digest_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_agent_runtime_token(token: &str) -> Result<(), &'static str> {
    if token.len() < 32 || token.len() > 512 || token.chars().any(char::is_whitespace) {
        return Err("CEREBRO_SLACK_AGENT_RUNTIME_TOKEN is invalid");
    }
    Ok(())
}

async fn turn_progress_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Query(query): Query<TurnProgressQuery>,
) -> Result<Json<AgentTurnProgress>, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    agent
        .turn_progress(&query.thread_ref, &query.request_id, query.after_sequence)
        .await
        .map(Json)
        .map_err(agent_error)
}

async fn claim_pending_wake_delivery_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(request): Json<WakeRunRequest>,
) -> Result<Json<WakeDeliveryClaimResponse>, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    let delivery = agent
        .claim_pending_wake_delivery(&request.worker_ref)
        .await
        .map_err(agent_error)?;
    Ok(Json(WakeDeliveryClaimResponse { delivery }))
}

async fn record_wake_delivery_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(receipt): Json<AgentWakeDeliveryReceipt>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    agent
        .record_wake_delivery(receipt)
        .await
        .map_err(agent_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn run_due_wake_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(request): Json<WakeRunRequest>,
) -> Result<Json<WakeRunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    let wake = agent
        .run_due_wake(&request.worker_ref)
        .await
        .map_err(agent_error)?;
    Ok(Json(WakeRunResponse { wake }))
}

async fn record_delivery_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(receipt): Json<AgentDeliveryReceipt>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    agent.record_delivery(receipt).await.map_err(agent_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn run_turn_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(request): Json<AgentTurnRequest>,
) -> Result<Json<AgentTurnOutcome>, (StatusCode, Json<ErrorResponse>)> {
    let agent = runtime.agent.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "agent_not_configured",
                message: "The Rust Slack agent runtime is not configured.".into(),
            }),
        )
    })?;
    let followup_acceptance = request.followup_acceptance.is_some();
    let mut boundary_receipt = TurnBoundaryReceipt::start(&request.request_id);
    match agent.run(request).await {
        Ok(outcome) => {
            boundary_receipt.finish("completed");
            runtime.agent_turns_total.fetch_add(1, Ordering::Relaxed);
            runtime
                .agent_tool_calls_total
                .fetch_add(outcome_tool_call_count(&outcome), Ordering::Relaxed);
            Ok(Json(outcome))
        }
        Err(error) => {
            boundary_receipt.finish("failed");
            runtime
                .agent_turn_failures_total
                .fetch_add(1, Ordering::Relaxed);
            Err(agent_turn_error(error, followup_acceptance))
        }
    }
}

fn outcome_tool_call_count(outcome: &AgentTurnOutcome) -> u64 {
    match outcome {
        AgentTurnOutcome::PendingDelivery {
            tool_call_count, ..
        }
        | AgentTurnOutcome::Delivered {
            tool_call_count, ..
        }
        | AgentTurnOutcome::ApprovalRequired {
            tool_call_count, ..
        } => (*tool_call_count).try_into().unwrap_or(u64::MAX),
        AgentTurnOutcome::Ignored { .. } => 0,
    }
}

fn agent_error(error: AgentRuntimeError) -> (StatusCode, Json<ErrorResponse>) {
    agent_turn_error(error, false)
}

fn agent_turn_error(
    error: AgentRuntimeError,
    followup_acceptance: bool,
) -> (StatusCode, Json<ErrorResponse>) {
    let followup_rejected_before_commit =
        followup_acceptance && !matches!(&error, AgentRuntimeError::ModelUnavailable(_));
    if matches!(
        &error,
        AgentRuntimeError::InvalidRequest(message)
            if message == "another turn currently owns this Slack session"
    ) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: if followup_rejected_before_commit {
                    "followup_acceptance_not_committed"
                } else {
                    "agent_turn_busy"
                },
                message: "The Slack thread already has an active agent turn.".to_owned(),
            }),
        );
    }
    let status = match &error {
        AgentRuntimeError::ModelUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (
        status,
        Json(ErrorResponse {
            // Validation failures occur before append_operator_finalized and
            // prove no acceptance commit. Store failures remain unknown: a
            // PostgreSQL COMMIT can succeed even when its acknowledgement is
            // lost, and the exact request must reconcile that state by replay.
            code: if followup_rejected_before_commit {
                "followup_acceptance_not_committed"
            } else {
                "agent_turn_failed"
            },
            message: error.to_string(),
        }),
    )
}

async fn authorize_question_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(candidate): Json<QuestionCandidate>,
) -> Result<Json<QuestionDecision>, (StatusCode, Json<ErrorResponse>)> {
    match authorize_question(&runtime.question_policy, candidate) {
        Ok(decision) => {
            runtime
                .question_authorized_total
                .fetch_add(1, Ordering::Relaxed);
            log_question_decision(
                &runtime,
                "authorized",
                Some(match decision.execution_lane {
                    QuestionExecutionLane::Converse => "converse",
                    QuestionExecutionLane::Lookup => "lookup",
                }),
                None,
                Some(&decision.request_id),
            );
            Ok(Json(decision))
        }
        Err(error) => {
            runtime
                .question_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            log_question_decision(
                &runtime,
                "rejected",
                None,
                Some(question_rejection_code(error)),
                None,
            );
            Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    code: "question_rejected",
                    message: error.to_string(),
                }),
            ))
        }
    }
}

async fn authority_status_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
) -> Json<AuthorityStatus> {
    Json(runtime.status())
}

async fn validate_answer_route(
    State(runtime): State<Arc<AuthorityRuntime>>,
    Json(candidate): Json<AnswerCandidate>,
) -> Result<Json<AnswerDecision>, (StatusCode, Json<ErrorResponse>)> {
    match validate_answer(candidate) {
        Ok(decision) => {
            match decision.disposition {
                AnswerDisposition::Grounded => {
                    runtime.grounded_total.fetch_add(1, Ordering::Relaxed);
                }
                AnswerDisposition::SafeRefusal => {
                    runtime.safe_refusal_total.fetch_add(1, Ordering::Relaxed);
                }
            }
            log_decision(
                &runtime,
                "accepted",
                Some(match decision.disposition {
                    AnswerDisposition::Grounded => "grounded",
                    AnswerDisposition::SafeRefusal => "safe_refusal",
                }),
                None,
                Some(&decision.trace_id),
            );
            Ok(Json(decision))
        }
        Err(error) => {
            runtime.rejected_total.fetch_add(1, Ordering::Relaxed);
            log_decision(
                &runtime,
                "rejected",
                None,
                Some(rejection_code(error)),
                None,
            );
            Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    code: "answer_rejected",
                    message: error.to_string(),
                }),
            ))
        }
    }
}

fn log_decision(
    runtime: &AuthorityRuntime,
    outcome: &'static str,
    disposition: Option<&'static str>,
    rejection_code: Option<&'static str>,
    trace_id: Option<&str>,
) {
    let status = runtime.status();
    println!(
        "{}",
        serde_json::json!({
            "authority": "rust",
            "component": "slack-answer-authority",
            "disposition": disposition,
            "grounded_total": status.grounded_total,
            "operation": "answer_validate",
            "outcome": outcome,
            "rejected_total": status.rejected_total,
            "rejection_code": rejection_code,
            "requests_total": status.requests_total,
            "safe_refusal_total": status.safe_refusal_total,
            "schema_version": "slack-answer-authority-decision-log/v1",
            "trace_id": trace_id,
        })
    );
}

fn log_question_decision(
    runtime: &AuthorityRuntime,
    outcome: &'static str,
    execution_lane: Option<&'static str>,
    rejection_code: Option<&'static str>,
    request_id: Option<&str>,
) {
    let status = runtime.status();
    println!(
        "{}",
        serde_json::json!({
            "authority": "rust",
            "component": "slack-answer-authority",
            "execution_lane": execution_lane,
            "operation": "question_authorize",
            "outcome": outcome,
            "question_authorized_total": status.question_authorized_total,
            "question_rejected_total": status.question_rejected_total,
            "rejection_code": rejection_code,
            "request_id": request_id,
            "requests_total": status.requests_total,
            "schema_version": "slack-question-authority-decision-log/v1",
        })
    );
}

fn rejection_code(error: AnswerAuthorityError) -> &'static str {
    match error {
        AnswerAuthorityError::CitationEvidenceMissing => "citation_evidence_missing",
        AnswerAuthorityError::ConflictingEvidenceStates => "conflicting_evidence_states",
        AnswerAuthorityError::Incomplete => "incomplete",
        AnswerAuthorityError::InvalidRefusal => "invalid_refusal",
        AnswerAuthorityError::InvalidSchema => "invalid_schema",
        AnswerAuthorityError::InvalidTrace => "invalid_trace",
        AnswerAuthorityError::MarkdownInvalid => "markdown_invalid",
    }
}

fn question_rejection_code(error: QuestionAuthorityError) -> &'static str {
    match error {
        QuestionAuthorityError::HistoryInvalid => "history_invalid",
        QuestionAuthorityError::InvalidPolicy => "invalid_policy",
        QuestionAuthorityError::InvalidRequest => "invalid_request",
        QuestionAuthorityError::InvalidSchema => "invalid_schema",
        QuestionAuthorityError::QuestionInvalid => "question_invalid",
        QuestionAuthorityError::TenantMismatch => "tenant_mismatch",
    }
}

fn require_loopback(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    if !address.ip().is_loopback() {
        return Err("Slack answer authority must bind to a loopback address".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header::CONTENT_TYPE},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn test_router() -> Router {
        router(
            QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap(),
            None,
            None,
        )
    }

    #[tokio::test]
    async fn agent_runtime_routes_require_the_exact_host_bearer() {
        let token = "test-agent-runtime-token-1234567890";
        let app = router(
            QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap(),
            None,
            Some(AgentRuntimeTokenDigest(
                Sha256::digest(token.as_bytes()).into(),
            )),
        );
        let body = r#"{
          "schema_version":"agent-turn-request/v1",
          "tenant_id":"writer-sec-dev",
          "request_id":"request-one",
          "thread_ref":"slack-thread:T:C:one",
          "actor_ref":"slack-user:U",
          "assessment_at":"2026-07-29T20:00:00Z",
          "message":"Investigate the source failure.",
          "history":[],
          "working_state":null,
          "effect_authorizations":[]
        }"#;
        let unauthorized = app
            .clone()
            .oneshot(
                Request::post("/v1/turns/run")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .oneshot(
                Request::post("/v1/turns/run")
                    .header(CONTENT_TYPE, "application/json")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn agent_runtime_token_is_long_bounded_and_header_safe() {
        assert!(validate_agent_runtime_token(&"a".repeat(32)).is_ok());
        assert!(validate_agent_runtime_token("short").is_err());
        assert!(validate_agent_runtime_token(&format!("{} x", "a".repeat(32))).is_err());
        assert!(validate_agent_runtime_token(&"a".repeat(513)).is_err());
        assert!(constant_time_digest_eq(&[1; 32], &[1; 32]));
        assert!(!constant_time_digest_eq(&[1; 32], &[2; 32]));
    }

    #[test]
    fn busy_agent_turn_has_a_safe_retryable_http_state() {
        let (status, Json(response)) = agent_error(AgentRuntimeError::InvalidRequest(
            "another turn currently owns this Slack session".to_owned(),
        ));

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response.code, "agent_turn_busy");
        assert_eq!(
            response.message,
            "The Slack thread already has an active agent turn."
        );
    }

    #[test]
    fn failed_followup_acceptance_has_an_explicit_no_commit_state() {
        let (status, Json(response)) = agent_turn_error(
            AgentRuntimeError::InvalidRequest("offer expired".to_owned()),
            true,
        );

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response.code, "followup_acceptance_not_committed");
    }

    #[test]
    fn unavailable_followup_acceptance_preserves_unknown_commit_state() {
        let (status, Json(response)) = agent_turn_error(
            AgentRuntimeError::ModelUnavailable("commit acknowledgement lost".to_owned()),
            true,
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.code, "agent_turn_failed");
    }

    #[tokio::test]
    async fn status_route_exposes_stable_runtime_attestation() {
        let app = test_router();
        let first = app
            .clone()
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let second = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        let first: Value = serde_json::from_slice(
            &to_bytes(first.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        let second: Value = serde_json::from_slice(
            &to_bytes(second.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(first["schema_version"], "slack-answer-authority-status/v3");
        assert_eq!(first["actuate_dispatch_total"], 0);
        assert_eq!(first["actuate_outcome_unknown_total"], 0);
        assert_eq!(first["build_commit_sha"], env!("CEREBRO_GIT_COMMIT_SHA"));
        assert_eq!(
            first["build_tree_clean"],
            env!("CEREBRO_GIT_TREE_CLEAN") == "1"
        );
        assert_eq!(first["session_schema_version"], "agent-session/v2");
        assert_eq!(first["model_provider"], Value::Null);
        assert_eq!(first["model_id"], Value::Null);
        assert_eq!(first["model_config_sha256"], Value::Null);
        let instance_ref = first["runtime_instance_ref"].as_str().unwrap();
        assert!(instance_ref.starts_with("slack-authority-instance://sha256/"));
        assert_eq!(
            instance_ref.len(),
            "slack-authority-instance://sha256/".len() + 64
        );
        assert_eq!(
            first["runtime_instance_ref"],
            second["runtime_instance_ref"]
        );
    }

    #[test]
    fn turn_boundary_receipt_is_opaque_and_provider_neutral() {
        let request_id = "sensitive-request-value";
        let request_ref = turn_request_ref(request_id);
        let event =
            turn_boundary_event(&request_ref, "failed", 300_001, Some(TURN_RUNTIME_BOUNDARY));

        assert_eq!(
            event,
            serde_json::json!({
                "authority": "rust",
                "component": "slack-answer-authority",
                "operation": "turn_run",
                "phase": "runtime_execution",
                "phase_elapsed_ms": 300_001,
                "request_ref": request_ref,
                "schema_version": "slack-agent-turn-boundary-receipt/v1",
                "state": "failed",
                "terminal_boundary": "rust_agent_runtime",
            })
        );
        assert!(!event.to_string().contains(request_id));
    }

    #[test]
    fn turn_boundary_receipt_distinguishes_start_from_terminal_exit() {
        let request_ref = turn_request_ref("request-one");
        let started = turn_boundary_event(&request_ref, "started", 0, None);
        let interrupted =
            turn_boundary_event(&request_ref, "interrupted", 42, Some(TURN_RUNTIME_BOUNDARY));

        assert_eq!(started["terminal_boundary"], Value::Null);
        assert_eq!(started["phase_elapsed_ms"], 0);
        assert_eq!(interrupted["terminal_boundary"], "rust_agent_runtime");
        assert_eq!(interrupted["phase_elapsed_ms"], 42);
    }

    #[tokio::test]
    async fn turn_route_fails_closed_when_the_agent_is_not_configured() {
        let response = test_router()
            .oneshot(
                Request::post("/v1/turns/run")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"agent-turn-request/v1",
                          "tenant_id":"writer-sec-dev",
                          "request_id":"request-one",
                          "thread_ref":"slack-thread:T:C:one",
                          "actor_ref":"slack-user:U",
                          "assessment_at":"2026-07-29T20:00:00Z",
                          "message":"Investigate the source failure.",
                          "history":[],
                          "working_state":null,
                          "effect_authorizations":[]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["code"], "agent_not_configured");
    }

    #[tokio::test]
    async fn wake_delivery_routes_fail_closed_when_the_agent_is_not_configured() {
        let app = test_router();
        let progress = app
            .clone()
            .oneshot(
                Request::get(
                    "/v1/turns/progress?thread_ref=slack-thread%3AT%3AC%3Aone&request_id=request-one",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(progress.status(), StatusCode::SERVICE_UNAVAILABLE);

        let wake = app
            .clone()
            .oneshot(
                Request::post("/v1/wakes/run")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"worker_ref":"slack-host:test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wake.status(), StatusCode::SERVICE_UNAVAILABLE);

        let claim = app
            .clone()
            .oneshot(
                Request::post("/v1/wakes/pending-deliveries/claim")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"worker_ref":"slack-host:test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(claim.status(), StatusCode::SERVICE_UNAVAILABLE);

        let receipt = app
            .clone()
            .oneshot(
                Request::post("/v1/wakes/deliveries")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{
                          "lease":{{
                            "commitment_ref":"commitment:test",
                            "delivery_attempt_ref":"wake-delivery-attempt://sha256/{}",
                            "delivery_ref":"wake-delivery://sha256/{}",
                            "fence":2,
                            "lease_expires_at":"2026-07-29T20:05:00Z",
                            "lease_owner":"slack-host:test",
                            "lease_token":"wake-delivery-lease://sha256/{}",
                            "payload_digest":"sha256:{}",
                            "request_id":"wake-request:test",
                            "schedule_generation":1,
                            "session_ref":"session:test"
                          }},
                          "receipt":{{
                            "schema_version":"agent-delivery-receipt/v1",
                            "tenant_id":"writer-sec-dev",
                            "thread_ref":"thread:test",
                            "request_id":"wake-request:test",
                            "transport":"slack",
                            "delivery_ref":"slack-message:test",
                            "payload_digest":"sha256:{}",
                            "delivered_at":"2026-07-29T20:00:00Z"
                          }}
                        }}"#,
                        "a".repeat(64),
                        "c".repeat(64),
                        "d".repeat(64),
                        "b".repeat(64),
                        "b".repeat(64),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::SERVICE_UNAVAILABLE);

        let delivery = app
            .oneshot(
                Request::post("/v1/turns/deliveries")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{
                          "schema_version":"agent-delivery-receipt/v1",
                          "tenant_id":"writer-sec-dev",
                          "thread_ref":"slack-thread:T:C:one",
                          "request_id":"request-one",
                          "transport":"slack",
                          "delivery_ref":"slack-message:test",
                          "payload_digest":"sha256:{}",
                          "delivered_at":"2026-07-29T20:00:00Z"
                        }}"#,
                        "b".repeat(64),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delivery.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn rejects_non_loopback_bindings() {
        assert!(require_loopback("127.0.0.1:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("[::1]:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("0.0.0.0:8091".parse().unwrap()).is_err());
        assert!(require_loopback("10.0.0.4:8091".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn accepted_answers_report_grounded_and_safe_refusal_counts() {
        let app = test_router();
        let safe_refusal = app
            .clone()
            .oneshot(
                Request::post("/v1/answers/validate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-answer-candidate/v1",
                          "completed":true,
                          "markdown":"Narrow the request to one source.",
                          "trace_id":"trace-refusal",
                          "citation_validation":null,
                          "unsupported_query":{
                            "code":"post_processing_candidate_limit",
                            "reason":"The result is too broad.",
                            "suggested_rewrites":["Show Okta connector health."],
                            "supported_intents":["source_health"],
                            "trace_id":"trace-refusal"
                          }
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(safe_refusal.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(safe_refusal.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["disposition"], "safe_refusal");
        assert_eq!(body["verified"], false);

        let grounded = app
            .clone()
            .oneshot(
                Request::post("/v1/answers/validate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-answer-candidate/v1",
                          "completed":true,
                          "markdown":"Current Okta evidence cites two graph rows.",
                          "trace_id":"trace-grounded",
                          "citation_validation":{"ok":true,"referenced_urn_count":2,"row_urn_count":2},
                          "unsupported_query":null
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grounded.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(grounded.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["disposition"], "grounded");
        assert_eq!(body["verified"], true);

        let status = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &to_bytes(status.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["requests_total"], 2);
        assert_eq!(body["grounded_total"], 1);
        assert_eq!(body["safe_refusal_total"], 1);
        assert_eq!(body["rejected_total"], 0);
    }

    #[tokio::test]
    async fn route_rejects_an_unstructured_uncited_answer() {
        let app = test_router();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/answers/validate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-answer-candidate/v1",
                          "completed":true,
                          "markdown":"Everything is fine.",
                          "trace_id":"trace-unsupported",
                          "citation_validation":{"ok":false,"referenced_urn_count":0,"row_urn_count":0},
                          "unsupported_query":null
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let status_response = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(status_response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(status_response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["authority"], "rust");
        assert_eq!(body["status"], "ready");
        assert_eq!(body["requests_total"], 1);
        assert_eq!(body["rejected_total"], 1);
        assert_eq!(body["grounded_total"], 0);
        assert_eq!(body["safe_refusal_total"], 0);
        assert_eq!(body["question_authorized_total"], 0);
        assert_eq!(body["question_rejected_total"], 0);
    }

    #[tokio::test]
    async fn question_route_authorizes_only_the_configured_tenant() {
        let app = test_router();
        let authorized = app
            .clone()
            .oneshot(
                Request::post("/v1/questions/authorize")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-question-candidate/v1",
                          "tenant_id":"writer-sec-dev",
                          "request_id":"C0B2VJDFJ5N:1753830794.123",
                          "question":"Show connector health for Okta.",
                          "history":[]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized_body: Value = serde_json::from_slice(
            &to_bytes(authorized.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(authorized_body["execution_lane"], "lookup");
        assert!(authorized_body.get("answer").is_none());

        let conversational = app
            .clone()
            .oneshot(
                Request::post("/v1/questions/authorize")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-question-candidate/v1",
                          "tenant_id":"writer-sec-dev",
                          "request_id":"C0B2VJDFJ5N:1753830794.124",
                          "question":"What can you tell me about yourself and your work today?",
                          "history":[]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conversational.status(), StatusCode::OK);
        let conversational_body: Value = serde_json::from_slice(
            &to_bytes(conversational.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(conversational_body["execution_lane"], "converse");
        assert!(
            conversational_body["answer"]
                .as_str()
                .unwrap()
                .contains("verified cross-thread work log")
        );

        let rejected = app
            .clone()
            .oneshot(
                Request::post("/v1/questions/authorize")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                          "schema_version":"slack-question-candidate/v1",
                          "tenant_id":"other-tenant",
                          "request_id":"request-2",
                          "question":"Show connector health for Okta.",
                          "history":[]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let status_response = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &to_bytes(status_response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["question_authorized_total"], 2);
        assert_eq!(body["question_rejected_total"], 1);
        assert_eq!(body["requests_total"], 3);
    }
}
