use std::{
    env,
    error::Error,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use cerebro_slack_authority::{
    AnswerAuthorityError, AnswerCandidate, AnswerDecision, AnswerDisposition,
    QuestionAuthorityError, QuestionCandidate, QuestionDecision, QuestionExecutionLane,
    QuestionPolicy, authorize_question, validate_answer,
};
use serde::Serialize;

const DEFAULT_BIND: &str = "127.0.0.1:8091";
const MAX_REQUEST_BYTES: usize = 96 * 1024;

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

struct AuthorityRuntime {
    question_authorized_total: AtomicU64,
    question_rejected_total: AtomicU64,
    question_policy: QuestionPolicy,
    conversational_total: AtomicU64,
    grounded_total: AtomicU64,
    rejected_total: AtomicU64,
    safe_refusal_total: AtomicU64,
    started_at: Instant,
}

#[derive(Serialize)]
struct AuthorityStatus {
    authority: &'static str,
    component: &'static str,
    conversational_total: u64,
    grounded_total: u64,
    question_authorized_total: u64,
    question_rejected_total: u64,
    rejected_total: u64,
    requests_total: u64,
    safe_refusal_total: u64,
    schema_version: &'static str,
    status: &'static str,
    uptime_ms: u64,
    version: &'static str,
}

impl AuthorityRuntime {
    fn new(question_policy: QuestionPolicy) -> Self {
        Self {
            question_authorized_total: AtomicU64::new(0),
            question_rejected_total: AtomicU64::new(0),
            conversational_total: AtomicU64::new(0),
            grounded_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            safe_refusal_total: AtomicU64::new(0),
            started_at: Instant::now(),
            question_policy,
        }
    }

    fn status(&self) -> AuthorityStatus {
        let conversational_total = self.conversational_total.load(Ordering::Relaxed);
        let grounded_total = self.grounded_total.load(Ordering::Relaxed);
        let rejected_total = self.rejected_total.load(Ordering::Relaxed);
        let safe_refusal_total = self.safe_refusal_total.load(Ordering::Relaxed);
        let question_authorized_total = self.question_authorized_total.load(Ordering::Relaxed);
        let question_rejected_total = self.question_rejected_total.load(Ordering::Relaxed);
        AuthorityStatus {
            authority: "rust",
            component: "slack-answer-authority",
            conversational_total,
            grounded_total,
            question_authorized_total,
            question_rejected_total,
            rejected_total,
            requests_total: conversational_total
                .saturating_add(grounded_total)
                .saturating_add(rejected_total)
                .saturating_add(safe_refusal_total)
                .saturating_add(question_authorized_total)
                .saturating_add(question_rejected_total),
            safe_refusal_total,
            schema_version: "slack-answer-authority-status/v1",
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

pub async fn serve() -> Result<(), Box<dyn Error>> {
    let bind = env::var("CEREBRO_SLACK_AUTHORITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let address: SocketAddr = bind.parse()?;
    require_loopback(address)?;
    let tenant_id = env::var("CEREBRO_SLACK_AUTHORITY_TENANT_ID")
        .map_err(|_| "CEREBRO_SLACK_AUTHORITY_TENANT_ID is required")?;
    let question_policy = QuestionPolicy::new(tenant_id)?;
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
    axum::serve(listener, router(question_policy)).await?;
    Ok(())
}

fn router(question_policy: QuestionPolicy) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/status", get(authority_status_route))
        .route("/v1/questions/authorize", post(authorize_question_route))
        .route("/v1/answers/validate", post(validate_answer_route))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(AuthorityRuntime::new(question_policy)))
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
                AnswerDisposition::Conversational => {
                    runtime.conversational_total.fetch_add(1, Ordering::Relaxed);
                }
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
                    AnswerDisposition::Conversational => "conversational",
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
            "conversational_total": status.conversational_total,
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
        AnswerAuthorityError::ConversationEvidenceInvalid => "conversation_evidence_invalid",
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
        router(QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap())
    }

    #[test]
    fn rejects_non_loopback_bindings() {
        assert!(require_loopback("127.0.0.1:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("[::1]:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("0.0.0.0:8091".parse().unwrap()).is_err());
        assert!(require_loopback("10.0.0.4:8091".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn route_returns_the_rust_authority_decision() {
        let response = test_router()
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

        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["disposition"], "safe_refusal");
        assert_eq!(body["verified"], false);
    }

    #[tokio::test]
    async fn route_accepts_a_complete_conversational_loop_receipt() {
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
                          "markdown":"I’m Cerebro. Ask one concrete security question.",
                          "trace_id":"trace-conversation",
                          "conversation_validation":{
                            "ok":true,
                            "route":"converse",
                            "route_reason":"self_context",
                            "router_attempts":1,
                            "draft_attempts":1,
                            "critic_attempts":1,
                            "critic_approved":true,
                            "fallback_used":false,
                            "policy_check_ids":[
                              "capability_scope_bounded",
                              "identity_truthful",
                              "next_action_actionable",
                              "no_current_evidence_claims",
                              "work_scope_explicit"
                            ],
                            "requires_graph_query":false
                          }
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["disposition"], "conversational");
        assert_eq!(body["verified"], false);

        let status_response = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status: Value = serde_json::from_slice(
            &to_bytes(status_response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status["conversational_total"], 1);
        assert_eq!(status["requests_total"], 1);
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
        assert_eq!(conversational_body["execution_lane"], "lookup");
        assert!(conversational_body.get("answer").is_none());

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
