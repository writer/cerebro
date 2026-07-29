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
use cerebro_slack_authority::{AnswerCandidate, AnswerDecision, validate_answer};
use serde::Serialize;

const DEFAULT_BIND: &str = "127.0.0.1:8091";
const MAX_REQUEST_BYTES: usize = 96 * 1024;

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

struct AuthorityRuntime {
    grounded_total: AtomicU64,
    rejected_total: AtomicU64,
    safe_refusal_total: AtomicU64,
    started_at: Instant,
}

#[derive(Serialize)]
struct AuthorityStatus {
    authority: &'static str,
    component: &'static str,
    grounded_total: u64,
    rejected_total: u64,
    requests_total: u64,
    safe_refusal_total: u64,
    schema_version: &'static str,
    status: &'static str,
    uptime_ms: u64,
    version: &'static str,
}

impl AuthorityRuntime {
    fn new() -> Self {
        Self {
            grounded_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            safe_refusal_total: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    fn status(&self) -> AuthorityStatus {
        let grounded_total = self.grounded_total.load(Ordering::Relaxed);
        let rejected_total = self.rejected_total.load(Ordering::Relaxed);
        let safe_refusal_total = self.safe_refusal_total.load(Ordering::Relaxed);
        AuthorityStatus {
            authority: "rust",
            component: "slack-answer-authority",
            grounded_total,
            rejected_total,
            requests_total: grounded_total
                .saturating_add(rejected_total)
                .saturating_add(safe_refusal_total),
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
    axum::serve(listener, router()).await?;
    Ok(())
}

fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/status", get(authority_status_route))
        .route("/v1/answers/validate", post(validate_answer_route))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(AuthorityRuntime::new()))
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
                cerebro_slack_authority::AnswerDisposition::Grounded => {
                    runtime.grounded_total.fetch_add(1, Ordering::Relaxed);
                }
                cerebro_slack_authority::AnswerDisposition::SafeRefusal => {
                    runtime.safe_refusal_total.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Json(decision))
        }
        Err(error) => {
            runtime.rejected_total.fetch_add(1, Ordering::Relaxed);
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

    #[test]
    fn rejects_non_loopback_bindings() {
        assert!(require_loopback("127.0.0.1:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("[::1]:8091".parse().unwrap()).is_ok());
        assert!(require_loopback("0.0.0.0:8091".parse().unwrap()).is_err());
        assert!(require_loopback("10.0.0.4:8091".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn route_returns_the_rust_authority_decision() {
        let response = router()
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
    async fn route_rejects_an_unstructured_uncited_answer() {
        let app = router();
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
    }
}
