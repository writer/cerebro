use std::{env, error::Error, net::SocketAddr};

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
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

pub async fn serve() -> Result<(), Box<dyn Error>> {
    let bind = env::var("CEREBRO_SLACK_AUTHORITY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let address: SocketAddr = bind.parse()?;
    require_loopback(address)?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router()).await?;
    Ok(())
}

fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/answers/validate", post(validate_answer_route))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
}

async fn validate_answer_route(
    Json(candidate): Json<AnswerCandidate>,
) -> Result<Json<AnswerDecision>, (StatusCode, Json<ErrorResponse>)> {
    validate_answer(candidate).map(Json).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                code: "answer_rejected",
                message: error.to_string(),
            }),
        )
    })
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
        let response = router()
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
    }
}
