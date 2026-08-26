//! Bounded HTTP request metrics and structured completion events.
//!
//! One middleware owns request classification, latency metrics, and the
//! `span_end` JSON line. Caller-controlled paths are collapsed before they
//! reach metric labels or structured events. Tenant identifiers and request
//! bodies are never recorded.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{MatchedPath, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex;

const EVENT_SCHEMA_VERSION: &str = "2026-06-19.1";
const LATENCY_BUCKETS_SECONDS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

#[derive(Clone, Default)]
pub(crate) struct PlatformMetrics(Arc<Mutex<BTreeMap<&'static str, RequestSeries>>>);

#[derive(Default)]
struct RequestSeries {
    successes: u64,
    failures: u64,
    duration_sum_seconds: f64,
    duration_buckets: [u64; 8],
}

pub(crate) async fn record_request(
    State(metrics): State<PlatformMetrics>,
    request: Request,
    next: Next,
) -> Response {
    let operation = bounded_operation(request.method(), request.uri().path());
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();

    metrics
        .record(operation, response.status(), elapsed.as_secs_f64())
        .await;
    emit_http_span_end(&HttpSpanEnd {
        method: &method,
        route: &route,
        status_code: response.status().as_u16(),
        duration: elapsed,
    });
    response
}

pub(crate) fn bounded_operation(method: &Method, path: &str) -> &'static str {
    match path {
        "/healthz" => "healthz",
        "/readyz" => "readyz",
        "/metrics" => "metrics",
        "/v1/me" => "current_user",
        "/v1/finding-validations" => "record_finding_validation",
        "/v1/action-definitions" => "action_definitions",
        "/v1/policy-definitions" => "policy_definitions",
        "/v1/action-dispatches" => "list_action_dispatches",
        "/v1/action-reconciliation-runs" => "run_action_reconciliation",
        "/v1/sources/summary" => "source_summary",
        "/v1/audit-events" => "list_audit_events",
        "/v1/identity/orgs" => "list_identity_orgs",
        "/v1/identity/users" => "list_identity_users",
        "/platform/graph/neighborhood" => "neighborhood",
        "/v1/graph/search" => "search",
        "/v1/graph/expand" => "expand",
        "/v1/graph/expand-batch" => "expand_batch",
        "/v1/graph/paths" => "paths",
        "/v1/graph/provenance" | "/platform/graph/provenance" => "graph_provenance",
        "/v1/security/lifecycle" => "security_lifecycle",
        "/v1/ask-queries" if method == Method::GET => "list_ask_queries",
        "/v1/ask-queries" => "create_ask_query",
        _ if path.starts_with("/v1/ask-queries/") && method == Method::DELETE => "delete_ask_query",
        _ if path.starts_with("/v1/ask-queries/") => "update_ask_query",
        "/v1/source-runtimes" => "list_source_runtimes",
        "/v1/source-runtimes/freshness" => "runtime_freshness",
        _ if path.starts_with("/v1/source-runtimes/") && path.ends_with("/invalid-events") => {
            "list_source_runtime_invalid_events"
        }
        _ if path.starts_with("/v1/source-runtimes/") && method == Method::PUT => {
            "put_source_runtime"
        }
        _ if path.starts_with("/v1/source-runtimes/") && path.ends_with("/sync") => {
            "sync_source_runtime"
        }
        _ if path.starts_with("/v1/source-runtimes/") => "get_source_runtime",
        "/v1/actions" if method == Method::GET => "list_actions",
        "/v1/actions" => "propose_action",
        "/v1/projections/legacy-deltas" => "record_legacy_projection",
        "/v1/projections/collections" => "record_source_collection",
        _ if path.starts_with("/v1/projections/collections/") => "get_source_collection",
        "/v1/projections/authority" => "projection_authority",
        _ if path.starts_with("/v1/entities/") => "get_entity",
        _ if path.starts_with("/v1/finding-validations/") => "get_finding_validation",
        _ if path.starts_with("/v1/action-dispatches/") => "get_action_dispatch",
        _ if path.starts_with("/v1/assertions/") => "explain_assertion",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/history") => "action_history",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/provider-observation") => {
            "observe_action_provider"
        }
        _ if path.starts_with("/v1/actions/") && path.ends_with("/commands") => "transition_action",
        _ if path.starts_with("/v1/actions/") => "get_action",
        _ if path.starts_with("/cerebro.graph.v1.OrganizationalGraphService/") => "connect_rpc",
        _ if path.starts_with("/cerebro.v1.SecurityLifecycleService/") => "security_lifecycle",
        _ => "other",
    }
}

impl PlatformMetrics {
    async fn record(&self, operation: &'static str, status: StatusCode, elapsed_seconds: f64) {
        let mut metrics = self.0.lock().await;
        let series = metrics.entry(operation).or_default();
        if status.is_success() {
            series.successes += 1;
        } else {
            series.failures += 1;
        }
        series.duration_sum_seconds += elapsed_seconds;
        for (index, upper_bound) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if elapsed_seconds <= *upper_bound {
                series.duration_buckets[index] += 1;
            }
        }
    }

    pub(crate) async fn render(&self) -> String {
        let metrics = self.0.lock().await;
        let mut output = String::from(
            "# HELP cerebro_rust_http_requests_total Bounded Rust platform HTTP requests.\n\
             # TYPE cerebro_rust_http_requests_total counter\n\
             # HELP cerebro_rust_http_request_duration_seconds Rust platform request latency.\n\
             # TYPE cerebro_rust_http_request_duration_seconds histogram\n",
        );
        for (operation, series) in metrics.iter() {
            output.push_str(&format!(
                "cerebro_rust_http_requests_total{{operation=\"{operation}\",status_class=\"success\"}} {}\n",
                series.successes
            ));
            output.push_str(&format!(
                "cerebro_rust_http_requests_total{{operation=\"{operation}\",status_class=\"failure\"}} {}\n",
                series.failures
            ));
            for (upper_bound, count) in LATENCY_BUCKETS_SECONDS
                .iter()
                .zip(series.duration_buckets.iter())
            {
                output.push_str(&format!(
                    "cerebro_rust_http_request_duration_seconds_bucket{{operation=\"{operation}\",le=\"{upper_bound}\"}} {count}\n"
                ));
            }
            let count = series.successes + series.failures;
            output.push_str(&format!(
                "cerebro_rust_http_request_duration_seconds_bucket{{operation=\"{operation}\",le=\"+Inf\"}} {count}\n\
                 cerebro_rust_http_request_duration_seconds_sum{{operation=\"{operation}\"}} {}\n\
                 cerebro_rust_http_request_duration_seconds_count{{operation=\"{operation}\"}} {count}\n",
                series.duration_sum_seconds
            ));
        }
        output
    }
}

struct HttpSpanEnd<'a> {
    pub method: &'a str,
    pub route: &'a str,
    pub status_code: u16,
    pub duration: Duration,
}

fn http_span_end_payload(span: &HttpSpanEnd<'_>, ts: OffsetDateTime) -> Value {
    let status = if span.status_code >= 500 {
        "failed"
    } else {
        "completed"
    };
    let mut payload = Map::new();
    payload.insert("kind".to_owned(), json!("span_end"));
    payload.insert("name".to_owned(), json!("http.server"));
    payload.insert(
        "ts".to_owned(),
        json!(
            ts.format(&Rfc3339)
                .expect("Rfc3339 supports OffsetDateTime")
        ),
    );
    payload.insert(
        "telemetry.schema.version".to_owned(),
        json!(EVENT_SCHEMA_VERSION),
    );
    payload.insert("event.dataset".to_owned(), json!("cerebro.telemetry"));
    payload.insert("telemetry.signal.kind".to_owned(), json!("span"));
    payload.insert("component".to_owned(), json!("http-middleware"));
    payload.insert("operation".to_owned(), json!(span.method));
    payload.insert("http.request.method".to_owned(), json!(span.method));
    payload.insert("http.route".to_owned(), json!(span.route));
    payload.insert(
        "http.response.status_code".to_owned(),
        json!(span.status_code),
    );
    payload.insert("status".to_owned(), json!(status));
    payload.insert("operation.name".to_owned(), json!("http.server"));
    payload.insert("operation.status".to_owned(), json!(status));
    payload.insert("event.type".to_owned(), json!("end"));
    payload.insert("event.outcome".to_owned(), json!(event_outcome(status)));
    payload.insert(
        "duration_ms".to_owned(),
        json!(u64::try_from(span.duration.as_millis()).unwrap_or(u64::MAX)),
    );
    payload.insert(
        "duration.bucket".to_owned(),
        json!(duration_bucket(span.duration)),
    );
    Value::Object(payload)
}

fn emit_http_span_end(span: &HttpSpanEnd<'_>) {
    let payload = http_span_end_payload(span, OffsetDateTime::now_utc());
    eprintln!("{payload}");
}

fn event_outcome(status: &str) -> &'static str {
    match status {
        "failed" | "error" => "failure",
        "" | "canceled" | "cancelled" => "unknown",
        _ => "success",
    }
}

fn duration_bucket(duration: Duration) -> &'static str {
    let millis = duration.as_millis();
    match millis {
        _ if millis < 10 => "lt_10ms",
        _ if millis < 50 => "lt_50ms",
        _ if millis < 100 => "lt_100ms",
        _ if millis < 250 => "lt_250ms",
        _ if millis < 500 => "lt_500ms",
        _ if millis < 1_000 => "lt_1s",
        _ if millis < 5_000 => "lt_5s",
        _ if millis < 30_000 => "lt_30s",
        _ if millis < 60_000 => "lt_1m",
        _ if millis < 300_000 => "lt_5m",
        _ if millis < 1_800_000 => "lt_30m",
        _ => "gte_30m",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ts() -> OffsetDateTime {
        OffsetDateTime::parse("2026-08-26T12:00:00Z", &Rfc3339).expect("valid test timestamp")
    }

    #[test]
    fn duration_buckets_follow_schema_boundaries() {
        assert_eq!(duration_bucket(Duration::from_millis(0)), "lt_10ms");
        assert_eq!(duration_bucket(Duration::from_millis(9)), "lt_10ms");
        assert_eq!(duration_bucket(Duration::from_millis(10)), "lt_50ms");
        assert_eq!(duration_bucket(Duration::from_millis(49)), "lt_50ms");
        assert_eq!(duration_bucket(Duration::from_millis(99)), "lt_100ms");
        assert_eq!(duration_bucket(Duration::from_millis(249)), "lt_250ms");
        assert_eq!(duration_bucket(Duration::from_millis(499)), "lt_500ms");
        assert_eq!(duration_bucket(Duration::from_millis(999)), "lt_1s");
        assert_eq!(duration_bucket(Duration::from_millis(4_999)), "lt_5s");
        assert_eq!(duration_bucket(Duration::from_millis(29_999)), "lt_30s");
        assert_eq!(duration_bucket(Duration::from_millis(59_999)), "lt_1m");
        assert_eq!(duration_bucket(Duration::from_secs(299)), "lt_5m");
        assert_eq!(duration_bucket(Duration::from_secs(1_799)), "lt_30m");
        assert_eq!(duration_bucket(Duration::from_secs(1_800)), "gte_30m");
    }

    #[test]
    fn outcome_mapping_is_bounded() {
        assert_eq!(event_outcome("completed"), "success");
        assert_eq!(event_outcome("failed"), "failure");
        assert_eq!(event_outcome("error"), "failure");
        assert_eq!(event_outcome(""), "unknown");
        assert_eq!(event_outcome("canceled"), "unknown");
    }

    #[test]
    fn success_payload_carries_request_event_fields() {
        let payload = http_span_end_payload(
            &HttpSpanEnd {
                method: "GET",
                route: "/v1/source-runtimes/health",
                status_code: 200,
                duration: Duration::from_millis(42),
            },
            test_ts(),
        );
        assert_eq!(payload["kind"], "span_end");
        assert_eq!(payload["name"], "http.server");
        assert_eq!(payload["operation.name"], "http.server");
        assert_eq!(payload["component"], "http-middleware");
        assert_eq!(payload["http.request.method"], "GET");
        assert_eq!(payload["http.route"], "/v1/source-runtimes/health");
        assert_eq!(payload["http.response.status_code"], 200);
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["operation.status"], "completed");
        assert_eq!(payload["event.type"], "end");
        assert_eq!(payload["event.outcome"], "success");
        assert_eq!(payload["duration_ms"], 42);
        assert_eq!(payload["duration.bucket"], "lt_50ms");
        assert_eq!(payload["telemetry.schema.version"], "2026-06-19.1");
        assert_eq!(payload["event.dataset"], "cerebro.telemetry");
        assert_eq!(payload["telemetry.signal.kind"], "span");
        assert_eq!(payload["ts"], "2026-08-26T12:00:00Z");
    }

    #[test]
    fn server_errors_report_failed_and_failure() {
        let payload = http_span_end_payload(
            &HttpSpanEnd {
                method: "POST",
                route: "/v1/ask-queries",
                status_code: 503,
                duration: Duration::from_millis(1),
            },
            test_ts(),
        );
        assert_eq!(payload["status"], "failed");
        assert_eq!(payload["operation.status"], "failed");
        assert_eq!(payload["event.outcome"], "failure");
        let client_error = http_span_end_payload(
            &HttpSpanEnd {
                method: "GET",
                route: "/v1/identity/orgs",
                status_code: 404,
                duration: Duration::from_millis(1),
            },
            test_ts(),
        );
        assert_eq!(client_error["status"], "completed");
        assert_eq!(client_error["event.outcome"], "success");
    }

    #[test]
    fn operation_labels_are_bounded_and_never_copy_unknown_paths() {
        assert_eq!(bounded_operation(&Method::GET, "/healthz"), "healthz");
        assert_eq!(
            bounded_operation(&Method::DELETE, "/v1/ask-queries/query-123"),
            "delete_ask_query"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/entities/customer-controlled-id"),
            "get_entity"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/unknown/customer-controlled-id"),
            "other"
        );
    }

    #[tokio::test]
    async fn metrics_render_success_failure_and_latency_counts() {
        let metrics = PlatformMetrics::default();
        metrics.record("healthz", StatusCode::OK, 0.004).await;
        metrics
            .record("healthz", StatusCode::SERVICE_UNAVAILABLE, 0.010)
            .await;

        let rendered = metrics.render().await;
        assert!(rendered.contains(
            "cerebro_rust_http_requests_total{operation=\"healthz\",status_class=\"success\"} 1"
        ));
        assert!(rendered.contains(
            "cerebro_rust_http_requests_total{operation=\"healthz\",status_class=\"failure\"} 1"
        ));
        assert!(
            rendered.contains(
                "cerebro_rust_http_request_duration_seconds_count{operation=\"healthz\"} 2"
            )
        );
    }
}
