use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
};
use cerebro_action_catalog::lookup;
use cerebro_action_provider::{
    AccessApprovalsClient, AccessApprovalsConfig, ProviderError, ProviderStatus,
};
use cerebro_action_store::ActionDispatch;
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{ActorId, ContentDigest, OpaqueId};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone, Default)]
struct Capture {
    requests: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
}

#[tokio::test]
async fn dispatch_posts_a_bound_request_and_returns_content_digested_evidence() {
    let capture = Capture::default();
    let app =
        Router::new()
            .route(
                "/root/admin/okta-jail/suspend",
                post(
                    |State(capture): State<Capture>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        capture
                            .requests
                            .lock()
                            .unwrap()
                            .push((headers, body.clone()));
                        Json(provider_response(&body, "provider-action:one", "queued"))
                    },
                ),
            )
            .with_state(capture.clone());
    let (base_url, server) = serve(app).await;
    let client = client(format!("{base_url}/root/"));
    let dispatch = dispatch();

    let receipt = client.dispatch(&dispatch).await.expect("provider receipt");
    assert_eq!(receipt.external_id.as_str(), "provider-action:one");
    assert_eq!(receipt.status, ProviderStatus::Queued);
    assert!(!receipt.status.is_terminal());
    assert_eq!(receipt.updated_at_unix_s, Some(42));
    assert_eq!(receipt.completed_at_unix_s, None);
    assert!(matches!(
        receipt.record_command(ActorId::parse("worker:one").expect("actor"), 42_000),
        ActionCommand::RecordProviderReceipt {
            provider_status,
            observed_at_unix_ms: 42_000,
            ..
        } if provider_status == "queued"
    ));

    let requests = capture.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let (headers, body) = &requests[0];
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer provider-token"
    );
    assert_eq!(body["email_or_user_id"], dispatch.target_id);
    assert_eq!(body["idempotency_key"], dispatch.idempotency_key);
    assert_eq!(body["tenant_id"], dispatch.tenant_id);
    assert_eq!(body["finding_id"], dispatch.finding_id);
    assert_eq!(body["source"], "cerebro:graph_action");
    assert_eq!(
        receipt.request_digest,
        Some(ContentDigest::of_bytes(
            br#"{"email_or_user_id":"okta-user:one","source":"cerebro:graph_action","idempotency_key":"idempotency:one","tenant_id":"tenant:one","finding_id":"finding:one"}"#
        ))
    );
    let expected = serde_json::to_vec(&provider_response(body, "provider-action:one", "queued"))
        .expect("provider JSON");
    assert_eq!(
        receipt.response_digest,
        ContentDigest::of_bytes(expected),
        "the digest must bind the exact provider response bytes"
    );
    server.abort();
}

#[tokio::test]
async fn observation_requires_the_same_external_action_and_dispatch_bindings() {
    let app = Router::new().route(
        "/admin/okta-jail/actions/{action_id}",
        get(|Path(action_id): Path<String>| async move {
            assert_eq!(action_id, "provider-action:one");
            Json(json!({
                "id": "provider-action:one",
                "action": "suspend",
                "status": "succeeded",
                "target": "okta-user:one",
                "idempotency_key": "idempotency:one",
                "tenant_id": "tenant:one",
                "finding_id": "finding:one",
                "updated_at_unix": 43,
                "completed_at_unix": 43
            }))
        }),
    );
    let (base_url, server) = serve(app).await;
    let client = client(base_url);
    let dispatch = dispatch();

    let receipt = client
        .observe(
            &dispatch,
            &OpaqueId::parse("provider-action:one").expect("external id"),
        )
        .await
        .expect("provider observation");
    assert_eq!(receipt.status, ProviderStatus::Succeeded);
    assert!(receipt.status.is_terminal());
    assert_eq!(receipt.completed_at_unix_s, Some(43));
    assert_eq!(receipt.request_digest, None);
    let reconciler = ActorId::parse("reconciler:one").expect("reconciler actor");
    assert!(matches!(
        receipt.observation_command(reconciler.clone(), 43_000),
        ActionCommand::ObserveProviderReceipt {
            provider_status,
            reconciler_actor_id,
            observed_at_unix_ms: 43_000,
            ..
        } if provider_status == "succeeded" && reconciler_actor_id == reconciler
    ));
    server.abort();
}

#[tokio::test]
async fn dispatch_never_follows_redirects_or_retries_ambiguous_responses() {
    let redirected = Arc::new(AtomicUsize::new(0));
    let redirected_state = redirected.clone();
    let app = Router::new()
        .route(
            "/admin/okta-jail/suspend",
            post(|| async { Redirect::temporary("/credential-capture") }),
        )
        .route(
            "/credential-capture",
            post(move || {
                let redirected = redirected_state.clone();
                async move {
                    redirected.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        );
    let (base_url, server) = serve(app).await;
    let client = client(base_url);

    assert_eq!(
        client.dispatch(&dispatch()).await,
        Err(ProviderError::DispatchAmbiguous)
    );
    assert_eq!(redirected.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn dispatch_classifies_rejection_ambiguity_and_unbounded_success_fail_closed() {
    let cases = BTreeMap::from([
        (
            "/rejected",
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "application/json",
                "{}".to_owned(),
            ),
        ),
        (
            "/ambiguous",
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "application/json",
                "{}".to_owned(),
            ),
        ),
        (
            "/oversized",
            (
                StatusCode::OK,
                "application/json",
                format!("{{\"id\":\"{}\"}}", "a".repeat((1 << 20) + 1)),
            ),
        ),
    ]);
    for (prefix, (status, content_type, body)) in cases {
        let path = format!("{prefix}/admin/okta-jail/suspend");
        let app = Router::new().route(
            &path,
            post(move || {
                let body = body.clone();
                async move {
                    (
                        status,
                        [(axum::http::header::CONTENT_TYPE, content_type)],
                        body,
                    )
                }
            }),
        );
        let (base_url, server) = serve(app).await;
        let client = client(format!("{base_url}{prefix}"));
        let error = client
            .dispatch(&dispatch())
            .await
            .expect_err("response must fail closed");
        match prefix {
            "/rejected" => assert_eq!(
                error,
                ProviderError::DispatchRejected {
                    status: StatusCode::UNPROCESSABLE_ENTITY.as_u16()
                }
            ),
            "/ambiguous" | "/oversized" => {
                assert_eq!(error, ProviderError::DispatchAmbiguous)
            }
            _ => unreachable!(),
        }
        server.abort();
    }
}

#[tokio::test]
async fn dispatch_rejects_provider_responses_that_do_not_echo_authority_bindings() {
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_for_handler = requests.clone();
    let app = Router::new().route(
        "/admin/okta-jail/suspend",
        post(move |Json(body): Json<Value>| {
            let requests = requests_for_handler.clone();
            async move {
                requests.fetch_add(1, Ordering::SeqCst);
                let mut response = provider_response(&body, "provider-action:one", "queued");
                response["tenant_id"] = json!("tenant:other");
                Json(response)
            }
        }),
    );
    let (base_url, server) = serve(app).await;
    let client = client(base_url);
    assert_eq!(
        client.dispatch(&dispatch()).await,
        Err(ProviderError::DispatchAmbiguous),
        "a successful but unbound response leaves mutation outcome unknown"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "the provider response binding must be checked after a valid dispatch is sent"
    );
    server.abort();
}

#[test]
fn configuration_rejects_credential_leaks_plaintext_and_unbounded_values() {
    for base_url in [
        "http://approvals.example.com",
        "https://user:password@approvals.example.com",
        "https://approvals.example.com?token=value",
        "https://approvals.example.com#credential",
        " https://approvals.example.com",
    ] {
        assert!(matches!(
            AccessApprovalsClient::new(AccessApprovalsConfig::new(base_url, "token")),
            Err(ProviderError::InvalidConfiguration(_))
        ));
    }
    assert!(
        AccessApprovalsClient::new(AccessApprovalsConfig::new(
            "https://approvals.example.com",
            "token\nforwarded"
        ))
        .is_err()
    );
    let mut too_fast = AccessApprovalsConfig::new("https://approvals.example.com", "token");
    too_fast.timeout = Duration::from_millis(99);
    assert!(AccessApprovalsClient::new(too_fast).is_err());
    let mut too_slow = AccessApprovalsConfig::new("https://approvals.example.com", "token");
    too_slow.timeout = Duration::from_secs(61);
    assert!(AccessApprovalsClient::new(too_slow).is_err());
}

fn client(base_url: String) -> AccessApprovalsClient {
    AccessApprovalsClient::new(AccessApprovalsConfig {
        base_url,
        bearer_token: "provider-token".to_owned(),
        timeout: Duration::from_secs(1),
    })
    .expect("client")
}

fn dispatch() -> ActionDispatch {
    let definition = lookup("identity.okta.suspend_user").expect("generated Action definition");
    let mut dispatch = ActionDispatch {
        tenant_id: "tenant:one".to_owned(),
        operation_id: "operation:one".to_owned(),
        operation_version: 6,
        proposal_digest: ContentDigest::of_bytes("proposal").to_string(),
        finding_id: "finding:one".to_owned(),
        finding_revision_digest: ContentDigest::of_bytes("finding revision").to_string(),
        finding_validation_receipt_digest: ContentDigest::of_bytes("finding validation")
            .to_string(),
        graph_revision: 1,
        action_kind: "identity.okta.suspend_user".to_owned(),
        action_definition_digest: definition.definition_digest.to_owned(),
        provider: definition.provider.to_owned(),
        provider_action: definition.provider_action.to_owned(),
        target_kind: definition.target_kind.to_owned(),
        target_id: "okta-user:one".to_owned(),
        effect: definition.effect.to_owned(),
        idempotency_key: "idempotency:one".to_owned(),
        requested_by: "worker:one".to_owned(),
        requested_at_unix_ms: 42,
        dispatch_digest: ContentDigest::of_bytes("dispatch").to_string(),
    };
    dispatch.dispatch_digest = dispatch
        .computed_digest()
        .expect("dispatch digest")
        .to_string();
    dispatch.validate().expect("valid dispatch");
    dispatch
}

fn provider_response(request: &Value, id: &str, status: &str) -> Value {
    json!({
        "id": id,
        "action": "suspend",
        "status": status,
        "target": request["email_or_user_id"],
        "idempotency_key": request["idempotency_key"],
        "tenant_id": request["tenant_id"],
        "finding_id": request["finding_id"],
        "updated_at_unix": 42
    })
}

async fn serve(app: Router) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("server address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("test server");
    });
    (format!("http://{address}"), task)
}
