use std::collections::BTreeMap;

use cerebro_source_catalog::CompiledSource;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use crate::{
    CredentialLeaseReference, EgressPolicy, EgressRequestContext, HttpProviderAccess,
    HttpSourceConnector, OperationScopedCredentialLease, ResolvedAuth, SourceRuntimeOperation,
};

pub(super) struct ProviderFixture {
    pub(super) base_url: String,
    task: JoinHandle<()>,
}

impl ProviderFixture {
    pub(super) async fn start(collections: usize) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..collections * 2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4_096];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let request_line = request.lines().next().unwrap();
                assert!(request_line.starts_with("GET /v1beta/models?"));
                assert!(request_line.contains("pageSize=100"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("x-goog-api-key: synthetic-gemini-key")
                );
                let body = if request_line.contains("pageToken=page-2") {
                    r#"{"models":[{"name":"models/gemini-2","displayName":"Gemini 2"}]}"#
                } else {
                    r#"{"models":[{"name":"models/gemini-1","displayName":"Gemini 1"}],"nextPageToken":"page-2"}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            base_url: format!("http://{address}"),
            task,
        }
    }

    pub(super) async fn finish(self) {
        self.task.await.unwrap();
    }
}

pub(super) fn connector(
    source: &CompiledSource,
    tenant_id: &str,
    runtime_id: &str,
    base_url: &str,
    generation: u64,
) -> HttpSourceConnector {
    let request_intent_digest = "a".repeat(64);
    let context = EgressRequestContext {
        tenant_id: tenant_id.to_owned(),
        runtime_id: runtime_id.to_owned(),
        source_id: "google_gemini".to_owned(),
        family_id: "model_catalog".to_owned(),
        operation: SourceRuntimeOperation::ReadPage,
        request_intent_digest: request_intent_digest.clone(),
        logical_page_id: format!("model-catalog-page-{generation}"),
        source_generation: generation,
        authority_epoch: 1,
    };
    let credential_lease = OperationScopedCredentialLease::new(
        CredentialLeaseReference::new(
            format!("gemini-model-catalog-lease-{generation}"),
            context.lease_scope().unwrap(),
            1_000,
            1_000,
        )
        .unwrap(),
    );
    let egress_policy = EgressPolicy::live(
        tenant_id,
        "model_catalog",
        &request_intent_digest,
        [base_url],
    )
    .unwrap();
    let auth = ResolvedAuth::Header {
        name: "x-goog-api-key".to_owned(),
        value: "synthetic-gemini-key".to_owned(),
    };
    assert!(!format!("{auth:?}").contains("synthetic-gemini-key"));
    HttpSourceConnector::new(
        source.clone(),
        "model_catalog",
        base_url,
        BTreeMap::new(),
        auth,
    )
    .unwrap()
    .with_provider_access(HttpProviderAccess::new_with_clock(
        context,
        egress_policy,
        credential_lease,
        1_500,
    ))
}
