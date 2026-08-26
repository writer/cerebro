use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_source_catalog::{CollectionAuthority, HttpMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::CollectionRequest;

use super::request_setup::{qdrant_runtime, qdrant_source};

#[tokio::test]
async fn accounts_collect_project_restart_and_preserve_tenant_identity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4_096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /api/account/v1/accounts HTTP/1.1"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: apikey fixture-management-key")
            );
            let body = r#"{"items":[{"id":"account-1","name":"Production account","resource_type":"account"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let source = qdrant_source();
    // This closes the technical catalog contract only. Persisted authority
    // evidence is a separate promotion gate owned by the runtime ledger.
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let accounts = source
        .families()
        .iter()
        .find(|family| family.id() == "accounts")
        .unwrap();
    assert_eq!(accounts.method(), HttpMethod::Get);
    assert_eq!(accounts.path(), "/api/account/v1/accounts");
    assert_eq!(accounts.record_selector(), "$.items[*]");
    assert_eq!(accounts.id_field(), "id");
    assert_eq!(accounts.projection().template(), "asset");

    let base_url = format!("http://{address}");
    let tenant_a = TenantId::parse("tenant-a").unwrap();
    let runtime_id = SourceRuntimeId::parse("qdrant-production").unwrap();
    let request = || CollectionRequest {
        tenant_id: tenant_a.clone(),
        source_runtime_id: runtime_id.clone(),
        cursor: None,
    };

    let mut first = qdrant_runtime(
        &source,
        "accounts",
        tenant_a.as_str(),
        runtime_id.as_str(),
        &base_url,
        1,
        OrganizationalGraph::new(),
    );
    let first_receipt = first.sync(request()).await.unwrap();
    assert_eq!(first_receipt.entities_upserted, 1);
    let graph = first.into_store();
    let first_entities = graph.entities(&tenant_a);
    assert_eq!(first_entities.len(), 1);
    let first_entity = &first_entities[0];
    let stable_id = first_entity.id().clone();
    assert_eq!(first_entity.label(), "Production account");
    assert_eq!(
        first_entity
            .properties()
            .get("resource_id")
            .map(String::as_str),
        Some("account-1")
    );
    assert!(
        first_entity
            .agent_key()
            .starts_with("urn:cerebro:tenant-a:organizational_entity:")
    );

    let mut restarted = qdrant_runtime(
        &source,
        "accounts",
        tenant_a.as_str(),
        runtime_id.as_str(),
        &base_url,
        2,
        graph,
    );
    restarted.sync(request()).await.unwrap();
    let graph = restarted.into_store();
    let restarted_entities = graph.entities(&tenant_a);
    assert_eq!(restarted_entities.len(), 1);
    assert_eq!(restarted_entities[0].id(), &stable_id);

    let tenant_b = TenantId::parse("tenant-b").unwrap();
    let mut second_tenant = qdrant_runtime(
        &source,
        "accounts",
        tenant_b.as_str(),
        runtime_id.as_str(),
        &base_url,
        1,
        graph,
    );
    second_tenant
        .sync(CollectionRequest {
            tenant_id: tenant_b.clone(),
            source_runtime_id: runtime_id,
            cursor: None,
        })
        .await
        .unwrap();
    let graph = second_tenant.into_store();
    let second_tenant_entities = graph.entities(&tenant_b);
    assert_eq!(second_tenant_entities.len(), 1);
    assert_ne!(second_tenant_entities[0].id(), &stable_id);
    assert_eq!(graph.entities(&tenant_a).len(), 1);
    server.await.unwrap();
}
