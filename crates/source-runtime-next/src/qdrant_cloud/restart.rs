use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{SourceRuntimeId, TenantId};

use crate::{CollectionRequest, ProviderFailureKind, RuntimeError};

use super::{
    fixture_server::{accept_request, assert_cluster_request, write_json, write_rate_limit},
    request_setup::{qdrant_runtime, qdrant_source},
};

const PAGE_ONE: &str = r#"{"items":[{"id":"cluster-1","name":"Cluster one","status":"ready"}],"next_page_token":"page-2"}"#;
const PAGE_TWO: &str =
    r#"{"items":[{"id":"cluster-2","name":"Cluster two","status":"ready"}],"next_page_token":""}"#;

#[tokio::test]
async fn clusters_retry_and_restart_without_duplicate_identities() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for request_index in 0..6 {
            let (socket, request) = accept_request(&listener).await;
            assert_cluster_request(&request, "account-fixture");
            let second_page = request_index % 2 == 1;
            if second_page {
                assert!(request.contains("page_token=page-2"));
            } else {
                assert!(!request.contains("page_token="));
            }
            if request_index == 1 {
                write_rate_limit(socket).await;
            } else {
                write_json(socket, if second_page { PAGE_TWO } else { PAGE_ONE }).await;
            }
        }
    });

    let source = qdrant_source();
    let base_url = format!("http://{address}");
    let tenant = TenantId::parse("tenant-clusters-restart").unwrap();
    let runtime_id = SourceRuntimeId::parse("qdrant-clusters-restart").unwrap();
    let request = || CollectionRequest {
        tenant_id: tenant.clone(),
        source_runtime_id: runtime_id.clone(),
        cursor: None,
    };

    let mut interrupted = qdrant_runtime(
        &source,
        "clusters",
        tenant.as_str(),
        runtime_id.as_str(),
        &base_url,
        1,
        OrganizationalGraph::new(),
    );
    let error = interrupted.sync(request()).await.unwrap_err();
    let RuntimeError::Collect(error) = error else {
        panic!("interrupted collection failed outside the provider boundary");
    };
    let classification = error.provider_failure_classification().unwrap();
    assert_eq!(classification.kind, ProviderFailureKind::RetryAfter);
    assert!(classification.retryable);
    assert!(!classification.advances_progress);
    let graph = interrupted.into_store();
    assert!(graph.entities(&tenant).is_empty());
    assert_eq!(graph.graph_revision(&tenant), 0);

    let mut resumed = qdrant_runtime(
        &source,
        "clusters",
        tenant.as_str(),
        runtime_id.as_str(),
        &base_url,
        2,
        graph,
    );
    assert_eq!(resumed.sync(request()).await.unwrap().entities_upserted, 2);
    let graph = resumed.into_store();
    let first_ids = graph
        .entities(&tenant)
        .into_iter()
        .map(|entity| entity.id().clone())
        .collect::<Vec<_>>();
    assert_eq!(first_ids.len(), 2);

    let mut restarted = qdrant_runtime(
        &source,
        "clusters",
        tenant.as_str(),
        runtime_id.as_str(),
        &base_url,
        3,
        graph,
    );
    restarted.sync(request()).await.unwrap();
    let restarted_ids = restarted
        .into_store()
        .entities(&tenant)
        .into_iter()
        .map(|entity| entity.id().clone())
        .collect::<Vec<_>>();
    assert_eq!(restarted_ids, first_ids);
    server.await.unwrap();
}
