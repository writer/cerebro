use cerebro_organizational_model::{SourceRuntimeId, TenantId};

use crate::{CollectedScope, CollectionRequest, SourceConnector};

use super::{
    fixture_server::{accept_request, assert_cluster_request, write_json},
    request_setup::{qdrant_connector, qdrant_source},
};

const PAGE_ONE: &str = r#"{"items":[{"id":"cluster-1","name":"Cluster one","status":"ready"}],"next_page_token":"page-2"}"#;
const PAGE_TWO: &str =
    r#"{"items":[{"id":"cluster-2","name":"Cluster two","status":"ready"}],"next_page_token":""}"#;

#[tokio::test]
async fn clusters_round_trip_two_pages_and_keep_cursor_on_the_declared_origin() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for request_index in 0..3 {
            let (socket, request) = accept_request(&listener).await;
            assert_cluster_request(&request, "account-fixture");
            match request_index {
                0 => {
                    assert!(!request.contains("page_token="));
                    write_json(socket, PAGE_ONE).await;
                }
                1 => {
                    assert!(request.contains("page_token=page-2"));
                    write_json(socket, PAGE_TWO).await;
                }
                2 => {
                    assert!(
                        request
                            .contains("page_token=https%3A%2F%2Fattacker.invalid%2Fescape%3Fx%3D1")
                    );
                    write_json(socket, PAGE_TWO).await;
                }
                _ => unreachable!(),
            }
        }
    });

    let source = qdrant_source();
    let clusters = source
        .families()
        .iter()
        .find(|family| family.id() == "clusters")
        .unwrap();
    assert_eq!(
        clusters.path(),
        "/api/cluster/v1/accounts/${config.account_id}/clusters"
    );
    assert_eq!(clusters.projection().template(), "deployment");

    let base_url = format!("http://{address}");
    let tenant = TenantId::parse("tenant-clusters-pagination").unwrap();
    let runtime_id = SourceRuntimeId::parse("qdrant-clusters-pagination").unwrap();
    let mut connector = qdrant_connector(
        &source,
        "clusters",
        tenant.as_str(),
        runtime_id.as_str(),
        &base_url,
        1,
    );
    let page_one = connector
        .collect(CollectionRequest {
            tenant_id: tenant.clone(),
            source_runtime_id: runtime_id.clone(),
            cursor: None,
        })
        .await
        .unwrap();
    assert!(matches!(&page_one.scope, CollectedScope::Complete(_)));
    assert_eq!(page_one.records[0].provider_id, "cluster-1");
    assert_eq!(page_one.next_cursor.as_deref(), Some("page-2"));

    let page_two = connector
        .collect(CollectionRequest {
            tenant_id: tenant.clone(),
            source_runtime_id: runtime_id.clone(),
            cursor: page_one.next_cursor,
        })
        .await
        .unwrap();
    assert_eq!(page_two.records[0].provider_id, "cluster-2");
    assert!(page_two.next_cursor.is_none());

    let origin_bound_page = connector
        .collect(CollectionRequest {
            tenant_id: tenant,
            source_runtime_id: runtime_id,
            cursor: Some("https://attacker.invalid/escape?x=1".to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(origin_bound_page.records[0].provider_id, "cluster-2");
    server.await.unwrap();
}
