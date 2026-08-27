use std::collections::BTreeMap;

use crate::{
    CollectionRequest, HttpSourceConnector, ProviderFailureKind, ResolvedAuth, RuntimeError,
};
use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{SourceRuntimeId, TenantId};

use super::{
    fixture_server::{accept_request, write_json},
    request_setup::{qdrant_runtime, qdrant_source},
};

#[tokio::test]
async fn clusters_reject_wrong_auth_malformed_and_oversized_provider_data() {
    let source = qdrant_source();
    assert!(matches!(
        HttpSourceConnector::new(
            source.clone(),
            "clusters",
            "https://api.cloud.qdrant.io",
            BTreeMap::from([("account_id".to_owned(), "account-fixture".to_owned())]),
            ResolvedAuth::Bearer {
                token: "wrong-auth-shape".to_owned(),
            },
        ),
        Err(crate::HttpConnectorError::InvalidConfiguration(_))
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let bodies = [
            "not-json".to_owned(),
            serde_json::json!({
                "items": [{"id": "x".repeat(1_025), "name": "Oversized identity"}],
                "next_page_token": ""
            })
            .to_string(),
            serde_json::json!({
                "items": [{"id": "cluster-oversized", "name": "x".repeat((16 << 20) + 1)}],
                "next_page_token": ""
            })
            .to_string(),
        ];
        for body in bodies {
            let (socket, _) = accept_request(&listener).await;
            write_json(socket, &body).await;
        }
    });

    let base_url = format!("http://{address}");
    for (generation, expected_kind) in [
        (1, Some(ProviderFailureKind::PartialPageResponse)),
        (2, None),
        (3, Some(ProviderFailureKind::ResponseSizeLimit)),
    ] {
        let mut runtime = qdrant_runtime(
            &source,
            "clusters",
            "tenant-failures",
            "qdrant-clusters-failures",
            &base_url,
            generation,
            OrganizationalGraph::new(),
        );
        let error = runtime
            .sync(CollectionRequest {
                tenant_id: TenantId::parse("tenant-failures").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("qdrant-clusters-failures").unwrap(),
                cursor: None,
            })
            .await
            .unwrap_err();
        match (expected_kind, error) {
            (Some(expected_kind), RuntimeError::Collect(error)) => {
                assert!(matches!(
                    &error,
                    crate::HttpConnectorError::InvalidResponse(_)
                ));
                let classification = error.provider_failure_classification().unwrap();
                assert_eq!(classification.kind, expected_kind);
                assert!(!classification.advances_progress);
            }
            (None, RuntimeError::Map(_)) => {}
            (_, error) => panic!("provider rejection crossed the expected boundary: {error:?}"),
        }
        assert_eq!(
            runtime
                .into_store()
                .graph_revision(&TenantId::parse("tenant-failures").unwrap()),
            0
        );
    }
    server.await.unwrap();
}
