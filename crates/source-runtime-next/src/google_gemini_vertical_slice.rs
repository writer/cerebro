use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use cerebro_organizational_graph::{GraphRead, OrganizationalGraph};
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_source_catalog::{CompiledSource, HttpMethod, SourceCatalog};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    CatalogGraphMapper, CollectionRequest, CommittedSourceEvent, CommittedSourceInput,
    CredentialLeaseReference, EgressPolicy, EgressRequestContext, GraphMapper, GraphSink,
    HttpProviderAccess, HttpSourceConnector, OperationScopedCredentialLease, PageAppendReceipt,
    PageEventInput, PageProjectionReceipt, PagePublication, PagePublicationError,
    PagePublicationInput, PagePublicationState, PublishClaim, ResolvedAuth, SourceConnector,
    SourceRuntime, SourceRuntimeOperation,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn digest<I, B>(parts: I) -> String
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    for part in parts {
        let part = part.as_ref();
        hasher.update(part.len().to_be_bytes());
        hasher.update(part);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn gemini_connector(
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
    let lease_scope = context.lease_scope().unwrap();
    let credential_lease = OperationScopedCredentialLease::new(
        CredentialLeaseReference::new(
            format!("gemini-model-catalog-lease-{generation}"),
            lease_scope,
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

#[tokio::test]
async fn google_gemini_model_catalog_collects_appends_projects_restarts_and_reads() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..4 {
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

    let root = repository_root();
    let source = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap()
    .get("google_gemini")
    .unwrap()
    .clone();
    let family = source
        .families()
        .iter()
        .find(|family| family.id() == "model_catalog")
        .unwrap();
    assert_eq!(family.method(), HttpMethod::Get);
    assert_eq!(family.path(), "/v1beta/models");
    assert_eq!(family.record_selector(), "$.models[*]");
    assert_eq!(family.id_field(), "name");
    assert_eq!(family.projection().template(), "asset");

    let base_url = format!("http://{address}");
    let tenant_a = TenantId::parse("tenant-a").unwrap();
    let runtime_id = SourceRuntimeId::parse("google-gemini-production").unwrap();
    let mut connector = gemini_connector(
        &source,
        tenant_a.as_str(),
        runtime_id.as_str(),
        &base_url,
        1,
    );
    let batch = connector
        .collect(CollectionRequest {
            tenant_id: tenant_a.clone(),
            source_runtime_id: runtime_id.clone(),
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records[0].provider_id, "models/gemini-1");
    assert_eq!(batch.records[1].provider_id, "models/gemini-2");

    let observed_at = batch.scope.receipt().observed_at_unix_ms();
    let committed = batch
        .records
        .iter()
        .map(|record| {
            CommittedSourceEvent::from_input(CommittedSourceInput {
                tenant_id: tenant_a.clone(),
                source_runtime_id: runtime_id.clone(),
                observation_id: record.observation_id.clone(),
                source_id: "google_gemini".to_owned(),
                family_id: "model_catalog".to_owned(),
                event_kind: "google_gemini.model_catalog".to_owned(),
                schema_ref: "google_gemini/model_catalog/v1".to_owned(),
                observed_at_unix_ms: observed_at,
                attributes: record.fields.clone(),
                payload: record.payload.clone(),
            })
            .unwrap()
        })
        .collect::<Vec<_>>();
    let event_inputs = committed
        .iter()
        .map(|event| PageEventInput {
            event_id: event.observation_id().clone(),
            envelope_sha256: event.record_digest(),
        })
        .collect::<Vec<_>>();
    let result_digest = digest(committed.iter().map(CommittedSourceEvent::record_digest));
    let mut publication = PagePublication::prepare(
        PagePublicationInput {
            logical_page_id: "gemini-model-catalog-page".to_owned(),
            tenant_id: tenant_a.clone(),
            source_runtime_id: runtime_id.clone(),
            source_id: "google_gemini".to_owned(),
            family_id: "model_catalog".to_owned(),
            lease_generation: 1,
            authority_epoch: 1,
            request_intent_sha256: digest([b"GET /v1beta/models".as_slice()]),
            input_progress_sha256: digest([b"initial".as_slice()]),
            target_progress_sha256: digest([b"terminal".as_slice()]),
            result_sha256: result_digest,
        },
        event_inputs,
    )
    .unwrap();
    let first_claim = PublishClaim::new("worker-a", 1).unwrap();
    publication.begin_publishing(first_claim.clone()).unwrap();
    let first_intent = publication.events()[0].clone();
    publication
        .record_append(
            &first_claim,
            PageAppendReceipt {
                ordinal: first_intent.ordinal(),
                event_id: first_intent.event_id().clone(),
                message_id: first_intent.message_id().to_owned(),
                stream: "source-events".to_owned(),
                stream_sequence: 41,
            },
        )
        .unwrap();

    let snapshot = serde_json::to_value(&publication).unwrap();
    let mut publication = PagePublication::restore_snapshot(snapshot).unwrap();
    let successor = PublishClaim::new("worker-b", 2).unwrap();
    publication
        .transfer_claim(&first_claim, successor.clone())
        .unwrap();
    let second_intent = publication.events()[1].clone();
    let second_receipt = PageAppendReceipt {
        ordinal: second_intent.ordinal(),
        event_id: second_intent.event_id().clone(),
        message_id: second_intent.message_id().to_owned(),
        stream: "source-events".to_owned(),
        stream_sequence: 42,
    };
    assert_eq!(
        publication.record_append(&first_claim, second_receipt.clone()),
        Err(PagePublicationError::StaleClaim)
    );
    publication
        .record_append(&successor, second_receipt)
        .unwrap();
    assert_eq!(publication.state(), PagePublicationState::Published);

    let mapper = CatalogGraphMapper::new(source.clone(), "google-gemini-model-catalog-v1").unwrap();
    let mut graph = OrganizationalGraph::new();
    let mut projection_digests = Vec::new();
    let mut graph_revision = 0;
    for event in committed {
        let provider_id = event.payload()["name"].as_str().unwrap().to_owned();
        let event_batch = event
            .into_batch("google_gemini.model_catalog".to_owned(), provider_id)
            .unwrap();
        let delta = mapper.map(&event_batch).unwrap();
        let receipt = GraphSink::apply(&mut graph, &event_batch, delta)
            .await
            .unwrap();
        projection_digests.push(receipt.delta_digest);
        graph_revision = receipt.graph_revision;
    }
    publication
        .record_projection(
            &successor,
            PageProjectionReceipt {
                delta_sha256: digest(projection_digests),
                graph_revision,
            },
        )
        .unwrap();
    publication.commit(&successor).unwrap();
    assert_eq!(publication.state(), PagePublicationState::Committed);

    let tenant_a_entities = graph.entities(&tenant_a);
    assert_eq!(tenant_a_entities.len(), 2);
    let tenant_a_ids = tenant_a_entities
        .iter()
        .map(|entity| entity.id().clone())
        .collect::<Vec<_>>();
    assert!(tenant_a_entities.iter().all(|entity| {
        entity
            .agent_key()
            .starts_with("urn:cerebro:tenant-a:organizational_entity:")
    }));

    let tenant_b = TenantId::parse("tenant-b").unwrap();
    let connector = gemini_connector(
        &source,
        tenant_b.as_str(),
        runtime_id.as_str(),
        &base_url,
        2,
    );
    let mapper = CatalogGraphMapper::new(source, "google-gemini-model-catalog-v1").unwrap();
    let mut second_tenant = SourceRuntime::new(connector, mapper, graph);
    second_tenant
        .sync(CollectionRequest {
            tenant_id: tenant_b.clone(),
            source_runtime_id: runtime_id,
            cursor: None,
        })
        .await
        .unwrap();
    let graph = second_tenant.into_store();
    let tenant_b_entities = graph.entities(&tenant_b);
    assert_eq!(tenant_b_entities.len(), 2);
    assert!(
        tenant_b_entities
            .iter()
            .all(|entity| !tenant_a_ids.contains(entity.id()))
    );
    assert_eq!(graph.entities(&tenant_a).len(), 2);
    server.await.unwrap();
}
