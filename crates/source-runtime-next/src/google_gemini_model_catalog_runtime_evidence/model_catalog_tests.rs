use std::path::{Path, PathBuf};

use cerebro_organizational_graph::GraphRead;
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_source_catalog::{HttpMethod, SourceCatalog};

use super::{
    provider_fixture::{ProviderFixture, connector},
    publication_fixture::{committed_events, record_append_receipts_and_project_after_restart},
};
use crate::{
    CatalogGraphMapper, CollectionRequest, PagePublicationState, SourceConnector, SourceRuntime,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[tokio::test]
async fn model_catalog_executes_bounded_pagination_and_preserves_tenant_identity_after_restart() {
    let provider = ProviderFixture::start(2).await;
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

    let tenant_a = TenantId::parse("tenant-a").unwrap();
    let runtime_id = SourceRuntimeId::parse("google-gemini-production").unwrap();
    let mut first = connector(
        &source,
        tenant_a.as_str(),
        runtime_id.as_str(),
        &provider.base_url,
        1,
    );
    let batch = first
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

    let committed = committed_events(&batch, &tenant_a, &runtime_id);
    let (graph, publication) = record_append_receipts_and_project_after_restart(
        &source,
        &tenant_a,
        &runtime_id,
        committed,
    )
    .await;
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
    let second = connector(
        &source,
        tenant_b.as_str(),
        runtime_id.as_str(),
        &provider.base_url,
        2,
    );
    let mapper = CatalogGraphMapper::new(source, "google-gemini-model-catalog-v1").unwrap();
    let mut second_tenant = SourceRuntime::new(second, mapper, graph);
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
    provider.finish().await;
}
