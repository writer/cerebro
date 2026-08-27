use std::{collections::BTreeMap, env, error::Error};

use cerebro_agent_context::AgentGraph;
use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_organizational_store::{
    DurableGraphStore, Neo4jProjector, PostgresLedger, StoredSourceRuntime,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectionRequest, HttpConnectorError, RuntimeError, SourceRuntime,
};
use tokio_postgres::NoTls;

#[path = "support/qdrant_cloud/mod.rs"]
mod support;

use support::{qdrant_connector, repository_root, spawn_cluster_provider};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and Neo4j instances"]
async fn clusters_resume_then_reject_a_stale_checkpoint_claim() -> Result<(), Box<dyn Error>> {
    let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (lease_client, lease_connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        lease_connection.await.expect("PostgreSQL lease connection");
    });
    let lease_ledger = PostgresLedger::from_client(lease_client);
    lease_ledger.migrate().await?;
    let (store_client, store_connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        store_connection.await.expect("PostgreSQL store connection");
    });
    let store_ledger = PostgresLedger::from_client(store_client);
    store_ledger.migrate().await?;

    let suffix = std::process::id();
    let tenant = TenantId::parse(format!("tenant-qdrant-durable-{suffix}"))?;
    let runtime_id = SourceRuntimeId::parse(format!("qdrant-durable-{suffix}"))?;
    let stored_runtime = StoredSourceRuntime::new(
        runtime_id.clone(),
        tenant.clone(),
        "qdrant_cloud".to_owned(),
        BTreeMap::from([
            ("family".to_owned(), "clusters".to_owned()),
            (
                "base_url".to_owned(),
                "https://api.cloud.qdrant.io".to_owned(),
            ),
            ("account_id".to_owned(), "account-durable".to_owned()),
        ]),
        Some(serde_json::json!({
            "watermark": "2026-08-26T00:00:00Z",
            "cursor_opaque": "{\"token\":\"page-1\",\"resumable_checkpoint\":true}"
        })),
        Some(serde_json::json!({"opaque": "page-1"})),
        None,
    )?;
    assert!(
        lease_ledger
            .put_source_runtime(&stored_runtime, None)
            .await?
    );
    let fence = lease_ledger
        .acquire_source_runtime_lease(&tenant, &runtime_id, "worker:qdrant-one", 60_000)
        .await?
        .expect("Qdrant lease");

    let (base_url, provider) = spawn_cluster_provider().await;
    let root = repository_root();
    let source = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )?
    .get("qdrant_cloud")
    .expect("Qdrant catalog source")
    .clone();
    let mapper = || CatalogGraphMapper::new(source.clone(), "qdrant-durable-v1").unwrap();
    let projector = Neo4jProjector::connect(
        &env::var("CEREBRO_TEST_NEO4J_URI")?,
        &env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
        &env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
    )
    .await?;
    projector.migrate().await?;
    let reader = projector.clone();
    let store = DurableGraphStore::new(store_ledger, projector);
    let request = |cursor: Option<String>| CollectionRequest {
        tenant_id: tenant.clone(),
        source_runtime_id: runtime_id.clone(),
        cursor,
    };

    let mut interrupted = SourceRuntime::new(
        qdrant_connector(
            source.clone(),
            &tenant,
            &runtime_id,
            &base_url,
            fence.generation(),
        ),
        mapper(),
        store,
    );
    let error = interrupted
        .sync_fenced(request(Some("page-1".to_owned())), &fence)
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        RuntimeError::Collect(HttpConnectorError::ProviderStatus(status))
            if status.as_u16() == 429
    ));
    let after_interruption = lease_ledger.load_source_runtime(&runtime_id).await?;
    assert_eq!(after_interruption.cursor(), Some("page-1"));
    assert!(after_interruption.last_synced_at().is_none());

    let mut resumed = SourceRuntime::new(
        qdrant_connector(
            source.clone(),
            &tenant,
            &runtime_id,
            &base_url,
            fence.generation(),
        ),
        mapper(),
        interrupted.into_store(),
    );
    let receipt = resumed
        .sync_fenced(request(Some("page-1".to_owned())), &fence)
        .await?;
    assert_eq!(receipt.entities_upserted, 2);
    let committed = lease_ledger.load_source_runtime(&runtime_id).await?;
    assert_eq!(committed.cursor(), None);
    assert_eq!(committed.next_cursor(), None);
    assert_eq!(
        committed
            .checkpoint()
            .and_then(|value| value.get("cursor_opaque"))
            .and_then(serde_json::Value::as_str),
        Some("")
    );
    assert!(committed.last_synced_at().is_some());
    assert_eq!(reader.revision(&tenant).await?, receipt.graph_revision);
    let product_entities = reader.search(&tenant, "Durable cluster", &[], 10).await?;
    assert_eq!(product_entities.len(), 2);

    let store = resumed.into_store();
    assert!(lease_ledger.release_source_runtime_lease(&fence).await?);
    let successor = lease_ledger
        .acquire_source_runtime_lease(&tenant, &runtime_id, "worker:qdrant-two", 60_000)
        .await?
        .expect("successor Qdrant lease");
    assert!(successor.generation() > fence.generation());
    let mut stale = SourceRuntime::new(
        qdrant_connector(
            source.clone(),
            &tenant,
            &runtime_id,
            &base_url,
            fence.generation(),
        ),
        mapper(),
        store,
    );
    assert!(matches!(
        stale.sync_fenced(request(None), &fence).await,
        Err(RuntimeError::Store(_))
    ));
    let after_stale = lease_ledger.load_source_runtime(&runtime_id).await?;
    assert_eq!(after_stale.next_cursor(), committed.next_cursor());
    assert_eq!(after_stale.checkpoint(), committed.checkpoint());
    assert_eq!(after_stale.last_synced_at(), committed.last_synced_at());
    assert_eq!(reader.revision(&tenant).await?, receipt.graph_revision);
    assert!(
        lease_ledger
            .release_source_runtime_lease(&successor)
            .await?
    );
    provider.await?;
    Ok(())
}
