use std::{collections::BTreeMap, env, error::Error};

use cerebro_agent_context::{AgentGraph, ContextError};
use cerebro_organizational_model::{
    AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity, EntityId,
    EntityKind, GraphAssertion, IdentityBindingAssertion, IdentityBindingState, IdentityClaim,
    IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity, ProviderKind,
    RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{DurableGraphStore, Neo4jProjector, PostgresLedger};
use cerebro_source_runtime_next::{CollectedBatch, CollectedScope, GraphSink, SourceRecord};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and Neo4j instances"]
async fn durable_commit_projects_and_serves_a_multi_hop_graph() -> Result<(), Box<dyn Error>> {
    let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        connection.await.expect("PostgreSQL test connection");
    });
    let ledger = PostgresLedger::from_client(client);
    ledger.migrate().await?;

    let projector = Neo4jProjector::connect(
        &env::var("CEREBRO_TEST_NEO4J_URI")?,
        &env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
        &env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
    )
    .await?;
    projector.migrate().await?;
    let reader = projector.clone();
    let mut store = DurableGraphStore::new(ledger, projector);

    let tenant = TenantId::parse("tenant-live")?;
    let runtime = SourceRuntimeId::parse("okta-live")?;
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-live-1")?,
        "okta.users",
        10,
    )?;
    let collection_id = collection.receipt().collection_id().as_str().to_owned();
    let observation_id = ObservationId::parse("observation-live-1")?;
    let provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                collection.receipt(),
                observation_id.clone(),
                "okta.identity_user:user-1",
            )?],
            "live-mapper",
            "v1",
        )
    };
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.identity_user")?,
        "user-1",
        "User One",
    )?;
    let identity_claim = IdentityClaim::employee_id("employee-1")?;
    let canonical = CanonicalIdentity::for_claim(tenant.clone(), &identity_claim, "User One")?;
    let group = Entity::canonical(
        tenant.clone(),
        EntityId::parse("group-1")?,
        EntityKind::Group,
        "Engineering",
    )?;
    let repository = Entity::canonical(
        tenant.clone(),
        EntityId::parse("repository-1")?,
        EntityKind::Repository,
        "Repository",
    )?;
    let binding = IdentityBindingAssertion::new(
        &provider,
        &canonical,
        IdentityResolutionMethod::AuthoritativeEmployeeId,
        Some(identity_claim),
        IdentityBindingState::Confirmed,
        provenance()?,
        10,
    )?;
    let membership = RelationshipAssertion::new(
        canonical.entity(),
        RelationKind::MemberOf,
        &group,
        provenance()?,
        10,
    )?;
    let access = RelationshipAssertion::new(
        &group,
        RelationKind::CanAccess,
        &repository,
        provenance()?,
        10,
    )?;
    let root_id = provider.entity().id().clone();
    let mut builder = collection.clone().begin_delta();
    builder.add_entity(provider.into_entity())?;
    builder.add_entity(canonical.into_entity())?;
    builder.add_entity(group)?;
    builder.add_entity(repository.clone())?;
    builder.add_assertion(GraphAssertion::IdentityBinding(binding))?;
    builder.add_assertion(GraphAssertion::Relationship(membership))?;
    builder.add_assertion(GraphAssertion::Relationship(access))?;
    let delta = builder.build();
    let batch = CollectedBatch {
        scope: CollectedScope::Complete(collection),
        records: vec![SourceRecord {
            observation_id,
            family: "users".to_owned(),
            provider_kind: "okta.identity_user".to_owned(),
            provider_id: "user-1".to_owned(),
            fields: BTreeMap::from([("employee_id".to_owned(), "employee-1".to_owned())]),
            payload: serde_json::json!({"id": "user-1", "employee_id": "employee-1"}),
        }],
        next_cursor: None,
    };
    let receipt = store.apply(&batch, delta.clone()).await?;
    assert_eq!(receipt.graph_revision, 1);
    let (mut outbox_client, outbox_connection) =
        tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        outbox_connection
            .await
            .expect("PostgreSQL outbox test connection");
    });
    let transaction = outbox_client.transaction().await?;
    transaction
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant.as_str()],
        )
        .await?;
    let stored_graph_revision = i64::try_from(receipt.graph_revision)?;
    transaction
        .execute(
            "UPDATE organizational_projection_outbox SET projected_at = NULL WHERE tenant_id = $1 AND graph_revision = $2",
            &[&tenant.as_str(), &stored_graph_revision],
        )
        .await?;
    transaction.commit().await?;
    let resumed = store
        .resume_collection(&tenant, &collection_id)
        .await?
        .expect("committed collection");
    assert_eq!(resumed, receipt);
    let replay = store.apply(&batch, delta).await?;
    assert_eq!(replay.graph_revision, receipt.graph_revision);

    let paths = reader
        .find_paths(&tenant, &root_id, repository.id(), 4, 10)
        .await?;
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].edges.len(), 3);
    assert_eq!(paths[0].edges[0].relation, "represents");
    let missing = EntityId::parse("missing-live-entity")?;
    assert_eq!(
        reader
            .find_paths(&tenant, &missing, repository.id(), 4, 10)
            .await,
        Err(ContextError::EntityNotFound)
    );
    assert_eq!(
        reader.find_paths(&tenant, &root_id, &missing, 4, 10).await,
        Err(ContextError::EntityNotFound)
    );
    Ok(())
}
