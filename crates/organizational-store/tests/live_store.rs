use std::{collections::BTreeMap, env, error::Error};

use cerebro_agent_context::{
    AgentGraph, ContextError, FactQuery, QueryAbsentEdge, QueryDirection, QueryEdge, QueryNode,
};
use cerebro_organizational_model::{
    AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity, EntityId,
    EntityKind, GraphAssertion, IdentityBindingAssertion, IdentityBindingState, IdentityClaim,
    IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity, ProviderKind,
    RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{DurableGraphStore, Neo4jProjector, PostgresLedger, StoreError};
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
        runtime.clone(),
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
        Some(identity_claim.clone()),
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
    let binding_id = binding.id().clone();
    let membership_id = membership.id().clone();
    let access_id = access.id().clone();
    let root_id = provider.entity().id().clone();
    let mut builder = collection.clone().begin_delta();
    builder.add_entity(provider.clone().into_entity())?;
    builder.add_entity(canonical.clone().into_entity())?;
    builder.add_entity(group.clone())?;
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

    let refresh_collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-live-2")?,
        "okta.users",
        20,
    )?;
    let refresh_observation = ObservationId::parse("observation-live-2")?;
    let refresh_provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                refresh_collection.receipt(),
                refresh_observation.clone(),
                "okta.identity_user:user-1",
            )?],
            "live-mapper",
            "v2",
        )
    };
    let refreshed_provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.identity_user")?,
        "user-1",
        "User One Updated",
    )?;
    let refreshed_canonical =
        CanonicalIdentity::for_claim(tenant.clone(), &identity_claim, "User One Updated")?;
    let refreshed_group = Entity::canonical(
        tenant.clone(),
        EntityId::parse("group-1")?,
        EntityKind::Group,
        "Platform Engineering",
    )?;
    let refreshed_binding = IdentityBindingAssertion::new(
        &refreshed_provider,
        &refreshed_canonical,
        IdentityResolutionMethod::AuthoritativeEmployeeId,
        Some(identity_claim),
        IdentityBindingState::Confirmed,
        refresh_provenance()?,
        20,
    )?;
    let refreshed_membership = RelationshipAssertion::new(
        refreshed_canonical.entity(),
        RelationKind::MemberOf,
        &refreshed_group,
        refresh_provenance()?,
        20,
    )?;
    let refreshed_access = RelationshipAssertion::new(
        &refreshed_group,
        RelationKind::CanAccess,
        &repository,
        refresh_provenance()?,
        20,
    )?;
    assert_eq!(refreshed_binding.id(), &binding_id);
    assert_eq!(refreshed_membership.id(), &membership_id);
    assert_eq!(refreshed_access.id(), &access_id);
    let mut refresh_builder = refresh_collection.clone().begin_delta();
    refresh_builder.add_entity(refreshed_provider.into_entity())?;
    refresh_builder.add_entity(refreshed_canonical.into_entity())?;
    refresh_builder.add_entity(refreshed_group)?;
    refresh_builder.add_entity(repository.clone())?;
    refresh_builder.add_assertion(GraphAssertion::IdentityBinding(refreshed_binding))?;
    refresh_builder.add_assertion(GraphAssertion::Relationship(refreshed_membership))?;
    refresh_builder.add_assertion(GraphAssertion::Relationship(refreshed_access))?;
    let refresh_batch = CollectedBatch {
        scope: CollectedScope::Complete(refresh_collection),
        records: vec![SourceRecord {
            observation_id: refresh_observation,
            family: "users".to_owned(),
            provider_kind: "okta.identity_user".to_owned(),
            provider_id: "user-1".to_owned(),
            fields: BTreeMap::from([("employee_id".to_owned(), "employee-1".to_owned())]),
            payload: serde_json::json!({"id": "user-1", "employee_id": "employee-1"}),
        }],
        next_cursor: None,
    };
    let refresh_receipt = store.apply(&refresh_batch, refresh_builder.build()).await?;
    assert_eq!(refresh_receipt.graph_revision, 2);
    assert_eq!(
        reader.resolve(&tenant, root_id.as_str()).await?.label,
        "User One Updated"
    );

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

    let compliance_runtime = SourceRuntimeId::parse("compliance-live")?;
    let compliance_collection = CompleteCollection::new(
        tenant.clone(),
        compliance_runtime,
        CollectionId::parse("collection-live-compliance")?,
        "compliance.current",
        25,
    )?;
    let compliance_observation = ObservationId::parse("observation-live-compliance")?;
    let compliance_provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                compliance_collection.receipt(),
                compliance_observation.clone(),
                "compliance.snapshot:1",
            )?],
            "compliance-projector",
            "v1",
        )
    };
    let control = Entity::canonical(
        tenant.clone(),
        EntityId::parse("control-live-cc6-1")?,
        EntityKind::Control,
        "SOC 2 CC6.1",
    )?;
    let unsupported_finding = Entity::canonical(
        tenant.clone(),
        EntityId::parse("finding-live-unsupported")?,
        EntityKind::Finding,
        "Missing access evidence",
    )?;
    let supported_finding = Entity::canonical(
        tenant.clone(),
        EntityId::parse("finding-live-supported")?,
        EntityKind::Finding,
        "Reviewed access evidence",
    )?;
    let evidence_record = Entity::canonical(
        tenant.clone(),
        EntityId::parse("evidence-live-1")?,
        EntityKind::Evidence,
        "Access review receipt",
    )?;
    let compliance_relationships = [
        RelationshipAssertion::new(
            &unsupported_finding,
            RelationKind::MappedToControl,
            &control,
            compliance_provenance()?,
            25,
        )?,
        RelationshipAssertion::new(
            &unsupported_finding,
            RelationKind::Affects,
            &repository,
            compliance_provenance()?,
            25,
        )?,
        RelationshipAssertion::new(
            &supported_finding,
            RelationKind::MappedToControl,
            &control,
            compliance_provenance()?,
            25,
        )?,
        RelationshipAssertion::new(
            &supported_finding,
            RelationKind::Affects,
            &repository,
            compliance_provenance()?,
            25,
        )?,
        RelationshipAssertion::new(
            &evidence_record,
            RelationKind::EvidenceFor,
            &supported_finding,
            compliance_provenance()?,
            25,
        )?,
    ];
    let mut compliance_builder = compliance_collection.clone().begin_delta();
    for entity in [
        control,
        unsupported_finding.clone(),
        supported_finding,
        evidence_record,
        repository.clone(),
    ] {
        compliance_builder.add_entity(entity)?;
    }
    for relationship in compliance_relationships {
        compliance_builder.add_assertion(GraphAssertion::Relationship(relationship))?;
    }
    let compliance_batch = CollectedBatch {
        scope: CollectedScope::Complete(compliance_collection),
        records: vec![SourceRecord {
            observation_id: compliance_observation,
            family: "current".to_owned(),
            provider_kind: "cerebro.compliance_snapshot".to_owned(),
            provider_id: "snapshot-1".to_owned(),
            fields: BTreeMap::new(),
            payload: serde_json::json!({"snapshot_id": "snapshot-1"}),
        }],
        next_cursor: None,
    };
    let compliance_receipt = store
        .apply(&compliance_batch, compliance_builder.build())
        .await?;
    assert_eq!(compliance_receipt.graph_revision, 3);
    let compliance_query = FactQuery::new(
        vec![
            QueryNode {
                variable: "finding".to_owned(),
                kinds: vec!["finding".to_owned()],
                keys: Vec::new(),
            },
            QueryNode {
                variable: "control".to_owned(),
                kinds: vec!["control".to_owned()],
                keys: vec!["control-live-cc6-1".to_owned()],
            },
            QueryNode {
                variable: "resource".to_owned(),
                kinds: vec!["repository".to_owned()],
                keys: vec![repository.id().to_string()],
            },
        ],
        vec![
            QueryEdge {
                variable: "control_mapping".to_owned(),
                from_variable: "finding".to_owned(),
                relation: "mapped_to_control".to_owned(),
                to_variable: "control".to_owned(),
            },
            QueryEdge {
                variable: "affected_resource".to_owned(),
                from_variable: "finding".to_owned(),
                relation: "affects".to_owned(),
                to_variable: "resource".to_owned(),
            },
        ],
        vec![QueryAbsentEdge {
            bound_variable: "finding".to_owned(),
            direction: QueryDirection::Incoming,
            relation: "evidence_for".to_owned(),
            other_kinds: vec!["evidence".to_owned()],
        }],
        10,
    )?;
    let compliance_result = reader.query(&tenant, &compliance_query).await?;
    assert_eq!(compliance_result.graph_revision, 3);
    assert_eq!(compliance_result.matches.len(), 1);
    assert_eq!(
        compliance_result.matches[0].entities["finding"].entity_id,
        unsupported_finding.id().clone()
    );

    let conflicting_collection = CompleteCollection::new(
        tenant.clone(),
        SourceRuntimeId::parse("conflict-live")?,
        CollectionId::parse("collection-live-conflict")?,
        "conflict.entities",
        30,
    )?;
    let mut conflicting_builder = conflicting_collection.clone().begin_delta();
    conflicting_builder.add_entity(Entity::canonical(
        tenant.clone(),
        root_id.clone(),
        EntityKind::Repository,
        "Conflicting identity",
    )?)?;
    let conflicting_batch = CollectedBatch {
        scope: CollectedScope::Complete(conflicting_collection),
        records: Vec::new(),
        next_cursor: None,
    };
    assert!(matches!(
        store
            .apply(&conflicting_batch, conflicting_builder.build())
            .await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        reader.resolve(&tenant, root_id.as_str()).await?.label,
        "User One Updated",
        "a rejected bulk write cannot alter the projected entity"
    );
    Ok(())
}
