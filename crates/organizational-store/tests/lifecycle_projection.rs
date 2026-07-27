use std::{collections::BTreeMap, env, error::Error};

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CollectionId, CompleteCollection, Entity, EntityKind, ObservationId, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{Neo4jProjector, StoreError};
use cerebro_security_lifecycle::{
    LifecycleQuery, LifecycleState, Observation, ProjectedResource, QuerySource, ResourceRef,
    SubjectKind, SubjectLocator, finalize_indexed_query, prepare_indexed_query,
    project_observation, query_records_with_source, resolve_finding_record,
};
use neo4rs::{Graph, query};

#[tokio::test]
#[ignore = "requires a disposable Neo4j instance"]
async fn lifecycle_projection_backfills_pages_matches_scan_and_removes_stale_rows()
-> Result<(), Box<dyn Error>> {
    let uri = env::var("CEREBRO_TEST_NEO4J_URI")?;
    let username = env::var("CEREBRO_TEST_NEO4J_USERNAME")?;
    let password = env::var("CEREBRO_TEST_NEO4J_PASSWORD")?;
    let graph = Graph::new(&uri, &username, &password).await?;
    let projector = Neo4jProjector::from_graph(graph.clone());
    projector.migrate().await?;
    let tenant = TenantId::parse(format!("tenant-lifecycle-{}", std::process::id()))?;
    cleanup(&graph, &tenant).await?;

    let mut scan_resources = Vec::new();
    let mut expired_resource_id = None;
    let mut expired_finding_id = None;
    for (index, observation) in [
        lifecycle_observation(
            &tenant,
            "credential-a",
            LifecycleState::Active,
            Some("2026-07-20T12:00:00Z"),
            "security",
        ),
        lifecycle_observation(
            &tenant,
            "credential-b",
            LifecycleState::Expired,
            Some("2026-07-01T12:00:00Z"),
            "security",
        ),
        lifecycle_observation(
            &tenant,
            "certificate-c",
            LifecycleState::Active,
            Some("2027-07-01T12:00:00Z"),
            "platform",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let revision = u64::try_from(index + 1)?;
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("lifecycle-test")?,
            CollectionId::parse(format!("lifecycle-collection-{revision}"))?,
            "security.lifecycle",
            1_721_995_200_000,
        )?;
        let delta = project_observation(
            collection.receipt().clone(),
            ObservationId::parse(format!("lifecycle-observation-{revision}"))?,
            &observation,
        )?;
        let resource = delta
            .entities()
            .iter()
            .find(|entity| entity.kind() == &EntityKind::Resource)
            .expect("lifecycle resource");
        if index == 1 {
            expired_resource_id = Some(resource.id().clone());
            expired_finding_id = delta
                .entities()
                .iter()
                .find(|entity| entity.kind() == &EntityKind::Finding)
                .map(|entity| entity.id().clone());
        }
        scan_resources.push(ProjectedResource {
            agent_key: resource.agent_key(),
            label: resource.label().to_owned(),
            properties: resource.properties().clone(),
        });
        projector
            .project(
                &delta,
                &GraphWriteReceipt {
                    tenant_id: tenant.clone(),
                    graph_revision: revision,
                    delta_digest: delta.digest().to_owned(),
                    entities_upserted: delta.entities().len(),
                    assertions_upserted: delta.assertions().len(),
                    assertions_retracted: delta.retractions().len(),
                },
            )
            .await?;
    }

    graph
        .run(
            query(
                "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id}) REMOVE entity:SecurityLifecycleSubject, entity:SecurityLifecycleFinding WITH count(entity) AS ignored MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) DETACH DELETE state",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    let filter = LifecycleQuery {
        subject_kinds: vec![SubjectKind::Credential],
        owner_urns: vec![format!("urn:cerebro:{}:team:security", tenant.as_str())],
        findings_only: true,
        limit: Some(1),
        ..LifecycleQuery::default()
    };
    let prepared = prepare_indexed_query(&tenant, &filter, "2026-07-26T12:00:00Z", 3)?;
    let unavailable = projector
        .query_lifecycle(&tenant, &prepared)
        .await
        .expect_err("an unbackfilled tenant must not use the lifecycle index");
    assert!(
        matches!(
            unavailable,
            StoreError::LifecycleProjectionUnavailable {
                graph_revision: 3,
                projection_revision: None
            }
        ),
        "unexpected readiness error: {unavailable:?}"
    );

    assert_eq!(projector.rebuild_lifecycle_projection(&tenant, 2).await?, 4);
    let indexed_page = projector.query_lifecycle(&tenant, &prepared).await?;
    let indexed = finalize_indexed_query(&tenant, &prepared, indexed_page)?;
    let scan = query_records_with_source(
        &tenant,
        &filter,
        scan_resources.clone(),
        "2026-07-26T12:00:00Z",
        QuerySource {
            scanned_entities: scan_resources.len(),
            graph_revision: 3,
            ..QuerySource::default()
        },
    )?;
    assert_eq!(indexed.aggregates, scan.aggregates);
    assert_eq!(indexed.records, scan.records);
    assert_eq!(indexed.metadata.coverage.scanned_entities, 0);
    assert_eq!(indexed.metadata.coverage.lifecycle_entities, 3);

    for parity_filter in [
        LifecycleQuery {
            subject_kinds: vec![SubjectKind::Credential],
            owner_urns: vec![format!("urn:cerebro:{}:team:security", tenant.as_str())],
            findings_only: true,
            limit: Some(10),
            ..LifecycleQuery::default()
        },
        LifecycleQuery {
            states: vec![LifecycleState::Active],
            expires_before: Some("2026-08-01T00:00:00Z".to_owned()),
            limit: Some(10),
            ..LifecycleQuery::default()
        },
        LifecycleQuery {
            subject_locator: Some(SubjectLocator {
                subject_kind: SubjectKind::Certificate,
                authority_id: "test-authority".to_owned(),
                stable_locator: "certificate-c".to_owned(),
            }),
            limit: Some(10),
            ..LifecycleQuery::default()
        },
    ] {
        let prepared = prepare_indexed_query(&tenant, &parity_filter, "2026-07-26T12:00:00Z", 3)?;
        let indexed = finalize_indexed_query(
            &tenant,
            &prepared,
            projector.query_lifecycle(&tenant, &prepared).await?,
        )?;
        let scan = query_records_with_source(
            &tenant,
            &parity_filter,
            scan_resources.clone(),
            "2026-07-26T12:00:00Z",
            QuerySource {
                scanned_entities: scan_resources.len(),
                graph_revision: 3,
                ..QuerySource::default()
            },
        )?;
        assert_eq!(indexed.aggregates, scan.aggregates);
        assert_eq!(indexed.records, scan.records);
    }
    let compliant_locator = LifecycleQuery {
        subject_locator: Some(SubjectLocator {
            subject_kind: SubjectKind::Certificate,
            authority_id: "test-authority".to_owned(),
            stable_locator: "certificate-c".to_owned(),
        }),
        limit: Some(1),
        ..LifecycleQuery::default()
    };
    let compliant_prepared =
        prepare_indexed_query(&tenant, &compliant_locator, "2026-07-26T12:00:00Z", 3)?;
    let compliant = finalize_indexed_query(
        &tenant,
        &compliant_prepared,
        projector
            .query_lifecycle(&tenant, &compliant_prepared)
            .await?,
    )?;
    assert_eq!(compliant.records.len(), 1);
    assert_eq!(compliant.records[0].source_runtime_id, "lifecycle-test");
    assert_eq!(
        compliant.records[0].source_collection_id,
        "runtime:lifecycle-test:2026-07-26T12:00:00Z"
    );
    assert!(compliant.records[0].findings.is_empty());

    graph
        .run(
            query(
                "MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) SET state.graph_revision = 2",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    assert!(matches!(
        projector.query_lifecycle(&tenant, &prepared).await,
        Err(StoreError::LifecycleProjectionUnavailable {
            graph_revision: 3,
            projection_revision: Some(2)
        })
    ));
    assert_eq!(projector.rebuild_lifecycle_projection(&tenant, 2).await?, 4);

    let first_token = indexed.next_page_token.clone().expect("next page");
    let second_filter = LifecycleQuery {
        page_token: Some(first_token),
        ..filter.clone()
    };
    let second_prepared =
        prepare_indexed_query(&tenant, &second_filter, "2026-07-26T12:01:00Z", 3)?;
    let second = finalize_indexed_query(
        &tenant,
        &second_prepared,
        projector.query_lifecycle(&tenant, &second_prepared).await?,
    )?;
    assert_eq!(second.records.len(), 1);
    assert!(second.previous_page_token.is_some());

    let expired_subject_urn = scan_resources[1].agent_key.clone();
    let finding_urn =
        cerebro_security_lifecycle::canonical_finding_urn(tenant.as_str(), &expired_subject_urn)?;
    let resolved = projector
        .resolve_lifecycle_finding(&tenant, &finding_urn)
        .await?
        .expect("durable lifecycle finding");
    assert_eq!(resolved.source_runtime_id, "lifecycle-test");
    assert_eq!(
        resolved.source_collection_id,
        "runtime:lifecycle-test:2026-07-26T12:00:00Z"
    );
    let resolved_record = resolve_finding_record(
        &tenant,
        &finding_urn,
        resolved.resource,
        "2026-07-26T12:00:00Z",
        resolved.graph_revision,
    )?
    .expect("current policy still finds the subject");
    assert_eq!(resolved_record.findings[0].finding_ref.id, finding_urn);
    assert_eq!(resolved_record.source_runtime_id, "lifecycle-test");
    assert_eq!(
        resolved_record.source_collection_id,
        "runtime:lifecycle-test:2026-07-26T12:00:00Z"
    );

    let replacement_collection = CompleteCollection::new(
        tenant.clone(),
        SourceRuntimeId::parse("lifecycle-test")?,
        CollectionId::parse("lifecycle-collection-4")?,
        "security.lifecycle",
        1_721_995_200_000,
    )?;
    let replacement = Entity::canonical(
        tenant.clone(),
        expired_resource_id.expect("expired resource"),
        EntityKind::Resource,
        "Credential A without lifecycle metadata",
    )?;
    let mut replacement_builder = replacement_collection.begin_delta();
    replacement_builder.add_entity(replacement)?;
    replacement_builder.add_entity(Entity::canonical(
        tenant.clone(),
        expired_finding_id.expect("expired finding"),
        EntityKind::Finding,
        "Closed lifecycle finding without projection metadata",
    )?)?;
    let replacement_delta = replacement_builder.build();
    projector
        .project(
            &replacement_delta,
            &GraphWriteReceipt {
                tenant_id: tenant.clone(),
                graph_revision: 4,
                delta_digest: replacement_delta.digest().to_owned(),
                entities_upserted: 2,
                assertions_upserted: 0,
                assertions_retracted: 0,
            },
        )
        .await?;
    let all_query = LifecycleQuery {
        limit: Some(10),
        ..LifecycleQuery::default()
    };
    let all_prepared = prepare_indexed_query(&tenant, &all_query, "2026-07-26T12:00:00Z", 4)?;
    let after_replacement = finalize_indexed_query(
        &tenant,
        &all_prepared,
        projector.query_lifecycle(&tenant, &all_prepared).await?,
    )?;
    assert_eq!(after_replacement.aggregates.matched_records, 2);
    assert_eq!(after_replacement.metadata.coverage.lifecycle_entities, 2);
    assert!(
        projector
            .resolve_lifecycle_finding(&tenant, &finding_urn)
            .await?
            .is_none(),
        "a stale finding entity cannot resolve after the subject stops being lifecycle-bearing"
    );
    let mut stale_projection_rows = graph
        .execute(
            query(
                "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id}) WHERE entity.entity_kind IN ['resource', 'finding'] RETURN count(CASE WHEN entity:SecurityLifecycleSubject THEN 1 END) AS subjects, count(CASE WHEN entity:SecurityLifecycleFinding THEN 1 END) AS findings, count(CASE WHEN entity.lifecycle_finding_urn IS NOT NULL THEN 1 END) AS finding_properties",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    let stale_projection = stale_projection_rows
        .next()
        .await?
        .expect("stale projection count");
    assert_eq!(stale_projection.get::<i64>("subjects")?, 2);
    assert_eq!(stale_projection.get::<i64>("findings")?, 0);
    assert_eq!(stale_projection.get::<i64>("finding_properties")?, 0);
    assert_eq!(projector.rebuild_lifecycle_projection(&tenant, 2).await?, 4);
    assert_eq!(projector.rebuild_lifecycle_projection(&tenant, 2).await?, 4);

    let mut secret_rows = graph
        .execute(
            query(
                "MATCH (entity:SecurityLifecycleSubject {tenant_id: $tenant_id}) RETURN entity.lifecycle_provider_command IS NOT NULL AS has_command, entity.lifecycle_secret_value IS NOT NULL AS has_secret LIMIT 1",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    let secret_row = secret_rows.next().await?.expect("lifecycle row");
    assert!(!secret_row.get::<bool>("has_command")?);
    assert!(!secret_row.get::<bool>("has_secret")?);

    graph
        .run(
            query(
                "CREATE (:OrganizationalEntity {tenant_id: $tenant_id, entity_id: 'malformed-lifecycle', entity_kind: 'resource', authority_json: '{}', label: 'Malformed lifecycle', properties_json: '{\"subject_kind\":\"credential\",\"lifecycle_state\":\"not-a-state\"}', external_id: 'malformed-lifecycle'})",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    projector
        .rebuild_lifecycle_projection(&tenant, 2)
        .await
        .expect_err("malformed projection must fail after invalidating readiness");
    let mut readiness_rows = graph
        .execute(
            query(
                "MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) RETURN state.ready AS ready",
            )
            .param("tenant_id", tenant.as_str()),
        )
        .await?;
    assert!(
        !readiness_rows
            .next()
            .await?
            .expect("projection readiness")
            .get::<bool>("ready")?,
        "a failed rebuild must leave readiness false"
    );

    cleanup(&graph, &tenant).await?;
    Ok(())
}

fn lifecycle_observation(
    tenant: &TenantId,
    locator: &str,
    state: LifecycleState,
    expires_at: Option<&str>,
    owner: &str,
) -> Observation {
    let kind = if locator.starts_with("certificate") {
        SubjectKind::Certificate
    } else {
        SubjectKind::Credential
    };
    let subject_urn = cerebro_security_lifecycle::canonical_resource_urn(
        tenant.as_str(),
        kind,
        "test-authority",
        locator,
    )
    .unwrap();
    Observation {
        subject_ref: ResourceRef {
            kind: kind.as_str().to_owned(),
            id: subject_urn,
            revision: Some(format!("material-{locator}")),
            state: Some(cerebro_security_lifecycle::lifecycle_state_name(state).to_owned()),
        },
        subject_kind: kind,
        provider: "test-provider".to_owned(),
        authority_id: "test-authority".to_owned(),
        stable_locator: locator.to_owned(),
        display_name: locator.to_owned(),
        state,
        observed_at: "2024-07-26T12:00:00Z".to_owned(),
        issued_at: None,
        expires_at: expires_at.map(str::to_owned),
        rotated_at: None,
        revoked_at: None,
        owner_urn: Some(format!("urn:cerebro:{}:team:{owner}", tenant.as_str())),
        scope_refs: Vec::new(),
        evidence_claim_refs: Vec::new(),
        attributes: BTreeMap::from([
            ("environment".to_owned(), "test".to_owned()),
            (
                "source_collection_id".to_owned(),
                "runtime:lifecycle-test:2026-07-26T12:00:00Z".to_owned(),
            ),
        ]),
    }
}

async fn cleanup(graph: &Graph, tenant: &TenantId) -> Result<(), Box<dyn Error>> {
    graph
        .run(
            query("MATCH (node {tenant_id: $tenant_id}) DETACH DELETE node")
                .param("tenant_id", tenant.as_str()),
        )
        .await?;
    Ok(())
}
