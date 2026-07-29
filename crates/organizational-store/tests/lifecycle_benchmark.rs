use std::{env, error::Error, time::Instant};

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CollectionId, CompleteCollection, Entity, EntityId, EntityKind, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::Neo4jProjector;
use cerebro_security_lifecycle::{
    LifecycleQuery, LifecycleState, SubjectKind, finalize_indexed_query, prepare_indexed_query,
};
use neo4rs::{Graph, query};
use serde::Serialize;

#[derive(Serialize)]
struct Measurement {
    operation: &'static str,
    lifecycle_entities: usize,
    iterations: usize,
    total_ms: f64,
    milliseconds_per_iteration: f64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable Neo4j instance and explicitly requested scale volume"]
async fn benchmark_lifecycle_projection_at_10k_and_100k() -> Result<(), Box<dyn Error>> {
    let uri = env::var("CEREBRO_TEST_NEO4J_URI")?;
    let username = env::var("CEREBRO_TEST_NEO4J_USERNAME")?;
    let password = env::var("CEREBRO_TEST_NEO4J_PASSWORD")?;
    let graph = Graph::new(&uri, &username, &password).await?;
    let projector = Neo4jProjector::from_graph(graph.clone());
    projector.migrate().await?;

    for entity_count in [10_000_usize, 100_000] {
        let tenant = TenantId::parse(format!(
            "tenant-lifecycle-benchmark-{entity_count}-{}",
            std::process::id()
        ))?;
        cleanup(&graph, &tenant).await?;

        let construction_started = Instant::now();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("lifecycle-benchmark")?,
            CollectionId::parse(format!("lifecycle-benchmark-{entity_count}"))?,
            "security.lifecycle",
            1_721_995_200_000,
        )?;
        let mut builder = collection.begin_delta();
        for index in 0..entity_count {
            let kind = if index % 5 == 0 {
                SubjectKind::Certificate
            } else {
                SubjectKind::Credential
            };
            let state = match index % 7 {
                0 => LifecycleState::Expired,
                1 => LifecycleState::Expiring,
                2 => LifecycleState::Rotated,
                _ => LifecycleState::Active,
            };
            let locator = format!("slot/{index:06}");
            let subject_urn = cerebro_security_lifecycle::canonical_resource_urn(
                tenant.as_str(),
                kind,
                "benchmark-authority",
                &locator,
            )?;
            let owner_urn = format!("urn:cerebro:{}:team:team-{}", tenant.as_str(), index % 20);
            let mut entity = Entity::canonical(
                tenant.clone(),
                EntityId::parse(format!("lifecycle-resource-{index:06}"))?,
                EntityKind::Resource,
                format!("Lifecycle subject {index}"),
            )?
            .with_property("resource_urn", subject_urn)?
            .with_property("material_revision", format!("material-{index:06}"))?
            .with_property("subject_kind", kind.as_str())?
            .with_property(
                "lifecycle_state",
                cerebro_security_lifecycle::lifecycle_state_name(state),
            )?
            .with_property("provider", "benchmark-provider")?
            .with_property("authority_id", "benchmark-authority")?
            .with_property("stable_locator", locator)?
            .with_property("observed_at", "2024-07-26T12:00:00Z")?
            .with_property("owner_urn", owner_urn)?;
            if matches!(
                state,
                LifecycleState::Active | LifecycleState::Expiring | LifecycleState::Expired
            ) {
                let expiry = if index % 3 == 0 {
                    "2026-07-01T12:00:00Z"
                } else {
                    "2027-07-01T12:00:00Z"
                };
                entity = entity.with_property("expires_at", expiry)?;
            }
            builder.add_entity(entity)?;
        }
        let delta = builder.build();
        emit(
            "construct_projection_input",
            entity_count,
            1,
            construction_started.elapsed(),
        )?;

        let receipt = GraphWriteReceipt {
            tenant_id: tenant.clone(),
            graph_revision: 1,
            delta_digest: delta.digest().to_owned(),
            entities_upserted: delta.entities().len(),
            assertions_upserted: 0,
            assertions_retracted: 0,
        };
        let projection_started = Instant::now();
        projector.project(&delta, &receipt).await?;
        emit(
            "project_lifecycle_metadata",
            entity_count,
            1,
            projection_started.elapsed(),
        )?;

        let rebuild_started = Instant::now();
        let rebuilt = projector
            .rebuild_lifecycle_projection(&tenant, 1_000)
            .await?;
        if rebuilt != entity_count {
            return Err(format!("rebuilt {rebuilt}, want {entity_count}").into());
        }
        emit(
            "rebuild_lifecycle_projection",
            entity_count,
            1,
            rebuild_started.elapsed(),
        )?;

        let replay_started = Instant::now();
        projector.project(&delta, &receipt).await?;
        emit(
            "idempotent_projection_replay",
            entity_count,
            1,
            replay_started.elapsed(),
        )?;

        let lifecycle_query = LifecycleQuery {
            subject_kinds: vec![SubjectKind::Credential],
            states: vec![LifecycleState::Active, LifecycleState::Expired],
            owner_urns: vec![format!("urn:cerebro:{}:team:team-7", tenant.as_str())],
            expires_before: Some("2028-01-01T00:00:00Z".to_owned()),
            limit: Some(100),
            ..LifecycleQuery::default()
        };
        let prepared = prepare_indexed_query(&tenant, &lifecycle_query, "2026-07-26T12:00:00Z", 1)?;
        let warmup = projector.query_lifecycle(&tenant, &prepared).await?;
        let warmup = finalize_indexed_query(&tenant, &prepared, warmup)?;
        if !warmup.metadata.coverage.complete || warmup.records.is_empty() {
            return Err("filtered lifecycle warmup was incomplete or empty".into());
        }
        let iterations = 20;
        let read_started = Instant::now();
        for _ in 0..iterations {
            let page = projector.query_lifecycle(&tenant, &prepared).await?;
            let result = finalize_indexed_query(&tenant, &prepared, page)?;
            if !result.metadata.coverage.complete || !result.aggregates.counts_are_exact {
                return Err("indexed lifecycle read lost exact coverage".into());
            }
        }
        emit(
            "filtered_aggregate_and_keyset_page",
            entity_count,
            iterations,
            read_started.elapsed(),
        )?;
        cleanup(&graph, &tenant).await?;
    }
    Ok(())
}

fn emit(
    operation: &'static str,
    lifecycle_entities: usize,
    iterations: usize,
    elapsed: std::time::Duration,
) -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string(&Measurement {
            operation,
            lifecycle_entities,
            iterations,
            total_ms: elapsed.as_secs_f64() * 1_000.0,
            milliseconds_per_iteration: elapsed.as_secs_f64() * 1_000.0 / iterations as f64,
        })?
    );
    Ok(())
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
