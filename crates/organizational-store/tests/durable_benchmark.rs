use std::{
    collections::BTreeMap,
    env,
    error::Error,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cerebro_agent_context::AgentGraph;
use cerebro_organizational_model::{
    AssertionProvenance, CollectionId, CompleteCollection, Entity, EntityKind, GraphAssertion,
    ObservationId, ObservationRef, ProviderKind, RelationKind, RelationshipAssertion,
    SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{DurableGraphStore, Neo4jProjector, PostgresLedger};
use cerebro_source_runtime_next::{CollectedBatch, CollectedScope, GraphSink, SourceRecord};
use serde::Serialize;
use tokio_postgres::NoTls;

#[derive(Serialize)]
struct Measurement {
    operation: &'static str,
    records: usize,
    iterations: usize,
    total_ms: f64,
    micros_per_operation: f64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires disposable PostgreSQL and Neo4j instances"]
async fn benchmark_durable_store_and_traversal() -> Result<(), Box<dyn Error>> {
    let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let neo4j_uri = env::var("CEREBRO_TEST_NEO4J_URI")?;
    let neo4j_username = env::var("CEREBRO_TEST_NEO4J_USERNAME")?;
    let neo4j_password = env::var("CEREBRO_TEST_NEO4J_PASSWORD")?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();

    let ledger = connect_ledger(&postgres_dsn).await?;
    ledger.migrate().await?;
    let projector = Neo4jProjector::connect(&neo4j_uri, &neo4j_username, &neo4j_password).await?;
    projector.migrate().await?;
    let reader = projector.clone();
    let mut store = DurableGraphStore::new(ledger, projector.clone());

    for records in [100, 1_000] {
        let (batch, delta) = entity_batch(&suffix, records, &format!("batch-{records}"))?;
        let started = Instant::now();
        store.apply(&batch, delta).await?;
        let elapsed = started.elapsed();
        emit(Measurement {
            operation: "provider_batch_to_postgres_and_neo4j",
            records,
            iterations: 1,
            total_ms: millis(elapsed),
            micros_per_operation: elapsed.as_secs_f64() * 1_000_000.0,
        })?;
    }

    let recovery_ledger = connect_ledger(&postgres_dsn).await?;
    let (recovery_batch, recovery_delta) = entity_batch(&suffix, 100, "recovery")?;
    recovery_ledger
        .commit_pending(&recovery_batch, &recovery_delta)
        .await?;
    let recovery_store = DurableGraphStore::new(recovery_ledger, projector.clone());
    let recovery_tenant = recovery_delta.collection().tenant_id().as_str().to_owned();
    let started = Instant::now();
    let replayed = recovery_store.replay_pending(&recovery_tenant, 100).await?;
    if replayed != 1 {
        return Err(format!("replayed {replayed} revisions, want 1").into());
    }
    emit(Measurement {
        operation: "outbox_recovery",
        records: 100,
        iterations: 1,
        total_ms: millis(started.elapsed()),
        micros_per_operation: started.elapsed().as_secs_f64() * 1_000_000.0,
    })?;

    let (path_batch, path_delta, path_entities) = path_batch(&suffix)?;
    store.apply(&path_batch, path_delta).await?;
    for depth in [1, 3, 6] {
        let iterations = 200;
        let started = Instant::now();
        for _ in 0..iterations {
            let paths = reader
                .find_paths(
                    path_batch.scope.receipt().tenant_id(),
                    path_entities[0].id(),
                    path_entities[depth].id(),
                    depth,
                    10,
                )
                .await?;
            if paths.len() != 1 || paths[0].edges.len() != depth {
                return Err(format!("depth {depth} returned an invalid path").into());
            }
        }
        let elapsed = started.elapsed();
        emit(Measurement {
            operation: match depth {
                1 => "one_hop_read",
                3 => "three_hop_read",
                _ => "six_hop_read",
            },
            records: depth,
            iterations,
            total_ms: millis(elapsed),
            micros_per_operation: elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64,
        })?;
    }

    let started = Instant::now();
    let mut tasks = Vec::new();
    for tenant_index in 0..8 {
        let postgres_dsn = postgres_dsn.clone();
        let projector = projector.clone();
        let suffix = suffix.clone();
        tasks.push(tokio::spawn(async move {
            let ledger = connect_ledger(&postgres_dsn)
                .await
                .map_err(|error| error.to_string())?;
            let mut store = DurableGraphStore::new(ledger, projector);
            let (batch, delta) = entity_batch(&suffix, 100, &format!("concurrent-{tenant_index}"))
                .map_err(|error| error.to_string())?;
            store
                .apply(&batch, delta)
                .await
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        }));
    }
    for task in tasks {
        task.await?.map_err(std::io::Error::other)?;
    }
    let elapsed = started.elapsed();
    emit(Measurement {
        operation: "eight_tenant_concurrent_commit",
        records: 800,
        iterations: 8,
        total_ms: millis(elapsed),
        micros_per_operation: elapsed.as_secs_f64() * 1_000_000.0 / 8.0,
    })?;
    Ok(())
}

async fn connect_ledger(dsn: &str) -> Result<PostgresLedger, Box<dyn Error>> {
    let (client, connection) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("benchmark PostgreSQL connection closed: {error}");
        }
    });
    Ok(PostgresLedger::from_client(client))
}

fn entity_batch(
    suffix: &str,
    records: usize,
    name: &str,
) -> Result<(CollectedBatch, cerebro_organizational_model::GraphDelta), Box<dyn Error>> {
    let tenant = TenantId::parse(format!("bench-{name}-{suffix}"))?;
    let runtime = SourceRuntimeId::parse("benchmark-runtime")?;
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse(format!("collection-{name}"))?,
        "benchmark.assets",
        10,
    )?;
    let mut builder = collection.clone().begin_delta();
    let mut source_records = Vec::with_capacity(records);
    for index in 0..records {
        let provider_id = format!("asset-{index:05}");
        let observation_id = ObservationId::parse(format!("observation-{index:05}"))?;
        builder.add_entity(Entity::provider(
            tenant.clone(),
            runtime.clone(),
            ProviderKind::parse("benchmark.asset")?,
            provider_id.clone(),
            EntityKind::Resource,
            format!("Asset {index:05}"),
        )?)?;
        source_records.push(SourceRecord {
            observation_id,
            family: "assets".to_owned(),
            provider_kind: "benchmark.asset".to_owned(),
            provider_id: provider_id.clone(),
            fields: BTreeMap::from([("resource_id".to_owned(), provider_id.clone())]),
            payload: serde_json::json!({"id": provider_id}),
        });
    }
    Ok((
        CollectedBatch {
            scope: CollectedScope::Complete(collection),
            records: source_records,
            next_cursor: None,
        },
        builder.build(),
    ))
}

fn path_batch(
    suffix: &str,
) -> Result<
    (
        CollectedBatch,
        cerebro_organizational_model::GraphDelta,
        Vec<Entity>,
    ),
    Box<dyn Error>,
> {
    let tenant = TenantId::parse(format!("bench-path-{suffix}"))?;
    let runtime = SourceRuntimeId::parse("benchmark-runtime")?;
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-path")?,
        "benchmark.path",
        10,
    )?;
    let observation_id = ObservationId::parse("observation-path")?;
    let provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                collection.receipt(),
                observation_id.clone(),
                "benchmark.path",
            )?],
            "benchmark-mapper",
            "v1",
        )
    };
    let entities = (0..=6)
        .map(|index| {
            Entity::provider(
                tenant.clone(),
                runtime.clone(),
                ProviderKind::parse("benchmark.asset")?,
                format!("path-{index}"),
                EntityKind::Resource,
                format!("Path {index}"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut builder = collection.clone().begin_delta();
    for entity in &entities {
        builder.add_entity(entity.clone())?;
    }
    for endpoints in entities.windows(2) {
        builder.add_assertion(GraphAssertion::Relationship(RelationshipAssertion::new(
            &endpoints[0],
            RelationKind::DependsOn,
            &endpoints[1],
            provenance()?,
            10,
        )?))?;
    }
    Ok((
        CollectedBatch {
            scope: CollectedScope::Complete(collection),
            records: vec![SourceRecord {
                observation_id,
                family: "path".to_owned(),
                provider_kind: "benchmark.path".to_owned(),
                provider_id: "path".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({"id": "path"}),
            }],
            next_cursor: None,
        },
        builder.build(),
        entities,
    ))
}

fn emit(measurement: Measurement) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string(&measurement)?);
    Ok(())
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
