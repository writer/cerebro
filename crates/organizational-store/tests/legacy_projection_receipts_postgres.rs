use std::{collections::BTreeMap, env, error::Error};

use cerebro_organizational_model::{ObservationId, SourceRuntimeId, TenantId};
use cerebro_organizational_store::{PostgresLedger, StoreError};
use cerebro_source_runtime_next::{CommittedSourceEvent, CommittedSourceInput};
use serde_json::{Value, json};
use tokio_postgres::NoTls;

const TENANT: &str = "tenant-legacy-receipts";
const RUNTIME: &str = "aws-legacy-receipts";

fn delta(collection_id: &str, role_name: &str) -> Value {
    json!({
        "entities": [{
            "urn": "urn:cerebro:tenant-legacy-receipts:aws_iam_role:role-1",
            "label": role_name,
            "attributes": {"source_collection_id": collection_id, "role_name": role_name}
        }],
        "links": [],
        "entity_retractions": [],
        "link_retractions": [],
        "cleanup_requests": []
    })
}

async fn record(ledger: &PostgresLedger, event_id: &str, delta: &Value) -> Result<(), StoreError> {
    ledger
        .record_legacy_projection(
            TENANT,
            event_id,
            RUNTIME,
            "aws",
            "iam_role",
            1_791_000_000_000,
            1,
            0,
            0,
            0,
            0,
            &format!(
                "digest-{}",
                delta["entities"][0]["attributes"]["source_collection_id"]
            ),
            delta,
        )
        .await
        .map(|_| ())
}

async fn receipt(dsn: &str, event_id: &str) -> Result<(i64, Value), Box<dyn Error>> {
    let (client, connection) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(connection);
    client
        .execute(
            "SELECT set_config('cerebro.tenant_id', $1, false)",
            &[&TENANT],
        )
        .await?;
    let row = client
        .query_one(
            "SELECT revision, delta_json FROM organizational_legacy_projection_receipts WHERE tenant_id = $1 AND event_id = $2",
            &[&TENANT, &event_id],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance"]
async fn legacy_receipts_replay_idempotently_and_revise_on_change() -> Result<(), Box<dyn Error>> {
    let dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(connection);
    let ledger = PostgresLedger::from_client(client);
    ledger.migrate().await?;

    let event_id = "aws-iam-role-role-1";
    ledger
        .record_source_event(&CommittedSourceEvent::from_input(CommittedSourceInput {
            tenant_id: TenantId::parse(TENANT)?,
            source_runtime_id: SourceRuntimeId::parse(RUNTIME)?,
            observation_id: ObservationId::parse(event_id)?,
            source_id: "aws".to_owned(),
            family_id: "iam_role".to_owned(),
            event_kind: "aws.iam_role".to_owned(),
            schema_ref: "aws/iam_role/v1".to_owned(),
            observed_at_unix_ms: 1_791_000_000_000,
            attributes: BTreeMap::new(),
            payload: json!({"role_name": "role-1"}),
        })?)
        .await?;

    record(&ledger, event_id, &delta("run-a", "role-1")).await?;
    // A later run re-reads the unchanged event with new collection provenance.
    record(&ledger, event_id, &delta("run-b", "role-1")).await?;
    let (revision, stored) = receipt(&dsn, event_id).await?;
    assert_eq!(revision, 1);
    assert_eq!(stored, delta("run-a", "role-1"));

    // The provider state changed under the same event ID.
    record(&ledger, event_id, &delta("run-c", "role-1-renamed")).await?;
    let (revision, stored) = receipt(&dsn, event_id).await?;
    assert_eq!(revision, 2);
    assert_eq!(stored, delta("run-c", "role-1-renamed"));

    match record(&ledger, "aws-iam-role-never-consumed", &delta("run-a", "x")).await {
        Err(StoreError::Conflict(message)) => {
            assert!(
                message.contains("has no committed source event receipt"),
                "{message}"
            );
        }
        other => panic!("missing source receipt must be an explicit conflict, got {other:?}"),
    }
    Ok(())
}
