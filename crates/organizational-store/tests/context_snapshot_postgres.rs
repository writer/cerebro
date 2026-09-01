use std::{env, error::Error};

use cerebro_agent_context::{ContextSelectorV1, ContextSnapshotRequestV1, ContextSnapshotV1};
use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::TenantId;
use cerebro_organizational_store::PostgresLedger;
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance"]
async fn immutable_context_snapshot_receipt_is_idempotent_and_tenant_isolated()
-> Result<(), Box<dyn Error>> {
    let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        connection.await.expect("PostgreSQL test connection");
    });
    let ledger = PostgresLedger::from_client(client);
    ledger.migrate().await?;

    let tenant = TenantId::parse("context-snapshot-tenant-a")?;
    let graph = OrganizationalGraph::new();
    let request = ContextSnapshotRequestV1::new(
        tenant.clone(),
        vec![ContextSelectorV1::canonical_person("person-missing")?],
        10,
    )?;
    let snapshot = ContextSnapshotV1::capture(&graph, request)?;

    let first = ledger.record_context_snapshot(&snapshot).await?;
    let replay = ledger.record_context_snapshot(&snapshot).await?;
    assert_eq!(first, replay);
    assert_eq!(
        ledger
            .context_snapshot_receipt(&tenant, snapshot.snapshot_id())
            .await?,
        Some(first)
    );
    assert!(
        ledger
            .context_snapshot_receipt(
                &TenantId::parse("context-snapshot-tenant-b")?,
                snapshot.snapshot_id(),
            )
            .await?
            .is_none()
    );
    Ok(())
}
