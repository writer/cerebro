use std::{
    env,
    error::Error,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{
    CutoverPolicy, ParityReceipt, PostgresLedger, ProjectionAuthority, ProjectionPromotionRequest,
};
use cerebro_source_catalog::SourceCatalog;
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn persisted_cutover_requires_three_matching_receipts_and_is_irreversible()
-> Result<(), Box<dyn Error>> {
    let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        connection.await.expect("PostgreSQL test connection");
    });
    let ledger = PostgresLedger::from_client(client);
    ledger.migrate().await?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let tenant_id = format!("cutover-{suffix}");
    for index in 1..=3 {
        ledger
            .record_parity(&ParityReceipt::compare_scoped(
                tenant_id.clone(),
                "box-runtime",
                "box",
                "users",
                format!("cutover-{suffix}-{index}"),
                "sha256:equal",
                "sha256:equal",
                true,
                index,
            )?)
            .await?;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )?;
    let authority = ledger
        .evaluate_and_promote_projection_authority(
            &catalog,
            &ProjectionPromotionRequest::new(
                tenant_id.clone(),
                "box",
                "users",
                CutoverPolicy::new(3, 0)?,
                0,
                100,
            )?,
        )
        .await?;
    assert_eq!(authority.authority, ProjectionAuthority::Rust);
    assert_eq!(
        ledger
            .projection_authority(&tenant_id, "box", "users")
            .await?
            .authority,
        ProjectionAuthority::Rust
    );

    ledger
        .record_parity(&ParityReceipt::compare_scoped(
            tenant_id.clone(),
            "box-runtime",
            "box",
            "users",
            format!("cutover-{suffix}-4"),
            "sha256:equal",
            "sha256:equal",
            true,
            4,
        )?)
        .await?;
    assert!(
        ledger
            .evaluate_and_promote_projection_authority(
                &catalog,
                &ProjectionPromotionRequest::new(
                    tenant_id.clone(),
                    "box",
                    "users",
                    CutoverPolicy::new(3, 0)?,
                    0,
                    101,
                )?,
            )
            .await
            .is_err()
    );
    Ok(())
}
