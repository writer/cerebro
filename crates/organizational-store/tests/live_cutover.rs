use std::{
    env,
    error::Error,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{
    CutoverPolicy, ParityReceipt, PostgresLedger, ProjectionAuthority, ProjectionPromotionRequest,
};
use cerebro_source_catalog::{AuthorityQualificationEvidence, SourceCatalog};
use tokio_postgres::NoTls;

fn qualification(
    catalog: &SourceCatalog,
    source_id: &str,
    family_id: &str,
    corpus: &str,
) -> AuthorityQualificationEvidence {
    let plan_digest = catalog
        .compiled_family_plan_digest(source_id, family_id)
        .unwrap();
    let runtime_plan_digest =
        cerebro_source_runtime_next::source_execution::SourceExecutionDispatcher
            .compile_plan(
                &cerebro_source_runtime_next::source_execution::SourceExecutionSelectionRequestV1 {
                    source_id: source_id.to_owned(),
                    family_id: family_id.to_owned(),
                },
            )
            .unwrap()
            .plan_digest_sha256;
    AuthorityQualificationEvidence {
        runtime_plan_digest,
        plan_digest,
        fixture_corpus_revision: corpus.to_owned(),
        supported_auth_modes: vec!["api_key".to_owned()],
        supported_pagination_grammar: vec!["cursor".to_owned()],
        supported_provider_errors: vec!["unauthorized".to_owned()],
        egress_allowlist: vec!["https://provider.example.test".to_owned()],
        response_limits: "body=1048576,decompression=4x".to_owned(),
        credential_lease_mode: "one_operation".to_owned(),
        projection_dependency: "rust_projection".to_owned(),
        rollback_receipt: "receipt:rollback".to_owned(),
        parity_status: "passed".to_owned(),
        canonical_digest_vectors: vec!["plan".to_owned()],
        config_safety_proof: "receipt:config".to_owned(),
        cursor_checkpoint_proof: "receipt:checkpoint".to_owned(),
        fencing_recovery_proof: "receipt:fencing".to_owned(),
        worker_build_id: "source-runtime-next:test".to_owned(),
        promotion_receipt: "sig:promotion:test".to_owned(),
        authenticated_collection_receipt: "receipt:collection".to_owned(),
        append_projection_checkpoint_receipt: "receipt:durable".to_owned(),
        lease_restart_receipt: "receipt:restart".to_owned(),
        product_read_receipt: "receipt:product-read".to_owned(),
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn persisted_promotion_requires_complete_evidence_and_three_matching_receipts()
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
    let tenant_id = format!("promotion-evidence-{suffix}");
    for index in 1..=3 {
        ledger
            .record_parity(&ParityReceipt::compare_scoped(
                tenant_id.clone(),
                "asana-runtime",
                "asana",
                "users",
                format!("promotion-evidence-{suffix}-{index}"),
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
    let request = ProjectionPromotionRequest::new(
        tenant_id.clone(),
        "asana",
        "users",
        CutoverPolicy::new(3, 0)?,
        0,
        100,
        qualification(
            &catalog,
            "asana",
            "users",
            &format!("promotion-evidence-{suffix}-3"),
        ),
    )?;
    let decision = ledger
        .evaluate_projection_authority(&catalog, &request)
        .await?;
    assert!(decision.is_allowed());
    assert_eq!(
        ledger
            .projection_authority(&tenant_id, "asana", "users")
            .await?
            .authority,
        ProjectionAuthority::Legacy,
        "evaluation must not change authority"
    );
    let authority = ledger
        .evaluate_and_promote_projection_authority(&catalog, &request)
        .await?;
    assert_eq!(authority.authority, ProjectionAuthority::Rust);

    let (mut inspection, inspection_connection) =
        tokio_postgres::connect(&postgres_dsn, NoTls).await?;
    tokio::spawn(async move {
        inspection_connection
            .await
            .expect("PostgreSQL inspection connection");
    });
    let inspection_transaction = inspection.transaction().await?;
    inspection_transaction
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
    let persisted_decision: serde_json::Value = inspection_transaction
        .query_one(
            "SELECT decision_json FROM organizational_projection_authority WHERE tenant_id = $1 AND source_id = 'asana' AND family_id = 'users'",
            &[&tenant_id],
        )
        .await?
        .get(0);
    inspection_transaction.commit().await?;
    assert_eq!(
        persisted_decision["tenant_id"].as_str(),
        Some(tenant_id.as_str())
    );
    assert_eq!(
        persisted_decision["qualification"]["product_read_receipt"],
        "receipt:product-read"
    );
    assert_eq!(
        ledger
            .projection_authority(&tenant_id, "asana", "users")
            .await?
            .authority,
        ProjectionAuthority::Rust
    );

    ledger
        .record_parity(&ParityReceipt::compare_scoped(
            tenant_id.clone(),
            "asana-runtime",
            "asana",
            "users",
            format!("promotion-evidence-{suffix}-4"),
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
                    "asana",
                    "users",
                    CutoverPolicy::new(3, 0)?,
                    0,
                    101,
                    qualification(
                        &catalog,
                        "asana",
                        "users",
                        &format!("promotion-evidence-{suffix}-4"),
                    ),
                )?,
            )
            .await
            .is_err()
    );
    Ok(())
}
