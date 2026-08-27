use std::{
    env,
    error::Error,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{
    CutoverPolicy, ParityReceipt, PostgresLedger, ProjectionAuthority, ProjectionPromotionRequest,
};
use cerebro_source_catalog::{
    AuthorityQualificationEvidence, PagePublicationReceiptReference, PersistedReceiptReference,
    SourceCatalog, SourceCollectionReceiptReference,
};
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
        rollback_receipt: PersistedReceiptReference {
            receipt_id: "rollback-test".to_owned(),
            receipt_digest_sha256: "c".repeat(64),
        },
        parity_status: "passed".to_owned(),
        canonical_digest_vectors: vec!["plan".to_owned()],
        config_safety_proof: "receipt:config".to_owned(),
        cursor_checkpoint_proof: "receipt:checkpoint".to_owned(),
        fencing_recovery_proof: "receipt:fencing".to_owned(),
        runtime_revision_sha256: "d".repeat(64),
        worker_runtime_build_identity: "source-runtime-next:test".to_owned(),
        promotion_receipt: PersistedReceiptReference {
            receipt_id: "promotion-test".to_owned(),
            receipt_digest_sha256: "e".repeat(64),
        },
        authenticated_collection_receipt: SourceCollectionReceiptReference {
            source_runtime_id: "asana-runtime".to_owned(),
            collection_id: corpus.to_owned(),
            manifest_digest_sha256: "f".repeat(64),
        },
        append_projection_checkpoint_receipt: PagePublicationReceiptReference {
            source_runtime_id: "asana-runtime".to_owned(),
            logical_page_id: "page-test".to_owned(),
            revision: 5,
            snapshot_digest_sha256: "1".repeat(64),
        },
        lease_restart_receipt: PagePublicationReceiptReference {
            source_runtime_id: "asana-runtime".to_owned(),
            logical_page_id: "page-restart-test".to_owned(),
            revision: 6,
            snapshot_digest_sha256: "2".repeat(64),
        },
        product_read_receipt: PersistedReceiptReference {
            receipt_id: "product-read-test".to_owned(),
            receipt_digest_sha256: "3".repeat(64),
        },
        parity_receipt_digests: vec!["4".repeat(64), "5".repeat(64), "6".repeat(64)],
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn persisted_promotion_rejects_fabricated_and_unverifiable_receipt_references()
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
    let mut parity_digests = Vec::new();
    for index in 1..=3 {
        let receipt = ParityReceipt::compare_scoped(
            tenant_id.clone(),
            "asana-runtime",
            "asana",
            "users",
            format!("promotion-evidence-{suffix}-{index}"),
            "sha256:equal",
            "sha256:equal",
            true,
            index,
        )?;
        parity_digests.push(receipt.receipt_digest().to_owned());
        ledger.record_parity(&receipt).await?;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )?;
    let mut evidence = qualification(
        &catalog,
        "asana",
        "users",
        &format!("promotion-evidence-{suffix}-3"),
    );
    evidence.parity_receipt_digests = parity_digests;
    ledger
        .record_source_collection(
            &format!("other-tenant-{suffix}"),
            &evidence.authenticated_collection_receipt.collection_id,
            &evidence.authenticated_collection_receipt.source_runtime_id,
            "asana",
            1,
            2,
            "complete",
            1,
            1,
            1,
            0,
            1,
            0,
            &evidence
                .authenticated_collection_receipt
                .manifest_digest_sha256,
            &serde_json::json!({"observed_family_ids": ["users"]}),
        )
        .await?;
    let request = ProjectionPromotionRequest::new(
        tenant_id.clone(),
        "asana",
        "users",
        CutoverPolicy::new(3, 0)?,
        0,
        100,
        evidence,
    )?;
    let decision = ledger
        .evaluate_projection_authority(&catalog, &request)
        .await?;
    assert!(!decision.is_allowed());
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason == "persisted collection receipt was not found")
    );
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason == "product-read receipt verifier is unavailable")
    );
    assert_eq!(
        ledger
            .projection_authority(&tenant_id, "asana", "users")
            .await?
            .authority,
        ProjectionAuthority::Legacy,
        "evaluation must not change authority"
    );
    assert!(
        ledger
            .evaluate_and_promote_projection_authority(&catalog, &request)
            .await
            .is_err()
    );
    assert_eq!(
        ledger
            .projection_authority(&tenant_id, "asana", "users")
            .await?
            .authority,
        ProjectionAuthority::Legacy
    );
    Ok(())
}
