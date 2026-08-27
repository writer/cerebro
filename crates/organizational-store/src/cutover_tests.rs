use super::*;
use crate::{
    SemanticSnapshot,
    promotion_evidence_store::test_support::{
        complete_test_verification, empty_test_verification, mismatched_test_verification,
    },
};
use cerebro_source_catalog::{
    PagePublicationReceiptReference, PersistedReceiptReference, SourceCollectionReceiptReference,
};
use cerebro_source_runtime_next::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionSelectionRequestV1,
};
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn qualification(
    catalog: &SourceCatalog,
    source_id: &str,
    family_id: &str,
    corpus: &str,
) -> AuthorityQualificationEvidence {
    let plan_digest = catalog
        .compiled_family_plan_digest(source_id, family_id)
        .unwrap();
    let selection = SourceExecutionSelectionRequestV1 {
        source_id: source_id.to_owned(),
        family_id: family_id.to_owned(),
    };
    let runtime_plan_digest = match SourceExecutionDispatcher.compile_plan(&selection) {
        Ok(plan) => plan.plan_digest_sha256,
        Err(SourceExecutionError::UnknownAdapter) => plan_digest.clone(),
        Err(error) => panic!("compile runtime plan: {error}"),
    };
    AuthorityQualificationEvidence {
        plan_digest,
        runtime_plan_digest,
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
            source_runtime_id: format!("{source_id}-runtime"),
            collection_id: corpus.to_owned(),
            manifest_digest_sha256: "f".repeat(64),
        },
        append_projection_checkpoint_receipt: PagePublicationReceiptReference {
            source_runtime_id: format!("{source_id}-runtime"),
            logical_page_id: "page-test".to_owned(),
            revision: 5,
            snapshot_digest_sha256: "1".repeat(64),
        },
        lease_restart_receipt: PagePublicationReceiptReference {
            source_runtime_id: format!("{source_id}-runtime"),
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

fn asana_verification(
    qualification: &AuthorityQualificationEvidence,
) -> PromotionEvidenceVerification {
    complete_test_verification("tenant-a", "asana", "users", qualification)
}

#[test]
fn promotion_gate_requires_complete_proof_three_matches_and_zero_lag() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let receipts: Vec<_> = (1..=3)
        .map(|index| {
            ParityReceipt::compare_scoped(
                "tenant-a",
                "asana-runtime",
                "asana",
                "users",
                format!("corpus-{index}"),
                "sha256:same",
                "sha256:same",
                true,
                index,
            )
            .unwrap()
        })
        .collect();
    let gate = CutoverGate::new(CutoverPolicy::new(3, 0).unwrap());
    let mut qualification = qualification(&catalog, "asana", "users", "corpus-3");
    qualification.parity_receipt_digests = receipts
        .iter()
        .map(|receipt| receipt.receipt_digest().to_owned())
        .collect();
    let empty_verification = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &receipts,
            0,
            &qualification,
            &empty_test_verification("tenant-a", "asana", "users", &qualification),
        )
        .unwrap();
    assert!(!empty_verification.is_allowed());
    for reason in [
        "verified durable collection proof is missing",
        "verified authenticated collection proof is missing",
        "verified append/projection/checkpoint proof is missing",
        "verified lease/restart proof is missing",
        "verified parity proof is missing",
        "verified runtime revision proof is missing",
        "verified product-read proof is missing",
        "verified promotion approval proof is missing",
        "verified recovery proof is missing",
    ] {
        assert!(
            empty_verification
                .reasons()
                .iter()
                .any(|actual| actual == reason),
            "missing blocker: {reason}"
        );
    }
    let mismatched_product_read = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &receipts,
            0,
            &qualification,
            &mismatched_test_verification(
                "tenant-a",
                "asana",
                "users",
                &qualification,
                VerifiedPromotionReceiptKind::ProductRead,
            ),
        )
        .unwrap();
    assert!(!mismatched_product_read.is_allowed());
    assert!(
        mismatched_product_read
            .reasons()
            .iter()
            .any(|reason| { reason == "verified product-read proof does not match qualification" })
    );
    let tenant_a = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &receipts,
            0,
            &qualification,
            &asana_verification(&qualification),
        )
        .unwrap();
    assert!(tenant_a.is_allowed());
    let tenant_b = gate
        .evaluate(
            &catalog,
            "tenant-b",
            "asana",
            "users",
            &receipts,
            0,
            &qualification,
            &complete_test_verification("tenant-b", "asana", "users", &qualification),
        )
        .unwrap();
    assert!(!tenant_b.is_allowed());
    assert!(
        tenant_b
            .reasons()
            .iter()
            .any(|reason| { reason == "parity receipt tenant does not match promotion request" })
    );
    assert_ne!(tenant_a.evidence_digest(), tenant_b.evidence_digest());
    let shuffled = vec![
        receipts[2].clone(),
        receipts[0].clone(),
        receipts[1].clone(),
    ];
    let shuffled_decision = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &shuffled,
            0,
            &qualification,
            &asana_verification(&qualification),
        )
        .unwrap();
    assert!(
        shuffled_decision.is_allowed(),
        "receipt order must not change the latest qualifying parity sequence"
    );
    assert_eq!(
        shuffled_decision.evidence_digest(),
        tenant_a.evidence_digest()
    );
    assert!(
        !gate
            .evaluate(
                &catalog,
                "tenant-a",
                "asana",
                "users",
                &receipts[..2],
                0,
                &qualification,
                &asana_verification(&qualification),
            )
            .unwrap()
            .is_allowed()
    );
    assert!(
        !gate
            .evaluate(
                &catalog,
                "tenant-a",
                "agiloft",
                "users",
                &receipts,
                0,
                &qualification,
                &asana_verification(&qualification),
            )
            .unwrap()
            .is_allowed()
    );
}

#[test]
fn catalog_only_family_cannot_pass_without_a_closed_runtime_adapter() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let receipts = (1..=3)
        .map(|index| {
            ParityReceipt::compare_scoped(
                "tenant-a",
                "box-runtime",
                "box",
                "content_assets",
                format!("corpus-{index}"),
                "sha256:same",
                "sha256:same",
                true,
                index,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let qualification = qualification(&catalog, "box", "content_assets", "corpus-3");
    let decision = CutoverGate::new(CutoverPolicy::new(3, 0).unwrap())
        .evaluate(
            &catalog,
            "tenant-a",
            "box",
            "content_assets",
            &receipts,
            0,
            &qualification,
            &complete_test_verification("tenant-a", "box", "content_assets", &qualification),
        )
        .unwrap();
    assert!(!decision.is_allowed());
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| { reason == "closed Rust source-execution adapter is not registered" })
    );
}

#[test]
fn promotion_gate_reports_each_failed_proof_instead_of_collapsing_them() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let receipts = vec![
        ParityReceipt::compare_scoped(
            "tenant-a",
            "asana-prod",
            "asana",
            "users",
            "corpus-1",
            "sha256:same",
            "sha256:same",
            true,
            1,
        )
        .unwrap(),
        ParityReceipt::compare_scoped(
            "tenant-a",
            "asana-prod",
            "asana",
            "users",
            "corpus-2",
            "sha256:left",
            "sha256:right",
            true,
            2,
        )
        .unwrap(),
        ParityReceipt::compare_scoped(
            "tenant-a",
            "asana-prod",
            "asana",
            "users",
            "corpus-3",
            "sha256:same",
            "sha256:same",
            false,
            3,
        )
        .unwrap(),
    ];
    let gate = CutoverGate::new(CutoverPolicy::new(3, 0).unwrap());
    let qualification = qualification(&catalog, "asana", "users", "corpus-3");
    let decision = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &receipts,
            4,
            &qualification,
            &asana_verification(&qualification),
        )
        .unwrap();
    assert_eq!(decision.tenant_id(), "tenant-a");
    assert_eq!(decision.source_id(), "asana");
    assert_eq!(decision.family_id(), "users");
    assert!(!decision.is_allowed());
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason.contains("projection lag 4"))
    );
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason.contains("consecutive parity matches"))
    );
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason == "latest corpus comparison is not a match")
    );
    assert!(decision.evidence_digest().starts_with("sha256:"));
    let decision_json = serde_json::to_value(&decision).unwrap();
    assert_eq!(decision_json["tenant_id"], "tenant-a");
    assert_eq!(
        decision_json["qualification"]["product_read_receipt"]["receipt_id"],
        "product-read-test"
    );

    assert_eq!(
        gate.evaluate(
            &catalog,
            "tenant-a",
            "missing",
            "users",
            &receipts,
            0,
            &qualification,
            &asana_verification(&qualification),
        ),
        Err(CutoverError::UnknownSource("missing".to_owned()))
    );
    assert_eq!(
        gate.evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "missing",
            &receipts,
            0,
            &qualification,
            &asana_verification(&qualification),
        ),
        Err(CutoverError::UnknownSource("asana/missing".to_owned()))
    );
}

#[test]
fn receipt_lag_is_checked_independently_of_current_projection_lag() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let base = ParityReceipt::compare_scoped(
        "tenant-a",
        "asana-runtime",
        "asana",
        "users",
        "corpus-1",
        "sha256:same",
        "sha256:same",
        true,
        1,
    )
    .unwrap();
    let legacy = SemanticSnapshot::from_facts(
        "tenant-a",
        "asana-runtime",
        "asana",
        "users",
        "corpus-1",
        "legacy-shadow",
        "legacy",
        true,
        Vec::new(),
    )
    .unwrap();
    let rust = SemanticSnapshot::from_facts(
        "tenant-a",
        "asana-runtime",
        "asana",
        "users",
        "corpus-1",
        "legacy-shadow",
        "rust",
        true,
        Vec::new(),
    )
    .unwrap();
    let lagged = ParityReceipt::compare_snapshots(&legacy, &rust, 3, 2, BTreeMap::new()).unwrap();
    let gate = CutoverGate::new(CutoverPolicy::new(3, 0).unwrap());
    let qualification = qualification(&catalog, "asana", "users", "corpus-1");
    let decision = gate
        .evaluate(
            &catalog,
            "tenant-a",
            "asana",
            "users",
            &[base.clone(), base, lagged],
            0,
            &qualification,
            &asana_verification(&qualification),
        )
        .unwrap();
    assert!(!decision.is_allowed());
    assert!(
        decision
            .reasons()
            .iter()
            .any(|reason| reason == "a latest parity receipt exceeds the projection lag policy")
    );
}
