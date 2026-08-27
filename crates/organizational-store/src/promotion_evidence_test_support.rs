use super::*;
use cerebro_source_catalog::AuthorityQualificationEvidence;

pub(crate) fn complete_test_verification(
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    qualification: &AuthorityQualificationEvidence,
) -> PromotionEvidenceVerification {
    let collection = &qualification.authenticated_collection_receipt;
    let append = &qualification.append_projection_checkpoint_receipt;
    let restart = &qualification.lease_restart_receipt;
    let mut receipts = vec![
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::DurableCollection,
            collection.collection_id.clone(),
            collection.manifest_digest_sha256.clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::AuthenticatedCollection,
            collection.collection_id.clone(),
            collection.manifest_digest_sha256.clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::AppendProjectionCheckpoint,
            append.logical_page_id.clone(),
            append.snapshot_digest_sha256.clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::LeaseRestart,
            restart.logical_page_id.clone(),
            restart.snapshot_digest_sha256.clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::RuntimeRevision,
            qualification.runtime_revision_sha256.clone(),
            qualification.runtime_revision_sha256.clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::ProductRead,
            qualification.product_read_receipt.receipt_id.clone(),
            qualification
                .product_read_receipt
                .receipt_digest_sha256
                .clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::PromotionApproval,
            qualification.promotion_receipt.receipt_id.clone(),
            qualification
                .promotion_receipt
                .receipt_digest_sha256
                .clone(),
        ),
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::Recovery,
            qualification.rollback_receipt.receipt_id.clone(),
            qualification.rollback_receipt.receipt_digest_sha256.clone(),
        ),
    ];
    receipts.extend(qualification.parity_receipt_digests.iter().map(|digest| {
        VerifiedPromotionReceipt::new(
            VerifiedPromotionReceiptKind::Parity,
            digest.clone(),
            digest.clone(),
        )
    }));
    PromotionEvidenceVerification::verified_by_store(
        tenant_id,
        source_id,
        family_id,
        &collection.source_runtime_id,
        &qualification.runtime_revision_sha256,
        Vec::new(),
        receipts,
    )
}

pub(crate) fn empty_test_verification(
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    qualification: &AuthorityQualificationEvidence,
) -> PromotionEvidenceVerification {
    PromotionEvidenceVerification::verified_by_store(
        tenant_id,
        source_id,
        family_id,
        &qualification
            .authenticated_collection_receipt
            .source_runtime_id,
        &qualification.runtime_revision_sha256,
        Vec::new(),
        Vec::new(),
    )
}

pub(crate) fn mismatched_test_verification(
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    qualification: &AuthorityQualificationEvidence,
    kind: VerifiedPromotionReceiptKind,
) -> PromotionEvidenceVerification {
    let mut verification =
        complete_test_verification(tenant_id, source_id, family_id, qualification);
    verification
        .receipts
        .iter_mut()
        .find(|receipt| receipt.kind == kind)
        .expect("complete test verification contains every receipt kind")
        .receipt_digest = "0".repeat(64);
    verification
}
