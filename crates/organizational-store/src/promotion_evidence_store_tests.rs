use super::*;
use cerebro_source_catalog::SourceCollectionReceiptReference;

fn page_reference() -> PagePublicationReceiptReference {
    PagePublicationReceiptReference {
        source_runtime_id: "runtime-a".to_owned(),
        logical_page_id: "page-a".to_owned(),
        revision: 8,
        snapshot_digest_sha256: "a".repeat(64),
    }
}

#[test]
fn persisted_page_verification_rejects_cross_family_stale_and_incomplete_states() {
    let reference = page_reference();
    assert_eq!(
        page_block_reason(
            "asana",
            "users",
            &reference,
            "runtime-a",
            "asana",
            "projects",
            "committed",
            PagePublicationState::Committed,
            true,
            &"a".repeat(64),
            false,
            Some(2),
        ),
        Some("{kind} page source family does not match promotion request".to_owned())
    );
    assert_eq!(
        page_block_reason(
            "asana",
            "users",
            &reference,
            "runtime-a",
            "asana",
            "users",
            "committed",
            PagePublicationState::Committed,
            false,
            &"a".repeat(64),
            false,
            Some(2),
        ),
        Some("{kind} page revision is stale".to_owned())
    );
    for (stored_state, page_state) in [
        ("published", PagePublicationState::Published),
        ("projected", PagePublicationState::Projected),
        ("publishing", PagePublicationState::Publishing),
    ] {
        assert_eq!(
            page_block_reason(
                "asana",
                "users",
                &reference,
                "runtime-a",
                "asana",
                "users",
                stored_state,
                page_state,
                true,
                &"a".repeat(64),
                true,
                Some(1),
            ),
            Some("{kind} page did not commit append projection and checkpoint".to_owned())
        );
    }
}

#[test]
fn persisted_collection_verification_rejects_scope_digest_and_family_mismatches() {
    let reference = SourceCollectionReceiptReference {
        source_runtime_id: "runtime-a".to_owned(),
        collection_id: "collection-a".to_owned(),
        manifest_digest_sha256: "a".repeat(64),
    };
    assert_eq!(
        collection_block_reason(
            "asana",
            &reference,
            "runtime-b",
            "asana",
            "complete",
            1,
            1,
            0,
            1,
            0,
            &"a".repeat(64),
            true,
        ),
        Some("collection receipt runtime does not match qualification".to_owned())
    );
    assert_eq!(
        collection_block_reason(
            "asana",
            &reference,
            "runtime-a",
            "asana",
            "complete",
            1,
            1,
            0,
            1,
            0,
            &"b".repeat(64),
            true,
        ),
        Some("collection manifest digest does not match qualification".to_owned())
    );
    assert_eq!(
        collection_block_reason(
            "asana",
            &reference,
            "runtime-a",
            "asana",
            "complete",
            1,
            1,
            0,
            1,
            0,
            &"a".repeat(64),
            false,
        ),
        Some("collection receipt does not include the promoted family".to_owned())
    );
}

#[test]
fn persisted_page_verification_requires_restart_successor_generation() {
    let reference = page_reference();
    assert_eq!(
        page_block_reason(
            "asana",
            "users",
            &reference,
            "runtime-a",
            "asana",
            "users",
            "committed",
            PagePublicationState::Committed,
            true,
            &"a".repeat(64),
            true,
            Some(1),
        ),
        Some("lease/restart page does not prove a successor generation".to_owned())
    );
}

#[test]
fn unavailable_receipt_owners_block_product_read_and_approval() {
    let reasons = unavailable_verifier_reasons();
    assert!(reasons.contains(&"product-read receipt verifier is unavailable".to_owned()));
    assert!(reasons.contains(&"promotion approval receipt verifier is unavailable".to_owned()));
    assert!(reasons.contains(&"runtime revision verifier is unavailable".to_owned()));
}
