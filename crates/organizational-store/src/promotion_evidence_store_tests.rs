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
fn authenticated_collection_verification_rejects_missing_and_mismatched_proof() {
    let supported = ["api_key".to_owned()];
    assert_eq!(
        authenticated_collection_block_reason(&serde_json::json!({}), &supported, "one_operation"),
        Some(
            "authenticated collection manifest does not include an authenticated request proof"
                .to_owned()
        )
    );
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"credential_lease_mode": "one_operation"}}),
            &supported,
            "one_operation",
        ),
        Some("authenticated request proof does not include an auth mode".to_owned())
    );
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"auth_mode": "oauth", "credential_lease_mode": "one_operation"}}),
            &supported,
            "one_operation",
        ),
        Some("authenticated request proof auth mode does not match qualification".to_owned())
    );
    let blank_alongside_real = ["api_key".to_owned(), String::new()];
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"auth_mode": "", "credential_lease_mode": "one_operation"}}),
            &blank_alongside_real,
            "one_operation",
        ),
        Some("authenticated request proof does not include an auth mode".to_owned())
    );
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"auth_mode": "api_key"}}),
            &supported,
            "one_operation",
        ),
        Some("authenticated request proof does not include a credential lease mode".to_owned())
    );
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"auth_mode": "api_key", "credential_lease_mode": "session"}}),
            &supported,
            "one_operation",
        ),
        Some(
            "authenticated request proof credential lease mode does not match qualification"
                .to_owned()
        )
    );
    assert_eq!(
        authenticated_collection_block_reason(
            &serde_json::json!({"authenticated_request_proof": {"auth_mode": "api_key", "credential_lease_mode": "one_operation"}}),
            &supported,
            "one_operation",
        ),
        None
    );
}

#[test]
fn runtime_revision_verification_rejects_missing_and_mismatched_fields() {
    let revision = "a".repeat(64);
    assert_eq!(
        runtime_revision_block_reason(&serde_json::json!({}), &revision, "build-1"),
        Some("stored source runtime does not record a runtime revision".to_owned())
    );
    assert_eq!(
        runtime_revision_block_reason(
            &serde_json::json!({"runtime_revision_sha256": "b".repeat(64)}),
            &revision,
            "build-1",
        ),
        Some("stored source runtime revision does not match qualification".to_owned())
    );
    assert_eq!(
        runtime_revision_block_reason(
            &serde_json::json!({"runtime_revision_sha256": revision.clone()}),
            &revision,
            "build-1",
        ),
        Some("stored source runtime does not record a worker build identity".to_owned())
    );
    assert_eq!(
        runtime_revision_block_reason(
            &serde_json::json!({
                "runtime_revision_sha256": revision.clone(),
                "worker_runtime_build_identity": "build-2",
            }),
            &revision,
            "build-1",
        ),
        Some("stored source runtime build identity does not match qualification".to_owned())
    );
    assert_eq!(
        runtime_revision_block_reason(
            &serde_json::json!({
                "runtime_revision_sha256": revision.clone(),
                "worker_runtime_build_identity": "build-1",
            }),
            &revision,
            "build-1",
        ),
        None
    );
}
