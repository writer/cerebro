//! Typed promotion references and shape validation before persisted verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_evidence::AuthorityEvidenceError;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedReceiptReference {
    pub receipt_id: String,
    pub receipt_digest_sha256: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCollectionReceiptReference {
    pub source_runtime_id: String,
    pub collection_id: String,
    pub manifest_digest_sha256: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PagePublicationReceiptReference {
    pub source_runtime_id: String,
    pub logical_page_id: String,
    pub revision: u64,
    pub snapshot_digest_sha256: String,
}

/// Typed, non-secret references submitted for persisted promotion verification.
/// Neither deserialization nor shape validation grants runtime authority.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityQualificationEvidence {
    pub plan_digest: String,
    pub runtime_plan_digest: String,
    pub fixture_corpus_revision: String,
    pub supported_auth_modes: Vec<String>,
    pub supported_pagination_grammar: Vec<String>,
    pub supported_provider_errors: Vec<String>,
    pub egress_allowlist: Vec<String>,
    pub response_limits: String,
    pub credential_lease_mode: String,
    pub projection_dependency: String,
    pub rollback_receipt: PersistedReceiptReference,
    pub parity_status: String,
    pub canonical_digest_vectors: Vec<String>,
    pub config_safety_proof: String,
    pub cursor_checkpoint_proof: String,
    pub fencing_recovery_proof: String,
    pub runtime_revision_sha256: String,
    pub worker_runtime_build_identity: String,
    pub promotion_receipt: PersistedReceiptReference,
    pub authenticated_collection_receipt: SourceCollectionReceiptReference,
    pub append_projection_checkpoint_receipt: PagePublicationReceiptReference,
    pub lease_restart_receipt: PagePublicationReceiptReference,
    pub product_read_receipt: PersistedReceiptReference,
    pub parity_receipt_digests: Vec<String>,
}

/// Validate the typed reference shape required before persisted verification.
pub fn validate_authority_qualification_evidence(
    evidence: &AuthorityQualificationEvidence,
) -> Result<(), AuthorityEvidenceError> {
    let missing = missing_authority_qualification_evidence(evidence);
    if let Some(field) = missing.first() {
        return Err(AuthorityEvidenceError::Invalid(field));
    }
    if !is_sha256_hex(&evidence.plan_digest) {
        return Err(AuthorityEvidenceError::Invalid("compiled_plan_digest"));
    }
    if !is_sha256_hex(&evidence.runtime_plan_digest) {
        return Err(AuthorityEvidenceError::Invalid("runtime_plan_digest"));
    }
    if !matches!(evidence.parity_status.trim(), "passed" | "matched") {
        return Err(AuthorityEvidenceError::Invalid("fixture_parity_status"));
    }
    for (field, digest) in [
        ("runtime_revision_sha256", &evidence.runtime_revision_sha256),
        (
            "collection_manifest_digest_sha256",
            &evidence
                .authenticated_collection_receipt
                .manifest_digest_sha256,
        ),
        (
            "page_publication_snapshot_digest_sha256",
            &evidence
                .append_projection_checkpoint_receipt
                .snapshot_digest_sha256,
        ),
        (
            "lease_restart_snapshot_digest_sha256",
            &evidence.lease_restart_receipt.snapshot_digest_sha256,
        ),
        (
            "product_read_receipt_digest_sha256",
            &evidence.product_read_receipt.receipt_digest_sha256,
        ),
        (
            "promotion_receipt_digest_sha256",
            &evidence.promotion_receipt.receipt_digest_sha256,
        ),
        (
            "rollback_receipt_digest_sha256",
            &evidence.rollback_receipt.receipt_digest_sha256,
        ),
    ] {
        if !is_sha256_hex(digest) {
            return Err(AuthorityEvidenceError::Invalid(field));
        }
    }
    if evidence
        .parity_receipt_digests
        .iter()
        .any(|digest| !is_canonical_sha256(digest))
    {
        return Err(AuthorityEvidenceError::Invalid("parity_receipt_digests"));
    }
    Ok(())
}

/// Return stable field names for every absent authority reference.
pub fn missing_authority_qualification_evidence(
    evidence: &AuthorityQualificationEvidence,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if evidence.plan_digest.trim().is_empty() {
        missing.push("compiled_plan_digest");
    }
    if evidence.runtime_plan_digest.trim().is_empty() {
        missing.push("runtime_plan_digest");
    }
    if evidence.fixture_corpus_revision.trim().is_empty() {
        missing.push("fixture_corpus_revision");
    }
    for (field, values) in [
        ("supported_auth_modes", &evidence.supported_auth_modes),
        (
            "supported_pagination_grammar",
            &evidence.supported_pagination_grammar,
        ),
        (
            "supported_provider_error_modes",
            &evidence.supported_provider_errors,
        ),
        ("egress_allowlist", &evidence.egress_allowlist),
        (
            "canonical_digest_vectors",
            &evidence.canonical_digest_vectors,
        ),
    ] {
        if values.iter().all(|value| value.trim().is_empty()) {
            missing.push(field);
        }
    }
    for (field, value) in [
        ("response_decompression_limits", &evidence.response_limits),
        ("credential_lease_mode", &evidence.credential_lease_mode),
        ("projection_dependency", &evidence.projection_dependency),
        ("fixture_parity_status", &evidence.parity_status),
        (
            "credential_config_safety_proof",
            &evidence.config_safety_proof,
        ),
        (
            "cursor_checkpoint_rollback_proof",
            &evidence.cursor_checkpoint_proof,
        ),
        (
            "operational_fencing_recovery_proof",
            &evidence.fencing_recovery_proof,
        ),
        ("runtime_revision_sha256", &evidence.runtime_revision_sha256),
        (
            "worker_runtime_build_identity",
            &evidence.worker_runtime_build_identity,
        ),
    ] {
        if value.trim().is_empty() {
            missing.push(field);
        }
    }
    for (field, value) in [
        (
            "rollback_receipt_digest_sha256",
            &evidence.rollback_receipt.receipt_digest_sha256,
        ),
        (
            "promotion_receipt_digest_sha256",
            &evidence.promotion_receipt.receipt_digest_sha256,
        ),
        (
            "collection_manifest_digest_sha256",
            &evidence
                .authenticated_collection_receipt
                .manifest_digest_sha256,
        ),
        (
            "page_publication_snapshot_digest_sha256",
            &evidence
                .append_projection_checkpoint_receipt
                .snapshot_digest_sha256,
        ),
        (
            "lease_restart_snapshot_digest_sha256",
            &evidence.lease_restart_receipt.snapshot_digest_sha256,
        ),
        (
            "product_read_receipt_digest_sha256",
            &evidence.product_read_receipt.receipt_digest_sha256,
        ),
    ] {
        if value.trim().is_empty() {
            missing.push(field);
        }
    }
    for (field, value) in [
        ("rollback_receipt", &evidence.rollback_receipt.receipt_id),
        ("promotion_receipt", &evidence.promotion_receipt.receipt_id),
        (
            "authenticated_collection_receipt",
            &evidence.authenticated_collection_receipt.collection_id,
        ),
        (
            "authenticated_collection_runtime",
            &evidence.authenticated_collection_receipt.source_runtime_id,
        ),
        (
            "append_projection_checkpoint_receipt",
            &evidence
                .append_projection_checkpoint_receipt
                .logical_page_id,
        ),
        (
            "append_projection_checkpoint_runtime",
            &evidence
                .append_projection_checkpoint_receipt
                .source_runtime_id,
        ),
        (
            "lease_restart_receipt",
            &evidence.lease_restart_receipt.logical_page_id,
        ),
        (
            "lease_restart_runtime",
            &evidence.lease_restart_receipt.source_runtime_id,
        ),
        (
            "product_read_receipt",
            &evidence.product_read_receipt.receipt_id,
        ),
    ] {
        if value.trim().is_empty() {
            missing.push(field);
        }
    }
    if evidence.append_projection_checkpoint_receipt.revision == 0 {
        missing.push("append_projection_checkpoint_revision");
    }
    if evidence.lease_restart_receipt.revision == 0 {
        missing.push("lease_restart_revision");
    }
    if evidence.parity_receipt_digests.is_empty() {
        missing.push("parity_receipt_digests");
    }
    missing.sort_unstable();
    missing
}

/// Digest the canonical typed reference bundle bound by a decision.
pub fn authority_qualification_digest(evidence: &AuthorityQualificationEvidence) -> String {
    let bytes = serde_json::to_vec(evidence).expect("authority qualification serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256_hex(value: &str) -> bool {
    let value = value.trim();
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_canonical_sha256(value: &str) -> bool {
    value
        .trim()
        .strip_prefix("sha256:")
        .is_some_and(is_sha256_hex)
        || is_sha256_hex(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualification_shape_validation_reports_all_missing_fields() {
        let missing =
            missing_authority_qualification_evidence(&AuthorityQualificationEvidence::default());

        for field in [
            "compiled_plan_digest",
            "runtime_plan_digest",
            "authenticated_collection_receipt",
            "append_projection_checkpoint_receipt",
            "lease_restart_receipt",
            "product_read_receipt",
            "promotion_receipt",
            "rollback_receipt",
            "runtime_revision_sha256",
            "worker_runtime_build_identity",
            "parity_receipt_digests",
        ] {
            assert!(missing.contains(&field), "missing {field}");
        }
        assert!(missing.len() > 10, "all missing fields must be retained");
    }

    #[test]
    fn opaque_receipt_labels_are_not_accepted_as_digests() {
        let evidence = AuthorityQualificationEvidence {
            plan_digest: "a".repeat(64),
            runtime_plan_digest: "b".repeat(64),
            fixture_corpus_revision: "fixtures:v1".to_owned(),
            supported_auth_modes: vec!["api_key".to_owned()],
            supported_pagination_grammar: vec!["cursor".to_owned()],
            supported_provider_errors: vec!["rate_limited".to_owned()],
            egress_allowlist: vec!["https://provider.example.test".to_owned()],
            response_limits: "body=1048576".to_owned(),
            credential_lease_mode: "one_operation".to_owned(),
            projection_dependency: "rust_projection".to_owned(),
            parity_status: "passed".to_owned(),
            canonical_digest_vectors: vec!["vector".to_owned()],
            config_safety_proof: "receipt:config".to_owned(),
            cursor_checkpoint_proof: "receipt:checkpoint".to_owned(),
            fencing_recovery_proof: "receipt:fencing".to_owned(),
            runtime_revision_sha256: "c".repeat(64),
            worker_runtime_build_identity: "source-runtime-next:test".to_owned(),
            rollback_receipt: PersistedReceiptReference {
                receipt_id: "rollback".to_owned(),
                receipt_digest_sha256: "sig:rollback".to_owned(),
            },
            promotion_receipt: PersistedReceiptReference {
                receipt_id: "promotion".to_owned(),
                receipt_digest_sha256: "d".repeat(64),
            },
            authenticated_collection_receipt: SourceCollectionReceiptReference {
                source_runtime_id: "runtime".to_owned(),
                collection_id: "collection".to_owned(),
                manifest_digest_sha256: "e".repeat(64),
            },
            append_projection_checkpoint_receipt: PagePublicationReceiptReference {
                source_runtime_id: "runtime".to_owned(),
                logical_page_id: "page".to_owned(),
                revision: 1,
                snapshot_digest_sha256: "f".repeat(64),
            },
            lease_restart_receipt: PagePublicationReceiptReference {
                source_runtime_id: "runtime".to_owned(),
                logical_page_id: "restart".to_owned(),
                revision: 2,
                snapshot_digest_sha256: "1".repeat(64),
            },
            product_read_receipt: PersistedReceiptReference {
                receipt_id: "product-read".to_owned(),
                receipt_digest_sha256: "2".repeat(64),
            },
            parity_receipt_digests: vec!["3".repeat(64)],
        };

        assert_eq!(
            validate_authority_qualification_evidence(&evidence),
            Err(AuthorityEvidenceError::Invalid(
                "rollback_receipt_digest_sha256"
            ))
        );
    }
}
