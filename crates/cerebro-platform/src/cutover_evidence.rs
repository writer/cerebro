use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use cerebro_source_catalog::AuthorityQualificationEvidence;

use crate::required_env;

pub(crate) fn load_single_authority_qualification()
-> Result<AuthorityQualificationEvidence, Box<dyn Error>> {
    let path = PathBuf::from(required_env("CEREBRO_AUTHORITY_EVIDENCE_PATH")?);
    load_authority_qualification(&path)
}

pub(crate) fn authority_qualification_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(required_env(
        "CEREBRO_AUTHORITY_EVIDENCE_DIR",
    )?))
}

pub(crate) fn load_family_authority_qualification(
    root: &Path,
    source_id: &str,
    family_id: &str,
) -> Result<AuthorityQualificationEvidence, Box<dyn Error>> {
    load_authority_qualification(&root.join(source_id).join(format!("{family_id}.json")))
}

fn load_authority_qualification(
    path: &Path,
) -> Result<AuthorityQualificationEvidence, Box<dyn Error>> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "read authority evidence {}: {error}",
            path.to_string_lossy()
        )
    })?;
    decode_authority_qualification(&bytes).map_err(|error| {
        format!(
            "decode authority evidence {}: {error}",
            path.to_string_lossy()
        )
        .into()
    })
}

fn decode_authority_qualification(
    bytes: &[u8],
) -> Result<AuthorityQualificationEvidence, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
pub(crate) fn authority_qualification_fixture(
    catalog: &cerebro_source_catalog::SourceCatalog,
    source_id: &str,
    family_id: &str,
    corpus: &str,
) -> AuthorityQualificationEvidence {
    use cerebro_source_catalog::{
        PagePublicationReceiptReference, PersistedReceiptReference,
        SourceCollectionReceiptReference,
    };
    use cerebro_source_runtime_next::source_execution::{
        SourceExecutionDispatcher, SourceExecutionSelectionRequestV1,
    };

    let plan_digest = catalog
        .compiled_family_plan_digest(source_id, family_id)
        .unwrap();
    let runtime_plan_digest = SourceExecutionDispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: source_id.to_owned(),
            family_id: family_id.to_owned(),
        })
        .unwrap()
        .plan_digest_sha256;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_input_rejects_unknown_or_incomplete_json_shapes() {
        assert!(decode_authority_qualification(br#"{"plan_digest":"abc"}"#).is_err());
        let catalog = crate::load_catalog().unwrap();
        let complete =
            authority_qualification_fixture(&catalog, "asana", "users", "fixture-corpus:test");
        let mut value = serde_json::to_value(complete).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), true.into());
        assert!(decode_authority_qualification(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
