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
