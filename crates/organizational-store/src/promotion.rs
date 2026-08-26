//! Promotion request validation, runtime-plan binding, and persisted decision types.

use cerebro_source_catalog::{
    AuthorityEvidenceError, AuthorityQualificationEvidence, SourceCatalog,
    validate_authority_qualification_evidence,
};
use cerebro_source_runtime_next::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionSelectionRequestV1,
};
use serde::Serialize;

use crate::cutover::{CutoverError, CutoverPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPromotionRequest {
    tenant_id: String,
    source_id: String,
    family_id: String,
    policy: CutoverPolicy,
    projection_lag: u64,
    promoted_at_unix_ms: i64,
    qualification: AuthorityQualificationEvidence,
}

impl ProjectionPromotionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        policy: CutoverPolicy,
        projection_lag: u64,
        promoted_at_unix_ms: i64,
        qualification: AuthorityQualificationEvidence,
    ) -> Result<Self, CutoverError> {
        let tenant_id = checked_text(tenant_id.into(), "tenant_id")?;
        let source_id = checked_text(source_id.into(), "source_id")?;
        let family_id = checked_text(family_id.into(), "family_id")?;
        if promoted_at_unix_ms <= 0 {
            return Err(CutoverError::Invalid("promoted_at_unix_ms"));
        }
        validate_qualification(&qualification)?;
        Ok(Self {
            tenant_id,
            source_id,
            family_id,
            policy,
            projection_lag,
            promoted_at_unix_ms,
            qualification,
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    pub(crate) fn policy(&self) -> CutoverPolicy {
        self.policy
    }

    pub fn projection_lag(&self) -> u64 {
        self.projection_lag
    }

    pub(crate) fn promoted_at_unix_ms(&self) -> i64 {
        self.promoted_at_unix_ms
    }

    pub fn qualification(&self) -> &AuthorityQualificationEvidence {
        &self.qualification
    }
}

fn checked_text(value: String, field: &'static str) -> Result<String, CutoverError> {
    if value.is_empty() || value.trim() != value {
        return Err(CutoverError::Invalid(field));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CutoverDecision {
    pub(crate) tenant_id: String,
    pub(crate) source_id: String,
    pub(crate) family_id: String,
    pub(crate) allowed: bool,
    pub(crate) reasons: Vec<String>,
    pub(crate) evidence_digest: String,
    pub(crate) qualification: AuthorityQualificationEvidence,
}

impl CutoverDecision {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn qualification(&self) -> &AuthorityQualificationEvidence {
        &self.qualification
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionAuthority {
    Legacy,
    Rust,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectionAuthorityRecord {
    pub tenant_id: String,
    pub source_id: String,
    pub family_id: String,
    pub authority: ProjectionAuthority,
    pub evidence_digest: String,
    pub promoted_at_unix_ms: Option<i64>,
}

pub(crate) fn promotion_evidence_reasons(
    catalog: &SourceCatalog,
    source_id: &str,
    family_id: &str,
    qualification: &AuthorityQualificationEvidence,
) -> Result<Vec<String>, CutoverError> {
    validate_qualification(qualification)?;
    let catalog_plan_digest = catalog
        .compiled_family_plan_digest(source_id, family_id)
        .ok_or_else(|| CutoverError::UnknownSource(format!("{source_id}/{family_id}")))?;
    let mut reasons = Vec::new();
    if qualification.plan_digest != catalog_plan_digest {
        reasons.push("compiled catalog plan digest does not match qualification".to_owned());
    }
    let selection = SourceExecutionSelectionRequestV1 {
        source_id: source_id.to_owned(),
        family_id: family_id.to_owned(),
    };
    match SourceExecutionDispatcher.compile_plan(&selection) {
        Ok(plan) if qualification.runtime_plan_digest != plan.plan_digest_sha256 => {
            reasons.push("compiled runtime plan digest does not match qualification".to_owned());
        }
        Ok(_) => {}
        Err(SourceExecutionError::UnknownAdapter) => {
            reasons.push("closed Rust source-execution adapter is not registered".to_owned());
        }
        Err(error) => {
            reasons.push(format!("closed Rust runtime plan failed: {}", error.code()));
        }
    }
    Ok(reasons)
}

fn validate_qualification(
    qualification: &AuthorityQualificationEvidence,
) -> Result<(), CutoverError> {
    validate_authority_qualification_evidence(qualification).map_err(|error| match error {
        AuthorityEvidenceError::Invalid(field) => CutoverError::Invalid(field),
        AuthorityEvidenceError::Immutable => CutoverError::Invalid("qualification_evidence"),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use cerebro_source_runtime_next::source_execution::{
        SourceExecutionDispatcher, SourceExecutionSelectionRequestV1,
    };

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn catalog() -> SourceCatalog {
        let root = repository_root();
        SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap()
    }

    fn qualification(catalog: &SourceCatalog) -> AuthorityQualificationEvidence {
        let selection = SourceExecutionSelectionRequestV1 {
            source_id: "asana".to_owned(),
            family_id: "users".to_owned(),
        };
        AuthorityQualificationEvidence {
            plan_digest: catalog
                .compiled_family_plan_digest("asana", "users")
                .unwrap(),
            runtime_plan_digest: SourceExecutionDispatcher
                .compile_plan(&selection)
                .unwrap()
                .plan_digest_sha256,
            fixture_corpus_revision: "corpus-3".to_owned(),
            supported_auth_modes: vec!["bearer".to_owned()],
            supported_pagination_grammar: vec!["cursor".to_owned()],
            supported_provider_errors: vec!["unauthorized".to_owned()],
            egress_allowlist: vec!["https://app.asana.com".to_owned()],
            response_limits: "body=1048576,decompression=4x".to_owned(),
            credential_lease_mode: "one_operation".to_owned(),
            projection_dependency: "rust_projection".to_owned(),
            rollback_receipt: "receipt:recovery-readiness".to_owned(),
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

    #[test]
    fn promotion_request_requires_complete_qualification_for_exact_scope() {
        let catalog = catalog();
        let request = ProjectionPromotionRequest::new(
            "tenant-a",
            "asana",
            "users",
            CutoverPolicy::new(3, 0).unwrap(),
            0,
            1,
            qualification(&catalog),
        )
        .unwrap();
        assert_eq!(request.tenant_id(), "tenant-a");
        assert_eq!(request.source_id(), "asana");
        assert_eq!(request.family_id(), "users");

        let mut incomplete = qualification(&catalog);
        incomplete.product_read_receipt.clear();
        assert_eq!(
            ProjectionPromotionRequest::new(
                "tenant-a",
                "asana",
                "users",
                CutoverPolicy::new(3, 0).unwrap(),
                0,
                1,
                incomplete,
            ),
            Err(CutoverError::Invalid("product_read_receipt"))
        );
    }

    #[test]
    fn promotion_evidence_binds_catalog_and_runtime_plan_digests() {
        let catalog = catalog();
        let mut evidence = qualification(&catalog);
        evidence.plan_digest = "a".repeat(64);
        evidence.runtime_plan_digest = "b".repeat(64);
        let reasons = promotion_evidence_reasons(&catalog, "asana", "users", &evidence).unwrap();
        assert_eq!(
            reasons,
            vec![
                "compiled catalog plan digest does not match qualification".to_owned(),
                "compiled runtime plan digest does not match qualification".to_owned(),
            ]
        );
    }
}
