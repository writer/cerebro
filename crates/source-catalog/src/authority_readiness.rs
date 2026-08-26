//! Evidence-aware catalog readiness reporting and compiled plan-digest lookup.

use super::{
    AuthorityDecisionKind, AuthorityEvidenceStream, AuthorityReadinessFamilyReport,
    AuthorityReadinessReport, CompiledFamily, SourceCatalog, family_plan_digest,
};

pub(super) fn compiled_family_plan_digest(
    catalog: &SourceCatalog,
    source_id: &str,
    family_id: &str,
) -> Option<String> {
    let source = catalog.get(source_id.trim())?;
    let family = source
        .families()
        .iter()
        .find(|family| family.id() == family_id.trim())?;
    Some(family_plan_digest(source, family))
}

pub(super) fn report_with_evidence(
    catalog: &SourceCatalog,
    tenant_id: &str,
    evidence: &AuthorityEvidenceStream,
) -> AuthorityReadinessReport {
    let mut families = Vec::new();
    let mut rust_authoritative_families = 0;
    for source in catalog.sources() {
        for family in source.families() {
            let plan_digest = family_plan_digest(source, family);
            let latest = (!tenant_id.trim().is_empty())
                .then(|| evidence.latest(tenant_id, source.id(), family.id()))
                .flatten();
            let mut engine = "go_or_shadow_only".to_owned();
            let mut authority_epoch = 0;
            let mut proof_revision = "provider-proof:incomplete".to_owned();
            let mut fixture_revision = String::new();
            let mut parity_status = "missing".to_owned();
            let mut rollback_status = "missing".to_owned();
            let mut projection_status = if family.is_projection_authoritative() {
                "go_projection_dependency".to_owned()
            } else {
                "missing".to_owned()
            };
            let mut promotion_decision_id = String::new();
            let mut blocking_reasons = default_blocking_reasons(family);

            if let Some(record) = latest {
                authority_epoch = record.authority_epoch;
                promotion_decision_id = record.decision_id.clone();
                proof_revision = record.input_evidence_digest_sha256.clone();
                match record.decision_kind {
                    AuthorityDecisionKind::Promotion => {
                        let qualification = record
                            .qualification
                            .as_ref()
                            .expect("verified promotion carries qualification evidence");
                        fixture_revision = qualification.fixture_corpus_revision.clone();
                        parity_status = qualification.parity_status.clone();
                        rollback_status = qualification.rollback_receipt.receipt_id.clone();
                        projection_status = qualification.projection_dependency.clone();
                        blocking_reasons.clear();
                        if !family.is_authoritative() {
                            blocking_reasons.push("compiled_collection_authority".to_owned());
                        }
                        if !family.is_projection_authoritative() {
                            blocking_reasons.push("projection_intent_readiness".to_owned());
                        }
                        if qualification.plan_digest != plan_digest {
                            blocking_reasons.push("compiled_plan_digest".to_owned());
                        }
                        blocking_reasons
                            .push("projection_authority_ledger_verification".to_owned());
                        if blocking_reasons.is_empty() {
                            engine = "rust_authoritative".to_owned();
                            rust_authoritative_families += 1;
                        }
                    }
                    AuthorityDecisionKind::Rollback => {
                        blocking_reasons = vec!["authority_decision_rollback".to_owned()];
                    }
                    AuthorityDecisionKind::ShadowOnlyBlocked => {
                        blocking_reasons =
                            vec!["authority_decision_shadow_only_blocked".to_owned()];
                    }
                    AuthorityDecisionKind::CapabilityChanged => {
                        blocking_reasons = vec!["authority_decision_capability_changed".to_owned()];
                    }
                }
            }
            blocking_reasons.sort();
            blocking_reasons.dedup();
            families.push(AuthorityReadinessFamilyReport {
                source_id: source.id().to_owned(),
                family_id: family.id().to_owned(),
                engine,
                authority_epoch,
                plan_digest,
                proof_revision,
                fixture_revision,
                parity_status,
                rollback_status,
                projection_status,
                promotion_decision_id,
                blocking_reasons,
            });
        }
    }
    AuthorityReadinessReport {
        total_families: families.len(),
        rust_authoritative_families,
        shadow_or_go_families: families.len() - rust_authoritative_families,
        families,
    }
}

fn default_blocking_reasons(family: &CompiledFamily) -> Vec<String> {
    let mut blocking_reasons = vec![
        "fixture_corpus_revision".to_owned(),
        "supported_auth_modes".to_owned(),
        "supported_pagination_grammar".to_owned(),
        "supported_provider_error_modes".to_owned(),
        "egress_allowlist".to_owned(),
        "response_decompression_limits".to_owned(),
        "credential_lease_mode".to_owned(),
        "rollback_receipt".to_owned(),
        "fixture_parity_status".to_owned(),
        "canonical_digest_vectors".to_owned(),
        "credential_config_safety_proof".to_owned(),
        "cursor_checkpoint_rollback_proof".to_owned(),
        "operational_fencing_recovery_proof".to_owned(),
        "runtime_revision_sha256".to_owned(),
        "worker_runtime_build_identity".to_owned(),
        "promotion_receipt".to_owned(),
        "authenticated_collection_receipt".to_owned(),
        "append_projection_checkpoint_receipt".to_owned(),
        "lease_restart_receipt".to_owned(),
        "product_read_receipt".to_owned(),
        "parity_receipt_digests".to_owned(),
    ];
    if !family.is_projection_authoritative() {
        blocking_reasons.push("projection_intent_readiness".to_owned());
    }
    blocking_reasons.sort();
    blocking_reasons
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{
        AuthorityEvidenceRecord, AuthorityQualificationEvidence, PagePublicationReceiptReference,
        PersistedReceiptReference, SourceCollectionReceiptReference,
        authority_qualification_digest,
    };

    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn catalog_evidence_cannot_replace_persisted_projection_authority() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let report = catalog.authority_readiness_report();
        let (source, family) = catalog
            .sources()
            .find_map(|source| {
                source
                    .families()
                    .iter()
                    .find(|family| {
                        family.is_authoritative() && family.is_projection_authoritative()
                    })
                    .map(|family| (source, family))
            })
            .expect("compile-qualified family");
        let plan_digest = report
            .families
            .iter()
            .find(|row| row.source_id == source.id() && row.family_id == family.id())
            .expect("readiness row")
            .plan_digest
            .clone();
        let qualification = complete_authority_qualification(plan_digest);
        let mut stream = AuthorityEvidenceStream::default();
        stream
            .append(AuthorityEvidenceRecord {
                tenant_id: "tenant-readiness".to_owned(),
                source_id: source.id().to_owned(),
                family_id: family.id().to_owned(),
                authority_epoch: 1,
                decision_id: "decision-promote-readiness".to_owned(),
                decision_kind: AuthorityDecisionKind::Promotion,
                input_evidence_digest_sha256: authority_qualification_digest(&qualification),
                actor_id: "system:cutover".to_owned(),
                timestamp_unix_ms: 1_787_136_000_000,
                reason_code: "complete_runtime_evidence".to_owned(),
                authenticated_receipt_id: "receipt:promotion".to_owned(),
                receipt_signature: String::new(),
                previous_decision_id: String::new(),
                qualification: Some(qualification),
                record_digest_sha256: String::new(),
            })
            .expect("verified promotion record");
        let promoted =
            catalog.authority_readiness_report_with_evidence("tenant-readiness", &stream);
        assert_eq!(promoted.rust_authoritative_families, 0);
        let promoted_family = promoted
            .families
            .iter()
            .find(|row| row.source_id == source.id() && row.family_id == family.id())
            .expect("promoted readiness row");
        assert_eq!(promoted_family.engine, "go_or_shadow_only");
        assert_eq!(promoted_family.authority_epoch, 1);
        assert_eq!(
            promoted_family.blocking_reasons,
            vec!["projection_authority_ledger_verification"]
        );
    }

    fn complete_authority_qualification(plan_digest: String) -> AuthorityQualificationEvidence {
        AuthorityQualificationEvidence {
            plan_digest,
            runtime_plan_digest: "b".repeat(64),
            fixture_corpus_revision: "fixture-corpus:v1".to_owned(),
            supported_auth_modes: vec!["api_key".to_owned()],
            supported_pagination_grammar: vec!["cursor".to_owned()],
            supported_provider_errors: vec!["unauthorized".to_owned(), "rate_limited".to_owned()],
            egress_allowlist: vec!["https://provider.example.test".to_owned()],
            response_limits: "body=1048576,decompression=4x".to_owned(),
            credential_lease_mode: "one_operation".to_owned(),
            projection_dependency: "rust_projection".to_owned(),
            rollback_receipt: PersistedReceiptReference {
                receipt_id: "rollback-test".to_owned(),
                receipt_digest_sha256: "c".repeat(64),
            },
            parity_status: "passed".to_owned(),
            canonical_digest_vectors: vec!["plan".to_owned(), "result".to_owned()],
            config_safety_proof: "receipt:config-safety".to_owned(),
            cursor_checkpoint_proof: "receipt:cursor-checkpoint".to_owned(),
            fencing_recovery_proof: "receipt:fencing-recovery".to_owned(),
            runtime_revision_sha256: "d".repeat(64),
            worker_runtime_build_identity: "source-runtime-next:test".to_owned(),
            promotion_receipt: PersistedReceiptReference {
                receipt_id: "promotion-test".to_owned(),
                receipt_digest_sha256: "e".repeat(64),
            },
            authenticated_collection_receipt: SourceCollectionReceiptReference {
                source_runtime_id: "runtime-test".to_owned(),
                collection_id: "collection-test".to_owned(),
                manifest_digest_sha256: "f".repeat(64),
            },
            append_projection_checkpoint_receipt: PagePublicationReceiptReference {
                source_runtime_id: "runtime-test".to_owned(),
                logical_page_id: "page-test".to_owned(),
                revision: 5,
                snapshot_digest_sha256: "1".repeat(64),
            },
            lease_restart_receipt: PagePublicationReceiptReference {
                source_runtime_id: "runtime-test".to_owned(),
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
}
