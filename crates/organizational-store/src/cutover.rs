use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_source_catalog::{
    AuthorityQualificationEvidence, SourceCatalog, authority_qualification_digest,
};
use sha2::{Digest, Sha256};

use crate::{
    ParityReceipt, ParityStatus,
    promotion::{CutoverDecision, promotion_evidence_reasons},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutoverPolicy {
    min_consecutive_matches: usize,
    max_projection_lag: u64,
}

impl CutoverPolicy {
    pub fn new(
        min_consecutive_matches: usize,
        max_projection_lag: u64,
    ) -> Result<Self, CutoverError> {
        if min_consecutive_matches < 3 {
            return Err(CutoverError::UnsafePolicy);
        }
        Ok(Self {
            min_consecutive_matches,
            max_projection_lag,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CutoverError {
    Invalid(&'static str),
    UnsafePolicy,
    UnknownSource(String),
}

impl fmt::Display for CutoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::UnsafePolicy => {
                formatter.write_str("cutover requires at least three matching runs")
            }
            Self::UnknownSource(source) => {
                write!(formatter, "source {source} is not in the catalog")
            }
        }
    }
}

impl Error for CutoverError {}

pub struct CutoverGate {
    policy: CutoverPolicy,
}

impl CutoverGate {
    pub fn new(policy: CutoverPolicy) -> Self {
        Self { policy }
    }

    pub fn evaluate(
        &self,
        catalog: &SourceCatalog,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
        receipts: &[ParityReceipt],
        projection_lag: u64,
        qualification: &AuthorityQualificationEvidence,
    ) -> Result<CutoverDecision, CutoverError> {
        let source = catalog
            .get(source_id)
            .ok_or_else(|| CutoverError::UnknownSource(source_id.to_owned()))?;
        let mut reasons = promotion_evidence_reasons(catalog, source_id, family_id, qualification)?;
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == family_id)
            .ok_or_else(|| CutoverError::UnknownSource(format!("{source_id}/{family_id}")))?;
        let catalog_plan_digest = catalog
            .compiled_family_plan_digest(source_id, family_id)
            .ok_or_else(|| CutoverError::UnknownSource(format!("{source_id}/{family_id}")))?;
        if !family.is_projection_authoritative() {
            reasons.push("provider method and path proof is incomplete".to_owned());
        }
        if !family.projection().class().can_be_authoritative() {
            reasons.push("projection class requires a native Rust mapper".to_owned());
        }
        if projection_lag > self.policy.max_projection_lag {
            reasons.push(format!(
                "projection lag {projection_lag} exceeds {}",
                self.policy.max_projection_lag
            ));
        }
        if receipts.iter().any(|receipt| {
            receipt.source_id() == source_id
                && receipt.family_id() == family_id
                && receipt.tenant_id() != tenant_id
        }) {
            reasons.push("parity receipt tenant does not match promotion request".to_owned());
        }
        let mut source_receipts: Vec<_> = receipts
            .iter()
            .filter(|receipt| receipt.tenant_id() == tenant_id)
            .filter(|receipt| receipt.source_id() == source_id)
            .filter(|receipt| receipt.family_id() == family_id)
            .collect();
        source_receipts.sort_by(|left, right| {
            left.compared_at_unix_ms()
                .cmp(&right.compared_at_unix_ms())
                .then_with(|| left.receipt_digest().cmp(right.receipt_digest()))
        });
        let consecutive = source_receipts
            .iter()
            .rev()
            .take_while(|receipt| receipt.status() == ParityStatus::Match)
            .count();
        if consecutive < self.policy.min_consecutive_matches {
            reasons.push(format!(
                "{consecutive} consecutive parity matches; {} required",
                self.policy.min_consecutive_matches
            ));
        }
        let mut latest_by_corpus = BTreeMap::new();
        for receipt in &source_receipts {
            latest_by_corpus.insert(receipt.collection_id(), *receipt);
        }
        if latest_by_corpus
            .values()
            .any(|receipt| receipt.status() != ParityStatus::Match)
        {
            reasons.push("latest corpus comparison is not a match".to_owned());
        }
        if latest_by_corpus
            .values()
            .any(|receipt| receipt.projection_lag() > self.policy.max_projection_lag)
        {
            reasons.push("a latest parity receipt exceeds the projection lag policy".to_owned());
        }
        if source_receipts
            .last()
            .is_some_and(|receipt| receipt.collection_id() != qualification.fixture_corpus_revision)
        {
            reasons
                .push("qualification fixture corpus is not the latest parity receipt".to_owned());
        }
        let qualification_digest = authority_qualification_digest(qualification);
        let evidence_digest = digest(
            &source_receipts
                .iter()
                .map(|receipt| receipt.receipt_digest())
                .chain([
                    tenant_id,
                    source_id,
                    family_id,
                    qualification_digest.as_str(),
                    catalog_plan_digest.as_str(),
                    qualification.runtime_plan_digest.as_str(),
                ])
                .collect::<Vec<_>>(),
        );
        Ok(CutoverDecision {
            tenant_id: tenant_id.to_owned(),
            source_id: source_id.to_owned(),
            family_id: family_id.to_owned(),
            allowed: reasons.is_empty(),
            reasons,
            evidence_digest,
            qualification: qualification.clone(),
        })
    }
}

fn digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut value = String::with_capacity(7 + bytes.len() * 2);
    value.push_str("sha256:");
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SemanticSnapshot;
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
        let qualification = qualification(&catalog, "asana", "users", "corpus-3");
        let tenant_a = gate
            .evaluate(
                &catalog,
                "tenant-a",
                "asana",
                "users",
                &receipts,
                0,
                &qualification,
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
            )
            .unwrap();
        assert!(!tenant_b.is_allowed());
        assert!(
            tenant_b.reasons().iter().any(|reason| {
                reason == "parity receipt tenant does not match promotion request"
            })
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
                    &qualification
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
            )
            .unwrap();
        assert!(!decision.is_allowed());
        assert!(
            decision.reasons().iter().any(|reason| {
                reason == "closed Rust source-execution adapter is not registered"
            })
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
            decision_json["qualification"]["product_read_receipt"],
            "receipt:product-read"
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
        let lagged =
            ParityReceipt::compare_snapshots(&legacy, &rust, 3, 2, BTreeMap::new()).unwrap();
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
            )
            .unwrap();
        assert!(!decision.is_allowed());
        assert!(decision
            .reasons()
            .iter()
            .any(|reason| reason == "a latest parity receipt exceeds the projection lag policy"));
    }
}
