use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_source_catalog::{
    AuthorityQualificationEvidence, SourceCatalog, authority_qualification_digest,
};
use sha2::{Digest, Sha256};

use crate::{
    ParityReceipt, ParityStatus,
    promotion::{CutoverDecision, promotion_evidence_reasons},
    promotion_evidence_store::{PromotionEvidenceVerification, VerifiedPromotionReceiptKind},
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

pub(crate) struct CutoverGate {
    policy: CutoverPolicy,
}

impl CutoverGate {
    pub(crate) fn new(policy: CutoverPolicy) -> Self {
        Self { policy }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn evaluate(
        &self,
        catalog: &SourceCatalog,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
        receipts: &[ParityReceipt],
        projection_lag: u64,
        qualification: &AuthorityQualificationEvidence,
        verification: &PromotionEvidenceVerification,
    ) -> Result<CutoverDecision, CutoverError> {
        let source = catalog
            .get(source_id)
            .ok_or_else(|| CutoverError::UnknownSource(source_id.to_owned()))?;
        let mut reasons = promotion_evidence_reasons(catalog, source_id, family_id, qualification)?;
        reasons.extend(verification.reasons().iter().cloned());
        reasons.extend(verified_scope_reasons(
            tenant_id,
            source_id,
            family_id,
            qualification,
            verification,
        ));
        reasons.extend(verified_receipt_binding_reasons(
            qualification,
            verification,
        ));
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
        let qualifying_receipt_digests = source_receipts
            .iter()
            .rev()
            .take(self.policy.min_consecutive_matches)
            .rev()
            .map(|receipt| receipt.receipt_digest().to_owned())
            .collect::<Vec<_>>();
        if qualification.parity_receipt_digests != qualifying_receipt_digests {
            reasons
                .push("persisted parity receipt sequence does not match qualification".to_owned());
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
        let verification_digest = verification.digest();
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
                    verification_digest.as_str(),
                ])
                .collect::<Vec<_>>(),
        );
        reasons.sort();
        reasons.dedup();
        Ok(CutoverDecision {
            tenant_id: tenant_id.to_owned(),
            source_id: source_id.to_owned(),
            family_id: family_id.to_owned(),
            allowed: reasons.is_empty(),
            reasons,
            evidence_digest,
            qualification: qualification.clone(),
            verified_receipts: verification.receipts().to_vec(),
        })
    }
}

fn verified_scope_reasons(
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    qualification: &AuthorityQualificationEvidence,
    verification: &PromotionEvidenceVerification,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if verification.tenant_id() != tenant_id {
        reasons.push("persisted verification tenant does not match promotion request".to_owned());
    }
    if verification.source_id() != source_id {
        reasons.push("persisted verification source does not match promotion request".to_owned());
    }
    if verification.family_id() != family_id {
        reasons.push("persisted verification family does not match promotion request".to_owned());
    }
    let collection_runtime = qualification
        .authenticated_collection_receipt
        .source_runtime_id
        .as_str();
    if qualification
        .append_projection_checkpoint_receipt
        .source_runtime_id
        != collection_runtime
        || qualification.lease_restart_receipt.source_runtime_id != collection_runtime
    {
        reasons.push("qualified receipt runtime identifiers do not match".to_owned());
    }
    if verification.source_runtime_id() != collection_runtime {
        reasons.push("persisted verification runtime does not match qualification".to_owned());
    }
    if verification.runtime_revision_sha256() != qualification.runtime_revision_sha256 {
        reasons.push(
            "persisted verification runtime revision does not match qualification".to_owned(),
        );
    }
    reasons
}

fn verified_receipt_binding_reasons(
    qualification: &AuthorityQualificationEvidence,
    verification: &PromotionEvidenceVerification,
) -> Vec<String> {
    let collection = &qualification.authenticated_collection_receipt;
    let append = &qualification.append_projection_checkpoint_receipt;
    let restart = &qualification.lease_restart_receipt;
    let mut reasons = Vec::new();
    for (kind, receipt_id, receipt_digest, label) in [
        (
            VerifiedPromotionReceiptKind::DurableCollection,
            collection.collection_id.as_str(),
            collection.manifest_digest_sha256.as_str(),
            "durable collection",
        ),
        (
            VerifiedPromotionReceiptKind::AuthenticatedCollection,
            collection.collection_id.as_str(),
            collection.manifest_digest_sha256.as_str(),
            "authenticated collection",
        ),
        (
            VerifiedPromotionReceiptKind::AppendProjectionCheckpoint,
            append.logical_page_id.as_str(),
            append.snapshot_digest_sha256.as_str(),
            "append/projection/checkpoint",
        ),
        (
            VerifiedPromotionReceiptKind::LeaseRestart,
            restart.logical_page_id.as_str(),
            restart.snapshot_digest_sha256.as_str(),
            "lease/restart",
        ),
        (
            VerifiedPromotionReceiptKind::RuntimeRevision,
            qualification.runtime_revision_sha256.as_str(),
            qualification.runtime_revision_sha256.as_str(),
            "runtime revision",
        ),
        (
            VerifiedPromotionReceiptKind::ProductRead,
            qualification.product_read_receipt.receipt_id.as_str(),
            qualification
                .product_read_receipt
                .receipt_digest_sha256
                .as_str(),
            "product-read",
        ),
        (
            VerifiedPromotionReceiptKind::PromotionApproval,
            qualification.promotion_receipt.receipt_id.as_str(),
            qualification
                .promotion_receipt
                .receipt_digest_sha256
                .as_str(),
            "promotion approval",
        ),
        (
            VerifiedPromotionReceiptKind::Recovery,
            qualification.rollback_receipt.receipt_id.as_str(),
            qualification
                .rollback_receipt
                .receipt_digest_sha256
                .as_str(),
            "recovery",
        ),
    ] {
        let matching_kind = verification
            .receipts()
            .iter()
            .filter(|receipt| receipt.kind() == kind)
            .collect::<Vec<_>>();
        if matching_kind.is_empty() {
            reasons.push(format!("verified {label} proof is missing"));
        } else if matching_kind.len() != 1
            || matching_kind[0].receipt_id() != receipt_id
            || matching_kind[0].receipt_digest() != receipt_digest
        {
            reasons.push(format!(
                "verified {label} proof does not match qualification"
            ));
        }
    }

    let mut actual_parity = verification
        .receipts()
        .iter()
        .filter(|receipt| receipt.kind() == VerifiedPromotionReceiptKind::Parity)
        .map(|receipt| (receipt.receipt_id(), receipt.receipt_digest()))
        .collect::<Vec<_>>();
    actual_parity.sort_unstable();
    let mut expected_parity = qualification
        .parity_receipt_digests
        .iter()
        .map(|digest| (digest.as_str(), digest.as_str()))
        .collect::<Vec<_>>();
    expected_parity.sort_unstable();
    if actual_parity.is_empty() {
        reasons.push("verified parity proof is missing".to_owned());
    } else if actual_parity != expected_parity {
        reasons.push("verified parity proof does not match qualification".to_owned());
    }
    reasons
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
#[path = "cutover_tests.rs"]
mod tests;
