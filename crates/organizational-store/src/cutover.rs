use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_source_catalog::SourceCatalog;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ParityReceipt, ParityStatus};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPromotionRequest {
    tenant_id: String,
    source_id: String,
    family_id: String,
    policy: CutoverPolicy,
    projection_lag: u64,
    promoted_at_unix_ms: i64,
}

impl ProjectionPromotionRequest {
    pub fn new(
        tenant_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        policy: CutoverPolicy,
        projection_lag: u64,
        promoted_at_unix_ms: i64,
    ) -> Result<Self, CutoverError> {
        let tenant_id = checked_text(tenant_id.into(), "tenant_id")?;
        let source_id = checked_text(source_id.into(), "source_id")?;
        let family_id = checked_text(family_id.into(), "family_id")?;
        if promoted_at_unix_ms <= 0 {
            return Err(CutoverError::Invalid("promoted_at_unix_ms"));
        }
        Ok(Self {
            tenant_id,
            source_id,
            family_id,
            policy,
            projection_lag,
            promoted_at_unix_ms,
        })
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn source_id(&self) -> &str {
        &self.source_id
    }

    pub(crate) fn family_id(&self) -> &str {
        &self.family_id
    }

    pub(crate) fn policy(&self) -> CutoverPolicy {
        self.policy
    }

    pub(crate) fn projection_lag(&self) -> u64 {
        self.projection_lag
    }

    pub(crate) fn promoted_at_unix_ms(&self) -> i64 {
        self.promoted_at_unix_ms
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
    source_id: String,
    family_id: String,
    allowed: bool,
    reasons: Vec<String>,
    evidence_digest: String,
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

impl CutoverDecision {
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
        source_id: &str,
        family_id: &str,
        receipts: &[ParityReceipt],
        projection_lag: u64,
    ) -> Result<CutoverDecision, CutoverError> {
        let source = catalog
            .get(source_id)
            .ok_or_else(|| CutoverError::UnknownSource(source_id.to_owned()))?;
        let mut reasons = Vec::new();
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == family_id)
            .ok_or_else(|| CutoverError::UnknownSource(format!("{source_id}/{family_id}")))?;
        if !family.is_authoritative() {
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
        let source_receipts: Vec<_> = receipts
            .iter()
            .filter(|receipt| receipt.source_id() == source_id)
            .filter(|receipt| receipt.family_id() == family_id)
            .collect();
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
        for receipt in source_receipts {
            latest_by_corpus.insert(receipt.collection_id(), receipt);
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
        let evidence_digest = digest(
            &receipts
                .iter()
                .filter(|receipt| receipt.source_id() == source_id)
                .filter(|receipt| receipt.family_id() == family_id)
                .map(ParityReceipt::receipt_digest)
                .collect::<Vec<_>>(),
        );
        Ok(CutoverDecision {
            source_id: source_id.to_owned(),
            family_id: family_id.to_owned(),
            allowed: reasons.is_empty(),
            reasons,
            evidence_digest,
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
    use std::path::{Path, PathBuf};

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn cutover_requires_proof_three_matches_and_zero_lag() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let receipts: Vec<_> = (1..=3)
            .map(|index| {
                ParityReceipt::compare(
                    "box",
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
        assert!(
            gate.evaluate(&catalog, "box", "users", &receipts, 0)
                .unwrap()
                .is_allowed()
        );
        assert!(
            !gate
                .evaluate(&catalog, "box", "users", &receipts[..2], 0)
                .unwrap()
                .is_allowed()
        );
        assert!(
            !gate
                .evaluate(&catalog, "agiloft", "users", &receipts, 0)
                .unwrap()
                .is_allowed()
        );
    }

    #[test]
    fn promotion_request_and_decision_bind_the_exact_scope() {
        let policy = CutoverPolicy::new(3, 2).unwrap();
        let request =
            ProjectionPromotionRequest::new("tenant-a", "box", "users", policy, 1, 100).unwrap();
        assert_eq!(request.tenant_id(), "tenant-a");
        assert_eq!(request.source_id(), "box");
        assert_eq!(request.family_id(), "users");
        assert_eq!(request.policy(), policy);
        assert_eq!(request.projection_lag(), 1);
        assert_eq!(request.promoted_at_unix_ms(), 100);

        assert_eq!(CutoverPolicy::new(2, 0), Err(CutoverError::UnsafePolicy));
        assert_eq!(
            ProjectionPromotionRequest::new("", "box", "users", policy, 0, 1),
            Err(CutoverError::Invalid("tenant_id"))
        );
        assert_eq!(
            ProjectionPromotionRequest::new("tenant", " box", "users", policy, 0, 1),
            Err(CutoverError::Invalid("source_id"))
        );
        assert_eq!(
            ProjectionPromotionRequest::new("tenant", "box", "users", policy, 0, 0),
            Err(CutoverError::Invalid("promoted_at_unix_ms"))
        );
        assert_eq!(
            CutoverError::UnsafePolicy.to_string(),
            "cutover requires at least three matching runs"
        );
        assert_eq!(
            CutoverError::UnknownSource("missing".to_owned()).to_string(),
            "source missing is not in the catalog"
        );
    }

    #[test]
    fn cutover_reports_each_failed_proof_instead_of_collapsing_them() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let receipts = vec![
            ParityReceipt::compare_scoped(
                "tenant-a",
                "box-prod",
                "box",
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
                "box-prod",
                "box",
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
                "box-prod",
                "box",
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
        let decision = gate
            .evaluate(&catalog, "box", "users", &receipts, 4)
            .unwrap();
        assert_eq!(decision.source_id(), "box");
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

        assert_eq!(
            gate.evaluate(&catalog, "missing", "users", &receipts, 0),
            Err(CutoverError::UnknownSource("missing".to_owned()))
        );
        assert_eq!(
            gate.evaluate(&catalog, "box", "missing", &receipts, 0),
            Err(CutoverError::UnknownSource("box/missing".to_owned()))
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
        let base = ParityReceipt::compare(
            "box",
            "users",
            "corpus-1",
            "sha256:same",
            "sha256:same",
            true,
            1,
        )
        .unwrap();
        let legacy = SemanticSnapshot::from_facts(
            "legacy-shadow",
            "legacy-shadow",
            "box",
            "users",
            "corpus-1",
            "legacy-shadow",
            "legacy",
            true,
            Vec::new(),
        )
        .unwrap();
        let rust = SemanticSnapshot::from_facts(
            "legacy-shadow",
            "legacy-shadow",
            "box",
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
        let decision = gate
            .evaluate(&catalog, "box", "users", &[base.clone(), base, lagged], 0)
            .unwrap();
        assert!(!decision.is_allowed());
        assert!(decision
            .reasons()
            .iter()
            .any(|reason| reason == "a latest parity receipt exceeds the projection lag policy"));
    }
}
