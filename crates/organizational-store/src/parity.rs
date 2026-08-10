#![deny(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use cerebro_organizational_model::{
    EntityAuthority, EntityKind, GraphAssertion, GraphDelta, IdentityBindingState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_FACT_PART_BYTES: usize = 4_096;
const MAX_MISMATCHES_IN_RECEIPT: usize = 100;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// Semantic unit compared across legacy and Rust projectors.
pub enum SemanticFactKind {
    /// A general organizational entity and its stable meaning.
    Entity,
    /// An externally owned identity record.
    ProviderIdentity,
    /// A Cerebro-owned canonical person identity.
    CanonicalIdentity,
    /// A typed directed relationship.
    Relationship,
    /// A provider-to-canonical identity decision.
    IdentityBinding,
    /// Observation identity supporting an assertion.
    Provenance,
    /// Removal of a previously admitted assertion.
    Retraction,
}

impl SemanticFactKind {
    /// Parses a stable snake-case fact-kind name.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] for an unknown name.
    pub fn parse(value: &str) -> Result<Self, ParityError> {
        match value {
            "entity" => Ok(Self::Entity),
            "provider_identity" => Ok(Self::ProviderIdentity),
            "canonical_identity" => Ok(Self::CanonicalIdentity),
            "relationship" => Ok(Self::Relationship),
            "identity_binding" => Ok(Self::IdentityBinding),
            "provenance" => Ok(Self::Provenance),
            "retraction" => Ok(Self::Retraction),
            _ => Err(ParityError::Invalid("semantic fact kind")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::ProviderIdentity => "provider_identity",
            Self::CanonicalIdentity => "canonical_identity",
            Self::Relationship => "relationship",
            Self::IdentityBinding => "identity_binding",
            Self::Provenance => "provenance",
            Self::Retraction => "retraction",
        }
    }
}

/// A comparison fact is deliberately smaller than either projector's storage
/// shape. It describes one meaning that must survive the migration.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticFact {
    kind: SemanticFactKind,
    parts: Vec<String>,
}

impl SemanticFact {
    /// Constructs one comparison fact from ordered semantic parts.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] when there are no parts, a part exceeds
    /// 4,096 bytes, or a part contains a control character.
    pub fn new(
        kind: SemanticFactKind,
        parts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ParityError> {
        let parts = parts
            .into_iter()
            .map(Into::into)
            .map(validate_fact_part)
            .collect::<Result<Vec<_>, _>>()?;
        if parts.is_empty() {
            return Err(ParityError::Invalid("semantic fact parts"));
        }
        Ok(Self { kind, parts })
    }

    /// Returns the semantic category being compared.
    pub fn kind(&self) -> SemanticFactKind {
        self.kind
    }

    /// Returns the ordered values defining the fact's meaning.
    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    fn canonical_line(&self) -> String {
        let mut line = self.kind.as_str().to_owned();
        for part in &self.parts {
            line.push('\u{1f}');
            line.push_str(&part.len().to_string());
            line.push(':');
            line.push_str(part);
        }
        line
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Canonical semantic output for one exact projector input corpus.
///
/// Facts are deduplicated and sorted before hashing, so insertion order and
/// duplicate emission cannot create false parity differences.
pub struct SemanticSnapshot {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    collection_id: String,
    input_digest: String,
    projector_revision: String,
    complete: bool,
    facts: Vec<SemanticFact>,
    digest: String,
}

impl SemanticSnapshot {
    /// Constructs a snapshot from explicitly normalized semantic facts.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] when a scope, digest, or revision value
    /// is empty, untrimmed, or exceeds 4,096 bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn from_facts(
        tenant_id: impl Into<String>,
        source_runtime_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        collection_id: impl Into<String>,
        input_digest: impl Into<String>,
        projector_revision: impl Into<String>,
        complete: bool,
        facts: impl IntoIterator<Item = SemanticFact>,
    ) -> Result<Self, ParityError> {
        let tenant_id = required(tenant_id.into(), "tenant_id")?;
        let source_runtime_id = required(source_runtime_id.into(), "source_runtime_id")?;
        let source_id = required(source_id.into(), "source_id")?;
        let family_id = required(family_id.into(), "family_id")?;
        let collection_id = required(collection_id.into(), "collection_id")?;
        let input_digest = required(input_digest.into(), "input_digest")?;
        let projector_revision = required(projector_revision.into(), "projector_revision")?;
        let facts = facts
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let digest = snapshot_digest(&facts);
        Ok(Self {
            tenant_id,
            source_runtime_id,
            source_id,
            family_id,
            collection_id,
            input_digest,
            projector_revision,
            complete,
            facts,
            digest,
        })
    }

    /// Converts a sealed Rust graph delta into its storage-neutral semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] when assertion endpoints are absent
    /// from the delta or a generated semantic part violates the fact contract.
    pub fn from_delta(
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        input_digest: impl Into<String>,
        projector_revision: impl Into<String>,
        delta: &GraphDelta,
    ) -> Result<Self, ParityError> {
        let mut facts = Vec::new();
        let mut entity_keys = BTreeMap::new();
        for entity in delta.entities() {
            let kind = entity_kind(entity.kind());
            match entity.authority() {
                EntityAuthority::Canonical => {
                    let entity_key = format!("canonical:{}", entity.id());
                    entity_keys.insert(entity.id().clone(), entity_key.clone());
                    let fact_kind = if matches!(entity.kind(), EntityKind::Person) {
                        SemanticFactKind::CanonicalIdentity
                    } else {
                        SemanticFactKind::Entity
                    };
                    facts.push(SemanticFact::new(
                        fact_kind,
                        [entity_key.as_str(), kind.as_str(), entity.label()],
                    )?);
                }
                EntityAuthority::Provider {
                    source_runtime_id,
                    provider_kind,
                    provider_id,
                } => {
                    let fact_kind = if matches!(entity.kind(), EntityKind::Identity) {
                        SemanticFactKind::ProviderIdentity
                    } else {
                        SemanticFactKind::Entity
                    };
                    let entity_key = format!(
                        "provider:{source_runtime_id}:{}:{provider_id}",
                        provider_kind.as_str()
                    );
                    entity_keys.insert(entity.id().clone(), entity_key.clone());
                    facts.push(SemanticFact::new(
                        fact_kind,
                        [entity_key.as_str(), kind.as_str(), entity.label()],
                    )?);
                }
            }
        }
        for assertion in delta.assertions() {
            let assertion_key = match assertion {
                GraphAssertion::Relationship(value) => {
                    let from = entity_keys
                        .get(value.from())
                        .ok_or(ParityError::Invalid("relationship from entity"))?;
                    let to = entity_keys
                        .get(value.to())
                        .ok_or(ParityError::Invalid("relationship to entity"))?;
                    facts.push(SemanticFact::new(
                        SemanticFactKind::Relationship,
                        [from.as_str(), value.relation().as_str(), to.as_str()],
                    )?);
                    format!("relationship:{from}:{}:{to}", value.relation().as_str())
                }
                GraphAssertion::IdentityBinding(value) => {
                    let provider = entity_keys
                        .get(value.provider_identity())
                        .ok_or(ParityError::Invalid("provider identity"))?;
                    let canonical = entity_keys
                        .get(value.canonical_identity())
                        .ok_or(ParityError::Invalid("canonical identity"))?;
                    let claim_kind = value
                        .claim()
                        .map(|claim| claim.kind().as_str())
                        .unwrap_or("");
                    let claim_value = value.claim().map(|claim| claim.value()).unwrap_or("");
                    facts.push(SemanticFact::new(
                        SemanticFactKind::IdentityBinding,
                        [
                            provider.as_str(),
                            canonical.as_str(),
                            identity_binding_state(value.state()),
                            claim_kind,
                            claim_value,
                        ],
                    )?);
                    format!("identity_binding:{provider}:{canonical}:{claim_kind}:{claim_value}")
                }
            };
            let provenance = assertion.provenance();
            let mut observations = provenance
                .observations()
                .iter()
                .map(|observation| observation.observation_id().as_str())
                .collect::<Vec<_>>();
            observations.sort_unstable();
            let mut parts = vec![assertion_key.as_str()];
            parts.extend(observations);
            facts.push(SemanticFact::new(SemanticFactKind::Provenance, parts)?);
        }
        for retraction in delta.retractions() {
            facts.push(SemanticFact::new(
                SemanticFactKind::Retraction,
                [retraction.assertion_id().as_str(), retraction.reason()],
            )?);
        }
        Self::from_facts(
            delta.collection().tenant_id().as_str(),
            delta.collection().source_runtime_id().as_str(),
            source_id,
            family_id,
            delta.collection().collection_id().as_str(),
            input_digest,
            projector_revision,
            matches!(
                delta.collection().completeness(),
                cerebro_organizational_model::CollectionCompleteness::Complete
            ),
            facts,
        )
    }

    /// Returns the compared tenant.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the runtime that collected the input.
    pub fn source_runtime_id(&self) -> &str {
        &self.source_runtime_id
    }

    /// Returns the catalog source.
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the catalog source family.
    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    /// Returns the exact collection or corpus identifier.
    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    /// Returns the digest of the projector input corpus.
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    /// Returns the implementation revision that produced this snapshot.
    pub fn projector_revision(&self) -> &str {
        &self.projector_revision
    }

    /// Returns whether the projector covered the complete declared corpus.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns the sorted, deduplicated semantic facts.
    pub fn facts(&self) -> &[SemanticFact] {
        &self.facts
    }

    /// Returns the deterministic digest of semantic fact membership.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Which projector emitted a semantic fact missing from the other snapshot.
pub enum MismatchSide {
    /// The fact exists only in the legacy projector output.
    LegacyOnly,
    /// The fact exists only in the Rust projector output.
    RustOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// One bounded semantic difference between projector outputs.
pub struct SemanticMismatch {
    side: MismatchSide,
    fact: SemanticFact,
}

impl SemanticMismatch {
    /// Returns which projector exclusively emitted the fact.
    pub fn side(&self) -> MismatchSide {
        self.side
    }

    /// Returns the differing semantic fact.
    pub fn fact(&self) -> &SemanticFact {
        &self.fact
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Completeness and equality outcome for one projector comparison.
pub enum ParityStatus {
    /// Both complete snapshots contain identical semantic facts.
    Match,
    /// Complete snapshots differ semantically.
    Mismatch,
    /// At least one snapshot did not cover the complete corpus.
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Content-bound evidence comparing legacy and Rust projector semantics.
///
/// The receipt records the total mismatch count but retains at most 100 sample
/// differences. A zero sampled difference is therefore meaningful only when
/// [`ParityReceipt::status`] is [`ParityStatus::Match`] and the denominator is
/// known to be nonzero outside this record.
pub struct ParityReceipt {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    collection_id: String,
    input_digest: String,
    legacy_projector_revision: String,
    rust_projector_revision: String,
    legacy_digest: String,
    rust_digest: String,
    status: ParityStatus,
    mismatch_count: usize,
    mismatches: Vec<SemanticMismatch>,
    projection_lag: u64,
    compared_at_unix_ms: i64,
    runtime_versions: BTreeMap<String, String>,
    receipt_digest: String,
}

impl ParityReceipt {
    /// Compares two complete, identically scoped semantic snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::ScopeMismatch`] when tenant, runtime, source,
    /// family, collection, or input digest differs, and [`ParityError::Invalid`]
    /// for a non-positive comparison time.
    pub fn compare_snapshots(
        legacy: &SemanticSnapshot,
        rust: &SemanticSnapshot,
        projection_lag: u64,
        compared_at_unix_ms: i64,
        runtime_versions: BTreeMap<String, String>,
    ) -> Result<Self, ParityError> {
        if compared_at_unix_ms <= 0 {
            return Err(ParityError::Invalid("compared_at_unix_ms"));
        }
        for (field, left, right) in [
            ("tenant_id", legacy.tenant_id(), rust.tenant_id()),
            (
                "source_runtime_id",
                legacy.source_runtime_id(),
                rust.source_runtime_id(),
            ),
            ("source_id", legacy.source_id(), rust.source_id()),
            ("family_id", legacy.family_id(), rust.family_id()),
            (
                "collection_id",
                legacy.collection_id(),
                rust.collection_id(),
            ),
            ("input_digest", legacy.input_digest(), rust.input_digest()),
        ] {
            if left != right {
                return Err(ParityError::ScopeMismatch(field));
            }
        }
        let legacy_facts = legacy.facts.iter().cloned().collect::<BTreeSet<_>>();
        let rust_facts = rust.facts.iter().cloned().collect::<BTreeSet<_>>();
        let all_mismatches = legacy_facts
            .difference(&rust_facts)
            .cloned()
            .map(|fact| SemanticMismatch {
                side: MismatchSide::LegacyOnly,
                fact,
            })
            .chain(
                rust_facts
                    .difference(&legacy_facts)
                    .cloned()
                    .map(|fact| SemanticMismatch {
                        side: MismatchSide::RustOnly,
                        fact,
                    }),
            )
            .collect::<Vec<_>>();
        let mismatch_count = all_mismatches.len();
        let mismatches = all_mismatches
            .into_iter()
            .take(MAX_MISMATCHES_IN_RECEIPT)
            .collect::<Vec<_>>();
        let status = if !legacy.complete || !rust.complete {
            ParityStatus::Incomplete
        } else if mismatch_count == 0 {
            ParityStatus::Match
        } else {
            ParityStatus::Mismatch
        };
        let mut receipt = Self {
            tenant_id: legacy.tenant_id.clone(),
            source_runtime_id: legacy.source_runtime_id.clone(),
            source_id: legacy.source_id.clone(),
            family_id: legacy.family_id.clone(),
            collection_id: legacy.collection_id.clone(),
            input_digest: legacy.input_digest.clone(),
            legacy_projector_revision: legacy.projector_revision.clone(),
            rust_projector_revision: rust.projector_revision.clone(),
            legacy_digest: legacy.digest.clone(),
            rust_digest: rust.digest.clone(),
            status,
            mismatch_count,
            mismatches,
            projection_lag,
            compared_at_unix_ms,
            runtime_versions,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt_digest(&receipt);
        Ok(receipt)
    }

    /// Compatibility constructor for existing digest-only shadow callers.
    ///
    /// This form uses synthetic legacy scope and cannot substitute for the
    /// fully bound snapshots required by an authority decision.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] for invalid scope, digest, or time.
    #[allow(clippy::too_many_arguments)]
    pub fn compare(
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        corpus_id: impl Into<String>,
        legacy_digest: impl Into<String>,
        rust_digest: impl Into<String>,
        complete: bool,
        compared_at_unix_ms: i64,
    ) -> Result<Self, ParityError> {
        Self::compare_scoped(
            "legacy-shadow",
            "legacy-shadow",
            source_id,
            family_id,
            corpus_id,
            legacy_digest,
            rust_digest,
            complete,
            compared_at_unix_ms,
        )
    }

    /// Constructs a scoped digest-only compatibility comparison.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Invalid`] for empty, untrimmed, oversized fields
    /// or a non-positive comparison time.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_scoped(
        tenant_id: impl Into<String>,
        source_runtime_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        corpus_id: impl Into<String>,
        legacy_digest: impl Into<String>,
        rust_digest: impl Into<String>,
        complete: bool,
        compared_at_unix_ms: i64,
    ) -> Result<Self, ParityError> {
        let tenant_id = required(tenant_id.into(), "tenant_id")?;
        let source_runtime_id = required(source_runtime_id.into(), "source_runtime_id")?;
        let source_id = required(source_id.into(), "source_id")?;
        let family_id = required(family_id.into(), "family_id")?;
        let collection_id = required(corpus_id.into(), "corpus_id")?;
        let legacy_digest = required(legacy_digest.into(), "legacy_digest")?;
        let rust_digest = required(rust_digest.into(), "rust_digest")?;
        if compared_at_unix_ms <= 0 {
            return Err(ParityError::Invalid("compared_at_unix_ms"));
        }
        let status = if !complete {
            ParityStatus::Incomplete
        } else if legacy_digest == rust_digest {
            ParityStatus::Match
        } else {
            ParityStatus::Mismatch
        };
        let mismatch_count = usize::from(status == ParityStatus::Mismatch);
        let mut receipt = Self {
            tenant_id,
            source_runtime_id,
            source_id,
            family_id,
            collection_id,
            input_digest: "legacy-shadow".to_owned(),
            legacy_projector_revision: "unknown".to_owned(),
            rust_projector_revision: "unknown".to_owned(),
            legacy_digest,
            rust_digest,
            status,
            mismatch_count,
            mismatches: Vec::new(),
            projection_lag: 0,
            compared_at_unix_ms,
            runtime_versions: BTreeMap::new(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt_digest(&receipt);
        Ok(receipt)
    }

    /// Returns the compared tenant.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the source runtime that collected the corpus.
    pub fn source_runtime_id(&self) -> &str {
        &self.source_runtime_id
    }

    /// Returns the catalog source.
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the catalog source family.
    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    /// Returns the compared collection or corpus ID.
    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    /// Returns the comparison outcome.
    pub fn status(&self) -> ParityStatus {
        self.status
    }

    /// Returns the total number of semantic differences before sample truncation.
    pub fn mismatch_count(&self) -> usize {
        self.mismatch_count
    }

    /// Returns the observed projection lag associated with the comparison.
    pub fn projection_lag(&self) -> u64 {
        self.projection_lag
    }

    /// Returns when comparison occurred, as positive Unix milliseconds.
    pub fn compared_at_unix_ms(&self) -> i64 {
        self.compared_at_unix_ms
    }

    /// Returns the digest binding all receipt fields and sampled differences.
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Invalid parity input or snapshots that describe different corpora.
pub enum ParityError {
    /// A named field violated its validation contract.
    Invalid(&'static str),
    /// Legacy and Rust snapshots disagreed on a named scope coordinate.
    ScopeMismatch(&'static str),
}

impl fmt::Display for ParityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::ScopeMismatch(field) => {
                write!(formatter, "projector snapshots disagree on {field}")
            }
        }
    }
}

impl Error for ParityError {}

fn required(value: String, field: &'static str) -> Result<String, ParityError> {
    if value.trim().is_empty() || value.trim() != value || value.len() > MAX_FACT_PART_BYTES {
        return Err(ParityError::Invalid(field));
    }
    Ok(value)
}

fn validate_fact_part(value: String) -> Result<String, ParityError> {
    if value.len() > MAX_FACT_PART_BYTES || value.chars().any(char::is_control) {
        return Err(ParityError::Invalid("semantic fact part"));
    }
    Ok(value)
}

fn snapshot_digest(facts: &[SemanticFact]) -> String {
    digest(
        facts
            .iter()
            .map(SemanticFact::canonical_line)
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str),
    )
}

fn receipt_digest(receipt: &ParityReceipt) -> String {
    let mut parts = vec![
        receipt.tenant_id.as_str(),
        receipt.source_runtime_id.as_str(),
        receipt.source_id.as_str(),
        receipt.family_id.as_str(),
        receipt.collection_id.as_str(),
        receipt.input_digest.as_str(),
        receipt.legacy_projector_revision.as_str(),
        receipt.rust_projector_revision.as_str(),
        receipt.legacy_digest.as_str(),
        receipt.rust_digest.as_str(),
        match receipt.status {
            ParityStatus::Match => "match",
            ParityStatus::Mismatch => "mismatch",
            ParityStatus::Incomplete => "incomplete",
        },
    ];
    let mismatch_count = receipt.mismatch_count.to_string();
    let projection_lag = receipt.projection_lag.to_string();
    let compared_at = receipt.compared_at_unix_ms.to_string();
    parts.extend([
        mismatch_count.as_str(),
        projection_lag.as_str(),
        compared_at.as_str(),
    ]);
    let runtime_parts = receipt
        .runtime_versions
        .iter()
        .map(|(name, version)| format!("{name}={version}"))
        .collect::<Vec<_>>();
    parts.extend(runtime_parts.iter().map(String::as_str));
    digest(parts)
}

fn digest<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
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

fn entity_kind(kind: &EntityKind) -> String {
    match kind {
        EntityKind::Provider(kind) => format!("provider:{}", kind.as_str()),
        kind => kind.as_str().to_owned(),
    }
}

fn identity_binding_state(state: IdentityBindingState) -> &'static str {
    match state {
        IdentityBindingState::Proposed => "proposed",
        IdentityBindingState::Confirmed => "confirmed",
        IdentityBindingState::Rejected => "rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_organizational_model::{
        AssertionId, AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection,
        Entity, EntityId, GraphAssertion, IdentityBindingAssertion, IdentityClaim,
        IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity, ProviderKind,
        RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
    };

    fn snapshot(revision: &str, facts: Vec<SemanticFact>) -> SemanticSnapshot {
        SemanticSnapshot::from_facts(
            "tenant-a",
            "box-prod",
            "box",
            "content_assets",
            "collection-1",
            "sha256:input",
            revision,
            true,
            facts,
        )
        .unwrap()
    }

    #[test]
    fn order_and_duplicate_facts_do_not_change_a_snapshot() {
        let first = SemanticFact::new(SemanticFactKind::Entity, ["asset-1", "resource"]).unwrap();
        let second = SemanticFact::new(SemanticFactKind::Entity, ["asset-2", "resource"]).unwrap();
        let left = snapshot("legacy", vec![first.clone(), second.clone(), first.clone()]);
        let right = snapshot("rust", vec![second, first]);
        assert_eq!(left.digest(), right.digest());
        let receipt =
            ParityReceipt::compare_snapshots(&left, &right, 0, 10, BTreeMap::new()).unwrap();
        assert_eq!(receipt.status(), ParityStatus::Match);
        assert_eq!(receipt.mismatch_count(), 0);
    }

    #[test]
    fn receipt_records_bounded_semantic_differences() {
        let legacy = snapshot(
            "legacy",
            vec![
                SemanticFact::new(
                    SemanticFactKind::Relationship,
                    ["person-1", "member_of", "team-1"],
                )
                .unwrap(),
            ],
        );
        let rust = snapshot(
            "rust",
            vec![
                SemanticFact::new(
                    SemanticFactKind::Relationship,
                    ["person-1", "member_of", "team-2"],
                )
                .unwrap(),
            ],
        );
        let receipt =
            ParityReceipt::compare_snapshots(&legacy, &rust, 0, 10, BTreeMap::new()).unwrap();
        assert_eq!(receipt.status(), ParityStatus::Mismatch);
        assert_eq!(receipt.mismatch_count(), 2);
        assert_eq!(receipt.mismatches.len(), 2);
    }

    #[test]
    fn different_input_corpora_cannot_be_compared() {
        let legacy = snapshot("legacy", Vec::new());
        let mut rust = snapshot("rust", Vec::new());
        rust.input_digest = "sha256:other".to_owned();
        assert!(matches!(
            ParityReceipt::compare_snapshots(&legacy, &rust, 0, 10, BTreeMap::new()),
            Err(ParityError::ScopeMismatch("input_digest"))
        ));
    }

    #[test]
    fn graph_delta_becomes_a_complete_semantic_snapshot() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse("collection-1").unwrap(),
            "okta.users",
            10,
        )
        .unwrap();
        let observation = ObservationRef::new(
            collection.receipt(),
            ObservationId::parse("observation-1").unwrap(),
            "okta.user:00u1",
        )
        .unwrap();
        let evidence =
            AssertionProvenance::direct(vec![observation], "identity-mapper", "v1").unwrap();
        let claim = IdentityClaim::verified_email("person@example.com").unwrap();
        let canonical = CanonicalIdentity::for_claim(tenant.clone(), &claim, "A Person").unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("okta.user").unwrap(),
            "00u1",
            "A Person",
        )
        .unwrap();
        let group = Entity::canonical(
            tenant,
            EntityId::parse("group-1").unwrap(),
            EntityKind::Group,
            "Engineering",
        )
        .unwrap();
        let relationship = RelationshipAssertion::new(
            provider.entity(),
            RelationKind::MemberOf,
            &group,
            evidence.clone(),
            10,
        )
        .unwrap();
        let binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::VerifiedEmail,
            Some(claim),
            IdentityBindingState::Confirmed,
            evidence,
            10,
        )
        .unwrap();

        let mut builder = collection.begin_delta();
        builder.add_entity(provider.into_entity()).unwrap();
        builder.add_entity(canonical.into_entity()).unwrap();
        builder.add_entity(group).unwrap();
        builder
            .add_assertion(GraphAssertion::Relationship(relationship))
            .unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(binding))
            .unwrap();
        builder
            .retract_missing(
                AssertionId::parse("assertion-old").unwrap(),
                "missing from complete collection",
            )
            .unwrap();
        let delta = builder.build();
        let snapshot =
            SemanticSnapshot::from_delta("okta", "users", "sha256:input", "rust-v1", &delta)
                .unwrap();
        assert_eq!(snapshot.tenant_id(), "tenant-a");
        assert_eq!(snapshot.source_runtime_id(), "okta-prod");
        assert_eq!(snapshot.source_id(), "okta");
        assert_eq!(snapshot.family_id(), "users");
        assert_eq!(snapshot.collection_id(), "collection-1");
        assert_eq!(snapshot.input_digest(), "sha256:input");
        assert_eq!(snapshot.projector_revision(), "rust-v1");
        assert!(snapshot.is_complete());
        assert!(snapshot.digest().starts_with("sha256:"));
        let kinds = snapshot
            .facts()
            .iter()
            .map(SemanticFact::kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([
                SemanticFactKind::Entity,
                SemanticFactKind::ProviderIdentity,
                SemanticFactKind::CanonicalIdentity,
                SemanticFactKind::Relationship,
                SemanticFactKind::IdentityBinding,
                SemanticFactKind::Provenance,
                SemanticFactKind::Retraction,
            ])
        );
        assert!(snapshot.facts().iter().all(|fact| !fact.parts().is_empty()));
    }

    #[test]
    fn every_entity_kind_and_binding_state_has_a_stable_semantic_name() {
        let kinds = [
            EntityKind::Person,
            EntityKind::Identity,
            EntityKind::Team,
            EntityKind::Organization,
            EntityKind::Repository,
            EntityKind::Service,
            EntityKind::Application,
            EntityKind::Environment,
            EntityKind::Account,
            EntityKind::Resource,
            EntityKind::Group,
            EntityKind::Role,
            EntityKind::Policy,
            EntityKind::Control,
            EntityKind::Finding,
            EntityKind::Provider(ProviderKind::parse("github.repository").unwrap()),
        ];
        let names = kinds.iter().map(entity_kind).collect::<Vec<_>>();
        assert_eq!(names.first().unwrap(), "person");
        assert_eq!(names.last().unwrap(), "provider:github.repository");
        assert_eq!(
            identity_binding_state(IdentityBindingState::Proposed),
            "proposed"
        );
        assert_eq!(
            identity_binding_state(IdentityBindingState::Confirmed),
            "confirmed"
        );
        assert_eq!(
            identity_binding_state(IdentityBindingState::Rejected),
            "rejected"
        );
    }

    #[test]
    fn receipt_accessors_and_mismatch_sides_bind_the_comparison() {
        let left = SemanticFact::new(SemanticFactKind::Entity, ["legacy", "resource"]).unwrap();
        let right = SemanticFact::new(SemanticFactKind::Entity, ["rust", "resource"]).unwrap();
        let legacy = snapshot("legacy-v1", vec![left]);
        let rust = snapshot("rust-v1", vec![right]);
        let versions = BTreeMap::from([
            ("go".to_owned(), "1.24".to_owned()),
            ("rust".to_owned(), "1.88".to_owned()),
        ]);
        let receipt = ParityReceipt::compare_snapshots(&legacy, &rust, 2, 42, versions).unwrap();
        assert_eq!(receipt.tenant_id(), "tenant-a");
        assert_eq!(receipt.source_runtime_id(), "box-prod");
        assert_eq!(receipt.source_id(), "box");
        assert_eq!(receipt.family_id(), "content_assets");
        assert_eq!(receipt.collection_id(), "collection-1");
        assert_eq!(receipt.status(), ParityStatus::Mismatch);
        assert_eq!(receipt.mismatch_count(), 2);
        assert_eq!(receipt.projection_lag(), 2);
        assert_eq!(receipt.compared_at_unix_ms(), 42);
        assert!(receipt.receipt_digest().starts_with("sha256:"));
        assert_eq!(receipt.mismatches[0].side(), MismatchSide::LegacyOnly);
        assert_eq!(receipt.mismatches[1].side(), MismatchSide::RustOnly);
        assert_eq!(
            receipt.mismatches[0].fact().kind(),
            SemanticFactKind::Entity
        );

        let incomplete = ParityReceipt::compare(
            "box",
            "content_assets",
            "collection-1",
            "sha256:same",
            "sha256:same",
            false,
            43,
        )
        .unwrap();
        assert_eq!(incomplete.status(), ParityStatus::Incomplete);
        let mismatch = ParityReceipt::compare_scoped(
            "tenant-a",
            "box-prod",
            "box",
            "content_assets",
            "collection-1",
            "sha256:left",
            "sha256:right",
            true,
            44,
        )
        .unwrap();
        assert_eq!(mismatch.status(), ParityStatus::Mismatch);
    }

    #[test]
    fn parity_input_validation_rejects_ambiguous_facts_and_scopes() {
        for (name, kind) in [
            ("entity", SemanticFactKind::Entity),
            ("provider_identity", SemanticFactKind::ProviderIdentity),
            ("canonical_identity", SemanticFactKind::CanonicalIdentity),
            ("relationship", SemanticFactKind::Relationship),
            ("identity_binding", SemanticFactKind::IdentityBinding),
            ("provenance", SemanticFactKind::Provenance),
            ("retraction", SemanticFactKind::Retraction),
        ] {
            assert_eq!(SemanticFactKind::parse(name), Ok(kind));
        }
        assert_eq!(
            SemanticFactKind::parse("unknown"),
            Err(ParityError::Invalid("semantic fact kind"))
        );
        assert_eq!(
            SemanticFact::new(SemanticFactKind::Entity, Vec::<String>::new()),
            Err(ParityError::Invalid("semantic fact parts"))
        );
        assert_eq!(
            SemanticFact::new(SemanticFactKind::Entity, ["bad\npart"]),
            Err(ParityError::Invalid("semantic fact part"))
        );
        assert_eq!(
            SemanticSnapshot::from_facts(
                "",
                "runtime",
                "source",
                "family",
                "collection",
                "input",
                "revision",
                true,
                Vec::new(),
            ),
            Err(ParityError::Invalid("tenant_id"))
        );
        assert_eq!(
            ParityReceipt::compare("source", "family", "corpus", "left", "right", true, 0),
            Err(ParityError::Invalid("compared_at_unix_ms"))
        );
        assert_eq!(
            ParityError::Invalid("field").to_string(),
            "field is invalid"
        );
        assert_eq!(
            ParityError::ScopeMismatch("field").to_string(),
            "projector snapshots disagree on field"
        );
    }
}
