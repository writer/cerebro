//! Transport-neutral provenance records for graph entities and assertions.
//!
//! Provenance identifies the source events and quality dimensions supporting
//! one graph fact at one revision. These types carry evidence claims; they do
//! not authenticate provider events, authorize disclosure, or verify that a
//! source runtime belongs to the enclosing tenant.

use serde::Serialize;

use crate::{
    AssertionId, ContentDigest, EntityId, GraphRevision, OpaqueId, SdkError, SourceRuntimeId,
    TenantId,
};

const MAX_PROVENANCE_EVIDENCE_REFERENCES: usize = 10_000;

/// Declared trust role of one evidence reference.
///
/// The value is descriptive input to downstream policy. Selecting a variant
/// does not itself prove the reference has that authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthority {
    /// Evidence read from the system of record for the represented fact.
    Authoritative,
    /// Independent evidence that supports, but does not own, the fact.
    Corroborating,
    /// Unconfirmed evidence supplied for review or later verification.
    Proposed,
    /// Evidence retained for context without a trusted authority claim.
    Untrusted,
}

/// Bounded quality vector associated with a set of evidence references.
///
/// Each numeric dimension uses the inclusive range `0..=100`. A zero is valid
/// and means that dimension supplies no confidence; [`Self::minimum_score`]
/// exposes the weakest dimension without hiding a conflict flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceQuality {
    /// Confidence that the evidence is recent enough for the decision.
    pub freshness: u8,
    /// Confidence that the relevant evidence set is complete.
    pub completeness: u8,
    /// Confidence in the authority of the contributing sources.
    pub source_authority: u8,
    /// Confidence that evidence was bound to the correct graph identity.
    pub identity_confidence: u8,
    /// Confidence that verification is independent of the originating actor.
    pub verification_independence: u8,
    /// Whether accepted evidence contains unresolved contradictory claims.
    pub conflicting: bool,
}

impl EvidenceQuality {
    /// Constructs a quality vector whose scores are all in `0..=100`.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] when any score exceeds 100.
    pub fn new(
        freshness: u8,
        completeness: u8,
        source_authority: u8,
        identity_confidence: u8,
        verification_independence: u8,
        conflicting: bool,
    ) -> Result<Self, SdkError> {
        if [
            freshness,
            completeness,
            source_authority,
            identity_confidence,
            verification_independence,
        ]
        .into_iter()
        .any(|score| score > 100)
        {
            return Err(SdkError::OutOfRange("evidence quality score"));
        }
        Ok(Self {
            freshness,
            completeness,
            source_authority,
            identity_confidence,
            verification_independence,
            conflicting,
        })
    }

    /// Returns the weakest numeric quality dimension.
    ///
    /// This bottleneck score intentionally excludes [`Self::conflicting`]. A
    /// consumer must evaluate that independent fail-closed signal separately.
    pub fn minimum_score(&self) -> u8 {
        [
            self.freshness,
            self.completeness,
            self.source_authority,
            self.identity_confidence,
            self.verification_independence,
        ]
        .into_iter()
        .min()
        .unwrap_or_default()
    }
}

/// Content-addressed reference to one source event used as graph evidence.
///
/// The record contains identifiers and a digest rather than a copy of the raw
/// provider payload. Timestamp and authority values are caller-supplied and
/// require validation at the importing trust boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceReference {
    /// Stable identity of this evidence reference within the platform contract.
    pub evidence_id: OpaqueId,
    /// Source runtime that collected or admitted the evidence.
    pub source_runtime_id: SourceRuntimeId,
    /// Stable source-event identity from the append or admission boundary.
    pub event_id: OpaqueId,
    /// Caller-supplied Unix-millisecond observation time.
    pub observed_at_unix_millis: i64,
    /// Declared role of the evidence in the supported fact.
    pub authority: EvidenceAuthority,
    /// Digest of the referenced evidence content.
    pub content_digest: ContentDigest,
}

/// Evidence explanation for exactly one entity or relationship assertion.
///
/// Explanations are scoped to one tenant and non-zero graph revision. The SDK
/// shape validator enforces the target and evidence-count invariants, while the
/// platform engine owns evidence ordering and digest construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProvenanceExplanation {
    /// Tenant whose graph contains the target fact.
    pub tenant_id: TenantId,
    /// Graph revision at which the explanation applies.
    pub graph_revision: GraphRevision,
    /// Target entity, present only for an entity explanation.
    pub entity_id: Option<EntityId>,
    /// Target assertion, present only for a relationship explanation.
    pub assertion_id: Option<AssertionId>,
    /// Non-empty supporting references, bounded to 10,000 entries.
    pub evidence: Vec<EvidenceReference>,
    /// Aggregate quality assessment for the referenced evidence set.
    pub quality: EvidenceQuality,
    /// Canonical digest assigned by the provenance assembly engine.
    pub explanation_digest: ContentDigest,
}

impl ProvenanceExplanation {
    /// Validates target exclusivity and the evidence-reference count.
    ///
    /// This shape check does not recompute [`Self::explanation_digest`],
    /// authenticate evidence, reject duplicate references, or prove that source
    /// runtimes belong to [`Self::tenant_id`]. Importing adapters and the
    /// provenance assembly engine own those stronger boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] unless exactly one target is present,
    /// [`SdkError::Empty`] when no evidence is supplied, or
    /// [`SdkError::OutOfRange`] when more than 10,000 references are supplied.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.entity_id.is_some() == self.assertion_id.is_some() {
            return Err(SdkError::Invalid("provenance target"));
        }
        if self.evidence.is_empty() {
            return Err(SdkError::Empty("provenance evidence"));
        }
        if self.evidence.len() > MAX_PROVENANCE_EVIDENCE_REFERENCES {
            return Err(SdkError::OutOfRange("provenance evidence count"));
        }
        Ok(())
    }
}
