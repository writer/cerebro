use serde::Serialize;

use crate::{AssertionId, ContentDigest, EntityId, GraphRevision, OpaqueId, SdkError, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthority {
    Authoritative,
    Corroborating,
    Proposed,
    Untrusted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceQuality {
    pub freshness: u8,
    pub completeness: u8,
    pub source_authority: u8,
    pub identity_confidence: u8,
    pub verification_independence: u8,
    pub conflicting: bool,
}

impl EvidenceQuality {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceReference {
    pub evidence_id: OpaqueId,
    pub source_runtime_id: String,
    pub event_id: String,
    pub observed_at_unix_millis: i64,
    pub authority: EvidenceAuthority,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProvenanceExplanation {
    pub tenant_id: TenantId,
    pub graph_revision: GraphRevision,
    pub entity_id: Option<EntityId>,
    pub assertion_id: Option<AssertionId>,
    pub evidence: Vec<EvidenceReference>,
    pub quality: EvidenceQuality,
    pub explanation_digest: ContentDigest,
}

impl ProvenanceExplanation {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.entity_id.is_some() == self.assertion_id.is_some() {
            return Err(SdkError::Invalid("provenance target"));
        }
        if self.evidence.is_empty() {
            return Err(SdkError::Empty("provenance evidence"));
        }
        Ok(())
    }
}
