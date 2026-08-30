//! Portable manifests and payload envelopes for incident snapshots.
//!
//! Snapshot contracts bind bounded graph references to exact payload bytes. The
//! SDK performs structural and payload-digest checks only; canonical encoding,
//! signature creation and verification, authorization, storage, and disclosure
//! policy remain responsibilities of trusted service boundaries.

use serde::Serialize;

use crate::{
    ContentDigest, EntityId, GraphRevision, IncidentSnapshotId, OpaqueId, SdkError, TenantId,
};

const MAX_INCIDENT_SNAPSHOT_ENTITIES: usize = 10_000;
const MAX_INCIDENT_SNAPSHOT_REFERENCES: usize = 10_000;

/// Content-addressed inventory of the records supporting an incident snapshot.
///
/// Reference vectors preserve caller order and may contain duplicates. Both
/// properties affect the manifest digest produced by the engine. The manifest
/// does not contain the snapshot payload digest or signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IncidentSnapshotManifest {
    /// Stable identity of the snapshot package.
    pub snapshot_id: IncidentSnapshotId,
    /// Tenant whose graph and evidence the snapshot represents.
    pub tenant_id: TenantId,
    /// Non-zero graph revision captured by the snapshot.
    pub graph_revision: GraphRevision,
    /// Caller-supplied Unix-millisecond creation time.
    pub created_at_unix_millis: i64,
    /// Non-empty captured entity list, bounded to 10,000 ordered references.
    pub entity_ids: Vec<EntityId>,
    /// Non-empty source receipt list, bounded to 10,000 ordered digests.
    pub source_receipt_digests: Vec<ContentDigest>,
    /// Policy definitions relevant to the incident, bounded to 10,000 digests.
    pub policy_digests: Vec<ContentDigest>,
    /// Related mission identities, bounded to 10,000 entries.
    pub mission_ids: Vec<OpaqueId>,
    /// Verification receipts, bounded to 10,000 ordered digests.
    pub verification_receipt_digests: Vec<ContentDigest>,
    /// Caller-supplied canonical digest of every preceding manifest field.
    pub manifest_digest: ContentDigest,
}

impl IncidentSnapshotManifest {
    /// Validates required collections and per-field reference bounds.
    ///
    /// This shape check does not reject duplicates, validate the timestamp,
    /// prove tenant ownership, or recompute [`Self::manifest_digest`].
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] unless entity count is `1..=10_000` or
    /// when any reference vector exceeds 10,000 entries, and
    /// [`SdkError::Empty`] when no source receipt digest is supplied.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.entity_ids.is_empty() || self.entity_ids.len() > MAX_INCIDENT_SNAPSHOT_ENTITIES {
            return Err(SdkError::OutOfRange("incident snapshot entity count"));
        }
        if self.source_receipt_digests.is_empty() {
            return Err(SdkError::Empty("incident snapshot source receipts"));
        }
        for (references, field) in [
            (
                self.source_receipt_digests.len(),
                "incident snapshot source receipt count",
            ),
            (self.policy_digests.len(), "incident snapshot policy count"),
            (self.mission_ids.len(), "incident snapshot mission count"),
            (
                self.verification_receipt_digests.len(),
                "incident snapshot verification receipt count",
            ),
        ] {
            if references > MAX_INCIDENT_SNAPSHOT_REFERENCES {
                return Err(SdkError::OutOfRange(field));
            }
        }
        Ok(())
    }
}

/// Packaged incident snapshot containing exact payload and signature bytes.
///
/// `canonical_payload` is named by contract but is not re-canonicalized by the
/// SDK. Validation verifies its SHA-256 digest and signature presence, not the
/// signature's algorithm, signer, trust chain, or cryptographic validity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IncidentSnapshot {
    /// Bounded reference inventory associated with the snapshot.
    pub manifest: IncidentSnapshotManifest,
    /// Exact caller-canonicalized payload bytes.
    pub canonical_payload: Vec<u8>,
    /// SHA-256 digest of [`Self::canonical_payload`].
    pub payload_digest: ContentDigest,
    /// Opaque, non-empty signature bytes interpreted by a trusted verifier.
    pub signature: Vec<u8>,
}

impl IncidentSnapshot {
    /// Validates manifest shape, payload presence and digest, and signature presence.
    ///
    /// This method does not recompute the manifest digest, verify the signature,
    /// bind the signature to either digest, or impose payload and signature size
    /// limits. Importing untrusted snapshots therefore requires the engine's
    /// manifest-digest check plus a bounded cryptographic verification boundary.
    ///
    /// # Errors
    ///
    /// Returns manifest validation errors, [`SdkError::Empty`] for an empty
    /// payload or signature, or [`SdkError::Invalid`] when the payload digest
    /// does not match the exact payload bytes.
    pub fn validate(&self) -> Result<(), SdkError> {
        self.manifest.validate()?;
        if self.canonical_payload.is_empty() {
            return Err(SdkError::Empty("incident snapshot payload"));
        }
        if ContentDigest::of_bytes(&self.canonical_payload) != self.payload_digest {
            return Err(SdkError::Invalid("incident snapshot payload digest"));
        }
        if self.signature.is_empty() {
            return Err(SdkError::Empty("incident snapshot signature"));
        }
        Ok(())
    }
}
