use serde::Serialize;

use crate::{
    ContentDigest, EntityId, GraphRevision, IncidentSnapshotId, OpaqueId, SdkError, TenantId,
};

const MAX_INCIDENT_SNAPSHOT_ENTITIES: usize = 10_000;
const MAX_INCIDENT_SNAPSHOT_REFERENCES: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IncidentSnapshotManifest {
    pub snapshot_id: IncidentSnapshotId,
    pub tenant_id: TenantId,
    pub graph_revision: GraphRevision,
    pub created_at_unix_millis: i64,
    pub entity_ids: Vec<EntityId>,
    pub source_receipt_digests: Vec<ContentDigest>,
    pub policy_digests: Vec<ContentDigest>,
    pub mission_ids: Vec<OpaqueId>,
    pub verification_receipt_digests: Vec<ContentDigest>,
    pub manifest_digest: ContentDigest,
}

impl IncidentSnapshotManifest {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IncidentSnapshot {
    pub manifest: IncidentSnapshotManifest,
    pub canonical_payload: Vec<u8>,
    pub payload_digest: ContentDigest,
    pub signature: Vec<u8>,
}

impl IncidentSnapshot {
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
