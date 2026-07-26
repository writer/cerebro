use cerebro_platform_sdk::{
    ContentDigest, GraphRevision, IncidentSnapshot, IncidentSnapshotId, IncidentSnapshotManifest,
    OpaqueId, SdkError, TenantId,
};
use serde::Serialize;

use crate::canonical;

#[derive(Serialize)]
struct ManifestMaterial<'a> {
    snapshot_id: &'a IncidentSnapshotId,
    tenant_id: &'a TenantId,
    graph_revision: GraphRevision,
    created_at_unix_millis: i64,
    entity_ids: &'a [cerebro_platform_sdk::EntityId],
    source_receipt_digests: &'a [ContentDigest],
    policy_digests: &'a [ContentDigest],
    mission_ids: &'a [OpaqueId],
    verification_receipt_digests: &'a [ContentDigest],
}

pub fn incident_manifest_digest(
    manifest: &IncidentSnapshotManifest,
) -> Result<ContentDigest, SdkError> {
    canonical::digest(&ManifestMaterial {
        snapshot_id: &manifest.snapshot_id,
        tenant_id: &manifest.tenant_id,
        graph_revision: manifest.graph_revision,
        created_at_unix_millis: manifest.created_at_unix_millis,
        entity_ids: &manifest.entity_ids,
        source_receipt_digests: &manifest.source_receipt_digests,
        policy_digests: &manifest.policy_digests,
        mission_ids: &manifest.mission_ids,
        verification_receipt_digests: &manifest.verification_receipt_digests,
    })
}

pub fn package_incident_snapshot(
    manifest: IncidentSnapshotManifest,
    canonical_payload: Vec<u8>,
    signature: Vec<u8>,
) -> Result<IncidentSnapshot, SdkError> {
    manifest.validate()?;
    if incident_manifest_digest(&manifest)? != manifest.manifest_digest {
        return Err(SdkError::Invalid("incident snapshot manifest digest"));
    }
    let snapshot = IncidentSnapshot {
        payload_digest: ContentDigest::of_bytes(&canonical_payload),
        manifest,
        canonical_payload,
        signature,
    };
    snapshot.validate()?;
    Ok(snapshot)
}
