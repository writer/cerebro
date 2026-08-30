//! Deterministic digesting and packaging for incident snapshots.
//!
//! The engine binds manifest fields and exact payload bytes into digests. It
//! does not canonicalize payload content, create or verify signatures, enforce
//! byte-size limits, persist packages, or authorize their disclosure.

use cerebro_platform_sdk::{
    ContentDigest, GraphRevision, IncidentSnapshot, IncidentSnapshotId, IncidentSnapshotManifest,
    OpaqueId, SdkError, TenantId,
};
use serde::Serialize;

use crate::canonical;

/// Manifest fields included in the content digest, excluding the digest itself.
///
/// Slices preserve caller order, so reordering or retaining duplicate references
/// changes the digest even when the referenced value set is otherwise equal.
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

/// Computes the canonical digest of all semantic manifest fields.
///
/// This function deliberately excludes [`IncidentSnapshotManifest::manifest_digest`]
/// to avoid a recursive content address. It does not call manifest validation,
/// so callers accepting untrusted material must validate shape separately.
///
/// # Errors
///
/// Returns [`SdkError::Backend`] if canonical serialization fails.
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

/// Verifies a manifest digest and packages exact payload and signature bytes.
///
/// The manifest is shape-validated before its digest is recomputed. The payload
/// digest is always computed by this function, then the assembled snapshot is
/// checked for non-empty payload and signature. The signature is accepted as
/// opaque bytes: no algorithm, signer, or cryptographic verification occurs.
///
/// Because the manifest contains neither payload digest nor signature, callers
/// that require one signed envelope must define and verify that binding outside
/// this packaging function.
///
/// # Errors
///
/// Returns manifest validation errors, [`SdkError::Invalid`] when the supplied
/// manifest digest does not match its semantic fields, [`SdkError::Empty`] for
/// an empty payload or signature, or [`SdkError::Backend`] if canonical manifest
/// serialization fails.
pub fn package_incident_snapshot(
    manifest: IncidentSnapshotManifest,
    canonical_payload: Vec<u8>,
    signature: Vec<u8>,
) -> Result<IncidentSnapshot, SdkError> {
    manifest.validate()?;
    if incident_manifest_digest(&manifest)? != manifest.manifest_digest {
        return Err(SdkError::Invalid("incident snapshot manifest digest"));
    }

    // Hash the exact bytes supplied by the caller; no serialization or content
    // normalization is applied at this boundary.
    let snapshot = IncidentSnapshot {
        payload_digest: ContentDigest::of_bytes(&canonical_payload),
        manifest,
        canonical_payload,
        signature,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{EntityId, IncidentSnapshotId};

    use super::*;

    fn manifest_with_digest(digest: ContentDigest) -> IncidentSnapshotManifest {
        IncidentSnapshotManifest {
            snapshot_id: IncidentSnapshotId::parse("snapshot:test").unwrap(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            graph_revision: GraphRevision::new(1).unwrap(),
            created_at_unix_millis: 10,
            entity_ids: vec![EntityId::parse("repository:one").unwrap()],
            source_receipt_digests: vec![ContentDigest::of_bytes("source")],
            policy_digests: Vec::new(),
            mission_ids: Vec::new(),
            verification_receipt_digests: Vec::new(),
            manifest_digest: digest,
        }
    }

    #[test]
    fn packaging_rejects_a_manifest_digest_not_bound_to_its_contents() {
        let error = package_incident_snapshot(
            manifest_with_digest(ContentDigest::of_bytes("wrong")),
            b"payload".to_vec(),
            vec![1],
        )
        .unwrap_err();

        assert_eq!(
            error,
            SdkError::Invalid("incident snapshot manifest digest")
        );
    }
}
