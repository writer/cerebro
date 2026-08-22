//! Typed Twilio audit-events provider object.

use serde::Deserialize;

use super::super::wire::{EvidenceCasWire, IdentityDiscriminatorsWire, MetadataWire, WireScalar};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct AuditEventWire {
    #[serde(flatten)]
    pub(super) identity: IdentityDiscriminatorsWire,
    pub(super) id: Option<WireScalar>,
    pub(super) event_id: Option<WireScalar>,
    pub(super) uuid: Option<WireScalar>,
    pub(super) request_id: Option<WireScalar>,
    pub(super) actor_email: Option<WireScalar>,
    pub(super) email: Option<WireScalar>,
    pub(super) user_id: Option<WireScalar>,
    pub(super) actor_id: Option<WireScalar>,
    #[serde(rename = "actorId")]
    pub(super) actor_id_camel: Option<WireScalar>,
    pub(super) actor_name: Option<WireScalar>,
    pub(super) event_type: Option<WireScalar>,
    pub(super) event_name: Option<WireScalar>,
    pub(super) action: Option<WireScalar>,
    #[serde(rename = "type")]
    pub(super) kind: Option<WireScalar>,
    pub(super) observed_at: Option<WireScalar>,
    pub(super) updated_at: Option<WireScalar>,
    #[serde(rename = "updatedAt")]
    pub(super) updated_at_camel: Option<WireScalar>,
    pub(super) last_seen_at: Option<WireScalar>,
    #[serde(rename = "lastSeenAt")]
    pub(super) last_seen_at_camel: Option<WireScalar>,
    pub(super) last_check_in: Option<WireScalar>,
    #[serde(rename = "lastCheckIn")]
    pub(super) last_check_in_camel: Option<WireScalar>,
    pub(super) created_at: Option<WireScalar>,
    #[serde(rename = "createdAt")]
    pub(super) created_at_camel: Option<WireScalar>,
    pub(super) timestamp: Option<WireScalar>,
    pub(super) resource_email: Option<WireScalar>,
    pub(super) target_email: Option<WireScalar>,
    pub(super) target_id: Option<WireScalar>,
    pub(super) object_id: Option<WireScalar>,
    pub(super) resource_id: Option<WireScalar>,
    pub(super) target_name: Option<WireScalar>,
    pub(super) object_name: Option<WireScalar>,
    pub(super) resource_name: Option<WireScalar>,
    pub(super) target_type: Option<WireScalar>,
    pub(super) object_type: Option<WireScalar>,
    pub(super) resource_type: Option<WireScalar>,
    pub(super) resource_urn: Option<WireScalar>,
    pub(super) urn: Option<WireScalar>,
    pub(super) evidence_cas_commit_id: Option<WireScalar>,
    pub(super) commit_id: Option<WireScalar>,
    pub(super) evidence_cas_digest: Option<WireScalar>,
    pub(super) digest: Option<WireScalar>,
    pub(super) evidence_cas_merkle_root: Option<WireScalar>,
    pub(super) merkle_root: Option<WireScalar>,
    pub(super) evidence_cas_ref_type: Option<WireScalar>,
    pub(super) ref_type: Option<WireScalar>,
    pub(super) evidence_cas_uri: Option<WireScalar>,
    pub(super) uri: Option<WireScalar>,
    pub(super) actor: Option<ActorWire>,
    pub(super) user: Option<ActorWire>,
    pub(super) target: Option<ResourceWire>,
    pub(super) resource: Option<ResourceWire>,
    pub(super) metadata: Option<MetadataWire>,
    pub(super) evidence_cas: Option<EvidenceCasWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ActorWire {
    pub(super) id: Option<WireScalar>,
    pub(super) email: Option<WireScalar>,
    pub(super) name: Option<WireScalar>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ResourceWire {
    pub(super) id: Option<WireScalar>,
    pub(super) email: Option<WireScalar>,
    pub(super) name: Option<WireScalar>,
    #[serde(rename = "type")]
    pub(super) kind: Option<WireScalar>,
}
