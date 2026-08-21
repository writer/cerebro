//! Typed Twilio accounts provider object.

use serde::Deserialize;

use super::super::wire::{EvidenceCasWire, IdentityDiscriminatorsWire, MetadataWire, WireScalar};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct AccountWire {
    #[serde(flatten)]
    pub(super) identity: IdentityDiscriminatorsWire,
    pub(super) id: Option<WireScalar>,
    pub(super) user_id: Option<WireScalar>,
    pub(super) uid: Option<WireScalar>,
    pub(super) email: Option<WireScalar>,
    pub(super) primary_email: Option<WireScalar>,
    pub(super) login: Option<WireScalar>,
    pub(super) username: Option<WireScalar>,
    pub(super) name: Option<WireScalar>,
    pub(super) display_name: Option<WireScalar>,
    pub(super) hostname: Option<WireScalar>,
    pub(super) created_at: Option<WireScalar>,
    pub(super) created: Option<WireScalar>,
    pub(super) updated_at: Option<WireScalar>,
    #[serde(rename = "updatedAt")]
    pub(super) updated_at_camel: Option<WireScalar>,
    pub(super) last_seen_at: Option<WireScalar>,
    #[serde(rename = "lastSeenAt")]
    pub(super) last_seen_at_camel: Option<WireScalar>,
    pub(super) last_check_in: Option<WireScalar>,
    #[serde(rename = "lastCheckIn")]
    pub(super) last_check_in_camel: Option<WireScalar>,
    #[serde(rename = "createdAt")]
    pub(super) created_at_camel: Option<WireScalar>,
    pub(super) timestamp: Option<WireScalar>,
    pub(super) department: Option<WireScalar>,
    pub(super) domain: Option<WireScalar>,
    pub(super) tenant_domain: Option<WireScalar>,
    pub(super) organization_domain: Option<WireScalar>,
    pub(super) job_title: Option<WireScalar>,
    pub(super) title: Option<WireScalar>,
    pub(super) last_login_at: Option<WireScalar>,
    pub(super) last_login: Option<WireScalar>,
    pub(super) manager: Option<WireScalar>,
    pub(super) observed_at: Option<WireScalar>,
    pub(super) resource_id: Option<WireScalar>,
    #[serde(rename = "type")]
    pub(super) kind: Option<WireScalar>,
    pub(super) resource_type: Option<WireScalar>,
    pub(super) resource_urn: Option<WireScalar>,
    pub(super) urn: Option<WireScalar>,
    pub(super) event_id: Option<WireScalar>,
    pub(super) status: Option<WireScalar>,
    pub(super) state: Option<WireScalar>,
    pub(super) lifecycle_state: Option<WireScalar>,
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
    pub(super) profile: Option<ProfileWire>,
    pub(super) metadata: Option<MetadataWire>,
    pub(super) evidence_cas: Option<EvidenceCasWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ProfileWire {
    pub(super) created_at: Option<WireScalar>,
    pub(super) department: Option<WireScalar>,
    pub(super) display_name: Option<WireScalar>,
    pub(super) name: Option<WireScalar>,
    pub(super) email: Option<WireScalar>,
    pub(super) title: Option<WireScalar>,
    pub(super) login: Option<WireScalar>,
    pub(super) manager: Option<WireScalar>,
}
