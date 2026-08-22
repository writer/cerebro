//! Typed Linode managed-issue response objects.

use serde::Deserialize;
use serde_json::{Number, Value};

#[derive(Clone, Debug, Deserialize)]
pub(super) struct IssuePageWire {
    pub(super) data: Vec<Value>,
    pub(super) page: u32,
    pub(super) pages: u32,
    pub(super) results: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct IssueWire {
    pub(super) id: Option<WireScalar>,
    pub(super) created: Option<WireScalar>,
    pub(super) finding_id: Option<WireScalar>,
    pub(super) resource_urn: Option<WireScalar>,
    pub(super) urn: Option<WireScalar>,
    pub(super) resource_id: Option<WireScalar>,
    pub(super) resource_type: Option<WireScalar>,
    pub(super) name: Option<WireScalar>,
    pub(super) display_name: Option<WireScalar>,
    pub(super) hostname: Option<WireScalar>,
    pub(super) entity: Option<Value>,
    pub(super) summary: Option<WireScalar>,
    pub(super) description: Option<WireScalar>,
    pub(super) severity: Option<WireScalar>,
    pub(super) risk: Option<WireScalar>,
    pub(super) priority: Option<WireScalar>,
    pub(super) status: Option<WireScalar>,
    pub(super) state: Option<WireScalar>,
    pub(super) event_id: Option<WireScalar>,
    pub(super) tenant_id: Option<WireScalar>,
    pub(super) observed_at: Option<WireScalar>,
    pub(super) updated_at: Option<WireScalar>,
    pub(super) last_seen_at: Option<WireScalar>,
    pub(super) created_at: Option<WireScalar>,
    pub(super) evidence_cas_digest: Option<WireScalar>,
    pub(super) evidence_cas_uri: Option<WireScalar>,
    pub(super) metadata: Option<MetadataWire>,
    pub(super) evidence_cas: Option<EvidenceCasWire>,
    #[serde(flatten)]
    pub(super) identity: IdentityDiscriminatorsWire,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct MetadataWire {
    pub(super) event_id: Option<WireScalar>,
    pub(super) resource_id: Option<WireScalar>,
    pub(super) resource_name: Option<WireScalar>,
    pub(super) resource_type: Option<WireScalar>,
    pub(super) resource_urn: Option<WireScalar>,
    pub(super) tenant_id: Option<WireScalar>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct EvidenceCasWire {
    pub(super) digest: Option<WireScalar>,
    pub(super) uri: Option<WireScalar>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct IdentityDiscriminatorsWire {
    pub(super) device_id: Option<WireScalar>,
    pub(super) serial_number: Option<WireScalar>,
    pub(super) agent_id: Option<WireScalar>,
    pub(super) device_uuid: Option<WireScalar>,
    pub(super) installed_version: Option<WireScalar>,
    pub(super) version: Option<WireScalar>,
    pub(super) device: Option<IdentityObjectWire>,
    pub(super) agent: Option<IdentityObjectWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct IdentityObjectWire {
    pub(super) id: Option<WireScalar>,
    pub(super) uuid: Option<WireScalar>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum WireScalar {
    String(String),
    Number(Number),
    Bool(bool),
}

impl WireScalar {
    pub(super) fn text(&self) -> String {
        match self {
            Self::String(value) => value.trim().to_owned(),
            Self::Number(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
        }
    }

    pub(super) fn canonical_identity(&self) -> bool {
        match self {
            Self::String(value) => value == value.trim() && !value.chars().any(char::is_control),
            Self::Number(_) => true,
            Self::Bool(_) => false,
        }
    }
}
