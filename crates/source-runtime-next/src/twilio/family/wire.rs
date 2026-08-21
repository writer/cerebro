//! Shared typed provider scalar and nested evidence objects.

use serde::Deserialize;
use serde_json::Number;

/// Provider scalar accepted by the Go JSON adapter.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(in crate::twilio) enum WireScalar {
    String(String),
    Number(Number),
    Bool(bool),
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(in crate::twilio) struct IdentityDiscriminatorsWire {
    pub(in crate::twilio) device_id: Option<WireScalar>,
    pub(in crate::twilio) serial_number: Option<WireScalar>,
    pub(in crate::twilio) agent_id: Option<WireScalar>,
    pub(in crate::twilio) device_uuid: Option<WireScalar>,
    pub(in crate::twilio) installed_version: Option<WireScalar>,
    pub(in crate::twilio) version: Option<WireScalar>,
    pub(in crate::twilio) device: Option<IdentityObjectWire>,
    pub(in crate::twilio) agent: Option<IdentityObjectWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(in crate::twilio) struct IdentityObjectWire {
    pub(in crate::twilio) id: Option<WireScalar>,
    pub(in crate::twilio) uuid: Option<WireScalar>,
}

impl IdentityDiscriminatorsWire {
    pub(in crate::twilio) fn contains_control(&self) -> bool {
        let device = self.device.as_ref();
        let agent = self.agent.as_ref();
        [
            self.device_id.as_ref(),
            device.and_then(|value| value.id.as_ref()),
            self.serial_number.as_ref(),
            self.agent_id.as_ref(),
            agent.and_then(|value| value.uuid.as_ref()),
            self.device_uuid.as_ref(),
            self.installed_version.as_ref(),
            self.version.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(WireScalar::contains_control)
    }
}

impl WireScalar {
    pub(in crate::twilio) fn text(&self) -> String {
        match self {
            Self::String(value) => value.trim().to_owned(),
            Self::Number(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
        }
    }

    pub(in crate::twilio) fn contains_control(&self) -> bool {
        matches!(self, Self::String(value) if value.chars().any(char::is_control))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct EvidenceCasWire {
    pub(super) commit_id: Option<WireScalar>,
    pub(super) digest: Option<WireScalar>,
    pub(super) merkle_root: Option<WireScalar>,
    pub(super) ref_type: Option<WireScalar>,
    pub(super) uri: Option<WireScalar>,
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
