use super::{JumpCloudError, JumpCloudFamily};

/// One exact event contract compiled from `sources/jumpcloud/catalog.yaml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JumpCloudEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one JumpCloud family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JumpCloudRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: JumpCloudFamily,
    /// Exact event contract.
    pub event_contract: JumpCloudEventContract,
    /// JumpCloud families are bounded pull operations.
    pub pull: bool,
}

impl JumpCloudRuntimeDefinition {
    /// Compile one catalog family into a closed definition.
    pub fn compile(family: JumpCloudFamily) -> Result<Self, JumpCloudError> {
        let event_contract = match family {
            JumpCloudFamily::Users => contract(
                family,
                &["tenant_id", "source_event_id", "user_id"],
                &["_id"],
            ),
            JumpCloudFamily::Groups => contract(
                family,
                &["tenant_id", "source_event_id", "group_id"],
                &["id"],
            ),
            JumpCloudFamily::Systems => contract(
                family,
                &["tenant_id", "source_event_id", "system_id"],
                &["_id"],
            ),
            JumpCloudFamily::Applications => contract(
                family,
                &["tenant_id", "source_event_id", "app_id"],
                &["_id"],
            ),
            JumpCloudFamily::SystemGroups => contract(
                family,
                &["tenant_id", "source_event_id", "group_id"],
                &["id"],
            ),
            JumpCloudFamily::GroupMembers => contract(
                family,
                &["tenant_id", "source_event_id", "group_id", "member_id"],
                &["to.id"],
            ),
            JumpCloudFamily::AuditEvents => contract(
                family,
                &["tenant_id", "source_event_id", "event_type", "actor_id"],
                &["id"],
            ),
        };
        Ok(Self {
            source_id: "jumpcloud",
            family,
            event_contract,
            pull: true,
        })
    }
}

const fn contract(
    family: JumpCloudFamily,
    required_attributes: &'static [&'static str],
    required_payload_fields: &'static [&'static str],
) -> JumpCloudEventContract {
    JumpCloudEventContract {
        kind: family.event_kind(),
        schema_ref: family.schema_ref(),
        required_attributes,
        required_payload_fields,
    }
}
