use super::{AsanaError, AsanaFamily};

/// One exact event contract compiled from `sources/asana/catalog.yaml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsanaEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Asana family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsanaRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AsanaFamily,
    /// Exact event contract.
    pub event_contract: AsanaEventContract,
    /// Asana families are bounded pull operations.
    pub pull: bool,
}

impl AsanaRuntimeDefinition {
    /// Compile one catalog family into a closed definition.
    pub fn compile(family: AsanaFamily) -> Result<Self, AsanaError> {
        let event_contract = match family {
            AsanaFamily::Users => AsanaEventContract {
                kind: "asana.users",
                schema_ref: "asana/users/v1",
                required_attributes: &["tenant_id", "source_event_id", "user_id"],
                required_payload_fields: &["gid"],
            },
            AsanaFamily::Projects => AsanaEventContract {
                kind: "asana.projects",
                schema_ref: "asana/projects/v1",
                required_attributes: &[
                    "tenant_id",
                    "source_event_id",
                    "resource_urn",
                    "resource_type",
                    "resource_id",
                ],
                required_payload_fields: &["gid"],
            },
            AsanaFamily::AuditEvents => AsanaEventContract {
                kind: "asana.audit_events",
                schema_ref: "asana/audit_events/v1",
                required_attributes: &["tenant_id", "source_event_id", "event_type", "actor_id"],
                required_payload_fields: &["gid"],
            },
        };
        Ok(Self {
            source_id: "asana",
            family,
            event_contract,
            pull: true,
        })
    }
}
