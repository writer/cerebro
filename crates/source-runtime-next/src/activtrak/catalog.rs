use super::{ActivTrakError, ActivTrakFamily};

/// Exact event contract compiled from the ActivTrak catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivTrakEventContract {
    /// Exact event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one ActivTrak family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivTrakRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: ActivTrakFamily,
    /// Exact event contract.
    pub event_contract: ActivTrakEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl ActivTrakRuntimeDefinition {
    /// Compile one declared family into a closed definition.
    pub fn compile(family: ActivTrakFamily) -> Result<Self, ActivTrakError> {
        let required_attributes = match family {
            ActivTrakFamily::ActivityLog => {
                &["tenant_id", "source_event_id", "event_type", "actor_id"][..]
            }
            ActivTrakFamily::Consumers | ActivTrakFamily::Users => {
                &["tenant_id", "source_event_id", "user_id"][..]
            }
            ActivTrakFamily::Clients | ActivTrakFamily::Groups => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ][..],
        };
        let required_payload_fields = match family {
            ActivTrakFamily::ActivityLog => &["logId"][..],
            _ => &["id"][..],
        };
        Ok(Self {
            source_id: "activtrak",
            family,
            event_contract: ActivTrakEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes,
                required_payload_fields,
            },
            pull: true,
        })
    }
}
