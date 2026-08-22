use super::{AdpError, AdpFamily};

/// Exact event contract compiled from the ADP catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdpEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one ADP family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdpRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AdpFamily,
    /// Exact event contract.
    pub event_contract: AdpEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AdpRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AdpFamily) -> Result<Self, AdpError> {
        Ok(Self {
            source_id: "adp_workforce_now",
            family,
            event_contract: AdpEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
