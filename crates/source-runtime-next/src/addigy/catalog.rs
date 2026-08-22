use super::{AddigyError, AddigyFamily};

/// Exact event contract compiled from the Addigy catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddigyEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Addigy family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddigyRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AddigyFamily,
    /// Exact event contract.
    pub event_contract: AddigyEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AddigyRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AddigyFamily) -> Result<Self, AddigyError> {
        Ok(Self {
            source_id: "addigy",
            family,
            event_contract: AddigyEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
