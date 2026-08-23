use super::{AkeneoError, AkeneoFamily};

/// Exact event contract compiled from the Akeneo catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AkeneoEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Akeneo family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AkeneoRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AkeneoFamily,
    /// Exact event contract.
    pub event_contract: AkeneoEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AkeneoRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AkeneoFamily) -> Result<Self, AkeneoError> {
        Ok(Self {
            source_id: "akeneo",
            family,
            event_contract: AkeneoEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
