use super::{AdaSupportError, AdaSupportFamily};

/// Exact event contract compiled from the Ada Support catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaSupportEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Ada Support family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaSupportRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AdaSupportFamily,
    /// Exact event contract.
    pub event_contract: AdaSupportEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AdaSupportRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AdaSupportFamily) -> Result<Self, AdaSupportError> {
        Ok(Self {
            source_id: "ada_support",
            family,
            event_contract: AdaSupportEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
