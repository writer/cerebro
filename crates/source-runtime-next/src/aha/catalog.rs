use super::{AhaError, AhaFamily};

/// Exact event contract compiled from the Aha catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhaEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Aha family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhaRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AhaFamily,
    /// Exact event contract.
    pub event_contract: AhaEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AhaRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AhaFamily) -> Result<Self, AhaError> {
        Ok(Self {
            source_id: "aha",
            family,
            event_contract: AhaEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
