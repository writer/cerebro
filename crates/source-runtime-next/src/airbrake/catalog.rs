use super::{AirbrakeError, AirbrakeFamily};

/// Exact event contract compiled from the Airbrake catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AirbrakeEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Airbrake family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AirbrakeRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AirbrakeFamily,
    /// Exact event contract.
    pub event_contract: AirbrakeEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AirbrakeRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AirbrakeFamily) -> Result<Self, AirbrakeError> {
        Ok(Self {
            source_id: "airbrake",
            family,
            event_contract: AirbrakeEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
            pull: true,
        })
    }
}
