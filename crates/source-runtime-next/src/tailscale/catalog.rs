use super::{TailscaleError, TailscaleFamily};

/// Exact event contract compiled for one Tailscale family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleEventContract {
    /// Event kind.
    pub kind: &'static str,
    /// Schema reference.
    pub schema_ref: &'static str,
    /// Attributes required before admission.
    pub required_attributes: &'static [&'static str],
    /// Payload fields required before admission.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition compiled from the provider source catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Provider family.
    pub family: TailscaleFamily,
    /// HTTP method.
    pub method: &'static str,
    /// Exact provider path.
    pub path: &'static str,
    /// Credential model owned by the trusted host.
    pub auth_model: &'static str,
    /// Exact admitted event contract.
    pub contract: TailscaleEventContract,
}

impl TailscaleRuntimeDefinition {
    /// Compile one family into a validated closed runtime definition.
    pub fn compile(family: TailscaleFamily) -> Result<Self, TailscaleError> {
        let definition = Self {
            source_id: "tailscale",
            family,
            method: "GET",
            path: family.path(),
            auth_model: "bearer_token",
            contract: TailscaleEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: family.required_attributes(),
                required_payload_fields: family.required_payload_fields(),
            },
        };
        definition.validate()?;
        Ok(definition)
    }

    fn validate(&self) -> Result<(), TailscaleError> {
        if self.source_id != "tailscale"
            || self.method != "GET"
            || self.auth_model != "bearer_token"
            || self.path != self.family.path()
            || self.contract.kind != self.family.event_kind()
            || self.contract.schema_ref != self.family.schema_ref()
            || self.contract.required_attributes.is_empty()
            || self.contract.required_payload_fields.is_empty()
        {
            return Err(TailscaleError::InvalidCatalogContract);
        }
        Ok(())
    }
}
