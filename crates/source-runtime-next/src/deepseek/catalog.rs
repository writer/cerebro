use super::{DeepSeekError, DeepSeekFamily};

/// One exact event contract compiled from the checked-in DeepSeek catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeepSeekEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one DeepSeek family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeepSeekRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: DeepSeekFamily,
    /// Exact event contract.
    pub event_contract: DeepSeekEventContract,
    /// DeepSeek families are bounded pull operations.
    pub pull: bool,
}

impl DeepSeekRuntimeDefinition {
    /// Compile one catalog family into a closed definition.
    pub fn compile(family: DeepSeekFamily) -> Result<Self, DeepSeekError> {
        let required_attributes = &[
            "tenant_id",
            "source_event_id",
            "resource_urn",
            "resource_type",
            "resource_id",
        ];
        let required_payload_fields: &'static [&'static str] = match family {
            DeepSeekFamily::ModelCatalog => &["id"],
            DeepSeekFamily::AccountBalances => &["currency"],
        };
        Ok(Self {
            source_id: "deepseek",
            family,
            event_contract: DeepSeekEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes,
                required_payload_fields,
            },
            pull: true,
        })
    }
}
