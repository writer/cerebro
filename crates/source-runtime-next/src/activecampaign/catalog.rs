use super::{ActiveCampaignError, ActiveCampaignFamily};

/// Exact event contract compiled from the ActiveCampaign catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCampaignEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one ActiveCampaign family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCampaignRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: ActiveCampaignFamily,
    /// Exact event contract.
    pub event_contract: ActiveCampaignEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl ActiveCampaignRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: ActiveCampaignFamily) -> Result<Self, ActiveCampaignError> {
        let required_attributes = if family == ActiveCampaignFamily::Users {
            &["tenant_id", "source_event_id", "user_id"][..]
        } else {
            &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ][..]
        };
        Ok(Self {
            source_id: "activecampaign",
            family,
            event_contract: ActiveCampaignEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes,
                required_payload_fields: &["id"],
            },
            pull: true,
        })
    }
}
