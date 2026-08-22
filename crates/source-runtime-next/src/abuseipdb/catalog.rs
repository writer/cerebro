use super::{AbuseIpDbError, AbuseIpDbFamily};

/// One exact event contract compiled from the AbuseIPDB catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbuseIpDbEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one AbuseIPDB family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbuseIpDbRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AbuseIpDbFamily,
    /// Exact event contract.
    pub event_contract: AbuseIpDbEventContract,
    /// Both families are bounded pull operations.
    pub pull: bool,
}

impl AbuseIpDbRuntimeDefinition {
    /// Compile one declared catalog family into a closed definition.
    pub fn compile(family: AbuseIpDbFamily) -> Result<Self, AbuseIpDbError> {
        let event_contract = match family {
            AbuseIpDbFamily::Reports => AbuseIpDbEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: &[
                    "tenant_id",
                    "source_event_id",
                    "finding_id",
                    "resource_urn",
                    "severity",
                    "status",
                ],
                required_payload_fields: &["reportedAt", "reporterId"],
            },
            AbuseIpDbFamily::IpAddresses => AbuseIpDbEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes: &[
                    "tenant_id",
                    "source_event_id",
                    "resource_urn",
                    "resource_type",
                    "resource_id",
                ],
                required_payload_fields: &["ipAddress"],
            },
        };
        Ok(Self {
            source_id: "abuseipdb",
            family,
            event_contract,
            pull: true,
        })
    }
}
