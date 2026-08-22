use super::{AbnormalSecurityError, AbnormalSecurityFamily};

/// Exact event contract compiled from the provider catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbnormalSecurityEventContract {
    /// Exact event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one provider family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbnormalSecurityRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AbnormalSecurityFamily,
    /// Exact event contract.
    pub event_contract: AbnormalSecurityEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AbnormalSecurityRuntimeDefinition {
    /// Compile one declared family into a closed definition.
    pub fn compile(family: AbnormalSecurityFamily) -> Result<Self, AbnormalSecurityError> {
        let required_attributes = match family {
            AbnormalSecurityFamily::Resources => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ][..],
            AbnormalSecurityFamily::Threats | AbnormalSecurityFamily::Cases => &[
                "tenant_id",
                "source_event_id",
                "finding_id",
                "severity",
                "status",
            ][..],
            AbnormalSecurityFamily::PostureCatalog => {
                &["tenant_id", "source_event_id", "policy_id", "policy_name"][..]
            }
            AbnormalSecurityFamily::AuditEvents => {
                &["tenant_id", "source_event_id", "event_type", "actor_id"][..]
            }
        };
        let required_payload_fields = match family {
            AbnormalSecurityFamily::Resources => &["resourceId"][..],
            AbnormalSecurityFamily::Threats => &["threatId"][..],
            AbnormalSecurityFamily::Cases => &["caseId"][..],
            AbnormalSecurityFamily::PostureCatalog => &["id"][..],
            AbnormalSecurityFamily::AuditEvents => &["timestamp"][..],
        };
        Ok(Self {
            source_id: "abnormal_security",
            family,
            event_contract: AbnormalSecurityEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes,
                required_payload_fields,
            },
            pull: true,
        })
    }
}
