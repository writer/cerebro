use super::{AcunetixError, AcunetixFamily};

/// Exact event contract compiled from the Acunetix catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcunetixEventContract {
    /// Exact event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one Acunetix family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcunetixRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: AcunetixFamily,
    /// Exact event contract.
    pub event_contract: AcunetixEventContract,
    /// Every family is a bounded pull operation.
    pub pull: bool,
}

impl AcunetixRuntimeDefinition {
    /// Compile one declared family into a closed definition.
    pub fn compile(family: AcunetixFamily) -> Result<Self, AcunetixError> {
        let required_attributes = match family {
            AcunetixFamily::Reports | AcunetixFamily::Targets => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ][..],
            AcunetixFamily::ScanningProfiles => {
                &["tenant_id", "source_event_id", "policy_id", "policy_name"][..]
            }
            AcunetixFamily::Scans => &[
                "tenant_id",
                "source_event_id",
                "finding_id",
                "resource_urn",
                "status",
            ][..],
            AcunetixFamily::Vulnerabilities => &[
                "tenant_id",
                "source_event_id",
                "finding_id",
                "resource_urn",
                "severity",
                "status",
            ][..],
        };
        let required_payload_fields = match family {
            AcunetixFamily::Reports => &["report_id"][..],
            AcunetixFamily::ScanningProfiles => &["profile_id"][..],
            AcunetixFamily::Scans => &["scan_id"][..],
            AcunetixFamily::Targets => &["target_id"][..],
            AcunetixFamily::Vulnerabilities => &["vuln_id"][..],
        };
        Ok(Self {
            source_id: "acunetix",
            family,
            event_contract: AcunetixEventContract {
                kind: family.event_kind(),
                schema_ref: family.schema_ref(),
                required_attributes,
                required_payload_fields,
            },
            pull: true,
        })
    }
}
