use std::str::FromStr;

use super::AbnormalSecurityError;

/// Closed Abnormal Security catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AbnormalSecurityFamily {
    /// Protected resources.
    Resources,
    /// Portal audit events.
    AuditEvents,
    /// Security cases.
    Cases,
    /// SaaS posture catalog.
    PostureCatalog,
    /// Email threats.
    Threats,
}

impl AbnormalSecurityFamily {
    /// Every provider-declared family.
    pub const ALL: [Self; 5] = [
        Self::Resources,
        Self::AuditEvents,
        Self::Cases,
        Self::PostureCatalog,
        Self::Threats,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::AuditEvents => "audit_events",
            Self::Cases => "cases",
            Self::PostureCatalog => "posture_catalog",
            Self::Threats => "threats",
        }
    }

    /// Exact provider path relative to `/v1`.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Resources => "/resources",
            Self::AuditEvents => "/auditlogs",
            Self::Cases => "/cases",
            Self::PostureCatalog => "/spm-v2/posture-catalog",
            Self::Threats => "/threats",
        }
    }

    /// Provider response-array key.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::AuditEvents => "auditLogs",
            Self::Cases => "cases",
            Self::PostureCatalog => "data",
            Self::Threats => "threats",
        }
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::Resources => "resourceId",
            Self::AuditEvents => "timestamp",
            Self::Cases => "caseId",
            Self::PostureCatalog => "id",
            Self::Threats => "threatId",
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Resources => "abnormal_security.resources",
            Self::AuditEvents => "abnormal_security.audit_events",
            Self::Cases => "abnormal_security.cases",
            Self::PostureCatalog => "abnormal_security.posture_catalog",
            Self::Threats => "abnormal_security.threats",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Resources => "abnormal_security/resources/v1",
            Self::AuditEvents => "abnormal_security/audit_events/v1",
            Self::Cases => "abnormal_security/cases/v1",
            Self::PostureCatalog => "abnormal_security/posture_catalog/v1",
            Self::Threats => "abnormal_security/threats/v1",
        }
    }
}

impl FromStr for AbnormalSecurityFamily {
    type Err = AbnormalSecurityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AbnormalSecurityError::InvalidFamily)
    }
}
