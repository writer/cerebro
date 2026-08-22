use std::str::FromStr;

use super::AddigyError;

/// Closed Addigy catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AddigyFamily {
    /// System audit events.
    AuditEvents,
    /// Managed Apple devices.
    Devices,
    /// End-user groups.
    Groups,
    /// Device policies.
    Policies,
    /// Organization users.
    Users,
}

impl AddigyFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 5] = [
        Self::AuditEvents,
        Self::Devices,
        Self::Groups,
        Self::Policies,
        Self::Users,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditEvents => "audit_events",
            Self::Devices => "devices",
            Self::Groups => "groups",
            Self::Policies => "policies",
            Self::Users => "users",
        }
    }

    /// Provider path relative to the fixed API v2 origin.
    pub fn path(self, organization_id: Option<&str>) -> Result<String, AddigyError> {
        match self {
            Self::AuditEvents => Ok("/system-events/search".to_owned()),
            Self::Devices => Ok("/devices".to_owned()),
            Self::Policies => Ok("/oa/policies/query".to_owned()),
            Self::Groups => Ok(format!(
                "/o/{}/end-users/groups/query",
                organization_id.ok_or(AddigyError::MissingOrganizationId)?
            )),
            Self::Users => Ok(format!(
                "/o/{}/users/query",
                organization_id.ok_or(AddigyError::MissingOrganizationId)?
            )),
        }
    }

    /// Whether the provider response is a root array.
    pub const fn root_array(self) -> bool {
        matches!(self, Self::Policies)
    }

    /// Whether this family has page pagination.
    pub const fn paginated(self) -> bool {
        !matches!(self, Self::Policies)
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::AuditEvents => "event_id",
            Self::Devices => "agentid",
            Self::Groups => "id",
            Self::Policies => "policyId",
            Self::Users => "email",
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::AuditEvents => "addigy.audit_events",
            Self::Devices => "addigy.devices",
            Self::Groups => "addigy.groups",
            Self::Policies => "addigy.policies",
            Self::Users => "addigy.users",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::AuditEvents => "addigy/audit_events/v1",
            Self::Devices => "addigy/devices/v1",
            Self::Groups => "addigy/groups/v1",
            Self::Policies => "addigy/policies/v1",
            Self::Users => "addigy/users/v1",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::AuditEvents => &["tenant_id", "source_event_id", "event_type"],
            Self::Devices => &[
                "tenant_id",
                "source_event_id",
                "resource_id",
                "resource_type",
            ],
            Self::Groups => &["tenant_id", "source_event_id", "group_id", "group_name"],
            Self::Policies => &["tenant_id", "source_event_id", "policy_id", "policy_name"],
            Self::Users => &["tenant_id", "source_event_id", "user_id"],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::AuditEvents => &["event_id"],
            Self::Devices => &["agentid"],
            Self::Groups => &["id"],
            Self::Policies => &["policyId"],
            Self::Users => &["email"],
        }
    }
}

impl FromStr for AddigyFamily {
    type Err = AddigyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AddigyError::InvalidFamily)
    }
}
