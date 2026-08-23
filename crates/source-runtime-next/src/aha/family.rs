use std::str::FromStr;

use super::AhaError;

/// Closed Aha! catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AhaFamily {
    /// Account audit records.
    AuditEvents,
    /// Product features.
    Features,
    /// Products and development teams.
    Products,
    /// Product-scoped releases.
    Releases,
    /// Account users.
    Users,
}

impl AhaFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 5] = [
        Self::AuditEvents,
        Self::Features,
        Self::Products,
        Self::Releases,
        Self::Users,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditEvents => "audit_events",
            Self::Features => "features",
            Self::Products => "products",
            Self::Releases => "releases",
            Self::Users => "users",
        }
    }

    /// Provider path relative to the account API v1 origin.
    pub fn path(self, product_id: Option<&str>) -> Result<String, AhaError> {
        Ok(match self {
            Self::AuditEvents => "/audits".to_owned(),
            Self::Features => "/features".to_owned(),
            Self::Products => "/products".to_owned(),
            Self::Releases => format!(
                "/products/{}/releases",
                product_id.ok_or(AhaError::MissingProductId)?
            ),
            Self::Users => "/users".to_owned(),
        })
    }

    /// JSON response collection field.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::AuditEvents => "audits",
            Self::Features => "features",
            Self::Products => "products",
            Self::Releases => "releases",
            Self::Users => "users",
        }
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        "id"
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::AuditEvents => "aha.audit_events",
            Self::Features => "aha.features",
            Self::Products => "aha.products",
            Self::Releases => "aha.releases",
            Self::Users => "aha.users",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::AuditEvents => "aha/audit_events/v1",
            Self::Features => "aha/features/v1",
            Self::Products => "aha/products/v1",
            Self::Releases => "aha/releases/v1",
            Self::Users => "aha/users/v1",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::AuditEvents => &["tenant_id", "source_event_id", "event_type", "actor_id"],
            Self::Features | Self::Products | Self::Releases => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ],
            Self::Users => &["tenant_id", "source_event_id", "user_id"],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        &["id"]
    }
}

impl FromStr for AhaFamily {
    type Err = AhaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AhaError::InvalidFamily)
    }
}
