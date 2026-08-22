use std::str::FromStr;

use super::AsanaError;

/// Closed Asana source-catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AsanaFamily {
    /// Workspace user inventory.
    Users,
    /// Workspace project inventory.
    Projects,
    /// Workspace audit log events.
    AuditEvents,
}

impl AsanaFamily {
    /// Every supported family in catalog order.
    pub const ALL: [Self; 3] = [Self::Users, Self::Projects, Self::AuditEvents];

    /// Exact catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Projects => "projects",
            Self::AuditEvents => "audit_events",
        }
    }

    /// Exact event kind admitted by the catalog.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Users => "asana.users",
            Self::Projects => "asana.projects",
            Self::AuditEvents => "asana.audit_events",
        }
    }

    /// Exact event schema admitted by the catalog.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Users => "asana/users/v1",
            Self::Projects => "asana/projects/v1",
            Self::AuditEvents => "asana/audit_events/v1",
        }
    }
}

impl FromStr for AsanaFamily {
    type Err = AsanaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AsanaError::InvalidFamily)
    }
}
