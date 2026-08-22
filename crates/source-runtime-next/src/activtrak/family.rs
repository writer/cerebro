use std::str::FromStr;

use super::ActivTrakError;

/// Closed ActivTrak catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActivTrakFamily {
    /// Activity-log audit events.
    ActivityLog,
    /// Administration clients.
    Clients,
    /// Administration consumers.
    Consumers,
    /// SCIM groups.
    Groups,
    /// SCIM users.
    Users,
}

impl ActivTrakFamily {
    /// Every provider-declared family.
    pub const ALL: [Self; 5] = [
        Self::ActivityLog,
        Self::Clients,
        Self::Consumers,
        Self::Groups,
        Self::Users,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivityLog => "activity_log",
            Self::Clients => "clients",
            Self::Consumers => "consumers",
            Self::Groups => "groups",
            Self::Users => "users",
        }
    }

    /// Exact provider path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::ActivityLog => "/reports/v2/activitylog",
            Self::Clients => "/admin/v1/clients",
            Self::Consumers => "/admin/v1/consumers",
            Self::Groups => "/scim/v1/groups",
            Self::Users => "/scim/v1/users",
        }
    }

    /// Provider response-array key.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::ActivityLog => "activity",
            Self::Clients => "clients",
            Self::Consumers => "consumers",
            Self::Groups | Self::Users => "resources",
        }
    }

    /// Maximum provider records admitted per page.
    pub const fn page_size(self) -> usize {
        match self {
            Self::ActivityLog => 150,
            _ => 100,
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::ActivityLog => "activtrak.activity_log",
            Self::Clients => "activtrak.clients",
            Self::Consumers => "activtrak.consumers",
            Self::Groups => "activtrak.groups",
            Self::Users => "activtrak.users",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::ActivityLog => "activtrak/activity_log/v1",
            Self::Clients => "activtrak/clients/v1",
            Self::Consumers => "activtrak/consumers/v1",
            Self::Groups => "activtrak/groups/v1",
            Self::Users => "activtrak/users/v1",
        }
    }

    /// Exact stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::ActivityLog => "logId",
            _ => "id",
        }
    }
}

impl FromStr for ActivTrakFamily {
    type Err = ActivTrakError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(ActivTrakError::InvalidFamily)
    }
}
