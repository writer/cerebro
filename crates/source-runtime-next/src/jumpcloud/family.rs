use std::str::FromStr;

use super::JumpCloudError;

/// Closed JumpCloud source-catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum JumpCloudFamily {
    /// Directory users.
    Users,
    /// User groups.
    Groups,
    /// Managed systems.
    Systems,
    /// SSO applications.
    Applications,
    /// Managed-system groups.
    SystemGroups,
    /// User-group membership edges.
    GroupMembers,
    /// Directory Insights audit events.
    AuditEvents,
}

impl JumpCloudFamily {
    /// Every supported family in catalog order.
    pub const ALL: [Self; 7] = [
        Self::Users,
        Self::Groups,
        Self::Systems,
        Self::Applications,
        Self::SystemGroups,
        Self::GroupMembers,
        Self::AuditEvents,
    ];

    /// Exact catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Groups => "groups",
            Self::Systems => "systems",
            Self::Applications => "applications",
            Self::SystemGroups => "system_groups",
            Self::GroupMembers => "group_members",
            Self::AuditEvents => "audit_events",
        }
    }

    /// Exact event kind admitted by the catalog.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Users => "jumpcloud.users",
            Self::Groups => "jumpcloud.groups",
            Self::Systems => "jumpcloud.systems",
            Self::Applications => "jumpcloud.applications",
            Self::SystemGroups => "jumpcloud.system_groups",
            Self::GroupMembers => "jumpcloud.group_members",
            Self::AuditEvents => "jumpcloud.audit_events",
        }
    }

    /// Exact event schema admitted by the catalog.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Users => "jumpcloud/users/v1",
            Self::Groups => "jumpcloud/groups/v1",
            Self::Systems => "jumpcloud/systems/v1",
            Self::Applications => "jumpcloud/applications/v1",
            Self::SystemGroups => "jumpcloud/system_groups/v1",
            Self::GroupMembers => "jumpcloud/group_members/v1",
            Self::AuditEvents => "jumpcloud/audit_events/v1",
        }
    }

    /// Provider HTTP method.
    pub const fn method(self) -> &'static str {
        if matches!(self, Self::AuditEvents) {
            "POST"
        } else {
            "GET"
        }
    }

    /// Provider-relative operation path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Users => "/systemusers",
            Self::Groups => "/v2/usergroups",
            Self::Systems => "/systems",
            Self::Applications => "/applications",
            Self::SystemGroups => "/v2/systemgroups",
            Self::GroupMembers => "/v2/usergroups/{group_id}/members",
            Self::AuditEvents => "/events",
        }
    }

    /// Required provider permission stated without credential material.
    pub const fn required_scope(self) -> &'static str {
        match self {
            Self::AuditEvents => "Directory Insights read access",
            Self::GroupMembers => "user-group membership read access",
            Self::Users | Self::Groups => "directory read access",
            Self::Systems | Self::SystemGroups => "systems read access",
            Self::Applications => "applications read access",
        }
    }

    pub(super) const fn uses_insights_origin(self) -> bool {
        matches!(self, Self::AuditEvents)
    }
}

impl FromStr for JumpCloudFamily {
    type Err = JumpCloudError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(JumpCloudError::InvalidFamily)
    }
}
