use std::str::FromStr;

use super::SlackError;

/// Closed Slack source-family catalog.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SlackFamily {
    /// Slack workspace/team inventory.
    Team,
    /// Slack user inventory.
    User,
    /// Public and private channel inventory.
    Channel,
    /// Slack user-group inventory.
    UserGroup,
    /// Team access-log rows.
    AccessLog,
    /// User-to-channel membership.
    ChannelMember,
    /// User-to-user-group membership.
    UserGroupMember,
    /// Enterprise Grid audit-log entries.
    AuditLog,
}

impl SlackFamily {
    /// Stable source-family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Team => "team",
            Self::User => "user",
            Self::Channel => "channel",
            Self::UserGroup => "user_group",
            Self::AccessLog => "access_log",
            Self::ChannelMember => "channel_member",
            Self::UserGroupMember => "user_group_member",
            Self::AuditLog => "audit_log",
        }
    }

    /// Exact event kind admitted for this family.
    pub fn event_kind(self) -> String {
        format!("slack.{}", self.as_str())
    }

    /// Exact event schema admitted for this family.
    pub fn schema_ref(self) -> String {
        format!("slack/{}/v1", self.as_str())
    }

    /// Provider method for this family.
    pub const fn method(self) -> &'static str {
        if matches!(self, Self::Team) {
            "POST"
        } else {
            "GET"
        }
    }

    /// Provider path for this family.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Team => "/auth.teams.list",
            Self::User => "/users.list",
            Self::Channel => "/conversations.list",
            Self::UserGroup => "/usergroups.list",
            Self::AccessLog => "/team.accessLogs",
            Self::ChannelMember => "/conversations.members",
            Self::UserGroupMember => "/usergroups.users.list",
            Self::AuditLog => "/logs",
        }
    }

    /// Required Slack provider scopes.
    pub const fn required_scopes(self) -> &'static [&'static str] {
        match self {
            Self::Team | Self::AccessLog => &["team:read"],
            Self::User => &["users:read", "users:read.email"],
            Self::Channel | Self::ChannelMember => &["channels:read", "groups:read"],
            Self::UserGroup | Self::UserGroupMember => &["usergroups:read"],
            Self::AuditLog => &["auditlogs:read"],
        }
    }

    pub(super) const fn uses_audit_origin(self) -> bool {
        matches!(self, Self::AuditLog)
    }

    pub(super) const fn supports_cursor(self) -> bool {
        !matches!(self, Self::UserGroup)
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Team => &["team_id"],
            Self::User => &["user_id"],
            Self::Channel => &["channel_id"],
            Self::UserGroup => &["group_id"],
            Self::AccessLog => &["actor_id", "event_type"],
            Self::ChannelMember => &["channel_id", "user_id"],
            Self::UserGroupMember => &["usergroup_id", "user_id"],
            Self::AuditLog => &["actor_id", "event_type"],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::Team | Self::User | Self::Channel | Self::UserGroup | Self::AuditLog => &["id"],
            Self::AccessLog => &["user_id"],
            Self::ChannelMember => &["channel_id", "user_id"],
            Self::UserGroupMember => &["usergroup_id", "user_id"],
        }
    }
}

impl FromStr for SlackFamily {
    type Err = SlackError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "team" => Ok(Self::Team),
            "user" => Ok(Self::User),
            "channel" => Ok(Self::Channel),
            "user_group" => Ok(Self::UserGroup),
            "access_log" => Ok(Self::AccessLog),
            "channel_member" => Ok(Self::ChannelMember),
            "user_group_member" => Ok(Self::UserGroupMember),
            "audit_log" => Ok(Self::AuditLog),
            _ => Err(SlackError::InvalidFamily),
        }
    }
}
