use std::str::FromStr;

use super::DiscordError;

/// One Discord source-catalog family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordFamily {
    /// Guild administrative audit entries.
    AuditLog,
    /// Guild members and their nested users.
    Member,
    /// Guild roles.
    Role,
    /// Guild application-command permission grants.
    Permission,
}

impl DiscordFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditLog => "audit_log",
            Self::Member => "member",
            Self::Role => "role",
            Self::Permission => "permission",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::AuditLog => "discord.audit_log",
            Self::Member => "discord.member",
            Self::Role => "discord.role",
            Self::Permission => "discord.permission",
        }
    }
}

impl FromStr for DiscordFamily {
    type Err = DiscordError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "audit_log" => Ok(Self::AuditLog),
            "member" => Ok(Self::Member),
            "role" => Ok(Self::Role),
            "permission" => Ok(Self::Permission),
            _ => Err(DiscordError::InvalidFamily),
        }
    }
}
