//! Credential-free Discord request planning and response normalization kernel.
//!
//! The kernel models the public HTTP contract without holding a bot token or
//! performing network I/O. Checked-in test vectors are normalized examples;
//! they are not live provider captures and do not carry provider provenance.

use std::{collections::BTreeMap, str::FromStr};

use reqwest::Url;
use serde_json::Value;

mod cursor;
mod error;
mod request;
mod response;

pub use error::DiscordError;

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

/// One credential-free Discord HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRequest {
    pub(super) url: Url,
    pub(super) family: DiscordFamily,
    pub(super) cursor: Option<String>,
}

/// One normalized Discord provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Provider-owned Discord snowflake.
    pub provider_id: String,
    /// Portable scalar attributes selected by the Go source contract.
    pub fields: BTreeMap<String, String>,
    /// Original provider record without credential material.
    pub payload: Value,
}

/// One bounded Discord provider page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordPage {
    /// Normalized records in provider order.
    pub records: Vec<DiscordRecord>,
    /// Highest audit-entry or member-user snowflake on a full page.
    pub next_cursor: Option<String>,
}

/// Provider-specific Discord request and response kernel.
#[derive(Clone, Debug)]
pub struct DiscordKernel {
    pub(super) base_url: Url,
    pub(super) guild_id: String,
    pub(super) application_id: Option<String>,
    pub(super) family: DiscordFamily,
    pub(super) page_size: Option<usize>,
}

#[cfg(test)]
mod tests;
