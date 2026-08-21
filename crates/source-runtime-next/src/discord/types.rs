use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::DiscordFamily;

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
