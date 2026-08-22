use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::DiscordFamily;

/// One credential-free Discord HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRequest {
    pub(super) url: Url,
    pub(super) operation_path: String,
    pub(super) tenant_id: String,
    pub(super) family: DiscordFamily,
    pub(super) cursor: Option<String>,
}

/// One normalized Discord provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRecord {
    /// Tenant supplied by the authenticated runtime context, never the provider payload.
    pub tenant_id: String,
    /// Go-compatible tenant- and request-scope-bound event identity.
    pub event_id: String,
    /// Canonical source identifier.
    pub source_id: String,
    /// Go-compatible event schema reference.
    pub schema_ref: String,
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Provider-owned Discord snowflake.
    pub provider_id: String,
    /// Provider occurrence time derived from the Discord snowflake epoch.
    pub occurred_at_unix_millis: i64,
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
    pub(super) tenant_id: String,
    pub(super) guild_id: String,
    pub(super) application_id: Option<String>,
    pub(super) family: DiscordFamily,
    pub(super) page_size: Option<usize>,
}
