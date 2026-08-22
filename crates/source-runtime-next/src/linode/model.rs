//! Public Linode page and normalized issue contracts.

use std::collections::BTreeMap;

use serde_json::Value;

/// One normalized Linode managed issue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinodeRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Exact provider kind.
    pub provider_kind: String,
    /// Exact source schema reference.
    pub schema_ref: String,
    /// Configured source tenant bound to this normalization.
    pub tenant_id: String,
    /// Stable provider identity selected in Go order.
    pub provider_id: String,
    /// Go-compatible tenant, scope, family, and provider event identity.
    pub event_id: String,
    /// Portable normalized attributes.
    pub fields: BTreeMap<String, String>,
    /// UTC provider occurrence time or observation fallback.
    pub occurred_at: String,
    /// Exact raw provider object.
    pub payload: Value,
}

/// One bounded Linode managed-issue page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinodePage {
    /// Deduplicated issues in provider order.
    pub records: Vec<LinodeRecord>,
    /// Validated next provider page.
    pub next_cursor: Option<String>,
    /// Provider total result count.
    pub total_results: u64,
}
