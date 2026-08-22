use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::AsanaFamily;

/// One credential-free Asana request plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsanaRequest {
    pub(super) url: Url,
    pub(super) family: AsanaFamily,
    pub(super) cursor: Option<String>,
}

/// One normalized tenant-scoped Asana event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct AsanaRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant- and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: AsanaFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Deterministic projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free normalized provider payload.
    pub payload: Value,
}

/// One bounded normalized Asana page.
#[derive(Clone, Debug, PartialEq)]
pub struct AsanaPage {
    /// Accepted records in provider order.
    pub records: Vec<AsanaRecord>,
    /// Validated continuation persisted only after durable commit.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/project persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsanaCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: AsanaFamily,
    /// Validated next cursor.
    pub cursor: Option<String>,
    /// Highest normalized occurrence time.
    pub watermark: Option<String>,
}

/// Closed Asana kernel for one tenant, workspace, and family.
#[derive(Clone, Debug)]
pub struct AsanaKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) workspace_gid: String,
    pub(super) family: AsanaFamily,
    pub(super) page_size: usize,
}
