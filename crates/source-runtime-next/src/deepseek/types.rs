use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::DeepSeekFamily;

/// Credential-free DeepSeek request description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekRequest {
    pub(super) url: Url,
    pub(super) family: DeepSeekFamily,
}

/// Normalized DeepSeek provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekRecord {
    /// Trusted tenant context.
    pub tenant_id: String,
    /// Deterministic tenant-scoped event identity.
    pub event_id: String,
    /// Stable provider-owned identity.
    pub provider_id: String,
    /// Closed catalog family.
    pub family: DeepSeekFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact event schema.
    pub schema_ref: String,
    /// Canonical observation time.
    pub occurred_at: String,
    /// Sorted normalized event attributes.
    pub attributes: BTreeMap<String, String>,
    /// Normalized provider payload.
    pub payload: Value,
}

/// One bounded, terminal DeepSeek page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekPage {
    /// Accepted canonical records.
    pub records: Vec<DeepSeekRecord>,
    /// Always terminal because both APIs are non-paginated.
    pub next_cursor: Option<String>,
}

/// Candidate persisted only after append and projection succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekCheckpointCandidate {
    /// Trusted tenant context.
    pub tenant_id: String,
    /// Closed catalog family.
    pub family: DeepSeekFamily,
    /// Always terminal for the two current families.
    pub cursor: Option<String>,
    /// Latest canonical observation time.
    pub watermark: Option<String>,
}

/// Portable request/response kernel for DeepSeek.
#[derive(Clone, Debug)]
pub struct DeepSeekKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: DeepSeekFamily,
}
