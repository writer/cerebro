use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{ActivTrakError, ActivTrakFamily, request, response};

/// Credential-free request intent for the trusted ActivTrak HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct ActivTrakRequest {
    pub(super) url: Url,
    pub(super) family: ActivTrakFamily,
    pub(super) cursor: Option<String>,
    pub(super) offset: Option<usize>,
    pub(super) page_size: usize,
}

impl fmt::Debug for ActivTrakRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivTrakRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("has_cursor", &self.cursor.is_some())
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl ActivTrakRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }
    /// Family owning this request.
    pub const fn family(&self) -> ActivTrakFamily {
        self.family
    }
    /// Authentication header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "x-api-key"
    }
    /// API keys have no prefix scheme.
    pub const fn authentication_scheme(&self) -> &'static str {
        ""
    }
    /// Host must redeem a credential reference before execution.
    pub const fn credential_reference_required(&self) -> bool {
        true
    }
    /// Expected response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
    /// Portable plan contains no credential bytes or references.
    pub const fn contains_credentials(&self) -> bool {
        false
    }
    /// Redirects are disabled by the trusted host.
    pub const fn allows_redirects(&self) -> bool {
        false
    }
    /// Maximum admitted response bytes.
    pub const fn max_response_bytes(&self) -> usize {
        response::MAX_RESPONSE_BYTES
    }
    /// Provider permission required for list operations.
    pub const fn required_scope(&self) -> &'static str {
        "ActivTrak API read access"
    }
    /// Maximum records admitted from this response.
    pub const fn record_limit(&self) -> usize {
        self.page_size
    }
}

/// One normalized tenant-scoped ActivTrak event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct ActivTrakRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-, family-, and provider-scoped identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: ActivTrakFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Deterministic projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free provider payload.
    pub payload: Value,
}

/// One bounded normalized ActivTrak page.
#[derive(Clone, Debug, PartialEq)]
pub struct ActivTrakPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<ActivTrakRecord>,
    /// Validated continuation, or terminal state.
    pub next_cursor: Option<String>,
}

/// Checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivTrakCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: ActivTrakFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed ActivTrak kernel for one tenant and family.
#[derive(Clone, Debug)]
pub struct ActivTrakKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: ActivTrakFamily,
    pub(super) observed_at: String,
}

impl ActivTrakKernel {
    /// Construct one family kernel from public execution context.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: ActivTrakFamily,
        observed_at: &str,
    ) -> Result<Self, ActivTrakError> {
        request::new_kernel(base_url, tenant_id, family, observed_at)
    }
    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }
    /// Plan one bounded origin-restricted request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<ActivTrakRequest, ActivTrakError> {
        request::plan(self, cursor)
    }
    /// Decode one bounded provider response.
    pub fn decode(
        &self,
        request: &ActivTrakRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<ActivTrakPage, ActivTrakError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }
    /// Validate a checkpoint candidate for post-commit persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &ActivTrakRequest,
        page: &ActivTrakPage,
        prior_watermark: Option<&str>,
    ) -> Result<ActivTrakCheckpointCandidate, ActivTrakError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
