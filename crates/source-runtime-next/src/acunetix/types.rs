use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{AcunetixError, AcunetixFamily, request, response};

/// Credential-free request intent for the trusted Acunetix HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct AcunetixRequest {
    pub(super) url: Url,
    pub(super) family: AcunetixFamily,
    pub(super) cursor: Option<String>,
    pub(super) page_size: usize,
}

impl fmt::Debug for AcunetixRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcunetixRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("has_cursor", &self.cursor.is_some())
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl AcunetixRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }
    /// Family owning this request.
    pub const fn family(&self) -> AcunetixFamily {
        self.family
    }
    /// Authentication header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "X-Auth"
    }
    /// API keys have no prefix scheme.
    pub const fn authentication_scheme(&self) -> &'static str {
        ""
    }
    /// Host must redeem a credential reference before execution.
    pub const fn credential_reference_required(&self) -> bool {
        true
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
    /// Maximum admitted records.
    pub const fn record_limit(&self) -> usize {
        self.page_size
    }
    /// Provider permission required by every family.
    pub const fn required_scope(&self) -> &'static str {
        "Acunetix API read access"
    }
}

/// One normalized tenant-scoped Acunetix event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct AcunetixRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-, origin-, family-, and provider-scoped identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: AcunetixFamily,
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

/// One bounded normalized Acunetix page.
#[derive(Clone, Debug, PartialEq)]
pub struct AcunetixPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<AcunetixRecord>,
    /// Validated continuation, or terminal state.
    pub next_cursor: Option<String>,
}

/// Checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcunetixCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: AcunetixFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed Acunetix kernel for one tenant, origin, and family.
#[derive(Clone, Debug)]
pub struct AcunetixKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: AcunetixFamily,
    pub(super) observed_at: String,
}

impl AcunetixKernel {
    /// Construct one family kernel from public execution context.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: AcunetixFamily,
        observed_at: &str,
    ) -> Result<Self, AcunetixError> {
        request::new_kernel(base_url, tenant_id, family, observed_at)
    }
    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }
    /// Plan one bounded origin-restricted request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AcunetixRequest, AcunetixError> {
        request::plan(self, cursor)
    }
    /// Decode one bounded provider response.
    pub fn decode(
        &self,
        request: &AcunetixRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<AcunetixPage, AcunetixError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }
    /// Validate a checkpoint candidate for post-commit persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &AcunetixRequest,
        page: &AcunetixPage,
        prior_watermark: Option<&str>,
    ) -> Result<AcunetixCheckpointCandidate, AcunetixError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
