use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{AdpError, AdpFamily, request, response};

/// Credential-free request intent for the trusted ADP HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct AdpRequest {
    pub(super) url: Url,
    pub(super) family: AdpFamily,
    pub(super) cursor: Option<String>,
    pub(super) offset: usize,
    pub(super) record_limit: usize,
}

impl fmt::Debug for AdpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdpRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("has_cursor", &self.cursor.is_some())
            .field("offset", &self.offset)
            .field("record_limit", &self.record_limit)
            .finish()
    }
}

impl AdpRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Family owning this request.
    pub const fn family(&self) -> AdpFamily {
        self.family
    }

    /// OAuth header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "Authorization"
    }

    /// OAuth access tokens use the bearer scheme.
    pub const fn authentication_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// ADP additionally requires a host-owned mutual TLS client identity.
    pub const fn requires_mutual_tls(&self) -> bool {
        true
    }

    /// The trusted host must redeem credential references before execution.
    pub const fn credential_references_required(&self) -> bool {
        true
    }

    /// Portable plans contain no credential bytes or references.
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

    /// Provider permission required for every operation.
    pub const fn required_scope(&self) -> &'static str {
        "ADP Workforce Now API read access"
    }

    /// Maximum records admitted from this response.
    pub const fn record_limit(&self) -> usize {
        self.record_limit
    }
}

/// One normalized tenant-scoped ADP event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct AdpRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-, family-, and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: AdpFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Deterministic projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free provider payload admitted by the event contract.
    pub payload: Value,
}

/// One bounded normalized ADP page.
#[derive(Clone, Debug, PartialEq)]
pub struct AdpPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<AdpRecord>,
    /// Validated offset continuation, or terminal state.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdpCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: AdpFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed ADP kernel for one tenant and family.
#[derive(Clone, Debug)]
pub struct AdpKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: AdpFamily,
    pub(super) observed_at: String,
}

impl AdpKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: AdpFamily,
        observed_at: &str,
    ) -> Result<Self, AdpError> {
        request::new_kernel(base_url, tenant_id, family, observed_at)
    }

    /// Kernel protocol never accepts OAuth or mutual TLS material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AdpRequest, AdpError> {
        request::plan(self, cursor)
    }

    /// Decode one bounded provider response under the exact request plan.
    pub fn decode(
        &self,
        request: &AdpRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<AdpPage, AdpError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }

    /// Validate a checkpoint candidate for post-commit host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &AdpRequest,
        page: &AdpPage,
        prior_watermark: Option<&str>,
    ) -> Result<AdpCheckpointCandidate, AdpError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
