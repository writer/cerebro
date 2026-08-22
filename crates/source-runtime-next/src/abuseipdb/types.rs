use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{AbuseIpDbError, AbuseIpDbFamily, request, response};

/// Public, credential-free filters compiled for one AbuseIPDB operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AbuseIpDbFilters {
    /// Required report-history IP address.
    pub ip_address: Option<String>,
    /// Optional report lookback from 1 through 365 days.
    pub max_age_in_days: Option<u16>,
    /// Optional blacklist confidence threshold from 25 through 100.
    pub confidence_minimum: Option<u8>,
    /// Optional blacklist IP version, either 4 or 6.
    pub ip_version: Option<u8>,
}

/// One credential-free AbuseIPDB request plan.
#[derive(Clone, Eq, PartialEq)]
pub struct AbuseIpDbRequest {
    pub(super) url: Url,
    pub(super) family: AbuseIpDbFamily,
    pub(super) page: usize,
    pub(super) cursor: Option<String>,
    pub(super) record_limit: usize,
}

impl fmt::Debug for AbuseIpDbRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbuseIpDbRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("page", &self.page)
            .field("has_cursor", &self.cursor.is_some())
            .field("record_limit", &self.record_limit)
            .finish()
    }
}

impl AbuseIpDbRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Family owning this request.
    pub const fn family(&self) -> AbuseIpDbFamily {
        self.family
    }

    /// Authentication header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "Key"
    }

    /// AbuseIPDB API keys have no prefix scheme.
    pub const fn authentication_scheme(&self) -> &'static str {
        ""
    }

    /// The trusted host must redeem a credential reference before execution.
    pub const fn credential_reference_required(&self) -> bool {
        true
    }

    /// Expected response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Portable request plans contain no credential bytes or references.
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

    /// Provider permission required for both read operations.
    pub const fn required_scope(&self) -> &'static str {
        "AbuseIPDB API read access"
    }

    /// Maximum records admitted from this response.
    pub const fn record_limit(&self) -> usize {
        self.record_limit
    }
}

/// One normalized tenant-scoped AbuseIPDB event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct AbuseIpDbRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable Go-compatible tenant- and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider identity.
    pub provider_id: String,
    /// Exact family.
    pub family: AbuseIpDbFamily,
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

/// One bounded normalized AbuseIPDB page.
#[derive(Clone, Debug, PartialEq)]
pub struct AbuseIpDbPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<AbuseIpDbRecord>,
    /// Validated numbered-page continuation, or terminal state.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbuseIpDbCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: AbuseIpDbFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed AbuseIPDB kernel for one tenant and family.
#[derive(Clone, Debug)]
pub struct AbuseIpDbKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: AbuseIpDbFamily,
    pub(super) filters: AbuseIpDbFilters,
    pub(super) observed_at: String,
}

impl AbuseIpDbKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: AbuseIpDbFamily,
        filters: AbuseIpDbFilters,
        observed_at: &str,
    ) -> Result<Self, AbuseIpDbError> {
        request::new_kernel(base_url, tenant_id, family, filters, observed_at)
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AbuseIpDbRequest, AbuseIpDbError> {
        request::plan(self, cursor)
    }

    /// Decode one bounded provider response under the exact request plan.
    pub fn decode(
        &self,
        request: &AbuseIpDbRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<AbuseIpDbPage, AbuseIpDbError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }

    /// Validate a checkpoint candidate for post-commit host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &AbuseIpDbRequest,
        page: &AbuseIpDbPage,
        prior_watermark: Option<&str>,
    ) -> Result<AbuseIpDbCheckpointCandidate, AbuseIpDbError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
