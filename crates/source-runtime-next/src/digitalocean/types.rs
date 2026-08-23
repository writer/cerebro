use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{DigitalOceanError, DigitalOceanFamily, request, response};

/// Provider operation using one selected legacy family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigitalOceanOperation {
    /// Catalog transport verification through DigitalOcean's account endpoint.
    AccountVerification,
    /// Credential and connectivity check through the selected family list.
    Check,
    /// Provider identity discovery through the selected family list.
    Discover,
    /// Event collection through the selected family list.
    Read,
}

/// Credential-free request intent for the trusted DigitalOcean HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct DigitalOceanRequest {
    pub(super) url: Url,
    pub(super) family: DigitalOceanFamily,
    pub(super) operation: DigitalOceanOperation,
    pub(super) cursor: Option<String>,
    pub(super) page: u32,
    pub(super) page_size: usize,
}

impl fmt::Debug for DigitalOceanRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("operation", &self.operation)
            .field("has_cursor", &self.cursor.is_some())
            .field("page", &self.page)
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl DigitalOceanRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Selected family.
    pub const fn family(&self) -> DigitalOceanFamily {
        self.family
    }

    /// Selected source operation.
    pub const fn operation(&self) -> DigitalOceanOperation {
        self.operation
    }

    /// Authentication header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "Authorization"
    }

    /// Authentication scheme applied outside this kernel.
    pub const fn authentication_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// The trusted host must redeem a credential reference before execution.
    pub const fn credential_reference_required(&self) -> bool {
        true
    }

    /// Portable plans contain neither credential values nor references.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are disabled by the trusted host.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Expected response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Maximum admitted response bytes.
    pub const fn max_response_bytes(&self) -> usize {
        response::MAX_RESPONSE_BYTES
    }

    /// Maximum admitted records from this response.
    pub const fn record_limit(&self) -> usize {
        self.page_size
    }

    /// Provider permission needed for the selected read operation.
    pub const fn required_scope(&self) -> &'static str {
        "DigitalOcean read access"
    }
}

/// One normalized tenant-scoped DigitalOcean event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct DigitalOceanRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-scoped event identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: DigitalOceanFamily,
    /// Exact event kind.
    pub kind: String,
    /// Exact schema reference.
    pub schema_ref: String,
    /// Normalized RFC3339 occurrence time.
    pub occurred_at: String,
    /// Exact Go-compatible event attributes.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free provider payload admitted by the event contract.
    pub payload: Value,
}

/// One bounded normalized DigitalOcean page.
#[derive(Clone, Debug, PartialEq)]
pub struct DigitalOceanPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<DigitalOceanRecord>,
    /// Validated next numeric page, or terminal state.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigitalOceanCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: DigitalOceanFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed DigitalOcean kernel for one tenant and one legacy family.
#[derive(Clone, Debug)]
pub struct DigitalOceanKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: DigitalOceanFamily,
    pub(super) page_size: usize,
    pub(super) observed_at: String,
}

impl DigitalOceanKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        base_url: Option<&str>,
        tenant_id: &str,
        family: DigitalOceanFamily,
        page_size: Option<usize>,
        observed_at: &str,
    ) -> Result<Self, DigitalOceanError> {
        request::new_kernel(base_url, tenant_id, family, page_size, observed_at)
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan Check against the configured family, matching the legacy Go source.
    pub fn plan_check(&self) -> Result<DigitalOceanRequest, DigitalOceanError> {
        request::plan(self, DigitalOceanOperation::Check, None)
    }

    /// Plan the declarative catalog's separate `/account` verification probe.
    pub fn plan_account_verification(&self) -> Result<DigitalOceanRequest, DigitalOceanError> {
        request::plan(self, DigitalOceanOperation::AccountVerification, None)
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(
        &self,
        operation: DigitalOceanOperation,
        cursor: Option<&str>,
    ) -> Result<DigitalOceanRequest, DigitalOceanError> {
        request::plan(self, operation, cursor)
    }

    /// Decode one bounded provider response under the exact request plan.
    pub fn decode(
        &self,
        request: &DigitalOceanRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<DigitalOceanPage, DigitalOceanError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }

    /// Validate a checkpoint candidate for post-commit host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &DigitalOceanRequest,
        page: &DigitalOceanPage,
        prior_watermark: Option<&str>,
    ) -> Result<DigitalOceanCheckpointCandidate, DigitalOceanError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
