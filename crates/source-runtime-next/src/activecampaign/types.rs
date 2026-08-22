use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{ActiveCampaignError, ActiveCampaignFamily, request, response};

/// Credential-free request intent for the trusted ActiveCampaign HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct ActiveCampaignRequest {
    pub(super) url: Url,
    pub(super) family: ActiveCampaignFamily,
    pub(super) offset: usize,
    pub(super) cursor: Option<String>,
    pub(super) page_size: usize,
}

impl fmt::Debug for ActiveCampaignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveCampaignRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("offset", &self.offset)
            .field("has_cursor", &self.cursor.is_some())
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl ActiveCampaignRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Family owning this request.
    pub const fn family(&self) -> ActiveCampaignFamily {
        self.family
    }

    /// Authentication header applied by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "Api-Token"
    }

    /// ActiveCampaign API tokens have no prefix scheme.
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

    /// Provider permission required for every list operation.
    pub const fn required_scope(&self) -> &'static str {
        "ActiveCampaign API read access"
    }

    /// Maximum records admitted from this response.
    pub const fn record_limit(&self) -> usize {
        self.page_size
    }
}

/// One normalized tenant-scoped ActiveCampaign event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveCampaignRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-, origin-, family-, and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: ActiveCampaignFamily,
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

/// One bounded normalized ActiveCampaign page.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveCampaignPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<ActiveCampaignRecord>,
    /// Validated offset continuation, or terminal state.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/projection persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveCampaignCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: ActiveCampaignFamily,
    /// Validated continuation state.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed ActiveCampaign kernel for one tenant, origin, and family.
#[derive(Clone, Debug)]
pub struct ActiveCampaignKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: ActiveCampaignFamily,
    pub(super) observed_at: String,
}

impl ActiveCampaignKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: ActiveCampaignFamily,
        observed_at: &str,
    ) -> Result<Self, ActiveCampaignError> {
        request::new_kernel(base_url, tenant_id, family, observed_at)
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<ActiveCampaignRequest, ActiveCampaignError> {
        request::plan(self, cursor)
    }

    /// Decode one bounded provider response under the exact request plan.
    pub fn decode(
        &self,
        request: &ActiveCampaignRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<ActiveCampaignPage, ActiveCampaignError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }

    /// Validate a checkpoint candidate for post-commit host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &ActiveCampaignRequest,
        page: &ActiveCampaignPage,
        prior_watermark: Option<&str>,
    ) -> Result<ActiveCampaignCheckpointCandidate, ActiveCampaignError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
