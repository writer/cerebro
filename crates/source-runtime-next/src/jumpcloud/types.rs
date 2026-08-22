use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{JumpCloudError, JumpCloudFamily, request, response};

/// Public, non-secret selectors for one JumpCloud family request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JumpCloudFilters {
    /// Optional organization header applied by the trusted host.
    pub org_id: Option<String>,
    /// User group selected for a membership page.
    pub group_id: Option<String>,
    /// Directory Insights lower time bound.
    pub audit_start_time: Option<String>,
    /// Optional Directory Insights upper time bound.
    pub audit_end_time: Option<String>,
    /// Directory Insights services, or `all` when empty.
    pub audit_services: Vec<String>,
    /// Directory Insights sort direction, defaulting to `ASC`.
    pub audit_sort: Option<String>,
}

/// Credential-free request intent for the trusted JumpCloud HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct JumpCloudRequest {
    pub(super) family: JumpCloudFamily,
    pub(super) url: Url,
    pub(super) method: &'static str,
    pub(super) page_size: usize,
    pub(super) cursor: Option<String>,
    pub(super) body: Option<Vec<u8>>,
    pub(super) org_id: Option<String>,
}

impl fmt::Debug for JumpCloudRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JumpCloudRequest")
            .field("family", &self.family)
            .field("url", &self.url)
            .field("method", &self.method)
            .field("page_size", &self.page_size)
            .field("has_cursor", &self.cursor.is_some())
            .field("has_body", &self.body.is_some())
            .field("has_org_id", &self.org_id.is_some())
            .finish()
    }
}

impl JumpCloudRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        self.method
    }
    /// Family owning this request.
    pub const fn family(&self) -> JumpCloudFamily {
        self.family
    }
    /// Authentication header applied outside this kernel.
    pub const fn authentication_header(&self) -> &'static str {
        "x-api-key"
    }
    /// JumpCloud API keys have no prefix scheme.
    pub const fn authentication_scheme(&self) -> &'static str {
        ""
    }
    /// Optional public organization header value.
    pub fn organization_id(&self) -> Option<&str> {
        self.org_id.as_deref()
    }
    /// Canonical credential-free request body for Directory Insights.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
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
    /// Provider permission required for this family.
    pub const fn required_scope(&self) -> &'static str {
        self.family.required_scope()
    }
}

/// Bounded response headers captured by the trusted host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JumpCloudResponseMetadata {
    /// Directory Insights `X-Result-Count` value.
    pub result_count: Option<usize>,
    /// Directory Insights `X-Limit` value.
    pub limit: Option<usize>,
    /// Directory Insights `X-Search_after` value.
    pub search_after: Option<String>,
    /// Bounded retry delay.
    pub retry_after_seconds: Option<u64>,
}

/// One normalized tenant-scoped JumpCloud event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct JumpCloudRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant- and provider-scoped event identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: JumpCloudFamily,
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

/// One bounded normalized JumpCloud page.
#[derive(Clone, Debug, PartialEq)]
pub struct JumpCloudPage {
    /// Accepted records in provider order.
    pub records: Vec<JumpCloudRecord>,
    /// Validated continuation persisted only after durable commit.
    pub next_cursor: Option<String>,
}

/// Validated checkpoint candidate for post-append/project persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpCloudCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: JumpCloudFamily,
    /// Validated next cursor.
    pub cursor: Option<String>,
    /// Highest normalized occurrence time.
    pub watermark: Option<String>,
}

/// Closed JumpCloud kernel for one tenant and family.
#[derive(Clone, Debug)]
pub struct JumpCloudKernel {
    pub(super) directory_origin: Url,
    pub(super) insights_origin: Url,
    pub(super) tenant_id: String,
    pub(super) family: JumpCloudFamily,
    pub(super) filters: JumpCloudFilters,
    pub(super) page_size: usize,
    pub(super) observed_at: String,
}

impl JumpCloudKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        directory_origin: &str,
        insights_origin: &str,
        tenant_id: &str,
        family: JumpCloudFamily,
        filters: JumpCloudFilters,
        page_size: Option<usize>,
        observed_at: &str,
    ) -> Result<Self, JumpCloudError> {
        request::new_kernel(
            directory_origin,
            insights_origin,
            tenant_id,
            family,
            filters,
            page_size,
            observed_at,
        )
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<JumpCloudRequest, JumpCloudError> {
        request::plan(self, cursor)
    }

    /// Decode one provider response under the exact planned request.
    pub fn decode(
        &self,
        request: &JumpCloudRequest,
        status: u16,
        metadata: &JumpCloudResponseMetadata,
        body: &[u8],
    ) -> Result<JumpCloudPage, JumpCloudError> {
        response::decode(self, request, status, metadata, body)
    }

    /// Validate a checkpoint candidate for durable host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &JumpCloudRequest,
        page: &JumpCloudPage,
        prior_watermark: Option<&str>,
    ) -> Result<JumpCloudCheckpointCandidate, JumpCloudError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
