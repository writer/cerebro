use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

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
    /// Ordered user-group fanout configured through plural or singular aliases.
    pub group_ids: Vec<String>,
    /// Directory Insights lower time bound.
    pub audit_start_time: Option<String>,
    /// Optional Directory Insights upper time bound.
    pub audit_end_time: Option<String>,
    /// Directory Insights services, or `all` when empty.
    pub audit_services: Vec<String>,
    /// Directory Insights sort direction, defaulting to `ASC`.
    pub audit_sort: Option<String>,
}

impl JumpCloudFilters {
    /// Apply the public runtime metadata keys accepted by the trusted bridge.
    ///
    /// This keeps alias precedence provider-owned while allowing a shared host
    /// to pass its credential-free public configuration through unchanged.
    #[must_use]
    pub fn with_group_member_public_config(self, public_config: &HashMap<String, String>) -> Self {
        self.with_group_member_config(
            public_config.get("group_ids").map(String::as_str),
            public_config.get("user_group_ids").map(String::as_str),
            public_config.get("group_id").map(String::as_str),
            public_config.get("user_group_id").map(String::as_str),
        )
    }

    /// Apply Go-compatible group-member aliases in their production precedence.
    ///
    /// Values are normalized, deduplicated, and bounded when the kernel is
    /// constructed; keeping alias parsing here lets the shared bridge remain
    /// provider-neutral.
    #[must_use]
    pub fn with_group_member_config(
        mut self,
        group_ids: Option<&str>,
        user_group_ids: Option<&str>,
        group_id: Option<&str>,
        user_group_id: Option<&str>,
    ) -> Self {
        self.group_ids.extend(
            [group_ids, user_group_ids, group_id, user_group_id]
                .into_iter()
                .flatten()
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        );
        self
    }
}

/// Credential-free request intent for the trusted JumpCloud HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct JumpCloudRequest {
    pub(super) family: JumpCloudFamily,
    pub(super) url: Url,
    pub(super) method: &'static str,
    pub(super) page_size: usize,
    pub(super) cursor: Option<String>,
    pub(super) input_cursor: Option<String>,
    pub(super) fanout_index: Option<usize>,
    pub(super) group_id: Option<String>,
    pub(super) body: Option<Vec<u8>>,
    pub(super) org_id: Option<String>,
    pub(super) checkpoint_watermark: Option<String>,
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
            .field("has_fanout", &self.fanout_index.is_some())
            .field("has_body", &self.body.is_some())
            .field("has_org_id", &self.org_id.is_some())
            .field(
                "has_checkpoint_watermark",
                &self.checkpoint_watermark.is_some(),
            )
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
    /// Prior terminal audit watermark bound into this request, when present.
    pub fn checkpoint_watermark(&self) -> Option<&str> {
        self.checkpoint_watermark.as_deref()
    }
    /// Request-bound group scope for membership fanout.
    pub fn group_id(&self) -> Option<&str> {
        self.group_id.as_deref()
    }
    /// Request media type required by the trusted host.
    pub const fn content_type(&self) -> Option<&'static str> {
        if matches!(self.family, JumpCloudFamily::AuditEvents) {
            Some("application/json")
        } else {
            None
        }
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

impl JumpCloudResponseMetadata {
    /// Parse only the bounded, public response headers required by JumpCloud.
    pub fn from_headers(headers: &BTreeMap<String, String>) -> Result<Self, JumpCloudError> {
        let result_count = bounded_usize(header(headers, "x-result-count")?, 1_000_000)?;
        let limit = bounded_usize(header(headers, "x-limit")?, 1_000)?;
        let search_after = header(headers, "x-search_after")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(request::validate_audit_cursor)
            .transpose()?;
        let retry_after_seconds = header(headers, "retry-after")?
            .map(str::trim)
            .map(|value| {
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| *seconds <= 3_600)
                    .ok_or(JumpCloudError::InvalidRetryAfter)
            })
            .transpose()?;
        Ok(Self {
            result_count,
            limit,
            search_after,
            retry_after_seconds,
        })
    }
}

fn header<'a>(
    headers: &'a BTreeMap<String, String>,
    expected: &str,
) -> Result<Option<&'a str>, JumpCloudError> {
    let mut matches = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.as_str());
    let first = matches.next();
    if matches.next().is_some() {
        return Err(JumpCloudError::MalformedResponse);
    }
    Ok(first)
}

fn bounded_usize(value: Option<&str>, maximum: usize) -> Result<Option<usize>, JumpCloudError> {
    value
        .map(str::trim)
        .map(|value| {
            value
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= maximum)
                .ok_or(JumpCloudError::MalformedResponse)
        })
        .transpose()
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

    /// Plan a request with the last terminal durable watermark.
    ///
    /// For Directory Insights this matches Go `ReadWithCheckpoint`: explicit
    /// configuration wins, otherwise the prior watermark becomes `start_time`.
    pub fn plan_with_checkpoint(
        &self,
        cursor: Option<&str>,
        prior_watermark: Option<&str>,
    ) -> Result<JumpCloudRequest, JumpCloudError> {
        request::plan_with_checkpoint(self, cursor, prior_watermark)
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
