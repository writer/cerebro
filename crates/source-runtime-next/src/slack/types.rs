use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::{SlackError, SlackFamily, request, response};

/// Public, non-secret selectors for one Slack family request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SlackFilters {
    /// Channel selected for `channel_member`.
    pub channel_id: Option<String>,
    /// User group selected for `user_group_member`.
    pub usergroup_id: Option<String>,
    /// Access-log upper time bound.
    pub before: Option<String>,
    /// Audit action filter.
    pub action: Option<String>,
    /// Audit actor filter.
    pub actor: Option<String>,
    /// Audit entity filter.
    pub entity: Option<String>,
    /// Audit lower Unix-second bound.
    pub oldest: Option<String>,
    /// Audit upper Unix-second bound.
    pub latest: Option<String>,
}

/// Credential-free request intent for the trusted Slack HTTP host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackRequest {
    pub(super) family: SlackFamily,
    pub(super) url: Url,
    pub(super) method: &'static str,
    pub(super) page_size: usize,
    pub(super) audit_window: Option<(String, String)>,
}

impl SlackRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Provider HTTP method.
    pub fn method(&self) -> &'static str {
        self.method
    }
    /// Authentication scheme the trusted host applies outside this kernel.
    pub fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }
    /// Expected response media type.
    pub fn accept(&self) -> &'static str {
        "application/json"
    }
    /// Redirect handling required of the trusted host.
    pub fn follow_redirects(&self) -> bool {
        false
    }
    /// Maximum admitted response bytes.
    pub fn max_response_bytes(&self) -> usize {
        super::response::MAX_RESPONSE_BYTES
    }
}

/// One canonical Slack event record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackRecord {
    /// Authenticated tenant identity.
    pub tenant_id: String,
    /// Deterministic tenant-scoped event identity.
    pub event_id: String,
    /// Exact event kind.
    pub kind: String,
    /// Exact event schema.
    pub schema_ref: String,
    /// Stable family identifier.
    pub family: String,
    /// Stable provider identity used for dedupe.
    pub provider_id: String,
    /// Provider occurrence time, or caller observation time when absent.
    pub occurred_at_unix_millis: i64,
    /// Canonical scalar event attributes.
    pub attributes: BTreeMap<String, String>,
    /// Bounded provider payload admitted by the family contract.
    pub payload: Value,
}

/// Proposed provider progress; durable commit remains outside the kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackCheckpoint {
    /// Provider continuation, when another page exists.
    pub next_cursor: Option<String>,
    /// Latest admitted provider occurrence time.
    pub watermark_unix_millis: Option<i64>,
}

/// One normalized Slack response page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackPage {
    /// Deduplicated canonical records.
    pub records: Vec<SlackRecord>,
    /// Provider continuation, when another page exists.
    pub next_cursor: Option<String>,
    /// Proposed progress for the durable host.
    pub checkpoint: SlackCheckpoint,
}

/// Closed credential-free Slack provider kernel.
#[derive(Clone, Debug)]
pub struct SlackKernel {
    pub(super) web_origin: Url,
    pub(super) audit_origin: Url,
    pub(super) tenant_id: String,
    pub(super) family: SlackFamily,
    pub(super) filters: SlackFilters,
    pub(super) page_size: usize,
    pub(super) observed_at_unix_millis: i64,
}

impl SlackKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        web_origin: &str,
        audit_origin: &str,
        tenant_id: &str,
        family: SlackFamily,
        filters: SlackFilters,
        page_size: Option<usize>,
        observed_at_unix_millis: i64,
    ) -> Result<Self, SlackError> {
        let web_origin = request::origin(web_origin)?;
        let audit_origin = request::origin(audit_origin)?;
        if !request::safe_component(tenant_id, 128) {
            return Err(SlackError::InvalidTenant);
        }
        let page_size = page_size.unwrap_or(100);
        if page_size == 0 || page_size > 100 {
            return Err(SlackError::InvalidPageSize);
        }
        request::validate_filters(family, &filters)?;
        Ok(Self {
            web_origin,
            audit_origin,
            tenant_id: tenant_id.to_owned(),
            family,
            filters,
            page_size,
            observed_at_unix_millis,
        })
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<SlackRequest, SlackError> {
        request::plan(self, cursor)
    }

    /// Decode one provider response under the exact planned request.
    pub fn decode(
        &self,
        request: &SlackRequest,
        status: u16,
        retry_after: Option<&str>,
        body: &[u8],
    ) -> Result<SlackPage, SlackError> {
        response::decode(self, request, status, retry_after, body)
    }
}
