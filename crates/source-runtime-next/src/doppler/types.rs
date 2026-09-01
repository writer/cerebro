use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::{error::DopplerError, family::DopplerFamily, request, response};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct DopplerRequest {
    pub(super) url: Url,
    pub(super) family: DopplerFamily,
    pub(super) cursor: Option<String>,
}

impl DopplerRequest {
    pub(super) fn url(&self) -> &Url {
        &self.url
    }

    pub(super) const fn method(&self) -> &'static str {
        "GET"
    }

    pub(super) const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    pub(super) const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    pub(super) const fn contains_credentials(&self) -> bool {
        false
    }

    pub(super) const fn allows_redirects(&self) -> bool {
        false
    }

    pub(super) const fn accept(&self) -> &'static str {
        "application/json"
    }

    pub(super) const fn max_response_bytes(&self) -> usize {
        response::MAX_RESPONSE_BYTES
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct DopplerRecord {
    pub(super) tenant_id: String,
    pub(super) event_id: String,
    pub(super) provider_id: String,
    pub(super) family: DopplerFamily,
    pub(super) event_kind: String,
    pub(super) schema_ref: String,
    pub(super) occurred_at_unix_millis: i64,
    pub(super) attributes: BTreeMap<String, String>,
    pub(super) payload: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct DopplerPage {
    pub(super) records: Vec<DopplerRecord>,
    pub(super) next_cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct DopplerKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: DopplerFamily,
    pub(super) observed_at_unix_millis: i64,
}

impl DopplerKernel {
    pub(super) fn new(
        base_url: Option<&str>,
        tenant_id: &str,
        family: DopplerFamily,
        observed_at_unix_millis: i64,
    ) -> Result<Self, DopplerError> {
        request::new_kernel(base_url, tenant_id, family, observed_at_unix_millis)
    }

    pub(super) fn plan(&self, cursor: Option<&str>) -> Result<DopplerRequest, DopplerError> {
        request::plan(self, cursor)
    }

    pub(super) fn decode(
        &self,
        request: &DopplerRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<DopplerPage, DopplerError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }
}
