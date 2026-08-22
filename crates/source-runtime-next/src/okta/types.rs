//! Public Okta kernel contracts.

use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::OktaFamily;

/// Public, non-secret selectors for one Okta family request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OktaFilters {
    /// Group parent for membership reads.
    pub group_id: Option<String>,
    /// Application parent for assignment reads.
    pub app_id: Option<String>,
    /// User parent for admin-role reads.
    pub user_id: Option<String>,
    /// Optional user label preserved in normalized role attributes.
    pub user_email: Option<String>,
    /// Policy parent for policy-rule reads.
    pub policy_id: Option<String>,
    /// Provider filter expression.
    pub filter: Option<String>,
    /// Provider text query.
    pub q: Option<String>,
    /// Provider search expression.
    pub search: Option<String>,
    /// User sort field.
    pub sort_by: Option<String>,
    /// User or audit sort direction.
    pub sort_order: Option<String>,
    /// Audit lower time bound.
    pub since: Option<String>,
    /// Audit upper time bound.
    pub until: Option<String>,
}

/// One credential-free Okta HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OktaRequest {
    pub(super) url: Url,
    pub(super) family: OktaFamily,
    pub(super) assignment_phase: Option<String>,
}

impl OktaRequest {
    /// Return the exact provider URL. The host must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return auth metadata without credential bytes.
    pub const fn authorization_scheme(&self) -> &'static str {
        "SSWS"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// Provider response metadata accepted by the credential-free decoder.
#[derive(Clone, Eq, PartialEq)]
pub struct OktaResponse<'a> {
    /// HTTP response status.
    pub status: u16,
    /// Bounded response body.
    pub body: &'a [u8],
    /// Optional Link response header used for continuation.
    pub link_header: Option<&'a str>,
}

impl fmt::Debug for OktaResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OktaResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("has_link_header", &self.link_header.is_some())
            .finish()
    }
}

/// One normalized Okta provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OktaRecord {
    /// Runtime family identifier.
    pub family: String,
    /// Exact provider event kind.
    pub provider_kind: String,
    /// Exact event schema reference.
    pub schema_ref: String,
    /// Trusted runtime tenant identity.
    pub tenant_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Deterministic tenant-scoped event identity.
    pub event_id: String,
    /// Portable event attributes.
    pub fields: BTreeMap<String, String>,
    /// UTC provider occurrence time or observation fallback.
    pub occurred_at: String,
    /// Exact provider object, never containing runtime credential material.
    pub payload: Value,
}

/// One bounded Okta page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OktaPage {
    /// Deduplicated records in provider order.
    pub records: Vec<OktaRecord>,
    /// Exact Go-compatible continuation when another page exists.
    pub next_cursor: Option<String>,
    /// Proposed high-watermark; the host owns durable checkpoint commit.
    pub proposed_checkpoint: Option<String>,
}

/// Bounded request and response kernel for one Okta family.
#[derive(Clone, Debug)]
pub struct OktaKernel {
    pub(super) base_url: Url,
    pub(super) base_origin: String,
    pub(super) tenant_id: String,
    pub(super) family: OktaFamily,
    pub(super) filters: OktaFilters,
    pub(super) page_size: usize,
}
