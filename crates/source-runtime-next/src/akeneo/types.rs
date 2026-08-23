use std::{collections::BTreeMap, fmt};

use reqwest::Url;
use serde_json::Value;

use super::{AkeneoError, AkeneoFamily, request, response};

/// Public non-secret path parameters for one Akeneo family.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AkeneoScope {
    asset_family_code: Option<String>,
    code: Option<String>,
    attribute_code: Option<String>,
    reference_entity_code: Option<String>,
    uuid: Option<String>,
}

impl AkeneoScope {
    /// Construct public path scope. Required fields are checked for the selected family.
    pub fn new(
        asset_family_code: Option<&str>,
        code: Option<&str>,
        attribute_code: Option<&str>,
        reference_entity_code: Option<&str>,
        uuid: Option<&str>,
    ) -> Self {
        Self {
            asset_family_code: asset_family_code.map(str::to_owned),
            code: code.map(str::to_owned),
            attribute_code: attribute_code.map(str::to_owned),
            reference_entity_code: reference_entity_code.map(str::to_owned),
            uuid: uuid.map(str::to_owned),
        }
    }

    pub(super) fn validate(self) -> Result<Self, AkeneoError> {
        Ok(Self {
            asset_family_code: validate_optional(self.asset_family_code, "asset_family_code")?,
            code: validate_optional(self.code, "code")?,
            attribute_code: validate_optional(self.attribute_code, "attribute_code")?,
            reference_entity_code: validate_optional(
                self.reference_entity_code,
                "reference_entity_code",
            )?,
            uuid: validate_optional(self.uuid, "uuid")?,
        })
    }

    pub(super) fn asset_family_code(&self) -> Result<&str, AkeneoError> {
        self.asset_family_code
            .as_deref()
            .ok_or(AkeneoError::MissingPathParameter("asset_family_code"))
    }

    pub(super) fn code(&self) -> Result<&str, AkeneoError> {
        self.code
            .as_deref()
            .ok_or(AkeneoError::MissingPathParameter("code"))
    }

    pub(super) fn attribute_code(&self) -> Result<&str, AkeneoError> {
        self.attribute_code
            .as_deref()
            .ok_or(AkeneoError::MissingPathParameter("attribute_code"))
    }

    pub(super) fn reference_entity_code(&self) -> Result<&str, AkeneoError> {
        self.reference_entity_code
            .as_deref()
            .ok_or(AkeneoError::MissingPathParameter("reference_entity_code"))
    }

    pub(super) fn uuid(&self) -> Result<&str, AkeneoError> {
        self.uuid
            .as_deref()
            .ok_or(AkeneoError::MissingPathParameter("uuid"))
    }

    pub(super) fn identity_scope(&self) -> String {
        [
            self.asset_family_code.as_deref().unwrap_or(""),
            self.code.as_deref().unwrap_or(""),
            self.attribute_code.as_deref().unwrap_or(""),
            self.reference_entity_code.as_deref().unwrap_or(""),
            self.uuid.as_deref().unwrap_or(""),
        ]
        .join("\0")
    }
}

fn validate_optional(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, AkeneoError> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_control)
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(AkeneoError::InvalidPathParameter(field));
            }
            Ok(value.to_owned())
        })
        .transpose()
}

/// Credential-free request intent for the trusted Akeneo HTTP host.
#[derive(Clone, Eq, PartialEq)]
pub struct AkeneoRequest {
    pub(super) url: Url,
    pub(super) family: AkeneoFamily,
    pub(super) record_limit: usize,
}

impl fmt::Debug for AkeneoRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AkeneoRequest")
            .field("url", &self.url)
            .field("family", &self.family)
            .field("record_limit", &self.record_limit)
            .finish()
    }
}

impl AkeneoRequest {
    /// Fully planned public provider URL, before trusted-host auth.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Provider HTTP method.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Family owning this request.
    pub const fn family(&self) -> AkeneoFamily {
        self.family
    }

    /// Authentication header applied only by the trusted host.
    pub const fn authentication_header(&self) -> &'static str {
        "Authorization"
    }

    /// Authentication scheme applied only by the trusted host.
    pub const fn authentication_scheme(&self) -> &'static str {
        "Bearer"
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

    /// Provider permission required for every read operation.
    pub const fn required_scope(&self) -> &'static str {
        "Akeneo API read access"
    }

    /// Maximum records admitted from this response.
    pub const fn record_limit(&self) -> usize {
        self.record_limit
    }
}

/// One normalized tenant-scoped Akeneo event candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct AkeneoRecord {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Stable tenant-, origin-, family-, scope-, and provider-scoped identity.
    pub event_id: String,
    /// Stable provider object identity.
    pub provider_id: String,
    /// Exact family.
    pub family: AkeneoFamily,
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

/// One bounded normalized Akeneo response.
#[derive(Clone, Debug, PartialEq)]
pub struct AkeneoPage {
    /// Accepted records after deterministic deduplication.
    pub records: Vec<AkeneoRecord>,
    /// Akeneo catalog declares these operations non-paginated.
    pub next_cursor: Option<String>,
}

/// Validated terminal checkpoint candidate for post-commit persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AkeneoCheckpointCandidate {
    /// Authenticated tenant scope.
    pub tenant_id: String,
    /// Selected family.
    pub family: AkeneoFamily,
    /// Always terminal for the current catalog contract.
    pub cursor: Option<String>,
    /// Provider observation watermark.
    pub watermark: String,
}

/// Closed Akeneo kernel for one tenant, origin, public scope, and family.
#[derive(Clone, Debug)]
pub struct AkeneoKernel {
    pub(super) base_url: Url,
    pub(super) tenant_id: String,
    pub(super) family: AkeneoFamily,
    pub(super) scope: AkeneoScope,
    pub(super) observed_at: String,
}

impl AkeneoKernel {
    /// Construct one family kernel from public execution context only.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: AkeneoFamily,
        scope: AkeneoScope,
        observed_at: &str,
    ) -> Result<Self, AkeneoError> {
        request::new_kernel(base_url, tenant_id, family, scope, observed_at)
    }

    /// Kernel protocol never accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded origin-restricted provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<AkeneoRequest, AkeneoError> {
        request::plan(self, cursor)
    }

    /// Decode one bounded provider response under the exact request plan.
    pub fn decode(
        &self,
        request: &AkeneoRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<AkeneoPage, AkeneoError> {
        response::decode(self, request, status, retry_after_seconds, body)
    }

    /// Validate a terminal checkpoint candidate for post-commit host persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &AkeneoRequest,
        page: &AkeneoPage,
        prior_watermark: Option<&str>,
    ) -> Result<AkeneoCheckpointCandidate, AkeneoError> {
        response::checkpoint_candidate(self, request, page, prior_watermark)
    }
}
