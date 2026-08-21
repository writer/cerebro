//! Credential-free GCP IAM request, page, and failure contracts.

mod service_account;
mod service_account_key;

#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde_json::Value;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;
const MAX_PROVIDER_CURSOR_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_RECORDS_PER_PAGE: usize = 200;

/// GCP IAM inventory families with a shared provider-owned page contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpIamFamily {
    /// IAM service accounts in one project.
    ServiceAccount,
    /// User-managed and system-managed keys for one service account.
    ServiceAccountKey,
}

impl GcpIamFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::ServiceAccountKey => "service_account_key",
        }
    }

    /// Return the exact provider kind emitted by the Go source.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::ServiceAccount => "gcp.service_account",
            Self::ServiceAccountKey => "gcp.service_account_key",
        }
    }

    /// Return the exact schema reference emitted by the Go source.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::ServiceAccount => "gcp/service_account/v1",
            Self::ServiceAccountKey => "gcp/service_account_key/v1",
        }
    }

    const fn response_field(self) -> &'static str {
        match self {
            Self::ServiceAccount => "accounts",
            Self::ServiceAccountKey => "keys",
        }
    }
}

impl FromStr for GcpIamFamily {
    type Err = GcpIamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "service_account" => Ok(Self::ServiceAccount),
            "service_account_key" => Ok(Self::ServiceAccountKey),
            _ => Err(GcpIamError::InvalidFamily),
        }
    }
}

/// Provider-local selectors for GCP IAM inventory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GcpIamFilters {
    /// One config-bound parent email required by the service-account-key family.
    /// This kernel does not perform parent discovery or fanout.
    pub service_account_email: Option<String>,
}

/// One credential-free IAM API request planned by the GCP kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamRequest {
    url: Url,
    family: GcpIamFamily,
}

impl GcpIamRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized GCP IAM provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Exact provider schema reference.
    pub schema_ref: String,
    /// Configured source tenant bound to this normalization.
    pub tenant_id: String,
    /// Provider identity used as the Go source's URN suffix.
    pub provider_id: String,
    /// Exact sanitized event identity emitted by the Go source.
    pub event_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Go-compatible UTC occurrence time bound to this observation.
    pub occurred_at: String,
    /// Go-compatible payload envelope containing provider raw and source scope.
    pub payload: Value,
}

/// One bounded GCP IAM page and its opaque provider cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamPage {
    /// Normalized records in provider order.
    pub records: Vec<GcpIamRecord>,
    /// Exact nextPageToken supplied by the provider.
    pub next_cursor: Option<String>,
}

/// Credential-free request and response kernel for GCP IAM inventory.
#[derive(Clone, Debug)]
pub struct GcpIamKernel {
    base_url: Url,
    tenant_id: String,
    project_id: String,
    family: GcpIamFamily,
    service_account_email: Option<String>,
    page_size: usize,
}

impl GcpIamKernel {
    /// Build a kernel for one IAM API origin and project.
    ///
    /// Planned requests still require the shared live-egress decision and an
    /// operation-scoped bearer credential. This type never accepts or stores a
    /// credential value.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        project_id: &str,
        family: GcpIamFamily,
        filters: GcpIamFilters,
        page_size: Option<usize>,
    ) -> Result<Self, GcpIamError> {
        let base_url = validate_gcp_origin(base_url)?;
        let tenant_id = required_gcp_value(tenant_id, GcpIamError::MissingTenantId)?;
        let project_id = required_gcp_value(project_id, GcpIamError::MissingProjectId)?;
        let service_account_email = nonblank_gcp(filters.service_account_email);
        if family == GcpIamFamily::ServiceAccountKey && service_account_email.is_none() {
            return Err(GcpIamError::MissingServiceAccountEmail);
        }
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(GcpIamError::InvalidPageSize);
        }
        Ok(Self {
            base_url,
            tenant_id,
            project_id,
            family,
            service_account_email,
            page_size,
        })
    }

    /// Return whether this planning and decoding kernel accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one provider page without performing I/O or accepting credentials.
    pub fn plan(&self, cursor: Option<&str>) -> Result<GcpIamRequest, GcpIamError> {
        let cursor = bounded_gcp_cursor(cursor)?;
        let mut url = self.endpoint()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", &self.page_size.to_string());
            if let Some(cursor) = cursor.as_deref() {
                query.append_pair("pageToken", cursor);
            }
        }
        Ok(GcpIamRequest {
            url,
            family: self.family,
        })
    }

    /// Decode one IAM response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &GcpIamRequest,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<GcpIamPage, GcpIamError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GcpIamError::ResponseTooLarge);
        }
        let payload: Value =
            serde_json::from_slice(body).map_err(|_| GcpIamError::InvalidResponse)?;
        let object = payload.as_object().ok_or(GcpIamError::InvalidResponse)?;
        let empty_records = Vec::new();
        let raw_records = match object.get(self.family.response_field()) {
            Some(Value::Array(records)) => records,
            None | Some(Value::Null) => &empty_records,
            Some(_) => return Err(GcpIamError::InvalidResponse),
        };
        if raw_records.len() > MAX_RECORDS_PER_PAGE {
            return Err(GcpIamError::TooManyRecords);
        }
        let records = raw_records
            .iter()
            .map(|record| self.normalize_record(record.clone(), observed_at))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = match object.get("nextPageToken") {
            Some(Value::String(value)) => bounded_gcp_cursor(Some(value))?,
            None | Some(Value::Null) => None,
            Some(_) => return Err(GcpIamError::InvalidResponse),
        };
        Ok(GcpIamPage {
            records,
            next_cursor,
        })
    }

    fn endpoint(&self) -> Result<Url, GcpIamError> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| GcpIamError::InvalidBaseUrl)?;
            segments.extend([
                "v1",
                "projects",
                self.project_id.as_str(),
                "serviceAccounts",
            ]);
            if self.family == GcpIamFamily::ServiceAccountKey {
                segments.extend([
                    self.service_account_email
                        .as_deref()
                        .ok_or(GcpIamError::MissingServiceAccountEmail)?,
                    "keys",
                ]);
            }
        }
        Ok(url)
    }

    fn validate_request(&self, request: &GcpIamRequest) -> Result<(), GcpIamError> {
        let endpoint = self.endpoint()?;
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.url.path() != endpoint.path()
            || request.url.fragment().is_some()
        {
            return Err(GcpIamError::RequestScopeMismatch);
        }
        let mut page_size = None;
        let mut page_token_seen = false;
        for (name, value) in request.url.query_pairs() {
            match name.as_ref() {
                "pageSize" if page_size.is_none() => page_size = Some(value.into_owned()),
                "pageToken" if !page_token_seen => page_token_seen = true,
                _ => return Err(GcpIamError::RequestScopeMismatch),
            }
        }
        let expected_page_size = self.page_size.to_string();
        if page_size.as_deref() != Some(expected_page_size.as_str()) {
            return Err(GcpIamError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn normalize_record(
        &self,
        payload: Value,
        observed_at: OffsetDateTime,
    ) -> Result<GcpIamRecord, GcpIamError> {
        if !payload.is_object() {
            return Err(GcpIamError::InvalidResponse);
        }
        match self.family {
            GcpIamFamily::ServiceAccount => {
                service_account::normalize(payload, &self.tenant_id, &self.project_id, observed_at)
            }
            GcpIamFamily::ServiceAccountKey => service_account_key::normalize(
                payload,
                &self.tenant_id,
                &self.project_id,
                self.service_account_email
                    .as_deref()
                    .ok_or(GcpIamError::MissingServiceAccountEmail)?,
                observed_at,
            ),
        }
    }
}

/// Stable GCP IAM kernel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpIamError {
    /// The configured IAM base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// The requested family is not owned by this kernel.
    InvalidFamily,
    /// Source tenant identity is required for Go-compatible event fields.
    MissingTenantId,
    /// GCP project identity is required.
    MissingProjectId,
    /// Service-account email is required for key inventory.
    MissingServiceAccountEmail,
    /// Page size is outside the Go source's inclusive 1 through 200 range.
    InvalidPageSize,
    /// Provider continuation is oversized, control-bearing, or otherwise unsafe.
    InvalidCursor,
    /// Provider response exceeds the Go source host's eight-mebibyte bound.
    ResponseTooLarge,
    /// Provider response exceeds the declared 200-record page bound.
    TooManyRecords,
    /// Response JSON does not match the selected provider family.
    InvalidResponse,
    /// A provider record has no stable identity under the Go fallback order.
    MissingProviderIdentity,
    /// A response request does not match this kernel's origin and endpoint.
    RequestScopeMismatch,
}

impl fmt::Display for GcpIamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "gcp IAM base URL must be a secure origin",
            Self::InvalidFamily => "gcp IAM family must be service_account or service_account_key",
            Self::MissingTenantId => "gcp tenant_id is required",
            Self::MissingProjectId => "gcp project_id is required",
            Self::MissingServiceAccountEmail => {
                "gcp service_account_email is required for service_account_key"
            }
            Self::InvalidPageSize => "gcp per_page must be between 1 and 200",
            Self::InvalidCursor => "gcp page cursor is invalid",
            Self::ResponseTooLarge => "gcp IAM response exceeds 8388608 bytes",
            Self::TooManyRecords => "gcp IAM response exceeds 200 records",
            Self::InvalidResponse => "gcp IAM response does not match the selected family",
            Self::MissingProviderIdentity => "gcp IAM record has no stable provider identity",
            Self::RequestScopeMismatch => "gcp IAM request does not match the kernel",
        })
    }
}

impl Error for GcpIamError {}

fn insert_gcp_field(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

fn first_gcp_value<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

fn first_nonblank_gcp<const N: usize>(values: [&str; N]) -> Result<String, GcpIamError> {
    values
        .into_iter()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(GcpIamError::MissingProviderIdentity)
}

fn sanitize_gcp_event_id(value: &str) -> String {
    value
        .replace([' ', '/', ':'], "-")
        .trim_matches('-')
        .to_owned()
}

fn nonblank_gcp(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalized_gcp_time(value: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339).ok()?;
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn normalized_observed_at(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("RFC3339 formats OffsetDateTime")
}

fn bounded_gcp_cursor(cursor: Option<&str>) -> Result<Option<String>, GcpIamError> {
    let cursor = cursor.filter(|value| !value.trim().is_empty());
    if cursor.is_some_and(|value| {
        value.len() > MAX_PROVIDER_CURSOR_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(GcpIamError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}

fn required_gcp_value(value: &str, error: GcpIamError) -> Result<String, GcpIamError> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned()).ok_or(error)
}

fn validate_gcp_origin(raw: &str) -> Result<Url, GcpIamError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| GcpIamError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(GcpIamError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_gcp_ip_literal(address, loopback)) {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(GcpIamError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn unsafe_gcp_ip_literal(address: IpAddr, loopback: bool) -> bool {
    if loopback {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}
