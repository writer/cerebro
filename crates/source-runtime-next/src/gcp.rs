//! Credential-free GCP source normalization kernels.
//!
//! Live GCP collection requires provider authorization, WIF token exchange,
//! and service-specific HTTP adapters. This module owns the portable, bounded
//! GCP IAM request/response contract plus the GCS object-content decision that
//! is shared across those adapters. It never accepts credentials or performs
//! provider I/O.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
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
                normalize_service_account(payload, &self.tenant_id, &self.project_id, observed_at)
            }
            GcpIamFamily::ServiceAccountKey => normalize_service_account_key(
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

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GcpServiceAccountWire {
    name: String,
    #[serde(rename = "projectId")]
    _project_id: String,
    unique_id: String,
    email: String,
    display_name: String,
    #[serde(rename = "description")]
    _description: String,
    disabled: bool,
    #[serde(rename = "oauth2ClientId")]
    _oauth2_client_id: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GcpServiceAccountKeyWire {
    name: String,
    #[serde(rename = "privateKeyType")]
    _private_key_type: String,
    #[serde(rename = "keyAlgorithm")]
    _key_algorithm: String,
    valid_after_time: String,
    #[serde(rename = "validBeforeTime")]
    _valid_before_time: String,
    #[serde(rename = "keyOrigin")]
    _key_origin: String,
    #[serde(rename = "keyType")]
    _key_type: String,
    disabled: bool,
}

fn normalize_service_account(
    payload: Value,
    tenant_id: &str,
    project_id: &str,
    observed_at: OffsetDateTime,
) -> Result<GcpIamRecord, GcpIamError> {
    let record: GcpServiceAccountWire =
        serde_json::from_value(payload.clone()).map_err(|_| GcpIamError::InvalidResponse)?;
    let email = record.email.trim().to_owned();
    let unique_id = record.unique_id.trim().to_owned();
    let name = record.name.trim().to_owned();
    let provider_id = first_nonblank_gcp([email.as_str(), unique_id.as_str(), name.as_str()])?;
    // Go event identity excludes `name`; rejecting name-only records is a
    // deliberate fail-closed tightening over Go's empty-suffix fallback.
    let event_suffix = first_nonblank_gcp([unique_id.as_str(), email.as_str()])?;
    let mut fields = BTreeMap::new();
    insert_gcp_field(
        &mut fields,
        "display_name",
        first_gcp_value([record.display_name, email.clone()]),
    );
    insert_gcp_field(&mut fields, "email", email.clone());
    insert_gcp_field(&mut fields, "domain", tenant_id.to_owned());
    insert_gcp_field(
        &mut fields,
        "family",
        GcpIamFamily::ServiceAccount.as_str().to_owned(),
    );
    insert_gcp_field(&mut fields, "mfa_enrolled", "false".to_owned());
    insert_gcp_field(&mut fields, "principal_type", "service_account".to_owned());
    insert_gcp_field(
        &mut fields,
        "status",
        if record.disabled {
            "DISABLED"
        } else {
            "ACTIVE"
        }
        .to_owned(),
    );
    insert_gcp_field(&mut fields, "unique_id", unique_id);
    insert_gcp_field(
        &mut fields,
        "user_id",
        first_gcp_value([email, record.unique_id, name]),
    );
    Ok(GcpIamRecord {
        family: GcpIamFamily::ServiceAccount.as_str().to_owned(),
        provider_kind: GcpIamFamily::ServiceAccount.provider_kind().to_owned(),
        schema_ref: GcpIamFamily::ServiceAccount.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id,
        event_id: sanitize_gcp_event_id(&format!("gcp-service-account-{event_suffix}")),
        fields,
        occurred_at: normalized_observed_at(observed_at),
        payload: json!({"raw": payload, "project_id": project_id}),
    })
}

fn normalize_service_account_key(
    payload: Value,
    tenant_id: &str,
    project_id: &str,
    service_account_email: &str,
    observed_at: OffsetDateTime,
) -> Result<GcpIamRecord, GcpIamError> {
    let record: GcpServiceAccountKeyWire =
        serde_json::from_value(payload.clone()).map_err(|_| GcpIamError::InvalidResponse)?;
    let name = record.name.trim().to_owned();
    let provider_id = first_nonblank_gcp([name.as_str(), service_account_email])?;
    let mut fields = BTreeMap::new();
    for (field, value) in [
        ("credential_id", provider_id.clone()),
        ("credential_type", "gcp_service_account_key".to_owned()),
        ("domain", tenant_id.to_owned()),
        ("event_type", "gcp_service_account_key_present".to_owned()),
        (
            "family",
            GcpIamFamily::ServiceAccountKey.as_str().to_owned(),
        ),
        ("resource_id", provider_id.clone()),
        ("resource_type", "service_account_key".to_owned()),
        (
            "status",
            if record.disabled {
                "DISABLED"
            } else {
                "ACTIVE"
            }
            .to_owned(),
        ),
        ("subject_email", service_account_email.to_owned()),
        ("subject_id", service_account_email.to_owned()),
        ("subject_type", "service_account".to_owned()),
    ] {
        insert_gcp_field(&mut fields, field, value);
    }
    let observed_at = normalized_observed_at(observed_at);
    let occurred_at =
        normalized_gcp_time(&record.valid_after_time).unwrap_or_else(|| observed_at.clone());
    Ok(GcpIamRecord {
        family: GcpIamFamily::ServiceAccountKey.as_str().to_owned(),
        provider_kind: GcpIamFamily::ServiceAccountKey.provider_kind().to_owned(),
        schema_ref: GcpIamFamily::ServiceAccountKey.schema_ref().to_owned(),
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: sanitize_gcp_event_id(&format!("gcp-service-account-key-{provider_id}")),
        fields,
        occurred_at,
        payload: json!({
            "raw": payload,
            "project_id": project_id,
            "service_account_email": service_account_email,
        }),
    })
}

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
/// Ordered data classifications emitted by GCP object inspection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GcpDataClassification {
    /// Content explicitly intended for public distribution.
    Public,
    /// Content intended only for the organization.
    Internal,
    /// Content requiring confidential handling.
    Confidential,
    /// Content containing regulated or secret material.
    Restricted,
}

impl GcpDataClassification {
    /// Return the source attribute value used by the Go GCP source.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

impl fmt::Display for GcpDataClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Signals derived from one bounded GCS object-content sample.
///
/// The original sample is deliberately absent so callers cannot accidentally
/// persist source object content in a runtime record or receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpContentInspection {
    /// Number of sample bytes inspected.
    pub bytes_scanned: usize,
    /// Whether the provider indicated that more object bytes exist.
    pub truncated: bool,
    /// Stable coarse finding names in GCP source order.
    pub findings: Vec<&'static str>,
    /// Strongest classification derived from the sample.
    pub data_classification: Option<GcpDataClassification>,
    /// Whether the sample contains an email address or US SSN pattern.
    pub contains_pii: bool,
    /// Whether the sample contains an assigned secret or private key marker.
    pub contains_secrets: bool,
}

/// Bounded, credential-free GCS object-content inspection kernel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GcpObjectContentKernel;

impl GcpObjectContentKernel {
    /// Return whether a GCS object is eligible for bounded text inspection.
    pub fn should_inspect(name: &str, content_type: &str) -> bool {
        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if content_type.starts_with("text/")
            || matches!(
                content_type.as_str(),
                "application/json"
                    | "application/xml"
                    | "application/yaml"
                    | "application/x-yaml"
                    | "application/javascript"
                    | "application/x-www-form-urlencoded"
            )
            || content_type.ends_with("+json")
            || content_type.ends_with("+xml")
        {
            return true;
        }

        let name = name.to_ascii_lowercase();
        [
            ".csv", ".env", ".ini", ".json", ".log", ".md", ".sql", ".tf", ".txt", ".xml", ".yaml",
            ".yml",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    }

    /// Inspect one already-bounded object sample without retaining its bytes.
    pub fn inspect(sample: &[u8], truncated: bool) -> GcpContentInspection {
        let normalized = String::from_utf8_lossy(sample).to_ascii_lowercase();
        let contains_pii = contains_email(&normalized) || contains_ssn(&normalized);
        let contains_secrets = contains_secret_assignment(&normalized)
            || (normalized.contains("-----begin ") && normalized.contains(" private key-----"));
        let mut findings = Vec::with_capacity(2);
        if contains_pii {
            findings.push("pii");
        }
        if contains_secrets {
            findings.push("secret");
        }
        let detected = find_classification(&normalized);
        let data_classification = if contains_pii || contains_secrets {
            Some(GcpDataClassification::Restricted)
        } else {
            detected
        };
        GcpContentInspection {
            bytes_scanned: sample.len(),
            truncated,
            findings,
            data_classification,
            contains_pii,
            contains_secrets,
        }
    }

    /// Merge metadata with an inspected classification without downgrade.
    ///
    /// Unknown non-empty metadata values are preserved exactly because they may
    /// be tenant-defined labels outside the four ordered classifications.
    pub fn strongest_classification(
        metadata_classification: &str,
        inspected_classification: Option<GcpDataClassification>,
    ) -> String {
        let metadata = metadata_classification.trim();
        let Some(content) = inspected_classification else {
            return metadata.to_owned();
        };
        if metadata.is_empty() {
            return content.as_str().to_owned();
        }
        let Some(metadata_class) = GcpDataClassification::parse(metadata) else {
            return metadata.to_owned();
        };
        if content > metadata_class {
            content.as_str().to_owned()
        } else {
            metadata.to_owned()
        }
    }

    /// Merge a metadata indicator with an optional inspection result.
    pub fn merge_contains_indicator(metadata_value: &str, inspected: Option<bool>) -> String {
        let metadata = metadata_value.trim();
        if inspected == Some(true) || truthy_indicator(metadata) {
            return "true".to_owned();
        }
        if !metadata.is_empty() {
            return metadata.to_owned();
        }
        inspected.map(|value| value.to_string()).unwrap_or_default()
    }

    /// Return whether this pure kernel requires credential material.
    pub const fn requires_credentials() -> bool {
        false
    }
}

fn contains_email(value: &str) -> bool {
    value
        .split(|character: char| !is_email_character(character))
        .map(|candidate| candidate.trim_end_matches('.'))
        .any(valid_email_candidate)
}

fn is_email_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '%' | '+' | '-' | '@')
}

fn valid_email_candidate(candidate: &str) -> bool {
    let Some((local, domain)) = candidate.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    let Some((host, suffix)) = domain.rsplit_once('.') else {
        return false;
    };
    !host.is_empty()
        && suffix.len() >= 2
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphabetic())
}

fn contains_ssn(value: &str) -> bool {
    value
        .as_bytes()
        .windows(11)
        .enumerate()
        .any(|(index, window)| {
            matches!(window, [a, b, c, b'-', d, e, b'-', f, g, h, i]
            if [a, b, c, d, e, f, g, h, i].iter().all(|byte| byte.is_ascii_digit()))
                && left_word_boundary(value.as_bytes(), index)
                && right_word_boundary(value.as_bytes(), index + window.len())
        })
}

fn contains_secret_assignment(value: &str) -> bool {
    [
        "api_key",
        "api-key",
        "apikey",
        "secret",
        "token",
        "password",
        "passwd",
        "private_key",
        "private-key",
        "privatekey",
    ]
    .iter()
    .any(|key| {
        value.match_indices(key).any(|(index, _)| {
            let tail = &value[index + key.len()..];
            let tail = tail.trim_start();
            let Some(tail) = tail.strip_prefix(':').or_else(|| tail.strip_prefix('=')) else {
                return false;
            };
            let tail = tail.trim_start();
            let tail = tail
                .strip_prefix('"')
                .or_else(|| tail.strip_prefix('\''))
                .unwrap_or(tail);
            tail.chars()
                .take_while(|character| is_secret_character(*character))
                .count()
                >= 12
        })
    })
}

fn is_secret_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '+' | '=' | '-')
}

fn find_classification(value: &str) -> Option<GcpDataClassification> {
    let mut first = None;
    for classification in [
        GcpDataClassification::Restricted,
        GcpDataClassification::Confidential,
        GcpDataClassification::Internal,
        GcpDataClassification::Public,
    ] {
        for (index, _) in value.match_indices(classification.as_str()) {
            let end = index + classification.as_str().len();
            if left_word_boundary(value.as_bytes(), index)
                && right_word_boundary(value.as_bytes(), end)
            {
                if first.is_none_or(|(first_index, _)| index < first_index) {
                    first = Some((index, classification));
                }
                break;
            }
        }
    }
    first.map(|(_, classification)| classification)
}

fn left_word_boundary(value: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(value[index - 1])
}

fn right_word_boundary(value: &[u8], index: usize) -> bool {
    index == value.len() || !is_word_byte(value[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn truthy_indicator(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVER_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/gcp/testdata/discover_service_account.json"
    ));
    const READ_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/gcp/testdata/read_service_account.json"
    ));
    const DISCOVER_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/gcp/testdata/discover_service_account_key.json"
    ));
    const READ_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/gcp/testdata/read_service_account_key.json"
    ));
    const SERVICE_ACCOUNT_EMAIL: &str = "sa@writer-prod.iam.gserviceaccount.com";
    const TENANT_ID: &str = "writer-prod";
    const OBSERVED_AT: &str = "2026-04-23T02:03:04.123456789+01:00";
    const SERVICE_ACCOUNT_NAME: &str =
        "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com";
    const SERVICE_ACCOUNT_RESPONSE: &[u8] = br#"{
        "accounts":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com",
            "email":"sa@writer-prod.iam.gserviceaccount.com",
            "uniqueId":"sa-1",
            "displayName":"Prod SA"
        }],
        "nextPageToken":"accounts-2"
    }"#;
    const SERVICE_ACCOUNT_KEY_RESPONSE: &[u8] = br#"{
        "keys":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
            "keyType":"USER_MANAGED",
            "validAfterTime":"2026-04-23T00:00:00Z"
        }],
        "nextPageToken":"keys-2"
    }"#;

    fn observed_at() -> OffsetDateTime {
        OffsetDateTime::parse(OBSERVED_AT, &Rfc3339).unwrap()
    }

    fn account_kernel() -> GcpIamKernel {
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccount,
            GcpIamFilters::default(),
            None,
        )
        .unwrap()
    }

    fn key_kernel() -> GcpIamKernel {
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccountKey,
            GcpIamFilters {
                service_account_email: Some(SERVICE_ACCOUNT_EMAIL.to_owned()),
            },
            None,
        )
        .unwrap()
    }

    #[test]
    fn iam_plans_exact_go_paths_auth_and_pagination() {
        let account_request = account_kernel().plan(Some("accounts-2")).unwrap();
        assert_eq!(
            account_request.url().as_str(),
            "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10&pageToken=accounts-2"
        );
        assert_eq!(account_request.authorization_scheme(), "Bearer");
        assert_eq!(account_request.accept(), "application/json");
        assert!(!GcpIamKernel::requires_credentials());

        let key_request = key_kernel().plan(Some("keys-2")).unwrap();
        assert_eq!(
            key_request.url().as_str(),
            "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys?pageSize=10&pageToken=keys-2"
        );
    }

    #[test]
    fn service_account_fields_and_identities_match_go_authority() {
        let kernel = account_kernel();
        let page = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                SERVICE_ACCOUNT_RESPONSE,
                observed_at(),
            )
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("accounts-2"));
        let record = &page.records[0];
        assert_eq!(record.family, "service_account");
        assert_eq!(record.provider_kind, "gcp.service_account");
        assert_eq!(record.schema_ref, "gcp/service_account/v1");
        assert_eq!(record.tenant_id, TENANT_ID);
        assert_eq!(record.provider_id, SERVICE_ACCOUNT_EMAIL);
        assert_eq!(record.event_id, "gcp-service-account-sa-1");
        assert_eq!(record.occurred_at, "2026-04-23T01:03:04.123456789Z");
        assert_eq!(
            record.fields.get("domain").map(String::as_str),
            Some(TENANT_ID)
        );
        assert_eq!(
            record.fields.get("family").map(String::as_str),
            Some("service_account")
        );
        assert_eq!(
            record.fields.get("display_name").map(String::as_str),
            Some("Prod SA")
        );
        assert_eq!(
            record.fields.get("user_id").map(String::as_str),
            Some(SERVICE_ACCOUNT_EMAIL)
        );
        assert_eq!(
            record.payload["raw"].get("name").and_then(Value::as_str),
            Some(SERVICE_ACCOUNT_NAME)
        );
        assert_eq!(record.payload["project_id"], "writer-prod");
        assert_eq!(record.payload.as_object().unwrap().len(), 2);
    }

    #[test]
    fn checked_in_service_account_fixtures_bind_kind_attributes_and_fallback_urn() {
        let expected: Value = serde_json::from_slice(READ_SERVICE_ACCOUNT_FIXTURE).unwrap();
        let expected_event = expected.as_array().unwrap().first().unwrap();
        let kernel = account_kernel();
        let page = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                SERVICE_ACCOUNT_RESPONSE,
                observed_at(),
            )
            .unwrap();
        let record = &page.records[0];
        assert_eq!(
            record.provider_kind,
            expected_event.get("kind").and_then(Value::as_str).unwrap()
        );
        let expected_attributes = expected_event.get("attributes").unwrap();
        for field in [
            "domain",
            "email",
            "family",
            "mfa_enrolled",
            "principal_type",
            "status",
            "unique_id",
            "user_id",
        ] {
            assert_eq!(
                record.fields.get(field).map(String::as_str),
                expected_attributes.get(field).and_then(Value::as_str),
                "field {field}"
            );
        }

        let fixture_urns: Vec<String> =
            serde_json::from_slice(DISCOVER_SERVICE_ACCOUNT_FIXTURE).unwrap();
        let fallback = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                br#"{"accounts":[{"uniqueId":"sa-1"}]}"#,
                observed_at(),
            )
            .unwrap();
        assert_eq!(
            fixture_urns,
            vec![format!(
                "urn:cerebro:writer-prod:gcp_service_account:{}",
                fallback.records[0].provider_id
            )]
        );
    }

    #[test]
    fn checked_in_key_fixtures_bind_identity_attributes_timestamp_and_raw_object() {
        let kernel = key_kernel();
        let page = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                SERVICE_ACCOUNT_KEY_RESPONSE,
                observed_at(),
            )
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("keys-2"));
        let record = &page.records[0];
        let expected: Value = serde_json::from_slice(READ_SERVICE_ACCOUNT_KEY_FIXTURE).unwrap();
        let expected_event = expected.as_array().unwrap().first().unwrap();
        assert_eq!(
            record.provider_kind,
            expected_event.get("kind").and_then(Value::as_str).unwrap()
        );
        assert_eq!(record.schema_ref, "gcp/service_account_key/v1");
        assert_eq!(record.tenant_id, TENANT_ID);
        let expected_attributes = expected_event.get("attributes").unwrap();
        for field in [
            "credential_id",
            "credential_type",
            "domain",
            "event_type",
            "family",
            "resource_id",
            "resource_type",
            "status",
            "subject_email",
            "subject_id",
            "subject_type",
        ] {
            assert_eq!(
                record.fields.get(field).map(String::as_str),
                expected_attributes.get(field).and_then(Value::as_str),
                "field {field}"
            );
        }
        assert_eq!(record.occurred_at, "2026-04-23T00:00:00Z");
        assert_eq!(
            record.event_id,
            "gcp-service-account-key-projects-writer-prod-serviceAccounts-sa@writer-prod.iam.gserviceaccount.com-keys-key-1"
        );
        assert_eq!(
            record.payload["raw"].get("keyType").and_then(Value::as_str),
            Some("USER_MANAGED")
        );
        assert_eq!(record.payload["project_id"], "writer-prod");
        assert_eq!(
            record.payload["service_account_email"],
            SERVICE_ACCOUNT_EMAIL
        );
        assert_eq!(record.payload.as_object().unwrap().len(), 3);
        let fixture_urns: Vec<String> =
            serde_json::from_slice(DISCOVER_SERVICE_ACCOUNT_KEY_FIXTURE).unwrap();
        assert_eq!(
            fixture_urns,
            vec![format!(
                "urn:cerebro:writer-prod:gcp_service_account_key:{}",
                record.provider_id
            )]
        );
    }

    #[test]
    fn service_account_key_is_config_scoped_to_one_parent_and_cursor() {
        let child_kernel = key_kernel();
        let child_page = child_kernel
            .decode(
                &child_kernel.plan(Some("keys-1")).unwrap(),
                SERVICE_ACCOUNT_KEY_RESPONSE,
                observed_at(),
            )
            .unwrap();
        assert_eq!(
            child_page.records[0].provider_id,
            format!("{SERVICE_ACCOUNT_NAME}/keys/key-1")
        );
        assert_eq!(child_page.next_cursor.as_deref(), Some("keys-2"));
        assert_eq!(
            child_kernel
                .plan(child_page.next_cursor.as_deref())
                .unwrap()
                .url()
                .as_str(),
            "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys?pageSize=10&pageToken=keys-2"
        );
    }

    #[test]
    fn iam_timestamp_identity_type_and_cursor_selectors_are_fail_closed() {
        let account_kernel = account_kernel();
        let account_request = account_kernel.plan(Some("  ")).unwrap();
        assert_eq!(
            account_request.url().as_str(),
            "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10"
        );
        let blank_next = account_kernel
            .decode(
                &account_request,
                br#"{"accounts":[{"email":"sa@writer-prod.iam.gserviceaccount.com"}],"nextPageToken":"  \t "}"#,
                observed_at(),
            )
            .unwrap();
        assert_eq!(blank_next.next_cursor, None);
        assert_eq!(
            blank_next.records[0].event_id,
            "gcp-service-account-sa@writer-prod.iam.gserviceaccount.com"
        );
        assert_eq!(
            account_kernel
                .decode(
                    &account_kernel.plan(None).unwrap(),
                    br#"{"accounts":[{"name":"projects/writer-prod/serviceAccounts/name-only"}]}"#,
                    observed_at(),
                )
                .unwrap_err(),
            GcpIamError::MissingProviderIdentity
        );
        for body in [
            br#"{"accounts":[{"uniqueId":7}]}"#.as_slice(),
            br#"{"accounts":[{"email":true}]}"#.as_slice(),
            br#"{"accounts":[{"uniqueId":"sa-1","disabled":"false"}]}"#.as_slice(),
        ] {
            assert_eq!(
                account_kernel
                    .decode(&account_kernel.plan(None).unwrap(), body, observed_at())
                    .unwrap_err(),
                GcpIamError::InvalidResponse
            );
        }

        let key_kernel = key_kernel();
        let key_request = key_kernel.plan(None).unwrap();
        let parsed = key_kernel
            .decode(
                &key_request,
                br#"{"keys":[{"name":"key-1","validAfterTime":"2026-04-23T02:03:04.123456789+01:00"}]}"#,
                observed_at(),
            )
            .unwrap();
        assert_eq!(
            parsed.records[0].occurred_at,
            "2026-04-23T01:03:04.123456789Z"
        );
        for valid_after_time in ["", "not-rfc3339"] {
            let body = serde_json::to_vec(&json!({
                "keys": [{"name": "key-1", "validAfterTime": valid_after_time}]
            }))
            .unwrap();
            let fallback = key_kernel
                .decode(&key_request, &body, observed_at())
                .unwrap();
            assert_eq!(
                fallback.records[0].occurred_at,
                "2026-04-23T01:03:04.123456789Z"
            );
        }
        for body in [
            br#"{"keys":[{"name":false}]}"#.as_slice(),
            br#"{"keys":[{"name":"key-1","disabled":{}}]}"#.as_slice(),
        ] {
            assert_eq!(
                key_kernel
                    .decode(&key_request, body, observed_at())
                    .unwrap_err(),
                GcpIamError::InvalidResponse
            );
        }
    }

    #[test]
    fn iam_fails_closed_for_config_scope_cursor_and_response_bounds() {
        assert_eq!(
            GcpIamFamily::from_str("unknown").unwrap_err(),
            GcpIamError::InvalidFamily
        );
        assert_eq!(
            GcpIamKernel::new(
                "https://iam.googleapis.com",
                "  ",
                "writer-prod",
                GcpIamFamily::ServiceAccount,
                GcpIamFilters::default(),
                None,
            )
            .unwrap_err(),
            GcpIamError::MissingTenantId
        );
        assert_eq!(
            GcpIamKernel::new(
                "https://iam.googleapis.com",
                TENANT_ID,
                "writer-prod",
                GcpIamFamily::ServiceAccountKey,
                GcpIamFilters::default(),
                None,
            )
            .unwrap_err(),
            GcpIamError::MissingServiceAccountEmail
        );
        assert_eq!(
            GcpIamKernel::new(
                "https://iam.googleapis.com",
                TENANT_ID,
                "writer-prod",
                GcpIamFamily::ServiceAccount,
                GcpIamFilters::default(),
                Some(201),
            )
            .unwrap_err(),
            GcpIamError::InvalidPageSize
        );
        let kernel = account_kernel();
        assert_eq!(
            kernel.plan(Some("bad\ncursor")).unwrap_err(),
            GcpIamError::InvalidCursor
        );
        assert_eq!(
            kernel
                .plan(Some(&"x".repeat(MAX_PROVIDER_CURSOR_BYTES + 1)))
                .unwrap_err(),
            GcpIamError::InvalidCursor
        );
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            kernel
                .decode(&request, br#"[]"#, observed_at())
                .unwrap_err(),
            GcpIamError::InvalidResponse
        );
        assert_eq!(
            kernel
                .decode(&request, br#"{"accounts":[{}]}"#, observed_at())
                .unwrap_err(),
            GcpIamError::MissingProviderIdentity
        );
        assert_eq!(
            kernel
                .decode(
                    &request,
                    &vec![b' '; MAX_RESPONSE_BYTES.saturating_add(1)],
                    observed_at(),
                )
                .unwrap_err(),
            GcpIamError::ResponseTooLarge
        );
        let too_many = serde_json::to_vec(&serde_json::json!({
            "accounts": (0..=MAX_RECORDS_PER_PAGE)
                .map(|index| serde_json::json!({"uniqueId": index.to_string()}))
                .collect::<Vec<_>>()
        }))
        .unwrap();
        assert_eq!(
            kernel
                .decode(&request, &too_many, observed_at())
                .unwrap_err(),
            GcpIamError::TooManyRecords
        );
        let key_request = key_kernel().plan(None).unwrap();
        assert_eq!(
            kernel
                .decode(&key_request, SERVICE_ACCOUNT_RESPONSE, observed_at())
                .unwrap_err(),
            GcpIamError::RequestScopeMismatch
        );
        for base_url in [
            "http://iam.googleapis.com",
            "https://user@iam.googleapis.com",
            "https://iam.googleapis.com/v1",
            "https://10.0.0.1",
        ] {
            assert_eq!(
                GcpIamKernel::new(
                    base_url,
                    TENANT_ID,
                    "writer-prod",
                    GcpIamFamily::ServiceAccount,
                    GcpIamFilters::default(),
                    None,
                )
                .unwrap_err(),
                GcpIamError::InvalidBaseUrl,
                "base URL {base_url}"
            );
        }
    }

    #[test]
    fn inspection_matches_the_go_gcs_fixture_vector_without_retaining_content() {
        let sample = b"email,token\nadmin@example.com,api_key=abcdefghijklmnopqrstuvwxyz\n";
        let inspection = GcpObjectContentKernel::inspect(sample, false);
        assert_eq!(inspection.bytes_scanned, 65);
        assert!(!inspection.truncated);
        assert_eq!(inspection.findings, vec!["pii", "secret"]);
        assert_eq!(
            inspection.data_classification,
            Some(GcpDataClassification::Restricted)
        );
        assert!(inspection.contains_pii);
        assert!(inspection.contains_secrets);
    }

    #[test]
    fn inspection_uses_whole_words_for_provider_classification() {
        let incidental =
            GcpObjectContentKernel::inspect(b"international publication schedule", false);
        assert_eq!(incidental.data_classification, None);
        let explicit = GcpObjectContentKernel::inspect(b"confidential launch notes", true);
        assert_eq!(
            explicit.data_classification,
            Some(GcpDataClassification::Confidential)
        );
        assert!(explicit.truncated);
    }

    #[test]
    fn inspection_recognizes_pii_and_secret_assignments() {
        let content = [
            b"contact=person@".as_slice(),
            b"example.com\n".as_slice(),
            b"api_".as_slice(),
            b"key=syntheticvalue12345".as_slice(),
        ]
        .concat();
        let inspection = GcpObjectContentKernel::inspect(&content, false);
        assert!(inspection.contains_pii);
        assert!(inspection.contains_secrets);
        assert_eq!(inspection.findings, vec!["pii", "secret"]);
    }

    #[test]
    fn short_secret_assignments_do_not_trigger() {
        let inspection = GcpObjectContentKernel::inspect(b"token=short", false);
        assert!(!inspection.contains_secrets);
        assert!(inspection.findings.is_empty());
    }

    #[test]
    fn inspectability_matches_gcs_text_contract() {
        assert!(GcpObjectContentKernel::should_inspect(
            "object.bin",
            "application/ld+json; charset=utf-8"
        ));
        assert!(GcpObjectContentKernel::should_inspect(
            "terraform.tf",
            "application/octet-stream"
        ));
        assert!(!GcpObjectContentKernel::should_inspect(
            "archive.zip",
            "application/octet-stream"
        ));
    }

    #[test]
    fn metadata_classification_is_never_downgraded() {
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "  INTERNAL  ",
                Some(GcpDataClassification::Public)
            ),
            "INTERNAL"
        );
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "restricted",
                Some(GcpDataClassification::Public)
            ),
            "restricted"
        );
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "internal",
                Some(GcpDataClassification::Restricted)
            ),
            "restricted"
        );
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "tenant-special",
                Some(GcpDataClassification::Restricted)
            ),
            "tenant-special"
        );
    }

    #[test]
    fn content_pii_can_raise_a_false_metadata_indicator() {
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("false", Some(true)),
            "true"
        );
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("custom", None),
            "custom"
        );
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("", Some(false)),
            "false"
        );
    }

    #[test]
    fn kernel_is_credential_free() {
        assert!(!GcpObjectContentKernel::requires_credentials());
    }
}
