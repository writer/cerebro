use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::{Map, Value};

use super::{
    CloudflareError, CloudflareFamily, CloudflareScope,
    cursor::{next_cursor, parse_cursor},
    normalize::{
        attribute_contract, bounded_component, common_attributes, kernel_fingerprint,
        reject_credential_material, string_at, string_path, tenant_event_id, value_string_at,
    },
    origin::validate_origin,
};

const MAX_RESPONSE_BYTES: usize = 8 << 20;
const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_TENANT_BYTES: usize = 255;

/// One credential-free Cloudflare request stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloudflareRequestKind {
    /// List one bounded page for the selected family.
    List,
    /// Fetch one provider object after a list result requested enrichment.
    Detail {
        /// Stable provider ID substituted into the checked-in detail path.
        provider_id: String,
    },
}

/// A bounded Cloudflare request plan without credential bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareRequest {
    url: Url,
    family: CloudflareFamily,
    scope_id: Option<String>,
    page: u32,
    page_size: usize,
    kind: CloudflareRequestKind,
    kernel_fingerprint: [u8; 32],
}

impl CloudflareRequest {
    /// Fully planned provider URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Selected catalog family.
    pub const fn family(&self) -> CloudflareFamily {
        self.family
    }

    /// Request stage.
    pub fn kind(&self) -> &CloudflareRequestKind {
        &self.kind
    }

    /// Header populated by the trusted credential host.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// Scheme applied outside this kernel.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Portable request plans never contain provider credential bytes.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects remain disabled at the trusted host.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Maximum response body admitted before decoding.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }

    /// Required provider response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Page represented by a list request.
    pub const fn page(&self) -> u32 {
        self.page
    }
}

/// One normalized, tenant-bound Cloudflare provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareRecord {
    /// Raw provider object ID retained for investigation.
    pub provider_id: String,
    /// Account- or zone-qualified provider identity used for dedupe.
    pub scoped_provider_id: String,
    /// Stable tenant-scoped event identity.
    pub event_id: String,
    /// Exact source-catalog family.
    pub family: String,
    /// Exact source-catalog event kind.
    pub event_kind: String,
    /// Exact source-catalog schema reference.
    pub schema_ref: String,
    /// Go-compatible scalar attributes in deterministic key order.
    pub attributes: BTreeMap<String, String>,
    /// Credential-free provider payload.
    pub payload: Value,
}

/// One normalized Cloudflare provider page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflarePage {
    /// Records in provider order after idempotent duplicate collapse.
    pub records: Vec<CloudflareRecord>,
    /// Go-compatible page continuation.
    pub next_cursor: Option<String>,
    /// Provider records examined before duplicate collapse.
    pub scanned_count: usize,
}

/// Closed Cloudflare provider kernel for one tenant, family, and scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareKernel {
    base_url: Url,
    tenant_id: String,
    family: CloudflareFamily,
    scope_id: Option<String>,
    page_size: usize,
    fingerprint: [u8; 32],
}

impl CloudflareKernel {
    /// Compile one family into an origin- and scope-bound provider kernel.
    ///
    /// `scope_id` is an account ID for account-scoped families and a zone ID
    /// for zone-scoped families. Global `account` and `zone` families reject it.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        family: CloudflareFamily,
        scope_id: Option<&str>,
        page_size: Option<usize>,
    ) -> Result<Self, CloudflareError> {
        let base_url = validate_origin(base_url)?;
        let tenant_id = bounded_component(tenant_id, MAX_TENANT_BYTES)
            .ok_or(CloudflareError::InvalidTenantId)?;
        let scope_id = match (family.scope(), scope_id) {
            (CloudflareScope::None, None) => None,
            (CloudflareScope::None, Some(value)) if value.trim().is_empty() => None,
            (CloudflareScope::None, Some(_)) => return Err(CloudflareError::InvalidScopeId),
            (_, Some(value)) => Some(
                bounded_component(value, MAX_IDENTIFIER_BYTES)
                    .ok_or(CloudflareError::InvalidScopeId)?,
            ),
            (_, None) => return Err(CloudflareError::InvalidScopeId),
        };
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(CloudflareError::InvalidPageSize);
        }
        let fingerprint = kernel_fingerprint(
            base_url.as_str(),
            &tenant_id,
            family,
            scope_id.as_deref(),
            page_size,
        );
        Ok(Self {
            base_url,
            tenant_id,
            family,
            scope_id,
            page_size,
            fingerprint,
        })
    }

    /// Plan one credential-free list request from an optional Go page cursor.
    pub fn plan(&self, cursor: Option<&str>) -> Result<CloudflareRequest, CloudflareError> {
        let page = parse_cursor(cursor)?;
        self.request(CloudflareRequestKind::List, page)
    }

    /// Plan a bounded detail request for families that declare one.
    pub fn plan_detail(&self, provider_id: &str) -> Result<CloudflareRequest, CloudflareError> {
        if self.family.detail_path_template().is_none() {
            return Err(CloudflareError::RequestScopeMismatch);
        }
        let provider_id = bounded_component(provider_id, MAX_IDENTIFIER_BYTES)
            .ok_or(CloudflareError::MissingProviderIdentity)?;
        self.request(CloudflareRequestKind::Detail { provider_id }, 1)
    }

    /// Classify status, validate a success envelope, and normalize one page.
    pub fn decode_http(
        &self,
        request: &CloudflareRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<CloudflarePage, CloudflareError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(CloudflareError::ResponseTooLarge);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(CloudflareError::InvalidRetryAfter);
        }
        match status {
            200 => {}
            401 => return Err(CloudflareError::AuthenticationRejected),
            403 => return Err(CloudflareError::RequiredScopeMissing),
            429 => {
                return Err(CloudflareError::RateLimited {
                    retry_after_seconds,
                });
            }
            500..=599 => return Err(CloudflareError::ProviderUnavailable { status }),
            _ => return Err(CloudflareError::UnexpectedStatus { status }),
        }
        let body: Value =
            serde_json::from_slice(body).map_err(|_| CloudflareError::InvalidResponse)?;
        reject_credential_material(&body, 0)?;
        let envelope = body.as_object().ok_or(CloudflareError::InvalidResponse)?;
        if envelope.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(CloudflareError::ProviderRejected);
        }
        match &request.kind {
            CloudflareRequestKind::List => self.decode_list(request, envelope),
            CloudflareRequestKind::Detail { provider_id } => {
                self.decode_detail(request, envelope, provider_id)
            }
        }
    }

    /// Decode a normal HTTP 200 response.
    pub fn decode(
        &self,
        request: &CloudflareRequest,
        body: &[u8],
    ) -> Result<CloudflarePage, CloudflareError> {
        self.decode_http(request, 200, None, body)
    }

    fn request(
        &self,
        kind: CloudflareRequestKind,
        page: u32,
    ) -> Result<CloudflareRequest, CloudflareError> {
        let template = match &kind {
            CloudflareRequestKind::List => self.family.path_template(),
            CloudflareRequestKind::Detail { .. } => self
                .family
                .detail_path_template()
                .ok_or(CloudflareError::RequestScopeMismatch)?,
        };
        let mut path = template.replace("{scope}", self.scope_id.as_deref().unwrap_or_default());
        if let CloudflareRequestKind::Detail { provider_id } = &kind {
            path = path.replace("{id}", provider_id);
        }
        if path.contains('{') || path.contains('}') {
            return Err(CloudflareError::RequestScopeMismatch);
        }
        let mut url = self.base_url.clone();
        let base_path = self.base_url.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}{path}"));
        url.set_query(None);
        url.set_fragment(None);
        if matches!(kind, CloudflareRequestKind::List) {
            url.query_pairs_mut()
                .append_pair("page", &page.to_string())
                .append_pair("per_page", &self.page_size.to_string());
        }
        Ok(CloudflareRequest {
            url,
            family: self.family,
            scope_id: self.scope_id.clone(),
            page,
            page_size: self.page_size,
            kind,
            kernel_fingerprint: self.fingerprint,
        })
    }

    fn validate_request(&self, request: &CloudflareRequest) -> Result<(), CloudflareError> {
        if request.family != self.family
            || request.scope_id != self.scope_id
            || request.page_size != self.page_size
            || request.kernel_fingerprint != self.fingerprint
            || request.url.origin() != self.base_url.origin()
        {
            return Err(CloudflareError::RequestScopeMismatch);
        }
        Ok(())
    }

    fn decode_list(
        &self,
        request: &CloudflareRequest,
        envelope: &Map<String, Value>,
    ) -> Result<CloudflarePage, CloudflareError> {
        let values = envelope
            .get("result")
            .and_then(Value::as_array)
            .ok_or(CloudflareError::InvalidResponse)?;
        if values.len() > MAX_PAGE_SIZE {
            return Err(CloudflareError::BudgetExceeded);
        }
        let records = self.normalize_records(values)?;
        let next_cursor = next_cursor(
            envelope.get("result_info"),
            request.page,
            request.page_size,
            values.len(),
        )?;
        Ok(CloudflarePage {
            records,
            next_cursor,
            scanned_count: values.len(),
        })
    }

    fn decode_detail(
        &self,
        _request: &CloudflareRequest,
        envelope: &Map<String, Value>,
        provider_id: &str,
    ) -> Result<CloudflarePage, CloudflareError> {
        let value = envelope
            .get("result")
            .and_then(Value::as_object)
            .ok_or(CloudflareError::InvalidResponse)?;
        let record = self.normalize_record(&Value::Object(value.clone()))?;
        if record.provider_id != provider_id {
            return Err(CloudflareError::ProviderScopeMismatch);
        }
        Ok(CloudflarePage {
            records: vec![record],
            next_cursor: None,
            scanned_count: 1,
        })
    }

    fn normalize_records(
        &self,
        values: &[Value],
    ) -> Result<Vec<CloudflareRecord>, CloudflareError> {
        let mut seen = BTreeMap::<String, Value>::new();
        let mut records = Vec::with_capacity(values.len());
        for value in values {
            let record = self.normalize_record(value)?;
            match seen.get(&record.scoped_provider_id) {
                Some(payload) if payload == &record.payload => continue,
                Some(_) => return Err(CloudflareError::ConflictingDuplicate),
                None => {
                    seen.insert(record.scoped_provider_id.clone(), record.payload.clone());
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn normalize_record(&self, value: &Value) -> Result<CloudflareRecord, CloudflareError> {
        let object = value.as_object().ok_or(CloudflareError::InvalidResponse)?;
        let provider_id = string_at(object, "id")
            .filter(|value| bounded_component(value, MAX_IDENTIFIER_BYTES).is_some())
            .ok_or(CloudflareError::MissingProviderIdentity)?;
        self.validate_provider_scope(object)?;
        let scoped_provider_id = match self.scope_id.as_deref() {
            Some(scope) => format!("{scope}|{provider_id}"),
            None => provider_id.clone(),
        };
        let event_id = tenant_event_id(&self.tenant_id, self.family, &scoped_provider_id);
        let mut attributes = common_attributes(self.family, &provider_id, &self.tenant_id);
        if let Some(scope) = self.scope_id.as_deref() {
            let key = match self.family.scope() {
                CloudflareScope::Account => "account_id",
                CloudflareScope::Zone => "zone_id",
                CloudflareScope::None => return Err(CloudflareError::RequestScopeMismatch),
            };
            attributes.insert(key.to_owned(), scope.to_owned());
        }
        for (key, paths) in attribute_contract(self.family) {
            if let Some(value) = paths.iter().find_map(|path| value_string_at(object, path)) {
                attributes.insert((*key).to_owned(), value);
            }
        }
        if attributes
            .get(self.family.id_attribute())
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(CloudflareError::MissingProviderIdentity);
        }
        Ok(CloudflareRecord {
            provider_id,
            scoped_provider_id,
            event_id,
            family: self.family.as_str().to_owned(),
            event_kind: self.family.event_kind(),
            schema_ref: self.family.schema_ref(),
            attributes,
            payload: value.clone(),
        })
    }

    fn validate_provider_scope(&self, object: &Map<String, Value>) -> Result<(), CloudflareError> {
        let Some(expected) = self.scope_id.as_deref() else {
            return Ok(());
        };
        let candidates: &[&str] = match self.family.scope() {
            CloudflareScope::Account => &["account_id", "account.id"],
            CloudflareScope::Zone => &["zone_id", "zone.id"],
            CloudflareScope::None => return Err(CloudflareError::RequestScopeMismatch),
        };
        if let Some(actual) = candidates.iter().find_map(|path| string_path(object, path))
            && actual != expected
        {
            return Err(CloudflareError::ProviderScopeMismatch);
        }
        Ok(())
    }
}
