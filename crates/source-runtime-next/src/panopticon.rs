//! Panopticon request, response, and case-to-IOC fanout kernel.
//!
//! The kernel plans credential-free provider requests and decodes native API
//! pages. Shared HTTP policy must authorize each URL and attach the bearer
//! credential before I/O.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{
    Date, OffsetDateTime, PrimitiveDateTime,
    format_description::{self, well_known::Rfc3339},
};

const CURSOR_SOURCE: &str = "panopticon/api/v1";
const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_RECORDS_PER_PAGE: usize = 1_000;
const USER_AGENT: &str = "cerebro-panopticon-source/1.0";

/// One Panopticon source family backed by the native pull API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PanopticonFamily {
    /// Security alerts returned by `/api/v2/alerts`.
    Alert,
    /// Curated cases returned by `/api/v2/cases`.
    Case,
    /// Indicators fetched by enumerating cases, then each case's IOC endpoint.
    Ioc,
}

impl PanopticonFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Case => "case",
            Self::Ioc => "ioc",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Alert => "panopticon.alert",
            Self::Case => "panopticon.case",
            Self::Ioc => "panopticon.ioc",
        }
    }

    /// Return the public event schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Alert => "panopticon/alert/v1",
            Self::Case => "panopticon/case/v1",
            Self::Ioc => "panopticon/ioc/v1",
        }
    }

    const fn default_path(self) -> &'static str {
        match self {
            Self::Alert => "/api/v2/alerts",
            Self::Case | Self::Ioc => "/api/v2/cases",
        }
    }
}

impl FromStr for PanopticonFamily {
    type Err = PanopticonError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "alert" => Ok(Self::Alert),
            "case" => Ok(Self::Case),
            "ioc" => Ok(Self::Ioc),
            _ => Err(PanopticonError::InvalidFamily),
        }
    }
}

/// One credential-free HTTP request planned by the Panopticon kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PanopticonRequest {
    url: Url,
    family: PanopticonFamily,
    api_path: String,
    stage: RequestStage,
    state: PanopticonCursor,
    ioc_context: Option<IocContext>,
}

impl PanopticonRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Return the Go-compatible provider user agent.
    pub const fn user_agent(&self) -> &'static str {
        USER_AGENT
    }
}

/// One normalized Panopticon provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PanopticonRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Public event schema reference.
    pub schema_ref: String,
    /// Stable Go-compatible record identity.
    pub provider_id: String,
    /// Provider occurrence time selected by the Go contract.
    pub occurred_at: String,
    /// Canonical scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider object overlaid with canonical family fields.
    pub payload: Value,
}

/// A bounded Panopticon result and its Go-compatible continuation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PanopticonPage {
    /// Normalized records in provider order.
    pub records: Vec<PanopticonRecord>,
    /// Opaque continuation cursor for the next source read.
    pub next_cursor: Option<String>,
    /// Greatest valid occurrence time observed by this page or prior cursor.
    pub watermark: Option<String>,
}

/// Result of decoding one Panopticon response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PanopticonOutcome {
    /// IOC collection resolved a case and requires its bounded IOC request.
    Request(PanopticonRequest),
    /// The provider response completed one source-runtime page.
    Page(PanopticonPage),
}

/// Provider-local Panopticon request and response state machine.
#[derive(Clone, Debug)]
pub struct PanopticonKernel {
    base_url: Url,
    family: PanopticonFamily,
    api_path: String,
    page_size: usize,
}

impl PanopticonKernel {
    /// Build a kernel for one Panopticon origin and family.
    ///
    /// `api_path` preserves the Go source's optional provider path override.
    /// The returned requests still require shared live-egress authorization and
    /// an operation-scoped bearer credential before network access.
    pub fn new(
        base_url: &str,
        family: PanopticonFamily,
        api_path: Option<&str>,
        page_size: Option<usize>,
    ) -> Result<Self, PanopticonError> {
        let base_url = validate_origin(base_url)?;
        let api_path = validate_api_path(api_path.unwrap_or(family.default_path()))?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(PanopticonError::InvalidPageSize);
        }
        Ok(Self {
            base_url,
            family,
            api_path,
            page_size,
        })
    }

    /// Plan the first credential-free request for one collection page.
    pub fn plan(&self, cursor: Option<&str>) -> Result<PanopticonRequest, PanopticonError> {
        let mut state = decode_cursor(cursor)?;
        match self.family {
            PanopticonFamily::Alert | PanopticonFamily::Case => {
                if state.page == 0 {
                    state.page = 1;
                }
                self.direct_request(state)
            }
            PanopticonFamily::Ioc => {
                if state.case_page == 0 {
                    state.case_page = 1;
                }
                if state.ioc_page == 0 {
                    state.ioc_page = 1;
                }
                self.case_request(state)
            }
        }
    }

    /// Decode a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &PanopticonRequest,
        body: &[u8],
    ) -> Result<PanopticonOutcome, PanopticonError> {
        if request.family != self.family
            || request.api_path != self.api_path
            || request.url.origin() != self.base_url.origin()
        {
            return Err(PanopticonError::RequestScopeMismatch);
        }
        match request.stage {
            RequestStage::Direct => self.decode_direct(request, body),
            RequestStage::ResolveCase => self.decode_case(request, body),
            RequestStage::Iocs => self.decode_iocs(request, body),
        }
    }

    fn direct_request(
        &self,
        state: PanopticonCursor,
    ) -> Result<PanopticonRequest, PanopticonError> {
        let url = self.page_url(&self.api_path, state.page)?;
        Ok(self.request(url, RequestStage::Direct, state, None))
    }

    fn case_request(&self, state: PanopticonCursor) -> Result<PanopticonRequest, PanopticonError> {
        let url = self.page_url(&self.api_path, state.case_page)?;
        Ok(self.request(url, RequestStage::ResolveCase, state, None))
    }

    fn ioc_request(
        &self,
        state: PanopticonCursor,
        context: IocContext,
    ) -> Result<PanopticonRequest, PanopticonError> {
        let mut url = self.endpoint(&self.api_path)?;
        url.path_segments_mut()
            .map_err(|_| PanopticonError::InvalidApiPath)?
            .push(&context.case_id)
            .push("iocs");
        add_page_query(&mut url, self.family, state.ioc_page, self.page_size);
        Ok(self.request(url, RequestStage::Iocs, state, Some(context)))
    }

    fn request(
        &self,
        url: Url,
        stage: RequestStage,
        state: PanopticonCursor,
        ioc_context: Option<IocContext>,
    ) -> PanopticonRequest {
        PanopticonRequest {
            url,
            family: self.family,
            api_path: self.api_path.clone(),
            stage,
            state,
            ioc_context,
        }
    }

    fn page_url(&self, path: &str, page: usize) -> Result<Url, PanopticonError> {
        let mut url = self.endpoint(path)?;
        add_page_query(&mut url, self.family, page, self.page_size);
        Ok(url)
    }

    fn endpoint(&self, path: &str) -> Result<Url, PanopticonError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| PanopticonError::InvalidApiPath)
    }

    fn decode_direct(
        &self,
        request: &PanopticonRequest,
        body: &[u8],
    ) -> Result<PanopticonOutcome, PanopticonError> {
        let decoded = decode_page(body)?;
        let next_page = decoded.next_page();
        let records = decoded
            .data
            .into_iter()
            .map(|payload| normalize_record(self.family, payload, None))
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = request.state.clone();
        state.page = next_page;
        finish_page(records, state).map(PanopticonOutcome::Page)
    }

    fn decode_case(
        &self,
        request: &PanopticonRequest,
        body: &[u8],
    ) -> Result<PanopticonOutcome, PanopticonError> {
        let decoded = decode_page(body)?;
        let index = request.state.case_index;
        let case_count = decoded.data.len();
        let next_case_page = decoded.next_page();
        let Some(case) = decoded.data.get(index) else {
            if next_case_page > 0 {
                let mut state = request.state.clone();
                state.case_page = next_case_page;
                state.case_index = 0;
                state.ioc_page = 1;
                return self.case_request(state).map(PanopticonOutcome::Request);
            }
            let mut state = request.state.clone();
            state.case_page = 0;
            state.case_index = 0;
            state.ioc_page = 0;
            return finish_page(Vec::new(), state).map(PanopticonOutcome::Page);
        };
        let case = case.as_object().ok_or(PanopticonError::InvalidResponse)?;
        let case_id = scalar_string(case.get("case_id"))
            .filter(|value| !value.is_empty())
            .ok_or(PanopticonError::MissingCaseIdentity)?;
        let occurred_at = first_time(case, &["initial_date", "open_date", "close_date"])
            .ok_or(PanopticonError::MissingOccurredAt)?;
        let context = IocContext {
            case_id,
            case_count,
            next_case_page,
            occurred_at,
        };
        self.ioc_request(request.state.clone(), context)
            .map(PanopticonOutcome::Request)
    }

    fn decode_iocs(
        &self,
        request: &PanopticonRequest,
        body: &[u8],
    ) -> Result<PanopticonOutcome, PanopticonError> {
        let context = request
            .ioc_context
            .as_ref()
            .ok_or(PanopticonError::MissingIocState)?;
        let decoded = decode_page(body)?;
        let next_ioc_page = decoded.next_page();
        let records = decoded
            .data
            .into_iter()
            .map(|payload| {
                normalize_record(
                    PanopticonFamily::Ioc,
                    payload,
                    Some(context.occurred_at.as_str()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = request.state.clone();
        if next_ioc_page > 0 {
            state.ioc_page = next_ioc_page;
        } else {
            state.case_index += 1;
            state.ioc_page = 1;
            if state.case_index >= context.case_count {
                state.case_index = 0;
                state.case_page = context.next_case_page;
                if state.case_page == 0 {
                    state.ioc_page = 0;
                }
            }
        }
        if records.is_empty() && state.has_more() {
            if next_ioc_page > 0 {
                return self
                    .ioc_request(state, context.clone())
                    .map(PanopticonOutcome::Request);
            }
            return self.case_request(state).map(PanopticonOutcome::Request);
        }
        finish_page(records, state).map(PanopticonOutcome::Page)
    }
}

/// Safe Panopticon kernel failures. Messages never contain credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PanopticonError {
    /// Family identifier is not one of the three supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Provider path is not a normalized absolute path.
    InvalidApiPath,
    /// Page size is outside the provider's 1 through 1000 bound.
    InvalidPageSize,
    /// Cursor is not a supported Go-compatible Panopticon cursor.
    InvalidCursor,
    /// Response JSON does not match the Panopticon page envelope.
    InvalidResponse,
    /// Provider response exceeded the Go source's record bound.
    TooManyRecords,
    /// A record omitted its family-specific stable identity.
    MissingRecordIdentity,
    /// Case fanout omitted the case identity required for the IOC path.
    MissingCaseIdentity,
    /// A record omitted the timestamp required by the source event contract.
    MissingOccurredAt,
    /// A record omitted another required canonical family field.
    MissingRequiredField,
    /// IOC response decoding lost its request-bound case state.
    MissingIocState,
    /// A request was decoded by a kernel configured for another family or scope.
    RequestScopeMismatch,
}

impl fmt::Display for PanopticonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "panopticon family is invalid",
            Self::InvalidBaseUrl => "panopticon base URL must be a secure origin",
            Self::InvalidApiPath => "panopticon API path must be an absolute provider path",
            Self::InvalidPageSize => "panopticon page size must be between 1 and 1000",
            Self::InvalidCursor => "panopticon cursor is invalid",
            Self::InvalidResponse => "panopticon response does not match the page contract",
            Self::TooManyRecords => "panopticon response exceeds 1000 records",
            Self::MissingRecordIdentity => "panopticon record identity is missing",
            Self::MissingCaseIdentity => "panopticon case identity is missing",
            Self::MissingOccurredAt => "panopticon record occurrence time is missing or invalid",
            Self::MissingRequiredField => "panopticon record is missing a required family field",
            Self::MissingIocState => "panopticon IOC request state is missing",
            Self::RequestScopeMismatch => {
                "panopticon request family, origin, or path does not match the kernel"
            }
        })
    }
}

impl Error for PanopticonError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestStage {
    Direct,
    ResolveCase,
    Iocs,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct PanopticonCursor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(default, skip_serializing_if = "is_false")]
    resumable_checkpoint: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    page: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    case_page: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    case_index: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    ioc_page: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    watermark: String,
}

impl PanopticonCursor {
    const fn has_more(&self) -> bool {
        self.page > 0 || self.case_page > 0 || self.ioc_page > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IocContext {
    case_id: String,
    case_count: usize,
    next_case_page: usize,
    occurred_at: String,
}

#[derive(Deserialize)]
struct NativePage {
    #[serde(default)]
    data: Vec<Value>,
    #[serde(default)]
    current_page: usize,
    #[serde(default)]
    next_page: Value,
}

impl NativePage {
    fn next_page(&self) -> usize {
        match &self.next_page {
            Value::Bool(true) => self.current_page.saturating_add(1),
            Value::Number(value) => value
                .as_u64()
                .and_then(|page| usize::try_from(page).ok())
                .unwrap_or(0),
            _ => 0,
        }
    }
}

fn add_page_query(url: &mut Url, family: PanopticonFamily, page: usize, page_size: usize) {
    let mut query = url.query_pairs_mut();
    query.append_pair("page", &page.max(1).to_string());
    query.append_pair("per_page", &page_size.to_string());
    if family == PanopticonFamily::Alert {
        query.append_pair("sort", "asc");
    } else {
        query.append_pair("order_by", "case_id");
        query.append_pair("sort_dir", "asc");
    }
}

fn validate_origin(raw: &str) -> Result<Url, PanopticonError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| PanopticonError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(PanopticonError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(PanopticonError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(PanopticonError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(PanopticonError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(PanopticonError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn validate_api_path(raw: &str) -> Result<String, PanopticonError> {
    let path = raw.trim();
    if !path.starts_with('/') || path == "/" || path.contains(['?', '#', '\\']) {
        return Err(PanopticonError::InvalidApiPath);
    }
    let parsed = Url::parse(&format!("https://provider.invalid{path}"))
        .map_err(|_| PanopticonError::InvalidApiPath)?;
    if parsed.path() != path || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(PanopticonError::InvalidApiPath);
    }
    Ok(path.to_owned())
}

fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
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

fn decode_cursor(cursor: Option<&str>) -> Result<PanopticonCursor, PanopticonError> {
    let Some(cursor) = cursor.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(PanopticonCursor::default());
    };
    if let Ok(page) = cursor.parse::<usize>() {
        return Ok(PanopticonCursor {
            page,
            ..PanopticonCursor::default()
        });
    }
    let mut state: PanopticonCursor =
        serde_json::from_str(cursor).map_err(|_| PanopticonError::InvalidCursor)?;
    if state.source != CURSOR_SOURCE {
        return Err(PanopticonError::InvalidCursor);
    }
    state.watermark = state.watermark.trim().to_owned();
    Ok(state)
}

fn encode_cursor(state: &PanopticonCursor) -> Result<String, PanopticonError> {
    let mut state = state.clone();
    state.source = CURSOR_SOURCE.to_owned();
    state.resumable_checkpoint = true;
    serde_json::to_string(&state).map_err(|_| PanopticonError::InvalidCursor)
}

fn decode_page(body: &[u8]) -> Result<NativePage, PanopticonError> {
    let page: NativePage =
        serde_json::from_slice(body).map_err(|_| PanopticonError::InvalidResponse)?;
    if page.data.iter().any(|record| !record.is_object()) {
        return Err(PanopticonError::InvalidResponse);
    }
    if page.data.len() > MAX_RECORDS_PER_PAGE {
        return Err(PanopticonError::TooManyRecords);
    }
    Ok(page)
}

fn finish_page(
    records: Vec<PanopticonRecord>,
    mut state: PanopticonCursor,
) -> Result<PanopticonPage, PanopticonError> {
    if let Some(latest) = records
        .iter()
        .filter_map(|record| {
            parsed_time(&record.occurred_at).map(|time| (time, &record.occurred_at))
        })
        .max_by_key(|(time, _)| *time)
        .map(|(_, raw)| raw.clone())
    {
        let replace = parsed_time(&state.watermark)
            .is_none_or(|prior| parsed_time(&latest).is_some_and(|candidate| candidate > prior));
        if replace {
            state.watermark = latest;
        }
    }
    let watermark = nonblank(&state.watermark).map(str::to_owned);
    let next_cursor = state
        .has_more()
        .then(|| encode_cursor(&state))
        .transpose()?;
    Ok(PanopticonPage {
        records,
        next_cursor,
        watermark,
    })
}

fn normalize_record(
    family: PanopticonFamily,
    payload: Value,
    fallback_occurred_at: Option<&str>,
) -> Result<PanopticonRecord, PanopticonError> {
    let object = payload
        .as_object()
        .ok_or(PanopticonError::InvalidResponse)?;
    let (provider_id, occurred_at, fields, canonical) = match family {
        PanopticonFamily::Alert => {
            let alert_id = required_scalar(object, "alert_id", true)?;
            let severity = first_nonblank([
                nested_scalar(object, "severity", "severity_name"),
                scalar_string(object.get("severity")),
                scalar_string(object.get("alert_severity_id")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let status = first_nonblank([
                nested_scalar(object, "status", "status_name"),
                scalar_string(object.get("status")),
                scalar_string(object.get("alert_status_id")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let title = first_nonblank([
                scalar_string(object.get("alert_title")),
                scalar_string(object.get("title")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let occurred_at = first_time(
                object,
                &[
                    "alert_source_event_time",
                    "alert_creation_time",
                    "observed_at",
                    "created_at",
                ],
            )
            .ok_or(PanopticonError::MissingOccurredAt)?;
            let observed_at = first_nonblank([
                scalar_string(object.get("observed_at")),
                scalar_string(object.get("alert_source_event_time")),
            ])
            .unwrap_or_default();
            let created_at = first_nonblank([
                scalar_string(object.get("created_at")),
                scalar_string(object.get("alert_creation_time")),
            ])
            .unwrap_or_default();
            let updated_at = first_nonblank([
                scalar_string(object.get("updated_at")),
                scalar_string(object.get("last_updated_at")),
                scalar_string(object.get("modified_at")),
                scalar_string(object.get("alert_updated_time")),
            ])
            .unwrap_or_default();
            let closed_at = first_nonblank([
                scalar_string(object.get("closed_at")),
                scalar_string(object.get("close_date")),
                scalar_string(object.get("alert_closed_time")),
            ])
            .unwrap_or_default();
            let resolved_at = first_nonblank([
                scalar_string(object.get("resolved_at")),
                scalar_string(object.get("resolved_date")),
                scalar_string(object.get("alert_resolved_time")),
            ])
            .unwrap_or_default();
            let case_id = scalar_string(object.get("case_id")).unwrap_or_default();
            let pairs = [
                ("alert_id", alert_id.clone()),
                ("severity", severity.clone()),
                ("status", status.clone()),
                ("observed_at", observed_at.clone()),
                ("created_at", created_at.clone()),
                ("updated_at", updated_at.clone()),
                ("closed_at", closed_at.clone()),
                ("resolved_at", resolved_at.clone()),
                ("case_id", case_id.clone()),
            ];
            let canonical = [
                ("alert_id", alert_id.clone()),
                ("severity", severity),
                ("status", status),
                ("title", title),
                ("observed_at", observed_at),
                ("created_at", created_at),
                ("updated_at", updated_at),
                ("closed_at", closed_at),
                ("resolved_at", resolved_at),
                ("case_id", case_id),
            ];
            (
                format!("alert-{alert_id}"),
                occurred_at,
                attributes(pairs),
                canonical.into_iter().collect::<BTreeMap<_, _>>(),
            )
        }
        PanopticonFamily::Case => {
            let case_id = required_scalar(object, "case_id", true)?;
            let status = first_nonblank([
                nested_scalar(object, "state", "state_name"),
                scalar_string(object.get("status")),
                scalar_string(object.get("status_id")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let title = first_nonblank([
                scalar_string(object.get("case_name")),
                scalar_string(object.get("name")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let occurred_at = first_time(object, &["initial_date", "open_date", "close_date"])
                .ok_or(PanopticonError::MissingOccurredAt)?;
            let created_at = first_nonblank([
                scalar_string(object.get("created_at")),
                scalar_string(object.get("initial_date")),
                scalar_string(object.get("open_date")),
            ])
            .unwrap_or_default();
            let updated_at = first_nonblank([
                scalar_string(object.get("updated_at")),
                scalar_string(object.get("last_updated_at")),
                scalar_string(object.get("modified_at")),
            ])
            .unwrap_or_default();
            let closed_at = first_nonblank([
                scalar_string(object.get("closed_at")),
                scalar_string(object.get("close_date")),
            ])
            .unwrap_or_default();
            let resolved_at = first_nonblank([
                scalar_string(object.get("resolved_at")),
                scalar_string(object.get("resolved_date")),
            ])
            .unwrap_or_default();
            let pairs = [
                ("case_id", case_id.clone()),
                ("status", status.clone()),
                ("created_at", created_at.clone()),
                ("updated_at", updated_at.clone()),
                ("closed_at", closed_at.clone()),
                ("resolved_at", resolved_at.clone()),
            ];
            let canonical = [
                ("case_id", case_id.clone()),
                ("status", status),
                ("title", title),
                ("created_at", created_at),
                ("updated_at", updated_at),
                ("closed_at", closed_at),
                ("resolved_at", resolved_at),
            ];
            (
                format!("case-{case_id}"),
                occurred_at,
                attributes(pairs),
                canonical.into_iter().collect::<BTreeMap<_, _>>(),
            )
        }
        PanopticonFamily::Ioc => {
            let ioc_id = required_scalar(object, "ioc_id", true)?;
            let ioc_type = first_nonblank([
                nested_scalar(object, "ioc_type", "type_name"),
                scalar_string(object.get("ioc_type")),
                scalar_string(object.get("ioc_type_id")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let value = first_nonblank([
                scalar_string(object.get("ioc_value")),
                scalar_string(object.get("value")),
            ])
            .ok_or(PanopticonError::MissingRequiredField)?;
            let occurred_at = fallback_occurred_at
                .and_then(normalized_time)
                .ok_or(PanopticonError::MissingOccurredAt)?;
            let pairs = [
                ("ioc_id", ioc_id.clone()),
                ("ioc_type", ioc_type.clone()),
                ("value", value.clone()),
            ];
            (
                format!("ioc-{ioc_id}"),
                occurred_at,
                attributes(pairs.clone()),
                pairs.into_iter().collect::<BTreeMap<_, _>>(),
            )
        }
    };
    let mut payload = payload;
    let payload_object = payload
        .as_object_mut()
        .ok_or(PanopticonError::InvalidResponse)?;
    for (key, value) in canonical {
        payload_object.insert(key.to_owned(), Value::String(value));
    }
    Ok(PanopticonRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        provider_id,
        occurred_at,
        fields,
        payload,
    })
}

fn required_scalar(
    object: &Map<String, Value>,
    key: &str,
    identity: bool,
) -> Result<String, PanopticonError> {
    scalar_string(object.get(key))
        .filter(|value| !value.is_empty())
        .ok_or(if identity {
            PanopticonError::MissingRecordIdentity
        } else {
            PanopticonError::MissingRequiredField
        })
}

fn nested_scalar(object: &Map<String, Value>, key: &str, nested_key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_object)
        .and_then(|nested| scalar_string(nested.get(nested_key)))
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) | Value::Null => None,
    }
}

fn first_nonblank<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values.into_iter().flatten().find(|value| !value.is_empty())
}

fn attributes<const N: usize>(pairs: [(&str, String); N]) -> BTreeMap<String, String> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn first_time(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| scalar_string(object.get(*key)).and_then(|value| normalized_time(&value)))
}

fn normalized_time(value: &str) -> Option<String> {
    parsed_time(value).map(|_| value.trim().to_owned())
}

fn parsed_time(value: &str) -> Option<OffsetDateTime> {
    let value = value.trim();
    OffsetDateTime::parse(value, &Rfc3339).ok().or_else(|| {
        for pattern in [
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]",
            "[year]-[month]-[day]T[hour]:[minute]:[second]",
        ] {
            let format = format_description::parse_borrowed::<2>(pattern).ok()?;
            if let Ok(parsed) = PrimitiveDateTime::parse(value, &format) {
                return Some(parsed.assume_utc());
            }
        }
        let format = format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?;
        Date::parse(value, &format)
            .ok()
            .map(|date| date.midnight().assume_utc())
    })
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

const fn is_zero(value: &usize) -> bool {
    *value == 0
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page(outcome: PanopticonOutcome) -> PanopticonPage {
        match outcome {
            PanopticonOutcome::Page(page) => page,
            PanopticonOutcome::Request(_) => panic!("expected completed page"),
        }
    }

    fn request(outcome: PanopticonOutcome) -> PanopticonRequest {
        match outcome {
            PanopticonOutcome::Request(request) => request,
            PanopticonOutcome::Page(_) => panic!("expected follow-up request"),
        }
    }

    #[test]
    fn alert_plan_and_decode_match_go_contract() {
        let kernel = PanopticonKernel::new(
            "https://panopticon.example.com",
            PanopticonFamily::Alert,
            None,
            Some(25),
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.url().path(), "/api/v2/alerts");
        assert_eq!(request.url().query(), Some("page=1&per_page=25&sort=asc"));
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.user_agent(), USER_AGENT);
        let body = serde_json::to_vec(&json!({
            "current_page": 1,
            "next_page": 2,
            "data": [{
                "alert_id": 7,
                "alert_title": "Suspicious activity",
                "alert_source_event_time": "2026-06-08T12:00:00Z",
                "severity": {"severity_name": "high"},
                "status": {"status_name": "open"},
                "case_id": "case-4"
            }]
        }))
        .unwrap();
        let page = page(kernel.decode(&request, &body).unwrap());
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.provider_id, "alert-7");
        assert_eq!(record.provider_kind, "panopticon.alert");
        assert_eq!(record.schema_ref, "panopticon/alert/v1");
        assert_eq!(
            record.fields.get("severity").map(String::as_str),
            Some("high")
        );
        assert_eq!(record.fields.get("closed_at").map(String::as_str), Some(""));
        assert_eq!(record.payload["status"], "open");
        assert_eq!(page.watermark.as_deref(), Some("2026-06-08T12:00:00Z"));
        let next = kernel.plan(page.next_cursor.as_deref()).unwrap();
        assert_eq!(next.url().query(), Some("page=2&per_page=25&sort=asc"));
    }

    #[test]
    fn case_payload_preserves_evidence_and_canonical_fields() {
        let kernel = PanopticonKernel::new(
            "https://panopticon.example.com",
            PanopticonFamily::Case,
            Some("/custom/cases"),
            None,
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            request.url().query(),
            Some("page=1&per_page=100&order_by=case_id&sort_dir=asc")
        );
        let body = serde_json::to_vec(&json!({
            "current_page": 1,
            "next_page": null,
            "data": [{
                "case_id": "88",
                "case_name": "Incident case",
                "initial_date": "2026-06-08T12:00:00",
                "state": {"state_name": "investigating"},
                "evidence": [{"evidence_id":"evidence-1","sha256":"sha256:abc"}]
            }]
        }))
        .unwrap();
        let page = page(kernel.decode(&request, &body).unwrap());
        let record = &page.records[0];
        assert_eq!(record.provider_id, "case-88");
        assert_eq!(
            record.fields.get("status").map(String::as_str),
            Some("investigating")
        );
        assert_eq!(record.payload["title"], "Incident case");
        assert_eq!(record.payload["evidence"][0]["evidence_id"], "evidence-1");
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn ioc_fanout_tracks_case_and_ioc_pages() {
        let kernel = PanopticonKernel::new(
            "https://panopticon.example.com",
            PanopticonFamily::Ioc,
            None,
            Some(10),
        )
        .unwrap();
        let cases = kernel.plan(None).unwrap();
        assert_eq!(cases.url().path(), "/api/v2/cases");
        let cases_body = serde_json::to_vec(&json!({
            "current_page": 1,
            "next_page": 2,
            "data": [{
                "case_id": "case/1",
                "initial_date": "2026-06-08T12:00:00Z"
            }]
        }))
        .unwrap();
        let iocs = request(kernel.decode(&cases, &cases_body).unwrap());
        assert_eq!(iocs.url().path(), "/api/v2/cases/case%2F1/iocs");
        assert_eq!(
            iocs.url().query(),
            Some("page=1&per_page=10&order_by=case_id&sort_dir=asc")
        );
        let ioc_body = serde_json::to_vec(&json!({
            "current_page": 1,
            "next_page": true,
            "data": [{
                "ioc_id": "7",
                "ioc_value": "evil.example",
                "ioc_type": {"type_name": "domain"}
            }]
        }))
        .unwrap();
        let first = page(kernel.decode(&iocs, &ioc_body).unwrap());
        assert_eq!(first.records[0].provider_id, "ioc-7");
        assert_eq!(first.records[0].occurred_at, "2026-06-08T12:00:00Z");
        let cases_again = kernel.plan(first.next_cursor.as_deref()).unwrap();
        let iocs_again = request(kernel.decode(&cases_again, &cases_body).unwrap());
        assert!(iocs_again.url().query().unwrap().starts_with("page=2&"));
        let last_body = br#"{"current_page":2,"next_page":null,"data":[]}"#;
        let next_cases = request(kernel.decode(&iocs_again, last_body).unwrap());
        assert!(next_cases.url().query().unwrap().starts_with("page=2&"));
    }

    #[test]
    fn invalid_scope_and_records_fail_closed() {
        assert!(
            PanopticonKernel::new(
                "http://provider.example",
                PanopticonFamily::Alert,
                None,
                None
            )
            .is_err()
        );
        assert!(
            PanopticonKernel::new(
                "https://provider.example",
                PanopticonFamily::Alert,
                Some("https://other.example/x"),
                None
            )
            .is_err()
        );
        assert!(
            PanopticonKernel::new(
                "https://provider.example",
                PanopticonFamily::Alert,
                None,
                Some(1_001)
            )
            .is_err()
        );
        let alert = PanopticonKernel::new(
            "https://provider.example",
            PanopticonFamily::Alert,
            None,
            None,
        )
        .unwrap();
        let request = alert.plan(None).unwrap();
        let invalid = br#"{"data":[{"alert_id":"1"}]}"#;
        assert_eq!(
            alert.decode(&request, invalid),
            Err(PanopticonError::MissingRequiredField)
        );
        let cases = PanopticonKernel::new(
            "https://provider.example",
            PanopticonFamily::Case,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            cases.decode(&request, br#"{"data":[]}"#),
            Err(PanopticonError::RequestScopeMismatch)
        );
        let too_many = serde_json::to_vec(&json!({
            "data": (0..=MAX_RECORDS_PER_PAGE)
                .map(|id| json!({"alert_id": id}))
                .collect::<Vec<_>>()
        }))
        .unwrap();
        assert_eq!(
            alert.decode(&request, &too_many),
            Err(PanopticonError::TooManyRecords)
        );
    }

    #[test]
    fn family_and_legacy_cursor_contracts_are_explicit() {
        assert_eq!("alert".parse(), Ok(PanopticonFamily::Alert));
        assert_eq!("ioc".parse(), Ok(PanopticonFamily::Ioc));
        assert_eq!(
            "finding".parse::<PanopticonFamily>(),
            Err(PanopticonError::InvalidFamily)
        );
        let kernel = PanopticonKernel::new(
            "https://provider.example",
            PanopticonFamily::Case,
            None,
            None,
        )
        .unwrap();
        assert!(
            kernel
                .plan(Some("9"))
                .unwrap()
                .url()
                .query()
                .unwrap()
                .starts_with("page=9&")
        );
        assert_eq!(kernel.plan(Some("{}")), Err(PanopticonError::InvalidCursor));
    }
}
