//! SentinelOne request, response, and application-fanout runtime kernel.
//!
//! SentinelOne exposes six directly paginated collection endpoints and one
//! application inventory endpoint that must first enumerate agents. This
//! module keeps that provider-specific state machine out of the generic HTTP
//! grammar while producing records that can cross the shared graph boundary.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const APPLICATION_CURSOR_PREFIX: &str = "cerebro-sentinelone-application-v1:";
const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

/// A SentinelOne runtime family with a provider-owned collection contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelOneFamily {
    /// Management-console and endpoint activity records.
    Activity,
    /// Managed endpoint agents.
    Agent,
    /// Installed applications collected through per-agent fanout.
    Application,
    /// Threat-detection exclusions.
    Exclusion,
    /// Endpoint groups.
    Group,
    /// Tenant sites.
    Site,
    /// Threat detections.
    Threat,
}

impl SentinelOneFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::Agent => "agent",
            Self::Application => "application",
            Self::Exclusion => "exclusion",
            Self::Group => "group",
            Self::Site => "site",
            Self::Threat => "threat",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Application => "sentinelone.application_inventory",
            Self::Activity => "sentinelone.activity",
            Self::Agent => "sentinelone.agent",
            Self::Exclusion => "sentinelone.exclusion",
            Self::Group => "sentinelone.group",
            Self::Site => "sentinelone.site",
            Self::Threat => "sentinelone.threat",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Activity => "/web/api/v2.1/activities",
            Self::Agent => "/web/api/v2.1/agents",
            Self::Application => "/web/api/v2.1/agents/applications",
            Self::Exclusion => "/web/api/v2.1/exclusions",
            Self::Group => "/web/api/v2.1/groups",
            Self::Site => "/web/api/v2.1/sites",
            Self::Threat => "/web/api/v2.1/threats",
        }
    }
}

impl FromStr for SentinelOneFamily {
    type Err = SentinelOneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "activity" => Ok(Self::Activity),
            "agent" => Ok(Self::Agent),
            "application" => Ok(Self::Application),
            "exclusion" => Ok(Self::Exclusion),
            "group" => Ok(Self::Group),
            "site" => Ok(Self::Site),
            "threat" => Ok(Self::Threat),
            _ => Err(SentinelOneError::InvalidFamily),
        }
    }
}

/// Optional provider filters accepted by SentinelOne collection families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SentinelOneFilters {
    /// Restrict agents, groups, threats, or activities to one site.
    pub site_id: Option<String>,
    /// Restrict agents or activities to one group.
    pub group_id: Option<String>,
    /// Restrict application inventory to one agent and skip agent discovery.
    pub agent_id: Option<String>,
    /// Inclusive provider timestamp lower bound for activity or threat reads.
    pub since: Option<String>,
    /// Inclusive provider timestamp upper bound for activity or threat reads.
    pub until: Option<String>,
    /// Restrict activity reads to one provider activity type.
    pub activity_type: Option<String>,
}

/// One credential-free HTTP request planned by the SentinelOne kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOneRequest {
    url: Url,
    family: SentinelOneFamily,
    stage: RequestStage,
    application_state: Option<ApplicationCursor>,
}

impl SentinelOneRequest {
    /// Return the exact provider URL. The caller must authorize this URL before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "ApiToken"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized provider record produced by the SentinelOne kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOneRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned identity, scoped by agent for applications.
    pub provider_id: String,
    /// Flattened scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider record, with no credentials added.
    pub payload: Value,
}

/// A bounded SentinelOne page and its opaque continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOnePage {
    /// Normalized records in provider order, or stable identity order for applications.
    pub records: Vec<SentinelOneRecord>,
    /// Provider or versioned fanout cursor for the next read.
    pub next_cursor: Option<String>,
}

/// Result of decoding one SentinelOne response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SentinelOneOutcome {
    /// Application collection resolved an agent and requires one bounded follow-up request.
    Request(SentinelOneRequest),
    /// The provider response completed one source-runtime page.
    Page(SentinelOnePage),
}

/// Provider-specific SentinelOne request and response state machine.
#[derive(Clone, Debug)]
pub struct SentinelOneKernel {
    base_url: Url,
    family: SentinelOneFamily,
    filters: SentinelOneFilters,
    page_size: usize,
}

impl SentinelOneKernel {
    /// Build a kernel for one SentinelOne origin and family.
    ///
    /// The returned request still requires the shared live-egress decision and
    /// operation-scoped credential lease before network access.
    pub fn new(
        base_url: &str,
        family: SentinelOneFamily,
        filters: SentinelOneFilters,
        page_size: Option<usize>,
    ) -> Result<Self, SentinelOneError> {
        let base_url = validate_origin(base_url)?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(SentinelOneError::InvalidPageSize);
        }
        validate_filters(family, &filters)?;
        Ok(Self {
            base_url,
            family,
            filters: trim_filters(filters),
            page_size,
        })
    }

    /// Plan the first credential-free request for one collection page.
    pub fn plan(&self, cursor: Option<&str>) -> Result<SentinelOneRequest, SentinelOneError> {
        let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
        if self.family != SentinelOneFamily::Application {
            return self.direct_request(cursor);
        }
        let (mut state, provider_cursor, encoded) = decode_application_cursor(cursor)?;
        if let Some(configured_agent) = self.filters.agent_id.as_deref() {
            if !encoded && cursor.is_some() {
                return Err(SentinelOneError::ConfiguredAgentCursor);
            }
            if !state.parent_id.is_empty() && state.parent_id != configured_agent {
                return Err(SentinelOneError::CursorParentMismatch);
            }
            state.parent_id = configured_agent.to_owned();
            state.next_parent_cursor.clear();
            return self.application_request(state);
        }
        if !state.parent_id.is_empty() {
            return self.application_request(state);
        }
        self.agent_discovery_request(provider_cursor.as_deref())
    }

    /// Decode a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &SentinelOneRequest,
        body: &[u8],
    ) -> Result<SentinelOneOutcome, SentinelOneError> {
        if request.family != self.family || request.url.origin() != self.base_url.origin() {
            return Err(SentinelOneError::RequestScopeMismatch);
        }
        match request.stage {
            RequestStage::Direct => self.decode_direct(body).map(SentinelOneOutcome::Page),
            RequestStage::ResolveAgent => self.decode_agent(body),
            RequestStage::Applications => self.decode_applications(request, body),
        }
    }

    fn direct_request(&self, cursor: Option<&str>) -> Result<SentinelOneRequest, SentinelOneError> {
        let mut url = self.endpoint(self.family.path())?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
            match self.family {
                SentinelOneFamily::Activity => {
                    if let Some(value) = self.filters.since.as_deref() {
                        query.append_pair("createdAt__gte", value);
                    }
                    if let Some(value) = self.filters.until.as_deref() {
                        query.append_pair("createdAt__lte", value);
                    }
                    if let Some(value) = self.filters.activity_type.as_deref() {
                        query.append_pair("activityTypes", value);
                    }
                    if let Some(value) = self.filters.site_id.as_deref() {
                        query.append_pair("siteIds", value);
                    }
                    if let Some(value) = self.filters.group_id.as_deref() {
                        query.append_pair("groupIds", value);
                    }
                }
                SentinelOneFamily::Threat => {
                    if let Some(value) = self.filters.since.as_deref() {
                        query.append_pair("createdAt__gte", value);
                    }
                    if let Some(value) = self.filters.until.as_deref() {
                        query.append_pair("createdAt__lte", value);
                    }
                    if let Some(value) = self.filters.site_id.as_deref() {
                        query.append_pair("siteIds", value);
                    }
                }
                SentinelOneFamily::Agent => {
                    if let Some(value) = self.filters.site_id.as_deref() {
                        query.append_pair("siteIds", value);
                    }
                    if let Some(value) = self.filters.group_id.as_deref() {
                        query.append_pair("groupIds", value);
                    }
                }
                SentinelOneFamily::Group => {
                    if let Some(value) = self.filters.site_id.as_deref() {
                        query.append_pair("siteIds", value);
                    }
                }
                SentinelOneFamily::Application
                | SentinelOneFamily::Exclusion
                | SentinelOneFamily::Site => {}
            }
        }
        Ok(SentinelOneRequest {
            url,
            family: self.family,
            stage: RequestStage::Direct,
            application_state: None,
        })
    }

    fn agent_discovery_request(
        &self,
        cursor: Option<&str>,
    ) -> Result<SentinelOneRequest, SentinelOneError> {
        let mut url = self.endpoint(SentinelOneFamily::Agent.path())?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", "1");
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
            if let Some(value) = self.filters.site_id.as_deref() {
                query.append_pair("siteIds", value);
            }
            if let Some(value) = self.filters.group_id.as_deref() {
                query.append_pair("groupIds", value);
            }
        }
        Ok(SentinelOneRequest {
            url,
            family: self.family,
            stage: RequestStage::ResolveAgent,
            application_state: None,
        })
    }

    fn application_request(
        &self,
        state: ApplicationCursor,
    ) -> Result<SentinelOneRequest, SentinelOneError> {
        if state.parent_id.is_empty() {
            return Err(SentinelOneError::CursorParentRequired);
        }
        let mut url = self.endpoint(SentinelOneFamily::Application.path())?;
        url.query_pairs_mut().append_pair("ids", &state.parent_id);
        Ok(SentinelOneRequest {
            url,
            family: self.family,
            stage: RequestStage::Applications,
            application_state: Some(state),
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, SentinelOneError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| SentinelOneError::InvalidBaseUrl)
    }

    fn decode_direct(&self, body: &[u8]) -> Result<SentinelOnePage, SentinelOneError> {
        let decoded = decode_list(body)?;
        let mut records = Vec::with_capacity(decoded.records.len());
        for payload in decoded.records {
            let provider_id = scalar_string(payload.get("id"))
                .filter(|value| !value.is_empty())
                .ok_or(SentinelOneError::MissingRecordIdentity)?;
            records.push(normalize_record(self.family, provider_id, payload, None));
        }
        Ok(SentinelOnePage {
            records,
            next_cursor: nonempty(decoded.next_cursor),
        })
    }

    fn decode_agent(&self, body: &[u8]) -> Result<SentinelOneOutcome, SentinelOneError> {
        let decoded = decode_list(body)?;
        let Some(agent) = decoded.records.first() else {
            return Ok(SentinelOneOutcome::Page(SentinelOnePage {
                records: Vec::new(),
                next_cursor: nonempty(decoded.next_cursor),
            }));
        };
        let parent_id = scalar_string(agent.get("id"))
            .filter(|value| !value.is_empty())
            .ok_or(SentinelOneError::MissingAgentIdentity)?;
        let state = ApplicationCursor {
            parent_id,
            next_parent_cursor: decoded.next_cursor,
            after_record_id: String::new(),
        };
        self.application_request(state)
            .map(SentinelOneOutcome::Request)
    }

    fn decode_applications(
        &self,
        request: &SentinelOneRequest,
        body: &[u8],
    ) -> Result<SentinelOneOutcome, SentinelOneError> {
        let mut state = request
            .application_state
            .clone()
            .ok_or(SentinelOneError::MissingApplicationState)?;
        let decoded = decode_list(body)?;
        let mut applications = decoded
            .records
            .into_iter()
            .map(|payload| {
                let application_id = application_identity(&payload);
                (application_id, payload)
            })
            .collect::<Vec<_>>();
        applications.sort_by(|left, right| left.0.cmp(&right.0));
        if applications
            .iter()
            .any(|(identity, _)| identity.trim().is_empty())
            || applications.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(SentinelOneError::DuplicateApplicationIdentity);
        }
        let start = applications
            .partition_point(|(identity, _)| identity.as_str() <= state.after_record_id.as_str());
        let end = start.saturating_add(self.page_size).min(applications.len());
        let total = applications.len();
        let mut records = Vec::with_capacity(end.saturating_sub(start));
        for (application_id, payload) in &applications[start..end] {
            let provider_id = format!("{}::{application_id}", state.parent_id);
            records.push(normalize_record(
                SentinelOneFamily::Application,
                provider_id,
                payload.clone(),
                Some(&state.parent_id),
            ));
        }
        let next_cursor = if end < total {
            let after_record_id = records
                .last()
                .and_then(|record| record.fields.get("application_id"))
                .cloned()
                .ok_or(SentinelOneError::MissingRecordIdentity)?;
            state.after_record_id = after_record_id;
            Some(encode_application_cursor(&state)?)
        } else {
            nonempty(state.next_parent_cursor)
        };
        Ok(SentinelOneOutcome::Page(SentinelOnePage {
            records,
            next_cursor,
        }))
    }
}

/// Safe SentinelOne kernel failures. Messages never include credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SentinelOneError {
    /// Family identifier is not one of the seven supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Page size is outside the provider's 1 through 200 bound.
    InvalidPageSize,
    /// A time filter was supplied to a family that does not support it.
    UnsupportedTimeFilter,
    /// An activity-type filter was supplied to a non-activity family.
    UnsupportedActivityFilter,
    /// A caller attempted to resume a configured agent with a provider cursor.
    ConfiguredAgentCursor,
    /// A versioned application cursor names a different configured agent.
    CursorParentMismatch,
    /// A versioned application cursor is malformed.
    InvalidCursor,
    /// A fanout cursor omitted its parent agent.
    CursorParentRequired,
    /// Response JSON does not match the SentinelOne list envelope.
    InvalidResponse,
    /// A provider record omitted its stable identity.
    MissingRecordIdentity,
    /// Agent discovery omitted the agent identity needed for fanout.
    MissingAgentIdentity,
    /// Application response decoding lost its request-bound fanout state.
    MissingApplicationState,
    /// Application inventory returned colliding stable identities for one agent.
    DuplicateApplicationIdentity,
    /// A request was decoded by a kernel configured for another family or origin.
    RequestScopeMismatch,
}

impl fmt::Display for SentinelOneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "sentinelone family is invalid",
            Self::InvalidBaseUrl => "sentinelone base URL must be a secure origin",
            Self::InvalidPageSize => "sentinelone page size must be between 1 and 200",
            Self::UnsupportedTimeFilter => {
                "sentinelone time filters require the activity or threat family"
            }
            Self::UnsupportedActivityFilter => {
                "sentinelone activity type filter requires the activity family"
            }
            Self::ConfiguredAgentCursor => {
                "sentinelone configured-agent reads reject provider cursors"
            }
            Self::CursorParentMismatch => {
                "sentinelone application cursor parent does not match configured agent"
            }
            Self::InvalidCursor => "sentinelone application cursor is invalid",
            Self::CursorParentRequired => "sentinelone application cursor parent is required",
            Self::InvalidResponse => "sentinelone response does not match the list contract",
            Self::MissingRecordIdentity => "sentinelone record identity is missing",
            Self::MissingAgentIdentity => "sentinelone agent identity is missing",
            Self::MissingApplicationState => "sentinelone application request state is missing",
            Self::DuplicateApplicationIdentity => {
                "sentinelone application identity is empty or duplicated"
            }
            Self::RequestScopeMismatch => {
                "sentinelone request family or origin does not match the kernel"
            }
        })
    }
}

impl Error for SentinelOneError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestStage {
    Direct,
    ResolveAgent,
    Applications,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct ApplicationCursor {
    parent_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    next_parent_cursor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    after_record_id: String,
}

struct DecodedList {
    records: Vec<Value>,
    next_cursor: String,
}

fn validate_origin(raw: &str) -> Result<Url, SentinelOneError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| SentinelOneError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(SentinelOneError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(SentinelOneError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(SentinelOneError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(SentinelOneError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(SentinelOneError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn validate_filters(
    family: SentinelOneFamily,
    filters: &SentinelOneFilters,
) -> Result<(), SentinelOneError> {
    if (nonblank(&filters.since).is_some() || nonblank(&filters.until).is_some())
        && !matches!(
            family,
            SentinelOneFamily::Activity | SentinelOneFamily::Threat
        )
    {
        return Err(SentinelOneError::UnsupportedTimeFilter);
    }
    if nonblank(&filters.activity_type).is_some() && family != SentinelOneFamily::Activity {
        return Err(SentinelOneError::UnsupportedActivityFilter);
    }
    Ok(())
}

fn trim_filters(filters: SentinelOneFilters) -> SentinelOneFilters {
    SentinelOneFilters {
        site_id: nonblank(&filters.site_id).map(str::to_owned),
        group_id: nonblank(&filters.group_id).map(str::to_owned),
        agent_id: nonblank(&filters.agent_id).map(str::to_owned),
        since: nonblank(&filters.since).map(str::to_owned),
        until: nonblank(&filters.until).map(str::to_owned),
        activity_type: nonblank(&filters.activity_type).map(str::to_owned),
    }
}

fn nonblank(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn decode_application_cursor(
    cursor: Option<&str>,
) -> Result<(ApplicationCursor, Option<String>, bool), SentinelOneError> {
    let Some(cursor) = cursor else {
        return Ok((ApplicationCursor::default(), None, false));
    };
    let Some(encoded) = cursor.strip_prefix(APPLICATION_CURSOR_PREFIX) else {
        return Ok((ApplicationCursor::default(), Some(cursor.to_owned()), false));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SentinelOneError::InvalidCursor)?;
    let mut state: ApplicationCursor =
        serde_json::from_slice(&bytes).map_err(|_| SentinelOneError::InvalidCursor)?;
    state.parent_id = state.parent_id.trim().to_owned();
    state.next_parent_cursor = state.next_parent_cursor.trim().to_owned();
    state.after_record_id = state.after_record_id.trim().to_owned();
    if state.parent_id.is_empty() {
        return Err(SentinelOneError::CursorParentRequired);
    }
    Ok((state, None, true))
}

fn encode_application_cursor(state: &ApplicationCursor) -> Result<String, SentinelOneError> {
    let payload = serde_json::to_vec(state).map_err(|_| SentinelOneError::InvalidCursor)?;
    Ok(format!(
        "{APPLICATION_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

fn decode_list(body: &[u8]) -> Result<DecodedList, SentinelOneError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| SentinelOneError::InvalidResponse)?;
    let object = root.as_object().ok_or(SentinelOneError::InvalidResponse)?;
    let data = object.get("data").unwrap_or(&Value::Null);
    let (records, nested_cursor) = records_from_data(data)?;
    let next_cursor = nested_cursor
        .or_else(|| cursor_from_object(object))
        .unwrap_or_default();
    Ok(DecodedList {
        records,
        next_cursor,
    })
}

fn records_from_data(data: &Value) -> Result<(Vec<Value>, Option<String>), SentinelOneError> {
    match data {
        Value::Null => Ok((Vec::new(), None)),
        Value::Array(records) => Ok((records.clone(), None)),
        Value::Object(object) => {
            let cursor = cursor_from_object(object);
            for key in [
                "activities",
                "agents",
                "applications",
                "exclusions",
                "groups",
                "sites",
                "threats",
                "items",
                "records",
                "data",
            ] {
                if let Some(Value::Array(records)) = object.get(key) {
                    return Ok((records.clone(), cursor));
                }
            }
            Err(SentinelOneError::InvalidResponse)
        }
        _ => Err(SentinelOneError::InvalidResponse),
    }
}

fn cursor_from_object(object: &Map<String, Value>) -> Option<String> {
    object
        .get("pagination")
        .and_then(Value::as_object)
        .and_then(|pagination| pagination.get("nextCursor"))
        .and_then(|value| scalar_string(Some(value)))
        .or_else(|| {
            object
                .get("nextCursor")
                .and_then(|value| scalar_string(Some(value)))
        })
        .and_then(nonempty)
}

fn normalize_record(
    family: SentinelOneFamily,
    provider_id: String,
    payload: Value,
    agent_id: Option<&str>,
) -> SentinelOneRecord {
    let mut fields = BTreeMap::new();
    flatten_scalars(None, &payload, &mut fields);
    if let Some(agent_id) = agent_id {
        fields.insert("agent_id".to_owned(), agent_id.to_owned());
        fields.insert("application_id".to_owned(), application_identity(&payload));
    }
    SentinelOneRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    }
}

fn flatten_scalars(prefix: Option<&str>, value: &Value, fields: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let path = prefix.map_or_else(|| key.clone(), |prefix| format!("{prefix}.{key}"));
                flatten_scalars(Some(&path), value, fields);
            }
        }
        Value::Array(_) | Value::Null => {}
        Value::Bool(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.to_string());
            }
        }
        Value::Number(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.to_string());
            }
        }
        Value::String(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.clone());
            }
        }
    }
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn application_identity(payload: &Value) -> String {
    let parts = ["publisher", "name", "version"]
        .into_iter()
        .filter_map(|field| scalar_string(payload.get(field)))
        .filter(|value| !value.is_empty())
        .map(|value| value.replace(' ', "_"))
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "unknown".to_owned()
    } else {
        parts.join("::")
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPLICATION_RESPONSE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/sentinelone/testdata/api/application/list_applications/response.json"
    ));

    fn kernel(family: SentinelOneFamily) -> SentinelOneKernel {
        SentinelOneKernel::new(
            "https://sentinelone.example.test",
            family,
            SentinelOneFilters::default(),
            Some(2),
        )
        .unwrap()
    }

    #[test]
    fn all_seven_families_plan_exact_provider_paths_and_auth_contract() {
        let cases = [
            (SentinelOneFamily::Activity, "/web/api/v2.1/activities"),
            (SentinelOneFamily::Agent, "/web/api/v2.1/agents"),
            (SentinelOneFamily::Application, "/web/api/v2.1/agents"),
            (SentinelOneFamily::Exclusion, "/web/api/v2.1/exclusions"),
            (SentinelOneFamily::Group, "/web/api/v2.1/groups"),
            (SentinelOneFamily::Site, "/web/api/v2.1/sites"),
            (SentinelOneFamily::Threat, "/web/api/v2.1/threats"),
        ];
        for (family, path) in cases {
            let request = kernel(family).plan(None).unwrap();
            assert_eq!(request.url().path(), path);
            assert_eq!(request.authorization_scheme(), "ApiToken");
            assert_eq!(request.accept(), "application/json");
        }
    }

    #[test]
    fn family_filters_and_provider_cursor_are_bound_to_the_request() {
        let kernel = SentinelOneKernel::new(
            "https://sentinelone.example.test",
            SentinelOneFamily::Activity,
            SentinelOneFilters {
                site_id: Some("site-1".to_owned()),
                group_id: Some("group-1".to_owned()),
                since: Some("2026-04-01T00:00:00Z".to_owned()),
                until: Some("2026-04-30T00:00:00Z".to_owned()),
                activity_type: Some("27".to_owned()),
                ..SentinelOneFilters::default()
            },
            Some(50),
        )
        .unwrap();
        let request = kernel.plan(Some("provider-next")).unwrap();
        let query = request
            .url()
            .query_pairs()
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("limit").map(String::as_str), Some("50"));
        assert_eq!(
            query.get("cursor").map(String::as_str),
            Some("provider-next")
        );
        assert_eq!(query.get("siteIds").map(String::as_str), Some("site-1"));
        assert_eq!(query.get("groupIds").map(String::as_str), Some("group-1"));
        assert_eq!(query.get("activityTypes").map(String::as_str), Some("27"));
    }

    #[test]
    fn direct_family_decodes_flexible_data_envelope_and_cursor() {
        let kernel = kernel(SentinelOneFamily::Threat);
        let request = kernel.plan(None).unwrap();
        let outcome = kernel
            .decode(
                &request,
                br#"{"data":{"threats":[{"id":"threat-1","threatInfo":{"incidentStatus":"unresolved"}}],"pagination":{"nextCursor":"next-1"}}}"#,
            )
            .unwrap();
        let SentinelOneOutcome::Page(page) = outcome else {
            panic!("expected page")
        };
        assert_eq!(page.next_cursor.as_deref(), Some("next-1"));
        assert_eq!(page.records[0].provider_id, "threat-1");
        assert_eq!(page.records[0].provider_kind, "sentinelone.threat");
        assert_eq!(
            page.records[0]
                .fields
                .get("threatInfo.incidentStatus")
                .map(String::as_str),
            Some("unresolved")
        );
    }

    #[test]
    fn genuine_application_response_preserves_agent_scoped_go_identity() {
        let kernel = SentinelOneKernel::new(
            "https://sentinelone.example.test",
            SentinelOneFamily::Application,
            SentinelOneFilters {
                agent_id: Some("agent-fixture-1".to_owned()),
                ..SentinelOneFilters::default()
            },
            Some(10),
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.url().path(), "/web/api/v2.1/agents/applications");
        assert_eq!(request.url().query(), Some("ids=agent-fixture-1"));
        let outcome = kernel.decode(&request, APPLICATION_RESPONSE).unwrap();
        let SentinelOneOutcome::Page(page) = outcome else {
            panic!("expected page")
        };
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        assert_eq!(
            page.records[0].provider_id,
            "agent-fixture-1::Example_Inc::Example_App::1.0.0"
        );
        assert_eq!(
            page.records[0]
                .fields
                .get("application_id")
                .map(String::as_str),
            Some("Example_Inc::Example_App::1.0.0")
        );
    }

    #[test]
    fn application_fanout_resolves_agent_and_bounds_children_with_versioned_cursor() {
        let kernel = kernel(SentinelOneFamily::Application);
        let resolve = kernel.plan(Some("agents-next-0")).unwrap();
        assert_eq!(resolve.url().query(), Some("limit=1&cursor=agents-next-0"));
        let next = kernel
            .decode(
                &resolve,
                br#"{"data":[{"id":"agent-1"}],"pagination":{"nextCursor":"agents-next-1"}}"#,
            )
            .unwrap();
        let SentinelOneOutcome::Request(applications) = next else {
            panic!("expected application request")
        };
        assert_eq!(applications.url().query(), Some("ids=agent-1"));
        let first = kernel
            .decode(
                &applications,
                br#"{"data":[{"name":"Zulu","publisher":"P","version":"1"},{"name":"Alpha","publisher":"P","version":"1"},{"name":"Middle","publisher":"P","version":"1"}]}"#,
            )
            .unwrap();
        let SentinelOneOutcome::Page(first) = first else {
            panic!("expected first page")
        };
        assert_eq!(
            first
                .records
                .iter()
                .map(|record| record.provider_id.as_str())
                .collect::<Vec<_>>(),
            vec!["agent-1::P::Alpha::1", "agent-1::P::Middle::1"]
        );
        let cursor = first.next_cursor.expect("versioned cursor");
        assert!(cursor.starts_with(APPLICATION_CURSOR_PREFIX));

        let resumed = kernel.plan(Some(&cursor)).unwrap();
        let second = kernel
            .decode(
                &resumed,
                br#"{"data":[{"name":"Zulu","publisher":"P","version":"1"},{"name":"Alpha","publisher":"P","version":"1"},{"name":"Middle","publisher":"P","version":"1"}]}"#,
            )
            .unwrap();
        let SentinelOneOutcome::Page(second) = second else {
            panic!("expected second page")
        };
        assert_eq!(second.records[0].provider_id, "agent-1::P::Zulu::1");
        assert_eq!(second.next_cursor.as_deref(), Some("agents-next-1"));
    }

    #[test]
    fn kernel_fails_closed_on_unsafe_origins_filters_cursors_and_duplicate_apps() {
        assert!(matches!(
            SentinelOneKernel::new(
                "http://169.254.169.254",
                SentinelOneFamily::Agent,
                SentinelOneFilters::default(),
                None,
            ),
            Err(SentinelOneError::InvalidBaseUrl)
        ));
        assert!(matches!(
            SentinelOneKernel::new(
                "https://sentinelone.example.test",
                SentinelOneFamily::Site,
                SentinelOneFilters {
                    since: Some("2026-04-01T00:00:00Z".to_owned()),
                    ..SentinelOneFilters::default()
                },
                None,
            ),
            Err(SentinelOneError::UnsupportedTimeFilter)
        ));
        assert!(matches!(
            kernel(SentinelOneFamily::Application)
                .plan(Some("cerebro-sentinelone-application-v1:not-base64")),
            Err(SentinelOneError::InvalidCursor)
        ));
        let agent_request = kernel(SentinelOneFamily::Agent).plan(None).unwrap();
        assert!(matches!(
            kernel(SentinelOneFamily::Threat).decode(&agent_request, br#"{"data":[]}"#),
            Err(SentinelOneError::RequestScopeMismatch)
        ));

        let kernel = SentinelOneKernel::new(
            "https://sentinelone.example.test",
            SentinelOneFamily::Application,
            SentinelOneFilters {
                agent_id: Some("agent-1".to_owned()),
                ..SentinelOneFilters::default()
            },
            None,
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        assert!(matches!(
            kernel.decode(
                &request,
                br#"{"data":[{"name":"App","publisher":"P","version":"1"},{"name":"App","publisher":"P","version":"1"}]}"#,
            ),
            Err(SentinelOneError::DuplicateApplicationIdentity)
        ));
    }
}
