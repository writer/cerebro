use std::{net::IpAddr, str::FromStr};

use reqwest::Url;
use sha2::{Digest, Sha256};

use super::{
    cursor::{bounded_provider_cursor, decode_application_cursor, encode_application_cursor},
    model::{
        ApplicationCursor, RequestStage, SentinelOneError, SentinelOneFamily, SentinelOneFilters,
        SentinelOneOutcome, SentinelOnePage, SentinelOneRequest,
    },
    response::{application_identity, decode_list, nonempty, normalize_record, scalar_string},
};

const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

/// Provider-specific SentinelOne request and response state machine.
#[derive(Clone, Debug)]
pub struct SentinelOneKernel {
    base_url: Url,
    family: SentinelOneFamily,
    filters: SentinelOneFilters,
    page_size: usize,
    fingerprint: [u8; 32],
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
        let filters = trim_filters(filters);
        validate_filters(family, &filters)?;
        let fingerprint = kernel_fingerprint(base_url.as_str(), family, &filters, page_size);
        Ok(Self {
            base_url,
            family,
            filters,
            page_size,
            fingerprint,
        })
    }

    /// Plan the first credential-free request for one collection page.
    pub fn plan(&self, cursor: Option<&str>) -> Result<SentinelOneRequest, SentinelOneError> {
        if self.family != SentinelOneFamily::Application {
            let cursor = bounded_provider_cursor(cursor)?;
            return self.direct_request(cursor.as_deref());
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
        if request.family != self.family
            || request.url.origin() != self.base_url.origin()
            || request.kernel_fingerprint != self.fingerprint
        {
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
                SentinelOneFamily::Exclusion => {
                    if let Some(value) = self.filters.site_id.as_deref() {
                        query.append_pair("siteIds", value);
                    }
                }
                SentinelOneFamily::Application | SentinelOneFamily::Site => {}
            }
        }
        Ok(SentinelOneRequest {
            url,
            family: self.family,
            stage: RequestStage::Direct,
            application_state: None,
            kernel_fingerprint: self.fingerprint,
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
            kernel_fingerprint: self.fingerprint,
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
            kernel_fingerprint: self.fingerprint,
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

fn kernel_fingerprint(
    base_url: &str,
    family: SentinelOneFamily,
    filters: &SentinelOneFilters,
    page_size: usize,
) -> [u8; 32] {
    let page_size = page_size.to_string();
    let values = [
        base_url,
        family.as_str(),
        filters.site_id.as_deref().unwrap_or_default(),
        filters.group_id.as_deref().unwrap_or_default(),
        filters.agent_id.as_deref().unwrap_or_default(),
        filters.since.as_deref().unwrap_or_default(),
        filters.until.as_deref().unwrap_or_default(),
        filters.activity_type.as_deref().unwrap_or_default(),
        &page_size,
    ];
    let mut digest = Sha256::new();
    for value in values {
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}
