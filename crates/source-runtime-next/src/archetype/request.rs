use std::{net::IpAddr, str::FromStr};

use reqwest::Url;

use super::{ArchetypeError, ArchetypeFamily};

const DEFAULT_API_PREFIX: &str = "/api/v1";
pub(super) const SCAN_PAGE_LIMIT: usize = 100;
const DEFAULT_FANOUT_CONCURRENCY: usize = 4;
const MAX_FANOUT_CONCURRENCY: usize = 16;

/// Purpose of one credential-free Archetype request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchetypeRequestKind {
    /// Descending scan-page collection.
    Scans,
    /// Repository identity enrichment.
    Repositories,
    /// Vulnerability enrichment for one scan.
    Vulnerabilities,
    /// Knowledge enrichment for one repository.
    Knowledge,
}

/// One credential-free HTTP request planned by the Archetype kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeRequest {
    url: Url,
    kind: ArchetypeRequestKind,
    scoped_id: Option<u64>,
}

impl ArchetypeRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the portable purpose of this request.
    pub const fn kind(&self) -> ArchetypeRequestKind {
        self.kind
    }

    /// Return the scan or repository ID bound to an enrichment request.
    pub const fn scoped_id(&self) -> Option<u64> {
        self.scoped_id
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
/// Provider-specific Archetype request and response kernel.
#[derive(Clone, Debug)]
pub struct ArchetypeKernel {
    pub(super) base_url: Url,
    pub(super) api_prefix: String,
    pub(super) family: ArchetypeFamily,
    pub(super) fanout_concurrency: usize,
}

impl ArchetypeKernel {
    /// Build a kernel for one portable Archetype origin and family.
    ///
    /// The kernel never accepts a bearer token. Planned requests still require
    /// shared live-egress authorization and an operation-scoped credential.
    pub fn new(
        base_url: &str,
        api_prefix: Option<&str>,
        family: ArchetypeFamily,
        fanout_concurrency: Option<usize>,
    ) -> Result<Self, ArchetypeError> {
        let base_url = validate_origin(base_url)?;
        let api_prefix = validate_api_prefix(api_prefix.unwrap_or(DEFAULT_API_PREFIX))?;
        let fanout_concurrency = fanout_concurrency.unwrap_or(DEFAULT_FANOUT_CONCURRENCY);
        if !(1..=MAX_FANOUT_CONCURRENCY).contains(&fanout_concurrency) {
            return Err(ArchetypeError::InvalidFanoutConcurrency);
        }
        Ok(Self {
            base_url,
            api_prefix,
            family,
            fanout_concurrency,
        })
    }

    /// Return the bounded number of enrichment requests callers may run concurrently.
    pub const fn fanout_concurrency(&self) -> usize {
        self.fanout_concurrency
    }

    /// Plan one descending scan-page request.
    pub fn plan_scans(&self, before_id: Option<u64>) -> Result<ArchetypeRequest, ArchetypeError> {
        if before_id == Some(0) {
            return Err(ArchetypeError::InvalidScopedId);
        }
        let mut request = self.request("/scans", ArchetypeRequestKind::Scans, None)?;
        {
            let mut query = request.url.query_pairs_mut();
            query.append_pair("limit", &SCAN_PAGE_LIMIT.to_string());
            if let Some(before_id) = before_id {
                query.append_pair("before_id", &before_id.to_string());
            }
        }
        Ok(request)
    }

    /// Plan repository identity enrichment for a scan page.
    pub fn plan_repositories(&self) -> Result<ArchetypeRequest, ArchetypeError> {
        self.request("/repositories", ArchetypeRequestKind::Repositories, None)
    }

    /// Plan vulnerability enrichment for one positive scan ID.
    pub fn plan_vulnerabilities(&self, scan_id: u64) -> Result<ArchetypeRequest, ArchetypeError> {
        self.require_vulnerability_family()?;
        if scan_id == 0 {
            return Err(ArchetypeError::InvalidScopedId);
        }
        self.request(
            &format!("/scans/{scan_id}/vulnerabilities"),
            ArchetypeRequestKind::Vulnerabilities,
            Some(scan_id),
        )
    }

    /// Plan knowledge enrichment for one positive repository ID.
    pub fn plan_knowledge(&self, repository_id: u64) -> Result<ArchetypeRequest, ArchetypeError> {
        self.require_vulnerability_family()?;
        if repository_id == 0 {
            return Err(ArchetypeError::InvalidScopedId);
        }
        self.request(
            &format!("/repositories/{repository_id}/knowledge"),
            ArchetypeRequestKind::Knowledge,
            Some(repository_id),
        )
    }
    fn request(
        &self,
        suffix: &str,
        kind: ArchetypeRequestKind,
        scoped_id: Option<u64>,
    ) -> Result<ArchetypeRequest, ArchetypeError> {
        let path = format!("{}{suffix}", self.api_prefix);
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| ArchetypeError::InvalidApiPrefix)?;
        Ok(ArchetypeRequest {
            url,
            kind,
            scoped_id,
        })
    }

    pub(super) fn validate_request(
        &self,
        request: &ArchetypeRequest,
        kind: ArchetypeRequestKind,
        scoped_id: Option<u64>,
    ) -> Result<(), ArchetypeError> {
        if request.kind != kind
            || request.scoped_id != scoped_id
            || request.url.origin() != self.base_url.origin()
            || !request
                .url
                .path()
                .starts_with(&format!("{}/", self.api_prefix))
        {
            return Err(ArchetypeError::RequestScopeMismatch);
        }
        Ok(())
    }

    pub(super) fn require_vulnerability_family(&self) -> Result<(), ArchetypeError> {
        if self.family != ArchetypeFamily::Vulnerability {
            return Err(ArchetypeError::UnsupportedEnrichment);
        }
        Ok(())
    }
}
fn validate_origin(raw: &str) -> Result<Url, ArchetypeError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| ArchetypeError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(ArchetypeError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ArchetypeError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ArchetypeError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(ArchetypeError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(ArchetypeError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
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

fn validate_api_prefix(raw: &str) -> Result<String, ArchetypeError> {
    let value = raw.trim().trim_end_matches('/');
    if !value.starts_with('/')
        || value == "/"
        || value.contains(['?', '#', '\\', '%'])
        || value.contains("//")
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(ArchetypeError::InvalidApiPrefix);
    }
    Ok(value.to_owned())
}
