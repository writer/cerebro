//! Archetype request, response, and enrichment-fanout runtime kernel.
//!
//! Archetype is a credentialed pull source. This module plans its portable
//! provider requests and decodes responses without performing network I/O,
//! accepting credential material, or owning durable checkpoint advancement.

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
    net::IpAddr,
    str::FromStr,
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

const DEFAULT_API_PREFIX: &str = "/api/v1";
const SCAN_PAGE_LIMIT: usize = 100;
const DEFAULT_FANOUT_CONCURRENCY: usize = 4;
const MAX_FANOUT_CONCURRENCY: usize = 16;

/// One Archetype source-catalog family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchetypeFamily {
    /// Scan lifecycle records only.
    Scan,
    /// Scan lifecycle, vulnerability, and repository knowledge records.
    Vulnerability,
}

impl ArchetypeFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Vulnerability => "vulnerability",
        }
    }
}

impl FromStr for ArchetypeFamily {
    type Err = ArchetypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "scan" => Ok(Self::Scan),
            "vulnerability" => Ok(Self::Vulnerability),
            _ => Err(ArchetypeError::InvalidFamily),
        }
    }
}

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

/// One decoded Archetype scan used to drive bounded enrichment fanout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeScan {
    /// Provider scan ID.
    pub id: u64,
    /// Provider repository ID attached to the scan.
    pub repository_id: u64,
    /// Provider scan lifecycle status.
    pub status: String,
    /// Go-compatible occurrence time precedence: completed, started, created.
    pub occurred_at: Option<String>,
    payload: Value,
}

/// One decoded repository identity used to enrich scan-derived records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeRepository {
    /// Provider repository ID.
    pub id: u64,
    /// Repository owner name.
    pub owner: String,
    /// Repository name.
    pub name: String,
}

/// Availability of the vulnerability fanout for one emitted scan record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VulnerabilityCollectionState {
    /// The scan-only family did not request vulnerabilities.
    NotRequested,
    /// The provider reported that retained scan results are unavailable.
    Unavailable,
    /// The vulnerability request completed successfully.
    Complete,
}

impl VulnerabilityCollectionState {
    /// Return the Go-compatible scan attribute value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Unavailable => "unavailable",
            Self::Complete => "complete",
        }
    }
}

/// One normalized Archetype record ready for the shared source mapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypeRecord {
    /// Source-catalog family that requested the record.
    pub family: String,
    /// Go-compatible emitted event kind.
    pub provider_kind: String,
    /// Go-compatible stable event identity.
    pub provider_id: String,
    /// Selected provider occurrence timestamp, when present.
    pub occurred_at: Option<String>,
    /// Portable scalar attributes used by source projection.
    pub fields: BTreeMap<String, String>,
    /// Provider payload with Go-compatible fallback enrichment applied.
    pub payload: Value,
}

/// One decoded descending scan page and its provider pagination hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchetypePage {
    /// Scans sorted by ascending provider ID to match Go event order.
    pub scans: Vec<ArchetypeScan>,
    /// Oldest scan ID for the next `before_id` request when this page is full.
    pub next_before_id: Option<u64>,
}

/// Provider-specific Archetype request and response kernel.
#[derive(Clone, Debug)]
pub struct ArchetypeKernel {
    base_url: Url,
    api_prefix: String,
    family: ArchetypeFamily,
    fanout_concurrency: usize,
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

    /// Decode and order one scan response without advancing a durable checkpoint.
    pub fn decode_scans(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
    ) -> Result<ArchetypePage, ArchetypeError> {
        self.validate_request(request, ArchetypeRequestKind::Scans, None)?;
        let raw: Vec<ScanResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let page_is_full = raw.len() == SCAN_PAGE_LIMIT;
        if raw.len() > SCAN_PAGE_LIMIT {
            return Err(ArchetypeError::ResponseLimitExceeded);
        }
        let mut scans = raw
            .into_iter()
            .map(scan_from_response)
            .collect::<Result<Vec<_>, _>>()?;
        scans.sort_by_key(|scan| scan.id);
        if scans.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ArchetypeError::DuplicateRecordIdentity);
        }
        let next_before_id = page_is_full && !scans.is_empty();
        Ok(ArchetypePage {
            next_before_id: next_before_id.then(|| scans[0].id),
            scans,
        })
    }

    /// Decode repository identity enrichment into an ID-indexed map.
    pub fn decode_repositories(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
    ) -> Result<BTreeMap<u64, ArchetypeRepository>, ArchetypeError> {
        self.validate_request(request, ArchetypeRequestKind::Repositories, None)?;
        let raw: Vec<RepositoryResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut repositories = BTreeMap::new();
        for repository in raw {
            if repository.id == 0 {
                return Err(ArchetypeError::MissingRecordIdentity);
            }
            let repository = ArchetypeRepository {
                id: repository.id,
                owner: repository.owner,
                name: repository.name,
            };
            if repositories.insert(repository.id, repository).is_some() {
                return Err(ArchetypeError::DuplicateRecordIdentity);
            }
        }
        Ok(repositories)
    }

    /// Normalize a scan after its vulnerability collection state is known.
    pub fn scan_record(
        &self,
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
        collection_state: VulnerabilityCollectionState,
    ) -> Result<ArchetypeRecord, ArchetypeError> {
        match (self.family, collection_state) {
            (ArchetypeFamily::Scan, VulnerabilityCollectionState::NotRequested)
            | (ArchetypeFamily::Vulnerability, VulnerabilityCollectionState::Unavailable)
            | (ArchetypeFamily::Vulnerability, VulnerabilityCollectionState::Complete) => {}
            _ => return Err(ArchetypeError::CollectionStateMismatch),
        }
        let mut fields = compact([
            ("scan_id", scan.id.to_string()),
            ("repository_id", scan.repository_id.to_string()),
            ("status", scan.status.clone()),
            ("source_product", "archetype".to_owned()),
            (
                "vulnerability_collection_state",
                collection_state.as_str().to_owned(),
            ),
        ]);
        add_repository_fields(&mut fields, repository);
        Ok(ArchetypeRecord {
            family: self.family.as_str().to_owned(),
            provider_kind: "archetype.scan".to_owned(),
            provider_id: format!("archetype-scan-{}", scan.id),
            occurred_at: scan.occurred_at.clone(),
            fields,
            payload: scan.payload.clone(),
        })
    }

    /// Decode and normalize vulnerabilities for the exact request-bound scan.
    pub fn decode_vulnerabilities(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
    ) -> Result<Vec<ArchetypeRecord>, ArchetypeError> {
        self.require_vulnerability_family()?;
        self.validate_request(
            request,
            ArchetypeRequestKind::Vulnerabilities,
            Some(scan.id),
        )?;
        let raw: Vec<VulnerabilityResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut identities = HashSet::new();
        raw.into_iter()
            .map(|vulnerability| {
                if vulnerability.id == 0 || vulnerability.scan_id == 0 {
                    return Err(ArchetypeError::MissingRecordIdentity);
                }
                if vulnerability.scan_id != scan.id {
                    return Err(ArchetypeError::ResponseScopeMismatch);
                }
                if !identities.insert(vulnerability.id) {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                let payload = serde_json::to_value(&vulnerability)
                    .map_err(|_| ArchetypeError::InvalidResponse)?;
                let mut fields = compact([
                    ("vulnerability_id", vulnerability.id.to_string()),
                    ("scan_id", vulnerability.scan_id.to_string()),
                    ("repository_id", scan.repository_id.to_string()),
                    ("severity", vulnerability.severity.clone()),
                    ("category", vulnerability.category.clone()),
                    ("file_path", vulnerability.file_path.clone()),
                    ("line_number", vulnerability.line_number.to_string()),
                    ("source_product", "archetype".to_owned()),
                ]);
                add_repository_fields(&mut fields, repository);
                Ok(ArchetypeRecord {
                    family: self.family.as_str().to_owned(),
                    provider_kind: "archetype.vulnerability".to_owned(),
                    provider_id: format!(
                        "archetype-vulnerability-{}-{}",
                        scan.id, vulnerability.id
                    ),
                    occurred_at: normalized_timestamp(&vulnerability.created_at)
                        .or_else(|| scan.occurred_at.clone()),
                    fields,
                    payload,
                })
            })
            .collect()
    }

    /// Decode and normalize repository knowledge for the request-bound scan.
    pub fn decode_knowledge(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
    ) -> Result<Vec<ArchetypeRecord>, ArchetypeError> {
        self.require_vulnerability_family()?;
        self.validate_request(
            request,
            ArchetypeRequestKind::Knowledge,
            Some(scan.repository_id),
        )?;
        let response: KnowledgeResponse =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut identities = HashSet::new();
        let mut records = Vec::new();
        for mut entry in response.entries {
            entry.slug = entry.slug.trim().to_owned();
            if entry.repository_id == 0 {
                entry.repository_id = scan.repository_id;
            }
            if entry.owner.trim().is_empty() {
                entry.owner = repository
                    .map_or("", |value| value.owner.as_str())
                    .to_owned();
            }
            if entry.repository_name.trim().is_empty() {
                entry.repository_name = repository
                    .map_or("", |value| value.name.as_str())
                    .to_owned();
            }
            entry.owner = entry.owner.trim().to_owned();
            entry.repository_name = entry.repository_name.trim().to_owned();
            if entry.slug.is_empty() || entry.owner.is_empty() || entry.repository_name.is_empty() {
                continue;
            }
            let identity = format!(
                "archetype-library-{}-{}",
                entry.repository_id,
                query_escape(&entry.slug)
            );
            if !identities.insert(identity.clone()) {
                return Err(ArchetypeError::DuplicateRecordIdentity);
            }
            let payload =
                serde_json::to_value(&entry).map_err(|_| ArchetypeError::InvalidResponse)?;
            let mut fields = compact([
                ("knowledge_slug", entry.slug.clone()),
                ("title", entry.title.clone()),
                ("scan_id", scan.id.to_string()),
                ("repository_id", entry.repository_id.to_string()),
                ("dominant_severity", entry.dominant_severity.clone()),
                ("topics", entry.topics.join(",")),
                ("generated_at", entry.generated_at.clone()),
                ("source_files", entry.source_files.join(",")),
                ("owner", entry.owner.clone()),
                ("repo", entry.repository_name.clone()),
            ]);
            for key in [
                "context_pack",
                "context_kind",
                "health_score",
                "freshness_state",
                "recommended_depth",
                "evidence_plane",
                "state_store",
                "context_stale",
                "needs_learning",
            ] {
                if let Some(value) = metadata_string(&entry.metadata, key) {
                    fields.insert(key.to_owned(), value);
                }
            }
            records.push(ArchetypeRecord {
                family: self.family.as_str().to_owned(),
                provider_kind: "archetype.library_note".to_owned(),
                provider_id: identity,
                occurred_at: scan.occurred_at.clone(),
                fields,
                payload,
            });
        }
        Ok(records)
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

    fn validate_request(
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

    fn require_vulnerability_family(&self) -> Result<(), ArchetypeError> {
        if self.family != ArchetypeFamily::Vulnerability {
            return Err(ArchetypeError::UnsupportedEnrichment);
        }
        Ok(())
    }
}

/// Safe Archetype kernel failures. Messages never include credentials or response bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchetypeError {
    /// Family identifier is not one of the two supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// API prefix is not a normalized absolute request path.
    InvalidApiPrefix,
    /// Fanout concurrency is outside the Go-compatible 1 through 16 bound.
    InvalidFanoutConcurrency,
    /// A scan or repository scope ID is zero.
    InvalidScopedId,
    /// Response JSON does not match the selected Archetype contract.
    InvalidResponse,
    /// The provider returned more scans than the fixed page limit.
    ResponseLimitExceeded,
    /// A provider record omitted its stable positive identity.
    MissingRecordIdentity,
    /// One response contains colliding stable provider identities.
    DuplicateRecordIdentity,
    /// A response record belongs to a different request-bound scan.
    ResponseScopeMismatch,
    /// A request was decoded by a kernel for another origin, purpose, or scope.
    RequestScopeMismatch,
    /// Vulnerability or knowledge fanout was requested for the scan-only family.
    UnsupportedEnrichment,
    /// Scan collection state does not match the configured family.
    CollectionStateMismatch,
}

impl fmt::Display for ArchetypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "archetype family is invalid",
            Self::InvalidBaseUrl => "archetype base URL must be a secure origin",
            Self::InvalidApiPrefix => "archetype API prefix is invalid",
            Self::InvalidFanoutConcurrency => {
                "archetype fanout concurrency must be between 1 and 16"
            }
            Self::InvalidScopedId => "archetype request scope ID must be positive",
            Self::InvalidResponse => "archetype response does not match the selected contract",
            Self::ResponseLimitExceeded => "archetype scan response exceeds the page limit",
            Self::MissingRecordIdentity => "archetype record identity is missing",
            Self::DuplicateRecordIdentity => "archetype record identity is duplicated",
            Self::ResponseScopeMismatch => {
                "archetype response record does not match the requested scan"
            }
            Self::RequestScopeMismatch => {
                "archetype request origin, purpose, prefix, or scope does not match the kernel"
            }
            Self::UnsupportedEnrichment => "archetype enrichment requires the vulnerability family",
            Self::CollectionStateMismatch => {
                "archetype vulnerability collection state does not match the family"
            }
        })
    }
}

impl Error for ArchetypeError {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct ScanResponse {
    id: u64,
    repository_id: u64,
    status: String,
    started_at: String,
    completed_at: String,
    created_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct RepositoryResponse {
    id: u64,
    owner: String,
    name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct VulnerabilityResponse {
    id: u64,
    scan_id: u64,
    line_number: u64,
    file_path: String,
    category: String,
    severity: String,
    description: String,
    analyzer_score: f64,
    analyzer_label: String,
    created_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct KnowledgeEntryResponse {
    slug: String,
    title: String,
    summary: String,
    topics: Vec<String>,
    generated_at: String,
    source_files: Vec<String>,
    metadata: BTreeMap<String, Value>,
    severity_tags: Vec<String>,
    dominant_severity: String,
    severity_breakdown: Vec<Value>,
    repository_id: u64,
    repository_name: String,
    owner: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct KnowledgeResponse {
    entries: Vec<KnowledgeEntryResponse>,
}

fn scan_from_response(scan: ScanResponse) -> Result<ArchetypeScan, ArchetypeError> {
    if scan.id == 0 || scan.repository_id == 0 {
        return Err(ArchetypeError::MissingRecordIdentity);
    }
    let occurred_at = [
        scan.completed_at.as_str(),
        scan.started_at.as_str(),
        scan.created_at.as_str(),
    ]
    .into_iter()
    .find_map(normalized_timestamp);
    let payload = serde_json::to_value(&scan).map_err(|_| ArchetypeError::InvalidResponse)?;
    Ok(ArchetypeScan {
        id: scan.id,
        repository_id: scan.repository_id,
        status: scan.status,
        occurred_at,
        payload,
    })
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

fn compact<const N: usize>(values: [(&str, String); N]) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| (!value.trim().is_empty()).then(|| (key.to_owned(), value)))
        .collect()
}

fn add_repository_fields(
    fields: &mut BTreeMap<String, String>,
    repository: Option<&ArchetypeRepository>,
) {
    if let Some(repository) = repository {
        if !repository.owner.trim().is_empty() {
            fields.insert("owner".to_owned(), repository.owner.clone());
        }
        if !repository.name.trim().is_empty() {
            fields.insert("repo".to_owned(), repository.name.clone());
        }
    }
}

fn metadata_string(metadata: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    match metadata.get(key)? {
        Value::String(value) => nonblank(value).map(str::to_owned),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn normalized_timestamp(value: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339).ok()?;
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn query_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(char::from(*byte));
            }
            b' ' => escaped.push('+'),
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(family: ArchetypeFamily) -> ArchetypeKernel {
        ArchetypeKernel::new("https://archetype.example.test", None, family, None).unwrap()
    }

    fn scan(kernel: &ArchetypeKernel) -> ArchetypeScan {
        let request = kernel.plan_scans(None).unwrap();
        kernel
            .decode_scans(
                &request,
                br#"[{"id":9,"repository_id":7,"status":"completed","completed_at":"2026-08-20T01:02:03Z"}]"#,
            )
            .unwrap()
            .scans
            .remove(0)
    }

    #[test]
    fn plans_the_go_pull_routes_without_credentials() {
        let kernel = ArchetypeKernel::new(
            "https://archetype.example.test",
            Some("/api/v1/"),
            ArchetypeFamily::Vulnerability,
            Some(16),
        )
        .unwrap();
        let scans = kernel.plan_scans(Some(106)).unwrap();
        assert_eq!(scans.url().path(), "/api/v1/scans");
        assert_eq!(scans.url().query(), Some("limit=100&before_id=106"));
        assert_eq!(scans.authorization_scheme(), "Bearer");
        assert_eq!(scans.accept(), "application/json");
        assert_eq!(kernel.fanout_concurrency(), 16);
        assert_eq!(
            kernel.plan_repositories().unwrap().url().path(),
            "/api/v1/repositories"
        );
        assert_eq!(
            kernel.plan_vulnerabilities(9).unwrap().url().path(),
            "/api/v1/scans/9/vulnerabilities"
        );
        assert_eq!(
            kernel.plan_knowledge(7).unwrap().url().path(),
            "/api/v1/repositories/7/knowledge"
        );
    }

    #[test]
    fn scan_page_is_ascending_and_emits_go_compatible_record() {
        let kernel = kernel(ArchetypeFamily::Vulnerability);
        let request = kernel.plan_scans(None).unwrap();
        let page = kernel
            .decode_scans(
                &request,
                br#"[
                  {"id":9,"repository_id":7,"status":"completed","completed_at":"2026-08-20T01:02:03Z"},
                  {"id":8,"repository_id":7,"status":"running","started_at":"2026-08-20T01:01:00Z"}
                ]"#,
            )
            .unwrap();
        assert_eq!(
            page.scans.iter().map(|scan| scan.id).collect::<Vec<_>>(),
            [8, 9]
        );
        assert_eq!(page.next_before_id, None);
        let repository = ArchetypeRepository {
            id: 7,
            owner: "WriterInternal".to_owned(),
            name: "Archetype".to_owned(),
        };
        let record = kernel
            .scan_record(
                &page.scans[1],
                Some(&repository),
                VulnerabilityCollectionState::Complete,
            )
            .unwrap();
        assert_eq!(record.family, "vulnerability");
        assert_eq!(record.provider_kind, "archetype.scan");
        assert_eq!(record.provider_id, "archetype-scan-9");
        assert_eq!(record.occurred_at.as_deref(), Some("2026-08-20T01:02:03Z"));
        assert_eq!(
            record.fields.get("owner").map(String::as_str),
            Some("WriterInternal")
        );
        assert_eq!(
            record
                .fields
                .get("vulnerability_collection_state")
                .map(String::as_str),
            Some("complete")
        );
    }

    #[test]
    fn full_scan_page_exposes_the_oldest_id_without_owning_the_checkpoint() {
        let kernel = kernel(ArchetypeFamily::Scan);
        let request = kernel.plan_scans(None).unwrap();
        let body = serde_json::to_vec(
            &(1..=SCAN_PAGE_LIMIT)
                .rev()
                .map(|id| {
                    serde_json::json!({
                        "id": id,
                        "repository_id": 7,
                        "status": "completed"
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let page = kernel.decode_scans(&request, &body).unwrap();
        assert_eq!(page.scans.len(), SCAN_PAGE_LIMIT);
        assert_eq!(page.scans.first().map(|scan| scan.id), Some(1));
        assert_eq!(page.scans.last().map(|scan| scan.id), Some(100));
        assert_eq!(page.next_before_id, Some(1));
    }

    #[test]
    fn vulnerability_identity_is_scoped_to_the_request_scan() {
        let kernel = kernel(ArchetypeFamily::Vulnerability);
        let scan = scan(&kernel);
        let request = kernel.plan_vulnerabilities(scan.id).unwrap();
        let records = kernel
            .decode_vulnerabilities(
                &request,
                br#"[{"id":1,"scan_id":9,"line_number":42,"file_path":"app/main.py","category":"ssrf","severity":"high","created_at":"2026-08-19T18:03:00-07:00"}]"#,
                &scan,
                None,
            )
            .unwrap();
        assert_eq!(records[0].provider_id, "archetype-vulnerability-9-1");
        assert_eq!(
            records[0].fields.get("line_number").map(String::as_str),
            Some("42")
        );
        assert_eq!(
            records[0].occurred_at.as_deref(),
            Some("2026-08-20T01:03:00Z")
        );

        let error = kernel
            .decode_vulnerabilities(&request, br#"[{"id":1,"scan_id":10}]"#, &scan, None)
            .unwrap_err();
        assert_eq!(error, ArchetypeError::ResponseScopeMismatch);
    }

    #[test]
    fn knowledge_uses_repository_fallbacks_and_go_query_escape_identity() {
        let kernel = kernel(ArchetypeFamily::Vulnerability);
        let scan = scan(&kernel);
        let repository = ArchetypeRepository {
            id: 7,
            owner: "WriterInternal".to_owned(),
            name: "Archetype".to_owned(),
        };
        let request = kernel.plan_knowledge(scan.repository_id).unwrap();
        let records = kernel
            .decode_knowledge(
                &request,
                br#"{"entries":[{"slug":"security:sql/injection","title":"SQL injection","summary":"context","topics":[" security ","sql"],"source_files":["state.json"],"metadata":{"context_pack":"repository_context_pack_v2","health_score":72,"context_stale":true}}]}"#,
                &scan,
                Some(&repository),
            )
            .unwrap();
        assert_eq!(
            records[0].provider_id,
            "archetype-library-7-security%3Asql%2Finjection"
        );
        assert_eq!(
            records[0].fields.get("owner").map(String::as_str),
            Some("WriterInternal")
        );
        assert_eq!(
            records[0].fields.get("topics").map(String::as_str),
            Some(" security ,sql")
        );
        assert_eq!(
            records[0].fields.get("health_score").map(String::as_str),
            Some("72")
        );
        assert_eq!(
            records[0].fields.get("context_stale").map(String::as_str),
            Some("true")
        );
        assert_eq!(records[0].payload["repository_id"], 7);
    }

    #[test]
    fn rejects_invalid_configuration_and_cross_kernel_requests() {
        assert_eq!(
            ArchetypeKernel::new(
                "http://archetype.example.test",
                None,
                ArchetypeFamily::Scan,
                None,
            )
            .unwrap_err(),
            ArchetypeError::InvalidBaseUrl
        );
        assert_eq!(
            ArchetypeKernel::new(
                "https://archetype.example.test",
                Some("api/v1"),
                ArchetypeFamily::Scan,
                None,
            )
            .unwrap_err(),
            ArchetypeError::InvalidApiPrefix
        );
        assert_eq!(
            ArchetypeKernel::new(
                "https://archetype.example.test",
                Some("/api/%2e%2e/private"),
                ArchetypeFamily::Scan,
                None,
            )
            .unwrap_err(),
            ArchetypeError::InvalidApiPrefix
        );
        assert_eq!(
            ArchetypeKernel::new(
                "https://archetype.example.test",
                None,
                ArchetypeFamily::Scan,
                Some(17),
            )
            .unwrap_err(),
            ArchetypeError::InvalidFanoutConcurrency
        );
        let scan_kernel = kernel(ArchetypeFamily::Scan);
        assert_eq!(
            scan_kernel.plan_vulnerabilities(1).unwrap_err(),
            ArchetypeError::UnsupportedEnrichment
        );
        let other = ArchetypeKernel::new(
            "https://other.example.test",
            None,
            ArchetypeFamily::Scan,
            None,
        )
        .unwrap();
        let request = other.plan_scans(None).unwrap();
        assert_eq!(
            scan_kernel.decode_scans(&request, b"[]").unwrap_err(),
            ArchetypeError::RequestScopeMismatch
        );
    }
}
