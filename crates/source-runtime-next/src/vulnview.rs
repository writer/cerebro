//! Portable VulnView request, response, and DNS-alert fanout kernel.
//!
//! This module models the public provider contract without embedding a
//! deployment origin, OAuth issuer, credential value, or egress decision.
//! Callers authorize the planned URL and supply a leased bearer token before
//! I/O; the kernel only owns family planning and deterministic normalization.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{Date, OffsetDateTime, Time, format_description::well_known::Rfc3339};

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 500;
const MAX_FILTER_BYTES: usize = 2_048;
const MAX_CURSOR_BYTES: usize = 4_096;
const DNS_CURSOR_PREFIX: &str = "dns:";

/// One portable VulnView source family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VulnViewFamily {
    /// Attack-surface sites.
    Site,
    /// Scan lifecycle records.
    Scan,
    /// Vulnerability findings.
    Vulnerability,
    /// External assets.
    Asset,
    /// DNS findings expanded from asset records.
    DnsAlert,
}

impl VulnViewFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::Scan => "scan",
            Self::Vulnerability => "vulnerability",
            Self::Asset => "asset",
            Self::DnsAlert => "dns_alert",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Site => "vulnview.site",
            Self::Scan => "vulnview.scan",
            Self::Vulnerability => "vulnview.vulnerability",
            Self::Asset => "vulnview.asset",
            Self::DnsAlert => "vulnview.dns_alert",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Site => "/sites",
            Self::Scan => "/scans",
            Self::Vulnerability => "/vulnerabilities",
            Self::Asset | Self::DnsAlert => "/assets",
        }
    }
}

impl FromStr for VulnViewFamily {
    type Err = VulnViewError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "site" => Ok(Self::Site),
            "scan" => Ok(Self::Scan),
            "vulnerability" => Ok(Self::Vulnerability),
            "asset" => Ok(Self::Asset),
            "dns_alert" => Ok(Self::DnsAlert),
            _ => Err(VulnViewError::InvalidFamily),
        }
    }
}

/// Optional VulnView collection filters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VulnViewFilters {
    /// Restrict records to one site.
    pub site_id: Option<String>,
    /// Restrict records by scan name. The provider accepts both `scanName` and `name`.
    pub scan_name: Option<String>,
    /// Restrict findings by provider severity.
    pub severity: Option<String>,
    /// Provider text search expression.
    pub search: Option<String>,
}

/// One credential-free HTTP request planned by the VulnView kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VulnViewRequest {
    url: Url,
    family: VulnViewFamily,
    cursor: Option<String>,
    dns_state: Option<DnsCursor>,
}

impl VulnViewRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the credential scheme required by the portable data request.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized VulnView source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VulnViewRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable Go-compatible provider identity.
    pub provider_id: String,
    /// Canonical provider occurrence time when the record supplied one.
    pub occurred_at: Option<String>,
    /// Portable scalar attributes used by source projection.
    pub fields: BTreeMap<String, String>,
    /// Original provider record, or the portable DNS-alert fanout object.
    pub payload: Value,
}

/// A bounded VulnView page and its continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VulnViewPage {
    /// Normalized records in provider order.
    pub records: Vec<VulnViewRecord>,
    /// Provider cursor, local offset, or versioned DNS fanout cursor.
    pub next_cursor: Option<String>,
}

/// Provider-specific VulnView request and response kernel.
#[derive(Clone, Debug)]
pub struct VulnViewKernel {
    base_url: Url,
    family: VulnViewFamily,
    filters: VulnViewFilters,
    page_size: usize,
}

impl VulnViewKernel {
    /// Build a kernel for one caller-authorized base URL and family.
    ///
    /// The base URL may include a fixed API path, but never credentials,
    /// query parameters, fragments, or a private/loopback IP literal.
    pub fn new(
        base_url: &str,
        family: VulnViewFamily,
        filters: VulnViewFilters,
        page_size: Option<usize>,
    ) -> Result<Self, VulnViewError> {
        let base_url = validate_base_url(base_url)?;
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(VulnViewError::InvalidPageSize);
        }
        let filters = trim_filters(filters);
        validate_filters(&filters)?;
        Ok(Self {
            base_url,
            family,
            filters,
            page_size,
        })
    }

    /// Plan one credential-free provider request.
    pub fn plan(&self, cursor: Option<&str>) -> Result<VulnViewRequest, VulnViewError> {
        let cursor = bounded_cursor(cursor)?;
        let dns_state = if self.family == VulnViewFamily::DnsAlert {
            Some(decode_dns_cursor(cursor.as_deref())?)
        } else {
            None
        };
        let provider_cursor = dns_state
            .as_ref()
            .map(|state| state.asset_cursor.as_str())
            .or(cursor.as_deref())
            .filter(|value| !value.is_empty());
        let mut url = self.endpoint(self.family.path())?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(value) = self.filters.site_id.as_deref() {
                query.append_pair("siteId", value);
            }
            if let Some(value) = self.filters.scan_name.as_deref() {
                query.append_pair("scanName", value);
                query.append_pair("name", value);
            }
            if let Some(value) = self.filters.severity.as_deref() {
                query.append_pair("severity", value);
            }
            if let Some(value) = self.filters.search.as_deref() {
                query.append_pair("search", value);
            }
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(cursor) = provider_cursor {
                query.append_pair("cursor", cursor);
            }
        }
        Ok(VulnViewRequest {
            url,
            family: self.family,
            cursor,
            dns_state,
        })
    }

    /// Decode one response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &VulnViewRequest,
        body: &[u8],
    ) -> Result<VulnViewPage, VulnViewError> {
        self.validate_request(request)?;
        let (items, next_cursor) = decode_list(body)?;
        if self.family == VulnViewFamily::DnsAlert {
            return self.decode_dns_alerts(request, items, next_cursor);
        }
        let records = items
            .into_iter()
            .map(|item| normalize_record(self.family, item, None))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let cursor = request.cursor.as_deref().unwrap_or_default();
        if next_cursor.is_some() || (!cursor.is_empty() && records.len() <= self.page_size) {
            return Ok(VulnViewPage {
                records,
                next_cursor,
            });
        }
        let (records, next_cursor) = page_by_offset(records, cursor, self.page_size)?;
        Ok(VulnViewPage {
            records,
            next_cursor,
        })
    }

    fn decode_dns_alerts(
        &self,
        request: &VulnViewRequest,
        assets: Vec<Value>,
        next_asset_cursor: Option<String>,
    ) -> Result<VulnViewPage, VulnViewError> {
        let state = request
            .dns_state
            .as_ref()
            .ok_or(VulnViewError::RequestScopeMismatch)?;
        let mut records = Vec::new();
        for asset in assets {
            let asset = asset.as_object().ok_or(VulnViewError::InvalidResponse)?;
            let alerts = match asset.get("dnsAlerts") {
                Some(Value::Array(alerts)) => alerts,
                _ => continue,
            };
            for (index, alert) in alerts.iter().enumerate() {
                let Some(alert) = alert.as_object() else {
                    continue;
                };
                let mut values = Map::new();
                values.insert(
                    "asset".to_owned(),
                    asset.get("asset").cloned().unwrap_or(Value::Null),
                );
                values.insert(
                    "siteNames".to_owned(),
                    asset.get("sites").cloned().unwrap_or(Value::Null),
                );
                values.insert(
                    "scanNames".to_owned(),
                    asset.get("scanNames").cloned().unwrap_or(Value::Null),
                );
                values.extend(alert.clone());
                let asset_id = value_string(values.get("asset"));
                let alert_id = first_value(&values, &["id", "alert", "name", "type"]);
                let provider_id = stable_id(&[&asset_id, &alert_id, &index.to_string()]);
                let record = normalize_record(
                    VulnViewFamily::DnsAlert,
                    Value::Object(values),
                    Some(provider_id),
                )?
                .ok_or(VulnViewError::InvalidResponse)?;
                records.push(record);
            }
        }
        let (records, next_offset) =
            page_by_offset(records, &state.alert_offset.to_string(), self.page_size)?;
        let next_cursor = if let Some(next_offset) = next_offset {
            Some(encode_dns_cursor(&DnsCursor {
                asset_cursor: state.asset_cursor.clone(),
                alert_offset: next_offset
                    .parse()
                    .map_err(|_| VulnViewError::InvalidCursor)?,
            })?)
        } else if let Some(asset_cursor) = next_asset_cursor {
            Some(encode_dns_cursor(&DnsCursor {
                asset_cursor,
                alert_offset: 0,
            })?)
        } else {
            None
        };
        Ok(VulnViewPage {
            records,
            next_cursor,
        })
    }

    fn endpoint(&self, suffix: &str) -> Result<Url, VulnViewError> {
        let mut url = self.base_url.clone();
        let path = format!("{}{}", self.base_url.path().trim_end_matches('/'), suffix);
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn validate_request(&self, request: &VulnViewRequest) -> Result<(), VulnViewError> {
        if request.family != self.family || request.url.origin() != self.base_url.origin() {
            return Err(VulnViewError::RequestScopeMismatch);
        }
        let expected_path = format!(
            "{}{}",
            self.base_url.path().trim_end_matches('/'),
            self.family.path()
        );
        if request.url.path() != expected_path {
            return Err(VulnViewError::RequestScopeMismatch);
        }
        Ok(())
    }
}

/// Safe VulnView planning and decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VulnViewError {
    /// Family identifier is outside the five portable contracts.
    InvalidFamily,
    /// Base URL is not an absolute, credential-free HTTPS URL.
    InvalidBaseUrl,
    /// Base URL uses an unsafe IP literal.
    UnsafeOrigin,
    /// Page size is outside the provider contract.
    InvalidPageSize,
    /// A configured filter is empty, oversized, or contains control bytes.
    InvalidFilter,
    /// Cursor is malformed, negative, or exceeds its bound.
    InvalidCursor,
    /// Provider response is not the portable list envelope.
    InvalidResponse,
    /// Request did not originate from this kernel and family.
    RequestScopeMismatch,
}

impl fmt::Display for VulnViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "vulnview family is invalid",
            Self::InvalidBaseUrl => "vulnview base URL is invalid",
            Self::UnsafeOrigin => "vulnview base URL uses an unsafe IP origin",
            Self::InvalidPageSize => "vulnview page size must be between 1 and 500",
            Self::InvalidFilter => "vulnview filter is invalid",
            Self::InvalidCursor => "vulnview cursor is invalid",
            Self::InvalidResponse => "vulnview response is invalid",
            Self::RequestScopeMismatch => "vulnview request does not belong to this kernel",
        })
    }
}

impl Error for VulnViewError {}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsCursor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    asset_cursor: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    alert_offset: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn validate_base_url(value: &str) -> Result<Url, VulnViewError> {
    let mut url = Url::parse(value.trim()).map_err(|_| VulnViewError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VulnViewError::InvalidBaseUrl);
    }
    if let Some(host) = url.host_str()
        && let Ok(address) = host.parse::<IpAddr>()
        && unsafe_address(address)
    {
        return Err(VulnViewError::UnsafeOrigin);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

fn trim_filters(filters: VulnViewFilters) -> VulnViewFilters {
    VulnViewFilters {
        site_id: trim_optional(filters.site_id),
        scan_name: trim_optional(filters.scan_name),
        severity: trim_optional(filters.severity).map(|value| value.to_lowercase()),
        search: trim_optional(filters.search),
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn validate_filters(filters: &VulnViewFilters) -> Result<(), VulnViewError> {
    for value in [
        filters.site_id.as_deref(),
        filters.scan_name.as_deref(),
        filters.severity.as_deref(),
        filters.search.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > MAX_FILTER_BYTES || value.chars().any(char::is_control) {
            return Err(VulnViewError::InvalidFilter);
        }
    }
    Ok(())
}

fn bounded_cursor(cursor: Option<&str>) -> Result<Option<String>, VulnViewError> {
    let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
    if cursor
        .is_some_and(|value| value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control))
    {
        return Err(VulnViewError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}

fn decode_list(body: &[u8]) -> Result<(Vec<Value>, Option<String>), VulnViewError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| VulnViewError::InvalidResponse)?;
    let root = root.as_object().ok_or(VulnViewError::InvalidResponse)?;
    let items = match root.get("items") {
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err(VulnViewError::InvalidResponse),
        None => Vec::new(),
    };
    let next_cursor = match root.get("nextCursor") {
        Some(Value::String(value)) => trim_optional(Some(value.clone())),
        Some(Value::Null) | None => None,
        Some(_) => return Err(VulnViewError::InvalidResponse),
    };
    Ok((items, next_cursor))
}

fn normalize_record(
    family: VulnViewFamily,
    payload: Value,
    explicit_id: Option<String>,
) -> Result<Option<VulnViewRecord>, VulnViewError> {
    let values = payload.as_object().ok_or(VulnViewError::InvalidResponse)?;
    let provider_id = explicit_id.unwrap_or_else(|| record_id(family, values));
    if provider_id.trim().is_empty() {
        return Ok(None);
    }
    let mut fields = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "vulnview".to_owned()),
        ("source_provider".to_owned(), "vulnview".to_owned()),
    ]);
    match family {
        VulnViewFamily::Site => copy_fields(
            &mut fields,
            values,
            &[("site_id", "siteId"), ("name", "name")],
        ),
        VulnViewFamily::Scan => copy_fields(
            &mut fields,
            values,
            &[
                ("scan_id", "scanId"),
                ("site_id", "siteId"),
                ("name", "name"),
                ("scan_type", "scanType"),
                ("target", "target"),
                ("status", "status"),
                ("findings_count", "findingsCount"),
                ("results_key", "resultsKey"),
                ("created_at", "createdAt"),
                ("started_at", "startedAt"),
                ("completed_at", "completedAt"),
                ("cloud_account_id", "cloudAccountId"),
            ],
        ),
        VulnViewFamily::Vulnerability => {
            copy_fields(
                &mut fields,
                values,
                &[
                    ("vulnerability_id", "templateId"),
                    ("template_id", "templateId"),
                    ("name", "name"),
                    ("severity", "severity"),
                    ("type", "type"),
                    ("target_id", "host"),
                    ("target_name", "host"),
                    ("host", "host"),
                    ("matched_at", "matchedAt"),
                    ("description", "description"),
                    ("remediation", "remediation"),
                    ("scan_id", "scanId"),
                    ("scan_name", "scanName"),
                    ("site_id", "siteId"),
                    ("site_name", "siteName"),
                    ("timestamp", "timestamp"),
                ],
            );
            if !fields.contains_key("template_id") {
                copy_fields(
                    &mut fields,
                    values,
                    &[
                        ("template_id", "template-id"),
                        ("vulnerability_id", "template-id"),
                    ],
                );
            }
            if !fields.contains_key("matched_at") {
                copy_fields(&mut fields, values, &[("matched_at", "matched-at")]);
            }
            add_finding_state(&mut fields, values);
            fields.insert("target_type".to_owned(), "external_asset".to_owned());
            let vulnerability_type = fields
                .get("type")
                .cloned()
                .unwrap_or_else(|| "vulnview".to_owned());
            fields.insert("vulnerability_type".to_owned(), vulnerability_type);
        }
        VulnViewFamily::Asset => {
            copy_fields(
                &mut fields,
                values,
                &[
                    ("asset_id", "asset"),
                    ("asset_name", "asset"),
                    ("target_id", "asset"),
                    ("target_name", "asset"),
                    ("highest_severity", "highestSeverity"),
                    ("findings_count", "findingsCount"),
                    ("sites", "sites"),
                    ("scan_names", "scanNames"),
                    ("critical_count", "severityCounts.critical"),
                    ("high_count", "severityCounts.high"),
                    ("medium_count", "severityCounts.medium"),
                    ("low_count", "severityCounts.low"),
                    ("info_count", "severityCounts.info"),
                    ("dns_alerts_count", "dnsAlertSummary.total"),
                    ("dns_highest_alert", "dnsAlertSummary.highestSeverity"),
                ],
            );
            fields.insert("target_type".to_owned(), "external_asset".to_owned());
        }
        VulnViewFamily::DnsAlert => {
            copy_fields(
                &mut fields,
                values,
                &[
                    ("asset_id", "asset"),
                    ("asset_name", "asset"),
                    ("target_id", "asset"),
                    ("target_name", "asset"),
                    ("alert", "alert"),
                    ("name", "alert"),
                    ("severity", "severity"),
                    ("description", "description"),
                    ("record_type", "recordType"),
                    ("record_value", "recordValue"),
                    ("sites", "siteNames"),
                    ("scan_names", "scanNames"),
                ],
            );
            add_finding_state(&mut fields, values);
            fields.insert("target_type".to_owned(), "external_asset".to_owned());
        }
    }
    fields.retain(|_, value| !value.trim().is_empty());
    Ok(Some(VulnViewRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        occurred_at: occurred_at(values),
        fields,
        payload,
    }))
}

fn record_id(family: VulnViewFamily, values: &Map<String, Value>) -> String {
    match family {
        VulnViewFamily::Site => first_value(values, &["siteId", "id", "name"]),
        VulnViewFamily::Scan => first_value(values, &["scanId", "id", "name"]),
        VulnViewFamily::Vulnerability => stable_id(&[
            &first_value(values, &["scanId"]),
            &first_value(values, &["templateId", "template-id", "id", "name"]),
            &first_value(values, &["matchedAt", "matched-at", "host"]),
        ]),
        VulnViewFamily::Asset => first_value(values, &["asset", "host", "matchedAt", "matched-at"]),
        VulnViewFamily::DnsAlert => first_value(values, &["id", "name"]),
    }
}

fn copy_fields(
    fields: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    mappings: &[(&str, &str)],
) {
    for (attribute, path) in mappings {
        let value = value_string(value_at(values, path));
        if !value.is_empty() {
            fields.insert((*attribute).to_owned(), value);
        }
    }
}

fn add_finding_state(fields: &mut BTreeMap<String, String>, values: &Map<String, Value>) {
    for (attribute, paths) in [
        ("vulnview_status", &["status"][..]),
        ("vulnview_state", &["state"][..]),
        (
            "vulnview_finding_status",
            &["findingStatus", "finding_status"][..],
        ),
        (
            "vulnview_remediation_state",
            &["remediationState", "remediation_state"][..],
        ),
        (
            "vulnview_lifecycle_state",
            &["lifecycleState", "lifecycle_state"][..],
        ),
    ] {
        let value = first_value(values, paths);
        if !value.is_empty() {
            fields.insert(attribute.to_owned(), value);
        }
    }
    for attribute in [
        "vulnview_status",
        "vulnview_state",
        "vulnview_finding_status",
        "vulnview_remediation_state",
        "vulnview_lifecycle_state",
    ] {
        if let Some(value) = fields.get(attribute).cloned() {
            fields.insert("vulnview_finding_state".to_owned(), value);
            break;
        }
    }
}

fn first_value(values: &Map<String, Value>, paths: &[&str]) -> String {
    paths
        .iter()
        .map(|path| value_string(value_at(values, path)))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

fn value_at<'a>(values: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut current = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value_string(Some(value)))
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(values)) => {
            let mut pairs = values
                .iter()
                .map(|(key, value)| format!("{key}:{}", value_string(Some(value))))
                .collect::<Vec<_>>();
            pairs.sort();
            format!("map[{}]", pairs.join(" "))
        }
    }
}

fn stable_id(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(":")
}

fn occurred_at(values: &Map<String, Value>) -> Option<String> {
    for path in [
        "timestamp",
        "completedAt",
        "startedAt",
        "createdAt",
        "matchedAt",
        "matched-at",
    ] {
        let value = value_string(value_at(values, path));
        if value.is_empty() {
            continue;
        }
        if let Ok(parsed) = OffsetDateTime::parse(&value, &Rfc3339) {
            return parsed.format(&Rfc3339).ok();
        }
        let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?;
        if let Ok(parsed) = Date::parse(&value, &format) {
            return parsed
                .with_time(Time::MIDNIGHT)
                .assume_utc()
                .format(&Rfc3339)
                .ok();
        }
    }
    None
}

fn page_by_offset<T>(
    items: Vec<T>,
    cursor: &str,
    page_size: usize,
) -> Result<(Vec<T>, Option<String>), VulnViewError> {
    let offset = if cursor.trim().is_empty() {
        0
    } else {
        cursor
            .trim()
            .parse::<usize>()
            .map_err(|_| VulnViewError::InvalidCursor)?
    };
    if offset >= items.len() {
        return Ok((Vec::new(), None));
    }
    let end = offset.saturating_add(page_size).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    Ok((
        items.into_iter().skip(offset).take(end - offset).collect(),
        next,
    ))
}

fn decode_dns_cursor(cursor: Option<&str>) -> Result<DnsCursor, VulnViewError> {
    let Some(cursor) = cursor else {
        return Ok(DnsCursor::default());
    };
    let Some(encoded) = cursor.strip_prefix(DNS_CURSOR_PREFIX) else {
        return Ok(DnsCursor {
            asset_cursor: cursor.to_owned(),
            alert_offset: 0,
        });
    };
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| VulnViewError::InvalidCursor)?;
    let mut state: DnsCursor =
        serde_json::from_slice(&payload).map_err(|_| VulnViewError::InvalidCursor)?;
    state.asset_cursor = state.asset_cursor.trim().to_owned();
    if state.asset_cursor.len() > MAX_CURSOR_BYTES
        || state.asset_cursor.chars().any(char::is_control)
    {
        return Err(VulnViewError::InvalidCursor);
    }
    Ok(state)
}

fn encode_dns_cursor(state: &DnsCursor) -> Result<String, VulnViewError> {
    let payload = serde_json::to_vec(state).map_err(|_| VulnViewError::InvalidCursor)?;
    Ok(format!(
        "{DNS_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn kernel(family: VulnViewFamily, page_size: usize) -> VulnViewKernel {
        VulnViewKernel::new(
            "https://api.example.test/v1",
            family,
            VulnViewFilters::default(),
            Some(page_size),
        )
        .unwrap()
    }

    fn body(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn all_five_families_plan_exact_paths_filters_and_auth_contract() {
        let filters = VulnViewFilters {
            site_id: Some(" site-1 ".to_owned()),
            scan_name: Some(" prod ".to_owned()),
            severity: Some(" HIGH ".to_owned()),
            search: Some(" exposed panel ".to_owned()),
        };
        for (family, path) in [
            (VulnViewFamily::Site, "/v1/sites"),
            (VulnViewFamily::Scan, "/v1/scans"),
            (VulnViewFamily::Vulnerability, "/v1/vulnerabilities"),
            (VulnViewFamily::Asset, "/v1/assets"),
            (VulnViewFamily::DnsAlert, "/v1/assets"),
        ] {
            let request = VulnViewKernel::new(
                "https://api.example.test/v1/",
                family,
                filters.clone(),
                Some(50),
            )
            .unwrap()
            .plan(None)
            .unwrap();
            assert_eq!(request.url().path(), path);
            let query = request
                .url()
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(query["siteId"], "site-1");
            assert_eq!(query["scanName"], "prod");
            assert_eq!(query["name"], "prod");
            assert_eq!(query["severity"], "high");
            assert_eq!(query["search"], "exposed panel");
            assert_eq!(query["limit"], "50");
            assert_eq!(request.authorization_scheme(), "Bearer");
            assert_eq!(request.accept(), "application/json");
        }
    }

    #[test]
    fn direct_families_preserve_go_identity_attributes_and_time_precedence() {
        let cases = [
            (
                VulnViewFamily::Site,
                json!({"siteId":"site-1","name":"Prod","createdAt":"2026-05-10T00:00:00Z"}),
                "site-1",
                "site_id",
            ),
            (
                VulnViewFamily::Scan,
                json!({"scanId":"scan-1","siteId":"site-1","status":"complete","completedAt":"2026-05-11T00:00:00Z","createdAt":"2026-05-01T00:00:00Z"}),
                "scan-1",
                "scan_id",
            ),
            (
                VulnViewFamily::Vulnerability,
                json!({"scanId":"scan-1","templateId":"cve-1","host":"app.example","matchedAt":"https://app.example/login","timestamp":"2026-05-12T00:00:00Z","severity":"high"}),
                "scan-1:cve-1:https://app.example/login",
                "template_id",
            ),
            (
                VulnViewFamily::Asset,
                json!({"asset":"app.example","sites":["prod","edge"],"severityCounts":{"critical":1},"createdAt":"2026-05-09"}),
                "app.example",
                "asset_id",
            ),
        ];
        for (family, item, expected_id, field) in cases {
            let kernel = kernel(family, 100);
            let request = kernel.plan(None).unwrap();
            let page = kernel
                .decode(&request, &body(json!({"items":[item]})))
                .unwrap();
            assert_eq!(page.records.len(), 1);
            let record = &page.records[0];
            assert_eq!(record.provider_id, expected_id);
            assert_eq!(record.provider_kind, family.provider_kind());
            assert!(record.fields.contains_key(field));
            assert!(record.occurred_at.is_some());
        }
    }

    #[test]
    fn local_offset_fallback_and_provider_cursor_match_go_semantics() {
        let kernel = kernel(VulnViewFamily::Site, 1);
        let first_request = kernel.plan(None).unwrap();
        let response = body(json!({"items":[{"siteId":"one"},{"siteId":"two"}]}));
        let first = kernel.decode(&first_request, &response).unwrap();
        assert_eq!(first.records[0].provider_id, "one");
        assert_eq!(first.next_cursor.as_deref(), Some("1"));
        let second_request = kernel.plan(first.next_cursor.as_deref()).unwrap();
        assert_eq!(
            second_request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "cursor")
                .unwrap()
                .1,
            "1"
        );
        let second = kernel.decode(&second_request, &response).unwrap();
        assert_eq!(second.records[0].provider_id, "two");
        assert_eq!(second.next_cursor, None);

        let provider_request = kernel.plan(Some("opaque-1")).unwrap();
        let provider_page = kernel
            .decode(
                &provider_request,
                &body(json!({"items":[{"siteId":"three"}],"nextCursor":"opaque-2"})),
            )
            .unwrap();
        assert_eq!(provider_page.next_cursor.as_deref(), Some("opaque-2"));
    }

    #[test]
    fn vulnerability_and_dns_states_remain_provider_namespaced() {
        let kernel = kernel(VulnViewFamily::Vulnerability, 100);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                &body(json!({"items":[{
                    "scanId":"scan-1","template-id":"cve-1","matched-at":"app.example",
                    "status":"resolved","finding_status":"closed"
                }]})),
            )
            .unwrap();
        let fields = &page.records[0].fields;
        assert_eq!(fields["vulnview_status"], "resolved");
        assert_eq!(fields["vulnview_finding_state"], "resolved");
        assert!(!fields.contains_key("status"));
        assert_eq!(fields["template_id"], "cve-1");
        assert_eq!(fields["matched_at"], "app.example");
    }

    #[test]
    fn dns_alert_fanout_pages_within_one_asset_without_losing_scope() {
        let kernel = kernel(VulnViewFamily::DnsAlert, 1);
        let request = kernel.plan(None).unwrap();
        let response = body(json!({"items":[{
            "asset":"staging.example","sites":["prod"],"scanNames":["external"],
            "dnsAlerts":[
                {"alert":"dangling-cname","severity":"high","state":"open"},
                {"alert":"stale-a-record","severity":"medium","state":"closed"}
            ]
        }]}));
        let first = kernel.decode(&request, &response).unwrap();
        assert_eq!(
            first.records[0].provider_id,
            "staging.example:dangling-cname:0"
        );
        assert_eq!(first.records[0].fields["asset_id"], "staging.example");
        assert_eq!(first.records[0].fields["sites"], "prod");
        assert_eq!(first.records[0].fields["vulnview_state"], "open");
        assert!(!first.records[0].fields.contains_key("state"));
        let second_request = kernel.plan(first.next_cursor.as_deref()).unwrap();
        let second = kernel.decode(&second_request, &response).unwrap();
        assert_eq!(
            second.records[0].provider_id,
            "staging.example:stale-a-record:1"
        );
        assert_eq!(second.next_cursor, None);
    }

    #[test]
    fn dns_alert_cursor_advances_across_empty_asset_pages() {
        let kernel = kernel(VulnViewFamily::DnsAlert, 10);
        let request = kernel.plan(None).unwrap();
        let first = kernel
            .decode(
                &request,
                &body(json!({"items":[{"asset":"empty","dnsAlerts":[]}],"nextCursor":"asset-2"})),
            )
            .unwrap();
        assert!(first.records.is_empty());
        let next_request = kernel.plan(first.next_cursor.as_deref()).unwrap();
        assert_eq!(
            next_request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "cursor")
                .unwrap()
                .1,
            "asset-2"
        );
        let second = kernel
            .decode(
                &next_request,
                &body(json!({"items":[{"asset":"live","dnsAlerts":[{"alert":"dangling"}]}]})),
            )
            .unwrap();
        assert_eq!(second.records[0].provider_id, "live:dangling:0");
    }

    #[test]
    fn missing_direct_identity_is_skipped_but_malformed_items_fail_closed() {
        let kernel = kernel(VulnViewFamily::Site, 100);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(&request, &body(json!({"items":[{}, {"siteId":"site-1"}]})))
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].provider_id, "site-1");
        assert_eq!(
            kernel.decode(&request, &body(json!({"items":["not-an-object"]}))),
            Err(VulnViewError::InvalidResponse)
        );
    }

    #[test]
    fn unsafe_origins_filters_page_sizes_and_cursors_fail_closed() {
        assert_eq!(
            VulnViewKernel::new(
                "http://api.example.test",
                VulnViewFamily::Site,
                VulnViewFilters::default(),
                None,
            )
            .unwrap_err()
            .to_string(),
            "vulnview base URL is invalid"
        );
        assert!(matches!(
            VulnViewKernel::new(
                "https://127.0.0.1/api",
                VulnViewFamily::Site,
                VulnViewFilters::default(),
                None,
            ),
            Err(VulnViewError::UnsafeOrigin)
        ));
        assert!(matches!(
            VulnViewKernel::new(
                "https://api.example.test",
                VulnViewFamily::Site,
                VulnViewFilters::default(),
                Some(501),
            ),
            Err(VulnViewError::InvalidPageSize)
        ));
        let dns_kernel = kernel(VulnViewFamily::DnsAlert, 10);
        assert_eq!(
            dns_kernel.plan(Some("dns:not-base64")),
            Err(VulnViewError::InvalidCursor)
        );
        let direct = kernel(VulnViewFamily::Site, 10);
        assert_eq!(
            direct.decode(&direct.plan(None).unwrap(), b"[]"),
            Err(VulnViewError::InvalidResponse)
        );
    }

    #[test]
    fn request_scope_and_cursor_types_are_bound_to_the_kernel() {
        let sites = kernel(VulnViewFamily::Site, 1);
        let scans = kernel(VulnViewFamily::Scan, 10);
        let request = sites.plan(None).unwrap();
        assert_eq!(
            scans.decode(&request, &body(json!({"items":[]}))),
            Err(VulnViewError::RequestScopeMismatch)
        );
        assert_eq!(
            sites.decode(&request, &body(json!({"items":[],"nextCursor":7}))),
            Err(VulnViewError::InvalidResponse)
        );
        let offset = sites.plan(Some("not-an-offset")).unwrap();
        assert_eq!(
            sites.decode(
                &offset,
                &body(json!({"items":[{"siteId":"one"},{"siteId":"two"}]})),
            ),
            Err(VulnViewError::InvalidCursor)
        );
    }
}
