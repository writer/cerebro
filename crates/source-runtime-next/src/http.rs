use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, CompleteCollection, ModelError, ObservationId,
};
use cerebro_source_catalog::{AuthModel, CompiledFamily, CompiledSource, HttpMethod, Pagination};
use futures_util::StreamExt;
use reqwest::{
    Client, Response, StatusCode, Url,
    header::{HeaderMap, HeaderName},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CollectedBatch, CollectedScope, CollectionRequest, SourceConnector, SourceRecord};

const MAX_PAGES: usize = 10_000;
const MAX_RESPONSE_BYTES: usize = 16 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedAuth {
    None,
    Bearer { token: String },
    Basic { username: String, password: String },
    Header { name: String, value: String },
}

#[derive(Debug)]
pub enum HttpConnectorError {
    InvalidConfiguration(String),
    InvalidUrl(String),
    Request(reqwest::Error),
    ProviderStatus(StatusCode),
    InvalidResponse(String),
    Domain(ModelError),
    PageLimit,
}

impl fmt::Display for HttpConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::InvalidUrl(message) => write!(formatter, "invalid provider URL: {message}"),
            Self::Request(error) => write!(formatter, "provider request failed: {error}"),
            Self::ProviderStatus(status) => write!(formatter, "provider returned HTTP {status}"),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid provider response: {message}")
            }
            Self::Domain(error) => write!(formatter, "invalid collection receipt: {error}"),
            Self::PageLimit => formatter.write_str("provider pagination exceeded the page limit"),
        }
    }
}

impl Error for HttpConnectorError {}

impl From<ModelError> for HttpConnectorError {
    fn from(value: ModelError) -> Self {
        Self::Domain(value)
    }
}

/// Generic collector for the checked-in definition grammar. Bespoke sources
/// implement `SourceConnector` directly but still cross the same graph mapper.
pub struct HttpSourceConnector {
    client: Client,
    source: CompiledSource,
    family: CompiledFamily,
    base_url: Url,
    config: BTreeMap<String, String>,
    auth: ResolvedAuth,
}

impl HttpSourceConnector {
    pub fn new(
        source: CompiledSource,
        family_id: &str,
        base_url: &str,
        config: BTreeMap<String, String>,
        auth: ResolvedAuth,
    ) -> Result<Self, HttpConnectorError> {
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == family_id)
            .cloned()
            .ok_or_else(|| {
                HttpConnectorError::InvalidConfiguration(format!(
                    "source {} has no family {family_id}",
                    source.id()
                ))
            })?;
        validate_auth(source.auth(), &auth)?;
        let mut base_url = Url::parse(base_url)
            .map_err(|error| HttpConnectorError::InvalidUrl(error.to_string()))?;
        if base_url.scheme() != "https" && !is_loopback(&base_url) {
            return Err(HttpConnectorError::InvalidConfiguration(
                "provider base URL must use HTTPS".to_owned(),
            ));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = build_client(REQUEST_TIMEOUT, CONNECT_TIMEOUT)?;
        Ok(Self {
            client,
            source,
            family,
            base_url,
            config,
            auth,
        })
    }

    fn request_url(&self) -> Result<Url, HttpConnectorError> {
        let mut path = self.family.path().to_owned();
        for (key, value) in &self.config {
            path = path.replace(&format!("{{{key}}}"), value);
            path = path.replace(&format!("${{config.{key}}}"), value);
        }
        if path.contains('{') || path.contains("${") {
            return Err(HttpConnectorError::InvalidConfiguration(format!(
                "family {} has unresolved path variables",
                self.family.id()
            )));
        }
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|error| HttpConnectorError::InvalidUrl(error.to_string()))
    }
}

#[async_trait]
impl SourceConnector for HttpSourceConnector {
    type Error = HttpConnectorError;

    async fn collect(&mut self, request: CollectionRequest) -> Result<CollectedBatch, Self::Error> {
        let observed_at = unix_millis()?;
        let mut url = self.request_url()?;
        let initial_cursor = effective_cursor(self.family.pagination(), request.cursor.as_deref());
        let mut cursor = initial_cursor.clone();
        let mut page = pagination_start(self.family.pagination());
        let mut offset = 0usize;
        let mut records = Vec::new();
        let mut exhausted = false;

        for _ in 0..MAX_PAGES {
            apply_query(
                &mut url,
                self.family.static_query(),
                self.family.pagination(),
                cursor.as_deref(),
                page,
                offset,
            );
            let mut builder = match self.family.method() {
                HttpMethod::Get => self.client.get(url.clone()),
                HttpMethod::Post => self.client.post(url.clone()),
            };
            builder = match &self.auth {
                ResolvedAuth::None => builder,
                ResolvedAuth::Bearer { token } => builder.bearer_auth(token),
                ResolvedAuth::Basic { username, password } => {
                    builder.basic_auth(username, Some(password))
                }
                ResolvedAuth::Header { name, value } => builder.header(name, value),
            };
            let response = builder.send().await.map_err(HttpConnectorError::Request)?;
            let status = response.status();
            if !status.is_success() {
                return Err(HttpConnectorError::ProviderStatus(status));
            }
            let next_link = response_next_link(response.headers(), self.family.pagination())?;
            let body = read_bounded_json(response).await?;
            let selected = select_records(&body, self.family.record_selector())?;
            let selected_count = selected.len();
            for value in selected {
                let provider_id = scalar_at(&value, self.family.id_field()).ok_or_else(|| {
                    HttpConnectorError::InvalidResponse(format!(
                        "family {} record is missing {}",
                        self.family.id(),
                        self.family.id_field()
                    ))
                })?;
                records.push(SourceRecord {
                    observation_id: observation_id(
                        self.source.id(),
                        self.family.id(),
                        &provider_id,
                        observed_at,
                    )?,
                    family: self.family.id().to_owned(),
                    provider_kind: format!("{}.{}", self.source.id(), self.family.id()),
                    provider_id,
                    fields: flatten_scalars(&value),
                    payload: value,
                });
            }

            match self.family.pagination() {
                Pagination::None => {
                    exhausted = true;
                    break;
                }
                Pagination::Cursor { response_path, .. } => {
                    cursor = scalar_at_path(&body, response_path);
                    if cursor.as_deref().is_none_or(str::is_empty) {
                        exhausted = true;
                        break;
                    }
                }
                Pagination::Page { page_size, .. } => {
                    if selected_count < *page_size {
                        exhausted = true;
                        break;
                    }
                    page = page.saturating_add(1);
                }
                Pagination::Offset { page_size, .. } => {
                    if selected_count < *page_size {
                        exhausted = true;
                        break;
                    }
                    offset = offset.saturating_add(*page_size);
                }
                Pagination::Link { .. } => {
                    let Some(next) = next_link else {
                        exhausted = true;
                        break;
                    };
                    let Some(next) = resolve_next_url(&url, &next)? else {
                        exhausted = true;
                        break;
                    };
                    ensure_same_origin(&self.base_url, &next)?;
                    url = next;
                }
                Pagination::NextUrl { response_path } => {
                    let Some(next) = scalar_at_path(&body, response_path) else {
                        exhausted = true;
                        break;
                    };
                    let Some(next) = resolve_next_url(&url, &next)? else {
                        exhausted = true;
                        break;
                    };
                    ensure_same_origin(&self.base_url, &next)?;
                    url = next;
                }
            }
        }
        if !exhausted {
            return Err(HttpConnectorError::PageLimit);
        }

        let collection_id = CollectionId::parse(format!(
            "collection:{}:{}:{observed_at}",
            self.source.id(),
            self.family.id()
        ))?;
        let scope_name = format!("{}.{}", self.source.id(), self.family.id());
        let authoritative = initial_cursor.is_none() && self.family.is_authoritative();
        let scope = if authoritative {
            CollectedScope::Complete(CompleteCollection::new(
                request.tenant_id,
                request.source_runtime_id,
                collection_id,
                scope_name,
                observed_at,
            )?)
        } else if initial_cursor.is_some() {
            CollectedScope::NonAuthoritative(CollectionReceipt::incremental(
                request.tenant_id,
                request.source_runtime_id,
                collection_id,
                scope_name,
                observed_at,
            )?)
        } else {
            CollectedScope::NonAuthoritative(CollectionReceipt::partial(
                request.tenant_id,
                request.source_runtime_id,
                collection_id,
                scope_name,
                observed_at,
            )?)
        };
        Ok(CollectedBatch {
            scope,
            records,
            next_cursor: cursor,
        })
    }
}

fn build_client(
    request_timeout: Duration,
    connect_timeout: Duration,
) -> Result<Client, HttpConnectorError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(request_timeout)
        .connect_timeout(connect_timeout)
        .build()
        .map_err(HttpConnectorError::Request)
}

async fn read_bounded_json(response: Response) -> Result<Value, HttpConnectorError> {
    read_bounded_json_with_limit(response, MAX_RESPONSE_BYTES).await
}

async fn read_bounded_json_with_limit(
    response: Response,
    max_response_bytes: usize,
) -> Result<Value, HttpConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(response_too_large(max_response_bytes));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(HttpConnectorError::Request)?;
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| response_too_large(max_response_bytes))?;
        if next_len > max_response_bytes {
            return Err(response_too_large(max_response_bytes));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| HttpConnectorError::InvalidResponse(error.to_string()))
}

fn response_too_large(max_response_bytes: usize) -> HttpConnectorError {
    HttpConnectorError::InvalidResponse(format!(
        "provider response exceeds the {max_response_bytes}-byte limit"
    ))
}

fn validate_auth(expected: &AuthModel, actual: &ResolvedAuth) -> Result<(), HttpConnectorError> {
    let valid = match expected {
        AuthModel::None => matches!(actual, ResolvedAuth::None),
        AuthModel::Basic => matches!(actual, ResolvedAuth::Basic { .. }),
        AuthModel::ApiKey => matches!(actual, ResolvedAuth::Header { .. }),
        AuthModel::BearerToken
        | AuthModel::OauthAuthorizationCode
        | AuthModel::OauthClientCredentials
        | AuthModel::TwoStep
        | AuthModel::Jwt => matches!(
            actual,
            ResolvedAuth::Bearer { .. } | ResolvedAuth::Header { .. }
        ),
        AuthModel::Signature | AuthModel::AwsSigV4 | AuthModel::DuoHmac | AuthModel::DuoHmacV5 => {
            false
        }
    };
    if valid {
        Ok(())
    } else {
        Err(HttpConnectorError::InvalidConfiguration(
            "resolved credential does not match the source auth model".to_owned(),
        ))
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
}

fn ensure_same_origin(base: &Url, next: &Url) -> Result<(), HttpConnectorError> {
    if base.scheme() == next.scheme()
        && base.host_str() == next.host_str()
        && base.port_or_known_default() == next.port_or_known_default()
    {
        Ok(())
    } else {
        Err(HttpConnectorError::InvalidResponse(
            "provider pagination changed origin".to_owned(),
        ))
    }
}

fn unix_millis() -> Result<i64, HttpConnectorError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HttpConnectorError::InvalidConfiguration(error.to_string()))?
        .as_millis();
    i64::try_from(value)
        .map_err(|_| HttpConnectorError::InvalidConfiguration("system time overflow".to_owned()))
}

fn pagination_start(pagination: &Pagination) -> usize {
    match pagination {
        Pagination::Page { start, .. } => *start,
        _ => 0,
    }
}

fn effective_cursor(pagination: &Pagination, requested: Option<&str>) -> Option<String> {
    match pagination {
        Pagination::Cursor { .. } => requested.map(str::to_owned),
        _ => None,
    }
}

fn apply_query(
    url: &mut Url,
    static_query: &BTreeMap<String, String>,
    pagination: &Pagination,
    cursor: Option<&str>,
    page: usize,
    offset: usize,
) {
    if matches!(
        pagination,
        Pagination::Link { .. } | Pagination::NextUrl { .. }
    ) {
        let retained = url
            .query_pairs()
            .filter(|(key, _)| !static_query.contains_key(key.as_ref()))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let mut query = url.query_pairs_mut();
        query.clear();
        query.extend_pairs(retained);
        query.extend_pairs(static_query);
        return;
    }

    let mut query = url.query_pairs_mut();
    query.clear();
    query.extend_pairs(static_query);
    match pagination {
        Pagination::None => {}
        Pagination::Link { .. } | Pagination::NextUrl { .. } => unreachable!(),
        Pagination::Cursor {
            parameter,
            page_size_parameter,
            page_size,
            ..
        } => {
            if let Some(cursor) = cursor {
                query.append_pair(parameter, cursor);
            }
            if let Some(parameter) = page_size_parameter {
                query.append_pair(parameter, &page_size.to_string());
            }
        }
        Pagination::Page {
            parameter,
            page_size_parameter,
            page_size,
            ..
        } => {
            query.append_pair(parameter, &page.to_string());
            if let Some(parameter) = page_size_parameter {
                query.append_pair(parameter, &page_size.to_string());
            }
        }
        Pagination::Offset {
            parameter,
            limit_parameter,
            page_size,
        } => {
            query.append_pair(parameter, &offset.to_string());
            query.append_pair(limit_parameter, &page_size.to_string());
        }
    }
}

fn select_records(body: &Value, selector: &str) -> Result<Vec<Value>, HttpConnectorError> {
    let selector = selector.trim();
    if selector == "$" {
        return Ok(vec![body.clone()]);
    }
    let wildcard = selector.ends_with("[*]");
    let path = selector
        .strip_prefix("$.")
        .or_else(|| selector.strip_prefix('$'))
        .unwrap_or(selector)
        .trim_end_matches("[*]");
    let selected = value_at_path(body, path).ok_or_else(|| {
        HttpConnectorError::InvalidResponse(format!("record selector {selector} did not match"))
    })?;
    if wildcard || selected.is_array() {
        return selected.as_array().cloned().ok_or_else(|| {
            HttpConnectorError::InvalidResponse(format!(
                "record selector {selector} did not select an array"
            ))
        });
    }
    Ok(vec![selected.clone()])
}

fn scalar_at(value: &Value, field: &str) -> Option<String> {
    scalar_at_path(value, field)
}

fn scalar_at_path(value: &Value, path: &str) -> Option<String> {
    let path = path.trim().trim_start_matches("$.").trim_start_matches('$');
    value_at_path(value, path).and_then(scalar)
}

fn value_at_path<'a>(mut value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }
    for part in path.split('.') {
        value = value.get(part)?;
    }
    Some(value)
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn flatten_scalars(value: &Value) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            if let Some(value) = scalar(value) {
                fields.insert(key.clone(), value);
            }
        }
    }
    fields
}

fn next_link_url(header: &str) -> Option<String> {
    split_link_header(header, ',').into_iter().find_map(|part| {
        let part = part.trim();
        let start = part.find('<')? + 1;
        let end = part[start..].find('>')? + start;
        let is_next = split_link_header(&part[end + 1..], ';')
            .into_iter()
            .filter_map(|parameter| parameter.trim().split_once('='))
            .any(|(key, value)| {
                key.trim().eq_ignore_ascii_case("rel")
                    && value
                        .trim()
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                        .unwrap_or_else(|| value.trim())
                        .split_ascii_whitespace()
                        .any(|relation| relation.eq_ignore_ascii_case("next"))
            });
        is_next.then(|| part[start..end].to_owned())
    })
}

fn response_next_link(
    headers: &HeaderMap,
    pagination: &Pagination,
) -> Result<Option<String>, HttpConnectorError> {
    let Pagination::Link { header } = pagination else {
        return Ok(None);
    };
    let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
        HttpConnectorError::InvalidConfiguration(format!(
            "pagination link header {header:?} is invalid"
        ))
    })?;
    Ok(headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .and_then(next_link_url))
}

fn split_link_header(value: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut in_target = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match character {
            '<' => in_target = true,
            '>' => in_target = false,
            _ if character == delimiter && !in_target => {
                parts.push(&value[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

fn resolve_next_url(current_url: &Url, next: &str) -> Result<Option<Url>, HttpConnectorError> {
    let next = next.trim();
    if next.is_empty() {
        return Ok(None);
    }
    Url::parse(next)
        .or_else(|_| current_url.join(next))
        .map(Some)
        .map_err(|error| HttpConnectorError::InvalidUrl(error.to_string()))
}

fn observation_id(
    source_id: &str,
    family_id: &str,
    provider_id: &str,
    observed_at: i64,
) -> Result<ObservationId, HttpConnectorError> {
    let mut hasher = Sha256::new();
    let observed_at = observed_at.to_string();
    for part in [source_id, family_id, provider_id, observed_at.as_str()] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    ObservationId::parse(format!("observation:{}", hex(&hasher.finalize()))).map_err(Into::into)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::Duration,
    };

    use cerebro_organizational_model::{SourceRuntimeId, TenantId};
    use cerebro_source_catalog::SourceCatalog;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn selectors_and_link_pagination_are_bounded_and_deterministic() {
        let body = serde_json::json!({"data": {"users": [{"id": 1}, {"id": 2}]}});
        let selected = select_records(&body, "$.data.users[*]").unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(scalar_at(&selected[0], "id").as_deref(), Some("1"));
        assert_eq!(
            next_link_url("<https://example.test/users?page=2>; rel=\"next\"").as_deref(),
            Some("https://example.test/users?page=2")
        );
        assert_eq!(
            next_link_url(
                "<https://example.test/users?labels=a,b&page=1>; rel=\"prev\"; title=\"a,b;c\", </users?page=2>; title=\"next; page\"; rel=\"prev next\""
            )
            .as_deref(),
            Some("/users?page=2")
        );
        assert_eq!(next_link_url("</users?page=2>; title=\"rel=next\""), None);
    }

    #[test]
    fn provider_owned_next_page_query_survives_static_query_merge() {
        let static_query = BTreeMap::from([
            ("include".to_owned(), "profile".to_owned()),
            ("tenant".to_owned(), "configured".to_owned()),
        ]);
        for pagination in [
            Pagination::Link {
                header: "link".to_owned(),
            },
            Pagination::NextUrl {
                response_path: "$.next".to_owned(),
            },
        ] {
            let mut url =
                Url::parse("https://provider.example/users?cursor=next&tenant=provider").unwrap();
            apply_query(&mut url, &static_query, &pagination, None, 0, 0);
            let query = url.query_pairs().collect::<BTreeMap<_, _>>();
            assert_eq!(
                query.get("cursor").map(|value| value.as_ref()),
                Some("next")
            );
            assert_eq!(
                query.get("include").map(|value| value.as_ref()),
                Some("profile")
            );
            assert_eq!(
                query.get("tenant").map(|value| value.as_ref()),
                Some("configured")
            );
        }
    }

    #[test]
    fn only_cursor_pagination_accepts_a_collection_cursor() {
        let requested = Some("resume-here");
        let cursor = Pagination::Cursor {
            parameter: "cursor".to_owned(),
            response_path: "$.next".to_owned(),
            page_size_parameter: None,
            page_size: 100,
        };
        assert_eq!(
            effective_cursor(&cursor, requested),
            Some("resume-here".to_owned())
        );

        for pagination in [
            Pagination::None,
            Pagination::Page {
                parameter: "page".to_owned(),
                start: 1,
                page_size_parameter: None,
                page_size: 100,
            },
            Pagination::Offset {
                parameter: "offset".to_owned(),
                limit_parameter: "limit".to_owned(),
                page_size: 100,
            },
            Pagination::Link {
                header: "link".to_owned(),
            },
            Pagination::NextUrl {
                response_path: "$.next".to_owned(),
            },
        ] {
            assert_eq!(effective_cursor(&pagination, requested), None);
        }
    }

    #[test]
    fn next_url_resolution_preserves_rfc3986_path_semantics() {
        let base = Url::parse("https://provider.example/api/v1/").unwrap();
        assert_eq!(
            resolve_next_url(&base, "/api/v2/page2")
                .unwrap()
                .unwrap()
                .as_str(),
            "https://provider.example/api/v2/page2"
        );
        assert_eq!(
            resolve_next_url(&base, "//provider.example/page2")
                .unwrap()
                .unwrap()
                .as_str(),
            "https://provider.example/page2"
        );
        let current = Url::parse("https://provider.example/api/v1/users/").unwrap();
        assert_eq!(
            resolve_next_url(&current, "page2")
                .unwrap()
                .unwrap()
                .as_str(),
            "https://provider.example/api/v1/users/page2"
        );
        assert!(resolve_next_url(&current, "  ").unwrap().is_none());
        let changed_origin = resolve_next_url(&base, "//other.example/page2")
            .unwrap()
            .unwrap();
        assert!(ensure_same_origin(&base, &changed_origin).is_err());
    }

    #[test]
    fn link_pagination_uses_the_catalog_header_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-next-page",
            "</users?page=2>; rel=\"next\"".parse().unwrap(),
        );
        assert_eq!(
            response_next_link(
                &headers,
                &Pagination::Link {
                    header: "x-next-page".to_owned(),
                },
            )
            .unwrap()
            .as_deref(),
            Some("/users?page=2")
        );
        assert!(
            response_next_link(
                &headers,
                &Pagination::Link {
                    header: "not a header".to_owned(),
                },
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn verified_catalog_family_executes_and_can_complete() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /users?"));
            assert!(request.contains("authorization: Bearer token"));
            let body = r#"{"entries":[{"id":"user-1","name":"User One","login":"user@example.test","status":"active"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let mut connector = HttpSourceConnector::new(
            catalog.get("box").unwrap().clone(),
            "users",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::Bearer {
                token: "token".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("box-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert!(matches!(batch.scope, CollectedScope::Complete(_)));
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "user-1");
    }

    #[tokio::test]
    async fn provider_response_is_rejected_before_declared_oversize_body_is_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                MAX_RESPONSE_BYTES + 1
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let response = build_client(Duration::from_secs(1), Duration::from_secs(1))
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let error = read_bounded_json(response).await.unwrap_err();
        server.await.unwrap();
        assert!(error.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn provider_request_timeout_also_bounds_a_stalled_response_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let response = build_client(Duration::from_millis(50), Duration::from_millis(50))
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let error = read_bounded_json(response).await.unwrap_err();
        server.await.unwrap();
        assert!(matches!(error, HttpConnectorError::Request(_)));
    }

    #[tokio::test]
    async fn chunked_provider_response_is_bounded_without_a_content_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let response = build_client(Duration::from_secs(1), Duration::from_secs(1))
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let error = read_bounded_json_with_limit(response, 8).await.unwrap_err();
        server.await.unwrap();
        assert!(error.to_string().contains("8-byte limit"));
    }
}
