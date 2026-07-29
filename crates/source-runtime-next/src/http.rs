use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        SignableBody, SignableRequest, SigningParams, SigningSettings, sign as sign_http_request,
    },
    sign::v4,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, CompleteCollection, ModelError, ObservationId,
};
use cerebro_source_catalog::{
    AuthModel, CompiledFamily, CompiledSource, HttpMethod, Pagination, PathParameterBinding,
};
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    Client, Request, Response, StatusCode, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha512};
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::{CollectedBatch, CollectedScope, CollectionRequest, SourceConnector, SourceRecord};

const MAX_PAGES: usize = 10_000;
const MAX_FANOUT_SCOPES: usize = 1_000;
const MAX_RESPONSE_BYTES: usize = 16 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Eq, PartialEq)]
pub enum ResolvedAuth {
    None,
    Bearer {
        token: String,
    },
    Basic {
        username: String,
        password: String,
    },
    Header {
        name: String,
        value: String,
    },
    HeaderParameters {
        parameters: BTreeMap<String, String>,
    },
    QueryParameters {
        parameters: BTreeMap<String, String>,
    },
    JsonBodyParameters {
        parameters: BTreeMap<String, String>,
    },
    AwsSigV4 {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        region: String,
        service: String,
    },
    DuoHmacV5 {
        integration_key: String,
        secret_key: String,
    },
}

impl fmt::Debug for ResolvedAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Bearer { .. } => formatter.write_str("Bearer { token: [REDACTED] }"),
            Self::Basic { .. } => {
                formatter.write_str("Basic { username: [REDACTED], password: [REDACTED] }")
            }
            Self::Header { name, .. } => formatter
                .debug_struct("Header")
                .field("name", name)
                .field("value", &"[REDACTED]")
                .finish(),
            Self::HeaderParameters { parameters } => formatter
                .debug_struct("HeaderParameters")
                .field("names", &parameters.keys().collect::<Vec<_>>())
                .field("values", &"[REDACTED]")
                .finish(),
            Self::QueryParameters { parameters } => formatter
                .debug_struct("QueryParameters")
                .field("names", &parameters.keys().collect::<Vec<_>>())
                .field("values", &"[REDACTED]")
                .finish(),
            Self::JsonBodyParameters { parameters } => formatter
                .debug_struct("JsonBodyParameters")
                .field("names", &parameters.keys().collect::<Vec<_>>())
                .field("values", &"[REDACTED]")
                .finish(),
            Self::AwsSigV4 { session_token, .. } => formatter
                .debug_struct("AwsSigV4")
                .field("access_key_id", &"[REDACTED]")
                .field("secret_access_key", &"[REDACTED]")
                .field(
                    "session_token",
                    &session_token.as_ref().map(|_| "[REDACTED]"),
                )
                .field("region", &"[CONFIGURED]")
                .field("service", &"[CONFIGURED]")
                .finish(),
            Self::DuoHmacV5 { .. } => formatter
                .debug_struct("DuoHmacV5")
                .field("integration_key", &"[REDACTED]")
                .field("secret_key", &"[REDACTED]")
                .finish(),
        }
    }
}

impl Drop for ResolvedAuth {
    fn drop(&mut self) {
        match self {
            Self::None => {}
            Self::Bearer { token } => token.zeroize(),
            Self::Basic { username, password } => {
                username.zeroize();
                password.zeroize();
            }
            Self::Header { value, .. } => value.zeroize(),
            Self::HeaderParameters { parameters } => {
                for value in parameters.values_mut() {
                    value.zeroize();
                }
            }
            Self::QueryParameters { parameters } => {
                for value in parameters.values_mut() {
                    value.zeroize();
                }
            }
            Self::JsonBodyParameters { parameters } => {
                for value in parameters.values_mut() {
                    value.zeroize();
                }
            }
            Self::AwsSigV4 {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => {
                access_key_id.zeroize();
                secret_access_key.zeroize();
                session_token.zeroize();
            }
            Self::DuoHmacV5 {
                integration_key,
                secret_key,
            } => {
                integration_key.zeroize();
                secret_key.zeroize();
            }
        }
    }
}

#[derive(Debug)]
pub enum HttpConnectorError {
    InvalidConfiguration(String),
    InvalidUrl(String),
    Request(reqwest::Error),
    RedactedRequest,
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
            Self::RedactedRequest => formatter.write_str("provider request failed"),
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

struct RequestScope {
    url: Url,
    query_parameters: BTreeMap<String, String>,
    record_attributes: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct RequestScopeValues {
    path_parameters: BTreeMap<String, String>,
    query_parameters: BTreeMap<String, String>,
    record_attributes: BTreeMap<String, String>,
}

#[derive(Clone)]
enum RequestParameterTarget {
    Path(String),
    Query(String),
    RecordAttribute(String),
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
        validate_auth(&source, &auth)?;
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

    fn request_scopes(&self) -> Result<Vec<RequestScope>, HttpConnectorError> {
        let mut binding_targets: BTreeMap<(String, u8), Vec<RequestParameterTarget>> =
            BTreeMap::new();
        for (parameter, binding) in self.family.path_parameters() {
            add_binding_target(
                &mut binding_targets,
                binding,
                RequestParameterTarget::Path(parameter.clone()),
            );
        }
        for (parameter, binding) in self.family.config_query() {
            add_binding_target(
                &mut binding_targets,
                binding,
                RequestParameterTarget::Query(parameter.clone()),
            );
        }
        for (attribute, binding) in self.family.config_attributes() {
            add_binding_target(
                &mut binding_targets,
                binding,
                RequestParameterTarget::RecordAttribute(attribute.clone()),
            );
        }

        let mut scopes = vec![RequestScopeValues::default()];
        for ((field, mode), targets) in binding_targets {
            let values = match mode {
                0 => vec![Some(required_config_value(&self.config, &field)?)],
                1 => vec![
                    self.config
                        .get(&field)
                        .filter(|value| !value.is_empty())
                        .cloned(),
                ],
                2 => csv_fanout_values(&self.config, &field)?
                    .into_iter()
                    .map(Some)
                    .collect(),
                _ => unreachable!(),
            };
            let expanded = scopes.len().checked_mul(values.len()).ok_or_else(|| {
                HttpConnectorError::InvalidConfiguration(format!(
                    "family {} fanout scope count overflowed",
                    self.family.id()
                ))
            })?;
            if expanded > MAX_FANOUT_SCOPES {
                return Err(HttpConnectorError::InvalidConfiguration(format!(
                    "family {} fanout exceeds {MAX_FANOUT_SCOPES} scopes",
                    self.family.id()
                )));
            }
            let mut next = Vec::with_capacity(expanded);
            for scope in &scopes {
                for value in &values {
                    let mut scope = scope.clone();
                    if let Some(value) = value {
                        for target in &targets {
                            match target {
                                RequestParameterTarget::Path(parameter) => {
                                    scope
                                        .path_parameters
                                        .insert(parameter.clone(), value.clone());
                                    scope
                                        .record_attributes
                                        .insert(parameter.clone(), value.clone());
                                }
                                RequestParameterTarget::Query(parameter) => {
                                    scope
                                        .query_parameters
                                        .insert(parameter.clone(), value.clone());
                                }
                                RequestParameterTarget::RecordAttribute(attribute) => {
                                    scope
                                        .record_attributes
                                        .insert(attribute.clone(), value.clone());
                                }
                            }
                        }
                    }
                    next.push(scope);
                }
            }
            scopes = next;
        }
        scopes
            .into_iter()
            .map(|scope| {
                self.request_url(&scope.path_parameters)
                    .map(|url| RequestScope {
                        url,
                        query_parameters: scope.query_parameters,
                        record_attributes: scope.record_attributes,
                    })
            })
            .collect()
    }

    fn request_url(
        &self,
        path_parameters: &BTreeMap<String, String>,
    ) -> Result<Url, HttpConnectorError> {
        let mut path = self.family.path().to_owned();
        for (key, value) in path_parameters {
            let direct = format!("{{{key}}}");
            let configured = format!("${{config.{key}}}");
            if path.contains(&direct) || path.contains(&configured) {
                let encoded = encode_path_parameter(key, value)?;
                path = path.replace(&direct, &encoded);
                path = path.replace(&configured, &encoded);
            }
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

fn add_binding_target(
    targets: &mut BTreeMap<(String, u8), Vec<RequestParameterTarget>>,
    binding: &PathParameterBinding,
    target: RequestParameterTarget,
) {
    let mode = match binding {
        PathParameterBinding::ScalarConfig { .. } => 0,
        PathParameterBinding::OptionalScalarConfig { .. } => 1,
        PathParameterBinding::CsvFanout { .. } => 2,
    };
    targets
        .entry((binding.field().to_owned(), mode))
        .or_default()
        .push(target);
}

fn required_config_value(
    config: &BTreeMap<String, String>,
    field: &str,
) -> Result<String, HttpConnectorError> {
    config
        .get(field)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            HttpConnectorError::InvalidConfiguration(format!("request config {field} is required"))
        })
}

fn csv_fanout_values(
    config: &BTreeMap<String, String>,
    field: &str,
) -> Result<Vec<String>, HttpConnectorError> {
    let raw = required_config_value(config, field)?;
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if seen.insert(value.to_owned()) {
            values.push(value.to_owned());
            if values.len() > MAX_FANOUT_SCOPES {
                return Err(HttpConnectorError::InvalidConfiguration(format!(
                    "path parameter config {field} exceeds {MAX_FANOUT_SCOPES} values"
                )));
            }
        }
    }
    if values.is_empty() {
        return Err(HttpConnectorError::InvalidConfiguration(format!(
            "request config {field} requires at least one value"
        )));
    }
    Ok(values)
}

fn encode_path_parameter(key: &str, value: &str) -> Result<String, HttpConnectorError> {
    if value.is_empty() {
        return Err(HttpConnectorError::InvalidConfiguration(format!(
            "path parameter {key} is required"
        )));
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(encoded)
}

#[async_trait]
impl SourceConnector for HttpSourceConnector {
    type Error = HttpConnectorError;

    async fn collect(&mut self, request: CollectionRequest) -> Result<CollectedBatch, Self::Error> {
        let observed_at = unix_millis()?;
        let request_scopes = self.request_scopes()?;
        let initial_cursor = effective_cursor(self.family.pagination(), request.cursor.as_deref());
        if request.cursor.is_some() && request_scopes.len() > 1 {
            return Err(HttpConnectorError::InvalidConfiguration(format!(
                "family {} fanout does not accept an unscoped cursor",
                self.family.id()
            )));
        }
        let mut records = Vec::new();
        let mut remaining_pages = MAX_PAGES;

        for RequestScope {
            mut url,
            query_parameters,
            record_attributes,
        } in request_scopes
        {
            let mut request_query = self.family.static_query().clone();
            request_query.extend(query_parameters);
            let mut cursor = initial_cursor.clone();
            let mut page = pagination_start(self.family.pagination());
            let mut offset = 0usize;
            let mut exhausted = false;
            while remaining_pages > 0 {
                remaining_pages -= 1;
                let query_cursor = (!self.family.cursor_in_json_body())
                    .then_some(cursor.as_deref())
                    .flatten();
                apply_query(
                    &mut url,
                    &request_query,
                    self.family.pagination(),
                    query_cursor,
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
                    ResolvedAuth::Header { .. } | ResolvedAuth::HeaderParameters { .. } => builder,
                    ResolvedAuth::QueryParameters { .. }
                    | ResolvedAuth::JsonBodyParameters { .. }
                    | ResolvedAuth::AwsSigV4 { .. }
                    | ResolvedAuth::DuoHmacV5 { .. } => builder,
                };
                if let ResolvedAuth::JsonBodyParameters { parameters } = &self.auth {
                    let body = json_auth_body(
                        parameters,
                        self.family.cursor_in_json_body(),
                        self.family.pagination(),
                        cursor.as_deref(),
                    )?;
                    builder = builder.json(&body);
                }
                let sensitive_query = matches!(self.auth, ResolvedAuth::QueryParameters { .. });
                let mut provider_request = builder.build().map_err(|error| {
                    if sensitive_query {
                        HttpConnectorError::RedactedRequest
                    } else {
                        HttpConnectorError::Request(error)
                    }
                })?;
                apply_auth_headers(&mut provider_request, &self.auth)?;
                if sensitive_query {
                    apply_auth_query_parameters(&mut provider_request, &self.auth)?;
                }
                match self.auth {
                    ResolvedAuth::AwsSigV4 { .. } => {
                        sign_aws_sigv4(&mut provider_request, &self.auth, SystemTime::now())?;
                    }
                    ResolvedAuth::DuoHmacV5 { .. } => {
                        sign_duo_hmac_v5(&mut provider_request, &self.auth, SystemTime::now())?;
                    }
                    _ => {}
                }
                let response = self
                    .client
                    .execute(provider_request)
                    .await
                    .map_err(|error| {
                        if sensitive_query {
                            HttpConnectorError::RedactedRequest
                        } else {
                            HttpConnectorError::Request(error)
                        }
                    })?;
                let status = response.status();
                if !status.is_success() {
                    return Err(HttpConnectorError::ProviderStatus(status));
                }
                let next_link = response_next_link(response.headers(), self.family.pagination())?;
                let body = read_bounded_json(response).await?;
                let selected = select_records(&body, self.family.record_selector())?;
                let selected_count = selected.len();
                for value in selected {
                    let value =
                        normalize_selected_record(value, self.family.scalar_record_field())?;
                    validate_record_scope(self.family.id(), &value, &record_attributes)?;
                    let provider_id =
                        scalar_at(&value, self.family.id_field()).ok_or_else(|| {
                            HttpConnectorError::InvalidResponse(format!(
                                "family {} record is missing {}",
                                self.family.id(),
                                self.family.id_field()
                            ))
                        })?;
                    let mut fields = flatten_scalars(&value);
                    fields.extend(record_attributes.clone());
                    records.push(SourceRecord {
                        observation_id: observation_id(
                            self.source.id(),
                            self.family.id(),
                            &provider_id,
                            &record_attributes,
                            observed_at,
                        )?,
                        family: self.family.id().to_owned(),
                        provider_kind: format!("{}.{}", self.source.id(), self.family.id()),
                        provider_id,
                        fields,
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
            next_cursor: None,
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

fn validate_auth(source: &CompiledSource, actual: &ResolvedAuth) -> Result<(), HttpConnectorError> {
    let valid = match source.auth() {
        AuthModel::None => matches!(actual, ResolvedAuth::None),
        AuthModel::Basic => matches!(actual, ResolvedAuth::Basic { .. }),
        AuthModel::ApiKey if !source.auth_json_body_parameters().is_empty() => {
            matches!(actual, ResolvedAuth::JsonBodyParameters { .. })
        }
        AuthModel::ApiKey if !source.auth_query_parameters().is_empty() => {
            matches!(actual, ResolvedAuth::QueryParameters { .. })
        }
        AuthModel::ApiKey if !source.auth_header_parameters().is_empty() => match actual {
            ResolvedAuth::HeaderParameters { parameters } => {
                parameters.len() == source.auth_header_parameters().len()
                    && parameters.values().all(|value| !value.is_empty())
                    && parameters.keys().all(|actual| {
                        source
                            .auth_header_parameters()
                            .keys()
                            .any(|expected| actual.eq_ignore_ascii_case(expected))
                    })
                    && source.auth_header_parameters().keys().all(|expected| {
                        parameters
                            .keys()
                            .any(|actual| actual.eq_ignore_ascii_case(expected))
                    })
            }
            _ => false,
        },
        AuthModel::ApiKey => match actual {
            ResolvedAuth::Header { name, value } => {
                let expected_header = source.token_header();
                let expected_scheme = source.token_scheme();
                !expected_header.is_empty()
                    && name.eq_ignore_ascii_case(expected_header)
                    && if expected_scheme.is_empty() {
                        !value.is_empty()
                    } else {
                        value
                            .strip_prefix(expected_scheme)
                            .and_then(|value| value.strip_prefix(' '))
                            .is_some_and(|value| !value.is_empty())
                    }
            }
            _ => false,
        },
        AuthModel::BearerToken
        | AuthModel::OauthAuthorizationCode
        | AuthModel::OauthClientCredentials
        | AuthModel::TwoStep
        | AuthModel::Jwt => matches!(
            actual,
            ResolvedAuth::Bearer { .. } | ResolvedAuth::Header { .. }
        ),
        AuthModel::AwsSigV4 => matches!(actual, ResolvedAuth::AwsSigV4 { .. }),
        AuthModel::DuoHmacV5 => matches!(actual, ResolvedAuth::DuoHmacV5 { .. }),
        AuthModel::Signature | AuthModel::DuoHmac => false,
    };
    if valid {
        Ok(())
    } else {
        Err(HttpConnectorError::InvalidConfiguration(
            "resolved credential does not match the source auth model".to_owned(),
        ))
    }
}

fn apply_auth_headers(
    request: &mut Request,
    auth: &ResolvedAuth,
) -> Result<(), HttpConnectorError> {
    match auth {
        ResolvedAuth::Header { name, value } => insert_sensitive_header(request, name, value),
        ResolvedAuth::HeaderParameters { parameters } => {
            for (name, value) in parameters {
                insert_sensitive_header(request, name, value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn insert_sensitive_header(
    request: &mut Request,
    name: &str,
    value: &str,
) -> Result<(), HttpConnectorError> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        HttpConnectorError::InvalidConfiguration(
            "resolved credential contains an invalid header name".to_owned(),
        )
    })?;
    let mut value = HeaderValue::from_str(value).map_err(|_| {
        HttpConnectorError::InvalidConfiguration(
            "resolved credential contains an invalid header value".to_owned(),
        )
    })?;
    value.set_sensitive(true);
    request.headers_mut().insert(name, value);
    Ok(())
}

fn apply_auth_query_parameters(
    request: &mut Request,
    auth: &ResolvedAuth,
) -> Result<(), HttpConnectorError> {
    let ResolvedAuth::QueryParameters { parameters } = auth else {
        return Err(HttpConnectorError::InvalidConfiguration(
            "query authentication requires query parameters".to_owned(),
        ));
    };
    if parameters.is_empty() {
        return Err(HttpConnectorError::InvalidConfiguration(
            "query authentication requires at least one parameter".to_owned(),
        ));
    }
    if parameters.len() > 16 {
        return Err(HttpConnectorError::InvalidConfiguration(
            "query authentication exceeds the 16-parameter limit".to_owned(),
        ));
    }
    for (name, value) in parameters {
        if !valid_auth_query_parameter_name(name) || value.is_empty() {
            return Err(HttpConnectorError::InvalidConfiguration(
                "query authentication parameters are invalid".to_owned(),
            ));
        }
    }
    let retained = request
        .url()
        .query_pairs()
        .filter(|(name, _)| !parameters.contains_key(name.as_ref()))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut query = request.url_mut().query_pairs_mut();
    query.clear();
    query.extend_pairs(retained);
    for (name, value) in parameters {
        query.append_pair(name, value);
    }
    Ok(())
}

fn valid_auth_query_parameter_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn json_auth_body(
    parameters: &BTreeMap<String, String>,
    cursor_in_json_body: bool,
    pagination: &Pagination,
    cursor: Option<&str>,
) -> Result<BTreeMap<String, String>, HttpConnectorError> {
    if parameters.is_empty() || parameters.len() > 16 {
        return Err(HttpConnectorError::InvalidConfiguration(
            "JSON body authentication requires 1 to 16 parameters".to_owned(),
        ));
    }
    let mut body = BTreeMap::new();
    for (name, value) in parameters {
        if !valid_auth_query_parameter_name(name) || value.is_empty() {
            return Err(HttpConnectorError::InvalidConfiguration(
                "JSON body authentication parameters are invalid".to_owned(),
            ));
        }
        body.insert(name.clone(), value.clone());
    }
    if cursor_in_json_body {
        let Pagination::Cursor { parameter, .. } = pagination else {
            return Err(HttpConnectorError::InvalidConfiguration(
                "JSON body cursor requires cursor pagination".to_owned(),
            ));
        };
        if body.contains_key(parameter) {
            return Err(HttpConnectorError::InvalidConfiguration(
                "JSON body cursor conflicts with an authentication parameter".to_owned(),
            ));
        }
        if let Some(cursor) = cursor.filter(|value| !value.is_empty()) {
            body.insert(parameter.clone(), cursor.to_owned());
        }
    }
    Ok(body)
}

fn sign_duo_hmac_v5(
    request: &mut Request,
    auth: &ResolvedAuth,
    signed_at: SystemTime,
) -> Result<(), HttpConnectorError> {
    let ResolvedAuth::DuoHmacV5 {
        integration_key,
        secret_key,
    } = auth
    else {
        return Err(HttpConnectorError::InvalidConfiguration(
            "Duo HMAC v5 signing requires Duo credentials".to_owned(),
        ));
    };
    for (field, value) in [
        ("integration key", integration_key.as_str()),
        ("secret key", secret_key.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(HttpConnectorError::InvalidConfiguration(format!(
                "Duo HMAC v5 {field} is required"
            )));
        }
    }
    let date_format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] -0000",
    )
    .map_err(|error| {
        HttpConnectorError::InvalidConfiguration(format!(
            "build Duo HMAC v5 date format: {error}"
        ))
    })?;
    let date = OffsetDateTime::from(signed_at)
        .format(&date_format)
        .map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!("format Duo HMAC v5 date: {error}"))
        })?;
    let canonical = duo_hmac_v5_canonical(request, &date)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(secret_key.as_bytes()).map_err(|error| {
        HttpConnectorError::InvalidConfiguration(format!("initialize Duo HMAC v5 signer: {error}"))
    })?;
    mac.update(canonical.as_bytes());
    let signature = hex(&mac.finalize().into_bytes());
    let mut authorization = HeaderValue::from_str(&format!(
        "Basic {}",
        BASE64.encode(format!("{integration_key}:{signature}"))
    ))
    .map_err(|error| {
        HttpConnectorError::InvalidConfiguration(format!(
            "build Duo HMAC v5 authorization: {error}"
        ))
    })?;
    authorization.set_sensitive(true);
    request.headers_mut().insert(
        reqwest::header::DATE,
        HeaderValue::from_str(&date).map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!(
                "build Duo HMAC v5 date header: {error}"
            ))
        })?,
    );
    request
        .headers_mut()
        .insert(reqwest::header::AUTHORIZATION, authorization);
    Ok(())
}

fn duo_hmac_v5_canonical(request: &Request, date: &str) -> Result<String, HttpConnectorError> {
    let body = match request.method() {
        &reqwest::Method::GET | &reqwest::Method::DELETE => {
            if request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .is_some_and(|body| !body.is_empty())
            {
                return Err(HttpConnectorError::InvalidConfiguration(
                    "Duo HMAC v5 GET and DELETE requests cannot contain a body".to_owned(),
                ));
            }
            &[][..]
        }
        &reqwest::Method::POST | &reqwest::Method::PUT | &reqwest::Method::PATCH => {
            let content_type = request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            if content_type != Some("application/json") {
                return Err(HttpConnectorError::InvalidConfiguration(
                    "Duo HMAC v5 request bodies require application/json".to_owned(),
                ));
            }
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or_else(|| {
                    HttpConnectorError::InvalidConfiguration(
                        "Duo HMAC v5 requires a replayable request body".to_owned(),
                    )
                })?
        }
        method => {
            return Err(HttpConnectorError::InvalidConfiguration(format!(
                "Duo HMAC v5 does not support {method} requests"
            )));
        }
    };
    let host = request.url().host_str().ok_or_else(|| {
        HttpConnectorError::InvalidConfiguration(
            "Duo HMAC v5 request URL requires a host".to_owned(),
        )
    })?;
    let mut additional_headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            name.starts_with("x-duo-").then(|| {
                value
                    .to_str()
                    .map(|value| (name, value.trim().to_owned()))
                    .map_err(|_| {
                        HttpConnectorError::InvalidConfiguration(
                            "Duo HMAC v5 cannot sign a non-text X-Duo header".to_owned(),
                        )
                    })
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    additional_headers.sort();
    let canonical_headers = additional_headers
        .iter()
        .flat_map(|(name, value)| [name.as_str(), value.as_str()])
        .collect::<Vec<_>>()
        .join("\0");
    Ok([
        date.to_owned(),
        request.method().as_str().to_ascii_uppercase(),
        host.to_ascii_lowercase(),
        request.url().path().to_owned(),
        duo_canonical_query(request.url()),
        sha512_hex(body),
        sha512_hex(canonical_headers.as_bytes()),
    ]
    .join("\n"))
}

fn duo_canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                duo_percent_encode(&key),
                duo_percent_encode(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn duo_percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn sha512_hex(value: impl AsRef<[u8]>) -> String {
    hex(&Sha512::digest(value))
}

fn sign_aws_sigv4(
    request: &mut Request,
    auth: &ResolvedAuth,
    time: SystemTime,
) -> Result<(), HttpConnectorError> {
    let ResolvedAuth::AwsSigV4 {
        access_key_id,
        secret_access_key,
        session_token,
        region,
        service,
    } = auth
    else {
        return Err(HttpConnectorError::InvalidConfiguration(
            "AWS SigV4 signing requires AWS credentials".to_owned(),
        ));
    };
    for (field, value) in [
        ("access key ID", access_key_id.as_str()),
        ("secret access key", secret_access_key.as_str()),
        ("region", region.as_str()),
        ("service", service.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(HttpConnectorError::InvalidConfiguration(format!(
                "AWS SigV4 {field} is required"
            )));
        }
    }
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .unwrap_or_default();
    if request.body().is_some() && request.body().and_then(reqwest::Body::as_bytes).is_none() {
        return Err(HttpConnectorError::InvalidConfiguration(
            "AWS SigV4 requires a replayable request body".to_owned(),
        ));
    }
    let header_values = request
        .headers()
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str(), value))
                .map_err(|_| {
                    HttpConnectorError::InvalidConfiguration(format!(
                        "AWS SigV4 cannot sign non-text header {}",
                        name.as_str()
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let credentials = Credentials::new(
        access_key_id,
        secret_access_key,
        session_token.clone(),
        None,
        "cerebro-source-runtime",
    );
    let identity = credentials.into();
    let params: SigningParams<'_> = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(time)
        .settings(SigningSettings::default())
        .build()
        .map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!(
                "build AWS SigV4 signing parameters: {error}"
            ))
        })?
        .into();
    let signable = SignableRequest::new(
        request.method().as_str(),
        request.url().as_str(),
        header_values.into_iter(),
        SignableBody::Bytes(body),
    )
    .map_err(|error| {
        HttpConnectorError::InvalidConfiguration(format!("build AWS SigV4 request: {error}"))
    })?;
    let (instructions, _) = sign_http_request(signable, &params)
        .map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!("sign AWS SigV4 request: {error}"))
        })?
        .into_parts();
    let (headers, query) = instructions.into_parts();
    if !query.is_empty() {
        return Err(HttpConnectorError::InvalidConfiguration(
            "AWS SigV4 unexpectedly returned query signing instructions".to_owned(),
        ));
    }
    for header in headers {
        let name = HeaderName::from_bytes(header.name().as_bytes()).map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!(
                "invalid AWS SigV4 header name: {error}"
            ))
        })?;
        let mut value = HeaderValue::from_str(header.value()).map_err(|error| {
            HttpConnectorError::InvalidConfiguration(format!(
                "invalid AWS SigV4 header value: {error}"
            ))
        })?;
        value.set_sensitive(
            header.sensitive()
                || name == reqwest::header::AUTHORIZATION
                || name.as_str() == "x-amz-security-token",
        );
        request.headers_mut().insert(name, value);
    }
    Ok(())
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
        drop(query);
        if url.query().is_some_and(str::is_empty) {
            url.set_query(None);
        }
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
    drop(query);
    if url.query().is_some_and(str::is_empty) {
        url.set_query(None);
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

fn normalize_selected_record(
    value: Value,
    scalar_record_field: Option<&str>,
) -> Result<Value, HttpConnectorError> {
    let Some(field) = scalar_record_field else {
        return Ok(value);
    };
    if scalar(&value).is_none_or(|value| value.trim().is_empty()) {
        return Err(HttpConnectorError::InvalidResponse(format!(
            "scalar record mapping for {field} selected a non-scalar value"
        )));
    }
    Ok(Value::Object(Map::from_iter([(field.to_owned(), value)])))
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

fn validate_record_scope(
    family_id: &str,
    value: &Value,
    path_parameters: &BTreeMap<String, String>,
) -> Result<(), HttpConnectorError> {
    for (parameter, expected) in path_parameters {
        if let Some(actual) = scalar_at(value, parameter)
            && actual != *expected
        {
            return Err(HttpConnectorError::InvalidResponse(format!(
                "family {family_id} record changed requested {parameter} scope"
            )));
        }
    }
    Ok(())
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
    path_parameters: &BTreeMap<String, String>,
    observed_at: i64,
) -> Result<ObservationId, HttpConnectorError> {
    let mut hasher = Sha256::new();
    let observed_at = observed_at.to_string();
    for part in [source_id, family_id, provider_id] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    for (parameter, value) in path_parameters {
        for part in [parameter.as_str(), value.as_str()] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
    }
    hasher.update((observed_at.len() as u64).to_be_bytes());
    hasher.update(observed_at.as_bytes());
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
        time::{Duration, UNIX_EPOCH},
    };

    use cerebro_organizational_model::{SourceRuntimeId, TenantId};
    use cerebro_source_catalog::SourceCatalog;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{CatalogGraphMapper, GraphMapper};

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

        let scalar = normalize_selected_record(
            Value::String("https://example.test".to_owned()),
            Some("url"),
        )
        .unwrap();
        assert_eq!(
            scalar_at(&scalar, "url").as_deref(),
            Some("https://example.test")
        );
        for invalid in [
            Value::Null,
            Value::String(String::new()),
            Value::String(" \t".to_owned()),
            serde_json::json!({}),
            serde_json::json!([]),
        ] {
            assert!(matches!(
                normalize_selected_record(invalid, Some("url")),
                Err(HttpConnectorError::InvalidResponse(_))
            ));
        }
        let object = serde_json::json!({"id": "one"});
        assert_eq!(
            normalize_selected_record(object.clone(), None).unwrap(),
            object
        );
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
    fn dynamic_catalog_path_values_cannot_expand_provider_scope() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let connector = HttpSourceConnector::new(
            catalog.get("telnyx").unwrap().clone(),
            "wireless_connectivity_log",
            "https://api.example.test/v2",
            BTreeMap::from([(
                "sim_card_id".to_owned(),
                "../other?scope=expanded#fragment".to_owned(),
            )]),
            ResolvedAuth::Bearer {
                token: "token".to_owned(),
            },
        )
        .unwrap();
        let scopes = connector.request_scopes().unwrap();
        assert_eq!(scopes.len(), 1);
        let url = &scopes[0].url;
        assert_eq!(
            url.as_str(),
            "https://api.example.test/v2/sim_cards/%2E%2E%2Fother%3Fscope%3Dexpanded%23fragment/wireless_connectivity_logs"
        );
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn promoted_source_paths_require_and_encode_exact_runtime_scope() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();

        let missing_airtable_scope = HttpSourceConnector::new(
            catalog.get("airtable").unwrap().clone(),
            "users",
            "https://api.airtable.com",
            BTreeMap::new(),
            ResolvedAuth::Bearer {
                token: "token".to_owned(),
            },
        )
        .unwrap()
        .request_scopes()
        .err()
        .unwrap();
        assert!(matches!(
            missing_airtable_scope,
            HttpConnectorError::InvalidConfiguration(_)
        ));

        let airtable = HttpSourceConnector::new(
            catalog.get("airtable").unwrap().clone(),
            "audit_events",
            "https://api.airtable.com",
            BTreeMap::from([(
                "enterprise_account_id".to_owned(),
                "../other?scope=expanded#fragment".to_owned(),
            )]),
            ResolvedAuth::Bearer {
                token: "token".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            airtable.request_scopes().unwrap()[0].url.as_str(),
            "https://api.airtable.com/v0/meta/enterpriseAccounts/%2E%2E%2Fother%3Fscope%3Dexpanded%23fragment/auditLogEvents"
        );

        let anchore = HttpSourceConnector::new(
            catalog.get("anchore").unwrap().clone(),
            "vulnerabilities",
            "https://anchore.example/v2",
            BTreeMap::from([
                ("app_id".to_owned(), "orders/api".to_owned()),
                ("version_id".to_owned(), "../production".to_owned()),
            ]),
            ResolvedAuth::Basic {
                username: "runtime-user".to_owned(),
                password: "runtime-password".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            anchore.request_scopes().unwrap()[0].url.as_str(),
            "https://anchore.example/v2/apps/orders%2Fapi/versions/%2E%2E%2Fproduction/vulnerabilities"
        );
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

    #[test]
    fn aws_sigv4_signing_is_deterministic_and_covers_the_query() {
        let auth = ResolvedAuth::AwsSigV4 {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "secret-example".to_owned(),
            session_token: Some("session-example".to_owned()),
            region: "us-east-1".to_owned(),
            service: "bedrock".to_owned(),
        };
        let time = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let client = Client::new();
        let mut first = client
            .get("https://bedrock.us-east-1.amazonaws.com/foundation-models?maxResults=10")
            .build()
            .unwrap();
        let mut same = first.try_clone().unwrap();
        let mut changed_query = client
            .get("https://bedrock.us-east-1.amazonaws.com/foundation-models?maxResults=11")
            .build()
            .unwrap();

        sign_aws_sigv4(&mut first, &auth, time).unwrap();
        sign_aws_sigv4(&mut same, &auth, time).unwrap();
        sign_aws_sigv4(&mut changed_query, &auth, time).unwrap();

        let authorization = first.headers()["authorization"].to_str().unwrap();
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 "));
        assert!(
            authorization
                .contains("Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request")
        );
        assert!(authorization.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
        assert_eq!(first.headers()["x-amz-date"], "20150830T123600Z");
        assert_eq!(first.headers()["x-amz-security-token"], "session-example");
        assert!(first.headers()["authorization"].is_sensitive());
        assert!(first.headers()["x-amz-security-token"].is_sensitive());
        assert_eq!(
            first.headers()["authorization"],
            same.headers()["authorization"]
        );
        assert_ne!(
            first.headers()["authorization"],
            changed_query.headers()["authorization"]
        );
        let debug = format!("{auth:?}");
        for secret in ["AKIDEXAMPLE", "secret-example", "session-example"] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn aws_sigv4_rejects_empty_signing_scope() {
        let mut request = Client::new()
            .get("https://bedrock.us-east-1.amazonaws.com/foundation-models")
            .build()
            .unwrap();
        let auth = ResolvedAuth::AwsSigV4 {
            access_key_id: "access".to_owned(),
            secret_access_key: "secret".to_owned(),
            session_token: None,
            region: " ".to_owned(),
            service: "bedrock".to_owned(),
        };
        let error = sign_aws_sigv4(&mut request, &auth, UNIX_EPOCH).unwrap_err();
        assert_eq!(error.to_string(), "AWS SigV4 region is required");
        assert!(!request.headers().contains_key("authorization"));
    }

    #[test]
    fn duo_hmac_v5_matches_the_provider_canonical_contract() {
        const EMPTY_SHA512: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let client = Client::new();
        let mut request = client
            .get("https://api-xxxxxxxx.duosecurity.com/admin/v1/users?username=root")
            .build()
            .unwrap();
        let canonical = duo_hmac_v5_canonical(&request, "Tue, 21 Aug 2012 17:29:18 -0000").unwrap();
        assert_eq!(
            canonical,
            [
                "Tue, 21 Aug 2012 17:29:18 -0000",
                "GET",
                "api-xxxxxxxx.duosecurity.com",
                "/admin/v1/users",
                "username=root",
                EMPTY_SHA512,
                EMPTY_SHA512,
            ]
            .join("\n")
        );

        let integration_key = ["DIWJ8X6AEYOR5", "OMC6TQ1"].concat();
        let secret_key = ["Zh5eGmUq9zpfQnyUIu5O", "L9iWoMMv5ZNmk3zLJ4Ep"].concat();
        let auth = ResolvedAuth::DuoHmacV5 {
            integration_key: integration_key.clone(),
            secret_key: secret_key.clone(),
        };
        sign_duo_hmac_v5(
            &mut request,
            &auth,
            UNIX_EPOCH + Duration::from_secs(1_345_570_158),
        )
        .unwrap();
        assert_eq!(request.headers()["date"], "Tue, 21 Aug 2012 17:29:18 -0000");
        let authorization = request.headers()["authorization"].to_str().unwrap();
        let credentials = BASE64
            .decode(authorization.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(
            String::from_utf8(credentials).unwrap(),
            "DIWJ8X6AEYOR5OMC6TQ1:c2f048c5ec058a0b27a2387820fefcf0c0a1059dab5f63d96e7add10cece874fe629f5b3c24aed25a1af1008a50e45096ea9823256930e398bc671856395b8af"
        );
        assert!(request.headers()["authorization"].is_sensitive());
        let debug = format!("{auth:?}");
        assert!(!debug.contains(&integration_key));
        assert!(!debug.contains(&secret_key));
    }

    #[test]
    fn duo_hmac_v5_sorts_and_encodes_queries_and_rejects_unsigned_bodies() {
        let request = Client::new()
            .get("https://api.example.test/admin/v1/users?username=root&realname=First%20Last")
            .header("x-duo-context", " tenant-a ")
            .build()
            .unwrap();
        let canonical = duo_hmac_v5_canonical(&request, "Tue, 21 Aug 2012 17:29:18 -0000").unwrap();
        assert_eq!(
            canonical.lines().nth(4),
            Some("realname=First%20Last&username=root")
        );
        let empty_hash = sha512_hex("");
        assert_ne!(canonical.lines().last(), Some(empty_hash.as_str()));

        let mut unsigned_body = Client::new()
            .post("https://api.example.test/admin/v1/users")
            .body("{}")
            .build()
            .unwrap();
        let auth = ResolvedAuth::DuoHmacV5 {
            integration_key: "integration".to_owned(),
            secret_key: "secret".to_owned(),
        };
        let error = sign_duo_hmac_v5(&mut unsigned_body, &auth, UNIX_EPOCH).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Duo HMAC v5 request bodies require application/json"
        );
        assert!(!unsigned_body.headers().contains_key("authorization"));
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
    async fn api2cart_uses_exact_sensitive_headers_and_offset_pagination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let request_line = request.lines().next().unwrap();
            assert!(request_line.starts_with("GET /attribute.group.list.json?"));
            assert!(request_line.contains("start=0"));
            assert!(request_line.contains("count=100"));
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("x-api-key: account-secret"))
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("x-store-key: store-secret"))
            );
            let body = r#"{"result":[{"id":"group-1","name":"Default"}]}"#;
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
        let source = catalog.get("api2cart").unwrap().clone();
        assert_eq!(
            source.authority(),
            cerebro_source_catalog::CollectionAuthority::Authoritative
        );
        let incomplete = HttpSourceConnector::new(
            source.clone(),
            "attribute_group_list_json",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::HeaderParameters {
                parameters: BTreeMap::from([("x-api-key".to_owned(), "account-secret".to_owned())]),
            },
        )
        .err()
        .unwrap();
        assert!(matches!(
            incomplete,
            HttpConnectorError::InvalidConfiguration(_)
        ));

        let malformed_auth = ResolvedAuth::HeaderParameters {
            parameters: BTreeMap::from([
                (
                    "x-api-key".to_owned(),
                    "account-secret\r\nx-leak: yes".to_owned(),
                ),
                ("x-store-key".to_owned(), "store-secret".to_owned()),
            ]),
        };
        assert!(!format!("{malformed_auth:?}").contains("account-secret"));
        let mut malformed = HttpSourceConnector::new(
            source.clone(),
            "attribute_group_list_json",
            &format!("http://{address}"),
            BTreeMap::new(),
            malformed_auth,
        )
        .unwrap();
        assert!(matches!(
            malformed
                .collect(CollectionRequest {
                    tenant_id: TenantId::parse("tenant-a").unwrap(),
                    source_runtime_id: SourceRuntimeId::parse("api2cart-malformed").unwrap(),
                    cursor: None,
                })
                .await,
            Err(HttpConnectorError::InvalidConfiguration(_))
        ));

        let auth = ResolvedAuth::HeaderParameters {
            parameters: BTreeMap::from([
                ("x-api-key".to_owned(), "account-secret".to_owned()),
                ("x-store-key".to_owned(), "store-secret".to_owned()),
            ]),
        };
        let mut request = Client::new()
            .get("https://api.example.test/resource")
            .build()
            .unwrap();
        apply_auth_headers(&mut request, &auth).unwrap();
        assert!(request.headers()["x-api-key"].is_sensitive());
        assert!(request.headers()["x-store-key"].is_sensitive());

        let mut connector = HttpSourceConnector::new(
            source,
            "attribute_group_list_json",
            &format!("http://{address}"),
            BTreeMap::new(),
            auth,
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("api2cart-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "group-1");
    }

    #[tokio::test]
    async fn botify_uses_token_auth_bounded_pages_and_scalar_provider_ids() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with(
                "GET /analyses/owner/project/20260728/features/sitemaps/samples/out_of_config?page=1&size=100 HTTP/1.1\r\n"
            ));
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Token botify-secret"))
            );
            let body = r#"{"count":1,"page":1,"size":100,"next":null,"previous":null,"results":["https://example.test/orphan"]}"#;
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
        let source = catalog.get("botify").unwrap().clone();
        assert_eq!(
            source.authority(),
            cerebro_source_catalog::CollectionAuthority::Authoritative
        );
        assert!(matches!(
            HttpSourceConnector::new(
                source.clone(),
                "out_of_config",
                &format!("http://{address}"),
                BTreeMap::from([
                    ("analysis_slug".to_owned(), "20260728".to_owned()),
                    ("project_slug".to_owned(), "project".to_owned()),
                    ("username".to_owned(), "owner".to_owned()),
                ]),
                ResolvedAuth::Header {
                    name: "Authorization".to_owned(),
                    value: "Bearer botify-secret".to_owned(),
                },
            ),
            Err(HttpConnectorError::InvalidConfiguration(_))
        ));

        let mut connector = HttpSourceConnector::new(
            source,
            "out_of_config",
            &format!("http://{address}"),
            BTreeMap::from([
                ("analysis_slug".to_owned(), "20260728".to_owned()),
                ("project_slug".to_owned(), "project".to_owned()),
                ("username".to_owned(), "owner".to_owned()),
            ]),
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Token botify-secret".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("botify-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "https://example.test/orphan");
    }

    #[tokio::test]
    async fn meraki_v1_access_policy_uses_the_proven_path_and_bearer_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(
                request.starts_with("GET /networks/network-1/switch/accessPolicies HTTP/1.1\r\n")
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer meraki-secret"))
            );
            assert!(!request.lines().next().unwrap().contains('?'));
            let body = r#"[{"accessPolicyNumber":"1234","name":"Guest WiFi"}]"#;
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
        let source = catalog.get("meraki").unwrap().clone();
        assert_eq!(
            source.authority(),
            cerebro_source_catalog::CollectionAuthority::Authoritative
        );
        for invalid_auth in [
            ResolvedAuth::Header {
                name: "X-Cisco-Meraki-API-Key".to_owned(),
                value: "meraki-secret".to_owned(),
            },
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Token meraki-secret".to_owned(),
            },
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Bearer ".to_owned(),
            },
        ] {
            assert!(matches!(
                HttpSourceConnector::new(
                    source.clone(),
                    "accesspolicy",
                    &format!("http://{address}"),
                    BTreeMap::from([("networkid".to_owned(), "network-1".to_owned())]),
                    invalid_auth,
                ),
                Err(HttpConnectorError::InvalidConfiguration(_))
            ));
        }
        let mut connector = HttpSourceConnector::new(
            source,
            "accesspolicy",
            &format!("http://{address}"),
            BTreeMap::from([("networkid".to_owned(), "network-1".to_owned())]),
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Bearer meraki-secret".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("meraki-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "1234");
    }

    #[tokio::test]
    async fn meraki_v1_event_type_uses_type_as_the_provider_id() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /networks/network-1/events/eventTypes HTTP/1.1\r\n"));
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer meraki-secret"))
            );
            let body = r#"[{"category":"802.11","type":"association","description":"802.11 association"}]"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let root = repository_root();
        let source = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap()
        .get("meraki")
        .unwrap()
        .clone();
        let mut connector = HttpSourceConnector::new(
            source,
            "eventtype",
            &format!("http://{address}"),
            BTreeMap::from([("networkid".to_owned(), "network-1".to_owned())]),
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Bearer meraki-secret".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("meraki-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "association");
    }

    #[tokio::test]
    async fn meraki_v1_organizations_follow_the_provider_link_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for page in 1..=2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let request_line = request.lines().next().unwrap();
                assert!(request_line.starts_with("GET /organizations?"));
                assert!(request_line.contains("perPage=9000"));
                assert_eq!(request_line.contains("startingAfter=2930418"), page == 2);
                assert!(
                    request.lines().any(
                        |line| line.eq_ignore_ascii_case("authorization: Bearer meraki-secret")
                    )
                );
                let body = if page == 1 {
                    r#"[{"id":"2930418","name":"First organization"}]"#
                } else {
                    r#"[{"id":"2930419","name":"Second organization"}]"#
                };
                let link = if page == 1 {
                    format!(
                        "link: <http://{address}/organizations?startingAfter=2930418>; rel=\"next\"\r\n"
                    )
                } else {
                    String::new()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{link}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let root = repository_root();
        let source = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap()
        .get("meraki")
        .unwrap()
        .clone();
        let mut connector = HttpSourceConnector::new(
            source,
            "organization",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Bearer meraki-secret".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("meraki-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert!(matches!(batch.scope, CollectedScope::Complete(_)));
        assert_eq!(
            batch
                .records
                .iter()
                .map(|record| record.provider_id.as_str())
                .collect::<Vec<_>>(),
            ["2930418", "2930419"]
        );
    }

    #[tokio::test]
    async fn meraki_v1_auth_user_preserves_provider_identity_fields() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /networks/network-1/merakiAuthUsers HTTP/1.1\r\n"));
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer meraki-secret"))
            );
            let body = r#"[{"id":"aGlAaGkuY29t","email":"miles@meraki.com","name":"Miles Meraki","accountType":"802.1X","isAdmin":false}]"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let root = repository_root();
        let source = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap()
        .get("meraki")
        .unwrap()
        .clone();
        let mut connector = HttpSourceConnector::new(
            source,
            "merakiauthuser",
            &format!("http://{address}"),
            BTreeMap::from([("networkid".to_owned(), "network-1".to_owned())]),
            ResolvedAuth::Header {
                name: "Authorization".to_owned(),
                value: "Bearer meraki-secret".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("meraki-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "aGlAaGkuY29t");
        assert_eq!(
            batch.records[0]
                .payload
                .get("name")
                .and_then(serde_json::Value::as_str),
            Some("Miles Meraki"),
        );
        assert_eq!(
            batch.records[0]
                .payload
                .get("email")
                .and_then(serde_json::Value::as_str),
            Some("miles@meraki.com"),
        );
    }

    #[tokio::test]
    async fn query_credentials_are_encoded_redacted_and_never_stored_in_runtime_config() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let request_line = request.lines().next().unwrap();
            assert!(request_line.starts_with("GET /v5/account?"));
            assert!(request_line.contains("api_token=token%26admin%3Dtrue"));
            assert!(request_line.contains("api_token_secret=secret%23fragment"));
            assert!(!request_line.contains("&admin=true"));
            assert!(!request_line.contains("#fragment"));
            let body = r#"{"data":{"id":"account-1","organization":"Example"}}"#;
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
        let wrong_placement = HttpSourceConnector::new(
            catalog.get("alchemer").unwrap().clone(),
            "account",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::Header {
                name: "X-API-Key".to_owned(),
                value: "secret".to_owned(),
            },
        )
        .err()
        .unwrap();
        assert!(matches!(
            wrong_placement,
            HttpConnectorError::InvalidConfiguration(_)
        ));
        let auth = ResolvedAuth::QueryParameters {
            parameters: BTreeMap::from([
                ("api_token".to_owned(), "token&admin=true".to_owned()),
                ("api_token_secret".to_owned(), "secret#fragment".to_owned()),
            ]),
        };
        let debug = format!("{auth:?}");
        assert!(!debug.contains("token&admin=true"));
        assert!(!debug.contains("secret#fragment"));
        let mut shadowed = Client::new()
            .get("https://api.example.test/v5/account?api_token=attacker&public=kept")
            .build()
            .unwrap();
        apply_auth_query_parameters(&mut shadowed, &auth).unwrap();
        let query = shadowed
            .url()
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let api_token_values = query
            .iter()
            .filter(|(name, _)| name == "api_token")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(api_token_values, vec!["token&admin=true"]);
        assert!(query.contains(&("public".to_owned(), "kept".to_owned())));

        let mut invalid_name = Client::new()
            .get("https://api.example.test/v5/account")
            .build()
            .unwrap();
        assert!(matches!(
            apply_auth_query_parameters(
                &mut invalid_name,
                &ResolvedAuth::QueryParameters {
                    parameters: BTreeMap::from([(
                        "api_token&admin".to_owned(),
                        "secret".to_owned()
                    )]),
                }
            ),
            Err(HttpConnectorError::InvalidConfiguration(_))
        ));
        assert!(invalid_name.url().query().is_none());
        let mut connector = HttpSourceConnector::new(
            catalog.get("alchemer").unwrap().clone(),
            "account",
            &format!("http://{address}"),
            BTreeMap::new(),
            auth,
        )
        .unwrap();
        assert!(connector.config.is_empty());
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("alchemer-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].provider_id, "account-1");

        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_address = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        let mut failing = HttpSourceConnector::new(
            catalog.get("alchemer").unwrap().clone(),
            "account",
            &format!("http://{closed_address}"),
            BTreeMap::new(),
            ResolvedAuth::QueryParameters {
                parameters: BTreeMap::from([
                    ("api_token".to_owned(), "token&admin=true".to_owned()),
                    ("api_token_secret".to_owned(), "secret#fragment".to_owned()),
                ]),
            },
        )
        .unwrap();
        let error = failing
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("alchemer-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "provider request failed");
        assert!(!format!("{error:?}").contains("token&admin=true"));
        assert!(!format!("{error:?}").contains("secret#fragment"));
    }

    #[tokio::test]
    async fn json_body_credentials_and_cursor_are_posted_without_query_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for page in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.starts_with("POST /list-items HTTP/1.1\r\n"));
                assert!(request.contains("content-type: application/json"));
                let body = request.split("\r\n\r\n").nth(1).unwrap();
                let body: Value = serde_json::from_str(body).unwrap();
                assert_eq!(
                    body.get("token").and_then(Value::as_str),
                    Some("body-secret")
                );
                if page == 0 {
                    assert!(body.get("pagination-token").is_none());
                } else {
                    assert_eq!(
                        body.get("pagination-token").and_then(Value::as_str),
                        Some("cursor-2")
                    );
                }
                let response_body = if page == 0 {
                    r#"{"items":[{"item_id":"item-1","item_name":"First"}],"next_page":"cursor-2"}"#
                } else {
                    r#"{"items":[{"item_id":"item-2","item_name":"Second"}],"next_page":""}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                    response_body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let wrong_placement = HttpSourceConnector::new(
            catalog.get("akeyless").unwrap().clone(),
            "items",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::Header {
                name: "X-API-Key".to_owned(),
                value: "secret".to_owned(),
            },
        )
        .err()
        .unwrap();
        assert!(matches!(
            wrong_placement,
            HttpConnectorError::InvalidConfiguration(_)
        ));
        let auth = ResolvedAuth::JsonBodyParameters {
            parameters: BTreeMap::from([("token".to_owned(), "body-secret".to_owned())]),
        };
        assert!(!format!("{auth:?}").contains("body-secret"));
        let mut connector = HttpSourceConnector::new(
            catalog.get("akeyless").unwrap().clone(),
            "items",
            &format!("http://{address}"),
            BTreeMap::new(),
            auth,
        )
        .unwrap();
        assert!(connector.config.is_empty());
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("akeyless-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[0].provider_id, "item-1");
        assert_eq!(batch.records[1].provider_id, "item-2");
    }

    #[tokio::test]
    async fn csv_path_fanout_is_bounded_deduplicated_and_scope_preserving() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap();
                requests.push(String::from_utf8_lossy(&request[..read]).into_owned());
                let body = format!(
                    r#"{{"entries":[{{"id":"membership-{}","user":{{"id":"user-1","login":"user@example.test","name":"User One"}},"role":"member"}}]}}"#,
                    index + 1
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });

        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("box").unwrap().clone();
        let mut connector = HttpSourceConnector::new(
            source.clone(),
            "group_memberships",
            &format!("http://{address}"),
            BTreeMap::from([(
                "group_ids".to_owned(),
                " group-a, group-a, group/b ".to_owned(),
            )]),
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
        let requests = server.await.unwrap();

        assert!(requests[0].starts_with("GET /groups/group-a/memberships?"));
        assert!(requests[1].starts_with("GET /groups/group%2Fb/memberships?"));
        assert!(matches!(batch.scope, CollectedScope::Complete(_)));
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[0].provider_id, "membership-1");
        assert_eq!(batch.records[1].provider_id, "membership-2");
        assert_ne!(
            batch.records[0].observation_id,
            batch.records[1].observation_id
        );
        assert_eq!(batch.records[0].fields["group_id"], "group-a");
        assert_eq!(batch.records[1].fields["group_id"], "group/b");

        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .map(&batch)
            .unwrap();
        assert_eq!(delta.assertions().len(), 2);
    }

    #[tokio::test]
    async fn csv_query_fanout_binds_the_requested_scope_into_records() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap();
                requests.push(String::from_utf8_lossy(&request[..read]).into_owned());
                let body = r#"{"values":[{"accountId":"user-1","displayName":"User One","emailAddress":"user@example.test"}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });

        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("jira").unwrap().clone();
        let mut connector = HttpSourceConnector::new(
            source.clone(),
            "group_members",
            &format!("http://{address}"),
            BTreeMap::from([("group_ids".to_owned(), "group-a,group/b".to_owned())]),
            ResolvedAuth::Basic {
                username: "user@example.test".to_owned(),
                password: "token".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("jira-prod").unwrap(),
                cursor: None,
            })
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert!(requests[0].starts_with("GET /rest/api/3/group/member?"));
        assert!(requests[0].contains("groupId=group-a"));
        assert!(requests[1].contains("groupId=group%2Fb"));
        assert_eq!(batch.records[0].fields["group_id"], "group-a");
        assert_eq!(batch.records[1].fields["group_id"], "group/b");
        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .map(&batch)
            .unwrap();
        assert_eq!(delta.assertions().len(), 2);
    }

    #[test]
    fn provider_records_cannot_contradict_the_requested_scope() {
        let error = validate_record_scope(
            "memberships",
            &serde_json::json!({"group_id": "other"}),
            &BTreeMap::from([("group_id".to_owned(), "requested".to_owned())]),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid provider response: family memberships record changed requested group_id scope"
        );
    }

    #[test]
    fn explicit_fanout_binding_drives_runtime_paths_and_record_scope() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let connector = HttpSourceConnector::new(
            catalog.get("fivetran").unwrap().clone(),
            "connector_metadata_details",
            "https://api.example.test",
            BTreeMap::from([(
                "connector_services".to_owned(),
                "snowflake,postgres".to_owned(),
            )]),
            ResolvedAuth::Basic {
                username: "key".to_owned(),
                password: "secret".to_owned(),
            },
        )
        .unwrap();
        let scopes = connector.request_scopes().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(
            scopes[0].url.path(),
            "/v1/metadata/connector-types/snowflake"
        );
        assert_eq!(
            scopes[1].url.path(),
            "/v1/metadata/connector-types/postgres"
        );
        assert_eq!(scopes[0].record_attributes["service"], "snowflake");
        assert_eq!(scopes[1].record_attributes["service"], "postgres");
    }

    #[test]
    fn csv_fanout_rejects_empty_and_oversized_scope_sets() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("box").unwrap().clone();
        for (value, expected) in [
            (
                " , ".to_owned(),
                "request config group_ids requires at least one value",
            ),
            (
                (0..=MAX_FANOUT_SCOPES)
                    .map(|value| format!("group-{value}"))
                    .collect::<Vec<_>>()
                    .join(","),
                "path parameter config group_ids exceeds 1000 values",
            ),
        ] {
            let connector = HttpSourceConnector::new(
                source.clone(),
                "group_memberships",
                "https://api.example.test",
                BTreeMap::from([("group_ids".to_owned(), value)]),
                ResolvedAuth::Bearer {
                    token: "token".to_owned(),
                },
            )
            .unwrap();
            let error = connector.request_scopes().err().unwrap();
            assert_eq!(error.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn duo_catalog_family_executes_with_v5_signing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /admin/v1/users?"));
            assert!(request.to_ascii_lowercase().contains("\r\ndate: "));
            let authorization = request
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("authorization: basic ")
                        .then(|| line.split_once(':').unwrap().1.trim())
                })
                .expect("Duo request must contain Basic authorization");
            let credentials = BASE64
                .decode(authorization.strip_prefix("Basic ").unwrap())
                .unwrap();
            let credentials = String::from_utf8(credentials).unwrap();
            let (integration_key, signature) = credentials.split_once(':').unwrap();
            assert_eq!(integration_key, "integration-example");
            assert_eq!(signature.len(), 128);
            assert!(signature.bytes().all(|byte| byte.is_ascii_hexdigit()));

            let body = r#"{"stat":"OK","response":[{"user_id":"user-1","username":"alice","status":"active"}]}"#;
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
            catalog.get("duo").unwrap().clone(),
            "user",
            &format!("http://{address}"),
            BTreeMap::new(),
            ResolvedAuth::DuoHmacV5 {
                integration_key: "integration-example".to_owned(),
                secret_key: "secret-example".to_owned(),
            },
        )
        .unwrap();
        let batch = connector
            .collect(CollectionRequest {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("duo-prod").unwrap(),
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
