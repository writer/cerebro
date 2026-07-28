#![forbid(unsafe_code)]

//! Bounded provider clients for durable Rust Action dispatches.
//!
//! A provider response is execution evidence, not finding closure. This crate
//! never retries a mutation and never manufactures an observed-effect digest.

use std::{error::Error, fmt, net::IpAddr, time::Duration};

use cerebro_action_store::ActionDispatch;
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{ActorId, ContentDigest, OpaqueId};
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::{Deserialize, Serialize};

const ACCESS_APPROVALS_PROVIDER: &str = "access-approvals";
const ACCESS_APPROVALS_SOURCE: &str = "cerebro:graph_action";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BASE_URL_BYTES: usize = 2_048;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1_024;
const MAX_SUCCESS_BODY_BYTES: usize = 1 << 20;
const MAX_ERROR_BODY_BYTES: usize = 4 << 10;

#[derive(Clone)]
pub struct AccessApprovalsConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
}

impl AccessApprovalsConfig {
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: bearer_token.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Clone)]
pub struct AccessApprovalsClient {
    base_url: Url,
    bearer_token: String,
    client: Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStatus {
    Pending,
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    NeedsAttention,
}

impl ProviderStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::NeedsAttention => "needs_attention",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::NeedsAttention
        )
    }
}

impl TryFrom<&str> for ProviderStatus {
    type Error = ProviderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "needs_attention" => Ok(Self::NeedsAttention),
            _ => Err(ProviderError::InvalidResponse("unknown provider status")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReceipt {
    pub external_id: OpaqueId,
    pub status: ProviderStatus,
    pub request_digest: Option<ContentDigest>,
    pub response_digest: ContentDigest,
    pub updated_at_unix_s: Option<u64>,
    pub completed_at_unix_s: Option<u64>,
}

impl ProviderReceipt {
    pub fn record_command(
        &self,
        executor_actor_id: ActorId,
        observed_at_unix_ms: u64,
    ) -> ActionCommand {
        ActionCommand::RecordProviderReceipt {
            external_receipt_ref: self.external_id.clone(),
            provider_receipt_digest: self.response_digest.clone(),
            provider_status: self.status.as_str().to_owned(),
            executor_actor_id,
            observed_at_unix_ms,
        }
    }

    pub fn observation_command(&self, observed_at_unix_ms: u64) -> ActionCommand {
        ActionCommand::ObserveProviderReceipt {
            provider_receipt_digest: self.response_digest.clone(),
            provider_status: self.status.as_str().to_owned(),
            observed_at_unix_ms,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    InvalidConfiguration(&'static str),
    InvalidDispatch(&'static str),
    DispatchRejected { status: u16 },
    DispatchAmbiguous,
    ObservationUnavailable,
    RedirectRejected,
    ResponseTooLarge,
    InvalidResponse(&'static str),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(field) => {
                write!(formatter, "invalid access-approvals configuration: {field}")
            }
            Self::InvalidDispatch(field) => {
                write!(formatter, "invalid access-approvals dispatch: {field}")
            }
            Self::DispatchRejected { status } => {
                write!(
                    formatter,
                    "access-approvals rejected dispatch with status {status}"
                )
            }
            Self::DispatchAmbiguous => {
                formatter.write_str("access-approvals dispatch outcome is unknown")
            }
            Self::ObservationUnavailable => {
                formatter.write_str("access-approvals observation is unavailable")
            }
            Self::RedirectRejected => formatter.write_str("access-approvals redirect was rejected"),
            Self::ResponseTooLarge => {
                formatter.write_str("access-approvals response exceeded the byte limit")
            }
            Self::InvalidResponse(field) => {
                write!(formatter, "invalid access-approvals response: {field}")
            }
        }
    }
}

impl Error for ProviderError {}

#[derive(Serialize)]
struct UserActionRequest<'a> {
    email_or_user_id: &'a str,
    source: &'static str,
    idempotency_key: &'a str,
    tenant_id: &'a str,
    finding_id: &'a str,
}

#[derive(Deserialize)]
struct UserActionResponse {
    id: String,
    action: String,
    status: String,
    target: String,
    #[serde(default)]
    idempotency_key: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    finding_id: String,
    #[serde(default)]
    updated_at_unix: Option<u64>,
    #[serde(default)]
    completed_at_unix: Option<u64>,
}

impl AccessApprovalsClient {
    pub fn new(config: AccessApprovalsConfig) -> Result<Self, ProviderError> {
        let base_url = validate_base_url(&config.base_url)?;
        let bearer_token = validate_bearer_token(config.bearer_token)?;
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&config.timeout) {
            return Err(ProviderError::InvalidConfiguration("timeout"));
        }
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderError::InvalidConfiguration("HTTP client"))?;
        Ok(Self {
            base_url,
            bearer_token,
            client,
        })
    }

    pub async fn dispatch(
        &self,
        dispatch: &ActionDispatch,
    ) -> Result<ProviderReceipt, ProviderError> {
        validate_dispatch(dispatch)?;
        let endpoint = match dispatch.provider_action.as_str() {
            "suspend" => self.endpoint(&["admin", "okta-jail", "suspend"])?,
            "unsuspend" => self.endpoint(&["admin", "okta-jail", "unsuspend"])?,
            _ => return Err(ProviderError::InvalidDispatch("provider action")),
        };
        let request = UserActionRequest {
            email_or_user_id: &dispatch.target_id,
            source: ACCESS_APPROVALS_SOURCE,
            idempotency_key: &dispatch.idempotency_key,
            tenant_id: &dispatch.tenant_id,
            finding_id: &dispatch.finding_id,
        };
        let request_body = serde_json::to_vec(&request)
            .map_err(|_| ProviderError::InvalidDispatch("provider request"))?;
        let request_digest = ContentDigest::of_bytes(&request_body);
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(&self.bearer_token)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(request_body)
            .send()
            .await
            .map_err(|_| ProviderError::DispatchAmbiguous)?;
        self.decode_dispatch_response(response, dispatch, request_digest)
            .await
    }

    pub async fn observe(
        &self,
        dispatch: &ActionDispatch,
        external_id: &OpaqueId,
    ) -> Result<ProviderReceipt, ProviderError> {
        validate_dispatch(dispatch)?;
        let endpoint = self.endpoint(&["admin", "okta-jail", "actions", external_id.as_str()])?;
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(&self.bearer_token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| ProviderError::ObservationUnavailable)?;
        self.decode_observation_response(response, dispatch, Some(external_id))
            .await
    }

    async fn decode_dispatch_response(
        &self,
        response: Response,
        dispatch: &ActionDispatch,
        request_digest: ContentDigest,
    ) -> Result<ProviderReceipt, ProviderError> {
        if response.status().is_redirection() {
            return Err(ProviderError::DispatchAmbiguous);
        }
        if !response.status().is_success() {
            let status = response.status();
            let _ = read_bounded(response, MAX_ERROR_BODY_BYTES).await;
            return if ambiguous_status(status) {
                Err(ProviderError::DispatchAmbiguous)
            } else {
                Err(ProviderError::DispatchRejected {
                    status: status.as_u16(),
                })
            };
        }
        if !is_json(&response) {
            return Err(ProviderError::DispatchAmbiguous);
        }
        let bytes = read_bounded(response, MAX_SUCCESS_BODY_BYTES)
            .await
            .map_err(|_| ProviderError::DispatchAmbiguous)?;
        decode_receipt(&bytes, dispatch, None, Some(request_digest))
            .map_err(|_| ProviderError::DispatchAmbiguous)
    }

    async fn decode_observation_response(
        &self,
        response: Response,
        dispatch: &ActionDispatch,
        expected_external_id: Option<&OpaqueId>,
    ) -> Result<ProviderReceipt, ProviderError> {
        if response.status().is_redirection() {
            return Err(ProviderError::RedirectRejected);
        }
        if !response.status().is_success() || !is_json(&response) {
            let _ = read_bounded(response, MAX_ERROR_BODY_BYTES).await;
            return Err(ProviderError::ObservationUnavailable);
        }
        let bytes = read_bounded(response, MAX_SUCCESS_BODY_BYTES).await?;
        decode_receipt(&bytes, dispatch, expected_external_id, None)
    }

    fn endpoint(&self, suffix: &[&str]) -> Result<Url, ProviderError> {
        let mut endpoint = self.base_url.clone();
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
            .path_segments_mut()
            .map_err(|_| ProviderError::InvalidConfiguration("base URL"))?
            .pop_if_empty()
            .extend(suffix);
        Ok(endpoint)
    }
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_BASE_URL_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidConfiguration("base URL"));
    }
    let url = Url::parse(value).map_err(|_| ProviderError::InvalidConfiguration("base URL"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::InvalidConfiguration("base URL"));
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !secure && !loopback_http {
        return Err(ProviderError::InvalidConfiguration("base URL scheme"));
    }
    Ok(url)
}

fn validate_bearer_token(value: String) -> Result<String, ProviderError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_BEARER_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidConfiguration("bearer token"));
    }
    Ok(value)
}

fn validate_dispatch(dispatch: &ActionDispatch) -> Result<(), ProviderError> {
    dispatch
        .validate()
        .map_err(|_| ProviderError::InvalidDispatch("content digest"))?;
    if dispatch.provider != ACCESS_APPROVALS_PROVIDER {
        return Err(ProviderError::InvalidDispatch("provider"));
    }
    if !matches!(dispatch.provider_action.as_str(), "suspend" | "unsuspend") {
        return Err(ProviderError::InvalidDispatch("provider action"));
    }
    Ok(())
}

fn decode_receipt(
    bytes: &[u8],
    dispatch: &ActionDispatch,
    expected_external_id: Option<&OpaqueId>,
    request_digest: Option<ContentDigest>,
) -> Result<ProviderReceipt, ProviderError> {
    let response: UserActionResponse =
        serde_json::from_slice(bytes).map_err(|_| ProviderError::InvalidResponse("JSON body"))?;
    let external_id =
        OpaqueId::parse(response.id).map_err(|_| ProviderError::InvalidResponse("external id"))?;
    if expected_external_id.is_some_and(|expected| expected != &external_id) {
        return Err(ProviderError::InvalidResponse("external id"));
    }
    if response.action != dispatch.provider_action
        || response.target != dispatch.target_id
        || response.idempotency_key != dispatch.idempotency_key
        || response.tenant_id != dispatch.tenant_id
        || response.finding_id != dispatch.finding_id
    {
        return Err(ProviderError::InvalidResponse("dispatch binding"));
    }
    let status = ProviderStatus::try_from(response.status.as_str())?;
    if status == ProviderStatus::Succeeded && response.completed_at_unix.is_none() {
        return Err(ProviderError::InvalidResponse(
            "succeeded receipt completion time",
        ));
    }
    Ok(ProviderReceipt {
        external_id,
        status,
        request_digest,
        response_digest: ContentDigest::of_bytes(bytes),
        updated_at_unix_s: response.updated_at_unix,
        completed_at_unix_s: response.completed_at_unix,
    })
}

fn ambiguous_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn is_json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
        })
}

async fn read_bounded(response: Response, limit: usize) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit as u64)
    {
        return Err(ProviderError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProviderError::ObservationUnavailable)?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ProviderError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
