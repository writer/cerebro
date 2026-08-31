#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded provider clients for durable Rust Action dispatches.
//!
//! A provider response is execution evidence, not finding closure. This crate
//! never retries a mutation and never manufactures an observed-effect digest.
//! Dispatch validates a durable [`ActionDispatch`], sends one bounded mutation,
//! and classifies any uncertain outcome as [`ProviderError::DispatchAmbiguous`]
//! so an upstream coordinator reconciles instead of replaying the mutation.
//! Observation is read-only and binds the returned receipt to the original
//! tenant, finding, target, idempotency key, and external identifier.

mod cerebro_device;

pub use cerebro_device::CerebroDeviceClient;

use std::{error::Error, fmt, net::IpAddr, time::Duration};

use cerebro_action_store::ActionDispatch;
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{ActorId, ContentDigest, OpaqueId};
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::{Deserialize, Serialize};

/// Catalog provider identifier accepted by the HTTP adapter.
const ACCESS_APPROVALS_PROVIDER: &str = "access-approvals";
/// Fixed provider-side attribution for mutations initiated by graph actions.
const ACCESS_APPROVALS_SOURCE: &str = "cerebro:graph_action";
/// Default end-to-end deadline for one provider request.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Lower deadline bound, preventing configurations that cannot make progress.
const MIN_TIMEOUT: Duration = Duration::from_millis(100);
/// Upper deadline bound on an unresponsive provider operation.
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum accepted configuration size for the provider origin and base path.
const MAX_BASE_URL_BYTES: usize = 2_048;
/// Maximum credential size accepted before constructing an authorization header.
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1_024;
/// Maximum successful response retained as receipt evidence.
const MAX_SUCCESS_BODY_BYTES: usize = 1 << 20;
/// Maximum error response drained before returning its status classification.
const MAX_ERROR_BODY_BYTES: usize = 4 << 10;

#[derive(Clone)]
/// Configuration for the access-approvals HTTP adapter.
pub struct AccessApprovalsConfig {
    /// Absolute HTTPS endpoint, with loopback HTTP permitted for local tests.
    pub base_url: String,
    /// Bearer credential sent to the provider; it must never be logged.
    pub bearer_token: String,
    /// End-to-end request timeout, constrained to 100 milliseconds through 60 seconds.
    pub timeout: Duration,
}

impl AccessApprovalsConfig {
    /// Creates configuration with the default ten-second timeout.
    ///
    /// Validation is deferred to [`AccessApprovalsClient::new`] so callers can
    /// construct and amend configuration before attempting to build a client.
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: bearer_token.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Clone)]
/// Bounded HTTP client for access-approval user lifecycle actions.
///
/// The client rejects redirects, bounds response bodies, and performs no
/// automatic mutation retry. Clone shares the underlying connection pool.
pub struct AccessApprovalsClient {
    /// Validated origin and optional deployment base path.
    base_url: Url,
    /// Secret copied into each authenticated request and never receipt material.
    bearer_token: String,
    /// Redirect-free client whose timeout covers the complete request.
    client: Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Normalized asynchronous state reported by an action provider.
pub enum ProviderStatus {
    /// The provider accepted the operation but has not queued it.
    Pending,
    /// The operation is waiting for provider execution.
    Queued,
    /// The provider is actively executing the operation.
    Running,
    /// The provider reports successful execution.
    Succeeded,
    /// The provider reports terminal failure.
    Failed,
    /// The provider reports terminal cancellation.
    Cancelled,
    /// Automation must stop and hand the operation to a human.
    NeedsAttention,
}

impl ProviderStatus {
    /// Returns the stable wire value stored in action state.
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

    /// Reports whether automated provider polling should stop.
    ///
    /// `NeedsAttention` is terminal for automation even though human work may
    /// continue outside the provider loop.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::NeedsAttention
        )
    }
}

impl TryFrom<&str> for ProviderStatus {
    type Error = ProviderError;

    /// Parses the closed provider-state vocabulary without accepting aliases.
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
/// Validated execution evidence returned by a provider adapter.
///
/// A receipt can advance action state but cannot prove that the intended effect
/// remains true. Independent observation supplies that later evidence.
pub struct ProviderReceipt {
    /// Provider-owned identifier used for later observation.
    pub external_id: OpaqueId,
    /// Normalized provider lifecycle state.
    pub status: ProviderStatus,
    /// Digest of the exact mutation request, present only for dispatch receipts.
    pub request_digest: Option<ContentDigest>,
    /// Digest of the bounded provider response used to build this receipt.
    pub response_digest: ContentDigest,
    /// Provider-reported last update time in Unix seconds, when available.
    pub updated_at_unix_s: Option<u64>,
    /// Provider-reported completion time in Unix seconds, when available.
    pub completed_at_unix_s: Option<u64>,
}

impl ProviderReceipt {
    /// Converts an initial dispatch receipt into the engine command that records
    /// provider acceptance without asserting independent verification.
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

    /// Converts a later read-only observation into a reconciliation command.
    pub fn observation_command(
        &self,
        reconciler_actor_id: ActorId,
        observed_at_unix_ms: u64,
    ) -> ActionCommand {
        ActionCommand::ObserveProviderReceipt {
            provider_receipt_digest: self.response_digest.clone(),
            provider_status: self.status.as_str().to_owned(),
            reconciler_actor_id,
            observed_at_unix_ms,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Fail-closed provider boundary errors.
pub enum ProviderError {
    /// Static client configuration is malformed or unsafe.
    InvalidConfiguration(&'static str),
    /// A durable dispatch does not match the adapter's provider contract.
    InvalidDispatch(&'static str),
    /// The provider definitively rejected the mutation.
    DispatchRejected {
        /// HTTP status returned by the provider.
        status: u16,
    },
    /// The mutation may have reached the provider, so automatic retry is unsafe.
    DispatchAmbiguous,
    /// A read-only receipt lookup could not produce usable evidence.
    ObservationUnavailable,
    /// A provider attempted to redirect a bounded request.
    RedirectRejected,
    /// A provider body exceeded the configured evidence limit.
    ResponseTooLarge,
    /// A provider response violated a field or binding invariant.
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
/// Mutation body sent to access-approvals.
///
/// The target and all correlation fields originate in the validated durable
/// dispatch. The bearer credential is transport metadata and is never included
/// in this serializable body or its digest.
struct UserActionRequest<'a> {
    /// Provider's legacy field for either a user email or durable user ID.
    email_or_user_id: &'a str,
    /// Fixed attribution understood by the provider audit trail.
    source: &'static str,
    /// Stable replay key chosen before entering the provider adapter.
    idempotency_key: &'a str,
    /// Tenant authority copied from the durable dispatch.
    tenant_id: &'a str,
    /// Finding that authorized the requested action.
    finding_id: &'a str,
}

#[derive(Deserialize)]
/// Provider receipt decoded from both mutation and observation responses.
///
/// Correlation fields default only to make their absence a binding failure with
/// a single error class. They are never treated as optional during validation.
struct UserActionResponse {
    /// Provider-owned action identifier used by the observation endpoint.
    id: String,
    /// Provider operation, which must echo the dispatch operation.
    action: String,
    /// Raw member of the closed [`ProviderStatus`] vocabulary.
    status: String,
    /// Provider target, which must echo the dispatch target.
    target: String,
    /// Echoed replay key; a missing value becomes empty and fails binding.
    #[serde(default)]
    idempotency_key: String,
    /// Echoed tenant; a missing value becomes empty and fails binding.
    #[serde(default)]
    tenant_id: String,
    /// Echoed finding; a missing value becomes empty and fails binding.
    #[serde(default)]
    finding_id: String,
    /// Provider-reported last transition time in Unix seconds.
    #[serde(default)]
    updated_at_unix: Option<u64>,
    /// Provider-reported terminal transition time in Unix seconds.
    #[serde(default)]
    completed_at_unix: Option<u64>,
}

impl AccessApprovalsClient {
    /// Validates configuration and builds a redirect-free bounded HTTP client.
    ///
    /// HTTPS is required except for literal loopback addresses and `localhost`,
    /// which permit HTTP for local tests. User information, query parameters,
    /// and fragments are rejected so request construction cannot inherit hidden
    /// authority or routing input from the base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidConfiguration`] when the URL, bearer
    /// token, timeout, or underlying HTTP client configuration violates the
    /// adapter bounds.
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

    /// Sends one mutation for a validated durable dispatch.
    ///
    /// Transport failure, redirect, an ambiguous HTTP status, an oversized
    /// success body, or a malformed success receipt all return
    /// [`ProviderError::DispatchAmbiguous`]. The caller must reconcile by the
    /// idempotency key rather than blindly retrying.
    ///
    /// The request digest covers the exact JSON body before transport metadata
    /// such as the bearer credential is applied. This function performs exactly
    /// one HTTP attempt and never follows a redirect.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidDispatch`] before network access for an
    /// invalid digest or catalog route, [`ProviderError::DispatchRejected`] for
    /// a definite provider rejection, and [`ProviderError::DispatchAmbiguous`]
    /// whenever the mutation outcome cannot be proven.
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
        // Commit only the provider-visible mutation body. Authorization headers
        // and connection details must not enter durable action evidence.
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

    /// Reads the provider receipt linked to `external_id` and revalidates its
    /// tenant, finding, target, action, and idempotency bindings.
    ///
    /// Observation is read-only and therefore may be repeated after an
    /// ambiguous dispatch. The identifier selects the provider object, but the
    /// response must still echo every durable dispatch binding before it is
    /// accepted as evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidDispatch`] for invalid authority input,
    /// [`ProviderError::ObservationUnavailable`] when the receipt cannot be
    /// read, or a more specific bounded-response error when returned evidence
    /// is unsafe or inconsistent.
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
        // A redirect after a mutation does not prove whether the original
        // endpoint committed the action. Preserve that uncertainty for the
        // coordinator instead of following or classifying it as rejection.
        if response.status().is_redirection() {
            return Err(ProviderError::DispatchAmbiguous);
        }
        if !response.status().is_success() {
            let status = response.status();
            // Attempt a bounded drain, but do not retain or expose provider
            // error content as action evidence.
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
        // Once a mutation returned success, malformed or unbound bytes cannot
        // prove whether the provider committed the intended operation.
        decode_receipt(&bytes, dispatch, None, Some(request_digest))
            .map_err(|_| ProviderError::DispatchAmbiguous)
    }

    async fn decode_observation_response(
        &self,
        response: Response,
        dispatch: &ActionDispatch,
        expected_external_id: Option<&OpaqueId>,
    ) -> Result<ProviderReceipt, ProviderError> {
        // Unlike dispatch, this request is read-only: redirects are a definite
        // policy violation rather than evidence of an uncertain mutation.
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
        // Preserve the validated scheme, authority, and deployment base path.
        // `path_segments_mut` percent-encodes each suffix as one path segment,
        // including an opaque external identifier supplied during observation.
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
    // Reject padding and control bytes before parsing so configuration has one
    // canonical textual representation and cannot smuggle header delimiters.
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_BASE_URL_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidConfiguration("base URL"));
    }
    let url = Url::parse(value).map_err(|_| ProviderError::InvalidConfiguration("base URL"))?;
    // Authentication belongs in the dedicated bearer field. Query and fragment
    // data are also prohibited because every operation builds its own fixed path.
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::InvalidConfiguration("base URL"));
    }
    let secure = url.scheme() == "https";
    // Plain HTTP exists only for local test servers. Parsed IP literals must be
    // loopback; arbitrary hostnames cannot opt into insecure transport.
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
    // Trimming would silently authenticate with a credential different from the
    // configured value. Control bytes are rejected to protect header framing.
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
    // Validate the dispatch's content commitment before trusting any field, then
    // narrow the envelope to the exact provider and supported action vocabulary.
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
    // Hash the exact bounded bytes below. Deserialization is used for validation,
    // not for re-encoding a potentially different representation of the receipt.
    let response: UserActionResponse =
        serde_json::from_slice(bytes).map_err(|_| ProviderError::InvalidResponse("JSON body"))?;
    let external_id =
        OpaqueId::parse(response.id).map_err(|_| ProviderError::InvalidResponse("external id"))?;
    if expected_external_id.is_some_and(|expected| expected != &external_id) {
        return Err(ProviderError::InvalidResponse("external id"));
    }
    // The provider-controlled identifier may select an object for observation,
    // but all authorization and correlation fields must echo the durable dispatch.
    if response.action != dispatch.provider_action
        || response.target != dispatch.target_id
        || response.idempotency_key != dispatch.idempotency_key
        || response.tenant_id != dispatch.tenant_id
        || response.finding_id != dispatch.finding_id
    {
        return Err(ProviderError::InvalidResponse("dispatch binding"));
    }
    let status = ProviderStatus::try_from(response.status.as_str())?;
    // Successful execution requires a completion instant. Other terminal states
    // may omit it because the provider contract does not promise one for them.
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
    // These statuses cannot distinguish rejection from a mutation that committed
    // before the provider or an intermediary timed out, throttled, or failed.
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn is_json(response: &Response) -> bool {
    // Accept parameters such as a charset, but require the exact JSON media type;
    // vendor `+json` responses are outside this provider's receipt contract.
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
    // A trustworthy Content-Length permits an early rejection, while the stream
    // check below remains authoritative for absent or inaccurate declarations.
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
        // Saturating arithmetic keeps an adversarial chunk length from wrapping
        // the bound check before the bytes are appended.
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ProviderError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
