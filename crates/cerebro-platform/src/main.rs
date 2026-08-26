#![forbid(unsafe_code)]

mod append_log_consumer;
mod ask_queries;
mod audit_events;
mod cutover_command;
mod graph_provenance;
mod identity_directory;
mod oidc;
mod parity_command;
mod ratelimit;
mod rpc;
mod slack_agent;
mod slack_agent_eval;
mod slack_agent_evidence_gold;
mod slack_agent_mcp;
mod slack_agent_session;
mod slack_authority;
mod slack_mrkdwn;
mod source_page_publisher;
mod source_runtime_invalid_events;
mod source_runtime_registry;
mod source_runtime_sync;
mod threat_insight_projection;
mod trusted_endpoint_projection;
mod vendor_discoveries;
mod vendor_register;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region, sts::AssumeRoleProvider};
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_sdk_secretsmanager::Client as AwsSecretsManagerClient;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use cerebro_action_catalog::{
    ActionCatalogError, definitions as action_definitions, lookup as lookup_action,
    validate_proposal,
};
use cerebro_action_provider::{
    AccessApprovalsClient, AccessApprovalsConfig, CerebroDeviceClient, ProviderError,
    ProviderReceipt,
};
use cerebro_action_store::{
    ActionDispatch, ActionDispatchPage, ActionEvent, ActionPage, ActionReconciliationDisposition,
    ActionReconciliationJob, ActionStoreError, PostgresActionLedger,
};
use cerebro_agent_context::{
    AgentContext, AgentGraph, ContextEntity, ContextError, GraphPath, MemoryAgentGraph,
    Neighborhood,
};
use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::{
    AssertionId, AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity,
    EntityId, EntityKind, GraphAssertion, IdentityBindingAssertion, IdentityBindingState,
    IdentityClaim, IdentityResolutionMethod, ModelError, ObservationId, ObservationRef,
    ProviderIdentity, ProviderKind, RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{
    DurableGraphStore, Neo4jProjector, PostgresLedger, ProjectionAuthority,
    SourceRuntimeGraphObservation, SourceRuntimeObservation, StoreError,
};
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{
    ActionOperation, ActionOperationId, ActionProposal, ActorId, ContentDigest, DecisionId,
    DecisionReceipt, FindingValidationReceipt, OpaqueId,
};
use cerebro_policy_catalog::{definitions as policy_definitions, validate_finding_receipt};
use cerebro_security_lifecycle::{
    CERTIFICATE_EVENT_KIND, CREDENTIAL_EVENT_KIND, LifecycleQuery, LifecycleState,
    ProjectedResource, QuerySource, SubjectKind, SubjectLocator, canonical_resource_urn,
    decode_protobuf_observation, finalize_indexed_query, prepare_indexed_query,
    project_observation, query_records_with_source,
};
use cerebro_source_catalog::{
    AuthModel, CatalogSummary, CompiledOauthAuthorizationCode, CompiledOauthClientCredentials,
    CompiledSource, ProjectionClass, SourceCatalog,
};
use cerebro_source_runtime_next::{
    AwsSecretReadError, AwsSecretReader, AwsSecretValue, CatalogGraphMapper, CommittedSourceEvent,
    GraphMapper, GraphSink, ResolvedAuth, RuntimeFreshnessDigest, RuntimeFreshnessEvidence,
    RuntimeFreshnessRollup, RuntimeHealthEvidence, RuntimeReadiness, SourceRuntimeLeaseFence,
    evaluate_runtime_freshness, evaluate_runtime_readiness, runtime_freshness_status,
    summarize_runtime_freshness,
};
use hmac::{Hmac, KeyInit, Mac};
use oidc::{AuthenticatedIdentity, AuthenticationError, OidcAuthenticator, OidcConfiguration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, oneshot};
use zeroize::Zeroize;

const TENANT_AUTH_HEADER: &str = "x-cerebro-tenant";
const WORKSPACE_AUTH_HEADER: &str = "x-cerebro-workspace";
const TENANT_AUTH_CONTEXT: &[u8] = b"cerebro-organizational-graph/tenant/v1\0";
const MAX_LEGACY_DELTA_RECORDS: usize = 100_000;
const MIN_SHARED_SECRET_BYTES: usize = 32;
const MAX_SECURITY_LIFECYCLE_SCAN: usize = 500;
const ACTION_PROPOSE_SCOPE: &str = "cerebro:actions:propose";
const ACTION_SIMULATE_SCOPE: &str = "cerebro:actions:simulate";
const ACTION_APPROVE_SCOPE: &str = "cerebro:actions:approve";
const ACTION_EXECUTE_SCOPE: &str = "cerebro:actions:execute";
const ACTION_RECONCILE_SCOPE: &str = "cerebro:actions:reconcile";
const FINDING_VALIDATE_SCOPE: &str = "cerebro:findings:validate";
const ACTION_RECONCILIATION_BATCH_LIMIT: usize = 10;
const ACTION_RECONCILIATION_LEASE_MS: u64 = 2 * 60 * 1_000;
const ACTION_RECONCILIATION_POLL_DELAY_MS: u64 = 15 * 1_000;
const DEFAULT_SOURCE_RUNTIME_LEASE_TTL_MS: u64 = 30 * 60 * 1_000;
const MAX_SOURCE_RUNTIME_LEASE_RENEWAL_INTERVAL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone)]
struct AppState {
    action_providers: ActionProviders,
    actions: Option<Arc<dyn ActionAuthority>>,
    graph: Arc<dyn AgentGraph>,
    lifecycle_projection: Option<Arc<Neo4jProjector>>,
    catalog_summary: Option<CatalogSummary>,
    projection: Option<Arc<ProjectionRuntime>>,
    runtime_ledger: Option<Arc<PostgresLedger>>,
    source_sync: Option<Arc<dyn source_runtime_sync::SourceRuntimeSyncAuthority>>,
    metrics: PlatformMetrics,
}

#[derive(Clone, Default)]
struct ActionBackends {
    actions: Option<Arc<dyn ActionAuthority>>,
    providers: ActionProviders,
}

#[derive(Clone, Default)]
struct PlatformStores {
    projection: Option<Arc<ProjectionRuntime>>,
    runtime_ledger: Option<Arc<PostgresLedger>>,
    source_sync: Option<Arc<dyn source_runtime_sync::SourceRuntimeSyncAuthority>>,
}

#[derive(Clone, Default)]
struct ActionProviders {
    access_approvals: Option<AccessApprovalsClient>,
    cerebro_device: Option<CerebroDeviceClient>,
}

struct AwsSecretsManagerReader {
    default_region: String,
    profile: Option<String>,
    role_arn: Option<String>,
    external_id: Option<String>,
    endpoint: Option<String>,
    credentials_provider: Option<SharedCredentialsProvider>,
}

impl AwsSecretsManagerReader {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let stores = required_secret_env_or_file("CEREBRO_CONNECTOR_SECRET_STORES")?;
        if !stores
            .split(',')
            .map(str::trim)
            .any(|store| store == "aws_secrets_manager")
        {
            return Err("AWS Secrets Manager connector resolution is not enabled".into());
        }
        let default_region = required_env("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION")?
            .trim()
            .to_owned();
        if default_region.len() > 128 {
            return Err("AWS Secrets Manager region is invalid".into());
        }
        let endpoint = optional_trimmed_env("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ENDPOINT")?;
        if let Some(endpoint) = endpoint.as_deref() {
            validate_aws_secrets_manager_endpoint(endpoint)?;
        }
        Ok(Self {
            default_region,
            profile: optional_trimmed_env("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE")?,
            role_arn: optional_trimmed_env("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN")?,
            external_id: optional_trimmed_env("CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID")?,
            endpoint,
            credentials_provider: None,
        })
    }

    async fn client(
        &self,
        region: Option<&str>,
    ) -> Result<AwsSecretsManagerClient, AwsSecretReadError> {
        let region = region.unwrap_or(&self.default_region).trim();
        if region.is_empty() || region.len() > 128 {
            return Err(AwsSecretReadError);
        }
        let mut loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.to_owned()));
        if let Some(profile) = self.profile.as_deref() {
            loader = loader.profile_name(profile);
        }
        if let Some(provider) = self.credentials_provider.as_ref() {
            loader = loader.credentials_provider(provider.clone());
        }
        let mut shared_config = loader.load().await;
        if let Some(role_arn) = self.role_arn.as_deref() {
            let mut builder = AssumeRoleProvider::builder(role_arn)
                .configure(&shared_config)
                .session_name("cerebro-connector-secret-store");
            if let Some(external_id) = self.external_id.as_deref() {
                builder = builder.external_id(external_id);
            }
            let provider = builder.build().await;
            shared_config = shared_config
                .to_builder()
                .credentials_provider(SharedCredentialsProvider::new(provider))
                .build();
        }
        let mut service_config = aws_sdk_secretsmanager::config::Builder::from(&shared_config);
        if let Some(endpoint) = self.endpoint.as_deref() {
            service_config = service_config.endpoint_url(endpoint);
        }
        Ok(AwsSecretsManagerClient::from_conf(service_config.build()))
    }
}

impl Drop for AwsSecretsManagerReader {
    fn drop(&mut self) {
        if let Some(external_id) = self.external_id.as_mut() {
            external_id.zeroize();
        }
    }
}

#[async_trait]
impl AwsSecretReader for AwsSecretsManagerReader {
    async fn read_secret(
        &self,
        region: Option<&str>,
        secret_id: &str,
    ) -> Result<AwsSecretValue, AwsSecretReadError> {
        let output = self
            .client(region)
            .await?
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .map_err(|_| AwsSecretReadError)?;
        if let Some(value) = output.secret_string {
            return Ok(AwsSecretValue::String(value));
        }
        if let Some(value) = output.secret_binary {
            return Ok(AwsSecretValue::Binary(value.into_inner()));
        }
        Err(AwsSecretReadError)
    }
}

#[async_trait]
trait ActionAuthority: Send + Sync {
    async fn health(&self) -> Result<(), ActionStoreError>;

    async fn record_finding_validation(
        &self,
        receipt: FindingValidationReceipt,
        committed_at_unix_ms: u64,
    ) -> Result<FindingValidationReceipt, ActionStoreError>;

    async fn get_finding_validation(
        &self,
        tenant_id: &TenantId,
        receipt_digest: &ContentDigest,
    ) -> Result<FindingValidationReceipt, ActionStoreError>;

    async fn propose(
        &self,
        proposal: ActionProposal,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError>;

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionOperation, ActionStoreError>;

    async fn list(
        &self,
        tenant_id: &TenantId,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<ActionPage, ActionStoreError>;

    async fn transition(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        actor_id: &ActorId,
        expected_version: u64,
        command: ActionCommand,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError>;

    async fn history(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<Vec<ActionEvent>, ActionStoreError>;

    async fn get_dispatch(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionDispatch, ActionStoreError>;

    async fn list_open_dispatches(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<ActionDispatchPage, ActionStoreError>;

    async fn claim_due_reconciliation(
        &self,
        tenant_id: &TenantId,
        worker_id: &ActorId,
        claimed_at_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    ) -> Result<Option<ActionReconciliationJob>, ActionStoreError>;

    async fn finish_reconciliation(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        worker_id: &ActorId,
        expected_operation_version: u64,
        finished_at_unix_ms: u64,
        disposition: ActionReconciliationDisposition,
    ) -> Result<(), ActionStoreError>;
}

#[async_trait]
impl ActionAuthority for PostgresActionLedger {
    async fn health(&self) -> Result<(), ActionStoreError> {
        self.health().await
    }

    async fn record_finding_validation(
        &self,
        receipt: FindingValidationReceipt,
        committed_at_unix_ms: u64,
    ) -> Result<FindingValidationReceipt, ActionStoreError> {
        self.record_finding_validation(receipt, committed_at_unix_ms)
            .await
    }

    async fn get_finding_validation(
        &self,
        tenant_id: &TenantId,
        receipt_digest: &ContentDigest,
    ) -> Result<FindingValidationReceipt, ActionStoreError> {
        self.get_finding_validation(tenant_id, receipt_digest).await
    }

    async fn propose(
        &self,
        proposal: ActionProposal,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError> {
        self.propose(proposal, committed_at_unix_ms).await
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionOperation, ActionStoreError> {
        self.get(tenant_id, operation_id).await
    }

    async fn list(
        &self,
        tenant_id: &TenantId,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<ActionPage, ActionStoreError> {
        self.list(tenant_id, limit, page_token).await
    }

    async fn transition(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        actor_id: &ActorId,
        expected_version: u64,
        command: ActionCommand,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError> {
        self.transition(
            tenant_id,
            operation_id,
            actor_id,
            expected_version,
            command,
            committed_at_unix_ms,
        )
        .await
    }

    async fn history(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<Vec<ActionEvent>, ActionStoreError> {
        self.history(tenant_id, operation_id).await
    }

    async fn get_dispatch(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionDispatch, ActionStoreError> {
        self.get_dispatch(tenant_id, operation_id).await
    }

    async fn list_open_dispatches(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<ActionDispatchPage, ActionStoreError> {
        self.list_open_dispatches(tenant_id, limit).await
    }

    async fn claim_due_reconciliation(
        &self,
        tenant_id: &TenantId,
        worker_id: &ActorId,
        claimed_at_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    ) -> Result<Option<ActionReconciliationJob>, ActionStoreError> {
        self.claim_due_reconciliation(
            tenant_id,
            worker_id,
            claimed_at_unix_ms,
            lease_expires_at_unix_ms,
        )
        .await
    }

    async fn finish_reconciliation(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        worker_id: &ActorId,
        expected_operation_version: u64,
        finished_at_unix_ms: u64,
        disposition: ActionReconciliationDisposition,
    ) -> Result<(), ActionStoreError> {
        self.finish_reconciliation(
            tenant_id,
            operation_id,
            worker_id,
            expected_operation_version,
            finished_at_unix_ms,
            disposition,
        )
        .await
    }
}

#[derive(Clone, Default)]
struct PlatformMetrics(Arc<Mutex<BTreeMap<&'static str, RequestSeries>>>);

#[derive(Default)]
struct RequestSeries {
    successes: u64,
    failures: u64,
    duration_sum_seconds: f64,
    duration_buckets: [u64; 8],
}

const LATENCY_BUCKETS_SECONDS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

#[derive(Clone)]
struct TenantRequestAuth {
    secret: Arc<[u8]>,
}

#[derive(Clone)]
struct AuthenticatedTenant(TenantId);

impl TenantRequestAuth {
    fn new(secret: String) -> Result<Self, String> {
        if secret.len() < MIN_SHARED_SECRET_BYTES {
            return Err(format!(
                "CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET must be at least {MIN_SHARED_SECRET_BYTES} bytes"
            ));
        }
        Ok(Self {
            secret: Arc::from(secret.into_bytes()),
        })
    }

    fn mac(&self, tenant_id: &TenantId) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .expect("HMAC accepts keys of any length");
        mac.update(TENANT_AUTH_CONTEXT);
        mac.update(&(tenant_id.as_str().len() as u64).to_be_bytes());
        mac.update(tenant_id.as_str().as_bytes());
        mac
    }

    fn verify(&self, tenant_id: &TenantId, token: &str) -> bool {
        let Some(tag) = decode_hex_tag(token) else {
            return false;
        };
        self.mac(tenant_id).verify_slice(&tag).is_ok()
    }

    #[cfg(test)]
    fn token(&self, tenant_id: &TenantId) -> String {
        self.mac(tenant_id)
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn decode_hex_tag(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut tag = [0_u8; 32];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(tag)
}

async fn authenticate_tenant(
    State(auth): State<TenantRequestAuth>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let tenant = request
        .headers()
        .get(TENANT_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| TenantId::parse(value.to_owned()).ok());
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(tenant) =
        tenant.filter(|tenant| token.is_some_and(|token| auth.verify(tenant, token)))
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                code: "authentication_required",
                message: "Valid tenant authentication is required.".to_owned(),
            }),
        ));
    };
    request.extensions_mut().insert(AuthenticatedTenant(tenant));
    Ok(next.run(request).await)
}

async fn authenticate_oidc(
    State(auth): State<OidcAuthenticator>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let bearer = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let identity = match bearer {
        Some(bearer) => auth.authenticate(bearer).await,
        None => Err(AuthenticationError::Invalid),
    };
    let identity = match identity {
        Ok(identity) => identity,
        Err(AuthenticationError::Invalid) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "authentication_required",
                    message: "A valid signed browser identity is required.".to_owned(),
                }),
            ));
        }
        Err(AuthenticationError::Unavailable(message)) => {
            eprintln!("OIDC verification unavailable: {message}");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "identity_verification_unavailable",
                    message: "Identity verification is temporarily unavailable.".to_owned(),
                }),
            ));
        }
    };
    let required_scope = oidc_scope_for_route(request.method(), request.uri().path());
    if !identity.has_scope(required_scope) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                code: "permission_denied",
                message: format!("The signed identity does not grant {required_scope}."),
            }),
        ));
    }
    request
        .extensions_mut()
        .insert(AuthenticatedTenant(identity.tenant.clone()));
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

fn oidc_scope_for_route(method: &Method, path: &str) -> &'static str {
    match path {
        "/v1/me" => "identity:read",
        "/v1/audit-events" => "cerebro:read",
        "/v1/identity/orgs" => "cerebro:read",
        "/v1/identity/users" => "cerebro:read",
        "/v1/source-runtimes/health" | "/v1/source-runtimes/freshness" => "cerebro:read",
        _ if path.starts_with("/v1/source-runtimes/") && method == Method::PUT => "cerebro:write",
        _ if path.starts_with("/v1/source-runtimes/") && path.ends_with("/sync") => "cerebro:write",
        "/v1/graph/provenance" => "cerebro:read",
        "/platform/graph/provenance" => "cerebro:read",
        "/v1/ask-queries" if method == Method::GET => "cerebro:read",
        "/v1/ask-queries" => "cerebro:write",
        _ if path.starts_with("/v1/ask-queries/") => "cerebro:write",
        "/v1/finding-validations" => "cerebro:write",
        _ if path.starts_with("/v1/finding-validations/") => "cerebro:read",
        "/v1/action-dispatches" => ACTION_EXECUTE_SCOPE,
        _ if path.starts_with("/v1/action-dispatches/") => ACTION_EXECUTE_SCOPE,
        "/v1/action-reconciliation-runs" => ACTION_RECONCILE_SCOPE,
        "/v1/actions" if method == Method::GET => "cerebro:actions:read",
        "/v1/actions" => "cerebro:actions:write",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/provider-observation") => {
            ACTION_RECONCILE_SCOPE
        }
        _ if path.starts_with("/v1/actions/") && path.ends_with("/commands") => {
            "cerebro:actions:write"
        }
        _ if path.starts_with("/v1/actions/") => "cerebro:actions:read",
        "/v1/projections/legacy-deltas" | "/v1/projections/collections" => "cerebro:write",
        _ => "cerebro:read",
    }
}

async fn record_request(
    State(metrics): State<PlatformMetrics>,
    request: Request,
    next: Next,
) -> Response {
    let operation = bounded_operation(request.method(), request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    metrics
        .record(
            operation,
            response.status(),
            started.elapsed().as_secs_f64(),
        )
        .await;
    response
}

fn bounded_operation(method: &Method, path: &str) -> &'static str {
    match path {
        "/healthz" => "healthz",
        "/readyz" => "readyz",
        "/metrics" => "metrics",
        "/v1/me" => "current_user",
        "/v1/finding-validations" => "record_finding_validation",
        "/v1/action-definitions" => "action_definitions",
        "/v1/policy-definitions" => "policy_definitions",
        "/v1/action-dispatches" => "list_action_dispatches",
        "/v1/action-reconciliation-runs" => "run_action_reconciliation",
        "/v1/sources/summary" => "source_summary",
        "/v1/audit-events" => "list_audit_events",
        "/v1/identity/orgs" => "list_identity_orgs",
        "/v1/identity/users" => "list_identity_users",
        "/platform/graph/neighborhood" => "neighborhood",
        "/v1/graph/search" => "search",
        "/v1/graph/expand" => "expand",
        "/v1/graph/expand-batch" => "expand_batch",
        "/v1/graph/paths" => "paths",
        "/v1/graph/provenance" => "graph_provenance",
        "/platform/graph/provenance" => "graph_provenance",
        "/v1/security/lifecycle" => "security_lifecycle",
        "/v1/ask-queries" if method == Method::GET => "list_ask_queries",
        "/v1/ask-queries" => "create_ask_query",
        _ if path.starts_with("/v1/ask-queries/") && method == Method::DELETE => "delete_ask_query",
        _ if path.starts_with("/v1/ask-queries/") => "update_ask_query",
        "/v1/source-runtimes" => "list_source_runtimes",
        "/v1/source-runtimes/freshness" => "runtime_freshness",
        _ if path.starts_with("/v1/source-runtimes/") && path.ends_with("/invalid-events") => {
            "list_source_runtime_invalid_events"
        }
        _ if path.starts_with("/v1/source-runtimes/") && method == Method::PUT => {
            "put_source_runtime"
        }
        _ if path.starts_with("/v1/source-runtimes/") && path.ends_with("/sync") => {
            "sync_source_runtime"
        }
        _ if path.starts_with("/v1/source-runtimes/") => "get_source_runtime",
        "/v1/actions" if method == Method::GET => "list_actions",
        "/v1/actions" => "propose_action",
        "/v1/projections/legacy-deltas" => "record_legacy_projection",
        "/v1/projections/collections" => "record_source_collection",
        _ if path.starts_with("/v1/projections/collections/") => "get_source_collection",
        "/v1/projections/authority" => "projection_authority",
        _ if path.starts_with("/v1/entities/") => "get_entity",
        _ if path.starts_with("/v1/finding-validations/") => "get_finding_validation",
        _ if path.starts_with("/v1/action-dispatches/") => "get_action_dispatch",
        _ if path.starts_with("/v1/assertions/") => "explain_assertion",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/history") => "action_history",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/provider-observation") => {
            "observe_action_provider"
        }
        _ if path.starts_with("/v1/actions/") && path.ends_with("/commands") => "transition_action",
        _ if path.starts_with("/v1/actions/") => "get_action",
        _ if path.starts_with("/cerebro.graph.v1.OrganizationalGraphService/") => "connect_rpc",
        _ if path.starts_with("/cerebro.v1.SecurityLifecycleService/") => "security_lifecycle",
        _ => "other",
    }
}

impl PlatformMetrics {
    async fn record(&self, operation: &'static str, status: StatusCode, elapsed_seconds: f64) {
        let mut metrics = self.0.lock().await;
        let series = metrics.entry(operation).or_default();
        if status.is_success() {
            series.successes += 1;
        } else {
            series.failures += 1;
        }
        series.duration_sum_seconds += elapsed_seconds;
        for (index, upper_bound) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if elapsed_seconds <= *upper_bound {
                series.duration_buckets[index] += 1;
            }
        }
    }

    async fn render(&self) -> String {
        let metrics = self.0.lock().await;
        let mut output = String::from(
            "# HELP cerebro_rust_http_requests_total Bounded Rust platform HTTP requests.\n\
             # TYPE cerebro_rust_http_requests_total counter\n\
             # HELP cerebro_rust_http_request_duration_seconds Rust platform request latency.\n\
             # TYPE cerebro_rust_http_request_duration_seconds histogram\n",
        );
        for (operation, series) in metrics.iter() {
            output.push_str(&format!(
                "cerebro_rust_http_requests_total{{operation=\"{operation}\",status_class=\"success\"}} {}\n",
                series.successes
            ));
            output.push_str(&format!(
                "cerebro_rust_http_requests_total{{operation=\"{operation}\",status_class=\"failure\"}} {}\n",
                series.failures
            ));
            for (upper_bound, count) in LATENCY_BUCKETS_SECONDS
                .iter()
                .zip(series.duration_buckets.iter())
            {
                output.push_str(&format!(
                    "cerebro_rust_http_request_duration_seconds_bucket{{operation=\"{operation}\",le=\"{upper_bound}\"}} {count}\n"
                ));
            }
            let count = series.successes + series.failures;
            output.push_str(&format!(
                "cerebro_rust_http_request_duration_seconds_bucket{{operation=\"{operation}\",le=\"+Inf\"}} {count}\n\
                 cerebro_rust_http_request_duration_seconds_sum{{operation=\"{operation}\"}} {}\n\
                 cerebro_rust_http_request_duration_seconds_count{{operation=\"{operation}\"}} {count}\n",
                series.duration_sum_seconds
            ));
        }
        output
    }
}

struct ProjectionRuntime {
    catalog: SourceCatalog,
    authority: PostgresLedger,
    store: Mutex<DurableGraphStore>,
}

#[derive(Debug)]
enum ProjectionFailure {
    Invalid(String),
    Store(StoreError),
}

impl ProjectionFailure {
    fn is_retryable(&self) -> bool {
        matches!(self, Self::Store(error) if error.is_retryable())
    }
}

impl std::fmt::Display for ProjectionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProjectionFailure {}

impl ProjectionRuntime {
    async fn project_committed_shadow(
        &self,
        event: CommittedSourceEvent,
    ) -> Result<ProjectEventResponse, ProjectionFailure> {
        self.project_committed_with_intent(event, true).await
    }

    async fn project_committed_with_intent(
        &self,
        event: CommittedSourceEvent,
        materialize_shadow: bool,
    ) -> Result<ProjectEventResponse, ProjectionFailure> {
        self.authority
            .record_source_event(&event)
            .await
            .map_err(ProjectionFailure::Store)?;
        if matches!(
            event.event_kind(),
            CREDENTIAL_EVENT_KIND | CERTIFICATE_EVENT_KIND
        ) {
            return self.project_security_lifecycle(event).await;
        }
        let authority = self
            .authority
            .projection_authority(
                event.tenant_id().as_str(),
                event.source_id(),
                event.family_id(),
            )
            .await
            .map_err(ProjectionFailure::Store)?;
        if !should_materialize(authority.authority, materialize_shadow) {
            return Ok(ProjectEventResponse {
                authority: ProjectionAuthority::Legacy,
                projected: false,
                graph_revision: None,
                entities_upserted: 0,
                assertions_upserted: 0,
            });
        }
        let tenant_id = event.tenant_id().clone();
        let collection_id = event
            .collection_id()
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        if let Some(receipt) = self
            .store
            .lock()
            .await
            .resume_collection(&tenant_id, collection_id.as_str())
            .await
            .map_err(ProjectionFailure::Store)?
        {
            return Ok(ProjectEventResponse {
                authority: ProjectionAuthority::Rust,
                projected: true,
                graph_revision: Some(receipt.graph_revision),
                entities_upserted: receipt.entities_upserted,
                assertions_upserted: receipt.assertions_upserted,
            });
        }
        if threat_insight_projection::matches(&event) {
            let (batch, delta) =
                threat_insight_projection::project(event).map_err(ProjectionFailure::Invalid)?;
            let receipt = self
                .store
                .lock()
                .await
                .apply(&batch, delta)
                .await
                .map_err(ProjectionFailure::Store)?;
            return Ok(ProjectEventResponse {
                authority: authority.authority,
                projected: true,
                graph_revision: Some(receipt.graph_revision),
                entities_upserted: receipt.entities_upserted,
                assertions_upserted: receipt.assertions_upserted,
            });
        }
        if trusted_endpoint_projection::matches(&event) {
            let contract = self
                .catalog
                .push_source(event.source_id())
                .and_then(|source| source.family(event.family_id()))
                .ok_or_else(|| {
                    ProjectionFailure::Invalid(format!(
                        "push family {}.{} is not in the compiled catalog",
                        event.source_id(),
                        event.family_id()
                    ))
                })?;
            let (batch, delta) = trusted_endpoint_projection::project(event, contract)
                .map_err(ProjectionFailure::Invalid)?;
            let receipt = self
                .store
                .lock()
                .await
                .apply(&batch, delta)
                .await
                .map_err(ProjectionFailure::Store)?;
            return Ok(ProjectEventResponse {
                authority: authority.authority,
                projected: true,
                graph_revision: Some(receipt.graph_revision),
                entities_upserted: receipt.entities_upserted,
                assertions_upserted: receipt.assertions_upserted,
            });
        }
        let source = self
            .catalog
            .get(event.source_id())
            .ok_or_else(|| {
                ProjectionFailure::Invalid(format!(
                    "source {} is not in the compiled catalog",
                    event.source_id()
                ))
            })?
            .clone();
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == event.family_id())
            .ok_or_else(|| {
                ProjectionFailure::Invalid(format!(
                    "family {}.{} is not in the compiled catalog",
                    event.source_id(),
                    event.family_id()
                ))
            })?;
        let provider_id = event_provider_id(event.attributes(), event.observation_id().as_str());
        let provider_kind = format!("{}.{}", event.source_id(), family.projection().template());
        let batch = event
            .into_batch(provider_kind, provider_id)
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        let identity_resolution = self
            .authority
            .identity_resolution_snapshot(&tenant_id)
            .await
            .map_err(ProjectionFailure::Store)?;
        let mapper = CatalogGraphMapper::new(source, env!("CARGO_PKG_VERSION"))
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?
            .with_identity_resolution(identity_resolution);
        let delta = mapper
            .map(&batch)
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        let receipt = self
            .store
            .lock()
            .await
            .apply(&batch, delta)
            .await
            .map_err(ProjectionFailure::Store)?;
        Ok(ProjectEventResponse {
            authority: authority.authority,
            projected: true,
            graph_revision: Some(receipt.graph_revision),
            entities_upserted: receipt.entities_upserted,
            assertions_upserted: receipt.assertions_upserted,
        })
    }

    async fn record_legacy_projection(
        &self,
        tenant_id: &TenantId,
        request: &LegacyProjectionRequest,
    ) -> Result<LegacyProjectionResponse, StoreError> {
        let delta_json = serde_json::to_value(&request.delta)?;
        let delta_digest = json_digest(&delta_json);
        self.authority
            .record_legacy_projection(
                tenant_id.as_str(),
                request.event_id.trim(),
                request.source_runtime_id.trim(),
                request.source_id.trim(),
                request.family_id.trim(),
                request.observed_at_unix_ms,
                request.delta.entities.len(),
                request.delta.links.len(),
                request.delta.entity_retractions.len(),
                request.delta.link_retractions.len(),
                request.delta.cleanup_requests.len(),
                &delta_digest,
                &delta_json,
            )
            .await?;
        Ok(LegacyProjectionResponse {
            recorded: true,
            delta_digest,
        })
    }

    async fn record_source_collection(
        &self,
        tenant_id: &TenantId,
        request: &SourceCollectionRequest,
    ) -> Result<SourceCollectionResponse, StoreError> {
        let manifest_json = serde_json::to_value(request)?;
        let manifest_digest = json_digest(&manifest_json);
        self.authority
            .record_source_collection(
                tenant_id.as_str(),
                request.collection_id.trim(),
                request.source_runtime_id.trim(),
                request.source_id.trim(),
                request.started_at_unix_ms,
                request.completed_at_unix_ms,
                &request.status,
                request.pages_read,
                request.records_scanned,
                request.records_accepted,
                request.records_rejected,
                request.entities_projected,
                request.links_projected,
                &manifest_digest,
                &manifest_json,
            )
            .await?;
        Ok(SourceCollectionResponse {
            recorded: true,
            manifest_digest,
        })
    }

    async fn source_collection(
        &self,
        tenant_id: &TenantId,
        source_runtime_id: &SourceRuntimeId,
        collection_id: &CollectionId,
    ) -> Result<Option<SourceCollectionRequest>, StoreError> {
        self.authority
            .source_collection_manifest(
                tenant_id.as_str(),
                source_runtime_id.as_str(),
                collection_id.as_str(),
            )
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(StoreError::from)
    }

    async fn project_security_lifecycle(
        &self,
        event: CommittedSourceEvent,
    ) -> Result<ProjectEventResponse, ProjectionFailure> {
        let tenant_id = event.tenant_id().clone();
        let collection_id = event
            .collection_id()
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        if let Some(receipt) = self
            .store
            .lock()
            .await
            .resume_collection(&tenant_id, collection_id.as_str())
            .await
            .map_err(ProjectionFailure::Store)?
        {
            return Ok(ProjectEventResponse {
                authority: ProjectionAuthority::Rust,
                projected: true,
                graph_revision: Some(receipt.graph_revision),
                entities_upserted: receipt.entities_upserted,
                assertions_upserted: receipt.assertions_upserted,
            });
        }
        let observation = decode_protobuf_observation(
            event.raw_payload(),
            &tenant_id,
            event.observed_at_unix_ms(),
        )
        .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        let observation_id = event.observation_id().clone();
        let provider_kind = format!(
            "security.lifecycle.{}",
            match event.event_kind() {
                CREDENTIAL_EVENT_KIND => "credential",
                CERTIFICATE_EVENT_KIND => "certificate",
                _ => unreachable!("caller checks the portable lifecycle kind"),
            }
        );
        let provider_id = observation.subject_ref.id.clone();
        let batch = event
            .into_batch(provider_kind, provider_id)
            .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        let delta =
            project_observation(batch.scope.receipt().clone(), observation_id, &observation)
                .map_err(|error| ProjectionFailure::Invalid(error.to_string()))?;
        let receipt = self
            .store
            .lock()
            .await
            .apply(&batch, delta)
            .await
            .map_err(ProjectionFailure::Store)?;
        Ok(ProjectEventResponse {
            authority: ProjectionAuthority::Rust,
            projected: true,
            graph_revision: Some(receipt.graph_revision),
            entities_upserted: receipt.entities_upserted,
            assertions_upserted: receipt.assertions_upserted,
        })
    }
}

fn should_materialize(authority: ProjectionAuthority, materialize_shadow: bool) -> bool {
    authority == ProjectionAuthority::Rust || materialize_shadow
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    runtime: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: String,
}

#[derive(Deserialize)]
struct SourceCollectionQuery {
    tenant_id: String,
    source_runtime_id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    page_token: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ActionReconciliationRun {
    claimed: usize,
    observed: usize,
    terminal: usize,
    provider_unavailable: usize,
}

#[derive(Debug, Default, Deserialize)]
struct HttpLifecycleQuery {
    #[serde(default)]
    subject_kind: Option<SubjectKind>,
    #[serde(default)]
    state: Option<LifecycleState>,
    #[serde(default)]
    owner_urn: Option<String>,
    #[serde(default)]
    expires_before: Option<String>,
    #[serde(default)]
    findings_only: bool,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    page_token: Option<String>,
    #[serde(default)]
    authority_id: Option<String>,
    #[serde(default)]
    stable_locator: Option<String>,
}

impl From<HttpLifecycleQuery> for LifecycleQuery {
    fn from(value: HttpLifecycleQuery) -> Self {
        let subject_locator =
            value
                .authority_id
                .zip(value.stable_locator)
                .map(|(authority_id, stable_locator)| SubjectLocator {
                    subject_kind: value
                        .subject_kind
                        .expect("subject locator validated before conversion"),
                    authority_id,
                    stable_locator,
                });
        Self {
            subject_kinds: value.subject_kind.into_iter().collect(),
            states: value.state.into_iter().collect(),
            owner_urns: value.owner_urn.into_iter().collect(),
            expires_before: value.expires_before,
            findings_only: value.findings_only,
            limit: value.limit,
            page_token: value.page_token,
            subject_locator,
        }
    }
}

#[derive(Deserialize)]
struct ExpandRequest {
    tenant_id: String,
    #[serde(alias = "root_entity_id")]
    root_key: String,
    depth: usize,
    limit: usize,
}

#[derive(Deserialize)]
struct ExpandBatchRequest {
    tenant_id: String,
    root_keys: Vec<String>,
    depth: usize,
    limit: usize,
}

#[derive(Serialize)]
struct ExpandBatchResponse {
    neighborhoods: BTreeMap<String, Neighborhood>,
}

#[derive(Deserialize)]
struct SearchRequest {
    tenant_id: String,
    query: String,
    #[serde(default)]
    kinds: Vec<String>,
    limit: usize,
}

#[derive(Deserialize)]
struct PathsRequest {
    tenant_id: String,
    from_entity_id: String,
    to_entity_id: String,
    max_depth: usize,
    limit: usize,
}

#[derive(Serialize)]
struct PathsResponse {
    paths: Vec<GraphPath>,
}

#[derive(Deserialize)]
struct ProductNeighborhoodQuery {
    root_urn: String,
    tenant_id: Option<String>,
    workspace_id: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct SourceRuntimeHealthQuery {
    source_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Clone, Serialize)]
struct RustSourceRuntimeHealthView {
    runtime_id: String,
    source_id: String,
    enabled_state: String,
    status: String,
    readiness: String,
    next_action: String,
    last_synced_at: Option<String>,
    stale_after_seconds: Option<u64>,
    expected_cadence_seconds: Option<u64>,
    cursor_pending: bool,
    checkpoint_cursor_present: bool,
    schedule_context_configured: bool,
    contract_probe_state: String,
    graph_state: String,
    finding_evaluation_state: String,
    latest_graph_run: Option<SourceRuntimeGraphObservation>,
    latest_finding_evaluation: Option<RustFindingEvaluationHealthView>,
}

#[derive(Clone, Serialize)]
struct RustFindingEvaluationHealthView {
    status: String,
}

#[derive(Serialize)]
struct RustSourceRuntimeHealthSummary {
    source_id: String,
    total: usize,
    healthy: usize,
    needs_refresh: usize,
    poor: usize,
    bad: usize,
    cursor_pending: usize,
    schedule_context_missing: usize,
    graph_current: usize,
    graph_behind: usize,
    graph_running: usize,
    graph_failed: usize,
    graph_not_observed: usize,
    graph_unknown: usize,
    latest_activity_at: Option<String>,
    readiness: String,
    next_action: String,
}

#[derive(Serialize)]
struct RustSourceRuntimeHealthResponse {
    generated_at: String,
    runtimes: Vec<RustSourceRuntimeHealthView>,
    source_summaries: Vec<RustSourceRuntimeHealthSummary>,
}

/// Go-parity `runtimeFreshnessRecord` view served from the Rust ledger.
///
/// Field names and serialization semantics mirror the Go
/// `runtimeFreshnessResponse` contract. `family`, `checkpoint_watermark`, and
/// `watermark_lag_seconds` are omitted-when-empty on the Go side and are not
/// observable from the Rust ledger, so they are always absent here.
#[derive(Serialize)]
struct RustRuntimeFreshnessRecord {
    runtime_id: String,
    source_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tenant_id: String,
    lifecycle_state: &'static str,
    schedule_state: &'static str,
    freshness_state: &'static str,
    source_sync_state: &'static str,
    graph_ingest_state: String,
    finding_evaluation_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_class: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    failure_reason: &'static str,
    backfill_eligible: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    backfill_eligibility_reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_synced_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_lag_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_graph_run: Option<SourceRuntimeGraphObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_lag_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_finding_evaluation: Option<RustFindingEvaluationHealthView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_cadence_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stale_after_seconds: Option<u64>,
    generated_at: String,
    next_action: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    recommended_workflow: &'static str,
    cursor_pending: bool,
    checkpoint_cursor_present: bool,
    schedule_context_configured: bool,
}

#[derive(Serialize)]
struct RustRuntimeFreshnessResponse {
    generated_at: String,
    status: &'static str,
    runtimes: Vec<RustRuntimeFreshnessRecord>,
    summaries: Vec<RuntimeFreshnessRollup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionTransitionRequest {
    expected_version: u64,
    command: HttpActionCommand,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionDispatchQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum HttpActionCommand {
    RecordSimulation {},
    RequestApproval {},
    RecordApproval {
        receipt: HttpDecisionReceipt,
    },
    Claim {
        worker_id: String,
        claimed_at_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    },
    RenewClaim {
        renewed_at_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    },
    ReleaseExpiredClaim {
        observed_at_unix_ms: u64,
    },
    StartExecution {
        started_at_unix_ms: u64,
    },
    Fail {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpDecisionReceipt {
    decision_id: String,
    proposal_digest: String,
    approved: bool,
    decided_by: String,
    decided_at_unix_ms: u64,
}

impl HttpActionCommand {
    fn required_scope(&self) -> &'static str {
        match self {
            Self::RecordSimulation {} => ACTION_SIMULATE_SCOPE,
            Self::RequestApproval {} => ACTION_PROPOSE_SCOPE,
            Self::RecordApproval { .. } => ACTION_APPROVE_SCOPE,
            Self::Claim { .. }
            | Self::RenewClaim { .. }
            | Self::ReleaseExpiredClaim { .. }
            | Self::StartExecution { .. }
            | Self::Fail {} => ACTION_EXECUTE_SCOPE,
        }
    }

    fn into_domain(self) -> Result<ActionCommand, String> {
        Ok(match self {
            Self::RecordSimulation {} => ActionCommand::RecordSimulation,
            Self::RequestApproval {} => ActionCommand::RequestApproval,
            Self::RecordApproval { receipt } => ActionCommand::RecordApproval {
                receipt: receipt.into_domain()?,
            },
            Self::Claim {
                worker_id,
                claimed_at_unix_ms,
                claim_expires_at_unix_ms,
            } => ActionCommand::Claim {
                worker_id: OpaqueId::parse(worker_id).map_err(|error| error.to_string())?,
                claimed_at_unix_ms,
                claim_expires_at_unix_ms,
            },
            Self::RenewClaim {
                renewed_at_unix_ms,
                claim_expires_at_unix_ms,
            } => ActionCommand::RenewClaim {
                renewed_at_unix_ms,
                claim_expires_at_unix_ms,
            },
            Self::ReleaseExpiredClaim {
                observed_at_unix_ms,
            } => ActionCommand::ReleaseExpiredClaim {
                observed_at_unix_ms,
            },
            Self::StartExecution { started_at_unix_ms } => {
                ActionCommand::StartExecution { started_at_unix_ms }
            }
            Self::Fail {} => ActionCommand::Fail,
        })
    }
}

impl HttpDecisionReceipt {
    fn into_domain(self) -> Result<DecisionReceipt, String> {
        Ok(DecisionReceipt {
            decision_id: DecisionId::parse(self.decision_id).map_err(|error| error.to_string())?,
            proposal_digest: self.proposal_digest,
            approved: self.approved,
            decided_by: parse_action_actor(self.decided_by)?,
            decided_at_unix_ms: self.decided_at_unix_ms,
        })
    }
}

fn parse_action_actor(value: String) -> Result<ActorId, String> {
    ActorId::parse(value).map_err(|error| error.to_string())
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ProductNeighborhoodNode {
    urn: String,
    entity_type: String,
    label: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ProductNeighborhoodRelation {
    from_urn: String,
    relation: String,
    to_urn: String,
    attributes: BTreeMap<String, String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ProductNeighborhood {
    root: ProductNeighborhoodNode,
    neighbors: Vec<ProductNeighborhoodNode>,
    relations: Vec<ProductNeighborhoodRelation>,
}

#[derive(Serialize)]
struct ProjectEventResponse {
    authority: ProjectionAuthority,
    projected: bool,
    graph_revision: Option<u64>,
    entities_upserted: usize,
    assertions_upserted: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyEntityDeltaRecord {
    urn: String,
    tenant_id: String,
    #[serde(default)]
    application_workspace_id: String,
    source_id: String,
    runtime_id: String,
    entity_type: String,
    label: String,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyLinkDeltaRecord {
    tenant_id: String,
    #[serde(default)]
    application_workspace_id: String,
    source_id: String,
    runtime_id: String,
    from_urn: String,
    to_urn: String,
    relation: String,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyCleanupRequest {
    tenant_id: String,
    source_id: String,
    runtime_id: String,
    finding_id: String,
    #[serde(default)]
    entity_types: Vec<String>,
    #[serde(default)]
    urn_prefixes: Vec<String>,
    only_isolated: bool,
    limit: u32,
    dry_run: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectionDelta {
    #[serde(default)]
    entities: Vec<LegacyEntityDeltaRecord>,
    #[serde(default)]
    links: Vec<LegacyLinkDeltaRecord>,
    #[serde(default)]
    entity_retractions: Vec<String>,
    #[serde(default)]
    link_retractions: Vec<LegacyLinkDeltaRecord>,
    #[serde(default)]
    cleanup_requests: Vec<LegacyCleanupRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectionRequest {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    event_id: String,
    observed_at_unix_ms: i64,
    append_log_committed: bool,
    delta: LegacyProjectionDelta,
}

#[derive(Serialize)]
struct LegacyProjectionResponse {
    recorded: bool,
    delta_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceCollectionRequest {
    collection_id: String,
    tenant_id: String,
    source_id: String,
    source_runtime_id: String,
    started_at_unix_ms: i64,
    completed_at_unix_ms: i64,
    status: String,
    #[serde(default)]
    incompleteness_reasons: Vec<String>,
    #[serde(default)]
    expected_family_ids: Vec<String>,
    #[serde(default)]
    observed_family_ids: Vec<String>,
    pages_read: u32,
    records_scanned: u32,
    records_accepted: u32,
    records_rejected: u32,
    entities_projected: u32,
    links_projected: u32,
}

#[derive(Serialize)]
struct SourceCollectionResponse {
    recorded: bool,
    manifest_digest: String,
}

#[derive(Deserialize)]
struct ProjectionAuthorityQuery {
    tenant_id: String,
    source_id: String,
    family_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    install_tls_crypto_provider()?;
    match env::args().nth(1).as_deref() {
        None | Some("demo") => demo().await,
        Some("serve") => serve_memory(OrganizationalGraph::new()).await,
        Some("serve-demo") => serve_memory(demo_graph()?.0).await,
        Some("serve-neo4j-readonly") => serve_neo4j_readonly().await,
        Some("serve-slack-authority") => slack_authority::serve().await,
        Some("eval-slack-agent") => slack_agent_eval::run().await,
        Some("serve-neo4j") => serve_neo4j().await,
        Some("serve-neo4j-consumer") => serve_neo4j_consumer().await,
        Some("consume-append-log") => consume_append_log().await,
        Some("inspect-append-log") => append_log_consumer::inspect().await,
        Some("inspect-consumer-run") => append_log_consumer::inspect_run().await,
        Some("migrate-stores") => migrate_stores().await,
        Some("rebuild-lifecycle-projection") => rebuild_lifecycle_projection().await,
        Some("audit-legacy-root-coverage") => audit_legacy_root_coverage().await,
        Some("sync-source") => sync_source().await,
        Some("publish-source-pages") => source_page_publisher::run().await,
        Some("catalog-summary") => catalog_summary(),
        Some("list-catalog-families") => list_catalog_families(),
        Some("compare-projection") => parity_command::compare_projection().await,
        Some("evaluate-family") => cutover_command::evaluate_family().await,
        Some("promote-family") => cutover_command::promote_family().await,
        Some("show-authority") => cutover_command::show_authority().await,
        Some("evaluate-all-families") => cutover_command::evaluate_all_families().await,
        Some("--help" | "-h") => {
            println!(
                "cerebro-platform <demo|serve|serve-demo|serve-neo4j-readonly|serve-slack-authority|eval-slack-agent|serve-neo4j|serve-neo4j-consumer|consume-append-log|inspect-append-log|inspect-consumer-run|migrate-stores|rebuild-lifecycle-projection|audit-legacy-root-coverage|sync-source|publish-source-pages|catalog-summary|list-catalog-families|compare-projection|evaluate-family|promote-family|show-authority|evaluate-all-families>"
            );
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

fn install_tls_crypto_provider() -> Result<(), Box<dyn Error>> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "TLS crypto provider was initialized concurrently".into())
}

async fn serve_memory(graph: OrganizationalGraph) -> Result<(), Box<dyn Error>> {
    serve(Arc::new(MemoryAgentGraph::new(graph)), None, None).await
}

async fn serve_neo4j_readonly() -> Result<(), Box<dyn Error>> {
    let graph = Neo4jProjector::connect(
        &required_env("CEREBRO_NEO4J_URI")?,
        &required_env("CEREBRO_NEO4J_USERNAME")?,
        &required_env("CEREBRO_NEO4J_PASSWORD")?,
    )
    .await?;
    let lifecycle_projection = Arc::new(graph.clone());
    serve(Arc::new(graph), Some(lifecycle_projection), None).await
}

async fn serve_neo4j() -> Result<(), Box<dyn Error>> {
    let (graph, projection) = neo4j_runtime().await?;
    let lifecycle_projection = Arc::new(graph.clone());
    serve(
        Arc::new(graph),
        Some(lifecycle_projection),
        Some(projection),
    )
    .await
}

async fn serve_neo4j_consumer() -> Result<(), Box<dyn Error>> {
    let (graph, projection) = neo4j_runtime().await?;
    let lifecycle_projection = Arc::new(graph.clone());
    let server = serve(
        Arc::new(graph),
        Some(lifecycle_projection),
        Some(projection.clone()),
    );
    let consumer = append_log_consumer::run(projection);
    tokio::select! {
        result = server => result,
        result = consumer => result,
    }
}

async fn consume_append_log() -> Result<(), Box<dyn Error>> {
    let (_, projection) = neo4j_runtime().await?;
    append_log_consumer::run(projection).await
}

async fn neo4j_runtime() -> Result<(Neo4jProjector, Arc<ProjectionRuntime>), Box<dyn Error>> {
    let uri = required_env("CEREBRO_NEO4J_URI")?;
    let username = required_env("CEREBRO_NEO4J_USERNAME")?;
    let password = required_env("CEREBRO_NEO4J_PASSWORD")?;
    let graph = Neo4jProjector::connect(&uri, &username, &password).await?;
    graph.migrate().await?;
    let connection_string = required_env("CEREBRO_POSTGRES_DSN")?;
    let authority = PostgresLedger::connect_tls(&connection_string).await?;
    authority.migrate().await?;
    let store_ledger = PostgresLedger::connect_tls(&connection_string).await?;
    store_ledger.migrate().await?;
    let projection = Arc::new(ProjectionRuntime {
        catalog: load_catalog()?,
        authority,
        store: Mutex::new(DurableGraphStore::new(store_ledger, graph.clone())),
    });
    Ok((graph, projection))
}

async fn migrate_stores() -> Result<(), Box<dyn Error>> {
    let ledger = PostgresLedger::connect_tls(&required_env("CEREBRO_POSTGRES_DSN")?).await?;
    ledger.migrate().await?;
    let graph = connect_neo4j().await?;
    graph.migrate().await?;
    println!("organizational stores migrated");
    Ok(())
}

async fn rebuild_lifecycle_projection() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::parse(required_env("CEREBRO_TENANT_ID")?)?;
    let graph = connect_neo4j().await?;
    graph.migrate().await?;
    let rebuilt = graph
        .rebuild_lifecycle_projection(&tenant_id, 1_000)
        .await?;
    println!(
        "{}",
        serde_json::json!({
            "tenant_id": tenant_id.as_str(),
            "entities_rebuilt": rebuilt,
        })
    );
    Ok(())
}

async fn audit_legacy_root_coverage() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::parse(required_env("CEREBRO_TENANT_ID")?)?;
    let graph = connect_neo4j().await?;
    let coverage = graph.legacy_root_coverage(&tenant_id).await?;
    serde_json::to_writer(io::stdout(), &coverage)?;
    println!();
    Ok(())
}

async fn sync_source() -> Result<(), Box<dyn Error>> {
    source_runtime_sync::sync_from_environment().await
}

fn source_config_environment_allowlist() -> BTreeSet<String> {
    env::var("CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST")
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn source_runtime_lease_ttl_millis() -> Result<u64, Box<dyn Error>> {
    let value = env::var("CEREBRO_SOURCE_LEASE_TTL_MS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(DEFAULT_SOURCE_RUNTIME_LEASE_TTL_MS);
    if value == 0 {
        return Err("CEREBRO_SOURCE_LEASE_TTL_MS must be positive".into());
    }
    Ok(value)
}

fn source_runtime_lease_owner() -> String {
    env::var("CEREBRO_SOURCE_LEASE_OWNER")
        .ok()
        .filter(|owner| !owner.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "cerebro-rust-source:{}:{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            )
        })
}

fn start_source_runtime_lease_renewal(
    ledger: Arc<PostgresLedger>,
    fence: SourceRuntimeLeaseFence,
    ttl_millis: u64,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let (stop_sender, mut stop_receiver) = oneshot::channel();
    let (failure_sender, failure_receiver) = oneshot::channel();
    let interval = Duration::from_millis(
        (ttl_millis / 2).clamp(1, MAX_SOURCE_RUNTIME_LEASE_RENEWAL_INTERVAL_MS),
    );
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_receiver => return,
                _ = ticker.tick() => {
                    match ledger.renew_source_runtime_lease(&fence, ttl_millis).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let _ = failure_sender.send(
                                "source runtime lease was lost during collection".to_owned(),
                            );
                            return;
                        }
                        Err(error) => {
                            let _ = failure_sender.send(format!(
                                "source runtime lease renewal failed: {error}"
                            ));
                            return;
                        }
                    }
                }
            }
        }
    });
    (stop_sender, failure_receiver, task)
}

async fn connect_neo4j() -> Result<Neo4jProjector, Box<dyn Error>> {
    Ok(Neo4jProjector::connect(
        &required_env("CEREBRO_NEO4J_URI")?,
        &required_env("CEREBRO_NEO4J_USERNAME")?,
        &required_env("CEREBRO_NEO4J_PASSWORD")?,
    )
    .await?)
}

#[derive(Default)]
struct CatalogAuthSettings {
    token_header: String,
    token_scheme: String,
    header_parameters: BTreeMap<String, String>,
    query_parameters: BTreeMap<String, String>,
    json_body_parameters: BTreeMap<String, String>,
    oauth_authorization_code: Option<CompiledOauthAuthorizationCode>,
    oauth_client_credentials: Option<CompiledOauthClientCredentials>,
}

impl CatalogAuthSettings {
    fn from_source(source: &CompiledSource) -> Self {
        Self {
            token_header: source.token_header().to_owned(),
            token_scheme: source.token_scheme().to_owned(),
            header_parameters: source.auth_header_parameters().clone(),
            query_parameters: source.auth_query_parameters().clone(),
            json_body_parameters: source.auth_json_body_parameters().clone(),
            oauth_authorization_code: source.oauth_authorization_code().cloned(),
            oauth_client_credentials: source.oauth_client_credentials().cloned(),
        }
    }
}

fn resolved_auth(
    model: &AuthModel,
    settings: CatalogAuthSettings,
    config: &mut BTreeMap<String, String>,
) -> Result<ResolvedAuth, Box<dyn Error>> {
    let CatalogAuthSettings {
        token_header,
        token_scheme,
        header_parameters,
        query_parameters,
        json_body_parameters,
        oauth_authorization_code,
        oauth_client_credentials,
    } = settings;
    Ok(match model {
        AuthModel::None => ResolvedAuth::None,
        AuthModel::Basic => ResolvedAuth::Basic {
            username: take_required_config(config, "username")?,
            password: take_required_config(config, "password")?,
        },
        AuthModel::ApiKey if !header_parameters.is_empty() => {
            let mut parameters = BTreeMap::new();
            for (header, credential_field) in header_parameters {
                parameters.insert(header, take_required_config(config, &credential_field)?);
            }
            ResolvedAuth::HeaderParameters { parameters }
        }
        AuthModel::ApiKey if !json_body_parameters.is_empty() => {
            let mut parameters = BTreeMap::new();
            for (parameter, credential_field) in json_body_parameters {
                parameters.insert(parameter, take_required_config(config, &credential_field)?);
            }
            ResolvedAuth::JsonBodyParameters { parameters }
        }
        AuthModel::ApiKey if !query_parameters.is_empty() => {
            let mut parameters = BTreeMap::new();
            for (parameter, credential_field) in query_parameters {
                parameters.insert(parameter, take_required_config(config, &credential_field)?);
            }
            ResolvedAuth::QueryParameters { parameters }
        }
        AuthModel::ApiKey => ResolvedAuth::Header {
            name: nonempty_catalog_auth_value(&token_header, "token_header")?,
            value: apply_auth_scheme(
                &token_scheme,
                take_first_required_config(config, &["token", "api_key", "auth_value"])?,
            ),
        },
        AuthModel::AwsSigV4 => ResolvedAuth::AwsSigV4 {
            access_key_id: take_required_config(config, "access_key")?,
            secret_access_key: take_required_config(config, "secret_key")?,
            session_token: remove_nonempty(config, "session_token"),
            region: required_config(config, "region")?,
            service: required_config(config, "service")?,
        },
        AuthModel::DuoHmacV5 => ResolvedAuth::DuoHmacV5 {
            integration_key: take_required_config(config, "client_id")?,
            secret_key: take_required_config(config, "client_secret")?,
        },
        AuthModel::OauthClientCredentials => {
            let oauth = oauth_client_credentials
                .as_ref()
                .ok_or("source catalog OAuth client-credentials settings are missing")?;
            let token_url = resolve_oauth_token_url(oauth.token_url(), config)?;
            let mut token_params = BTreeMap::new();
            for (key, value) in oauth.token_params() {
                token_params.insert(key.clone(), render_source_config_template(value, config)?);
            }
            ResolvedAuth::OauthClientCredentials {
                client_id: take_required_config(config, "client_id")?,
                client_secret: take_required_config(config, "client_secret")?,
                token_url,
                scopes: oauth.scopes().to_vec(),
                scope_separator: oauth.scope_separator().to_owned(),
                token_request_auth_method: oauth.token_request_auth_method().to_owned(),
                token_params,
            }
        }
        AuthModel::OauthAuthorizationCode => {
            if let Some(token) = take_first_config(
                config,
                &["token", "access_token", "api_token", "bearer_token"],
            ) {
                for key in [
                    "token",
                    "access_token",
                    "api_token",
                    "bearer_token",
                    "client_id",
                    "client_secret",
                    "refresh_token",
                    "oauth_client_reference",
                ] {
                    discard_config_secret(config, key);
                }
                ResolvedAuth::Bearer { token }
            } else {
                let oauth = oauth_authorization_code
                    .as_ref()
                    .ok_or("source catalog OAuth authorization-code settings are missing")?;
                let token_url = resolve_oauth_token_url(oauth.token_url(), config)?;
                let mut token_params = BTreeMap::new();
                for (key, value) in oauth.token_params() {
                    token_params.insert(key.clone(), render_source_config_template(value, config)?);
                }
                discard_config_secret(config, "oauth_client_reference");
                ResolvedAuth::OauthAuthorizationCode {
                    client_id: take_required_config(config, "client_id")?,
                    client_secret: take_required_config(config, "client_secret")?,
                    refresh_token: take_required_config(config, "refresh_token")?,
                    token_url,
                    scopes: oauth.scopes().to_vec(),
                    scope_separator: oauth.scope_separator().to_owned(),
                    token_request_auth_method: oauth.token_request_auth_method().to_owned(),
                    token_params,
                }
            }
        }
        AuthModel::Signature => {
            let aliases = [
                "token",
                "signature",
                "auth_value",
                "access_token",
                "api_token",
                "api_key",
            ];
            let value = take_first_required_config(config, &aliases)?;
            for alias in aliases {
                discard_config_secret(config, alias);
            }
            ResolvedAuth::Header {
                name: if token_header.trim().is_empty() {
                    "Authorization".to_owned()
                } else {
                    nonempty_catalog_auth_value(&token_header, "token_header")?
                },
                value: apply_auth_scheme(
                    if token_scheme.trim().is_empty() {
                        "Signature"
                    } else {
                        &token_scheme
                    },
                    value,
                ),
            }
        }
        AuthModel::DuoHmac => {
            return Err("source auth requires a bespoke Rust connector".into());
        }
        _ => ResolvedAuth::Bearer {
            token: take_first_required_config(
                config,
                &["token", "access_token", "api_token", "bearer_token"],
            )?,
        },
    })
}

fn resolve_source_url(
    value: &str,
    config: &BTreeMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    if let Ok(url) = reqwest::Url::parse(value) {
        return Ok(url.to_string());
    }
    if !value.starts_with('/') {
        return Err("source catalog URL is invalid".into());
    }
    let base_url = reqwest::Url::parse(&required_config(config, "base_url")?)?;
    Ok(base_url.join(value)?.to_string())
}

fn resolve_oauth_token_url(
    template: &str,
    config: &BTreeMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    let rendered = render_source_config_template(template, config)?;
    let resolved = resolve_source_url(&rendered, config)?;
    let authority = template
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split('/').next())
        .unwrap_or_default();
    if authority.contains("${config.") {
        let token_url = reqwest::Url::parse(&resolved)?;
        let base_url = reqwest::Url::parse(&required_config(config, "base_url")?)?;
        if token_url.origin() != base_url.origin() {
            return Err("dynamic OAuth token URL must use the provider base origin".into());
        }
    }
    Ok(resolved)
}

fn render_source_config_template(
    template: &str,
    config: &BTreeMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    let mut rendered = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find("${config.") {
        rendered.push_str(&remaining[..start]);
        let placeholder = &remaining[start + "${config.".len()..];
        let end = placeholder
            .find('}')
            .ok_or("source catalog config template is not closed")?;
        let key = &placeholder[..end];
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("source catalog config template key is invalid".into());
        }
        rendered.push_str(&required_config(config, key)?);
        remaining = &placeholder[end + 1..];
    }
    rendered.push_str(remaining);
    if rendered.contains("${") || rendered.chars().any(char::is_control) || rendered.len() > 4_096 {
        return Err("source catalog config template is invalid".into());
    }
    Ok(rendered)
}

fn nonempty_catalog_auth_value(value: &str, field: &str) -> Result<String, Box<dyn Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("source catalog auth {field} is required").into());
    }
    Ok(value.to_owned())
}

fn apply_auth_scheme(scheme: &str, value: String) -> String {
    let scheme = scheme.trim();
    if scheme.is_empty() {
        value
    } else {
        format!("{scheme} {value}")
    }
}

fn required_config(config: &BTreeMap<String, String>, key: &str) -> Result<String, Box<dyn Error>> {
    config
        .get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("stored source runtime config {key:?} is required").into())
}

fn take_required_config(
    config: &mut BTreeMap<String, String>,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    remove_nonempty(config, key)
        .ok_or_else(|| format!("stored source runtime config {key:?} is required").into())
}

fn take_first_required_config(
    config: &mut BTreeMap<String, String>,
    keys: &[&str],
) -> Result<String, Box<dyn Error>> {
    for key in keys {
        if let Some(value) = remove_nonempty(config, key) {
            return Ok(value);
        }
    }
    Err(format!(
        "stored source runtime config requires one of {}",
        keys.iter()
            .map(|key| format!("{key:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .into())
}

fn take_first_config(config: &mut BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = remove_nonempty(config, key) {
            return Some(value);
        }
    }
    None
}

fn discard_config_secret(config: &mut BTreeMap<String, String>, key: &str) {
    if let Some(mut value) = config.remove(key) {
        value.zeroize();
    }
}

fn remove_nonempty(config: &mut BTreeMap<String, String>, key: &str) -> Option<String> {
    config
        .remove(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

async fn serve(
    graph: Arc<dyn AgentGraph>,
    lifecycle_projection: Option<Arc<Neo4jProjector>>,
    projection: Option<Arc<ProjectionRuntime>>,
) -> Result<(), Box<dyn Error>> {
    let source_sync_enabled = projection.is_some();
    let bind = env::var("CEREBRO_RUST_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let tenant_auth =
        TenantRequestAuth::new(required_env("CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET")?)
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let oidc = match OidcAuthenticator::from_env()
        .await
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?
    {
        OidcConfiguration::Disabled => None,
        OidcConfiguration::Configured(authenticator) => Some(authenticator),
    };
    let (actions, cerebro_device, runtime_ledger, source_sync) =
        match env::var("CEREBRO_POSTGRES_DSN") {
            Ok(connection_string) => {
                let ledger = PostgresActionLedger::connect_tls(&connection_string).await?;
                ledger.migrate().await?;
                let device = CerebroDeviceClient::connect_tls(&connection_string).await?;
                let runtime_ledger = PostgresLedger::connect_tls(&connection_string).await?;
                runtime_ledger.migrate().await?;
                (
                    Some(Arc::new(ledger) as Arc<dyn ActionAuthority>),
                    Some(device),
                    Some(Arc::new(runtime_ledger)),
                    source_sync_enabled.then(|| {
                        Arc::new(source_runtime_sync::EnvironmentSourceRuntimeSync)
                            as Arc<dyn source_runtime_sync::SourceRuntimeSyncAuthority>
                    }),
                )
            }
            Err(env::VarError::NotPresent) => (None, None, None, None),
            Err(error) => return Err(error.into()),
        };
    let access_approvals = access_approvals_from_env()?;
    let action_providers = ActionProviders {
        access_approvals,
        cerebro_device,
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("cerebro Rust platform listening on {bind}");
    axum::serve(
        listener,
        router_with_backend(
            graph,
            lifecycle_projection,
            load_catalog_summary().ok(),
            PlatformStores {
                projection,
                runtime_ledger,
                source_sync,
            },
            ActionBackends {
                actions,
                providers: action_providers,
            },
            tenant_auth,
            oidc,
        )
        .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
fn router(graph: OrganizationalGraph) -> Router {
    router_with_backend(
        Arc::new(MemoryAgentGraph::new(graph)),
        None,
        None,
        PlatformStores::default(),
        ActionBackends::default(),
        TenantRequestAuth::new("test-organizational-graph-secret-32-bytes".to_owned()).unwrap(),
        None,
    )
}

fn router_with_backend(
    graph: Arc<dyn AgentGraph>,
    lifecycle_projection: Option<Arc<Neo4jProjector>>,
    catalog_summary: Option<CatalogSummary>,
    stores: PlatformStores,
    action_backends: ActionBackends,
    tenant_auth: TenantRequestAuth,
    oidc: Option<OidcAuthenticator>,
) -> Router {
    let PlatformStores {
        projection,
        runtime_ledger,
        source_sync,
    } = stores;
    let platform_metrics = PlatformMetrics::default();
    let connect = rpc::router(
        graph.clone(),
        lifecycle_projection.clone(),
        catalog_summary.clone(),
        tenant_auth.clone(),
    );
    let protected = Router::new()
        .route(
            "/platform/graph/neighborhood",
            get(product_neighborhood_route),
        )
        .route("/v1/entities/{entity_id}", get(get_entity))
        .route("/v1/assertions/{assertion_id}", get(explain_assertion))
        .route("/v1/graph/search", post(search))
        .route("/v1/graph/expand", post(expand))
        .route("/v1/graph/expand-batch", post(expand_batch))
        .route("/v1/graph/paths", post(find_paths))
        .route("/v1/graph/provenance", get(graph_provenance_route))
        .route("/platform/graph/provenance", get(graph_provenance_route))
        .route("/v1/security/lifecycle", get(security_lifecycle))
        .route(
            "/v1/ask-queries",
            get(ask_queries::list_ask_queries).post(ask_queries::create_ask_query),
        )
        .route(
            "/v1/ask-queries/{query_id}",
            patch(ask_queries::update_ask_query).delete(ask_queries::delete_ask_query),
        )
        .route("/v1/source-runtimes", get(list_source_runtimes))
        .route("/v1/source-runtimes/health", get(source_runtime_health))
        .route("/v1/source-runtimes/freshness", get(runtime_freshness))
        .route(
            "/v1/source-runtimes/{runtime_id}",
            get(get_source_runtime).put(put_source_runtime),
        )
        .route(
            "/v1/source-runtimes/{runtime_id}/sync",
            post(sync_source_runtime),
        )
        .route(
            "/v1/source-runtimes/{runtime_id}/invalid-events",
            get(list_source_runtime_invalid_events),
        )
        .route("/v1/audit-events", get(list_audit_events))
        .route("/v1/identity/orgs", get(list_identity_organizations))
        .route("/v1/identity/users", get(list_identity_users))
        .route(
            "/v1/projections/legacy-deltas",
            post(record_legacy_projection),
        )
        .route(
            "/v1/projections/collections",
            post(record_source_collection),
        )
        .route(
            "/v1/projections/collections/{collection_id}",
            get(get_source_collection),
        )
        .route("/v1/projections/authority", get(projection_authority));
    let protected = if let Some(oidc) = oidc {
        protected
            .route("/v1/me", get(current_user))
            .route("/v1/finding-validations", post(record_finding_validation))
            .route(
                "/v1/finding-validations/{receipt_digest}",
                get(get_finding_validation),
            )
            .route("/v1/action-definitions", get(list_action_definitions))
            .route("/v1/policy-definitions", get(list_policy_definitions))
            .route("/v1/action-dispatches", get(list_action_dispatches))
            .route(
                "/v1/action-reconciliation-runs",
                post(run_action_reconciliation),
            )
            .route(
                "/v1/action-dispatches/{operation_id}",
                get(get_action_dispatch),
            )
            .route("/v1/actions", get(list_actions).post(propose_action))
            .route("/v1/actions/{operation_id}", get(get_action))
            .route(
                "/v1/actions/{operation_id}/history",
                get(get_action_history),
            )
            .route(
                "/v1/actions/{operation_id}/commands",
                post(transition_action_route),
            )
            .route(
                "/v1/actions/{operation_id}/provider-observation",
                post(observe_action_provider_route),
            )
            .route_layer(middleware::from_fn_with_state(oidc, authenticate_oidc))
    } else {
        protected.route_layer(middleware::from_fn_with_state(
            tenant_auth,
            authenticate_tenant,
        ))
    };
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .route("/v1/sources/summary", get(source_summary))
        .merge(protected)
        .fallback_service(connect.into_axum_service())
        .with_state(AppState {
            action_providers: action_backends.providers,
            actions: action_backends.actions,
            graph,
            lifecycle_projection,
            catalog_summary,
            projection,
            runtime_ledger,
            source_sync,
            metrics: platform_metrics.clone(),
        })
        .layer(middleware::from_fn_with_state(
            ratelimit::EdgeRateLimit::from_env()
                .unwrap_or_else(|error| panic!("invalid rate limit configuration: {error}")),
            ratelimit::enforce,
        ))
        .layer(middleware::from_fn_with_state(
            platform_metrics,
            record_request,
        ))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render().await,
    )
}

async fn projection_authority(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<ProjectionAuthorityQuery>,
) -> Result<
    Json<cerebro_organizational_store::ProjectionAuthorityRecord>,
    (StatusCode, Json<ErrorResponse>),
> {
    let runtime = state.projection.ok_or_else(|| {
        service_unavailable(
            "projection_runtime_unavailable",
            "The organizational projection runtime is not configured.",
        )
    })?;
    let tenant_id = authorized_tenant(&authenticated, query.tenant_id)?;
    runtime
        .authority
        .projection_authority(tenant_id.as_str(), &query.source_id, &query.family_id)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn record_legacy_projection(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<LegacyProjectionRequest>,
) -> Result<Json<LegacyProjectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let runtime = state.projection.ok_or_else(|| {
        service_unavailable(
            "projection_runtime_unavailable",
            "The organizational projection runtime is not configured.",
        )
    })?;
    if !request.append_log_committed {
        return Err(bad_request(
            "append_log_required",
            "The source event must be committed to the append log before recording its legacy projection.",
        ));
    }
    if request.observed_at_unix_ms <= 0 {
        return Err(bad_request(
            "invalid_observed_at",
            "observed_at_unix_ms must be positive.",
        ));
    }
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id.clone())?;
    validate_legacy_projection(&tenant_id, &request)?;
    runtime
        .record_legacy_projection(&tenant_id, &request)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn record_source_collection(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<SourceCollectionRequest>,
) -> Result<Json<SourceCollectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let runtime = state.projection.ok_or_else(|| {
        service_unavailable(
            "projection_runtime_unavailable",
            "The organizational projection runtime is not configured.",
        )
    })?;
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id.clone())?;
    validate_source_collection(&request)?;
    runtime
        .record_source_collection(&tenant_id, &request)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn get_source_collection(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(collection_id): Path<String>,
    Query(query): Query<SourceCollectionQuery>,
) -> Result<Json<SourceCollectionRequest>, (StatusCode, Json<ErrorResponse>)> {
    let runtime = state.projection.ok_or_else(|| {
        service_unavailable(
            "projection_runtime_unavailable",
            "The organizational projection runtime is not configured.",
        )
    })?;
    let tenant_id = authorized_tenant(&authenticated, query.tenant_id)?;
    let source_runtime_id = SourceRuntimeId::parse(query.source_runtime_id).map_err(model_error)?;
    let collection_id = CollectionId::parse(collection_id).map_err(model_error)?;
    runtime
        .source_collection(&tenant_id, &source_runtime_id, &collection_id)
        .await
        .map_err(store_error)?
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    code: "source_collection_not_found",
                    message: "The source collection receipt was not found.".to_owned(),
                }),
            )
        })
}

fn validate_source_collection(
    request: &SourceCollectionRequest,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    CollectionId::parse(request.collection_id.clone()).map_err(model_error)?;
    SourceRuntimeId::parse(request.source_runtime_id.clone()).map_err(model_error)?;
    if request.source_id.trim().is_empty() {
        return Err(bad_request(
            "invalid_source_collection",
            "source_id is required.",
        ));
    }
    if request.started_at_unix_ms <= 0 || request.completed_at_unix_ms < request.started_at_unix_ms
    {
        return Err(bad_request(
            "invalid_source_collection_time",
            "Collection times must be positive and completed_at_unix_ms cannot precede started_at_unix_ms.",
        ));
    }
    match request.status.as_str() {
        "complete" if !request.incompleteness_reasons.is_empty() => {
            return Err(bad_request(
                "invalid_source_collection_status",
                "A complete collection cannot contain incompleteness reasons.",
            ));
        }
        "incomplete" if request.incompleteness_reasons.is_empty() => {
            return Err(bad_request(
                "invalid_source_collection_status",
                "An incomplete collection must contain at least one reason.",
            ));
        }
        "complete" | "incomplete" => {}
        _ => {
            return Err(bad_request(
                "invalid_source_collection_status",
                "status must be complete or incomplete.",
            ));
        }
    }
    if request
        .records_accepted
        .saturating_add(request.records_rejected)
        > request.records_scanned
    {
        return Err(bad_request(
            "invalid_source_collection_counts",
            "Accepted and rejected records cannot exceed scanned records.",
        ));
    }
    for values in [
        &request.incompleteness_reasons,
        &request.expected_family_ids,
        &request.observed_family_ids,
    ] {
        if values.len() > 10_000
            || values.iter().any(|value| value.trim().is_empty())
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(bad_request(
                "invalid_source_collection_values",
                "Collection reason and family lists must be non-empty, unique, sorted, and bounded.",
            ));
        }
    }
    Ok(())
}

fn validate_legacy_projection(
    tenant_id: &TenantId,
    request: &LegacyProjectionRequest,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    SourceRuntimeId::parse(request.source_runtime_id.clone()).map_err(model_error)?;
    ObservationId::parse(request.event_id.clone()).map_err(model_error)?;
    let source_id = request.source_id.trim();
    let family_id = request.family_id.trim();
    if source_id.is_empty() || family_id.is_empty() {
        return Err(bad_request(
            "invalid_legacy_projection",
            "source_id and family_id are required.",
        ));
    }
    let record_count = request
        .delta
        .entities
        .len()
        .saturating_add(request.delta.links.len())
        .saturating_add(request.delta.entity_retractions.len())
        .saturating_add(request.delta.link_retractions.len())
        .saturating_add(request.delta.cleanup_requests.len());
    if record_count > MAX_LEGACY_DELTA_RECORDS {
        return Err(bad_request(
            "legacy_projection_too_large",
            format!(
                "A legacy projection delta cannot contain more than {MAX_LEGACY_DELTA_RECORDS} records."
            ),
        ));
    }
    let expected_tenant = tenant_id.as_str();
    let expected_runtime = request.source_runtime_id.trim();
    for entity in &request.delta.entities {
        if entity.tenant_id.trim() != expected_tenant
            || !valid_legacy_application_workspace_id(&entity.application_workspace_id)
            || entity.source_id.trim() != source_id
            || entity.runtime_id.trim() != expected_runtime
            || entity.urn.trim().is_empty()
            || entity.entity_type.trim().is_empty()
            || !legacy_urn_matches_tenant(expected_tenant, &entity.urn)
        {
            return Err(bad_request(
                "legacy_projection_scope_mismatch",
                "Every projected entity must match the request tenant, source, and runtime.",
            ));
        }
    }
    for link in request
        .delta
        .links
        .iter()
        .chain(request.delta.link_retractions.iter())
    {
        if link.tenant_id.trim() != expected_tenant
            || !valid_legacy_application_workspace_id(&link.application_workspace_id)
            || link.source_id.trim() != source_id
            || link.runtime_id.trim() != expected_runtime
            || link.relation.trim().is_empty()
            || !legacy_urn_matches_tenant(expected_tenant, &link.from_urn)
            || !legacy_urn_matches_tenant(expected_tenant, &link.to_urn)
        {
            return Err(bad_request(
                "legacy_projection_scope_mismatch",
                "Every projected link must match the request tenant, source, and runtime.",
            ));
        }
    }
    if request
        .delta
        .entity_retractions
        .iter()
        .any(|urn| !legacy_urn_matches_tenant(expected_tenant, urn))
    {
        return Err(bad_request(
            "legacy_projection_scope_mismatch",
            "Every entity retraction must match the request tenant.",
        ));
    }
    for cleanup in &request.delta.cleanup_requests {
        if cleanup.tenant_id.trim() != expected_tenant
            || cleanup.source_id.trim() != source_id
            || cleanup.runtime_id.trim() != expected_runtime
            || cleanup
                .urn_prefixes
                .iter()
                .any(|urn| !legacy_urn_matches_tenant(expected_tenant, urn))
        {
            return Err(bad_request(
                "legacy_projection_scope_mismatch",
                "Every cleanup request must match the request tenant, source, and runtime.",
            ));
        }
    }
    Ok(())
}

fn valid_legacy_application_workspace_id(value: &str) -> bool {
    value.is_empty()
        || (value.trim() == value
            && value.len() <= 128
            && value != "*"
            && !value.contains(',')
            && !value.chars().any(char::is_control))
}

fn legacy_urn_matches_tenant(tenant_id: &str, value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && (!value.starts_with("urn:cerebro:")
            || value.starts_with(&format!("urn:cerebro:{tenant_id}:")))
}

fn json_digest(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("serializing a JSON value cannot fail");
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        runtime: "rust-organizational-platform",
    })
}

async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.graph.health().await.map_err(context_error)?;
    if let Some(actions) = state.actions.as_ref() {
        actions.health().await.map_err(action_store_error)?;
    }
    Ok(health().await)
}

async fn source_summary(
    State(state): State<AppState>,
) -> Result<Json<CatalogSummary>, (StatusCode, Json<ErrorResponse>)> {
    state.catalog_summary.clone().map(Json).ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "source_catalog_unavailable",
                message: "The source catalog is not loaded.".to_owned(),
            }),
        )
    })
}

async fn current_user(
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Json<oidc::CurrentUserResponse> {
    Json(identity.current_user_response())
}

async fn put_source_runtime(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(runtime_id): Path<String>,
    Json(request): Json<source_runtime_registry::PutSourceRuntimeRequest>,
) -> Result<Json<source_runtime_registry::SourceRuntimeResponse>, (StatusCode, Json<ErrorResponse>)>
{
    use source_runtime_registry::SourceRuntimeRegistryAuthority;

    let ledger = state
        .runtime_ledger
        .ok_or_else(source_runtime_registry_unavailable)?;
    source_runtime_registry::PostgresSourceRuntimeRegistry::new(ledger)
        .put(&authenticated.0, &runtime_id, request)
        .await
        .map(Json)
        .map_err(source_runtime_registry_error)
}

async fn get_source_runtime(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(runtime_id): Path<String>,
) -> Result<Json<source_runtime_registry::SourceRuntimeResponse>, (StatusCode, Json<ErrorResponse>)>
{
    use source_runtime_registry::SourceRuntimeRegistryAuthority;

    let ledger = state
        .runtime_ledger
        .ok_or_else(source_runtime_registry_unavailable)?;
    source_runtime_registry::PostgresSourceRuntimeRegistry::new(ledger)
        .get(&authenticated.0, &runtime_id)
        .await
        .map(Json)
        .map_err(source_runtime_registry_error)
}

async fn list_source_runtimes(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<source_runtime_registry::SourceRuntimeListQuery>,
) -> Result<
    Json<source_runtime_registry::SourceRuntimeListResponse>,
    (StatusCode, Json<ErrorResponse>),
> {
    use source_runtime_registry::SourceRuntimeRegistryAuthority;

    let ledger = state
        .runtime_ledger
        .ok_or_else(source_runtime_registry_unavailable)?;
    source_runtime_registry::PostgresSourceRuntimeRegistry::new(ledger)
        .list(&authenticated.0, query)
        .await
        .map(Json)
        .map_err(source_runtime_registry_error)
}

fn source_runtime_registry_unavailable() -> (StatusCode, Json<ErrorResponse>) {
    service_unavailable(
        "source_runtime_registry_unavailable",
        "The Rust source-runtime registry is not configured.",
    )
}

fn source_runtime_registry_error(
    error: source_runtime_registry::SourceRuntimeRegistryFailure,
) -> (StatusCode, Json<ErrorResponse>) {
    use source_runtime_registry::SourceRuntimeRegistryFailureKind;

    eprintln!("Rust source-runtime registry request failed: {error}");
    match error.kind() {
        SourceRuntimeRegistryFailureKind::InvalidRequest => bad_request(
            "invalid_source_runtime",
            "The source runtime definition or list filter is invalid.",
        ),
        SourceRuntimeRegistryFailureKind::TenantMismatch => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                code: "source_runtime_tenant_mismatch",
                message: "The source runtime tenant does not match the authenticated tenant."
                    .to_owned(),
            }),
        ),
        SourceRuntimeRegistryFailureKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "source_runtime_not_found",
                message: "The source runtime was not found for this tenant.".to_owned(),
            }),
        ),
        SourceRuntimeRegistryFailureKind::Conflict => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "source_runtime_registry_conflict",
                message: "The source runtime changed or started syncing. Retry the update."
                    .to_owned(),
            }),
        ),
        SourceRuntimeRegistryFailureKind::RuntimeUnavailable => {
            source_runtime_registry_unavailable()
        }
    }
}

async fn list_source_runtime_invalid_events(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(runtime_id): Path<String>,
) -> Result<
    Json<source_runtime_invalid_events::SourceRuntimeInvalidEventsResponse>,
    (StatusCode, Json<ErrorResponse>),
> {
    let ledger = state.runtime_ledger.ok_or_else(|| {
        service_unavailable(
            "source_runtime_invalid_events_unavailable",
            "The Rust source-runtime ledger is not configured.",
        )
    })?;
    source_runtime_invalid_events::list_source_runtime_invalid_events(
        ledger,
        &authenticated.0,
        &runtime_id,
    )
    .await
    .map(Json)
    .map_err(source_runtime_invalid_events_error)
}

fn source_runtime_invalid_events_error(
    error: source_runtime_invalid_events::SourceRuntimeInvalidEventsFailure,
) -> (StatusCode, Json<ErrorResponse>) {
    use source_runtime_invalid_events::SourceRuntimeInvalidEventsFailureKind;

    eprintln!("Rust source-runtime invalid-event request failed: {error}");
    match error.kind() {
        SourceRuntimeInvalidEventsFailureKind::InvalidRequest => bad_request(
            "invalid_source_runtime",
            "The source runtime identifier is invalid.",
        ),
        SourceRuntimeInvalidEventsFailureKind::RuntimeUnavailable => service_unavailable(
            "source_runtime_invalid_events_unavailable",
            "Source-runtime invalid-event evidence is temporarily unavailable.",
        ),
    }
}

/// Serves the persisted identity organizations for the authenticated tenant.
/// Auth-config-derived organizations remain on the Go route until the auth
/// pipeline moves; `meta.configured` is always zero here.
async fn list_identity_organizations(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(params): Query<identity_directory::IdentityDirectoryRequestParams>,
) -> Result<Json<identity_directory::ListOrganizationsResponse>, (StatusCode, Json<ErrorResponse>)>
{
    let ledger = state.runtime_ledger.clone().ok_or_else(|| {
        service_unavailable(
            "identity_directory_unavailable",
            "The Rust identity directory store is not configured.",
        )
    })?;
    let tenant_id = match params
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|requested| !requested.is_empty())
    {
        Some(requested) => authorized_tenant(&authenticated, requested.to_owned())?,
        None => authenticated.0.clone(),
    };
    let query = identity_directory::store_query(&params, tenant_id.as_str(), false);
    let organizations = ledger
        .list_identity_organizations(&query)
        .await
        .map_err(|error| {
            eprintln!("Rust identity organization read failed: {error}");
            service_unavailable(
                "identity_directory_unavailable",
                "Identity organizations are temporarily unavailable.",
            )
        })?;
    Ok(Json(identity_directory::organizations_response(
        tenant_id.as_str(),
        query.limit,
        organizations,
    )))
}

/// Serves the persisted identity users for the authenticated tenant; see
/// [`list_identity_organizations`] for the configured-identity scope note.
async fn list_identity_users(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(params): Query<identity_directory::IdentityDirectoryRequestParams>,
) -> Result<Json<identity_directory::ListUsersResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ledger = state.runtime_ledger.clone().ok_or_else(|| {
        service_unavailable(
            "identity_directory_unavailable",
            "The Rust identity directory store is not configured.",
        )
    })?;
    let tenant_id = match params
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|requested| !requested.is_empty())
    {
        Some(requested) => authorized_tenant(&authenticated, requested.to_owned())?,
        None => authenticated.0.clone(),
    };
    let query = identity_directory::store_query(&params, tenant_id.as_str(), true);
    let users = ledger.list_identity_users(&query).await.map_err(|error| {
        eprintln!("Rust identity user read failed: {error}");
        service_unavailable(
            "identity_directory_unavailable",
            "Identity users are temporarily unavailable.",
        )
    })?;
    Ok(Json(identity_directory::users_response(
        tenant_id.as_str(),
        query.org_id.as_str(),
        query.limit,
        users,
    )))
}

/// Native REST parity route for `GET /platform/audit-events`: one bounded,
/// tenant-scoped, deterministically paged read of the projected audit-event
/// allowlist. Cursor contents never authorize anything; every page
/// re-authorizes the tenant through the transport layer.
async fn list_audit_events(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(params): Query<audit_events::AuditEventsRequestParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let ledger = state.runtime_ledger.clone().ok_or_else(|| {
        service_unavailable(
            "audit_events_unavailable",
            "The Rust audit-event store is not configured.",
        )
    })?;
    let tenant_id = match params
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|requested| !requested.is_empty())
    {
        Some(requested) => authorized_tenant(&authenticated, requested.to_owned())?,
        None => authenticated.0.clone(),
    };
    let query = audit_events::parse_request(&params, tenant_id.as_str(), OffsetDateTime::now_utc())
        .map_err(audit_events_error)?;
    let scope = audit_events::store_query(&query).map_err(audit_events_error)?;
    let page = ledger.list_audit_events(&scope).await.map_err(|error| {
        eprintln!("Rust audit-event read failed: {error}");
        service_unavailable(
            "audit_events_unavailable",
            "Audit events are temporarily unavailable.",
        )
    })?;
    let response = audit_events::build_page(&query, &page).map_err(audit_events_error)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "private, no-store")],
        Json(response),
    ))
}

fn audit_events_error(
    error: audit_events::AuditEventsFailure,
) -> (StatusCode, Json<ErrorResponse>) {
    use audit_events::AuditEventsFailureKind;

    match error.kind() {
        AuditEventsFailureKind::InvalidRequest => {
            bad_request("invalid_audit_event_query", error.to_string())
        }
        AuditEventsFailureKind::Unavailable => {
            eprintln!("Rust audit-event response failed: {error}");
            service_unavailable(
                "audit_events_unavailable",
                "Audit events are temporarily unavailable.",
            )
        }
    }
}

async fn sync_source_runtime(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(runtime_id): Path<String>,
) -> Result<Json<source_runtime_sync::SourceRuntimeSyncReceipt>, (StatusCode, Json<ErrorResponse>)>
{
    let source_sync = state.source_sync.as_ref().ok_or_else(|| {
        service_unavailable(
            "source_runtime_sync_unavailable",
            "The Rust source-runtime sync service is not configured.",
        )
    })?;
    source_sync
        .sync(&authenticated.0, &runtime_id)
        .await
        .map(Json)
        .map_err(source_runtime_sync_error)
}

fn source_runtime_sync_error(
    error: source_runtime_sync::SourceRuntimeSyncFailure,
) -> (StatusCode, Json<ErrorResponse>) {
    use source_runtime_sync::SourceRuntimeSyncFailureKind;

    eprintln!("Rust source-runtime sync failed: {error}");
    match error.kind() {
        SourceRuntimeSyncFailureKind::InvalidRequest => bad_request(
            "invalid_source_runtime_sync",
            "The source runtime definition or sync request is invalid.",
        ),
        SourceRuntimeSyncFailureKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "source_runtime_not_found",
                message: "The source runtime was not found for this tenant.".to_owned(),
            }),
        ),
        SourceRuntimeSyncFailureKind::Conflict => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "source_runtime_sync_conflict",
                message: "The source runtime is already syncing or lost its lease.".to_owned(),
            }),
        ),
        SourceRuntimeSyncFailureKind::ProviderUnavailable => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                code: "source_provider_unavailable",
                message: "The provider request did not complete.".to_owned(),
            }),
        ),
        SourceRuntimeSyncFailureKind::RuntimeUnavailable => service_unavailable(
            "source_runtime_sync_unavailable",
            "The source-runtime ledger or graph projection is unavailable.",
        ),
    }
}

async fn source_runtime_health(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<SourceRuntimeHealthQuery>,
) -> Result<Json<RustSourceRuntimeHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(500);
    if limit == 0 || limit > 500 {
        return Err(bad_request(
            "invalid_source_runtime_limit",
            "Source runtime health limit must be between 1 and 500.",
        ));
    }
    let ledger = state.runtime_ledger.as_ref().ok_or_else(|| {
        service_unavailable(
            "source_runtime_health_unavailable",
            "The Rust source-runtime ledger is not configured.",
        )
    })?;
    let graph = state.lifecycle_projection.as_ref().ok_or_else(|| {
        service_unavailable(
            "source_runtime_health_unavailable",
            "The Rust graph projection is not configured.",
        )
    })?;
    let source_id = query.source_id.as_deref().unwrap_or_default().trim();
    let records = ledger
        .source_runtime_observations(authenticated.0.as_str(), source_id, limit)
        .await
        .map_err(|_| {
            service_unavailable(
                "source_runtime_health_unavailable",
                "Source-runtime evidence is temporarily unavailable.",
            )
        })?;
    let runtime_ids = records
        .iter()
        .map(|record| record.runtime_id.clone())
        .collect::<Vec<_>>();
    let graph_records = graph
        .source_runtime_graph_observations(&runtime_ids)
        .await
        .map_err(|_| {
            service_unavailable(
                "source_runtime_health_unavailable",
                "Graph-ingest evidence is temporarily unavailable.",
            )
        })?
        .into_iter()
        .map(|record| (record.runtime_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let generated_at = OffsetDateTime::now_utc();
    let runtimes = records
        .into_iter()
        .map(|record| {
            let graph_record = graph_records.get(&record.runtime_id).cloned();
            rust_source_runtime_health_view(record, graph_record, generated_at)
        })
        .collect::<Vec<_>>();
    let source_summaries = rust_source_runtime_health_summaries(&runtimes);
    let generated_at = generated_at.format(&Rfc3339).map_err(|_| {
        service_unavailable(
            "source_runtime_health_unavailable",
            "Source-runtime health time is unavailable.",
        )
    })?;
    Ok(Json(RustSourceRuntimeHealthResponse {
        generated_at,
        runtimes,
        source_summaries,
    }))
}

async fn runtime_freshness(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<SourceRuntimeHealthQuery>,
) -> Result<Json<RustRuntimeFreshnessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(500);
    if limit == 0 || limit > 500 {
        return Err(bad_request(
            "invalid_source_runtime_limit",
            "Source runtime freshness limit must be between 1 and 500.",
        ));
    }
    let ledger = state.runtime_ledger.as_ref().ok_or_else(|| {
        service_unavailable(
            "source_runtime_freshness_unavailable",
            "The Rust source-runtime ledger is not configured.",
        )
    })?;
    let graph = state.lifecycle_projection.as_ref().ok_or_else(|| {
        service_unavailable(
            "source_runtime_freshness_unavailable",
            "The Rust graph projection is not configured.",
        )
    })?;
    let source_id = query.source_id.as_deref().unwrap_or_default().trim();
    let records = ledger
        .source_runtime_observations(authenticated.0.as_str(), source_id, limit)
        .await
        .map_err(|_| {
            service_unavailable(
                "source_runtime_freshness_unavailable",
                "Source-runtime evidence is temporarily unavailable.",
            )
        })?;
    let runtime_ids = records
        .iter()
        .map(|record| record.runtime_id.clone())
        .collect::<Vec<_>>();
    let graph_records = graph
        .source_runtime_graph_observations(&runtime_ids)
        .await
        .map_err(|_| {
            service_unavailable(
                "source_runtime_freshness_unavailable",
                "Graph-ingest evidence is temporarily unavailable.",
            )
        })?
        .into_iter()
        .map(|record| (record.runtime_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let now = OffsetDateTime::now_utc();
    let generated_at = now.format(&Rfc3339).map_err(|_| {
        service_unavailable(
            "source_runtime_freshness_unavailable",
            "Source-runtime freshness time is unavailable.",
        )
    })?;
    let runtimes = records
        .into_iter()
        .map(|record| {
            let graph_record = graph_records.get(&record.runtime_id).cloned();
            rust_runtime_freshness_record(
                record,
                graph_record,
                authenticated.0.as_str(),
                now,
                generated_at.clone(),
            )
        })
        .collect::<Vec<_>>();
    let status = runtime_freshness_status(runtimes.iter().map(|record| record.freshness_state));
    let digests = runtimes
        .iter()
        .map(|record| RuntimeFreshnessDigest {
            source_id: &record.source_id,
            freshness_state: record.freshness_state,
            backfill_eligible: record.backfill_eligible,
        })
        .collect::<Vec<_>>();
    let summaries = summarize_runtime_freshness(&digests);
    Ok(Json(RustRuntimeFreshnessResponse {
        generated_at,
        status,
        runtimes,
        summaries,
    }))
}

fn rust_runtime_freshness_record(
    record: SourceRuntimeObservation,
    graph: Option<SourceRuntimeGraphObservation>,
    tenant_id: &str,
    now: OffsetDateTime,
    generated_at: String,
) -> RustRuntimeFreshnessRecord {
    let source_status = rust_source_status(&record, now);
    let graph_state = rust_graph_state(graph.as_ref(), record.stale_after_seconds, now);
    let finding_state = rust_finding_state(record.latest_finding_evaluation_status.as_deref());
    let schedule_context_configured =
        record.stale_after_seconds.is_some() || record.expected_cadence_seconds.is_some();
    let freshness = evaluate_runtime_freshness(RuntimeFreshnessEvidence {
        enabled_state: &record.enabled_state,
        source_status,
        last_failure_category: record.last_failure_category.as_deref().unwrap_or_default(),
        graph_ingest_state: graph_state,
        finding_evaluation_state: finding_state,
        schedule_context_configured,
    });
    let sync_lag_seconds = rust_lag_seconds(
        record
            .last_synced_at
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value.trim(), &Rfc3339).ok()),
        now,
    );
    let graph_lag_seconds = rust_lag_seconds(graph.as_ref().and_then(rust_graph_observed_at), now);
    RustRuntimeFreshnessRecord {
        runtime_id: record.runtime_id,
        source_id: record.source_id,
        tenant_id: tenant_id.to_owned(),
        lifecycle_state: freshness.lifecycle_state,
        schedule_state: freshness.schedule_state,
        freshness_state: freshness.freshness_state,
        source_sync_state: freshness.source_sync_state,
        graph_ingest_state: freshness.graph_ingest_state,
        finding_evaluation_state: freshness.finding_evaluation_state,
        failure_class: freshness.failure_class,
        failure_reason: freshness.failure_reason,
        backfill_eligible: freshness.backfill_eligible,
        backfill_eligibility_reason: freshness.backfill_eligibility_reason,
        last_synced_at: record.last_synced_at,
        sync_lag_seconds,
        latest_graph_run: graph,
        graph_lag_seconds,
        latest_finding_evaluation: record
            .latest_finding_evaluation_status
            .map(|status| RustFindingEvaluationHealthView { status }),
        expected_cadence_seconds: record.expected_cadence_seconds,
        stale_after_seconds: record.stale_after_seconds,
        generated_at,
        next_action: freshness.next_action,
        recommended_workflow: freshness.recommended_workflow,
        cursor_pending: record.cursor_pending,
        checkpoint_cursor_present: record.checkpoint_cursor_present,
        schedule_context_configured,
    }
}

fn rust_lag_seconds(observed: Option<OffsetDateTime>, now: OffsetDateTime) -> Option<i64> {
    observed.map(|observed| (now - observed).whole_seconds().max(0))
}

fn rust_graph_observed_at(graph: &SourceRuntimeGraphObservation) -> Option<OffsetDateTime> {
    [&graph.finished_at, &graph.started_at]
        .into_iter()
        .find_map(|value| OffsetDateTime::parse(value.trim(), &Rfc3339).ok())
}

fn rust_source_runtime_health_view(
    record: SourceRuntimeObservation,
    graph: Option<SourceRuntimeGraphObservation>,
    now: OffsetDateTime,
) -> RustSourceRuntimeHealthView {
    let source_status = rust_source_status(&record, now);
    let graph_state = rust_graph_state(graph.as_ref(), record.stale_after_seconds, now);
    let finding_state = rust_finding_state(record.latest_finding_evaluation_status.as_deref());
    let contract_probe_state = rust_contract_probe_state(&record).to_owned();
    let schedule_context_configured =
        record.stale_after_seconds.is_some() || record.expected_cadence_seconds.is_some();
    let decision = evaluate_runtime_readiness(RuntimeHealthEvidence {
        enabled_state: &record.enabled_state,
        source_status,
        graph_state,
        cursor_pending: record.cursor_pending,
        schedule_context_configured,
        contract_probe_state: &contract_probe_state,
        finding_evaluation_state: finding_state,
    });
    RustSourceRuntimeHealthView {
        runtime_id: record.runtime_id,
        source_id: record.source_id,
        enabled_state: record.enabled_state,
        status: source_status.to_owned(),
        readiness: decision.readiness.as_str().to_owned(),
        next_action: decision.next_action.as_str().to_owned(),
        last_synced_at: record.last_synced_at,
        stale_after_seconds: record.stale_after_seconds,
        expected_cadence_seconds: record.expected_cadence_seconds,
        cursor_pending: record.cursor_pending,
        checkpoint_cursor_present: record.checkpoint_cursor_present,
        schedule_context_configured,
        contract_probe_state,
        graph_state: graph_state.to_owned(),
        finding_evaluation_state: finding_state.to_owned(),
        latest_graph_run: graph,
        latest_finding_evaluation: record
            .latest_finding_evaluation_status
            .map(|status| RustFindingEvaluationHealthView { status }),
    }
}

fn rust_source_status(record: &SourceRuntimeObservation, now: OffsetDateTime) -> &'static str {
    if record.last_failure_category.is_some() {
        return "failing";
    }
    let Some(last_sync) = record
        .last_synced_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
    else {
        return "unknown";
    };
    if record.stale_after_seconds.is_some_and(|threshold| {
        i64::try_from(threshold)
            .is_ok_and(|threshold| (now - last_sync).whole_seconds().max(0) > threshold)
    }) {
        "stale"
    } else {
        "healthy"
    }
}

fn rust_graph_state(
    graph: Option<&SourceRuntimeGraphObservation>,
    stale_after_seconds: Option<u64>,
    now: OffsetDateTime,
) -> &'static str {
    let Some(graph) = graph else {
        return "not_observed";
    };
    let status = graph.status.trim().to_ascii_lowercase();
    if status.contains("fail") || status.contains("error") || status.contains("cancel") {
        return "failed";
    }
    if status.contains("running") || status.contains("pending") {
        return "running";
    }
    if !graph.checkpoint_cursor.trim().is_empty() || graph.checkpoint_complete == Some(false) {
        return "behind";
    }
    let graph_time = rust_graph_observed_at(graph);
    if stale_after_seconds
        .zip(graph_time)
        .is_some_and(|(threshold, observed)| {
            i64::try_from(threshold)
                .is_ok_and(|threshold| (now - observed).whole_seconds().max(0) > threshold)
        })
    {
        return "behind";
    }
    "current"
}

fn rust_finding_state(status: Option<&str>) -> &'static str {
    let Some(status) = status else {
        return "not_observed";
    };
    let status = status.trim().to_ascii_lowercase();
    if status.contains("fail") || status.contains("error") || status.contains("cancel") {
        "failed"
    } else if status.contains("running") || status.contains("pending") {
        "running"
    } else {
        "current"
    }
}

fn rust_contract_probe_state(record: &SourceRuntimeObservation) -> &str {
    let state = record.contract_probe_state.trim();
    if state != "unknown" {
        return state;
    }
    if record.source_id != "evidence_cas" {
        "not_configured"
    } else if record.last_synced_at.is_some() {
        "passing"
    } else {
        "unknown"
    }
}

fn rust_source_runtime_health_summaries(
    runtimes: &[RustSourceRuntimeHealthView],
) -> Vec<RustSourceRuntimeHealthSummary> {
    let mut summaries = BTreeMap::<String, RustSourceRuntimeHealthSummary>::new();
    for runtime in runtimes {
        let summary = summaries
            .entry(runtime.source_id.clone())
            .or_insert_with(|| RustSourceRuntimeHealthSummary {
                source_id: runtime.source_id.clone(),
                total: 0,
                healthy: 0,
                needs_refresh: 0,
                poor: 0,
                bad: 0,
                cursor_pending: 0,
                schedule_context_missing: 0,
                graph_current: 0,
                graph_behind: 0,
                graph_running: 0,
                graph_failed: 0,
                graph_not_observed: 0,
                graph_unknown: 0,
                latest_activity_at: None,
                readiness: "healthy".to_owned(),
                next_action: "monitor".to_owned(),
            });
        summary.total += 1;
        summary.cursor_pending += usize::from(runtime.cursor_pending);
        summary.schedule_context_missing += usize::from(!runtime.schedule_context_configured);
        match runtime.graph_state.as_str() {
            "current" => summary.graph_current += 1,
            "behind" => summary.graph_behind += 1,
            "running" => summary.graph_running += 1,
            "failed" => summary.graph_failed += 1,
            "not_observed" | "missing" => summary.graph_not_observed += 1,
            _ => summary.graph_unknown += 1,
        }
        if runtime.last_synced_at.as_ref().is_some_and(|observed| {
            summary
                .latest_activity_at
                .as_ref()
                .is_none_or(|current| observed > current)
        }) {
            summary.latest_activity_at = runtime.last_synced_at.clone();
        }
        match runtime.readiness.as_str() {
            "bad" => summary.bad += 1,
            "needs_refresh" => summary.needs_refresh += 1,
            "poor" => summary.poor += 1,
            _ => summary.healthy += 1,
        }
        let runtime_readiness = match runtime.readiness.as_str() {
            "bad" => RuntimeReadiness::Bad,
            "needs_refresh" => RuntimeReadiness::NeedsRefresh,
            "poor" => RuntimeReadiness::Poor,
            _ => RuntimeReadiness::Healthy,
        };
        let summary_readiness = match summary.readiness.as_str() {
            "bad" => RuntimeReadiness::Bad,
            "needs_refresh" => RuntimeReadiness::NeedsRefresh,
            "poor" => RuntimeReadiness::Poor,
            _ => RuntimeReadiness::Healthy,
        };
        if runtime_readiness < summary_readiness {
            summary.readiness = runtime.readiness.clone();
            summary.next_action = runtime.next_action.clone();
        }
    }
    summaries.into_values().collect()
}

async fn list_action_definitions()
-> Json<&'static [cerebro_action_catalog::ActionDefinition<'static>]> {
    Json(action_definitions())
}

async fn list_policy_definitions()
-> Json<&'static [cerebro_policy_catalog::PolicyDefinition<'static>]> {
    Json(policy_definitions())
}

async fn record_finding_validation(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Json(receipt): Json<FindingValidationReceipt>,
) -> Result<Json<FindingValidationReceipt>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, FINDING_VALIDATE_SCOPE)?;
    let actor_id = authenticated_action_actor(&identity)?;
    if receipt.tenant_id != identity.tenant || receipt.validated_by != actor_id {
        return Err(permission_denied(
            "The finding validation tenant and validator must match the signed identity.",
        ));
    }
    validate_finding_receipt(&receipt)
        .map_err(|error| bad_request("invalid_policy_definition", error.to_string()))?;
    let committed_at = current_unix_millis()?;
    action_authority(&state)?
        .record_finding_validation(receipt, committed_at)
        .await
        .map(Json)
        .map_err(finding_validation_store_error)
}

async fn get_finding_validation(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(receipt_digest): Path<String>,
) -> Result<Json<FindingValidationReceipt>, (StatusCode, Json<ErrorResponse>)> {
    let receipt_digest = ContentDigest::parse(receipt_digest)
        .map_err(|error| bad_request("invalid_finding_validation_digest", error.to_string()))?;
    action_authority(&state)?
        .get_finding_validation(&identity.tenant, &receipt_digest)
        .await
        .map(Json)
        .map_err(finding_validation_store_error)
}

async fn propose_action(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Json(proposal): Json<ActionProposal>,
) -> Result<Json<ActionOperation>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_PROPOSE_SCOPE)?;
    let actor_id = authenticated_action_actor(&identity)?;
    if proposal.tenant_id != identity.tenant || proposal.proposed_by != actor_id {
        return Err(permission_denied(
            "The Action proposal tenant and proposer must match the signed identity.",
        ));
    }
    validate_proposal(&proposal).map_err(action_catalog_error)?;
    let committed_at = current_unix_millis()?;
    action_authority(&state)?
        .propose(proposal, committed_at)
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn list_actions(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Query(query): Query<ActionListQuery>,
) -> Result<Json<ActionPage>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(25);
    if !(1..=100).contains(&limit) {
        return Err(bad_request(
            "invalid_action_query",
            "limit must be between 1 and 100.",
        ));
    }
    action_authority(&state)?
        .list(&identity.tenant, limit, query.page_token.as_deref())
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn get_action(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
) -> Result<Json<ActionOperation>, (StatusCode, Json<ErrorResponse>)> {
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    action_authority(&state)?
        .get(&identity.tenant, &operation_id)
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn get_action_history(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
) -> Result<Json<Vec<ActionEvent>>, (StatusCode, Json<ErrorResponse>)> {
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    action_authority(&state)?
        .history(&identity.tenant, &operation_id)
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn list_action_dispatches(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Query(query): Query<ActionDispatchQuery>,
) -> Result<Json<ActionDispatchPage>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_EXECUTE_SCOPE)?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(bad_request(
            "invalid_action_dispatch_query",
            "limit must be between 1 and 100.",
        ));
    }
    action_authority(&state)?
        .list_open_dispatches(&identity.tenant, limit)
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn get_action_dispatch(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
) -> Result<Json<ActionDispatch>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_EXECUTE_SCOPE)?;
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    action_authority(&state)?
        .get_dispatch(&identity.tenant, &operation_id)
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn transition_action_route(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
    Json(request): Json<ActionTransitionRequest>,
) -> Result<Json<ActionOperation>, (StatusCode, Json<ErrorResponse>)> {
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    require_action_scope(&identity, request.command.required_scope())?;
    let actor_id = authenticated_action_actor(&identity)?;
    let starts_execution = matches!(&request.command, HttpActionCommand::StartExecution { .. });
    let authority = action_authority(&state)?.clone();
    let provider = if starts_execution {
        if state.action_providers.access_approvals.is_none()
            && state.action_providers.cerebro_device.is_none()
        {
            return Err(service_unavailable(
                "action_provider_unavailable",
                "No Action provider is configured in the Rust runtime.",
            ));
        }
        let current = authority
            .get(&identity.tenant, &operation_id)
            .await
            .map_err(action_store_error)?;
        let definition =
            lookup_action(&current.proposal.action_kind).map_err(action_catalog_error)?;
        require_configured_action_provider(&state, definition.provider)?;
        Some(definition.provider)
    } else {
        None
    };
    let command = request
        .command
        .into_domain()
        .map_err(|error| bad_request("invalid_action_command", error))?;
    let committed_at = current_unix_millis()?;
    let operation = authority
        .transition(
            &identity.tenant,
            &operation_id,
            &actor_id,
            request.expected_version,
            command,
            committed_at,
        )
        .await
        .map_err(action_store_error)?;
    let Some(_provider) = provider else {
        return Ok(Json(operation));
    };

    let dispatch = authority
        .get_dispatch(&identity.tenant, &operation_id)
        .await
        .map_err(action_store_error)?;
    let provider_result = dispatch_action_provider(&state, &dispatch).await;
    if let Err(error) = &provider_result {
        eprintln!(
            "Action provider dispatch returned no receipt: operation_id={operation_id} error={error}"
        );
    }
    let observed_at = current_unix_millis()?;
    authority
        .transition(
            &identity.tenant,
            &operation_id,
            &actor_id,
            operation.version,
            provider_dispatch_command(provider_result, actor_id.clone(), observed_at),
            observed_at,
        )
        .await
        .map(Json)
        .map_err(action_store_error)
}

async fn run_action_reconciliation(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ActionReconciliationRun>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_RECONCILE_SCOPE)?;
    let actor_id = authenticated_action_actor(&identity)?;
    let authority = action_authority(&state)?.clone();
    let mut result = ActionReconciliationRun {
        claimed: 0,
        observed: 0,
        terminal: 0,
        provider_unavailable: 0,
    };
    for _ in 0..ACTION_RECONCILIATION_BATCH_LIMIT {
        let claimed_at = current_unix_millis()?;
        let lease_expires_at = claimed_at
            .checked_add(ACTION_RECONCILIATION_LEASE_MS)
            .ok_or_else(action_clock_overflow)?;
        let Some(job) = authority
            .claim_due_reconciliation(&identity.tenant, &actor_id, claimed_at, lease_expires_at)
            .await
            .map_err(action_store_error)?
        else {
            break;
        };
        result.claimed += 1;
        let external_id = job.operation.external_receipt_ref.as_ref().ok_or_else(|| {
            action_store_error(ActionStoreError::Corrupt(
                "Action reconciliation job has no provider receipt".to_owned(),
            ))
        })?;
        let receipt = observe_action_provider(&state, &job.dispatch, external_id).await;
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(_) => {
                let finished_at = current_unix_millis()?;
                let next_attempt_at = finished_at
                    .checked_add(ACTION_RECONCILIATION_POLL_DELAY_MS)
                    .ok_or_else(action_clock_overflow)?;
                authority
                    .finish_reconciliation(
                        &identity.tenant,
                        &job.operation.proposal.operation_id,
                        &actor_id,
                        job.operation.version,
                        finished_at,
                        ActionReconciliationDisposition::PollAgain {
                            next_attempt_at_unix_ms: next_attempt_at,
                        },
                    )
                    .await
                    .map_err(action_store_error)?;
                result.provider_unavailable += 1;
                continue;
            }
        };
        let previous_observation = job.operation.provider_observed_at_unix_ms.ok_or_else(|| {
            action_store_error(ActionStoreError::Corrupt(
                "Action reconciliation job has no provider observation time".to_owned(),
            ))
        })?;
        let observed_at =
            next_provider_observation_time(previous_observation, current_unix_millis()?)
                .ok_or_else(action_clock_overflow)?;
        let operation = authority
            .transition(
                &identity.tenant,
                &job.operation.proposal.operation_id,
                &actor_id,
                job.operation.version,
                receipt.observation_command(actor_id.clone(), observed_at),
                observed_at,
            )
            .await
            .map_err(action_store_error)?;
        let terminal = receipt.status.is_terminal();
        let disposition = if terminal {
            ActionReconciliationDisposition::Terminal {
                provider_status: receipt.status.as_str().to_owned(),
            }
        } else {
            ActionReconciliationDisposition::PollAgain {
                next_attempt_at_unix_ms: observed_at
                    .checked_add(ACTION_RECONCILIATION_POLL_DELAY_MS)
                    .ok_or_else(action_clock_overflow)?,
            }
        };
        authority
            .finish_reconciliation(
                &identity.tenant,
                &operation.proposal.operation_id,
                &actor_id,
                operation.version,
                observed_at,
                disposition,
            )
            .await
            .map_err(action_store_error)?;
        result.observed += 1;
        if terminal {
            result.terminal += 1;
        }
    }
    Ok(Json(result))
}

async fn observe_action_provider_route(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
) -> Result<Json<ActionOperation>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_RECONCILE_SCOPE)?;
    let actor_id = authenticated_action_actor(&identity)?;
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    if state.action_providers.access_approvals.is_none()
        && state.action_providers.cerebro_device.is_none()
    {
        return Err(service_unavailable(
            "action_provider_unavailable",
            "No Action provider is configured in the Rust runtime.",
        ));
    }
    let authority = action_authority(&state)?.clone();
    let operation = authority
        .get(&identity.tenant, &operation_id)
        .await
        .map_err(action_store_error)?;
    let external_id = operation.external_receipt_ref.as_ref().ok_or_else(|| {
        bad_request(
            "action_provider_receipt_unavailable",
            "The Action has no provider receipt to observe.",
        )
    })?;
    let previous_observation =
        require_provider_observation_time(operation.provider_observed_at_unix_ms)?;
    let dispatch = authority
        .get_dispatch(&identity.tenant, &operation_id)
        .await
        .map_err(action_store_error)?;
    require_configured_action_provider(&state, &dispatch.provider)?;
    let receipt = observe_action_provider(&state, &dispatch, external_id)
        .await
        .map_err(action_provider_error)?;
    let observed_at = next_provider_observation_time(previous_observation, current_unix_millis()?)
        .ok_or_else(|| {
            service_unavailable(
                "action_clock_unavailable",
                "The Action provider observation time cannot advance.",
            )
        })?;
    authority
        .transition(
            &identity.tenant,
            &operation_id,
            &actor_id,
            operation.version,
            receipt.observation_command(actor_id.clone(), observed_at),
            observed_at,
        )
        .await
        .map(Json)
        .map_err(action_store_error)
}

fn next_provider_observation_time(previous: u64, current: u64) -> Option<u64> {
    previous.checked_add(1).map(|minimum| current.max(minimum))
}

fn require_provider_observation_time(
    previous: Option<u64>,
) -> Result<u64, (StatusCode, Json<ErrorResponse>)> {
    previous.ok_or_else(|| {
        bad_request(
            "action_not_observable",
            "The Action was not dispatched through the observable provider path.",
        )
    })
}

fn action_clock_overflow() -> (StatusCode, Json<ErrorResponse>) {
    service_unavailable(
        "action_clock_unavailable",
        "The Action reconciliation schedule cannot advance.",
    )
}

fn require_configured_action_provider(
    state: &AppState,
    provider: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let configured = match provider {
        "access-approvals" => state.action_providers.access_approvals.is_some(),
        "cerebro-device-auth" => state.action_providers.cerebro_device.is_some(),
        _ => false,
    };
    if configured {
        Ok(())
    } else {
        Err(service_unavailable(
            "action_provider_unavailable",
            "The Action provider is not configured in the Rust runtime.",
        ))
    }
}

async fn dispatch_action_provider(
    state: &AppState,
    dispatch: &ActionDispatch,
) -> Result<ProviderReceipt, ProviderError> {
    match dispatch.provider.as_str() {
        "access-approvals" => {
            state
                .action_providers
                .access_approvals
                .as_ref()
                .ok_or(ProviderError::InvalidConfiguration("access-approvals"))?
                .dispatch(dispatch)
                .await
        }
        "cerebro-device-auth" => {
            state
                .action_providers
                .cerebro_device
                .as_ref()
                .ok_or(ProviderError::InvalidConfiguration("cerebro-device-auth"))?
                .dispatch(dispatch)
                .await
        }
        _ => Err(ProviderError::InvalidDispatch("provider")),
    }
}

async fn observe_action_provider(
    state: &AppState,
    dispatch: &ActionDispatch,
    external_id: &OpaqueId,
) -> Result<ProviderReceipt, ProviderError> {
    match dispatch.provider.as_str() {
        "access-approvals" => {
            state
                .action_providers
                .access_approvals
                .as_ref()
                .ok_or(ProviderError::ObservationUnavailable)?
                .observe(dispatch, external_id)
                .await
        }
        "cerebro-device-auth" => {
            state
                .action_providers
                .cerebro_device
                .as_ref()
                .ok_or(ProviderError::ObservationUnavailable)?
                .observe(dispatch, external_id)
                .await
        }
        _ => Err(ProviderError::ObservationUnavailable),
    }
}

fn provider_dispatch_command(
    result: Result<ProviderReceipt, ProviderError>,
    actor_id: ActorId,
    observed_at_unix_ms: u64,
) -> ActionCommand {
    match result {
        Ok(receipt) => receipt.record_command(actor_id, observed_at_unix_ms),
        Err(_) => ActionCommand::MarkOutcomeUnknown,
    }
}

fn action_provider_error(_error: ProviderError) -> (StatusCode, Json<ErrorResponse>) {
    service_unavailable(
        "action_provider_unavailable",
        "The Action provider observation is temporarily unavailable.",
    )
}

fn action_authority(
    state: &AppState,
) -> Result<&Arc<dyn ActionAuthority>, (StatusCode, Json<ErrorResponse>)> {
    state.actions.as_ref().ok_or_else(|| {
        service_unavailable(
            "action_authority_unavailable",
            "The Rust Action ledger is not configured.",
        )
    })
}

fn authenticated_action_actor(
    identity: &AuthenticatedIdentity,
) -> Result<ActorId, (StatusCode, Json<ErrorResponse>)> {
    ActorId::parse(identity.actor_id.clone()).map_err(|_| {
        permission_denied("The signed identity does not contain a valid Action actor ID.")
    })
}

fn require_action_scope(
    identity: &AuthenticatedIdentity,
    required_scope: &'static str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if identity.has_scope(required_scope) {
        Ok(())
    } else {
        Err(permission_denied(format!(
            "The signed identity does not grant {required_scope}."
        )))
    }
}

fn current_unix_millis() -> Result<u64, (StatusCode, Json<ErrorResponse>)> {
    let millis = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis).map_err(|_| {
        service_unavailable(
            "action_clock_unavailable",
            "The current Action commit time is unavailable.",
        )
    })
}

async fn get_entity(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(entity_id): Path<String>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<ContextEntity>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, query.tenant_id)?;
    let entity_id = EntityId::parse(entity_id)
        .map_err(|error| bad_request("invalid_entity_id", error.to_string()))?;
    state
        .graph
        .get(&tenant_id, &entity_id)
        .await
        .map(Json)
        .map_err(context_error)
}

async fn search(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<SearchRequest>,
) -> Result<Json<Vec<ContextEntity>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id)?;
    state
        .graph
        .search(&tenant_id, &request.query, &request.kinds, request.limit)
        .await
        .map(Json)
        .map_err(context_error)
}

#[derive(Deserialize)]
struct GraphProvenanceQuery {
    urn: Option<String>,
    root_urn: Option<String>,
}

/// Native REST parity for the Go `GET /platform/graph/provenance` route: one
/// exact-key entity read plus the pure derivation in [`graph_provenance`].
async fn graph_provenance_route(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<GraphProvenanceQuery>,
) -> Result<Json<graph_provenance::GraphProvenanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    let urn = [query.urn.as_deref(), query.root_urn.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned();
    let tenant = graph_provenance::tenant_id_from_urn(&urn).ok_or_else(|| {
        bad_request(
            "invalid_graph_request",
            "urn must be a tenant-scoped Cerebro URN.",
        )
    })?;
    let tenant_id = authorized_tenant(&authenticated, tenant.to_owned())?;
    let entity = state
        .graph
        .resolve(&tenant_id, &urn)
        .await
        .map_err(context_error)?;
    if entity.agent_key != urn {
        // `resolve` also accepts native entity IDs; provenance is exact-key
        // only, mirroring the Go `ExactAgentKey` catalog filter.
        return Err(context_error(ContextError::EntityNotFound));
    }
    Ok(Json(graph_provenance::provenance_response(
        tenant_id.as_str(),
        &entity,
    )))
}

async fn security_lifecycle(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<HttpLifecycleQuery>,
) -> Result<Json<cerebro_security_lifecycle::QueryResult>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authenticated.0;
    if query.authority_id.is_some() != query.stable_locator.is_some()
        || (query.authority_id.is_some() && query.subject_kind.is_none())
    {
        return Err(bad_request(
            "invalid_security_lifecycle_locator",
            "authority_id, stable_locator, and subject_kind are required together.",
        ));
    }
    let lifecycle_query: LifecycleQuery = query.into();
    if let Some(projection) = state.lifecycle_projection.as_ref() {
        let graph_revision = state
            .graph
            .revision(&tenant_id)
            .await
            .map_err(context_error)?;
        let as_of = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| {
                service_unavailable(
                    "clock_format_failed",
                    format!("Cannot format read time: {error}"),
                )
            })?;
        let prepared = prepare_indexed_query(&tenant_id, &lifecycle_query, &as_of, graph_revision)
            .map_err(|error| bad_request("invalid_security_lifecycle_query", error.to_string()))?;
        let indexed = tokio::time::timeout(
            Duration::from_secs(2),
            projection.query_lifecycle(&tenant_id, &prepared),
        )
        .await
        .map_err(|_| {
            service_unavailable(
                "lifecycle_projection_timeout",
                "The lifecycle projection read exceeded 2 seconds.",
            )
        })?;
        match indexed {
            Ok(page) => {
                return finalize_indexed_query(&tenant_id, &prepared, page)
                    .map(Json)
                    .map_err(|error| {
                        service_unavailable("lifecycle_projection_invalid", error.to_string())
                    });
            }
            Err(StoreError::LifecycleProjectionUnavailable { .. }) => {}
            Err(error) => return Err(store_error(error)),
        }
    }
    let revision_before = state
        .graph
        .revision(&tenant_id)
        .await
        .map_err(context_error)?;
    let (entities, scan_truncated) = if let Some(locator) = lifecycle_query.subject_locator.as_ref()
    {
        let subject_urn = canonical_resource_urn(
            tenant_id.as_str(),
            locator.subject_kind,
            &locator.authority_id,
            &locator.stable_locator,
        )
        .map_err(|error| bad_request("invalid_security_lifecycle_locator", error.to_string()))?;
        match state.graph.resolve(&tenant_id, &subject_urn).await {
            Ok(entity) => (vec![entity], false),
            Err(ContextError::EntityNotFound) => (Vec::new(), false),
            Err(error) => return Err(context_error(error)),
        }
    } else {
        let resource_kinds = vec!["resource".to_owned()];
        let entities = state
            .graph
            .search(&tenant_id, "", &resource_kinds, MAX_SECURITY_LIFECYCLE_SCAN)
            .await
            .map_err(context_error)?;
        let scan_truncated = entities.len() == MAX_SECURITY_LIFECYCLE_SCAN;
        (entities, scan_truncated)
    };
    let scanned_entities = entities.len();
    let entities = entities
        .into_iter()
        .map(|entity| ProjectedResource {
            agent_key: entity.agent_key,
            label: entity.label,
            properties: entity.properties,
        })
        .collect();
    let revision_after = state
        .graph
        .revision(&tenant_id)
        .await
        .map_err(context_error)?;
    let as_of = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| {
            service_unavailable(
                "clock_format_failed",
                format!("Cannot format read time: {error}"),
            )
        })?;
    query_records_with_source(
        &tenant_id,
        &lifecycle_query,
        entities,
        &as_of,
        QuerySource {
            scanned_entities,
            truncated: scan_truncated,
            graph_revision: revision_after,
            graph_changed: revision_before != revision_after,
        },
    )
    .map(Json)
    .map_err(|error| bad_request("invalid_security_lifecycle_query", error.to_string()))
}

async fn explain_assertion(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Path(assertion_id): Path<String>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<cerebro_agent_context::ContextEdge>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, query.tenant_id)?;
    let assertion_id = AssertionId::parse(assertion_id)
        .map_err(|error| bad_request("invalid_assertion_id", error.to_string()))?;
    state
        .graph
        .explain(&tenant_id, &assertion_id)
        .await
        .map(Json)
        .map_err(context_error)
}

async fn expand(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<ExpandRequest>,
) -> Result<Json<Neighborhood>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id)?;
    let mut neighborhoods = state
        .graph
        .expand_many(
            &tenant_id,
            std::slice::from_ref(&request.root_key),
            request.depth,
            request.limit,
        )
        .await
        .map_err(context_error)?;
    neighborhoods
        .remove(&request.root_key)
        .map(Json)
        .ok_or_else(|| context_error(ContextError::EntityNotFound))
}

async fn expand_batch(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<ExpandBatchRequest>,
) -> Result<Json<ExpandBatchResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id)?;
    state
        .graph
        .expand_many(&tenant_id, &request.root_keys, request.depth, request.limit)
        .await
        .map(|neighborhoods| Json(ExpandBatchResponse { neighborhoods }))
        .map_err(context_error)
}

async fn find_paths(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<PathsRequest>,
) -> Result<Json<PathsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id)?;
    let from = EntityId::parse(request.from_entity_id)
        .map_err(|error| bad_request("invalid_from_entity_id", error.to_string()))?;
    let to = EntityId::parse(request.to_entity_id)
        .map_err(|error| bad_request("invalid_to_entity_id", error.to_string()))?;
    state
        .graph
        .find_paths(&tenant_id, &from, &to, request.max_depth, request.limit)
        .await
        .map(|paths| Json(PathsResponse { paths }))
        .map_err(context_error)
}

async fn product_neighborhood_route(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    headers: HeaderMap,
    Query(query): Query<ProductNeighborhoodQuery>,
) -> Result<Json<ProductNeighborhood>, (StatusCode, Json<ErrorResponse>)> {
    if query.workspace_id.is_some() || headers.contains_key(WORKSPACE_AUTH_HEADER) {
        return Err(bad_request(
            "workspace_scope_unsupported",
            "Application workspace scope is not supported for graph neighborhood reads.",
        ));
    }
    let tenant = product_urn_tenant(&query.root_urn).ok_or_else(|| {
        bad_request(
            "invalid_root_urn",
            "root_urn must be a tenant-scoped Cerebro URN.",
        )
    })?;
    if let Some(query_tenant) = query.tenant_id {
        let query_tenant = parse_tenant(query_tenant)?;
        if query_tenant.as_str() != tenant {
            return Err(bad_request(
                "tenant_selector_mismatch",
                "The tenant selector does not match the graph root tenant.",
            ));
        }
    }
    let tenant_id = authorized_tenant(&authenticated, tenant.to_owned())?;
    let limit = normalize_product_neighborhood_limit(query.limit);
    let mut neighborhoods = state
        .graph
        .expand_many(&tenant_id, std::slice::from_ref(&query.root_urn), 1, limit)
        .await
        .map_err(context_error)?;
    let neighborhood = neighborhoods
        .remove(&query.root_urn)
        .ok_or_else(|| context_error(ContextError::EntityNotFound))?;
    product_neighborhood(&query.root_urn, &tenant_id, neighborhood)
        .map(Json)
        .map_err(context_error)
}

fn normalize_product_neighborhood_limit(limit: Option<u32>) -> usize {
    usize::try_from(limit.unwrap_or(10).clamp(1, 50)).unwrap_or(50)
}

fn product_urn_tenant(value: &str) -> Option<&str> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() < 5
        || parts[0] != "urn"
        || parts[1] != "cerebro"
        || value.chars().any(char::is_control)
        || parts.last().is_none_or(|part| part.is_empty())
        || parts[2..].iter().any(|part| part.trim() != *part)
        || parts[2..5].contains(&"")
    {
        return None;
    }
    if parts[3] == "runtime" && (parts.len() < 7 || parts[5].is_empty()) {
        return None;
    }
    Some(parts[2])
}

fn product_neighborhood(
    requested_root: &str,
    tenant_id: &TenantId,
    neighborhood: Neighborhood,
) -> Result<ProductNeighborhood, ContextError> {
    if neighborhood.tenant_id != *tenant_id
        || product_urn_tenant(&neighborhood.root.agent_key) != Some(tenant_id.as_str())
        || neighborhood.root.agent_key != requested_root
    {
        return Err(invalid_product_neighborhood(
            "graph root does not match the requested tenant-scoped key",
        ));
    }
    let root = product_node(requested_root.to_owned(), &neighborhood.root)?;

    let mut keys_by_id = BTreeMap::from([(
        neighborhood.root.entity_id.clone(),
        requested_root.to_owned(),
    )]);
    let mut ids_by_key = BTreeMap::from([(
        requested_root.to_owned(),
        neighborhood.root.entity_id.clone(),
    )]);
    let mut neighbors = Vec::with_capacity(neighborhood.entities.len());
    for entity in neighborhood.entities {
        if product_urn_tenant(&entity.agent_key) != Some(tenant_id.as_str()) {
            return Err(invalid_product_neighborhood(
                "graph entity is not bound to the requested tenant",
            ));
        }
        if let Some(existing) = keys_by_id.get(&entity.entity_id) {
            if existing != &entity.agent_key {
                return Err(invalid_product_neighborhood(
                    "one graph entity has multiple product keys",
                ));
            }
            return Err(invalid_product_neighborhood(
                "graph root was repeated as a neighbor",
            ));
        }
        if ids_by_key
            .insert(entity.agent_key.clone(), entity.entity_id.clone())
            .is_some()
        {
            return Err(invalid_product_neighborhood(
                "multiple graph entities have the same product key",
            ));
        }
        keys_by_id.insert(entity.entity_id.clone(), entity.agent_key.clone());
        neighbors.push(product_node(entity.agent_key.clone(), &entity)?);
    }

    let mut relations = Vec::with_capacity(neighborhood.edges.len());
    let mut seen = BTreeMap::new();
    for edge in neighborhood.edges {
        if !valid_product_text(&edge.relation) || !valid_product_text(&edge.source_runtime_id) {
            return Err(invalid_product_neighborhood(
                "graph edge has invalid relation or source runtime metadata",
            ));
        }
        let from_urn = keys_by_id.get(&edge.from).cloned().ok_or_else(|| {
            invalid_product_neighborhood("graph edge starts outside its neighborhood")
        })?;
        let to_urn = keys_by_id.get(&edge.to).cloned().ok_or_else(|| {
            invalid_product_neighborhood("graph edge ends outside its neighborhood")
        })?;
        let relation_key = (from_urn.clone(), edge.relation.clone(), to_urn.clone());
        if seen.insert(relation_key, ()).is_some() {
            continue;
        }
        let mut attributes =
            BTreeMap::from([("source_runtime_id".to_owned(), edge.source_runtime_id)]);
        if edge.identity_binding {
            attributes.insert("identity_binding".to_owned(), "true".to_owned());
        }
        relations.push(ProductNeighborhoodRelation {
            from_urn,
            relation: edge.relation,
            to_urn,
            attributes,
        });
    }

    Ok(ProductNeighborhood {
        root,
        neighbors,
        relations,
    })
}

fn product_node(
    urn: String,
    entity: &ContextEntity,
) -> Result<ProductNeighborhoodNode, ContextError> {
    let entity_type = entity
        .properties
        .get("entity_type")
        .filter(|value| !value.is_empty())
        .unwrap_or(&entity.entity_kind);
    if !valid_product_text(entity_type) || !valid_product_text(&entity.label) {
        return Err(invalid_product_neighborhood(
            "graph entity has invalid type or label metadata",
        ));
    }
    Ok(ProductNeighborhoodNode {
        urn,
        entity_type: entity_type.clone(),
        label: entity.label.clone(),
    })
}

fn valid_product_text(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}

fn invalid_product_neighborhood(message: impl Into<String>) -> ContextError {
    ContextError::BackendUnavailable(format!("invalid product neighborhood: {}", message.into()))
}

fn parse_tenant(value: String) -> Result<TenantId, (StatusCode, Json<ErrorResponse>)> {
    TenantId::parse(value).map_err(|error| bad_request("invalid_tenant_id", error.to_string()))
}

fn authorized_tenant(
    authenticated: &AuthenticatedTenant,
    requested: String,
) -> Result<TenantId, (StatusCode, Json<ErrorResponse>)> {
    let requested = parse_tenant(requested)?;
    if requested != authenticated.0 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                code: "tenant_forbidden",
                message: "The authenticated tenant does not match the requested tenant.".to_owned(),
            }),
        ));
    }
    Ok(requested)
}

fn context_error(error: ContextError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        ContextError::EntityNotFound => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "entity_not_found",
                message: error.to_string(),
            }),
        ),
        ContextError::BackendUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "graph_unavailable",
                message: error.to_string(),
            }),
        ),
        _ => bad_request("invalid_graph_request", error.to_string()),
    }
}

fn event_provider_id(attributes: &BTreeMap<String, String>, fallback: &str) -> String {
    for key in [
        "resource_id",
        "user_id",
        "group_id",
        "repository_id",
        "finding_id",
        "alert_id",
        "policy_id",
        "id",
        "external_id",
    ] {
        if let Some(value) = attributes.get(key)
            && !value.trim().is_empty()
        {
            return value.clone();
        }
    }
    fallback.to_owned()
}

fn model_error(error: ModelError) -> (StatusCode, Json<ErrorResponse>) {
    bad_request("invalid_projection_event", error.to_string())
}

fn store_error(error: StoreError) -> (StatusCode, Json<ErrorResponse>) {
    service_unavailable("projection_store_unavailable", error.to_string())
}

fn action_store_error(error: ActionStoreError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        ActionStoreError::Conflict(message) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "action_conflict",
                message,
            }),
        ),
        ActionStoreError::NotFound(message) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "action_not_found",
                message,
            }),
        ),
        ActionStoreError::Invalid(error) => bad_request("invalid_action", error.to_string()),
        ActionStoreError::Catalog(error) => {
            bad_request("invalid_action_definition", error.to_string())
        }
        ActionStoreError::PolicyCatalog(error) => {
            bad_request("invalid_policy_definition", error.to_string())
        }
        ActionStoreError::OutOfRange(field) => bad_request("invalid_action", field),
        ActionStoreError::Postgres(error) => {
            eprintln!("Action PostgreSQL unavailable: {error}");
            service_unavailable(
                "action_authority_unavailable",
                "The Rust Action ledger is temporarily unavailable.",
            )
        }
        ActionStoreError::Serialization(error) => {
            eprintln!("Action serialization failed: {error}");
            service_unavailable(
                "action_authority_unavailable",
                "The Rust Action ledger is temporarily unavailable.",
            )
        }
        ActionStoreError::Corrupt(message) => {
            eprintln!("Action ledger corruption detected: {message}");
            service_unavailable(
                "action_authority_invalid",
                "The stored Action failed authority validation.",
            )
        }
        ActionStoreError::InvalidPageToken => bad_request(
            "invalid_action_page_token",
            "The Action page token is invalid.",
        ),
    }
}

fn action_catalog_error(error: ActionCatalogError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        ActionCatalogError::InvalidProposal(error) => {
            bad_request("invalid_action", error.to_string())
        }
        error => bad_request("invalid_action_definition", error.to_string()),
    }
}

fn finding_validation_store_error(error: ActionStoreError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        ActionStoreError::Conflict(message) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "finding_validation_conflict",
                message,
            }),
        ),
        ActionStoreError::NotFound(message) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "finding_validation_not_found",
                message,
            }),
        ),
        other => action_store_error(other),
    }
}

fn permission_denied(message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            code: "permission_denied",
            message: message.into(),
        }),
    )
}

fn service_unavailable(
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            code,
            message: message.into(),
        }),
    )
}

fn bad_request(
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            code,
            message: message.into(),
        }),
    )
}

async fn demo() -> Result<(), Box<dyn Error>> {
    let (graph, tenant, root_id) = demo_graph()?;
    let neighborhood = AgentContext::new(&graph).expand(&tenant, &root_id, 4, 100)?;
    println!("{}", serde_json::to_string_pretty(&neighborhood)?);
    Ok(())
}

fn catalog_summary() -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&load_catalog_summary()?)?
    );
    Ok(())
}

/// One catalog family rendered by `list-catalog-families`. The fields are the
/// minimum an operator needs to drive per-family cutover over the existing
/// `evaluate-family`, `promote-family`, and `show-authority` commands: the
/// family address, its closed projection class, and whether the catalog marked
/// it collection- and projection-authoritative.
#[derive(Clone, Copy, Debug, Serialize)]
struct CatalogFamilyRecord<'a> {
    source_id: &'a str,
    family_id: &'a str,
    projection_class: ProjectionClass,
    authoritative: bool,
    projection_authoritative: bool,
    can_be_authoritative: bool,
}

fn catalog_family_records(catalog: &SourceCatalog) -> Vec<CatalogFamilyRecord<'_>> {
    let mut records = Vec::new();
    for source in catalog.sources() {
        let source_id = source.id();
        for family in source.families() {
            let class = family.projection().class();
            records.push(CatalogFamilyRecord {
                source_id,
                family_id: family.id(),
                projection_class: class,
                authoritative: family.is_authoritative(),
                projection_authoritative: family.is_projection_authoritative(),
                can_be_authoritative: class.can_be_authoritative(),
            });
        }
    }
    records
}

/// Operator-selected filters for `list-catalog-families`. Each field is
/// optional; `None` means the field does not restrict the output. This lets an
/// operator target a cutover cohort (for example only not-yet-authoritative
/// identity/resource families) instead of enumerating every compiled family.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CatalogFamilyFilter {
    projection_classes: Option<BTreeSet<ProjectionClass>>,
    authoritative: Option<bool>,
    can_be_authoritative: Option<bool>,
}

impl CatalogFamilyFilter {
    /// Parse `--projection-class=<class>`, `--authoritative=<bool>`, and
    /// `--can-be-authoritative=<bool>` flags from the arguments after the
    /// subcommand. `--projection-class` may repeat to select multiple classes.
    /// Unknown flags or missing values fail closed.
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut filter = Self::default();
        for argument in arguments {
            let (flag, value) = match argument.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (argument.as_str(), None),
            };
            match flag {
                "--projection-class" => {
                    let value = value.ok_or("--projection-class requires =<class>")?;
                    let class = parse_projection_class(value)?;
                    filter
                        .projection_classes
                        .get_or_insert_with(BTreeSet::new)
                        .insert(class);
                }
                "--authoritative" => {
                    let value = value.ok_or("--authoritative requires =<bool>")?;
                    filter.authoritative = Some(parse_bool(value, "--authoritative")?);
                }
                "--can-be-authoritative" => {
                    let value = value.ok_or("--can-be-authoritative requires =<bool>")?;
                    filter.can_be_authoritative =
                        Some(parse_bool(value, "--can-be-authoritative")?);
                }
                other => {
                    return Err(format!("unknown list-catalog-families flag {other:?}").into());
                }
            }
        }
        Ok(filter)
    }

    fn matches(&self, record: &CatalogFamilyRecord<'_>) -> bool {
        self.projection_classes
            .as_ref()
            .is_none_or(|classes| classes.contains(&record.projection_class))
            && self
                .authoritative
                .is_none_or(|required| record.authoritative == required)
            && self
                .can_be_authoritative
                .is_none_or(|required| record.can_be_authoritative == required)
    }
}

fn parse_projection_class(value: &str) -> Result<ProjectionClass, Box<dyn Error>> {
    match value.trim() {
        "identity" => Ok(ProjectionClass::Identity),
        "access" => Ok(ProjectionClass::Access),
        "resource" => Ok(ProjectionClass::Resource),
        "finding" => Ok(ProjectionClass::Finding),
        "activity" => Ok(ProjectionClass::Activity),
        "bespoke" => Ok(ProjectionClass::Bespoke),
        other => Err(format!("unknown projection class {other:?}").into()),
    }
}

fn parse_bool(value: &str, flag: &str) -> Result<bool, Box<dyn Error>> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("{flag} requires =true or =false").into()),
    }
}

fn list_catalog_families() -> Result<(), Box<dyn Error>> {
    use std::io::Write;

    let filter = CatalogFamilyFilter::parse(env::args().skip(2))?;
    let catalog = load_catalog()?;
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    for record in catalog_family_records(&catalog) {
        if filter.matches(&record) {
            serde_json::to_writer(&mut writer, &record)?;
            writeln!(&mut writer)?;
        }
    }
    Ok(())
}

fn load_catalog_summary() -> Result<CatalogSummary, Box<dyn Error>> {
    Ok(load_catalog()?.summary())
}

fn load_catalog() -> Result<SourceCatalog, Box<dyn Error>> {
    let root = env::var("CEREBRO_REPOSITORY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    Ok(SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )?)
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.trim().is_empty() {
        return Err(format!("{name} is required").into());
    }
    Ok(value)
}

fn access_approvals_from_env() -> Result<Option<AccessApprovalsClient>, Box<dyn Error>> {
    const BASE_URL: &str = "CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL";
    const BEARER_TOKEN: &str = "CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN";
    const BEARER_TOKEN_FILE: &str = "CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE";
    const TIMEOUT: &str = "CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT";

    let base_url = optional_env(BASE_URL)?;
    let direct_token = optional_env(BEARER_TOKEN)?;
    let token_file = optional_env(BEARER_TOKEN_FILE)?;
    if base_url.is_none() && direct_token.is_none() && token_file.is_none() {
        return Ok(None);
    }
    let base_url = base_url.ok_or_else(|| format!("{BASE_URL} is required"))?;
    let bearer_token = match (direct_token, token_file) {
        (Some(_), Some(_)) => {
            return Err(
                format!("configure only one of {BEARER_TOKEN} and {BEARER_TOKEN_FILE}").into(),
            );
        }
        (Some(token), None) => token,
        (None, Some(path)) => read_bounded_secret_file(&path)?,
        (None, None) => {
            return Err(
                format!("one of {BEARER_TOKEN} and {BEARER_TOKEN_FILE} is required").into(),
            );
        }
    };
    let mut config = AccessApprovalsConfig::new(base_url, bearer_token);
    if let Some(timeout) = optional_env(TIMEOUT)? {
        config.timeout = parse_provider_timeout(&timeout)?;
    }
    AccessApprovalsClient::new(config)
        .map(Some)
        .map_err(|error| error.into())
}

fn optional_env(name: &str) -> Result<Option<String>, env::VarError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error),
    }
}

fn optional_trimmed_env(name: &str) -> Result<Option<String>, Box<dyn Error>> {
    const MAX_CONFIG_BYTES: usize = 4 * 1_024;
    let value = optional_env(name)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_CONFIG_BYTES)
    {
        return Err(format!("{name} is too large").into());
    }
    Ok(value)
}

fn validate_aws_secrets_manager_endpoint(endpoint: &str) -> Result<(), Box<dyn Error>> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| "AWS Secrets Manager endpoint is invalid")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("AWS Secrets Manager endpoint is invalid".into());
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !secure && !loopback_http {
        return Err("AWS Secrets Manager endpoint must use HTTPS or loopback HTTP".into());
    }
    Ok(())
}

fn required_secret_env_or_file(name: &str) -> Result<String, Box<dyn Error>> {
    let direct = optional_env(name)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let file_name = format!("{name}_FILE");
    let file = optional_env(&file_name)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match (direct, file) {
        (Some(_), Some(_)) => Err(format!("configure only one of {name} and {file_name}").into()),
        (Some(value), None) => Ok(value),
        (None, Some(path)) => read_bounded_secret_file(&path),
        (None, None) => Err(format!("one of {name} and {file_name} is required").into()),
    }
}

fn read_bounded_secret_file(path: &str) -> Result<String, Box<dyn Error>> {
    use std::io::Read as _;

    const MAX_SECRET_FILE_BYTES: usize = 16 * 1_024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_SECRET_FILE_BYTES {
        return Err("secret file is empty or too large".into());
    }
    let token = String::from_utf8(bytes)?;
    let token = token
        .strip_suffix("\r\n")
        .or_else(|| token.strip_suffix('\n'))
        .unwrap_or(&token)
        .trim()
        .to_owned();
    if token.is_empty() {
        return Err("secret file is empty or too large".into());
    }
    Ok(token)
}

fn parse_provider_timeout(value: &str) -> Result<Duration, Box<dyn Error>> {
    let duration = if let Some(milliseconds) = value.strip_suffix("ms") {
        Duration::from_millis(milliseconds.parse()?)
    } else if let Some(seconds) = value.strip_suffix('s') {
        Duration::from_secs(seconds.parse()?)
    } else {
        return Err("access-approvals timeout must use an ms or s suffix".into());
    };
    Ok(duration)
}

fn demo_graph() -> Result<(OrganizationalGraph, TenantId, EntityId), Box<dyn Error>> {
    let tenant = TenantId::parse("tenant-demo")?;
    let runtime = SourceRuntimeId::parse("okta-demo")?;
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("collection-demo")?,
        "okta.users",
        1,
    )?;
    let provider_identity = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.user")?,
        "00u-demo",
        "Provider identity",
    )?;
    let identity_claim = IdentityClaim::employee_id("employee-demo")?;
    let canonical_identity =
        CanonicalIdentity::for_claim(tenant.clone(), &identity_claim, "Demo person")?;
    let group = Entity::canonical(
        tenant.clone(),
        EntityId::parse("group-security")?,
        EntityKind::Group,
        "Security",
    )?;
    let repository = Entity::canonical(
        tenant.clone(),
        EntityId::parse("repository-cerebro")?,
        EntityKind::Repository,
        "writer/cerebro",
    )?;

    let provenance = || {
        AssertionProvenance::direct(
            vec![ObservationRef::new(
                collection.receipt(),
                ObservationId::parse("observation-demo")?,
                "okta.user:00u-demo",
            )?],
            "demo-mapper",
            "v1",
        )
    };
    let identity_binding = IdentityBindingAssertion::new(
        &provider_identity,
        &canonical_identity,
        IdentityResolutionMethod::AuthoritativeEmployeeId,
        Some(identity_claim),
        IdentityBindingState::Confirmed,
        provenance()?,
        1,
    )?;
    let membership = RelationshipAssertion::new(
        canonical_identity.entity(),
        RelationKind::MemberOf,
        &group,
        provenance()?,
        1,
    )?;
    let access = RelationshipAssertion::new(
        &group,
        RelationKind::CanAccess,
        &repository,
        provenance()?,
        1,
    )?;

    let root_id = provider_identity.entity().id().clone();
    let mut builder = collection.begin_delta();
    builder.add_entity(provider_identity.into_entity())?;
    builder.add_entity(canonical_identity.into_entity())?;
    builder.add_entity(group)?;
    builder.add_entity(repository)?;
    builder.add_assertion(GraphAssertion::IdentityBinding(identity_binding))?;
    builder.add_assertion(GraphAssertion::Relationship(membership))?;
    builder.add_assertion(GraphAssertion::Relationship(access))?;

    let mut graph = OrganizationalGraph::new();
    graph.apply(builder.build())?;

    let vendor_runtime = SourceRuntimeId::parse("vendor-demo")?;
    let vendor_collection = CompleteCollection::new(
        tenant.clone(),
        vendor_runtime.clone(),
        CollectionId::parse("vendor-collection-demo")?,
        "vendor.records",
        1,
    )?;
    let vendor_kind = ProviderKind::parse("demo.vendor")?;
    let identity_vendor = Entity::provider(
        tenant.clone(),
        vendor_runtime.clone(),
        vendor_kind.clone(),
        "identity-platform",
        EntityKind::Provider(vendor_kind.clone()),
        "Identity Platform",
    )?
    .with_property("entity_type", "vendor")?
    .with_property(
        "entity_urn",
        "urn:cerebro:tenant-demo:vendor:identity-platform",
    )?
    .with_property("source_id", "rust-demo")?
    .with_property("vendor_id", "identity-platform")?
    .with_property("category", "identity")?
    .with_property("services_provided", "Workforce identity and access")?
    .with_property("security_owner_user_id", "identity-security")?
    .with_property("lifecycle_state", "approved")?
    .with_property("risk_level", "high")?
    .with_property("security_review_status", "approved")?;
    let collaboration_vendor = Entity::provider(
        tenant.clone(),
        vendor_runtime,
        vendor_kind.clone(),
        "collaboration-suite",
        EntityKind::Provider(vendor_kind),
        "Collaboration Suite",
    )?
    .with_property("entity_type", "vendor")?
    .with_property(
        "entity_urn",
        "urn:cerebro:tenant-demo:vendor:collaboration-suite",
    )?
    .with_property("source_id", "rust-demo")?
    .with_property("vendor_id", "collaboration-suite")?
    .with_property("category", "productivity")?
    .with_property("services_provided", "Documents and team collaboration")?
    .with_property("security_owner_user_id", "security-operations")?
    .with_property("lifecycle_state", "active")?
    .with_property("risk_level", "medium")?
    .with_property("security_review_status", "approved")?;
    let mut vendor_builder = vendor_collection.begin_delta();
    vendor_builder.add_entity(identity_vendor)?;
    vendor_builder.add_entity(collaboration_vendor)?;
    graph.apply(vendor_builder.build())?;
    Ok((graph, tenant, root_id))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use aws_credential_types::Credentials;
    use axum::{
        body::{Body, Bytes},
        http::{HeaderMap, Request, StatusCode, header::CONTENT_TYPE},
        routing::post,
    };
    use cerebro_agent_context::ContextEdge;
    use cerebro_platform_sdk::{ActionEffect, GraphRevision};
    use tower::ServiceExt;

    use super::*;

    const TEST_SHARED_SECRET: &str = "test-organizational-graph-secret-32-bytes";

    fn runtime_health_record(runtime_id: &str) -> SourceRuntimeObservation {
        SourceRuntimeObservation {
            runtime_id: runtime_id.to_owned(),
            source_id: "aws".to_owned(),
            enabled_state: "enabled".to_owned(),
            last_failure_category: None,
            last_synced_at: Some("2026-08-24T11:59:00Z".to_owned()),
            cursor_pending: false,
            checkpoint_cursor_present: false,
            stale_after_seconds: Some(300),
            expected_cadence_seconds: Some(300),
            contract_probe_state: "passing".to_owned(),
            latest_finding_evaluation_status: Some("current".to_owned()),
            latest_collection: None,
        }
    }

    fn current_graph(runtime_id: &str) -> SourceRuntimeGraphObservation {
        SourceRuntimeGraphObservation {
            runtime_id: runtime_id.to_owned(),
            status: "completed".to_owned(),
            checkpoint_cursor: String::new(),
            checkpoint_complete: Some(true),
            started_at: "2026-08-24T11:58:00Z".to_owned(),
            finished_at: "2026-08-24T11:59:30Z".to_owned(),
        }
    }

    #[test]
    fn rust_runtime_health_view_and_rollup_preserve_original_three_record_parity() {
        let now = OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339).unwrap();
        let healthy = rust_source_runtime_health_view(
            runtime_health_record("aws-healthy"),
            Some(current_graph("aws-healthy")),
            now,
        );
        let mut cursor_record = runtime_health_record("aws-cursor");
        cursor_record.cursor_pending = true;
        let cursor =
            rust_source_runtime_health_view(cursor_record, Some(current_graph("aws-cursor")), now);
        let mut finding_record = runtime_health_record("aws-finding");
        finding_record.latest_finding_evaluation_status = Some("failed".to_owned());
        let finding = rust_source_runtime_health_view(
            finding_record,
            Some(current_graph("aws-finding")),
            now,
        );

        assert_eq!(
            (healthy.readiness.as_str(), healthy.next_action.as_str()),
            ("healthy", "monitor")
        );
        assert_eq!(
            (cursor.readiness.as_str(), cursor.next_action.as_str()),
            ("needs_refresh", "run_sync")
        );
        assert_eq!(
            (finding.readiness.as_str(), finding.next_action.as_str()),
            ("bad", "inspect_finding_evaluation")
        );

        let summaries = rust_source_runtime_health_summaries(&[healthy, cursor, finding]);
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(
            (
                summary.total,
                summary.healthy,
                summary.needs_refresh,
                summary.bad
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(
            (summary.readiness.as_str(), summary.next_action.as_str()),
            ("bad", "inspect_finding_evaluation")
        );
        assert_eq!(summary.cursor_pending, 1);
        assert_eq!(summary.graph_current, 3);
    }

    #[test]
    fn catalog_family_records_cover_every_compiled_family() {
        let catalog = load_catalog().expect("checked-in catalog must load");
        let records = catalog_family_records(&catalog);
        assert!(
            !records.is_empty(),
            "catalog must compile at least one family"
        );
        for record in &records {
            assert!(!record.source_id.is_empty(), "family missing source id");
            assert!(!record.family_id.is_empty(), "family missing family id");
            // `can_be_authoritative` is false only for the bespoke class.
            assert_eq!(
                record.can_be_authoritative,
                !matches!(record.projection_class, ProjectionClass::Bespoke),
                "can_be_authoritative must track the bespoke class for {}/{}",
                record.source_id,
                record.family_id,
            );
        }
    }

    #[test]
    fn catalog_family_filter_parses_and_matches() {
        let filter = CatalogFamilyFilter::parse(
            [
                "--projection-class=identity",
                "--projection-class=access",
                "--authoritative=false",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        assert_eq!(
            filter.projection_classes,
            Some(BTreeSet::from([
                ProjectionClass::Identity,
                ProjectionClass::Access
            ])),
        );
        assert_eq!(filter.authoritative, Some(false));
        assert!(filter.can_be_authoritative.is_none());

        let matching = CatalogFamilyRecord {
            source_id: "s",
            family_id: "f",
            projection_class: ProjectionClass::Identity,
            authoritative: false,
            projection_authoritative: false,
            can_be_authoritative: true,
        };
        assert!(
            filter.matches(&matching),
            "identity non-authoritative matches"
        );

        let wrong_class = CatalogFamilyRecord {
            projection_class: ProjectionClass::Resource,
            ..matching
        };
        assert!(
            !filter.matches(&wrong_class),
            "resource is filtered out by class"
        );

        let wrong_authority = CatalogFamilyRecord {
            authoritative: true,
            ..matching
        };
        assert!(
            !filter.matches(&wrong_authority),
            "authoritative is filtered out"
        );

        // Unknown flags and bad values fail closed.
        assert!(CatalogFamilyFilter::parse(["--bogus"].into_iter().map(String::from)).is_err());
        assert!(
            CatalogFamilyFilter::parse(["--projection-class=bogus".to_owned()].into_iter())
                .is_err()
        );
        assert!(
            CatalogFamilyFilter::parse(["--authoritative=maybe".to_owned()].into_iter()).is_err()
        );
        assert!(CatalogFamilyFilter::parse(["--projection-class".to_owned()].into_iter()).is_err());
    }

    #[test]
    fn catalog_family_filter_authoritative_partitions_the_catalog() {
        let catalog = load_catalog().expect("checked-in catalog must load");
        let records = catalog_family_records(&catalog);
        let authoritative =
            CatalogFamilyFilter::parse(["--authoritative=true".to_owned()].into_iter()).unwrap();
        let non_authoritative =
            CatalogFamilyFilter::parse(["--authoritative=false".to_owned()].into_iter()).unwrap();
        let yes: Vec<_> = records
            .iter()
            .filter(|r| authoritative.matches(r))
            .collect();
        let no: Vec<_> = records
            .iter()
            .filter(|r| non_authoritative.matches(r))
            .collect();
        assert!(
            yes.iter().all(|r| r.authoritative),
            "authoritative=true keeps only authoritative"
        );
        assert!(
            no.iter().all(|r| !r.authoritative),
            "authoritative=false keeps only non-authoritative"
        );
        assert_eq!(
            yes.len() + no.len(),
            records.len(),
            "authoritative filter must partition the catalog"
        );
    }

    #[test]
    fn catalog_family_filter_can_be_authoritative_false_selects_only_bespoke() {
        let catalog = load_catalog().expect("checked-in catalog must load");
        let records = catalog_family_records(&catalog);
        let filter =
            CatalogFamilyFilter::parse(["--can-be-authoritative=false".to_owned()].into_iter())
                .unwrap();
        let matching: Vec<_> = records.iter().filter(|r| filter.matches(r)).collect();
        let bespoke: Vec<_> = records
            .iter()
            .filter(|r| matches!(r.projection_class, ProjectionClass::Bespoke))
            .collect();
        assert_eq!(
            matching.len(),
            bespoke.len(),
            "can_be_authoritative=false selects exactly the bespoke families"
        );
        assert!(
            matching
                .iter()
                .all(|r| matches!(r.projection_class, ProjectionClass::Bespoke)),
            "can_be_authoritative=false selects only bespoke families"
        );
    }

    #[test]
    fn startup_installs_a_tls_crypto_provider() {
        install_tls_crypto_provider().expect("TLS crypto provider should install");
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        install_tls_crypto_provider()
            .expect("TLS crypto provider installation should be idempotent");
    }

    #[test]
    fn aws_secrets_manager_endpoint_requires_a_safe_transport() {
        for endpoint in [
            "https://secretsmanager.us-east-1.amazonaws.com",
            "http://localhost:4566",
            "http://127.0.0.1:4566",
            "http://[::1]:4566",
        ] {
            validate_aws_secrets_manager_endpoint(endpoint)
                .unwrap_or_else(|error| panic!("{endpoint} must be accepted: {error}"));
        }
        for endpoint in [
            "http://secretsmanager.example.com",
            "https://user:password@secretsmanager.example.com",
            "https://secretsmanager.example.com?token=secret",
            "https://secretsmanager.example.com#secret",
            "ftp://localhost/secrets",
            "not-a-url",
        ] {
            assert!(
                validate_aws_secrets_manager_endpoint(endpoint).is_err(),
                "{endpoint} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn aws_secrets_manager_reader_signs_one_scoped_backend_request() {
        let reads = Arc::new(AtomicUsize::new(0));
        let fixture_reads = Arc::clone(&reads);
        let fixture = Router::new().route(
            "/",
            post(move |headers: HeaderMap, body: Bytes| {
                let fixture_reads = Arc::clone(&fixture_reads);
                async move {
                    fixture_reads.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(
                        headers
                            .get("x-amz-target")
                            .and_then(|value| value.to_str().ok()),
                        Some("secretsmanager.GetSecretValue")
                    );
                    assert!(
                        headers
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                    );
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                        serde_json::json!({
                            "SecretId": "cerebro/tenant-a/github/runtime-a/credentials"
                        })
                    );
                    (
                        [(CONTENT_TYPE, "application/x-amz-json-1.1")],
                        serde_json::json!({
                            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:cerebro/tenant-a/github/runtime-a/credentials",
                            "Name": "cerebro/tenant-a/github/runtime-a/credentials",
                            "SecretString": "{\"token\":\"resolved-token\",\"username\":\"runtime-user\"}"
                        })
                        .to_string(),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, fixture).await.unwrap();
        });
        let reader = AwsSecretsManagerReader {
            default_region: "us-east-1".to_owned(),
            profile: None,
            role_arn: None,
            external_id: None,
            endpoint: Some(format!("http://{address}")),
            credentials_provider: Some(SharedCredentialsProvider::new(Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "test",
            ))),
        };
        let config = BTreeMap::from([
            (
                "token".to_owned(),
                "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#token".to_owned(),
            ),
            (
                "username".to_owned(),
                "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#username"
                    .to_owned(),
            ),
        ]);
        let resolved = cerebro_source_runtime_next::resolve_aws_secret_references(
            "tenant-a",
            "github",
            "runtime-a",
            &config,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            resolved.get("token").map(String::as_str),
            Some("resolved-token")
        );
        assert_eq!(
            resolved.get("username").map(String::as_str),
            Some("runtime-user")
        );
        server.abort();
    }

    #[test]
    fn rust_source_sync_accepts_only_the_stored_runtime_selector() {
        let sync_source = include_str!("source_runtime_sync.rs");
        assert!(sync_source.contains("CEREBRO_SOURCE_RUNTIME_ID"));
        for deprecated in [
            ["CEREBRO", "SOURCE", "ID"].join("_"),
            ["CEREBRO", "SOURCE", "FAMILY"].join("_"),
            ["CEREBRO", "TENANT", "ID"].join("_"),
            ["CEREBRO", "SOURCE", "BASE", "URL"].join("_"),
            ["CEREBRO", "SOURCE", "CONFIG", "JSON"].join("_"),
            ["CEREBRO", "SOURCE", "CURSOR"].join("_"),
            ["CEREBRO", "SOURCE", "TOKEN"].join("_"),
            ["CEREBRO", "SOURCE", "AUTH", "VALUE"].join("_"),
        ] {
            assert!(
                !sync_source.contains(&deprecated),
                "sync-source still accepts deprecated authority input {deprecated}"
            );
        }
    }

    #[test]
    fn aws_sigv4_resolution_scrubs_secrets_but_preserves_runtime_config() {
        let mut config = BTreeMap::from([
            ("access_key".to_owned(), "access-example".to_owned()),
            ("secret_key".to_owned(), "secret-example".to_owned()),
            ("session_token".to_owned(), "session-example".to_owned()),
            ("region".to_owned(), "us-east-1".to_owned()),
            ("service".to_owned(), "bedrock".to_owned()),
            ("account".to_owned(), "account-a".to_owned()),
        ]);
        let auth = resolved_auth(
            &AuthModel::AwsSigV4,
            CatalogAuthSettings::default(),
            &mut config,
        )
        .unwrap();
        assert!(matches!(
            auth,
            ResolvedAuth::AwsSigV4 {
                ref access_key_id,
                ref secret_access_key,
                session_token: Some(ref session_token),
                ref region,
                ref service,
            } if access_key_id == "access-example"
                && secret_access_key == "secret-example"
                && session_token == "session-example"
                && region == "us-east-1"
                && service == "bedrock"
        ));
        for secret_key in ["access_key", "secret_key", "session_token"] {
            assert!(!config.contains_key(secret_key));
        }
        assert_eq!(config.get("region").map(String::as_str), Some("us-east-1"));
        assert_eq!(config.get("service").map(String::as_str), Some("bedrock"));
        assert_eq!(config.get("account").map(String::as_str), Some("account-a"));
    }

    #[test]
    fn duo_hmac_v5_resolution_scrubs_both_credentials() {
        let mut config = BTreeMap::from([
            ("client_id".to_owned(), "integration-example".to_owned()),
            ("client_secret".to_owned(), "secret-example".to_owned()),
            ("base_url".to_owned(), "https://api.example.test".to_owned()),
        ]);
        let auth = resolved_auth(
            &AuthModel::DuoHmacV5,
            CatalogAuthSettings::default(),
            &mut config,
        )
        .unwrap();
        assert!(matches!(
            auth,
            ResolvedAuth::DuoHmacV5 {
                ref integration_key,
                ref secret_key,
            } if integration_key == "integration-example" && secret_key == "secret-example"
        ));
        assert!(!config.contains_key("client_id"));
        assert!(!config.contains_key("client_secret"));
        assert_eq!(
            config.get("base_url").map(String::as_str),
            Some("https://api.example.test")
        );
    }

    #[test]
    fn oauth_client_credentials_resolution_renders_provider_contract_and_scrubs_secrets() {
        let catalog = load_catalog().unwrap();
        let source = catalog.get("auth0").unwrap();
        let mut config = BTreeMap::from([
            ("client_id".to_owned(), "client-example".to_owned()),
            ("client_secret".to_owned(), "credential-example".to_owned()),
            ("domain".to_owned(), "tenant.example.test".to_owned()),
            (
                "base_url".to_owned(),
                "https://tenant.example.test/api/v2".to_owned(),
            ),
            ("family".to_owned(), "users".to_owned()),
        ]);
        let auth = resolved_auth(
            source.auth(),
            CatalogAuthSettings::from_source(source),
            &mut config,
        )
        .unwrap();
        assert!(matches!(
            auth,
            ResolvedAuth::OauthClientCredentials {
                ref client_id,
                ref client_secret,
                ref token_url,
                ref token_params,
                ..
            } if client_id == "client-example"
                && client_secret == "credential-example"
                && token_url == "https://tenant.example.test/oauth/token"
                && token_params.get("audience").map(String::as_str)
                    == Some("https://tenant.example.test/api/v2/")
        ));
        assert!(!config.contains_key("client_id"));
        assert!(!config.contains_key("client_secret"));
        assert_eq!(
            config.get("domain").map(String::as_str),
            Some("tenant.example.test")
        );
        assert!(
            resolve_oauth_token_url(
                "https://${config.domain}/oauth/token",
                &BTreeMap::from([
                    ("domain".to_owned(), "attacker.example.test".to_owned()),
                    (
                        "base_url".to_owned(),
                        "https://tenant.example.test/api/v2".to_owned(),
                    ),
                ]),
            )
            .is_err()
        );
    }

    #[test]
    fn oauth_authorization_code_resolution_refreshes_or_uses_a_resolved_bearer() {
        let catalog = load_catalog().unwrap();
        let source = catalog.get("hubspot").unwrap();
        let mut refresh = BTreeMap::from([
            ("client_id".to_owned(), "client-example".to_owned()),
            ("client_secret".to_owned(), "credential-example".to_owned()),
            ("refresh_token".to_owned(), "refresh-example".to_owned()),
            ("base_url".to_owned(), "https://api.hubapi.com".to_owned()),
            ("family".to_owned(), "users".to_owned()),
        ]);
        let auth = resolved_auth(
            source.auth(),
            CatalogAuthSettings::from_source(source),
            &mut refresh,
        )
        .unwrap();
        assert!(matches!(
            auth,
            ResolvedAuth::OauthAuthorizationCode {
                ref client_id,
                ref client_secret,
                ref refresh_token,
                ref token_url,
                ..
            } if client_id == "client-example"
                && client_secret == "credential-example"
                && refresh_token == "refresh-example"
                && token_url == "https://api.hubapi.com/oauth/token"
        ));
        for secret_key in ["client_id", "client_secret", "refresh_token"] {
            assert!(!refresh.contains_key(secret_key));
        }
        assert_eq!(refresh.get("family").map(String::as_str), Some("users"));

        let referenced = catalog.get("drchrono").unwrap();
        let mut bearer = BTreeMap::from([
            ("access_token".to_owned(), "access-example".to_owned()),
            (
                "oauth_client_reference".to_owned(),
                "managed-client-example".to_owned(),
            ),
            ("base_url".to_owned(), "https://drchrono.com".to_owned()),
            ("family".to_owned(), "patients".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                referenced.auth(),
                CatalogAuthSettings::from_source(referenced),
                &mut bearer,
            )
            .unwrap(),
            ResolvedAuth::Bearer { ref token } if token == "access-example"
        ));
        assert!(!bearer.contains_key("access_token"));
        assert!(!bearer.contains_key("oauth_client_reference"));
    }

    #[test]
    fn stored_signature_auth_matches_go_aliases_and_scrubs_every_secret() {
        let catalog = load_catalog().unwrap();
        for (source_id, selected_alias) in [("netsuite", "token"), ("veracode", "signature")] {
            let source = catalog.get(source_id).unwrap();
            let mut config = BTreeMap::from([
                (
                    selected_alias.to_owned(),
                    format!("{source_id}-precomputed-proof"),
                ),
                ("access_token".to_owned(), "unused-access-proof".to_owned()),
                ("api_key".to_owned(), "unused-api-proof".to_owned()),
                ("family".to_owned(), source.families()[0].id().to_owned()),
            ]);
            let auth = resolved_auth(
                source.auth(),
                CatalogAuthSettings::from_source(source),
                &mut config,
            )
            .unwrap();
            assert!(matches!(
                auth,
                ResolvedAuth::Header {
                    ref name,
                    ref value,
                } if name == "Authorization"
                    && value == &format!("Signature {source_id}-precomputed-proof")
            ));
            assert!(!format!("{auth:?}").contains("precomputed-proof"));
            for alias in [
                "token",
                "signature",
                "auth_value",
                "access_token",
                "api_token",
                "api_key",
            ] {
                assert!(!config.contains_key(alias));
            }
            assert!(config.contains_key("family"));
        }
    }

    #[test]
    fn stored_basic_and_api_key_auth_scrub_credentials_from_connector_config() {
        let mut basic = BTreeMap::from([
            ("username".to_owned(), "service-account".to_owned()),
            ("password".to_owned(), "secret-example".to_owned()),
            ("family".to_owned(), "users".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::Basic,
                CatalogAuthSettings::default(),
                &mut basic
            )
            .unwrap(),
            ResolvedAuth::Basic {
                ref username,
                ref password,
            } if username == "service-account" && password == "secret-example"
        ));
        assert!(!basic.contains_key("username"));
        assert!(!basic.contains_key("password"));

        let mut api_key = BTreeMap::from([
            ("token".to_owned(), "secret-example".to_owned()),
            ("family".to_owned(), "resources".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::ApiKey,
                CatalogAuthSettings {
                    token_header: "X-API-Key".to_owned(),
                    token_scheme: "Token".to_owned(),
                    ..CatalogAuthSettings::default()
                },
                &mut api_key
            )
            .unwrap(),
            ResolvedAuth::Header {
                ref name,
                ref value,
            } if name == "X-API-Key" && value == "Token secret-example"
        ));
        assert!(!api_key.contains_key("token"));

        let mut header_api_keys = BTreeMap::from([
            ("api_key".to_owned(), "account-secret".to_owned()),
            ("store_key".to_owned(), "store-secret".to_owned()),
            ("family".to_owned(), "attributes".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::ApiKey,
                CatalogAuthSettings {
                    header_parameters: BTreeMap::from([
                        ("x-api-key".to_owned(), "api_key".to_owned()),
                        ("x-store-key".to_owned(), "store_key".to_owned()),
                    ]),
                    ..CatalogAuthSettings::default()
                },
                &mut header_api_keys
            )
            .unwrap(),
            ResolvedAuth::HeaderParameters { ref parameters }
                if parameters.get("x-api-key").map(String::as_str) == Some("account-secret")
                    && parameters.get("x-store-key").map(String::as_str)
                        == Some("store-secret")
        ));
        assert!(!header_api_keys.contains_key("api_key"));
        assert!(!header_api_keys.contains_key("store_key"));
        assert_eq!(
            header_api_keys.get("family").map(String::as_str),
            Some("attributes")
        );

        let mut query_api_key = BTreeMap::from([
            ("api_token".to_owned(), "token-example".to_owned()),
            ("api_token_secret".to_owned(), "secret-example".to_owned()),
            ("family".to_owned(), "surveys".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::ApiKey,
                CatalogAuthSettings {
                    query_parameters: BTreeMap::from([
                        ("api_token".to_owned(), "api_token".to_owned()),
                        (
                            "api_token_secret".to_owned(),
                            "api_token_secret".to_owned(),
                        ),
                    ]),
                    ..CatalogAuthSettings::default()
                },
                &mut query_api_key
            )
            .unwrap(),
            ResolvedAuth::QueryParameters { ref parameters }
                if parameters.get("api_token").map(String::as_str) == Some("token-example")
                    && parameters.get("api_token_secret").map(String::as_str)
                        == Some("secret-example")
        ));
        assert!(!query_api_key.contains_key("api_token"));
        assert!(!query_api_key.contains_key("api_token_secret"));
        assert_eq!(
            query_api_key.get("family").map(String::as_str),
            Some("surveys")
        );

        let mut body_api_key = BTreeMap::from([
            ("api_token".to_owned(), "token-example".to_owned()),
            ("family".to_owned(), "items".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::ApiKey,
                CatalogAuthSettings {
                    json_body_parameters: BTreeMap::from([(
                        "token".to_owned(),
                        "api_token".to_owned(),
                    )]),
                    ..CatalogAuthSettings::default()
                },
                &mut body_api_key
            )
            .unwrap(),
            ResolvedAuth::JsonBodyParameters { ref parameters }
                if parameters.get("token").map(String::as_str) == Some("token-example")
        ));
        assert!(!body_api_key.contains_key("api_token"));
        assert_eq!(
            body_api_key.get("family").map(String::as_str),
            Some("items")
        );
    }

    #[test]
    fn stored_bearer_auth_scrubs_token_from_connector_config() {
        let mut config = BTreeMap::from([
            ("token".to_owned(), "secret-example".to_owned()),
            ("family".to_owned(), "resources".to_owned()),
        ]);
        assert!(matches!(
            resolved_auth(
                &AuthModel::BearerToken,
                CatalogAuthSettings::default(),
                &mut config
            )
            .unwrap(),
            ResolvedAuth::Bearer { ref token } if token == "secret-example"
        ));
        assert!(!config.contains_key("token"));
        assert_eq!(config.get("family").map(String::as_str), Some("resources"));
    }

    #[derive(Default)]
    struct UnavailableGraph {
        reads: Option<Arc<AtomicUsize>>,
    }

    impl UnavailableGraph {
        fn counting(reads: Arc<AtomicUsize>) -> Self {
            Self { reads: Some(reads) }
        }

        fn record_read(&self) {
            if let Some(reads) = &self.reads {
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    struct FixtureSourceRuntimeSync;

    #[async_trait]
    impl source_runtime_sync::SourceRuntimeSyncAuthority for FixtureSourceRuntimeSync {
        async fn sync(
            &self,
            tenant_id: &TenantId,
            runtime_id: &str,
        ) -> Result<
            source_runtime_sync::SourceRuntimeSyncReceipt,
            source_runtime_sync::SourceRuntimeSyncFailure,
        > {
            if tenant_id.as_str() != "tenant-demo" {
                return Err(source_runtime_sync::SourceRuntimeSyncFailure::new(
                    source_runtime_sync::SourceRuntimeSyncFailureKind::NotFound,
                    "source runtime is not stored",
                ));
            }
            Ok(source_runtime_sync::SourceRuntimeSyncReceipt {
                runtime_id: runtime_id.to_owned(),
                source_id: "fixture".to_owned(),
                family_id: "users".to_owned(),
                graph: cerebro_organizational_graph::GraphWriteReceipt {
                    tenant_id: tenant_id.clone(),
                    graph_revision: 7,
                    delta_digest: "a".repeat(64),
                    entities_upserted: 2,
                    assertions_upserted: 1,
                    assertions_retracted: 0,
                },
            })
        }
    }
    struct UnreachableActionAuthority;

    #[async_trait]
    impl ActionAuthority for UnreachableActionAuthority {
        async fn health(&self) -> Result<(), ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn record_finding_validation(
            &self,
            _receipt: FindingValidationReceipt,
            _committed_at_unix_ms: u64,
        ) -> Result<FindingValidationReceipt, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn get_finding_validation(
            &self,
            _tenant_id: &TenantId,
            _receipt_digest: &ContentDigest,
        ) -> Result<FindingValidationReceipt, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn propose(
            &self,
            _proposal: ActionProposal,
            _committed_at_unix_ms: u64,
        ) -> Result<ActionOperation, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn get(
            &self,
            _tenant_id: &TenantId,
            _operation_id: &ActionOperationId,
        ) -> Result<ActionOperation, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn list(
            &self,
            _tenant_id: &TenantId,
            _limit: usize,
            _page_token: Option<&str>,
        ) -> Result<ActionPage, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn transition(
            &self,
            _tenant_id: &TenantId,
            _operation_id: &ActionOperationId,
            _actor_id: &ActorId,
            _expected_version: u64,
            _command: ActionCommand,
            _committed_at_unix_ms: u64,
        ) -> Result<ActionOperation, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn history(
            &self,
            _tenant_id: &TenantId,
            _operation_id: &ActionOperationId,
        ) -> Result<Vec<ActionEvent>, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn get_dispatch(
            &self,
            _tenant_id: &TenantId,
            _operation_id: &ActionOperationId,
        ) -> Result<ActionDispatch, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn list_open_dispatches(
            &self,
            _tenant_id: &TenantId,
            _limit: usize,
        ) -> Result<ActionDispatchPage, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn claim_due_reconciliation(
            &self,
            _tenant_id: &TenantId,
            _worker_id: &ActorId,
            _claimed_at_unix_ms: u64,
            _lease_expires_at_unix_ms: u64,
        ) -> Result<Option<ActionReconciliationJob>, ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }

        async fn finish_reconciliation(
            &self,
            _tenant_id: &TenantId,
            _operation_id: &ActionOperationId,
            _worker_id: &ActorId,
            _expected_operation_version: u64,
            _finished_at_unix_ms: u64,
            _disposition: ActionReconciliationDisposition,
        ) -> Result<(), ActionStoreError> {
            panic!("spoofed request reached the Action authority")
        }
    }

    fn unavailable() -> ContextError {
        ContextError::BackendUnavailable("test backend is unavailable".to_owned())
    }

    #[async_trait]
    impl AgentGraph for UnavailableGraph {
        async fn health(&self) -> Result<(), ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn revision(&self, _tenant_id: &TenantId) -> Result<u64, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn search(
            &self,
            _tenant_id: &TenantId,
            _query: &str,
            _kinds: &[String],
            _limit: usize,
        ) -> Result<Vec<ContextEntity>, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn get(
            &self,
            _tenant_id: &TenantId,
            _entity_id: &EntityId,
        ) -> Result<ContextEntity, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn resolve(
            &self,
            _tenant_id: &TenantId,
            _key: &str,
        ) -> Result<ContextEntity, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn expand(
            &self,
            _tenant_id: &TenantId,
            _root_id: &EntityId,
            _depth: usize,
            _limit: usize,
        ) -> Result<Neighborhood, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn find_paths(
            &self,
            _tenant_id: &TenantId,
            _from: &EntityId,
            _to: &EntityId,
            _max_depth: usize,
            _limit: usize,
        ) -> Result<Vec<GraphPath>, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn explain(
            &self,
            _tenant_id: &TenantId,
            _assertion_id: &AssertionId,
        ) -> Result<ContextEdge, ContextError> {
            self.record_read();
            Err(unavailable())
        }

        async fn query(
            &self,
            _tenant_id: &TenantId,
            _query: &cerebro_agent_context::FactQuery,
        ) -> Result<cerebro_agent_context::QueryResult, ContextError> {
            self.record_read();
            Err(unavailable())
        }
    }

    fn authenticated(
        mut request: axum::http::request::Builder,
        tenant: &str,
    ) -> axum::http::request::Builder {
        let tenant_id = TenantId::parse(tenant).unwrap();
        let auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        request = request.header(TENANT_AUTH_HEADER, tenant);
        request.header(AUTHORIZATION, format!("Bearer {}", auth.token(&tenant_id)))
    }

    fn action_identity(tenant_id: &str, actor_id: &str) -> AuthenticatedIdentity {
        AuthenticatedIdentity {
            tenant: TenantId::parse(tenant_id).unwrap(),
            actor_id: actor_id.to_owned(),
            actor_label: actor_id.to_owned(),
            display_name: actor_id.to_owned(),
            initials: "AT".to_owned(),
            email: None,
            username: None,
            subject: actor_id.to_owned(),
            groups: Vec::new(),
            roles: Vec::new(),
            scopes: BTreeSet::from([
                "cerebro:actions:write".to_owned(),
                ACTION_PROPOSE_SCOPE.to_owned(),
                FINDING_VALIDATE_SCOPE.to_owned(),
            ]),
            issuer: "https://identity.example".to_owned(),
            audience: "cerebro".to_owned(),
            key_id: "key-one".to_owned(),
        }
    }

    fn action_proposal(tenant_id: &str, proposed_by: &str) -> ActionProposal {
        let definition = cerebro_action_catalog::lookup("endpoint.cerebro.revoke_device").unwrap();
        let mut proposal = ActionProposal {
            operation_id: ActionOperationId::parse("operation:http:one").unwrap(),
            tenant_id: TenantId::parse(tenant_id).unwrap(),
            finding_id: OpaqueId::parse("finding:http:one").unwrap(),
            finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
            finding_validation_receipt_digest: ContentDigest::of_bytes("finding-validation"),
            graph_revision: GraphRevision::new(1).unwrap(),
            action_kind: definition.id.to_owned(),
            action_definition_digest: ContentDigest::parse(definition.definition_digest).unwrap(),
            target_id: OpaqueId::parse("grant:http:one").unwrap(),
            expected_effects: vec![ActionEffect {
                target_id: OpaqueId::parse("grant:http:one").unwrap(),
                effect_kind: definition.effect.to_owned(),
                expected_state_digest: ContentDigest::of_bytes("expected"),
            }],
            rollback_ref: OpaqueId::parse("rollback:http:one").unwrap(),
            idempotency_key: OpaqueId::parse("idempotency:http:one").unwrap(),
            simulation_digest: ContentDigest::of_bytes("simulation"),
            verification_plan_digest: ContentDigest::of_bytes("verification-plan"),
            proposed_by: ActorId::parse(proposed_by).unwrap(),
            proposed_at_unix_ms: 1,
            proposal_expires_at_unix_ms: u64::MAX,
            proposal_digest: ContentDigest::of_bytes("placeholder"),
        };
        proposal.bind_computed_digest().unwrap();
        proposal
    }

    fn finding_validation(tenant_id: &str, validated_by: &str) -> FindingValidationReceipt {
        let policy = policy_definitions().first().expect("generated policy");
        let mut receipt = FindingValidationReceipt {
            tenant_id: TenantId::parse(tenant_id).unwrap(),
            finding_id: OpaqueId::parse("finding:http:one").unwrap(),
            finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
            graph_revision: GraphRevision::new(1).unwrap(),
            policy_id: policy.id.to_owned(),
            policy_definition_digest: ContentDigest::parse(policy.definition_digest).unwrap(),
            decision: cerebro_platform_sdk::FindingValidationDecision::Confirmed,
            evidence_digests: vec![ContentDigest::of_bytes("finding-evidence")],
            validated_by: ActorId::parse(validated_by).unwrap(),
            validated_at_unix_ms: 1,
            expires_at_unix_ms: u64::MAX,
            receipt_digest: ContentDigest::of_bytes("placeholder"),
        };
        receipt.bind_computed_digest().unwrap();
        receipt
    }

    fn context_entity(
        entity_id: &str,
        agent_key: &str,
        entity_kind: &str,
        label: &str,
    ) -> ContextEntity {
        ContextEntity {
            entity_id: EntityId::parse(entity_id).unwrap(),
            agent_key: agent_key.to_owned(),
            entity_kind: entity_kind.to_owned(),
            authority: serde_json::Value::Null,
            label: label.to_owned(),
            properties: BTreeMap::new(),
        }
    }

    fn product_fixture() -> (String, TenantId, Neighborhood) {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let root_urn = "urn:cerebro:tenant-a:directory_user:alice".to_owned();
        let root = context_entity("identity-alice", &root_urn, "identity", "Alice");
        let mut neighbor = context_entity(
            "repository-cerebro",
            "urn:cerebro:tenant-a:repository:writer/cerebro",
            "repository",
            "writer/cerebro",
        );
        neighbor
            .properties
            .insert("entity_type".to_owned(), "source.repository".to_owned());
        let edge = ContextEdge {
            assertion_id: AssertionId::parse("assertion-access").unwrap(),
            from: root.entity_id.clone(),
            relation: "can_access".to_owned(),
            to: neighbor.entity_id.clone(),
            source_runtime_id: "github-prod".to_owned(),
            application_workspace_id: String::new(),
            identity_binding: false,
        };
        (
            root_urn,
            tenant.clone(),
            Neighborhood {
                tenant_id: tenant,
                graph_revision: 7,
                root,
                entities: vec![neighbor],
                edges: vec![edge],
                truncated: false,
            },
        )
    }

    #[test]
    fn tenant_auth_matches_the_go_client_test_vector() {
        let auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(
            auth.token(&tenant),
            "34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6"
        );
    }

    #[test]
    fn tenant_auth_rejects_short_secrets_and_cross_tenant_tokens() {
        assert!(TenantRequestAuth::new("too-short".to_owned()).is_err());
        let auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        let tenant_a = TenantId::parse("tenant-a").unwrap();
        let tenant_b = TenantId::parse("tenant-b").unwrap();
        assert!(auth.verify(&tenant_a, &auth.token(&tenant_a)));
        assert!(!auth.verify(&tenant_b, &auth.token(&tenant_a)));
    }

    #[test]
    fn tenant_auth_rejects_malformed_tags_without_panicking() {
        let auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        for token in [
            "",
            "0",
            "00",
            "g4b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6",
            "34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d",
            "34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d60",
        ] {
            assert!(!auth.verify(&tenant, token), "token {token:?} was accepted");
        }
    }

    #[test]
    fn source_collection_requires_consistent_status_counts_and_sorted_families() {
        let mut request = SourceCollectionRequest {
            collection_id: "collection-one".to_owned(),
            tenant_id: "tenant-demo".to_owned(),
            source_id: "box".to_owned(),
            source_runtime_id: "box-runtime".to_owned(),
            started_at_unix_ms: 100,
            completed_at_unix_ms: 200,
            status: "complete".to_owned(),
            incompleteness_reasons: Vec::new(),
            expected_family_ids: vec!["content_assets".to_owned(), "users".to_owned()],
            observed_family_ids: vec!["content_assets".to_owned()],
            pages_read: 1,
            records_scanned: 2,
            records_accepted: 2,
            records_rejected: 0,
            entities_projected: 2,
            links_projected: 1,
        };
        assert!(validate_source_collection(&request).is_ok());

        request.status = "incomplete".to_owned();
        assert!(validate_source_collection(&request).is_err());
        request.incompleteness_reasons = vec!["next_cursor_present".to_owned()];
        assert!(validate_source_collection(&request).is_ok());
        request.observed_family_ids = vec!["users".to_owned(), "content_assets".to_owned()];
        assert!(validate_source_collection(&request).is_err());
    }

    #[test]
    fn legacy_projection_rejects_cross_scope_records() {
        let tenant_id = TenantId::parse("tenant-demo").unwrap();
        let mut request = LegacyProjectionRequest {
            tenant_id: tenant_id.as_str().to_owned(),
            source_runtime_id: "box-runtime".to_owned(),
            source_id: "box".to_owned(),
            family_id: "content_assets".to_owned(),
            event_id: "event-one".to_owned(),
            observed_at_unix_ms: 100,
            append_log_committed: true,
            delta: LegacyProjectionDelta {
                entities: vec![LegacyEntityDeltaRecord {
                    urn: "urn:cerebro:tenant-demo:asset:one".to_owned(),
                    tenant_id: tenant_id.as_str().to_owned(),
                    application_workspace_id: "workspace-a".to_owned(),
                    source_id: "box".to_owned(),
                    runtime_id: "box-runtime".to_owned(),
                    entity_type: "box.asset".to_owned(),
                    label: "One".to_owned(),
                    attributes: BTreeMap::new(),
                }],
                links: Vec::new(),
                entity_retractions: Vec::new(),
                link_retractions: Vec::new(),
                cleanup_requests: Vec::new(),
            },
        };
        assert!(validate_legacy_projection(&tenant_id, &request).is_ok());
        request.delta.entities[0].application_workspace_id = "w".repeat(128);
        assert!(validate_legacy_projection(&tenant_id, &request).is_ok());
        request.delta.entities[0].application_workspace_id = "w".repeat(129);
        assert!(validate_legacy_projection(&tenant_id, &request).is_err());
        request.delta.entities[0].application_workspace_id = "workspace-a".to_owned();
        request.delta.entities[0].tenant_id = "tenant-other".to_owned();
        assert!(validate_legacy_projection(&tenant_id, &request).is_err());
    }

    #[test]
    fn product_urn_parser_accepts_supported_cerebro_shapes() {
        assert_eq!(
            product_urn_tenant("urn:cerebro:tenant-a:asset:database"),
            Some("tenant-a")
        );
        assert_eq!(
            product_urn_tenant(
                "urn:cerebro:tenant-a:runtime:github-prod:repository:writer/cerebro"
            ),
            Some("tenant-a")
        );
        assert_eq!(
            product_urn_tenant("urn:cerebro:tenant-a:aws_resource:arn:aws:s3:::bucket"),
            Some("tenant-a")
        );
    }

    #[test]
    fn product_urn_parser_rejects_every_missing_scope_component() {
        for value in [
            "",
            "asset",
            "urn:cerebro",
            "urn:cerebro:tenant-a",
            "urn:cerebro:tenant-a:asset",
            "urn:other:tenant-a:asset:id",
            "urn:cerebro::asset:id",
            "urn:cerebro:tenant-a::id",
            "urn:cerebro:tenant-a:asset:",
            "urn:cerebro: tenant-a:asset:id",
            "urn:cerebro:tenant-a:asset: id",
            "urn:cerebro:tenant-a:asset:line\nbreak",
            "urn:cerebro:tenant-a:runtime:runtime-id:asset",
            "urn:cerebro:tenant-a:runtime::asset:id",
        ] {
            assert_eq!(product_urn_tenant(value), None, "{value:?} was accepted");
        }
    }

    #[test]
    fn product_neighborhood_limit_has_a_small_fixed_ceiling() {
        assert_eq!(normalize_product_neighborhood_limit(None), 10);
        assert_eq!(normalize_product_neighborhood_limit(Some(0)), 1);
        assert_eq!(normalize_product_neighborhood_limit(Some(1)), 1);
        assert_eq!(normalize_product_neighborhood_limit(Some(49)), 49);
        assert_eq!(normalize_product_neighborhood_limit(Some(50)), 50);
        assert_eq!(normalize_product_neighborhood_limit(Some(51)), 50);
        assert_eq!(normalize_product_neighborhood_limit(Some(u32::MAX)), 50);
    }

    #[test]
    fn product_neighborhood_preserves_the_exact_web_contract() {
        let (root_urn, tenant, neighborhood) = product_fixture();
        let product = product_neighborhood(&root_urn, &tenant, neighborhood).unwrap();
        assert_eq!(
            product.root,
            ProductNeighborhoodNode {
                urn: root_urn.clone(),
                entity_type: "identity".to_owned(),
                label: "Alice".to_owned(),
            }
        );
        assert_eq!(
            product.neighbors,
            vec![ProductNeighborhoodNode {
                urn: "urn:cerebro:tenant-a:repository:writer/cerebro".to_owned(),
                entity_type: "source.repository".to_owned(),
                label: "writer/cerebro".to_owned(),
            }]
        );
        assert_eq!(
            product.relations,
            vec![ProductNeighborhoodRelation {
                from_urn: root_urn,
                relation: "can_access".to_owned(),
                to_urn: "urn:cerebro:tenant-a:repository:writer/cerebro".to_owned(),
                attributes: BTreeMap::from([(
                    "source_runtime_id".to_owned(),
                    "github-prod".to_owned(),
                )]),
            }]
        );
    }

    #[test]
    fn product_neighborhood_marks_identity_bindings() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.edges[0].relation = "represents".to_owned();
        neighborhood.edges[0].identity_binding = true;
        let product = product_neighborhood(&root_urn, &tenant, neighborhood).unwrap();
        assert_eq!(
            product.relations[0].attributes,
            BTreeMap::from([
                ("identity_binding".to_owned(), "true".to_owned()),
                ("source_runtime_id".to_owned(), "github-prod".to_owned()),
            ])
        );
    }

    #[test]
    fn product_neighborhood_deduplicates_semantically_identical_relations() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        let mut duplicate = neighborhood.edges[0].clone();
        duplicate.assertion_id = AssertionId::parse("assertion-access-duplicate").unwrap();
        duplicate.source_runtime_id = "github-replay".to_owned();
        neighborhood.edges.push(duplicate);
        let product = product_neighborhood(&root_urn, &tenant, neighborhood).unwrap();
        assert_eq!(product.relations.len(), 1);
        assert_eq!(
            product.relations[0].attributes["source_runtime_id"],
            "github-prod"
        );
    }

    #[test]
    fn product_neighborhood_rejects_a_cross_tenant_result() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.tenant_id = TenantId::parse("tenant-b").unwrap();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_a_cross_tenant_root_key() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.root.agent_key = "urn:cerebro:tenant-b:directory_user:alice".to_owned();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_a_different_same_tenant_root_key() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.root.agent_key = "urn:cerebro:tenant-a:directory_user:bob".to_owned();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_a_cross_tenant_neighbor_key() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.entities[0].agent_key =
            "urn:cerebro:tenant-b:repository:writer/cerebro".to_owned();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_duplicate_product_keys() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        let mut duplicate = neighborhood.entities[0].clone();
        duplicate.entity_id = EntityId::parse("repository-other").unwrap();
        neighborhood.entities.push(duplicate);
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_root_repeated_as_a_neighbor() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.entities.push(neighborhood.root.clone());
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_edges_with_missing_endpoints() {
        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.edges[0].to = EntityId::parse("missing").unwrap();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));

        let (root_urn, tenant, mut neighborhood) = product_fixture();
        neighborhood.edges[0].from = EntityId::parse("missing").unwrap();
        assert!(matches!(
            product_neighborhood(&root_urn, &tenant, neighborhood),
            Err(ContextError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn product_neighborhood_rejects_invalid_entity_metadata() {
        for invalid in ["", " ", " repository", "repository\nadmin"] {
            let (root_urn, tenant, mut neighborhood) = product_fixture();
            neighborhood.entities[0].entity_kind = invalid.to_owned();
            neighborhood.entities[0].properties.clear();
            assert!(
                matches!(
                    product_neighborhood(&root_urn, &tenant, neighborhood),
                    Err(ContextError::BackendUnavailable(_))
                ),
                "entity kind {invalid:?} was accepted"
            );
        }
        for invalid in ["", " ", " writer/cerebro", "writer\ncerebro"] {
            let (root_urn, tenant, mut neighborhood) = product_fixture();
            neighborhood.entities[0].label = invalid.to_owned();
            assert!(
                matches!(
                    product_neighborhood(&root_urn, &tenant, neighborhood),
                    Err(ContextError::BackendUnavailable(_))
                ),
                "entity label {invalid:?} was accepted"
            );
        }
    }

    #[test]
    fn product_neighborhood_rejects_invalid_edge_metadata() {
        for invalid in ["", " ", " can_access", "can\naccess"] {
            let (root_urn, tenant, mut neighborhood) = product_fixture();
            neighborhood.edges[0].relation = invalid.to_owned();
            assert!(
                matches!(
                    product_neighborhood(&root_urn, &tenant, neighborhood),
                    Err(ContextError::BackendUnavailable(_))
                ),
                "relation {invalid:?} was accepted"
            );
        }
        for invalid in ["", " ", " github-prod", "github\nprod"] {
            let (root_urn, tenant, mut neighborhood) = product_fixture();
            neighborhood.edges[0].source_runtime_id = invalid.to_owned();
            assert!(
                matches!(
                    product_neighborhood(&root_urn, &tenant, neighborhood),
                    Err(ContextError::BackendUnavailable(_))
                ),
                "source runtime {invalid:?} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn product_neighborhood_route_is_served_entirely_by_rust() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let root_urn = format!("urn:cerebro:tenant-demo:organizational_entity:{root_id}");
        let response = router(graph)
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri(format!(
                        "/platform/graph/neighborhood?root_urn={root_urn}&limit=10"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["root"]["urn"], root_urn);
        assert_eq!(body["neighbors"].as_array().unwrap().len(), 1);
        assert_eq!(body["relations"].as_array().unwrap().len(), 1);
        assert_eq!(body["relations"][0]["relation"], "represents");
        assert_eq!(
            body["relations"][0]["attributes"]["identity_binding"],
            "true"
        );
    }

    #[tokio::test]
    async fn product_neighborhood_route_rejects_missing_auth_and_cross_tenant_auth() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let uri = format!(
            "/platform/graph/neighborhood?root_urn=urn:cerebro:tenant-demo:organizational_entity:{root_id}"
        );
        let app = router(graph);
        let missing = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let cross_tenant = app
            .oneshot(
                authenticated(Request::builder(), "tenant-other")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_tenant.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn graph_provenance_route_is_served_entirely_by_rust() {
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/graph/provenance"),
            "cerebro:read"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/graph/provenance"),
            "graph_provenance"
        );
        let (graph, _, root_id) = demo_graph().unwrap();
        let root_urn = format!("urn:cerebro:tenant-demo:organizational_entity:{root_id}");
        let response = router(graph)
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri(format!("/v1/graph/provenance?urn={root_urn}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["urn"], root_urn);
        assert_eq!(body["tenant_id"], "tenant-demo");
        assert_eq!(body["projection_class"], "durable_state");
        assert_eq!(body["projection_reason"], "projected_current_state");
        assert_eq!(body["provenance"]["surface"], "graph-provenance");
        assert_eq!(body["provenance"]["scope"], "tenant-demo");
        assert_eq!(body["provenance"]["citation_status"], "valid");
        assert_eq!(body["provenance"]["source_urns"][0], root_urn);
    }

    #[tokio::test]
    async fn graph_provenance_route_accepts_the_root_urn_query_alias() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let root_urn = format!("urn:cerebro:tenant-demo:organizational_entity:{root_id}");
        let response = router(graph)
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri(format!("/v1/graph/provenance?root_urn={root_urn}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn graph_provenance_route_rejects_bad_auth_bad_urns_and_missing_entities() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let root_urn = format!("urn:cerebro:tenant-demo:organizational_entity:{root_id}");
        let app = router(graph);

        let missing_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/graph/provenance?urn={root_urn}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        let cross_tenant = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-other")
                    .uri(format!("/v1/graph/provenance?urn={root_urn}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_tenant.status(), StatusCode::FORBIDDEN);

        for invalid in ["", "urn=urn:cerebro:tenant-demo:asset", "urn=not-a-urn"] {
            let response = app
                .clone()
                .oneshot(
                    authenticated(Request::builder(), "tenant-demo")
                        .uri(format!("/v1/graph/provenance?{invalid}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "query {invalid:?} was accepted"
            );
        }

        let missing_entity = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri("/v1/graph/provenance?urn=urn:cerebro:tenant-demo:okta.user:missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_entity.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn product_neighborhood_route_rejects_scope_mismatch_before_graph_read() {
        let root_urn = "urn:cerebro:tenant-demo:asset:one";
        let graph_reads = Arc::new(AtomicUsize::new(0));
        let app = router_with_backend(
            Arc::new(UnavailableGraph::counting(graph_reads.clone())),
            None,
            None,
            PlatformStores::default(),
            ActionBackends::default(),
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
            None,
        );
        for request in [
            authenticated(Request::builder(), "tenant-demo")
                .uri(format!(
                    "/platform/graph/neighborhood?root_urn={root_urn}&workspace_id=workspace-a"
                ))
                .body(Body::empty())
                .unwrap(),
            authenticated(Request::builder(), "tenant-demo")
                .header(WORKSPACE_AUTH_HEADER, "workspace-a")
                .uri(format!("/platform/graph/neighborhood?root_urn={root_urn}"))
                .body(Body::empty())
                .unwrap(),
            authenticated(Request::builder(), "tenant-demo")
                .uri(format!(
                    "/platform/graph/neighborhood?root_urn={root_urn}&tenant_id=tenant-other"
                ))
                .body(Body::empty())
                .unwrap(),
            authenticated(Request::builder(), "tenant-demo")
                .uri(format!(
                    "/platform/graph/neighborhood?root_urn={root_urn}&tenant_id=tenant-other&workspace_id=workspace-a"
                ))
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(graph_reads.load(Ordering::Relaxed), 0);
        }

        let matching_tenant = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri(format!(
                        "/platform/graph/neighborhood?root_urn={root_urn}&tenant_id=tenant-demo"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(matching_tenant.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(graph_reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn product_neighborhood_route_distinguishes_bad_roots_from_missing_roots() {
        let (graph, _, _) = demo_graph().unwrap();
        let app = router(graph);
        let malformed = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri("/platform/graph/neighborhood?root_urn=not-a-urn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let missing = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri(
                        "/platform/graph/neighborhood?root_urn=urn:cerebro:tenant-demo:asset:missing",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn product_neighborhood_route_rejects_invalid_query_limits() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let app = router(graph);
        for limit in ["-1", "ten", "4294967296"] {
            let response = app
                .clone()
                .oneshot(
                    authenticated(Request::builder(), "tenant-demo")
                        .uri(format!(
                            "/platform/graph/neighborhood?root_urn=urn:cerebro:tenant-demo:organizational_entity:{root_id}&limit={limit}"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "limit {limit:?} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn product_neighborhood_route_surfaces_backend_failure_as_unavailable() {
        let app = router_with_backend(
            Arc::new(UnavailableGraph::default()),
            None,
            None,
            PlatformStores::default(),
            ActionBackends::default(),
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
            None,
        );
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri("/platform/graph/neighborhood?root_urn=urn:cerebro:tenant-demo:asset:one")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_and_bounded_graph_routes_are_served_by_rust() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let app = router(graph);
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let readiness = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness.status(), StatusCode::OK);

        let metrics = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics = axum::body::to_bytes(metrics.into_body(), 1 << 20)
            .await
            .unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        assert!(metrics.contains(
            "cerebro_rust_http_requests_total{operation=\"healthz\",status_class=\"success\"} 1"
        ));
        assert!(
            metrics.contains(
                "cerebro_rust_http_request_duration_seconds_count{operation=\"readyz\"} 1"
            )
        );

        let request = serde_json::json!({
            "tenant_id": "tenant-demo",
            "root_key": root_id.as_str(),
            "depth": 7,
            "limit": 100
        });
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/v1/graph/expand")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = serde_json::json!({
            "tenant_id": "tenant-demo",
            "root_keys": [root_id.as_str()],
            "depth": 1,
            "limit": 100
        });
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/v1/graph/expand-batch")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn ask_query_routes_are_scoped_and_bounded() {
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/ask-queries"),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/ask-queries"),
            "cerebro:write"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::PATCH, "/v1/ask-queries/ask-query-1"),
            "cerebro:write"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::DELETE, "/v1/ask-queries/ask-query-1"),
            "cerebro:write"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/ask-queries"),
            "list_ask_queries"
        );
        assert_eq!(
            bounded_operation(&Method::POST, "/v1/ask-queries"),
            "create_ask_query"
        );
        assert_eq!(
            bounded_operation(&Method::PATCH, "/v1/ask-queries/ask-query-1"),
            "update_ask_query"
        );
        assert_eq!(
            bounded_operation(&Method::DELETE, "/v1/ask-queries/ask-query-1"),
            "delete_ask_query"
        );
    }

    #[tokio::test]
    async fn ask_query_routes_are_tenant_authenticated_and_fail_closed() {
        let (graph, _, _) = demo_graph().unwrap();
        let app = router_with_backend(
            Arc::new(MemoryAgentGraph::new(graph)),
            None,
            None,
            PlatformStores::default(),
            ActionBackends::default(),
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
            None,
        );

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ask-queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        // Without a configured Postgres ledger the routes fail closed, like the
        // Go handlers do when no ask-query store is configured.
        let no_store = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .uri("/v1/ask-queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_store.status(), StatusCode::SERVICE_UNAVAILABLE);

        let create_without_store = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/v1/ask-queries")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Weekly risk","question":"Who owns S3?"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            create_without_store.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn runtime_freshness_route_is_read_scoped_and_bounded() {
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/source-runtimes/freshness"),
            "cerebro:read"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/source-runtimes/freshness"),
            "runtime_freshness"
        );
    }

    #[tokio::test]
    async fn source_runtime_sync_route_is_tenant_bound_and_served_by_rust() {
        assert_eq!(
            oidc_scope_for_route(&Method::PUT, "/v1/source-runtimes/runtime-demo"),
            "cerebro:write"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/source-runtimes/runtime-demo"),
            "cerebro:read"
        );
        assert_eq!(
            bounded_operation(&Method::PUT, "/v1/source-runtimes/runtime-demo"),
            "put_source_runtime"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/source-runtimes/runtime-demo"),
            "get_source_runtime"
        );
        assert_eq!(
            oidc_scope_for_route(
                &Method::GET,
                "/v1/source-runtimes/runtime-demo/invalid-events"
            ),
            "cerebro:read"
        );
        assert_eq!(
            bounded_operation(
                &Method::GET,
                "/v1/source-runtimes/runtime-demo/invalid-events"
            ),
            "list_source_runtime_invalid_events"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/source-runtimes/runtime-demo/sync"),
            "cerebro:write"
        );
        assert_eq!(
            bounded_operation(&Method::POST, "/v1/source-runtimes/runtime-demo/sync"),
            "sync_source_runtime"
        );

        let (graph, _, _) = demo_graph().unwrap();
        let app = router_with_backend(
            Arc::new(MemoryAgentGraph::new(graph)),
            None,
            None,
            PlatformStores {
                source_sync: Some(Arc::new(FixtureSourceRuntimeSync)),
                ..PlatformStores::default()
            },
            ActionBackends::default(),
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
            None,
        );

        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder().method(Method::POST), "tenant-demo")
                    .uri("/v1/source-runtimes/runtime-demo/sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["runtime_id"], "runtime-demo");
        assert_eq!(body["source_id"], "fixture");
        assert_eq!(body["family_id"], "users");
        assert_eq!(body["graph"]["tenant_id"], "tenant-demo");
        assert_eq!(body["graph"]["graph_revision"], 7);

        let cross_tenant = app
            .oneshot(
                authenticated(Request::builder().method(Method::POST), "tenant-other")
                    .uri("/v1/source-runtimes/runtime-demo/sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn source_runtime_sync_failures_keep_operator_actions_distinct() {
        use source_runtime_sync::SourceRuntimeSyncFailureKind;

        for (kind, status, code) in [
            (
                SourceRuntimeSyncFailureKind::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "invalid_source_runtime_sync",
            ),
            (
                SourceRuntimeSyncFailureKind::NotFound,
                StatusCode::NOT_FOUND,
                "source_runtime_not_found",
            ),
            (
                SourceRuntimeSyncFailureKind::Conflict,
                StatusCode::CONFLICT,
                "source_runtime_sync_conflict",
            ),
            (
                SourceRuntimeSyncFailureKind::ProviderUnavailable,
                StatusCode::BAD_GATEWAY,
                "source_provider_unavailable",
            ),
            (
                SourceRuntimeSyncFailureKind::RuntimeUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "source_runtime_sync_unavailable",
            ),
        ] {
            let error = source_runtime_sync_error(
                source_runtime_sync::SourceRuntimeSyncFailure::new(kind, "internal detail"),
            );
            assert_eq!(error.0, status);
            assert_eq!(error.1.0.code, code);
            assert!(!error.1.0.message.contains("internal detail"));
        }
    }

    #[tokio::test]
    async fn committed_event_payloads_cannot_be_submitted_over_http() {
        let app = router(OrganizationalGraph::new());
        let response = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/v1/projections/events")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"append_log_committed":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn lifecycle_requests_have_a_bounded_metrics_operation() {
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/security/lifecycle"),
            "security_lifecycle"
        );
        assert_eq!(
            bounded_operation(
                &Method::POST,
                "/cerebro.v1.SecurityLifecycleService/ListSecurityLifecycle"
            ),
            "security_lifecycle"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/actions"),
            "list_actions"
        );
        assert_eq!(
            bounded_operation(&Method::POST, "/v1/actions"),
            "propose_action"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/action-dispatches"),
            "list_action_dispatches"
        );
        assert_eq!(
            bounded_operation(&Method::GET, "/v1/action-dispatches/operation:one"),
            "get_action_dispatch"
        );
        assert_eq!(
            bounded_operation(
                &Method::POST,
                "/v1/actions/operation:one/provider-observation"
            ),
            "observe_action_provider"
        );
        assert_eq!(
            bounded_operation(&Method::POST, "/v1/action-reconciliation-runs"),
            "run_action_reconciliation"
        );
    }

    #[test]
    fn oidc_authorization_scopes_cover_reads_identity_and_mutations() {
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/me"),
            "identity:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/security/lifecycle"),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/action-definitions"),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/policy-definitions"),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/finding-validations"),
            "cerebro:write"
        );
        assert_eq!(
            oidc_scope_for_route(
                &Method::GET,
                "/v1/finding-validations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/graph/search"),
            "cerebro:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/actions"),
            "cerebro:actions:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/action-dispatches"),
            ACTION_EXECUTE_SCOPE
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/action-dispatches/operation:one"),
            ACTION_EXECUTE_SCOPE
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/actions"),
            "cerebro:actions:write"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/actions/operation:one"),
            "cerebro:actions:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/actions/operation:one/history"),
            "cerebro:actions:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/actions/operation:one/commands"),
            "cerebro:actions:write"
        );
        assert_eq!(
            oidc_scope_for_route(
                &Method::POST,
                "/v1/actions/operation:one/provider-observation"
            ),
            ACTION_RECONCILE_SCOPE
        );
        assert_eq!(
            oidc_scope_for_route(&Method::POST, "/v1/action-reconciliation-runs"),
            ACTION_RECONCILE_SCOPE
        );
    }

    #[test]
    fn action_commands_reject_unknown_fields_and_unvalidated_values() {
        let unknown = serde_json::json!({
            "expected_version": 1,
            "command": {
                "command": "record_simulation",
                "actor_id": "attacker"
            }
        });
        assert!(serde_json::from_value::<ActionTransitionRequest>(unknown).is_err());

        let caller_supplied_completion = serde_json::json!({
            "expected_version": 1,
            "command": {
                "command": "complete",
                "external_receipt_ref": "receipt:one",
                "provider_receipt_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "observed_effect_digest": "not-a-digest",
                "executor_actor_id": "executor:one",
                "executed_at_unix_ms": 10
            }
        });
        assert!(
            serde_json::from_value::<ActionTransitionRequest>(caller_supplied_completion).is_err()
        );

        let invalid_provider_receipt = serde_json::json!({
            "expected_version": 6,
            "command": {
                "command": "record_provider_receipt",
                "external_receipt_ref": "receipt:one",
                "provider_receipt_digest": "not-a-digest",
                "provider_status": "queued",
                "executor_actor_id": "executor:one",
                "observed_at_unix_ms": 10
            }
        });
        assert!(
            serde_json::from_value::<ActionTransitionRequest>(invalid_provider_receipt).is_err()
        );

        let claim_without_expiry = serde_json::json!({
            "expected_version": 1,
            "command": {
                "command": "claim",
                "worker_id": "worker:one",
                "claimed_at_unix_ms": 10
            }
        });
        assert!(
            serde_json::from_value::<ActionTransitionRequest>(claim_without_expiry).is_err(),
            "the HTTP boundary must not create an unbounded claim"
        );

        let valid = serde_json::json!({
            "expected_version": 1,
            "command": {"command": "record_simulation"}
        });
        let request =
            serde_json::from_value::<ActionTransitionRequest>(valid).expect("valid command");
        assert_eq!(request.expected_version, 1);
        assert!(matches!(
            request.command.into_domain().unwrap(),
            ActionCommand::RecordSimulation
        ));
    }

    #[test]
    fn provider_observation_time_advances_within_one_clock_tick() {
        assert_eq!(next_provider_observation_time(42, 42), Some(43));
        assert_eq!(next_provider_observation_time(42, 41), Some(43));
        assert_eq!(next_provider_observation_time(42, 44), Some(44));
        assert_eq!(next_provider_observation_time(u64::MAX, u64::MAX), None);

        let error = require_provider_observation_time(None)
            .expect_err("legacy Action must not be treated as retryable provider work");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1.0.code, "action_not_observable");
    }

    #[tokio::test]
    async fn action_queue_rejects_unknown_and_unbounded_queries_before_storage() {
        assert!(
            serde_json::from_value::<ActionListQuery>(serde_json::json!({
                "limit": 25,
                "tenant_id": "tenant:http:other"
            }))
            .is_err()
        );

        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        for limit in [0, 101, usize::MAX] {
            let error = list_actions(
                State(state.clone()),
                Extension(action_identity("tenant:http:one", "actor:http:one")),
                Query(ActionListQuery {
                    limit: Some(limit),
                    page_token: None,
                }),
            )
            .await
            .expect_err("unbounded query must fail before storage");
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1.0.code, "invalid_action_query");
        }

        let mut execution_identity = action_identity("tenant:http:one", "worker:http:one");
        execution_identity
            .scopes
            .insert(ACTION_EXECUTE_SCOPE.to_owned());
        for limit in [0, 101, usize::MAX] {
            let error = list_action_dispatches(
                State(state.clone()),
                Extension(execution_identity.clone()),
                Query(ActionDispatchQuery { limit: Some(limit) }),
            )
            .await
            .expect_err("unbounded dispatch query must fail before storage");
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1.0.code, "invalid_action_dispatch_query");
        }
    }

    #[tokio::test]
    async fn action_commands_require_separate_signed_authority_scopes() {
        assert_eq!(
            HttpActionCommand::RecordSimulation {}.required_scope(),
            ACTION_SIMULATE_SCOPE
        );
        assert_eq!(
            HttpActionCommand::RequestApproval {}.required_scope(),
            ACTION_PROPOSE_SCOPE
        );
        assert_eq!(
            HttpActionCommand::StartExecution {
                started_at_unix_ms: 10,
            }
            .required_scope(),
            ACTION_EXECUTE_SCOPE
        );
        for internal_command in [
            serde_json::json!({
                "command": "record_provider_receipt",
                "external_receipt_ref": "receipt:one",
                "provider_receipt_digest": ContentDigest::of_bytes("queued"),
                "provider_status": "queued",
                "executor_actor_id": "worker:one",
                "observed_at_unix_ms": 10
            }),
            serde_json::json!({
                "command": "observe_provider_receipt",
                "provider_receipt_digest": ContentDigest::of_bytes("running"),
                "provider_status": "running",
                "observed_at_unix_ms": 11
            }),
            serde_json::json!({"command": "mark_outcome_unknown"}),
            serde_json::json!({
                "command": "complete",
                "external_receipt_ref": "receipt:one",
                "provider_receipt_digest": ContentDigest::of_bytes("succeeded"),
                "observed_effect_digest": ContentDigest::of_bytes("effect"),
                "executor_actor_id": "worker:one",
                "executed_at_unix_ms": 12
            }),
            serde_json::json!({
                "command": "reconcile",
                "observed_effect_digest": ContentDigest::of_bytes("effect"),
                "executor_actor_id": "worker:one",
                "executed_at_unix_ms": 12
            }),
            serde_json::json!({
                "command": "verify",
                "receipt": {
                    "operation_id": "operation:one",
                    "proposal_digest": ContentDigest::of_bytes("proposal"),
                    "observed_effect_digest": ContentDigest::of_bytes("effect"),
                    "receipt": {
                        "verification_id": "verification:one",
                        "executor_actor_id": "worker:one",
                        "verifier_actor_id": "verifier:one",
                        "previous_source_revision": "source:one",
                        "observed_source_revision": "source:two",
                        "effective": true,
                        "evidence_urns": ["urn:cerebro:tenant:observation:one"],
                        "verified_at_unix_ms": 13
                    }
                }
            }),
            serde_json::json!({"command": "reject_verification"}),
            serde_json::json!({"command": "roll_back"}),
        ] {
            assert!(
                serde_json::from_value::<HttpActionCommand>(internal_command).is_err(),
                "provider receipts, effect completion, and verification are internal Rust authority commands"
            );
        }
        assert_eq!(
            HttpActionCommand::RenewClaim {
                renewed_at_unix_ms: 10,
                claim_expires_at_unix_ms: 20,
            }
            .required_scope(),
            ACTION_EXECUTE_SCOPE
        );
        assert_eq!(
            HttpActionCommand::ReleaseExpiredClaim {
                observed_at_unix_ms: 20,
            }
            .required_scope(),
            ACTION_EXECUTE_SCOPE
        );
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let mut identity = action_identity("tenant:http:one", "actor:http:one");
        identity.scopes = BTreeSet::from(["cerebro:actions:write".to_owned()]);
        let error = transition_action_route(
            State(state.clone()),
            Extension(identity.clone()),
            Path("operation:http:one".to_owned()),
            Json(ActionTransitionRequest {
                expected_version: 1,
                command: HttpActionCommand::StartExecution {
                    started_at_unix_ms: 10,
                },
            }),
        )
        .await
        .expect_err("broad write scope must not grant execution authority");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.0.code, "permission_denied");

        let mut executor_identity = action_identity("tenant:http:one", "executor:http:one");
        executor_identity
            .scopes
            .insert(ACTION_EXECUTE_SCOPE.to_owned());
        let error = observe_action_provider_route(
            State(state.clone()),
            Extension(executor_identity.clone()),
            Path("operation:http:one".to_owned()),
        )
        .await
        .expect_err("execution authority must not grant reconciliation authority");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.0.code, "permission_denied");

        let error = run_action_reconciliation(State(state.clone()), Extension(executor_identity))
            .await
            .expect_err("execution authority must not wake reconciliation work");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.0.code, "permission_denied");

        let error = list_action_dispatches(
            State(state.clone()),
            Extension(identity.clone()),
            Query(ActionDispatchQuery { limit: Some(10) }),
        )
        .await
        .expect_err("broad write scope must not expose provider dispatches");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.0.code, "permission_denied");

        let error = get_action_dispatch(
            State(state),
            Extension(identity),
            Path("operation:http:one".to_owned()),
        )
        .await
        .expect_err("broad write scope must not expose a provider dispatch");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.0.code, "permission_denied");
    }

    #[test]
    fn provider_submission_results_become_internal_authority_commands() {
        let actor = ActorId::parse("worker:one").unwrap();
        let receipt = cerebro_action_provider::ProviderReceipt {
            external_id: OpaqueId::parse("provider-action:one").unwrap(),
            status: cerebro_action_provider::ProviderStatus::Queued,
            request_digest: Some(ContentDigest::of_bytes("request")),
            response_digest: ContentDigest::of_bytes("response"),
            updated_at_unix_s: Some(10),
            completed_at_unix_s: None,
        };
        assert!(matches!(
            provider_dispatch_command(Ok(receipt), actor.clone(), 10_000),
            ActionCommand::RecordProviderReceipt {
                external_receipt_ref,
                provider_status,
                executor_actor_id,
                observed_at_unix_ms: 10_000,
                ..
            } if external_receipt_ref.as_str() == "provider-action:one"
                && provider_status == "queued"
                && executor_actor_id == actor
        ));
        assert!(matches!(
            provider_dispatch_command(Err(ProviderError::DispatchAmbiguous), actor, 10_000),
            ActionCommand::MarkOutcomeUnknown
        ));
    }

    #[test]
    fn provider_timeouts_use_explicit_bounded_units() {
        assert_eq!(
            parse_provider_timeout("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_provider_timeout("10s").unwrap(),
            Duration::from_secs(10)
        );
        for invalid in ["", "10", "1m", " 10s", "10s "] {
            assert!(parse_provider_timeout(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn start_execution_fails_before_storage_when_rust_provider_is_unconfigured() {
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let mut identity = action_identity("tenant:http:one", "actor:http:one");
        identity.scopes.insert(ACTION_EXECUTE_SCOPE.to_owned());
        identity.scopes.insert(ACTION_RECONCILE_SCOPE.to_owned());
        let error = transition_action_route(
            State(state.clone()),
            Extension(identity.clone()),
            Path("operation:http:one".to_owned()),
            Json(ActionTransitionRequest {
                expected_version: 5,
                command: HttpActionCommand::StartExecution {
                    started_at_unix_ms: 10,
                },
            }),
        )
        .await
        .expect_err("unconfigured Rust provider must fail before touching storage");
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.1.0.code, "action_provider_unavailable");

        let error = observe_action_provider_route(
            State(state),
            Extension(identity),
            Path("operation:http:one".to_owned()),
        )
        .await
        .expect_err("unconfigured Rust provider observation must fail before storage");
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.1.0.code, "action_provider_unavailable");
    }

    #[tokio::test]
    async fn action_proposals_reject_spoofed_tenants_and_actors_before_storage() {
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let identity = action_identity("tenant:http:one", "actor:http:one");

        for proposal in [
            action_proposal("tenant:http:other", "actor:http:one"),
            action_proposal("tenant:http:one", "actor:http:other"),
        ] {
            let error = propose_action(
                State(state.clone()),
                Extension(identity.clone()),
                Json(proposal),
            )
            .await
            .expect_err("spoofed proposal must fail");
            assert_eq!(error.0, StatusCode::FORBIDDEN);
            assert_eq!(error.1.0.code, "permission_denied");
        }
    }

    #[tokio::test]
    async fn action_proposals_reject_unregistered_or_tampered_definitions_before_storage() {
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let identity = action_identity("tenant:http:one", "actor:http:one");
        let definition = cerebro_action_catalog::lookup("endpoint.cerebro.revoke_device").unwrap();

        let mut malformed = action_proposal("tenant:http:one", "actor:http:one");
        malformed.proposed_at_unix_ms = 0;
        let error = propose_action(
            State(state.clone()),
            Extension(identity.clone()),
            Json(malformed),
        )
        .await
        .expect_err("malformed proposal must fail before catalog classification");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1.0.code, "invalid_action");

        let mut unknown = action_proposal("tenant:http:one", "actor:http:one");
        unknown.action_kind = "endpoint.attacker.erase_device".to_owned();
        unknown.bind_computed_digest().unwrap();

        let mut wrong_digest = action_proposal("tenant:http:one", "actor:http:one");
        wrong_digest.action_definition_digest = ContentDigest::of_bytes("attacker definition");
        wrong_digest.bind_computed_digest().unwrap();

        let mut wrong_effect = action_proposal("tenant:http:one", "actor:http:one");
        wrong_effect.expected_effects[0].effect_kind = "grant_device_access".to_owned();
        wrong_effect.bind_computed_digest().unwrap();

        let mut wrong_target = action_proposal("tenant:http:one", "actor:http:one");
        wrong_target.expected_effects[0].target_id = OpaqueId::parse("device:http:other").unwrap();
        wrong_target.bind_computed_digest().unwrap();

        for proposal in [unknown, wrong_digest, wrong_effect, wrong_target] {
            let error = propose_action(
                State(state.clone()),
                Extension(identity.clone()),
                Json(proposal),
            )
            .await
            .expect_err("tampered definition must fail before storage");
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1.0.code, "invalid_action_definition");
        }

        let definitions = list_action_definitions().await.0;
        assert!(definitions.iter().any(|candidate| candidate == definition));
        assert!(list_policy_definitions().await.0.len() > 1_000);
    }

    #[tokio::test]
    async fn finding_validation_rejects_unknown_or_tampered_policies_before_storage() {
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let identity = action_identity("tenant:http:one", "validator:http:one");

        let mut unknown = finding_validation("tenant:http:one", "validator:http:one");
        unknown.policy_id = "unknown-policy".to_owned();
        unknown.bind_computed_digest().unwrap();

        let mut tampered = finding_validation("tenant:http:one", "validator:http:one");
        tampered.policy_definition_digest = ContentDigest::of_bytes("attacker policy");
        tampered.bind_computed_digest().unwrap();

        for receipt in [unknown, tampered] {
            let error = record_finding_validation(
                State(state.clone()),
                Extension(identity.clone()),
                Json(receipt),
            )
            .await
            .expect_err("unregistered policy must fail before storage");
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1.0.code, "invalid_policy_definition");
        }
    }

    #[tokio::test]
    async fn finding_validation_rejects_spoofed_identity_before_storage() {
        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            action_providers: ActionProviders::default(),
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            lifecycle_projection: None,
            catalog_summary: None,
            projection: None,
            runtime_ledger: None,
            source_sync: None,
            metrics: PlatformMetrics::default(),
        };
        let identity = action_identity("tenant:http:one", "validator:http:one");

        for receipt in [
            finding_validation("tenant:http:other", "validator:http:one"),
            finding_validation("tenant:http:one", "validator:http:other"),
        ] {
            let error = record_finding_validation(
                State(state.clone()),
                Extension(identity.clone()),
                Json(receipt),
            )
            .await
            .expect_err("spoofed validation must fail before storage");
            assert_eq!(error.0, StatusCode::FORBIDDEN);
            assert_eq!(error.1.0.code, "permission_denied");
        }

        let error = get_finding_validation(
            State(state),
            Extension(identity),
            Path("not-a-digest".to_owned()),
        )
        .await
        .expect_err("invalid digest must fail before storage");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1.0.code, "invalid_finding_validation_digest");
    }

    #[tokio::test]
    async fn legacy_tenant_auth_does_not_expose_action_authority() {
        let (graph, _, _) = demo_graph().unwrap();
        let app = router(graph);
        let response = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/v1/actions")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn connect_graph_contract_is_tenant_bound_and_served_by_rust() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let app = router(graph);
        let body = serde_json::json!({
            "tenantId": "tenant-demo",
            "query": "",
            "limit": 10
        })
        .to_string();
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/Search")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let error = axum::body::to_bytes(unauthenticated.into_body(), 1024)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&error).unwrap();
        assert_eq!(error["code"], "unauthenticated");

        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/Search")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["graphRevision"], "2");
        assert_eq!(response["entities"].as_array().unwrap().len(), 6);
        assert!(
            response["entities"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entity| entity["agentKey"].as_str().is_some())
        );

        let body = serde_json::json!({
            "tenantId": "tenant-demo",
            "rootKeys": [root_id.as_str()],
            "depth": 1,
            "limit": 10
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/ExpandBatch")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            response["neighborhoods"][root_id.as_str()]["tenantId"],
            "tenant-demo"
        );

        let body = serde_json::json!({
            "tenantId": "tenant-demo",
            "nodes": [
                {"variable": "person", "kinds": ["person"]},
                {"variable": "group", "kinds": ["group"], "keys": ["group-security"]}
            ],
            "edges": [
                {
                    "variable": "membership",
                    "fromVariable": "person",
                    "relation": "member_of",
                    "toVariable": "group"
                }
            ],
            "limit": 10
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/QueryFacts")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["tenantId"], "tenant-demo");
        assert_eq!(response["graphRevision"], "2");
        assert_eq!(response["matches"].as_array().unwrap().len(), 1);
        assert_eq!(
            response["matches"][0]["edges"][0]["edge"]["relation"],
            "member_of"
        );

        let invalid = serde_json::json!({
            "tenantId": "tenant-demo",
            "nodes": [
                {"variable": "person", "kinds": ["person"]},
                {"variable": "group", "kinds": ["group"]}
            ],
            "edges": [
                {
                    "variable": "membership",
                    "fromVariable": "person",
                    "relation": "raw_cypher_escape",
                    "toVariable": "group"
                }
            ],
            "limit": 10
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/QueryFacts")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(invalid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let cross_tenant = serde_json::json!({
            "tenantId": "tenant-other",
            "nodes": [{"variable": "person", "kinds": ["person"]}],
            "limit": 10
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/QueryFacts")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(cross_tenant))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let unbounded = serde_json::json!({
            "tenantId": "tenant-demo",
            "nodes": [{"variable": "person", "kinds": ["person"]}],
            "limit": 501
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/QueryFacts")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(unbounded))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let unspecified_direction = serde_json::json!({
            "tenantId": "tenant-demo",
            "nodes": [{"variable": "person", "kinds": ["person"]}],
            "absentEdges": [{
                "boundVariable": "person",
                "relation": "member_of",
                "otherKinds": ["group"]
            }],
            "limit": 10
        })
        .to_string();
        let response = app
            .oneshot(
                authenticated(Request::builder(), "tenant-demo")
                    .method("POST")
                    .uri("/cerebro.graph.v1.OrganizationalGraphService/QueryFacts")
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(Body::from(unspecified_direction))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn readiness_fails_without_breaking_process_liveness() {
        let app = router_with_backend(
            Arc::new(UnavailableGraph::default()),
            None,
            None,
            PlatformStores::default(),
            ActionBackends::default(),
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
            None,
        );
        let liveness = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(liveness.status(), StatusCode::OK);

        let readiness = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn graph_routes_require_tenant_bound_authentication() {
        let (graph, _, root_id) = demo_graph().unwrap();
        let app = router(graph);
        let body = serde_json::json!({
            "tenant_id": "tenant-demo",
            "root_key": root_id.as_str(),
            "depth": 1,
            "limit": 10
        })
        .to_string();
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/graph/expand")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let wrong_tenant = app
            .oneshot(
                authenticated(Request::builder(), "tenant-other")
                    .method("POST")
                    .uri("/v1/graph/expand")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_tenant.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL and Neo4j instances"]
    async fn promoted_box_family_projects_only_through_rust() {
        let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN").unwrap();
        let authority = PostgresLedger::connect_tls(&postgres_dsn).await.unwrap();
        authority.migrate().await.unwrap();
        let store_ledger = PostgresLedger::connect_tls(&postgres_dsn).await.unwrap();
        store_ledger.migrate().await.unwrap();
        let graph = Neo4jProjector::connect(
            &env::var("CEREBRO_TEST_NEO4J_URI").unwrap(),
            &env::var("CEREBRO_TEST_NEO4J_USERNAME").unwrap(),
            &env::var("CEREBRO_TEST_NEO4J_PASSWORD").unwrap(),
        )
        .await
        .unwrap();
        graph.migrate().await.unwrap();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        let tenant_id = format!("platform-cutover-{suffix}");
        for index in 1..=3 {
            authority
                .record_parity(
                    &cerebro_organizational_store::ParityReceipt::compare_scoped(
                        tenant_id.clone(),
                        "box-runtime",
                        "box",
                        "content_assets",
                        format!("corpus-{suffix}-{index}"),
                        "sha256:equal",
                        "sha256:equal",
                        true,
                        index,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let catalog = load_catalog().unwrap();
        authority
            .evaluate_and_promote_projection_authority(
                &catalog,
                &cerebro_organizational_store::ProjectionPromotionRequest::new(
                    tenant_id.clone(),
                    "box",
                    "content_assets",
                    cerebro_organizational_store::CutoverPolicy::new(3, 0).unwrap(),
                    0,
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let runtime = Arc::new(ProjectionRuntime {
            catalog,
            authority,
            store: Mutex::new(DurableGraphStore::new(store_ledger, graph.clone())),
        });
        let resource_urn = format!("urn:cerebro:{tenant_id}:runtime_file:asset-1");
        let response = runtime
            .project_committed_with_intent(
                CommittedSourceEvent::from_input(
                    cerebro_source_runtime_next::CommittedSourceInput {
                        tenant_id: TenantId::parse(tenant_id.clone()).unwrap(),
                        source_runtime_id: SourceRuntimeId::parse("box-runtime").unwrap(),
                        observation_id: ObservationId::parse("event-1").unwrap(),
                        source_id: "box".to_owned(),
                        family_id: "content_assets".to_owned(),
                        event_kind: "box.content_assets".to_owned(),
                        schema_ref: "box/content_assets/v1".to_owned(),
                        observed_at_unix_ms: 100,
                        attributes: BTreeMap::from([
                            ("resource_id".to_owned(), "asset-1".to_owned()),
                            ("resource_name".to_owned(), "Architecture".to_owned()),
                            ("resource_type".to_owned(), "file".to_owned()),
                            ("resource_urn".to_owned(), resource_urn.clone()),
                        ]),
                        payload: serde_json::json!({
                            "id": "asset-1",
                            "name": "Architecture",
                            "type": "file",
                            "resource_urn": resource_urn.clone()
                        }),
                    },
                )
                .unwrap(),
                false,
            )
            .await
            .unwrap();
        assert!(response.projected);
        let tenant = TenantId::parse(tenant_id).unwrap();
        let entity = graph.resolve(&tenant, &resource_urn).await.unwrap();
        assert_eq!(entity.label, "Architecture");
        assert_eq!(entity.properties.get("resource_urn"), Some(&resource_urn));
    }

    #[test]
    fn replay_materializes_shadow_without_promoting_family_authority() {
        assert!(should_materialize(ProjectionAuthority::Legacy, true));
        assert!(!should_materialize(ProjectionAuthority::Legacy, false));
        assert!(should_materialize(ProjectionAuthority::Rust, false));
    }
}
