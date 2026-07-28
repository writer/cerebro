#![forbid(unsafe_code)]

mod append_log_consumer;
mod cutover_command;
mod oidc;
mod parity_command;
mod rpc;

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{Method, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cerebro_action_catalog::{
    ActionCatalogError, definitions as action_definitions, lookup as lookup_action,
    validate_proposal,
};
use cerebro_action_provider::{AccessApprovalsClient, AccessApprovalsConfig, ProviderError};
use cerebro_action_store::{
    ActionDispatch, ActionDispatchPage, ActionEvent, ActionPage, ActionStoreError,
    PostgresActionLedger,
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
    DurableGraphStore, Neo4jProjector, PostgresLedger, ProjectionAuthority, StoreError,
};
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{
    ActionOperation, ActionOperationId, ActionProposal, ActionVerificationReceipt, ActorId,
    ContentDigest, DecisionId, DecisionReceipt, FindingValidationReceipt, OpaqueId, VerificationId,
    VerificationReceipt,
};
use cerebro_policy_catalog::{definitions as policy_definitions, validate_finding_receipt};
use cerebro_security_lifecycle::{
    CERTIFICATE_EVENT_KIND, CREDENTIAL_EVENT_KIND, LifecycleQuery, LifecycleState,
    ProjectedResource, SubjectKind, decode_protobuf_observation, project_observation,
    query_records,
};
use cerebro_source_catalog::{AuthModel, CatalogSummary, SourceCatalog};
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectionRequest, CommittedSourceEvent, CommittedSourceInput, GraphMapper,
    GraphSink, HttpSourceConnector, ResolvedAuth, SourceRuntime,
};
use hmac::{Hmac, KeyInit, Mac};
use oidc::{AuthenticatedIdentity, AuthenticationError, OidcAuthenticator, OidcConfiguration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;

const TENANT_AUTH_HEADER: &str = "x-cerebro-tenant";
const TENANT_AUTH_CONTEXT: &[u8] = b"cerebro-organizational-graph/tenant/v1\0";
const MAX_LEGACY_DELTA_RECORDS: usize = 100_000;
const MIN_SHARED_SECRET_BYTES: usize = 32;
const MAX_SECURITY_LIFECYCLE_SCAN: usize = 500;
const ACTION_PROPOSE_SCOPE: &str = "cerebro:actions:propose";
const ACTION_SIMULATE_SCOPE: &str = "cerebro:actions:simulate";
const ACTION_APPROVE_SCOPE: &str = "cerebro:actions:approve";
const ACTION_EXECUTE_SCOPE: &str = "cerebro:actions:execute";
const ACTION_RECONCILE_SCOPE: &str = "cerebro:actions:reconcile";
const ACTION_VERIFY_SCOPE: &str = "cerebro:actions:verify";
const FINDING_VALIDATE_SCOPE: &str = "cerebro:findings:validate";

#[derive(Clone)]
struct AppState {
    access_approvals: Option<AccessApprovalsClient>,
    actions: Option<Arc<dyn ActionAuthority>>,
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    projection: Option<Arc<ProjectionRuntime>>,
    metrics: PlatformMetrics,
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
        "/v1/finding-validations" => "cerebro:write",
        _ if path.starts_with("/v1/finding-validations/") => "cerebro:read",
        "/v1/action-dispatches" => "cerebro:actions:read",
        _ if path.starts_with("/v1/action-dispatches/") => "cerebro:actions:read",
        "/v1/actions" if method == Method::GET => "cerebro:actions:read",
        "/v1/actions" => "cerebro:actions:write",
        _ if path.starts_with("/v1/actions/") && path.ends_with("/provider-observation") => {
            "cerebro:actions:write"
        }
        _ if path.starts_with("/v1/actions/") && path.ends_with("/commands") => {
            "cerebro:actions:write"
        }
        _ if path.starts_with("/v1/actions/") => "cerebro:actions:read",
        "/v1/projections/events"
        | "/v1/projections/legacy-deltas"
        | "/v1/projections/collections" => "cerebro:write",
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
        "/v1/sources/summary" => "source_summary",
        "/platform/graph/neighborhood" => "neighborhood",
        "/v1/graph/search" => "search",
        "/v1/graph/expand" => "expand",
        "/v1/graph/expand-batch" => "expand_batch",
        "/v1/graph/paths" => "paths",
        "/v1/security/lifecycle" => "security_lifecycle",
        "/v1/actions" if method == Method::GET => "list_actions",
        "/v1/actions" => "propose_action",
        "/v1/projections/events" => "project_event",
        "/v1/projections/legacy-deltas" => "record_legacy_projection",
        "/v1/projections/collections" => "record_source_collection",
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
    async fn project_committed(
        &self,
        event: CommittedSourceEvent,
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
        if authority.authority == ProjectionAuthority::Legacy {
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
            authority: ProjectionAuthority::Rust,
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    page_token: Option<String>,
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
}

impl From<HttpLifecycleQuery> for LifecycleQuery {
    fn from(value: HttpLifecycleQuery) -> Self {
        Self {
            subject_kinds: value.subject_kind.into_iter().collect(),
            states: value.state.into_iter().collect(),
            owner_urns: value.owner_urn.into_iter().collect(),
            expires_before: value.expires_before,
            findings_only: value.findings_only,
            limit: value.limit,
            page_token: value.page_token,
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
    limit: Option<u32>,
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
    Verify {
        receipt: HttpActionVerificationReceipt,
    },
    RejectVerification {},
    Fail {},
    RollBack {},
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpActionVerificationReceipt {
    operation_id: String,
    proposal_digest: String,
    observed_effect_digest: String,
    receipt: HttpVerificationReceipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpVerificationReceipt {
    verification_id: String,
    executor_actor_id: String,
    verifier_actor_id: String,
    previous_source_revision: String,
    observed_source_revision: String,
    effective: bool,
    evidence_urns: Vec<String>,
    verified_at_unix_ms: u64,
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
            | Self::Fail {}
            | Self::RollBack {} => ACTION_EXECUTE_SCOPE,
            Self::Verify { .. } | Self::RejectVerification {} => ACTION_VERIFY_SCOPE,
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
            Self::Verify { receipt } => ActionCommand::Verify {
                receipt: receipt.into_domain()?,
            },
            Self::RejectVerification {} => ActionCommand::RejectVerification,
            Self::Fail {} => ActionCommand::Fail,
            Self::RollBack {} => ActionCommand::RollBack,
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

impl HttpActionVerificationReceipt {
    fn into_domain(self) -> Result<ActionVerificationReceipt, String> {
        Ok(ActionVerificationReceipt {
            operation_id: ActionOperationId::parse(self.operation_id)
                .map_err(|error| error.to_string())?,
            proposal_digest: ContentDigest::parse(self.proposal_digest)
                .map_err(|error| error.to_string())?,
            observed_effect_digest: ContentDigest::parse(self.observed_effect_digest)
                .map_err(|error| error.to_string())?,
            receipt: self.receipt.into_domain()?,
        })
    }
}

impl HttpVerificationReceipt {
    fn into_domain(self) -> Result<VerificationReceipt, String> {
        Ok(VerificationReceipt {
            verification_id: VerificationId::parse(self.verification_id)
                .map_err(|error| error.to_string())?,
            executor_actor_id: parse_action_actor(self.executor_actor_id)?,
            verifier_actor_id: parse_action_actor(self.verifier_actor_id)?,
            previous_source_revision: self.previous_source_revision,
            observed_source_revision: self.observed_source_revision,
            effective: self.effective,
            evidence_urns: self.evidence_urns,
            verified_at_unix_ms: self.verified_at_unix_ms,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectEventRequest {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    event_id: String,
    #[serde(default)]
    event_kind: String,
    #[serde(default)]
    schema_ref: String,
    observed_at_unix_ms: i64,
    append_log_committed: bool,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
    #[serde(default)]
    payload: serde_json::Value,
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
    match env::args().nth(1).as_deref() {
        None | Some("demo") => demo().await,
        Some("serve") => serve_memory(OrganizationalGraph::new()).await,
        Some("serve-demo") => serve_memory(demo_graph()?.0).await,
        Some("serve-neo4j-readonly") => serve_neo4j_readonly().await,
        Some("serve-neo4j") => serve_neo4j().await,
        Some("serve-neo4j-consumer") => serve_neo4j_consumer().await,
        Some("consume-append-log") => consume_append_log().await,
        Some("migrate-stores") => migrate_stores().await,
        Some("sync-source") => sync_source().await,
        Some("catalog-summary") => catalog_summary(),
        Some("compare-projection") => parity_command::compare_projection().await,
        Some("evaluate-family") => cutover_command::evaluate_family().await,
        Some("promote-family") => cutover_command::promote_family().await,
        Some("show-authority") => cutover_command::show_authority().await,
        Some("--help" | "-h") => {
            println!(
                "cerebro-platform <demo|serve|serve-demo|serve-neo4j-readonly|serve-neo4j|serve-neo4j-consumer|consume-append-log|migrate-stores|sync-source|catalog-summary|compare-projection|evaluate-family|promote-family|show-authority>"
            );
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

async fn serve_memory(graph: OrganizationalGraph) -> Result<(), Box<dyn Error>> {
    serve(Arc::new(MemoryAgentGraph::new(graph)), None).await
}

async fn serve_neo4j_readonly() -> Result<(), Box<dyn Error>> {
    let graph = Neo4jProjector::connect(
        &required_env("CEREBRO_NEO4J_URI")?,
        &required_env("CEREBRO_NEO4J_USERNAME")?,
        &required_env("CEREBRO_NEO4J_PASSWORD")?,
    )
    .await?;
    serve(Arc::new(graph), None).await
}

async fn serve_neo4j() -> Result<(), Box<dyn Error>> {
    let (graph, projection) = neo4j_runtime().await?;
    serve(Arc::new(graph), Some(projection)).await
}

async fn serve_neo4j_consumer() -> Result<(), Box<dyn Error>> {
    let (graph, projection) = neo4j_runtime().await?;
    let server = serve(Arc::new(graph), Some(projection.clone()));
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

async fn sync_source() -> Result<(), Box<dyn Error>> {
    let catalog = load_catalog()?;
    let source_id = required_env("CEREBRO_SOURCE_ID")?;
    let family_id = required_env("CEREBRO_SOURCE_FAMILY")?;
    let tenant_id = TenantId::parse(required_env("CEREBRO_TENANT_ID")?)?;
    let source = catalog
        .get(&source_id)
        .ok_or_else(|| format!("source {source_id} is not in the catalog"))?
        .clone();
    let auth = resolved_auth(source.auth())?;
    let config = env::var("CEREBRO_SOURCE_CONFIG_JSON")
        .ok()
        .map(|value| serde_json::from_str::<BTreeMap<String, String>>(&value))
        .transpose()?
        .unwrap_or_default();
    let connector = HttpSourceConnector::new(
        source.clone(),
        &family_id,
        &required_env("CEREBRO_SOURCE_BASE_URL")?,
        config,
        auth,
    )?;
    let ledger = PostgresLedger::connect_tls(&required_env("CEREBRO_POSTGRES_DSN")?).await?;
    ledger.migrate().await?;
    let identity_resolution = ledger.identity_resolution_snapshot(&tenant_id).await?;
    let mapper = CatalogGraphMapper::new(source, env!("CARGO_PKG_VERSION"))?
        .with_identity_resolution(identity_resolution);
    let projector = connect_neo4j().await?;
    projector.migrate().await?;
    let store = DurableGraphStore::new(ledger, projector);
    let mut runtime = SourceRuntime::new(connector, mapper, store);
    let receipt = runtime
        .sync(CollectionRequest {
            tenant_id,
            source_runtime_id: SourceRuntimeId::parse(required_env("CEREBRO_SOURCE_RUNTIME_ID")?)?,
            cursor: env::var("CEREBRO_SOURCE_CURSOR").ok(),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

async fn connect_neo4j() -> Result<Neo4jProjector, Box<dyn Error>> {
    Ok(Neo4jProjector::connect(
        &required_env("CEREBRO_NEO4J_URI")?,
        &required_env("CEREBRO_NEO4J_USERNAME")?,
        &required_env("CEREBRO_NEO4J_PASSWORD")?,
    )
    .await?)
}

fn resolved_auth(model: &AuthModel) -> Result<ResolvedAuth, Box<dyn Error>> {
    Ok(match model {
        AuthModel::None => ResolvedAuth::None,
        AuthModel::Basic => ResolvedAuth::Basic {
            username: required_env("CEREBRO_SOURCE_USERNAME")?,
            password: required_env("CEREBRO_SOURCE_PASSWORD")?,
        },
        AuthModel::ApiKey => ResolvedAuth::Header {
            name: required_env("CEREBRO_SOURCE_AUTH_HEADER")?,
            value: required_env("CEREBRO_SOURCE_AUTH_VALUE")?,
        },
        AuthModel::DuoHmac | AuthModel::DuoHmacV5 | AuthModel::Signature | AuthModel::AwsSigV4 => {
            return Err("source auth requires a bespoke Rust connector".into());
        }
        _ => ResolvedAuth::Bearer {
            token: required_env("CEREBRO_SOURCE_TOKEN")?,
        },
    })
}

async fn serve(
    graph: Arc<dyn AgentGraph>,
    projection: Option<Arc<ProjectionRuntime>>,
) -> Result<(), Box<dyn Error>> {
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
    let actions: Option<Arc<dyn ActionAuthority>> = match env::var("CEREBRO_POSTGRES_DSN") {
        Ok(connection_string) => {
            let ledger = PostgresActionLedger::connect_tls(&connection_string).await?;
            ledger.migrate().await?;
            Some(Arc::new(ledger))
        }
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let access_approvals = access_approvals_from_env()?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("cerebro Rust platform listening on {bind}");
    axum::serve(
        listener,
        router_with_backend(
            graph,
            load_catalog_summary().ok(),
            projection,
            actions,
            access_approvals,
            tenant_auth,
            oidc,
        ),
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
        None,
        None,
        TenantRequestAuth::new("test-organizational-graph-secret-32-bytes".to_owned()).unwrap(),
        None,
    )
}

fn router_with_backend(
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    projection: Option<Arc<ProjectionRuntime>>,
    actions: Option<Arc<dyn ActionAuthority>>,
    access_approvals: Option<AccessApprovalsClient>,
    tenant_auth: TenantRequestAuth,
    oidc: Option<OidcAuthenticator>,
) -> Router {
    let platform_metrics = PlatformMetrics::default();
    let connect = rpc::router(graph.clone(), catalog_summary.clone(), tenant_auth.clone());
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
        .route("/v1/security/lifecycle", get(security_lifecycle))
        .route("/v1/projections/events", post(project_event))
        .route(
            "/v1/projections/legacy-deltas",
            post(record_legacy_projection),
        )
        .route(
            "/v1/projections/collections",
            post(record_source_collection),
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
            access_approvals,
            actions,
            graph,
            catalog_summary,
            projection,
            metrics: platform_metrics.clone(),
        })
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

async fn project_event(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Json(request): Json<ProjectEventRequest>,
) -> Result<Json<ProjectEventResponse>, (StatusCode, Json<ErrorResponse>)> {
    let runtime = state.projection.ok_or_else(|| {
        service_unavailable(
            "projection_runtime_unavailable",
            "The organizational projection runtime is not configured.",
        )
    })?;
    if !request.append_log_committed {
        return Err(bad_request(
            "append_log_required",
            "The source event must be committed to the append log before projection.",
        ));
    }
    if request.observed_at_unix_ms <= 0 {
        return Err(bad_request(
            "invalid_observed_at",
            "observed_at_unix_ms must be positive.",
        ));
    }
    let tenant_id = authorized_tenant(&authenticated, request.tenant_id)?;
    let source_id = request.source_id.trim().to_owned();
    let family_id = request.family_id.trim().to_owned();
    let event_kind = if request.event_kind.trim().is_empty() {
        format!("{source_id}.{family_id}")
    } else {
        request.event_kind
    };
    let event = CommittedSourceEvent::from_input(CommittedSourceInput {
        tenant_id,
        source_runtime_id: SourceRuntimeId::parse(request.source_runtime_id)
            .map_err(model_error)?,
        observation_id: ObservationId::parse(request.event_id).map_err(model_error)?,
        source_id,
        family_id,
        event_kind,
        schema_ref: request.schema_ref,
        observed_at_unix_ms: request.observed_at_unix_ms,
        attributes: request.attributes,
        payload: request.payload,
    })
    .map_err(|error| bad_request("invalid_source_event", error.to_string()))?;
    runtime
        .project_committed(event)
        .await
        .map(Json)
        .map_err(|error| match error {
            ProjectionFailure::Invalid(message) => {
                bad_request("projection_mapping_failed", message)
            }
            ProjectionFailure::Store(error) => store_error(error),
        })
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
        let provider = state.access_approvals.clone().ok_or_else(|| {
            service_unavailable(
                "action_provider_unavailable",
                "The access-approvals provider is not configured in the Rust runtime.",
            )
        })?;
        let current = authority
            .get(&identity.tenant, &operation_id)
            .await
            .map_err(action_store_error)?;
        let definition =
            lookup_action(&current.proposal.action_kind).map_err(action_catalog_error)?;
        if definition.provider != "access-approvals" {
            return Err(service_unavailable(
                "action_provider_unavailable",
                "The Action provider is not available in the Rust runtime.",
            ));
        }
        Some(provider)
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
    let Some(provider) = provider else {
        return Ok(Json(operation));
    };

    let dispatch = authority
        .get_dispatch(&identity.tenant, &operation_id)
        .await
        .map_err(action_store_error)?;
    let provider_result = provider.dispatch(&dispatch).await;
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

async fn observe_action_provider_route(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(operation_id): Path<String>,
) -> Result<Json<ActionOperation>, (StatusCode, Json<ErrorResponse>)> {
    require_action_scope(&identity, ACTION_RECONCILE_SCOPE)?;
    let actor_id = authenticated_action_actor(&identity)?;
    let operation_id = ActionOperationId::parse(operation_id)
        .map_err(|error| bad_request("invalid_action_operation_id", error.to_string()))?;
    let provider = state.access_approvals.clone().ok_or_else(|| {
        service_unavailable(
            "action_provider_unavailable",
            "The access-approvals provider is not configured in the Rust runtime.",
        )
    })?;
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
    let dispatch = authority
        .get_dispatch(&identity.tenant, &operation_id)
        .await
        .map_err(action_store_error)?;
    let receipt = provider
        .observe(&dispatch, external_id)
        .await
        .map_err(action_provider_error)?;
    let previous_observation = operation.provider_observed_at_unix_ms.ok_or_else(|| {
        service_unavailable(
            "action_provider_receipt_unavailable",
            "The Action provider receipt has no authority observation time.",
        )
    })?;
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

fn provider_dispatch_command(
    result: Result<cerebro_action_provider::ProviderReceipt, ProviderError>,
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

async fn security_lifecycle(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedTenant>,
    Query(query): Query<HttpLifecycleQuery>,
) -> Result<Json<cerebro_security_lifecycle::QueryResult>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = authenticated.0;
    let resource_kinds = vec!["resource".to_owned()];
    let entities = state
        .graph
        .search(&tenant_id, "", &resource_kinds, MAX_SECURITY_LIFECYCLE_SCAN)
        .await
        .map_err(context_error)?
        .into_iter()
        .map(|entity| ProjectedResource {
            agent_key: entity.agent_key,
            label: entity.label,
            properties: entity.properties,
        })
        .collect();
    let as_of = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| {
            service_unavailable(
                "clock_format_failed",
                format!("Cannot format read time: {error}"),
            )
        })?;
    query_records(&tenant_id, &query.into(), entities, &as_of)
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
    Query(query): Query<ProductNeighborhoodQuery>,
) -> Result<Json<ProductNeighborhood>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = product_urn_tenant(&query.root_urn).ok_or_else(|| {
        bad_request(
            "invalid_root_urn",
            "root_urn must be a tenant-scoped Cerebro URN.",
        )
    })?;
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

fn read_bounded_secret_file(path: &str) -> Result<String, Box<dyn Error>> {
    use std::io::Read as _;

    const MAX_SECRET_FILE_BYTES: usize = 16 * 1_024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_SECRET_FILE_BYTES {
        return Err("access-approvals bearer token file is empty or too large".into());
    }
    let token = String::from_utf8(bytes)?;
    Ok(token
        .strip_suffix("\r\n")
        .or_else(|| token.strip_suffix('\n'))
        .unwrap_or(&token)
        .to_owned())
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
    Ok((graph, tenant, root_id))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        time::{SystemTime, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use cerebro_agent_context::ContextEdge;
    use cerebro_platform_sdk::{ActionEffect, GraphRevision};
    use tower::ServiceExt;

    use super::*;

    const TEST_SHARED_SECRET: &str = "test-organizational-graph-secret-32-bytes";

    struct UnavailableGraph;
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
    }

    fn unavailable() -> ContextError {
        ContextError::BackendUnavailable("test backend is unavailable".to_owned())
    }

    #[async_trait]
    impl AgentGraph for UnavailableGraph {
        async fn health(&self) -> Result<(), ContextError> {
            Err(unavailable())
        }

        async fn revision(&self, _tenant_id: &TenantId) -> Result<u64, ContextError> {
            Err(unavailable())
        }

        async fn search(
            &self,
            _tenant_id: &TenantId,
            _query: &str,
            _kinds: &[String],
            _limit: usize,
        ) -> Result<Vec<ContextEntity>, ContextError> {
            Err(unavailable())
        }

        async fn get(
            &self,
            _tenant_id: &TenantId,
            _entity_id: &EntityId,
        ) -> Result<ContextEntity, ContextError> {
            Err(unavailable())
        }

        async fn resolve(
            &self,
            _tenant_id: &TenantId,
            _key: &str,
        ) -> Result<ContextEntity, ContextError> {
            Err(unavailable())
        }

        async fn expand(
            &self,
            _tenant_id: &TenantId,
            _root_id: &EntityId,
            _depth: usize,
            _limit: usize,
        ) -> Result<Neighborhood, ContextError> {
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
            Err(unavailable())
        }

        async fn explain(
            &self,
            _tenant_id: &TenantId,
            _assertion_id: &AssertionId,
        ) -> Result<ContextEdge, ContextError> {
            Err(unavailable())
        }

        async fn query(
            &self,
            _tenant_id: &TenantId,
            _query: &cerebro_agent_context::FactQuery,
        ) -> Result<cerebro_agent_context::QueryResult, ContextError> {
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
            Arc::new(UnavailableGraph),
            None,
            None,
            None,
            None,
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
            oidc_scope_for_route(&Method::POST, "/v1/projections/events"),
            "cerebro:write"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/actions"),
            "cerebro:actions:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/action-dispatches"),
            "cerebro:actions:read"
        );
        assert_eq!(
            oidc_scope_for_route(&Method::GET, "/v1/action-dispatches/operation:one"),
            "cerebro:actions:read"
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
            "cerebro:actions:write"
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
        ] {
            assert!(
                serde_json::from_value::<HttpActionCommand>(internal_command).is_err(),
                "provider receipts and effect completion are internal Rust authority commands"
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
        assert_eq!(
            HttpActionCommand::RejectVerification {}.required_scope(),
            ACTION_VERIFY_SCOPE
        );

        let (graph, _, _) = demo_graph().unwrap();
        let state = AppState {
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
            Extension(executor_identity),
            Path("operation:http:one".to_owned()),
        )
        .await
        .expect_err("execution authority must not grant reconciliation authority");
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
            access_approvals: None,
            actions: Some(Arc::new(UnreachableActionAuthority)),
            graph: Arc::new(MemoryAgentGraph::new(graph)),
            catalog_summary: None,
            projection: None,
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
        assert_eq!(response["graphRevision"], "1");
        assert_eq!(response["entities"].as_array().unwrap().len(), 4);
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
        assert_eq!(response["graphRevision"], "1");
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
            Arc::new(UnavailableGraph),
            None,
            None,
            None,
            None,
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
        let tenant_auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        let app = router_with_backend(
            Arc::new(graph.clone()),
            None,
            Some(runtime),
            None,
            None,
            tenant_auth,
            None,
        );
        let resource_urn = format!("urn:cerebro:{tenant_id}:runtime_file:asset-1");
        let response = app
            .oneshot(
                authenticated(Request::builder(), &tenant_id)
                    .method("POST")
                    .uri("/v1/projections/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "tenant_id": tenant_id.clone(),
                            "source_runtime_id": "box-runtime",
                            "source_id": "box",
                            "family_id": "content_assets",
                            "event_id": "event-1",
                            "observed_at_unix_ms": 100,
                            "append_log_committed": true,
                            "attributes": {
                                "resource_id": "asset-1",
                                "resource_name": "Architecture",
                                "resource_type": "file",
                                "resource_urn": resource_urn.clone()
                            },
                            "payload": {
                                "id": "asset-1",
                                "name": "Architecture",
                                "type": "file",
                                "resource_urn": resource_urn.clone()
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tenant = TenantId::parse(tenant_id).unwrap();
        let entity = graph.resolve(&tenant, &resource_urn).await.unwrap();
        assert_eq!(entity.label, "Architecture");
        assert_eq!(entity.properties.get("resource_urn"), Some(&resource_urn));
    }
}
