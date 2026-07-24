#![forbid(unsafe_code)]

mod append_log_consumer;
mod cutover_command;
mod parity_command;
mod rpc;

use std::{collections::BTreeMap, env, error::Error, path::PathBuf, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use cerebro_agent_context::{
    AgentContext, AgentGraph, ContextEntity, ContextError, GraphPath, MemoryAgentGraph,
    Neighborhood,
};
use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::{
    AssertionId, AssertionProvenance, CanonicalIdentity, CollectionId, CollectionReceipt,
    CompleteCollection, Entity, EntityId, EntityKind, GraphAssertion, IdentityBindingAssertion,
    IdentityBindingState, IdentityClaim, IdentityResolutionMethod, ModelError, ObservationId,
    ObservationRef, ProviderIdentity, ProviderKind, RelationKind, RelationshipAssertion,
    SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{
    DurableGraphStore, Neo4jProjector, PostgresLedger, ProjectionAuthority, StoreError,
};
use cerebro_source_catalog::{AuthModel, CatalogSummary, SourceCatalog};
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectedBatch, CollectedScope, CollectionRequest, CommittedSourceEvent,
    GraphMapper, GraphSink, HttpSourceConnector, ResolvedAuth, SourceRecord, SourceRuntime,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

const TENANT_AUTH_HEADER: &str = "x-cerebro-tenant";
const TENANT_AUTH_CONTEXT: &[u8] = b"cerebro-organizational-graph/tenant/v1\0";
const MIN_SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone)]
struct AppState {
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    projection: Option<Arc<ProjectionRuntime>>,
}

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
#[serde(deny_unknown_fields)]
struct ProjectEventRequest {
    tenant_id: String,
    source_runtime_id: String,
    source_id: String,
    family_id: String,
    event_id: String,
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
        Some("serve-neo4j") => serve_neo4j().await,
        Some("serve-neo4j-consumer") => serve_neo4j_consumer().await,
        Some("consume-append-log") => consume_append_log().await,
        Some("migrate-stores") => migrate_stores().await,
        Some("sync-source") => sync_source().await,
        Some("catalog-summary") => catalog_summary(),
        Some("compare-projection") => parity_command::compare_projection().await,
        Some("promote-family") => cutover_command::promote_family().await,
        Some("show-authority") => cutover_command::show_authority().await,
        Some("--help" | "-h") => {
            println!(
                "cerebro-platform <demo|serve|serve-demo|serve-neo4j|serve-neo4j-consumer|consume-append-log|migrate-stores|sync-source|catalog-summary|compare-projection|promote-family|show-authority>"
            );
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

async fn serve_memory(graph: OrganizationalGraph) -> Result<(), Box<dyn Error>> {
    serve(Arc::new(MemoryAgentGraph::new(graph)), None).await
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
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("cerebro Rust platform listening on {bind}");
    axum::serve(
        listener,
        router_with_backend(graph, load_catalog_summary().ok(), projection, tenant_auth),
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
        TenantRequestAuth::new("test-organizational-graph-secret-32-bytes".to_owned()).unwrap(),
    )
}

fn router_with_backend(
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    projection: Option<Arc<ProjectionRuntime>>,
    tenant_auth: TenantRequestAuth,
) -> Router {
    let connect = rpc::router(graph.clone(), catalog_summary.clone(), tenant_auth.clone());
    let protected = Router::new()
        .route("/v1/entities/{entity_id}", get(get_entity))
        .route("/v1/assertions/{assertion_id}", get(explain_assertion))
        .route("/v1/graph/search", post(search))
        .route("/v1/graph/expand", post(expand))
        .route("/v1/graph/expand-batch", post(expand_batch))
        .route("/v1/graph/paths", post(find_paths))
        .route("/v1/projections/events", post(project_event))
        .route("/v1/projections/authority", get(projection_authority))
        .route_layer(middleware::from_fn_with_state(
            tenant_auth,
            authenticate_tenant,
        ));
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/v1/sources/summary", get(source_summary))
        .merge(protected)
        .fallback_service(connect.into_axum_service())
        .with_state(AppState {
            graph,
            catalog_summary,
            projection,
        })
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
    let authority = runtime
        .authority
        .projection_authority(tenant_id.as_str(), &request.source_id, &request.family_id)
        .await
        .map_err(store_error)?;
    if authority.authority == ProjectionAuthority::Legacy {
        return Ok(Json(ProjectEventResponse {
            authority: ProjectionAuthority::Legacy,
            projected: false,
            graph_revision: None,
            entities_upserted: 0,
            assertions_upserted: 0,
        }));
    }
    let source = runtime
        .catalog
        .get(&request.source_id)
        .ok_or_else(|| bad_request("unknown_source", "The source is not in the catalog."))?
        .clone();
    let family = source
        .families()
        .iter()
        .find(|family| family.id() == request.family_id)
        .ok_or_else(|| bad_request("unknown_family", "The source family is not in the catalog."))?;
    let source_runtime_id =
        SourceRuntimeId::parse(request.source_runtime_id).map_err(model_error)?;
    let observation_id = ObservationId::parse(request.event_id.clone()).map_err(model_error)?;
    let collection_id =
        CollectionId::parse(format!("event:{}", request.event_id)).map_err(model_error)?;
    let scope = CollectedScope::NonAuthoritative(
        CollectionReceipt::incremental(
            tenant_id.clone(),
            source_runtime_id,
            collection_id,
            format!("{}.{}", request.source_id, request.family_id),
            request.observed_at_unix_ms,
        )
        .map_err(model_error)?,
    );
    let provider_id = event_provider_id(&request.attributes, &request.event_id);
    let batch = CollectedBatch {
        scope,
        records: vec![SourceRecord {
            observation_id,
            family: request.family_id.clone(),
            provider_kind: format!("{}.{}", request.source_id, family.projection().template()),
            provider_id,
            fields: request.attributes,
            payload: request.payload,
        }],
        next_cursor: None,
    };
    let identity_resolution = runtime
        .authority
        .identity_resolution_snapshot(&tenant_id)
        .await
        .map_err(store_error)?;
    let mapper = CatalogGraphMapper::new(source, env!("CARGO_PKG_VERSION"))
        .map_err(|error| bad_request("projection_mapping_failed", error.to_string()))?
        .with_identity_resolution(identity_resolution);
    let delta = mapper
        .map(&batch)
        .map_err(|error| bad_request("projection_mapping_failed", error.to_string()))?;
    let receipt = runtime
        .store
        .lock()
        .await
        .apply(&batch, delta)
        .await
        .map_err(store_error)?;
    Ok(Json(ProjectEventResponse {
        authority: ProjectionAuthority::Rust,
        projected: true,
        graph_revision: Some(receipt.graph_revision),
        entities_upserted: receipt.entities_upserted,
        assertions_upserted: receipt.assertions_upserted,
    }))
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use cerebro_agent_context::ContextEdge;
    use tower::ServiceExt;

    use super::*;

    const TEST_SHARED_SECRET: &str = "test-organizational-graph-secret-32-bytes";

    struct UnavailableGraph;

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

    #[test]
    fn tenant_auth_matches_the_go_client_test_vector() {
        let auth = TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(
            auth.token(&tenant),
            "34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6"
        );
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

    #[tokio::test]
    async fn connect_graph_contract_is_tenant_bound_and_served_by_rust() {
        let (graph, _, _) = demo_graph().unwrap();
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
    }

    #[tokio::test]
    async fn readiness_fails_without_breaking_process_liveness() {
        let app = router_with_backend(
            Arc::new(UnavailableGraph),
            None,
            None,
            TenantRequestAuth::new(TEST_SHARED_SECRET.to_owned()).unwrap(),
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
        let app = router_with_backend(Arc::new(graph.clone()), None, Some(runtime), tenant_auth);
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
