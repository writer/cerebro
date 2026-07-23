#![forbid(unsafe_code)]

use std::{collections::BTreeMap, env, error::Error, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use cerebro_agent_context::{
    AgentContext, AgentGraph, ContextEntity, ContextError, GraphPath, MemoryAgentGraph,
    Neighborhood,
};
use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_organizational_model::{
    AssertionId, AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity,
    EntityId, EntityKind, GraphAssertion, IdentityBindingAssertion, IdentityBindingState,
    IdentityClaim, IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity,
    ProviderKind, RelationKind, RelationshipAssertion, SourceRuntimeId, TenantId,
};
use cerebro_organizational_store::{DurableGraphStore, Neo4jProjector, PostgresLedger};
use cerebro_source_catalog::{AuthModel, CatalogSummary, SourceCatalog};
use cerebro_source_runtime_next::{
    CatalogGraphMapper, CollectionRequest, HttpSourceConnector, ResolvedAuth, SourceRuntime,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct AppState {
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
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
    root_entity_id: String,
    depth: usize,
    limit: usize,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        None | Some("demo") => demo().await,
        Some("serve") => serve_memory(OrganizationalGraph::new()).await,
        Some("serve-demo") => serve_memory(demo_graph()?.0).await,
        Some("serve-neo4j") => serve_neo4j().await,
        Some("migrate-stores") => migrate_stores().await,
        Some("sync-source") => sync_source().await,
        Some("catalog-summary") => catalog_summary(),
        Some("--help" | "-h") => {
            println!(
                "cerebro-platform <demo|serve|serve-demo|serve-neo4j|migrate-stores|sync-source|catalog-summary>"
            );
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

async fn serve_memory(graph: OrganizationalGraph) -> Result<(), Box<dyn Error>> {
    serve(Arc::new(MemoryAgentGraph::new(graph))).await
}

async fn serve_neo4j() -> Result<(), Box<dyn Error>> {
    let uri = required_env("CEREBRO_NEO4J_URI")?;
    let username = required_env("CEREBRO_NEO4J_USERNAME")?;
    let password = required_env("CEREBRO_NEO4J_PASSWORD")?;
    let graph = Neo4jProjector::connect(&uri, &username, &password).await?;
    graph.migrate().await?;
    serve(Arc::new(graph)).await
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
    let mapper = CatalogGraphMapper::new(source, env!("CARGO_PKG_VERSION"))?;
    let ledger = PostgresLedger::connect_tls(&required_env("CEREBRO_POSTGRES_DSN")?).await?;
    ledger.migrate().await?;
    let projector = connect_neo4j().await?;
    projector.migrate().await?;
    let store = DurableGraphStore::new(ledger, projector);
    let mut runtime = SourceRuntime::new(connector, mapper, store);
    let receipt = runtime
        .sync(CollectionRequest {
            tenant_id: TenantId::parse(required_env("CEREBRO_TENANT_ID")?)?,
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

async fn serve(graph: Arc<dyn AgentGraph>) -> Result<(), Box<dyn Error>> {
    let bind = env::var("CEREBRO_RUST_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("cerebro Rust platform listening on {bind}");
    axum::serve(
        listener,
        router_with_backend(graph, load_catalog_summary().ok()),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
fn router(graph: OrganizationalGraph) -> Router {
    router_with_backend(Arc::new(MemoryAgentGraph::new(graph)), None)
}

fn router_with_backend(
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/sources/summary", get(source_summary))
        .route("/v1/entities/{entity_id}", get(get_entity))
        .route("/v1/assertions/{assertion_id}", get(explain_assertion))
        .route("/v1/graph/search", post(search))
        .route("/v1/graph/expand", post(expand))
        .route("/v1/graph/paths", post(find_paths))
        .with_state(AppState {
            graph,
            catalog_summary,
        })
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        runtime: "rust-organizational-platform",
    })
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
    Path(entity_id): Path<String>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<ContextEntity>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = parse_tenant(query.tenant_id)?;
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
    Json(request): Json<SearchRequest>,
) -> Result<Json<Vec<ContextEntity>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = parse_tenant(request.tenant_id)?;
    state
        .graph
        .search(&tenant_id, &request.query, &request.kinds, request.limit)
        .await
        .map(Json)
        .map_err(context_error)
}

async fn explain_assertion(
    State(state): State<AppState>,
    Path(assertion_id): Path<String>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<cerebro_agent_context::ContextEdge>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = parse_tenant(query.tenant_id)?;
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
    Json(request): Json<ExpandRequest>,
) -> Result<Json<Neighborhood>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = parse_tenant(request.tenant_id)?;
    let root_id = EntityId::parse(request.root_entity_id)
        .map_err(|error| bad_request("invalid_entity_id", error.to_string()))?;
    state
        .graph
        .expand(&tenant_id, &root_id, request.depth, request.limit)
        .await
        .map(Json)
        .map_err(context_error)
}

async fn find_paths(
    State(state): State<AppState>,
    Json(request): Json<PathsRequest>,
) -> Result<Json<PathsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = parse_tenant(request.tenant_id)?;
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

fn bad_request(code: &'static str, message: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { code, message }),
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
        .unwrap_or(env::current_dir()?);
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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

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

        let request = serde_json::json!({
            "tenant_id": "tenant-demo",
            "root_entity_id": root_id.as_str(),
            "depth": 7,
            "limit": 100
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/graph/expand")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
