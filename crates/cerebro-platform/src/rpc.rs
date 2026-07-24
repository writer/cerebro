use std::{future::Future, sync::Arc, time::Duration};

use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, GraphPath as ContextPath, Neighborhood,
};
use cerebro_organizational_model::{AssertionId, EntityId, TenantId};
use cerebro_source_catalog::CatalogSummary;
use connectrpc::{ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult};

use crate::{AUTHORIZATION, TENANT_AUTH_HEADER, TenantRequestAuth};

pub mod proto {
    pub mod cerebro {
        pub mod graph {
            #[allow(clippy::wrong_self_convention, unused_imports)]
            pub mod v1 {
                include!("generated/buffa/cerebro.graph.v1.rs");
            }
        }
    }
}

mod service {
    pub mod cerebro {
        pub mod graph {
            #[allow(clippy::match_single_binding, dead_code)]
            pub mod v1 {
                include!("generated/connect/cerebro.graph.v1.mod.rs");
            }
        }
    }
}

use proto::cerebro::graph::v1::*;
use service::cerebro::graph::v1::{OrganizationalGraphService, OrganizationalGraphServiceExt};

// Bound every durable graph read independently of client-side deadlines.
const GRAPH_RPC_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn router(
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    tenant_auth: TenantRequestAuth,
) -> Router {
    Arc::new(GraphRpc {
        graph,
        catalog_summary,
        tenant_auth,
    })
    .register(Router::new())
}

struct GraphRpc {
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    tenant_auth: TenantRequestAuth,
}

impl GraphRpc {
    fn authorized_tenant(
        &self,
        context: &RequestContext,
        requested: &str,
    ) -> Result<TenantId, ConnectError> {
        let requested = TenantId::parse(requested.to_owned())
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
        let header_tenant = context
            .headers()
            .get(TENANT_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| TenantId::parse(value.to_owned()).ok());
        let token = context
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let Some(header_tenant) = header_tenant
            .filter(|tenant| token.is_some_and(|token| self.tenant_auth.verify(tenant, token)))
        else {
            return Err(ConnectError::unauthenticated(
                "Valid tenant authentication is required.",
            ));
        };
        if requested != header_tenant {
            return Err(ConnectError::permission_denied(
                "The authenticated tenant does not match the requested tenant.",
            ));
        }
        Ok(requested)
    }

    async fn graph_call<T>(
        &self,
        operation: impl Future<Output = Result<T, ContextError>>,
    ) -> Result<T, ConnectError> {
        graph_call_with_timeout(GRAPH_RPC_TIMEOUT, operation).await
    }
}

#[allow(refining_impl_trait)]
impl OrganizationalGraphService for GraphRpc {
    async fn search(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, SearchRequest>,
    ) -> ServiceResult<SearchResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let kinds = request
            .kinds
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect::<Vec<_>>();
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let (entities, graph_revision) = self
            .graph_call(async {
                let entities = self
                    .graph
                    .search(&tenant, request.query, &kinds, limit)
                    .await?;
                let graph_revision = self.graph.revision(&tenant).await?;
                Ok((entities, graph_revision))
            })
            .await?;
        Response::ok(SearchResponse {
            graph_revision,
            entities: entities.into_iter().map(graph_entity).collect(),
            ..Default::default()
        })
    }

    async fn get_entity(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, GetEntityRequest>,
    ) -> ServiceResult<GetEntityResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let entity_id = EntityId::parse(request.entity_id.to_owned())
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
        let (entity, graph_revision) = self
            .graph_call(async {
                let entity = self.graph.get(&tenant, &entity_id).await?;
                let graph_revision = self.graph.revision(&tenant).await?;
                Ok((entity, graph_revision))
            })
            .await?;
        Response::ok(GetEntityResponse {
            graph_revision,
            entity: graph_entity(entity).into(),
            ..Default::default()
        })
    }

    async fn expand(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ExpandRequest>,
    ) -> ServiceResult<ExpandResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let depth = usize::try_from(request.depth)
            .map_err(|_| ConnectError::invalid_argument("depth exceeds usize"))?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let mut neighborhoods = self
            .graph_call(self.graph.expand_many(
                &tenant,
                &[request.root_key.to_owned()],
                depth,
                limit,
            ))
            .await?;
        let neighborhood = neighborhoods
            .remove(request.root_key)
            .ok_or_else(|| ConnectError::not_found("entity was not found"))?;
        Response::ok(expand_response(neighborhood))
    }

    async fn expand_batch(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ExpandBatchRequest>,
    ) -> ServiceResult<ExpandBatchResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let root_keys = request
            .root_keys
            .iter()
            .map(|root_key| (*root_key).to_owned())
            .collect::<Vec<_>>();
        let depth = usize::try_from(request.depth)
            .map_err(|_| ConnectError::invalid_argument("depth exceeds usize"))?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let neighborhoods = self
            .graph_call(self.graph.expand_many(&tenant, &root_keys, depth, limit))
            .await?
            .into_iter()
            .map(|(root_key, neighborhood)| (root_key, expand_response(neighborhood)))
            .collect();
        Response::ok(ExpandBatchResponse {
            neighborhoods,
            ..Default::default()
        })
    }

    async fn find_paths(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, FindPathsRequest>,
    ) -> ServiceResult<FindPathsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let from = EntityId::parse(request.from_entity_id.to_owned())
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
        let to = EntityId::parse(request.to_entity_id.to_owned())
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
        let max_depth = usize::try_from(request.max_depth)
            .map_err(|_| ConnectError::invalid_argument("max_depth exceeds usize"))?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let (paths, graph_revision) = self
            .graph_call(async {
                let paths = self
                    .graph
                    .find_paths(&tenant, &from, &to, max_depth, limit)
                    .await?;
                let graph_revision = self.graph.revision(&tenant).await?;
                Ok((paths, graph_revision))
            })
            .await?;
        Response::ok(FindPathsResponse {
            graph_revision,
            paths: paths.into_iter().map(graph_path).collect(),
            ..Default::default()
        })
    }

    async fn explain_assertion(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ExplainAssertionRequest>,
    ) -> ServiceResult<ExplainAssertionResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let assertion_id = AssertionId::parse(request.assertion_id.to_owned())
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
        let edge = self
            .graph_call(self.graph.explain(&tenant, &assertion_id))
            .await?;
        Response::ok(ExplainAssertionResponse {
            edge: graph_edge(edge).into(),
            ..Default::default()
        })
    }

    async fn get_source_summary(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, GetSourceSummaryRequest>,
    ) -> ServiceResult<GetSourceSummaryResponse> {
        self.authorized_tenant(&context, request.tenant_id)?;
        let summary = self
            .catalog_summary
            .as_ref()
            .ok_or_else(|| ConnectError::unavailable("The source catalog is not loaded."))?;
        Response::ok(GetSourceSummaryResponse {
            sources: count(summary.sources)?,
            families: count(summary.families)?,
            authoritative_sources: count(summary.authoritative_sources)?,
            authoritative_families: count(summary.authoritative_families)?,
            shadow_only_sources: count(summary.shadow_only_sources)?,
            projection_classes: summary
                .projection_classes
                .iter()
                .map(|(class, count_value)| {
                    Ok((
                        serde_json::to_value(class)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .ok_or_else(|| {
                                ConnectError::internal("projection class has no wire name")
                            })?,
                        count(*count_value)?,
                    ))
                })
                .collect::<Result<_, ConnectError>>()?,
            ..Default::default()
        })
    }
}

async fn graph_call_with_timeout<T>(
    timeout: Duration,
    operation: impl Future<Output = Result<T, ContextError>>,
) -> Result<T, ConnectError> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| ConnectError::unavailable("The graph backend exceeded its RPC deadline."))?
        .map_err(context_error)
}

fn count(value: usize) -> Result<u64, ConnectError> {
    u64::try_from(value).map_err(|_| ConnectError::internal("catalog count exceeds u64"))
}

fn graph_entity(entity: ContextEntity) -> GraphEntity {
    let authority = entity.authority;
    GraphEntity {
        entity_id: entity.entity_id.to_string(),
        agent_key: entity.agent_key,
        entity_kind: entity.entity_kind,
        label: entity.label,
        authority: authority
            .get("authority")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
            .to_owned(),
        source_runtime_id: authority
            .get("source_runtime_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned(),
        provider_kind: authority
            .get("provider_kind")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned(),
        provider_id: authority
            .get("provider_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned(),
        properties: entity.properties.into_iter().collect(),
        ..Default::default()
    }
}

fn graph_edge(edge: ContextEdge) -> GraphEdge {
    GraphEdge {
        assertion_id: edge.assertion_id.to_string(),
        from_entity_id: edge.from.to_string(),
        relation: edge.relation,
        to_entity_id: edge.to.to_string(),
        source_runtime_id: edge.source_runtime_id,
        identity_binding: edge.identity_binding,
        ..Default::default()
    }
}

fn graph_path(path: ContextPath) -> GraphPath {
    GraphPath {
        entities: path.entities.into_iter().map(graph_entity).collect(),
        edges: path.edges.into_iter().map(graph_edge).collect(),
        ..Default::default()
    }
}

fn expand_response(neighborhood: Neighborhood) -> ExpandResponse {
    ExpandResponse {
        tenant_id: neighborhood.tenant_id.to_string(),
        graph_revision: neighborhood.graph_revision,
        root: graph_entity(neighborhood.root).into(),
        entities: neighborhood
            .entities
            .into_iter()
            .map(graph_entity)
            .collect(),
        edges: neighborhood.edges.into_iter().map(graph_edge).collect(),
        truncated: neighborhood.truncated,
        ..Default::default()
    }
}

fn context_error(error: ContextError) -> ConnectError {
    match error {
        ContextError::EntityNotFound => ConnectError::not_found(error.to_string()),
        ContextError::BackendUnavailable(_) => ConnectError::unavailable(error.to_string()),
        _ => ConnectError::invalid_argument(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::future;

    use connectrpc::ErrorCode;

    use super::*;

    #[tokio::test]
    async fn graph_deadline_returns_protocol_unavailable() {
        let error = graph_call_with_timeout(
            Duration::from_millis(1),
            future::pending::<Result<(), ContextError>>(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(
            error.message.as_deref(),
            Some("The graph backend exceeded its RPC deadline.")
        );
    }
}
