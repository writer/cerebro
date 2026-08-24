use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Arc,
    time::Duration,
};

use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, FactQuery, GraphPath as ContextPath,
    Neighborhood, QueryAbsentEdge as ContextQueryAbsentEdge,
    QueryDirection as ContextQueryDirection, QueryEdge as ContextQueryEdge,
    QueryMatch as ContextQueryMatch, QueryNode as ContextQueryNode,
};
use cerebro_organizational_model::{AssertionId, EntityId, TenantId};
use cerebro_organizational_store::{
    CloudAttackPath as StoreCloudAttackPath, CloudAttackPathCounts as StoreCloudAttackPathCounts,
    CloudAttackPathEdge as StoreCloudAttackPathEdge,
    CloudAttackPathNode as StoreCloudAttackPathNode,
    CloudAttackPathOwnership as StoreCloudAttackPathOwnership,
    CloudAttackPathPage as StoreCloudAttackPathPage,
    EntityCatalogDirection as StoreCatalogDirection, EntityCatalogFilter as StoreCatalogFilter,
    EntityCatalogKindPage as StoreCatalogKindPage, EntityCatalogPage as StoreCatalogPage,
    EntityCatalogRelationCountFilter as StoreCatalogRelationCountFilter,
    EntityCatalogRelationKindPage as StoreCatalogRelationKindPage,
    EntityCatalogRelationPage as StoreCatalogRelationPage,
    ExposureCoverageEntity as StoreExposureEntity, ExposureCoverageProfile as StoreExposureProfile,
    ExposureCoverageQuery as StoreExposureQuery, ExposureCoverageResult as StoreExposureResult,
    Neo4jProjector, PersonAccessPathPage as StorePersonAccessPathPage, StoreError,
};
use cerebro_security_lifecycle::{
    LifecycleQuery, LifecycleState, ProjectedResource, QueryResult as LifecycleQueryResult,
    QuerySource, SubjectKind, SubjectLocator, canonical_resource_urn, finalize_indexed_query,
    prepare_indexed_query, query_records_with_source, resolve_finding_record,
};
use cerebro_source_catalog::CatalogSummary;
use connectrpc::{ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{AUTHORIZATION, TENANT_AUTH_HEADER, TenantRequestAuth};

pub mod proto {
    pub mod cerebro {
        #[allow(
            clippy::derivable_impls,
            clippy::wrong_self_convention,
            unused_imports,
            non_camel_case_types
        )]
        pub mod v1 {
            include!("generated/buffa/cerebro.v1.rs");
        }
        pub mod graph {
            #[allow(
                clippy::derivable_impls,
                clippy::wrong_self_convention,
                unused_imports,
                non_camel_case_types
            )]
            pub mod v1 {
                include!("generated/buffa/cerebro.graph.v1.rs");
            }
        }
    }
}

mod service {
    pub mod cerebro {
        #[allow(clippy::match_single_binding, dead_code)]
        pub mod v1 {
            include!("generated/connect/cerebro.v1.mod.rs");
        }
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
use service::cerebro::v1::{SecurityLifecycleService, SecurityLifecycleServiceExt};

// Bound every durable graph read independently of client-side deadlines.
const GRAPH_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SECURITY_LIFECYCLE_SCAN: usize = 500;
const MAX_IN_MEMORY_CATALOG_SCAN: usize = 500;

pub(crate) fn router(
    graph: Arc<dyn AgentGraph>,
    lifecycle_projection: Option<Arc<Neo4jProjector>>,
    catalog_summary: Option<CatalogSummary>,
    tenant_auth: TenantRequestAuth,
) -> Router {
    let service = Arc::new(GraphRpc {
        graph,
        lifecycle_projection,
        catalog_summary,
        tenant_auth,
    });
    let router = OrganizationalGraphServiceExt::register(Arc::clone(&service), Router::new());
    SecurityLifecycleServiceExt::register(service, router)
}

struct GraphRpc {
    graph: Arc<dyn AgentGraph>,
    lifecycle_projection: Option<Arc<Neo4jProjector>>,
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

    async fn lifecycle_records(
        &self,
        tenant: &TenantId,
        query: &LifecycleQuery,
    ) -> Result<LifecycleQueryResult, ConnectError> {
        if let Some(projection) = self.lifecycle_projection.as_ref() {
            let graph_revision = self.graph_call(self.graph.revision(tenant)).await?;
            let as_of = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|error| {
                    ConnectError::internal(format!("Cannot format read time: {error}"))
                })?;
            let prepared = prepare_indexed_query(tenant, query, &as_of, graph_revision)
                .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
            let indexed = tokio::time::timeout(
                GRAPH_RPC_TIMEOUT,
                projection.query_lifecycle(tenant, &prepared),
            )
            .await
            .map_err(|_| {
                ConnectError::unavailable("Lifecycle projection read exceeded 2 seconds.")
            })?;
            match indexed {
                Ok(page) => {
                    return finalize_indexed_query(tenant, &prepared, page)
                        .map_err(|error| ConnectError::internal(error.to_string()));
                }
                Err(StoreError::LifecycleProjectionUnavailable { .. }) => {}
                Err(error) => return Err(ConnectError::unavailable(error.to_string())),
            }
        }
        let revision_before = self.graph_call(self.graph.revision(tenant)).await?;
        let (entities, scan_truncated): (Vec<_>, bool) = if let Some(locator) =
            query.subject_locator.as_ref()
        {
            let subject_urn = canonical_resource_urn(
                tenant.as_str(),
                locator.subject_kind,
                &locator.authority_id,
                &locator.stable_locator,
            )
            .map_err(|error| ConnectError::invalid_argument(error.to_string()))?;
            match self
                .graph_call(self.graph.resolve(tenant, &subject_urn))
                .await
            {
                Ok(entity) => (vec![entity], false),
                Err(error) if error.code == connectrpc::ErrorCode::NotFound => (Vec::new(), false),
                Err(error) => return Err(error),
            }
        } else {
            let resource_kinds = vec!["resource".to_owned()];
            let entities = self
                .graph_call(self.graph.search(
                    tenant,
                    "",
                    &resource_kinds,
                    MAX_SECURITY_LIFECYCLE_SCAN,
                ))
                .await?;
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
        let revision_after = self.graph_call(self.graph.revision(tenant)).await?;
        let as_of = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| ConnectError::internal(format!("Cannot format read time: {error}")))?;
        query_records_with_source(
            tenant,
            query,
            entities,
            &as_of,
            QuerySource {
                scanned_entities,
                truncated: scan_truncated,
                graph_revision: revision_after,
                graph_changed: revision_before != revision_after,
            },
        )
        .map_err(|error| ConnectError::invalid_argument(error.to_string()))
    }

    async fn in_memory_catalog_page(
        &self,
        tenant: &TenantId,
        filter: &StoreCatalogFilter,
        limit: usize,
        after_agent_key: &str,
    ) -> Result<StoreCatalogPage, ConnectError> {
        validate_in_memory_catalog_request(tenant, filter, after_agent_key)?;
        let revision_before = self.graph_call(self.graph.revision(tenant)).await?;
        if filter.expected_graph_revision != 0 && filter.expected_graph_revision != revision_before
        {
            return Err(ConnectError::unavailable(
                "Entity catalog revision changed before continuation.",
            ));
        }

        let mut entities = if filter.exact_agent_key.is_empty() {
            let entities = self
                .graph_call(
                    self.graph
                        .search(tenant, "", &[], MAX_IN_MEMORY_CATALOG_SCAN),
                )
                .await?;
            if entities.len() == MAX_IN_MEMORY_CATALOG_SCAN {
                return Err(ConnectError::unavailable(
                    "The in-memory entity catalog exceeds its authoritative scan bound.",
                ));
            }
            entities
        } else {
            match self
                .graph_call(self.graph.resolve(tenant, &filter.exact_agent_key))
                .await
            {
                Ok(entity) => vec![entity],
                Err(error) if error.code == connectrpc::ErrorCode::NotFound => Vec::new(),
                Err(error) => return Err(error),
            }
        };
        entities.retain(|entity| {
            entity.agent_key.as_str() > after_agent_key
                && in_memory_catalog_entity_matches(entity, filter)
        });
        entities.sort_by(|left, right| left.agent_key.cmp(&right.agent_key));
        let truncated = entities.len() > limit;
        entities.truncate(limit);

        let relation_counts = if let Some(count_filter) = filter.relation_counts.as_ref() {
            self.in_memory_catalog_relation_counts(tenant, revision_before, &entities, count_filter)
                .await?
        } else {
            Vec::new()
        };
        let revision_after = self.graph_call(self.graph.revision(tenant)).await?;
        if revision_after != revision_before {
            return Err(ConnectError::unavailable(
                "Entity catalog revision changed during the read.",
            ));
        }
        let next_after_agent_key = truncated
            .then(|| entities.last().map(|entity| entity.agent_key.clone()))
            .flatten()
            .unwrap_or_default();
        Ok(StoreCatalogPage {
            tenant_id: tenant.as_str().to_owned(),
            graph_revision: revision_before,
            entities,
            truncated,
            next_after_agent_key,
            relation_counts,
        })
    }

    async fn in_memory_catalog_relation_counts(
        &self,
        tenant: &TenantId,
        graph_revision: u64,
        entities: &[ContextEntity],
        filter: &StoreCatalogRelationCountFilter,
    ) -> Result<Vec<cerebro_organizational_store::EntityCatalogRelationCount>, ConnectError> {
        let mut grouped = BTreeMap::<(String, String, String, String), BTreeSet<EntityId>>::new();
        for chunk in entities.chunks(100) {
            let keys = chunk
                .iter()
                .map(|entity| entity.agent_key.clone())
                .collect::<Vec<_>>();
            let neighborhoods = self
                .graph_call(self.graph.expand_many(tenant, &keys, 1, 500))
                .await?;
            for root_key in keys {
                let neighborhood = neighborhoods.get(&root_key).ok_or_else(|| {
                    ConnectError::unavailable("The in-memory catalog omitted a requested root.")
                })?;
                if neighborhood.graph_revision != graph_revision || neighborhood.truncated {
                    return Err(ConnectError::unavailable(
                        "The in-memory catalog could not produce complete revision-bound relation counts.",
                    ));
                }
                let neighbors = neighborhood
                    .entities
                    .iter()
                    .map(|entity| (entity.entity_id.clone(), entity))
                    .collect::<BTreeMap<_, _>>();
                for edge in &neighborhood.edges {
                    let (direction, neighbor_id) = if edge.from == neighborhood.root.entity_id {
                        (StoreCatalogDirection::Outgoing, &edge.to)
                    } else if edge.to == neighborhood.root.entity_id {
                        (StoreCatalogDirection::Incoming, &edge.from)
                    } else {
                        continue;
                    };
                    let Some(neighbor) = neighbors.get(neighbor_id) else {
                        return Err(ConnectError::unavailable(
                            "The in-memory catalog relation omitted its neighbor.",
                        ));
                    };
                    if !filter.directions.contains(&direction)
                        || !filter.relations.contains(&edge.relation)
                        || !filter.neighbor_kinds.contains(&neighbor.entity_kind)
                    {
                        continue;
                    }
                    let direction_key = match direction {
                        StoreCatalogDirection::Incoming => "incoming",
                        StoreCatalogDirection::Outgoing => "outgoing",
                    };
                    grouped
                        .entry((
                            root_key.clone(),
                            direction_key.to_owned(),
                            edge.relation.clone(),
                            neighbor.entity_kind.clone(),
                        ))
                        .or_default()
                        .insert(neighbor.entity_id.clone());
                }
            }
        }
        Ok(grouped
            .into_iter()
            .map(
                |((agent_key, direction, relation, neighbor_kind), neighbors)| {
                    cerebro_organizational_store::EntityCatalogRelationCount {
                        agent_key,
                        direction: if direction == "incoming" {
                            StoreCatalogDirection::Incoming
                        } else {
                            StoreCatalogDirection::Outgoing
                        },
                        relation,
                        neighbor_kind,
                        count: neighbors.len() as u64,
                    }
                },
            )
            .collect())
    }
}

#[allow(refining_impl_trait)]
impl SecurityLifecycleService for GraphRpc {
    async fn list_security_lifecycle(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, proto::cerebro::v1::ListSecurityLifecycleRequest>,
    ) -> ServiceResult<proto::cerebro::v1::ListSecurityLifecycleResponse> {
        let owned_request = request.to_owned_message();
        let requested_query = owned_request
            .query
            .as_option()
            .ok_or_else(|| ConnectError::invalid_argument("query is required"))?;
        let tenant = self.authorized_tenant(&context, &requested_query.tenant_id)?;
        let query = lifecycle_query(requested_query)?;
        let result = self.lifecycle_records(&tenant, &query).await?;
        let response = lifecycle_query_result(result)?;
        Response::ok(proto::cerebro::v1::ListSecurityLifecycleResponse {
            result: response.into(),
            ..Default::default()
        })
    }

    async fn resolve_security_lifecycle_finding(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest>,
    ) -> ServiceResult<proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse> {
        let owned_request = request.to_owned_message();
        let tenant = self.authorized_tenant(&context, &owned_request.tenant_id)?;
        let finding_urn = owned_request.finding_urn.trim();
        if finding_urn.is_empty() {
            return Err(ConnectError::invalid_argument("finding_urn is required"));
        }
        let expected_prefix = cerebro_security_lifecycle::canonical_finding_urn_prefix(
            tenant.as_str(),
        )
        .map_err(|_| {
            ConnectError::invalid_argument(
                "finding_urn must be a bounded finding URN for the requested tenant",
            )
        })?;
        if finding_urn.len() > 4_096 || !finding_urn.starts_with(&expected_prefix) {
            return Err(ConnectError::invalid_argument(
                "finding_urn must be a bounded finding URN for the requested tenant",
            ));
        }
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("Lifecycle finding resolution requires the durable graph.")
        })?;
        let resolved = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.resolve_lifecycle_finding(&tenant, finding_urn),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Lifecycle finding resolution exceeded 2 seconds."))?
        .map_err(lifecycle_store_error)?;
        let resolved =
            resolved.ok_or_else(|| ConnectError::not_found("Lifecycle finding was not found."))?;
        let as_of = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| ConnectError::internal(format!("Cannot format read time: {error}")))?;
        let record = resolve_finding_record(
            &tenant,
            finding_urn,
            resolved.resource,
            &as_of,
            resolved.graph_revision,
        )
        .map_err(|error| ConnectError::internal(error.to_string()))?
        .ok_or_else(|| ConnectError::not_found("Lifecycle finding is no longer open."))?;
        Response::ok(
            proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse {
                record: lifecycle_record(record)?.into(),
                graph_revision: resolved.graph_revision,
                source_runtime_id: resolved.source_runtime_id,
                source_collection_id: resolved.source_collection_id,
                ..Default::default()
            },
        )
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

    async fn query_facts(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, QueryFactsRequest>,
    ) -> ServiceResult<QueryFactsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let query = FactQuery::new(
            request
                .nodes
                .iter()
                .map(|node| ContextQueryNode {
                    variable: node.variable.to_owned(),
                    kinds: node.kinds.iter().map(|value| (*value).to_owned()).collect(),
                    keys: node.keys.iter().map(|value| (*value).to_owned()).collect(),
                })
                .collect(),
            request
                .edges
                .iter()
                .map(|edge| ContextQueryEdge {
                    variable: edge.variable.to_owned(),
                    from_variable: edge.from_variable.to_owned(),
                    relation: edge.relation.to_owned(),
                    to_variable: edge.to_variable.to_owned(),
                })
                .collect(),
            request
                .absent_edges
                .iter()
                .map(|absence| {
                    let direction = match absence.direction.as_known() {
                        Some(QueryDirection::Outgoing) => ContextQueryDirection::Outgoing,
                        Some(QueryDirection::Incoming) => ContextQueryDirection::Incoming,
                        _ => {
                            return Err(ConnectError::invalid_argument(
                                "absence direction must be outgoing or incoming",
                            ));
                        }
                    };
                    Ok(ContextQueryAbsentEdge {
                        bound_variable: absence.bound_variable.to_owned(),
                        direction,
                        relation: absence.relation.to_owned(),
                        other_kinds: absence
                            .other_kinds
                            .iter()
                            .map(|value| (*value).to_owned())
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, ConnectError>>()?,
            limit,
        )
        .map_err(context_error)?;
        let result = self.graph_call(self.graph.query(&tenant, &query)).await?;
        Response::ok(QueryFactsResponse {
            tenant_id: result.tenant_id.to_string(),
            graph_revision: result.graph_revision,
            matches: result.matches.into_iter().map(query_match).collect(),
            truncated: result.truncated,
            ..Default::default()
        })
    }

    async fn compare_exposure_coverage(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, CompareExposureCoverageRequest>,
    ) -> ServiceResult<CompareExposureCoverageResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let profile = request.profile.as_option().ok_or_else(|| {
            ConnectError::invalid_argument("exposure coverage profile is required")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let query = StoreExposureQuery {
            profile: StoreExposureProfile {
                primary_source_id: profile.primary_source_id.to_owned(),
                primary_entity_kind_prefix: profile.primary_entity_kind_prefix.to_owned(),
                corroborating_source_id: profile.corroborating_source_id.to_owned(),
                corroborating_entity_kind: profile.corroborating_entity_kind.to_owned(),
                indicator_kinds: profile
                    .indicator_kinds
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                account_kind: profile.account_kind.to_owned(),
                corroborating_observation_kind: profile.corroborating_observation_kind.to_owned(),
            },
            account_id: request.account_id.to_owned(),
            region: request.region.to_owned(),
            search: request.query.to_owned(),
            limit,
        };
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The organizational graph projection is not loaded.")
        })?;
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.compare_exposure_coverage(&tenant, &query),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Exposure coverage read exceeded 2 seconds."))?
        .map_err(exposure_store_error)?;
        Response::ok(exposure_coverage_response(result))
    }

    async fn list_entities(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ListEntitiesRequest>,
    ) -> ServiceResult<ListEntitiesResponse> {
        let filter = request
            .filter
            .as_option()
            .ok_or_else(|| ConnectError::invalid_argument("entity catalog filter is required"))?;
        let tenant = self.authorized_tenant(&context, filter.tenant_id)?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let mapped_filter = catalog_filter(filter);
        let result = if let Some(projection) = self.lifecycle_projection.as_ref() {
            tokio::time::timeout(
                GRAPH_RPC_TIMEOUT,
                projection.list_catalog_entities(
                    &tenant,
                    &mapped_filter,
                    limit,
                    request.after_agent_key,
                ),
            )
            .await
            .map_err(|_| ConnectError::unavailable("Entity catalog read exceeded 2 seconds."))?
            .map_err(catalog_store_error)?
        } else {
            self.in_memory_catalog_page(&tenant, &mapped_filter, limit, request.after_agent_key)
                .await?
        };
        Response::ok(catalog_page_response(result))
    }

    async fn count_entity_kinds(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, CountEntityKindsRequest>,
    ) -> ServiceResult<CountEntityKindsResponse> {
        let filter = request
            .filter
            .as_option()
            .ok_or_else(|| ConnectError::invalid_argument("entity catalog filter is required"))?;
        let tenant = self.authorized_tenant(&context, filter.tenant_id)?;
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The entity catalog projection is not loaded.")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.count_catalog_entity_kinds(
                &tenant,
                &catalog_filter(filter),
                limit,
                request.after_entity_kind,
            ),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Entity kind count read exceeded 2 seconds."))?
        .map_err(catalog_store_error)?;
        Response::ok(catalog_kind_response(result))
    }

    async fn count_relations(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, CountRelationsRequest>,
    ) -> ServiceResult<CountRelationsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The entity catalog projection is not loaded.")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.count_catalog_relations(
                &tenant,
                limit,
                request.after_relation,
                request.expected_graph_revision,
            ),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Relation count read exceeded 2 seconds."))?
        .map_err(catalog_store_error)?;
        Response::ok(catalog_relation_kind_response(result))
    }

    async fn list_person_access_paths(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ListPersonAccessPathsRequest>,
    ) -> ServiceResult<ListPersonAccessPathsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The entity catalog projection is not loaded.")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let depth = usize::try_from(request.max_depth)
            .map_err(|_| ConnectError::invalid_argument("max_depth exceeds usize"))?;
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.list_person_access_paths(
                &tenant,
                request.person_urn,
                request.person_query,
                limit,
                depth,
                request.expected_graph_revision,
            ),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Person access path read exceeded 2 seconds."))?
        .map_err(catalog_store_error)?;
        Response::ok(person_access_path_response(result))
    }

    async fn list_cloud_attack_paths(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ListCloudAttackPathsRequest>,
    ) -> ServiceResult<ListCloudAttackPathsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The entity catalog projection is not loaded.")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let depth = usize::try_from(request.max_depth)
            .map_err(|_| ConnectError::invalid_argument("max_depth exceeds usize"))?;
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.list_cloud_attack_paths(
                &tenant,
                request.account_id,
                request.runtime_id,
                request.require_assertion_proof,
                limit,
                depth,
                request.expected_graph_revision,
            ),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Cloud attack path read exceeded 2 seconds."))?
        .map_err(catalog_store_error)?;
        Response::ok(cloud_attack_path_response(result))
    }

    async fn list_entity_relations(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, ListEntityRelationsRequest>,
    ) -> ServiceResult<ListEntityRelationsResponse> {
        let tenant = self.authorized_tenant(&context, request.tenant_id)?;
        let directions = request
            .directions
            .iter()
            .map(|value| match value.as_known() {
                Some(EntityRelationDirection::Incoming) => Ok(StoreCatalogDirection::Incoming),
                Some(EntityRelationDirection::Outgoing) => Ok(StoreCatalogDirection::Outgoing),
                _ => Err(ConnectError::invalid_argument(
                    "relation direction must be incoming or outgoing",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let after_direction = match request.after_direction.as_known() {
            None | Some(EntityRelationDirection::Unspecified) => None,
            Some(EntityRelationDirection::Incoming) => Some(StoreCatalogDirection::Incoming),
            Some(EntityRelationDirection::Outgoing) => Some(StoreCatalogDirection::Outgoing),
        };
        let projection = self.lifecycle_projection.as_ref().ok_or_else(|| {
            ConnectError::unavailable("The entity catalog projection is not loaded.")
        })?;
        let limit = usize::try_from(request.limit)
            .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
        let relations = request
            .relations
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let neighbor_kinds = request
            .neighbor_kinds
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let result = tokio::time::timeout(
            GRAPH_RPC_TIMEOUT,
            projection.list_catalog_relations(
                &tenant,
                request.agent_key,
                &directions,
                &relations,
                &neighbor_kinds,
                limit,
                request.after_agent_key,
                request.after_relation,
                after_direction,
                request.expected_graph_revision,
            ),
        )
        .await
        .map_err(|_| ConnectError::unavailable("Entity relation read exceeded 2 seconds."))?
        .map_err(catalog_store_error)?;
        Response::ok(catalog_relation_response(result))
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

fn exposure_store_error(error: StoreError) -> ConnectError {
    match error {
        StoreError::Conflict(message)
            if message.starts_with("invalid exposure coverage")
                || message.starts_with("exposure coverage limit")
                || message.starts_with("exposure coverage requires") =>
        {
            ConnectError::invalid_argument(message)
        }
        StoreError::Conflict(message) => ConnectError::unavailable(message),
        other => ConnectError::unavailable(other.to_string()),
    }
}

fn exposure_coverage_response(result: StoreExposureResult) -> CompareExposureCoverageResponse {
    CompareExposureCoverageResponse {
        tenant_id: result.tenant_id,
        graph_revision: result.graph_revision,
        counts: ExposureCoverageCounts {
            primary_entities: result.counts.primary_entities,
            indicators: result.counts.indicators,
            host_indicators: result.counts.host_indicators,
            ip_indicators: result.counts.ip_indicators,
            overlapping_primary_entities: result.counts.overlapping_primary_entities,
            overlapping_indicators: result.counts.overlapping_indicators,
            overlapping_corroborating_entities: result.counts.overlapping_corroborating_entities,
            ..Default::default()
        }
        .into(),
        type_counts: result
            .type_counts
            .into_iter()
            .map(|value| ExposureCoverageKindCount {
                entity_kind: value.entity_kind,
                count: value.count,
                ..Default::default()
            })
            .collect(),
        overlaps: result
            .overlaps
            .into_iter()
            .map(|value| ExposureCoverageOverlap {
                primary: exposure_graph_entity(value.primary).into(),
                indicator: exposure_graph_entity(value.indicator).into(),
                corroborating: exposure_graph_entity(value.corroborating).into(),
                ..Default::default()
            })
            .collect(),
        primary_only: result
            .primary_only
            .into_iter()
            .map(|value| ExposureCoveragePair {
                primary: exposure_graph_entity(value.primary).into(),
                indicator: exposure_graph_entity(value.indicator).into(),
                ..Default::default()
            })
            .collect(),
        corroborating_only: result
            .corroborating_only
            .into_iter()
            .map(|value| ExposureCoverageCorroboratingOnly {
                corroborating: exposure_graph_entity(value.corroborating).into(),
                indicator: exposure_graph_entity(value.indicator).into(),
                ..Default::default()
            })
            .collect(),
        accounts: result
            .accounts
            .into_iter()
            .map(|value| ExposureCoverageAccount {
                account: exposure_graph_entity(value.account).into(),
                primary_entities: value.primary_entities,
                corroborating_observations: value.corroborating_observations,
                ..Default::default()
            })
            .collect(),
        completeness: ExposureCoverageCompleteness {
            type_counts_truncated: result.completeness.type_counts_truncated,
            overlaps_truncated: result.completeness.overlaps_truncated,
            primary_only_truncated: result.completeness.primary_only_truncated,
            corroborating_only_truncated: result.completeness.corroborating_only_truncated,
            accounts_truncated: result.completeness.accounts_truncated,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

fn exposure_graph_entity(value: StoreExposureEntity) -> GraphEntity {
    GraphEntity {
        entity_id: value.agent_key.clone(),
        agent_key: value.agent_key,
        entity_kind: value.entity_kind,
        label: value.label,
        ..Default::default()
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

fn lifecycle_query(
    request: &proto::cerebro::v1::SecurityLifecycleQuery,
) -> Result<LifecycleQuery, ConnectError> {
    let subject_kinds = request
        .subject_kinds
        .iter()
        .map(|value| match value.as_known() {
            Some(proto::cerebro::v1::SecurityLifecycleSubjectKind::Credential) => {
                Ok(SubjectKind::Credential)
            }
            Some(proto::cerebro::v1::SecurityLifecycleSubjectKind::Certificate) => {
                Ok(SubjectKind::Certificate)
            }
            _ => Err(ConnectError::invalid_argument(
                "subject_kinds contains an unspecified or unknown value",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let states = request
        .states
        .iter()
        .map(|value| match value.as_known() {
            Some(proto::cerebro::v1::SecurityLifecycleState::Active) => Ok(LifecycleState::Active),
            Some(proto::cerebro::v1::SecurityLifecycleState::Expiring) => {
                Ok(LifecycleState::Expiring)
            }
            Some(proto::cerebro::v1::SecurityLifecycleState::Expired) => {
                Ok(LifecycleState::Expired)
            }
            Some(proto::cerebro::v1::SecurityLifecycleState::Rotated) => {
                Ok(LifecycleState::Rotated)
            }
            Some(proto::cerebro::v1::SecurityLifecycleState::Revoked) => {
                Ok(LifecycleState::Revoked)
            }
            Some(proto::cerebro::v1::SecurityLifecycleState::Inactive) => {
                Ok(LifecycleState::Inactive)
            }
            Some(proto::cerebro::v1::SecurityLifecycleState::Unknown) => {
                Ok(LifecycleState::Unknown)
            }
            _ => Err(ConnectError::invalid_argument(
                "states contains an unspecified or unknown value",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expires_before = request
        .expires_before
        .as_option()
        .map(format_proto_timestamp)
        .transpose()?;
    let limit = (request.limit != 0)
        .then(|| usize::try_from(request.limit))
        .transpose()
        .map_err(|_| ConnectError::invalid_argument("limit exceeds usize"))?;
    Ok(LifecycleQuery {
        subject_kinds,
        states,
        owner_urns: request.owner_urns.to_vec(),
        expires_before,
        findings_only: request.findings_only,
        limit,
        page_token: (!request.page_token.is_empty()).then(|| request.page_token.to_owned()),
        subject_locator: request
            .subject_locator
            .as_option()
            .map(|locator| {
                let subject_kind = match locator.subject_kind.as_known() {
                    Some(proto::cerebro::v1::SecurityLifecycleSubjectKind::Credential) => {
                        Ok(SubjectKind::Credential)
                    }
                    Some(proto::cerebro::v1::SecurityLifecycleSubjectKind::Certificate) => {
                        Ok(SubjectKind::Certificate)
                    }
                    _ => Err(ConnectError::invalid_argument(
                        "subject_locator.subject_kind is required",
                    )),
                }?;
                Ok::<SubjectLocator, ConnectError>(SubjectLocator {
                    subject_kind,
                    authority_id: locator.authority_id.to_owned(),
                    stable_locator: locator.stable_locator.to_owned(),
                })
            })
            .transpose()?,
    })
}

fn format_proto_timestamp(
    timestamp: &buffa_types::google::protobuf::Timestamp,
) -> Result<String, ConnectError> {
    let nanos = u32::try_from(timestamp.nanos)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)
        .ok_or_else(|| ConnectError::invalid_argument("timestamp nanos is out of range"))?;
    let value = OffsetDateTime::from_unix_timestamp(timestamp.seconds)
        .and_then(|value| value.replace_nanosecond(nanos))
        .map_err(|error| ConnectError::invalid_argument(format!("invalid timestamp: {error}")))?;
    value
        .format(&Rfc3339)
        .map_err(|error| ConnectError::invalid_argument(format!("invalid timestamp: {error}")))
}

fn lifecycle_query_result(
    result: LifecycleQueryResult,
) -> Result<proto::cerebro::v1::SecurityLifecycleQueryResult, ConnectError> {
    let mut value = serde_json::to_value(&result).map_err(|error| {
        ConnectError::internal(format!("Cannot encode lifecycle result: {error}"))
    })?;
    let records = value
        .get_mut("records")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| ConnectError::internal("Lifecycle result has no records array"))?;
    for record in records {
        normalize_lifecycle_record(record)?;
    }
    let aggregates = value
        .get_mut("aggregates")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| ConnectError::internal("Lifecycle result has no aggregates"))?;
    let subject_kind_counts = aggregates
        .get_mut("subject_kind_counts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            ConnectError::internal("Lifecycle aggregates have no subject kind counts")
        })?;
    for count in subject_kind_counts {
        let count = count
            .as_object_mut()
            .ok_or_else(|| ConnectError::internal("Lifecycle subject kind count is invalid"))?;
        let subject_kind = match count
            .get("subject_kind")
            .and_then(serde_json::Value::as_str)
        {
            Some("credential") => "SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL",
            Some("certificate") => "SECURITY_LIFECYCLE_SUBJECT_KIND_CERTIFICATE",
            _ => {
                return Err(ConnectError::internal(
                    "Lifecycle subject kind count is invalid",
                ));
            }
        };
        count.insert(
            "subject_kind".to_owned(),
            serde_json::Value::String(subject_kind.to_owned()),
        );
    }
    let state_counts = aggregates
        .get_mut("state_counts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| ConnectError::internal("Lifecycle aggregates have no state counts"))?;
    for count in state_counts {
        let count = count
            .as_object_mut()
            .ok_or_else(|| ConnectError::internal("Lifecycle state count is invalid"))?;
        let state = match count.get("state").and_then(serde_json::Value::as_str) {
            Some("active") => "SECURITY_LIFECYCLE_STATE_ACTIVE",
            Some("expiring") => "SECURITY_LIFECYCLE_STATE_EXPIRING",
            Some("expired") => "SECURITY_LIFECYCLE_STATE_EXPIRED",
            Some("rotated") => "SECURITY_LIFECYCLE_STATE_ROTATED",
            Some("revoked") => "SECURITY_LIFECYCLE_STATE_REVOKED",
            Some("inactive") => "SECURITY_LIFECYCLE_STATE_INACTIVE",
            Some("unknown") => "SECURITY_LIFECYCLE_STATE_UNKNOWN",
            _ => return Err(ConnectError::internal("Lifecycle state count is invalid")),
        };
        count.insert(
            "state".to_owned(),
            serde_json::Value::String(state.to_owned()),
        );
    }
    let policy_state_counts = aggregates
        .get_mut("policy_state_counts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            ConnectError::internal("Lifecycle aggregates have no policy state counts")
        })?;
    for count in policy_state_counts {
        let count = count
            .as_object_mut()
            .ok_or_else(|| ConnectError::internal("Lifecycle policy state count is invalid"))?;
        let policy_state = match count
            .get("policy_state")
            .and_then(serde_json::Value::as_str)
        {
            Some("compliant") => "SECURITY_LIFECYCLE_POLICY_STATE_COMPLIANT",
            Some("expiring") => "SECURITY_LIFECYCLE_POLICY_STATE_EXPIRING",
            Some("expired") => "SECURITY_LIFECYCLE_POLICY_STATE_EXPIRED",
            Some("unknown") => "SECURITY_LIFECYCLE_POLICY_STATE_UNKNOWN",
            _ => {
                return Err(ConnectError::internal(
                    "Lifecycle policy state count is invalid",
                ));
            }
        };
        count.insert(
            "policy_state".to_owned(),
            serde_json::Value::String(policy_state.to_owned()),
        );
    }
    let reason = value
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("coverage"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|coverage| coverage.get_mut("reason"))
        .ok_or_else(|| ConnectError::internal("Lifecycle coverage reason is missing"))?;
    let reason_name = match reason.as_str() {
        Some("complete") => "SECURITY_LIFECYCLE_COVERAGE_REASON_COMPLETE",
        Some("scan_limit") => "SECURITY_LIFECYCLE_COVERAGE_REASON_SCAN_LIMIT",
        Some("graph_changed") => "SECURITY_LIFECYCLE_COVERAGE_REASON_GRAPH_CHANGED",
        _ => {
            return Err(ConnectError::internal(
                "Lifecycle coverage reason is invalid",
            ));
        }
    };
    *reason = serde_json::Value::String(reason_name.to_owned());
    serde_json::from_value(value)
        .map_err(|error| ConnectError::internal(format!("Cannot encode lifecycle result: {error}")))
}

fn lifecycle_record(
    record: cerebro_security_lifecycle::LifecycleRecord,
) -> Result<proto::cerebro::v1::SecurityLifecycleRecord, ConnectError> {
    let mut value = serde_json::to_value(record).map_err(|error| {
        ConnectError::internal(format!("Cannot encode lifecycle record: {error}"))
    })?;
    normalize_lifecycle_record(&mut value)?;
    serde_json::from_value(value)
        .map_err(|error| ConnectError::internal(format!("Cannot encode lifecycle record: {error}")))
}

fn normalize_lifecycle_record(record: &mut serde_json::Value) -> Result<(), ConnectError> {
    let observation = record
        .get_mut("observation")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| ConnectError::internal("Lifecycle record has no observation"))?;
    let subject_kind = match observation
        .get("subject_kind")
        .and_then(serde_json::Value::as_str)
    {
        Some("credential") => "SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL",
        Some("certificate") => "SECURITY_LIFECYCLE_SUBJECT_KIND_CERTIFICATE",
        _ => return Err(ConnectError::internal("Lifecycle subject kind is invalid")),
    };
    let state = match observation.get("state").and_then(serde_json::Value::as_str) {
        Some("active") => "SECURITY_LIFECYCLE_STATE_ACTIVE",
        Some("expiring") => "SECURITY_LIFECYCLE_STATE_EXPIRING",
        Some("expired") => "SECURITY_LIFECYCLE_STATE_EXPIRED",
        Some("rotated") => "SECURITY_LIFECYCLE_STATE_ROTATED",
        Some("revoked") => "SECURITY_LIFECYCLE_STATE_REVOKED",
        Some("inactive") => "SECURITY_LIFECYCLE_STATE_INACTIVE",
        Some("unknown") => "SECURITY_LIFECYCLE_STATE_UNKNOWN",
        _ => return Err(ConnectError::internal("Lifecycle state is invalid")),
    };
    observation.insert(
        "subject_kind".to_owned(),
        serde_json::Value::String(subject_kind.to_owned()),
    );
    observation.insert(
        "state".to_owned(),
        serde_json::Value::String(state.to_owned()),
    );
    Ok(())
}

fn catalog_filter(filter: &__buffa::view::EntityCatalogFilterView<'_>) -> StoreCatalogFilter {
    let relation_counts =
        filter
            .relation_counts
            .as_option()
            .map(|counts| StoreCatalogRelationCountFilter {
                directions: counts
                    .directions
                    .iter()
                    .filter_map(|value| match value.as_known() {
                        Some(EntityRelationDirection::Incoming) => {
                            Some(StoreCatalogDirection::Incoming)
                        }
                        Some(EntityRelationDirection::Outgoing) => {
                            Some(StoreCatalogDirection::Outgoing)
                        }
                        _ => None,
                    })
                    .collect(),
                relations: counts
                    .relations
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                neighbor_kinds: counts
                    .neighbor_kinds
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            });
    StoreCatalogFilter {
        source_id: filter.source_id.to_owned(),
        runtime_ids: filter
            .runtime_ids
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        exact_agent_key: filter.exact_agent_key.to_owned(),
        include_kinds: filter
            .include_kinds
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        include_kind_prefixes: filter
            .include_kind_prefixes
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        exclude_kinds: filter
            .exclude_kinds
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        exclude_kind_prefixes: filter
            .exclude_kind_prefixes
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        search: filter.query.to_owned(),
        search_attributes: filter.query_attributes,
        relation_counts,
        expected_graph_revision: filter.expected_graph_revision,
    }
}

fn validate_in_memory_catalog_request(
    tenant: &TenantId,
    filter: &StoreCatalogFilter,
    after_agent_key: &str,
) -> Result<(), ConnectError> {
    let tenant_prefix = format!("urn:cerebro:{}:", tenant.as_str());
    if (!filter.exact_agent_key.is_empty() && !filter.exact_agent_key.starts_with(&tenant_prefix))
        || (!after_agent_key.is_empty() && !after_agent_key.starts_with(&tenant_prefix))
        || !catalog_values_are_closed(&filter.runtime_ids)
        || !catalog_values_are_closed(&filter.include_kinds)
        || !catalog_values_are_closed(&filter.include_kind_prefixes)
        || !catalog_values_are_closed(&filter.exclude_kinds)
        || !catalog_values_are_closed(&filter.exclude_kind_prefixes)
        || filter.search.trim() != filter.search
    {
        return Err(ConnectError::invalid_argument(
            "invalid in-memory entity catalog request",
        ));
    }
    if let Some(counts) = filter.relation_counts.as_ref()
        && (counts.directions.is_empty()
            || counts.relations.is_empty()
            || counts.neighbor_kinds.is_empty()
            || counts.directions.iter().collect::<BTreeSet<_>>().len() != counts.directions.len()
            || !catalog_values_are_closed(&counts.relations)
            || !catalog_values_are_closed(&counts.neighbor_kinds))
    {
        return Err(ConnectError::invalid_argument(
            "invalid in-memory entity catalog relation counts",
        ));
    }
    Ok(())
}

fn catalog_values_are_closed(values: &[String]) -> bool {
    values.len() <= 100
        && values
            .iter()
            .all(|value| !value.is_empty() && value.trim() == value)
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn in_memory_catalog_entity_matches(entity: &ContextEntity, filter: &StoreCatalogFilter) -> bool {
    if !filter.exact_agent_key.is_empty() && entity.agent_key != filter.exact_agent_key {
        return false;
    }
    if !filter.source_id.is_empty() && entity.properties.get("source_id") != Some(&filter.source_id)
    {
        return false;
    }
    if !filter.runtime_ids.is_empty() {
        let runtime_id = entity
            .properties
            .get("runtime_id")
            .map(String::as_str)
            .or_else(|| {
                entity
                    .authority
                    .get("source_runtime_id")
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or_default();
        if !filter.runtime_ids.iter().any(|value| value == runtime_id) {
            return false;
        }
    }
    let included = filter.include_kinds.is_empty() && filter.include_kind_prefixes.is_empty()
        || filter.include_kinds.contains(&entity.entity_kind)
        || filter
            .include_kind_prefixes
            .iter()
            .any(|prefix| entity.entity_kind.starts_with(prefix));
    if !included
        || filter.exclude_kinds.contains(&entity.entity_kind)
        || filter
            .exclude_kind_prefixes
            .iter()
            .any(|prefix| entity.entity_kind.starts_with(prefix))
    {
        return false;
    }
    if filter.search.is_empty() {
        return true;
    }
    let query = filter.search.to_lowercase();
    entity.agent_key.to_lowercase().contains(&query)
        || entity.label.to_lowercase().contains(&query)
        || (filter.search_attributes
            && entity.properties.iter().any(|(key, value)| {
                key.to_lowercase().contains(&query) || value.to_lowercase().contains(&query)
            }))
}

fn catalog_store_error(error: StoreError) -> ConnectError {
    match error {
        StoreError::Conflict(message)
            if message.starts_with("invalid entity catalog")
                || message.contains("limit must")
                || message.contains("contains duplicates")
                || message.contains("exceeds its bound")
                || message.contains("cursor is incomplete")
                || message.contains("not tenant scoped")
                || message.contains("directions are invalid") =>
        {
            ConnectError::invalid_argument(message)
        }
        StoreError::Conflict(message) if message.contains("was not found") => {
            ConnectError::not_found(message)
        }
        StoreError::Conflict(message) => ConnectError::unavailable(message),
        other => ConnectError::unavailable(other.to_string()),
    }
}

fn catalog_page_response(page: StoreCatalogPage) -> ListEntitiesResponse {
    ListEntitiesResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        entities: page.entities.into_iter().map(graph_entity).collect(),
        truncated: page.truncated,
        next_after_agent_key: page.next_after_agent_key,
        relation_counts: page
            .relation_counts
            .into_iter()
            .map(|value| EntityRelationCount {
                agent_key: value.agent_key,
                direction: match value.direction {
                    StoreCatalogDirection::Incoming => EntityRelationDirection::Incoming,
                    StoreCatalogDirection::Outgoing => EntityRelationDirection::Outgoing,
                }
                .into(),
                relation: value.relation,
                neighbor_kind: value.neighbor_kind,
                count: value.count,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn catalog_kind_response(page: StoreCatalogKindPage) -> CountEntityKindsResponse {
    CountEntityKindsResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        counts: page
            .counts
            .into_iter()
            .map(|count| EntityKindCount {
                entity_kind: count.entity_kind,
                count: count.count,
                ..Default::default()
            })
            .collect(),
        truncated: page.truncated,
        next_after_entity_kind: page.next_after_entity_kind,
        ..Default::default()
    }
}

fn catalog_relation_kind_response(page: StoreCatalogRelationKindPage) -> CountRelationsResponse {
    CountRelationsResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        counts: page
            .counts
            .into_iter()
            .map(|value| RelationCount {
                relation: value.relation,
                count: value.count,
                ..Default::default()
            })
            .collect(),
        truncated: page.truncated,
        next_after_relation: page.next_after_relation,
        ..Default::default()
    }
}

fn person_access_path_response(page: StorePersonAccessPathPage) -> ListPersonAccessPathsResponse {
    ListPersonAccessPathsResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        paths: page
            .paths
            .into_iter()
            .map(|path| PersonAccessPath {
                person: graph_entity(path.person).into(),
                identity: graph_entity(path.identity).into(),
                principal: graph_entity(path.principal).into(),
                access_target: graph_entity(path.access_target).into(),
                relation_chain: path.relation_chain,
                ..Default::default()
            })
            .collect(),
        truncated: page.truncated,
        ..Default::default()
    }
}

fn cloud_attack_path_response(page: StoreCloudAttackPathPage) -> ListCloudAttackPathsResponse {
    ListCloudAttackPathsResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        counts: cloud_attack_path_counts(page.counts).into(),
        paths: page.paths.into_iter().map(cloud_attack_path).collect(),
        truncated: page.truncated,
        ..Default::default()
    }
}

fn cloud_attack_path_counts(counts: StoreCloudAttackPathCounts) -> CloudAttackPathCounts {
    CloudAttackPathCounts {
        paths: counts.paths,
        exposed_resources: counts.exposed_resources,
        privileged_principals: counts.privileged_principals,
        cloud_accounts: counts.cloud_accounts,
        ..Default::default()
    }
}

fn cloud_attack_path(path: StoreCloudAttackPath) -> CloudAttackPath {
    CloudAttackPath {
        public_principal: cloud_attack_path_node(path.public_principal).into(),
        exposed_resource: cloud_attack_path_node(path.exposed_resource).into(),
        cloud_account: cloud_attack_path_node(path.cloud_account).into(),
        principal: cloud_attack_path_node(path.principal).into(),
        permission: cloud_attack_path_node(path.permission).into(),
        ownerships: path
            .ownerships
            .into_iter()
            .map(cloud_attack_path_ownership)
            .collect(),
        reach_relation: path.reach_relation,
        access_relation: path.access_relation,
        relation_chain: path.relation_chain,
        exposure_edge: cloud_attack_path_edge(path.exposure_edge).into(),
        resource_account_edge: cloud_attack_path_edge(path.resource_account_edge).into(),
        traversal_edges: path
            .traversal_edges
            .into_iter()
            .map(cloud_attack_path_edge)
            .collect(),
        privilege_edge: cloud_attack_path_edge(path.privilege_edge).into(),
        permission_account_edge: cloud_attack_path_edge(path.permission_account_edge).into(),
        ..Default::default()
    }
}

fn cloud_attack_path_ownership(
    ownership: StoreCloudAttackPathOwnership,
) -> CloudAttackPathOwnership {
    CloudAttackPathOwnership {
        owner: cloud_attack_path_node(ownership.owner).into(),
        edge: cloud_attack_path_edge(ownership.edge).into(),
        ..Default::default()
    }
}

fn cloud_attack_path_edge(edge: StoreCloudAttackPathEdge) -> CloudAttackPathEdge {
    CloudAttackPathEdge {
        from: cloud_attack_path_node(edge.from).into(),
        relation: edge.relation,
        to: cloud_attack_path_node(edge.to).into(),
        direction: edge.direction,
        source_id: edge.source_id,
        source_runtime_id: edge.source_runtime_id,
        assertion_runtime_ids: edge.assertion_runtime_ids,
        attributes_json: edge.attributes_json,
        ..Default::default()
    }
}

fn cloud_attack_path_node(node: StoreCloudAttackPathNode) -> CloudAttackPathNode {
    CloudAttackPathNode {
        urn: node.urn,
        entity_kind: node.entity_kind,
        label: node.label,
        ..Default::default()
    }
}

fn catalog_relation_response(page: StoreCatalogRelationPage) -> ListEntityRelationsResponse {
    let next_after_direction = match page.next_after_direction {
        Some(StoreCatalogDirection::Incoming) => EntityRelationDirection::Incoming,
        Some(StoreCatalogDirection::Outgoing) => EntityRelationDirection::Outgoing,
        None => EntityRelationDirection::Unspecified,
    };
    ListEntityRelationsResponse {
        tenant_id: page.tenant_id,
        graph_revision: page.graph_revision,
        relations: page
            .relations
            .into_iter()
            .map(|value| EntityRelation {
                direction: match value.direction {
                    StoreCatalogDirection::Incoming => EntityRelationDirection::Incoming,
                    StoreCatalogDirection::Outgoing => EntityRelationDirection::Outgoing,
                }
                .into(),
                relation: value.relation,
                entity: graph_entity(value.entity).into(),
                ..Default::default()
            })
            .collect(),
        truncated: page.truncated,
        next_after_agent_key: page.next_after_agent_key,
        next_after_relation: page.next_after_relation,
        next_after_direction: next_after_direction.into(),
        ..Default::default()
    }
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

fn query_match(value: ContextQueryMatch) -> QueryFactMatch {
    QueryFactMatch {
        entities: value
            .entities
            .into_iter()
            .map(|(variable, entity)| QueryBoundEntity {
                variable,
                entity: graph_entity(entity).into(),
                ..Default::default()
            })
            .collect(),
        edges: value
            .edges
            .into_iter()
            .map(|(variable, edge)| QueryBoundEdge {
                variable,
                edge: graph_edge(edge).into(),
                ..Default::default()
            })
            .collect(),
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

fn lifecycle_store_error(error: StoreError) -> ConnectError {
    match error {
        StoreError::Conflict(message) => ConnectError::internal(message),
        StoreError::LifecycleProjectionUnavailable { .. } => {
            ConnectError::unavailable(error.to_string())
        }
        _ => ConnectError::unavailable(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, future};

    use buffa::{HasMessageView, Message};
    use cerebro_organizational_store::{
        CloudAttackPath as StoreCloudAttackPath,
        CloudAttackPathCounts as StoreCloudAttackPathCounts,
        CloudAttackPathEdge as StoreCloudAttackPathEdge,
        CloudAttackPathNode as StoreCloudAttackPathNode,
        CloudAttackPathOwnership as StoreCloudAttackPathOwnership,
        CloudAttackPathPage as StoreCloudAttackPathPage, EntityCatalogKindCount,
        EntityCatalogRelation, EntityCatalogRelationCount,
        ExposureCoverageAccount as StoreExposureAccount,
        ExposureCoverageCompleteness as StoreExposureCompleteness,
        ExposureCoverageCorroboratingOnly as StoreExposureCorroboratingOnly,
        ExposureCoverageCounts as StoreExposureCounts,
        ExposureCoverageKindCount as StoreExposureKindCount,
        ExposureCoverageOverlap as StoreExposureOverlap, ExposureCoveragePair as StoreExposurePair,
        PersonAccessPath as StorePersonAccessPath,
    };
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

    #[tokio::test]
    async fn in_memory_catalog_lists_demo_vendors_at_one_revision() {
        let (graph, tenant, _) = crate::demo_graph().unwrap();
        let graph = Arc::new(cerebro_agent_context::MemoryAgentGraph::new(graph));
        let service = GraphRpc {
            graph,
            lifecycle_projection: None,
            catalog_summary: None,
            tenant_auth: TenantRequestAuth::new(
                "test-organizational-graph-secret-32-bytes".to_owned(),
            )
            .unwrap(),
        };

        let page = service
            .in_memory_catalog_page(
                &tenant,
                &StoreCatalogFilter {
                    include_kinds: vec!["vendor".to_owned()],
                    ..Default::default()
                },
                100,
                "",
            )
            .await
            .unwrap();

        assert_eq!(page.graph_revision, 2);
        assert_eq!(page.entities.len(), 2);
        assert!(
            page.entities
                .iter()
                .all(|entity| entity.entity_kind == "vendor")
        );
        assert!(!page.truncated);
    }

    #[test]
    fn lifecycle_store_conflicts_are_not_retryable() {
        let conflict = lifecycle_store_error(StoreError::Conflict(
            "persistent lifecycle graph inconsistency".to_owned(),
        ));
        assert_eq!(conflict.code, ErrorCode::Internal);

        let unavailable = lifecycle_store_error(StoreError::LifecycleProjectionUnavailable {
            graph_revision: 3,
            projection_revision: Some(2),
        });
        assert_eq!(unavailable.code, ErrorCode::Unavailable);
    }

    #[test]
    fn lifecycle_result_uses_proto_timestamp_and_page_token() {
        let response = lifecycle_query_result(LifecycleQueryResult {
            records: vec![cerebro_security_lifecycle::LifecycleRecord {
                observation: cerebro_security_lifecycle::Observation {
                    subject_ref: cerebro_security_lifecycle::ResourceRef {
                        kind: "credential".to_owned(),
                        id: "urn:cerebro:tenant-a:credential:aws%2Fproduction:deploy%2Fsigning"
                            .to_owned(),
                        revision: Some("key-2026-07".to_owned()),
                        state: Some("expiring".to_owned()),
                    },
                    subject_kind: SubjectKind::Credential,
                    provider: "aws".to_owned(),
                    authority_id: "aws/production".to_owned(),
                    stable_locator: "deploy/signing".to_owned(),
                    display_name: "Deployment signing credential".to_owned(),
                    state: LifecycleState::Expiring,
                    observed_at: "2026-07-26T12:00:00Z".to_owned(),
                    issued_at: None,
                    expires_at: Some("2026-08-01T12:00:00Z".to_owned()),
                    rotated_at: None,
                    revoked_at: None,
                    owner_urn: None,
                    scope_refs: Vec::new(),
                    evidence_claim_refs: Vec::new(),
                    attributes: Default::default(),
                },
                policy_evaluations: Vec::new(),
                findings: Vec::new(),
                action_routes: Vec::new(),
                projected_at: "2026-07-26T12:00:00Z".to_owned(),
                source_runtime_id: "lifecycle-test".to_owned(),
                source_collection_id: "runtime:lifecycle-test:collection-1".to_owned(),
            }],
            next_page_token: Some("v1.616263".to_owned()),
            previous_page_token: Some("v2.previous".to_owned()),
            truncated: true,
            as_of: "2026-07-26T12:00:00Z".to_owned(),
            aggregates: cerebro_security_lifecycle::LifecycleAggregates {
                counts_are_exact: true,
                matched_records: 1,
                matched_findings: 0,
                subject_kind_counts: vec![cerebro_security_lifecycle::SubjectKindCount {
                    subject_kind: SubjectKind::Credential,
                    count: 1,
                }],
                state_counts: vec![cerebro_security_lifecycle::StateCount {
                    state: LifecycleState::Expiring,
                    count: 1,
                }],
                policy_state_counts: vec![cerebro_security_lifecycle::PolicyStateCount {
                    policy_state: cerebro_security_lifecycle::PolicyState::Expiring,
                    count: 1,
                }],
            },
            metadata: cerebro_security_lifecycle::QueryMetadata {
                coverage: cerebro_security_lifecycle::QueryCoverage {
                    complete: true,
                    truncated: false,
                    scanned_entities: 1,
                    lifecycle_entities: 1,
                    graph_revision: 7,
                    reason: cerebro_security_lifecycle::CoverageReason::Complete,
                },
                freshness: cerebro_security_lifecycle::QueryFreshness {
                    as_of: "2026-07-26T12:00:00Z".to_owned(),
                    oldest_observed_at: Some("2026-07-26T12:00:00Z".to_owned()),
                    newest_observed_at: Some("2026-07-26T12:00:00Z".to_owned()),
                },
                page_truncated: true,
            },
        })
        .unwrap();

        assert_eq!(response.next_page_token, "v1.616263");
        assert!(response.truncated);
        assert_eq!(response.previous_page_token, "v2.previous");
        assert_eq!(response.aggregates.matched_records, 1);
        assert!(response.metadata.coverage.complete);
        assert_eq!(response.as_of.seconds, 1_785_067_200);
        assert_eq!(
            response.records[0].observation.subject_kind,
            proto::cerebro::v1::SecurityLifecycleSubjectKind::Credential
        );
    }

    #[test]
    fn lifecycle_query_maps_every_filter_into_the_rust_authority() {
        let request = proto::cerebro::v1::SecurityLifecycleQuery {
            tenant_id: "tenant-a".to_owned(),
            subject_kinds: vec![
                proto::cerebro::v1::SecurityLifecycleSubjectKind::Credential.into(),
                proto::cerebro::v1::SecurityLifecycleSubjectKind::Certificate.into(),
            ],
            states: vec![
                proto::cerebro::v1::SecurityLifecycleState::Active.into(),
                proto::cerebro::v1::SecurityLifecycleState::Expiring.into(),
                proto::cerebro::v1::SecurityLifecycleState::Expired.into(),
                proto::cerebro::v1::SecurityLifecycleState::Rotated.into(),
                proto::cerebro::v1::SecurityLifecycleState::Revoked.into(),
                proto::cerebro::v1::SecurityLifecycleState::Inactive.into(),
                proto::cerebro::v1::SecurityLifecycleState::Unknown.into(),
            ],
            owner_urns: vec!["urn:cerebro:tenant-a:team:security".to_owned()],
            expires_before: buffa_types::google::protobuf::Timestamp {
                seconds: 1_785_067_200,
                nanos: 123_000_000,
                ..Default::default()
            }
            .into(),
            findings_only: true,
            limit: 37,
            page_token: "v1.616263".to_owned(),
            ..Default::default()
        };

        let query = lifecycle_query(&request).unwrap();

        assert_eq!(
            query.subject_kinds,
            vec![SubjectKind::Credential, SubjectKind::Certificate]
        );
        assert_eq!(
            query.states,
            vec![
                LifecycleState::Active,
                LifecycleState::Expiring,
                LifecycleState::Expired,
                LifecycleState::Rotated,
                LifecycleState::Revoked,
                LifecycleState::Inactive,
                LifecycleState::Unknown,
            ]
        );
        assert_eq!(query.owner_urns, vec!["urn:cerebro:tenant-a:team:security"]);
        assert_eq!(
            query.expires_before.as_deref(),
            Some("2026-07-26T12:00:00.123Z")
        );
        assert!(query.findings_only);
        assert_eq!(query.limit, Some(37));
        assert_eq!(query.page_token.as_deref(), Some("v1.616263"));
    }

    #[test]
    fn lifecycle_query_rejects_unknown_enums_and_invalid_timestamps() {
        let mut request = proto::cerebro::v1::SecurityLifecycleQuery {
            subject_kinds: vec![buffa::EnumValue::from(99)],
            ..Default::default()
        };
        assert_eq!(
            lifecycle_query(&request).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        request.subject_kinds.clear();
        request.states = vec![buffa::EnumValue::from(99)];
        assert_eq!(
            lifecycle_query(&request).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        request.states.clear();
        request.expires_before = buffa_types::google::protobuf::Timestamp {
            seconds: 0,
            nanos: -1,
            ..Default::default()
        }
        .into();
        assert_eq!(
            lifecycle_query(&request).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    fn context_entity(id: &str, kind: &str) -> ContextEntity {
        ContextEntity {
            entity_id: EntityId::parse(id).unwrap(),
            agent_key: format!("urn:cerebro:tenant-a:{kind}:{id}"),
            entity_kind: kind.to_owned(),
            authority: serde_json::json!({
                "authority": "provider",
                "source_runtime_id": "runtime-a",
                "provider_kind": kind,
                "provider_id": id,
            }),
            label: format!("{kind} {id}"),
            properties: BTreeMap::from([("region".to_owned(), "us-west-2".to_owned())]),
        }
    }

    fn context_edge(id: &str) -> ContextEdge {
        ContextEdge {
            assertion_id: AssertionId::parse(id).unwrap(),
            from: EntityId::parse("entity-a").unwrap(),
            relation: "owns".to_owned(),
            to: EntityId::parse("entity-b").unwrap(),
            source_runtime_id: "runtime-a".to_owned(),
            identity_binding: false,
        }
    }

    fn exposure_entity(id: &str, kind: &str) -> StoreExposureEntity {
        StoreExposureEntity {
            agent_key: format!("urn:cerebro:tenant-a:{kind}:{id}"),
            entity_kind: kind.to_owned(),
            label: format!("{kind} {id}"),
        }
    }

    #[test]
    fn exposure_response_preserves_every_bounded_collection_and_completeness_flag() {
        let primary = exposure_entity("primary", "endpoint");
        let indicator = exposure_entity("indicator", "indicator.ip");
        let corroborating = exposure_entity("corroborating", "observation");
        let account = exposure_entity("account", "account");
        let response = exposure_coverage_response(StoreExposureResult {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            counts: StoreExposureCounts {
                primary_entities: 1,
                indicators: 2,
                host_indicators: 3,
                ip_indicators: 4,
                overlapping_primary_entities: 5,
                overlapping_indicators: 6,
                overlapping_corroborating_entities: 7,
            },
            type_counts: vec![StoreExposureKindCount {
                entity_kind: "endpoint".to_owned(),
                count: 8,
            }],
            overlaps: vec![StoreExposureOverlap {
                primary: primary.clone(),
                indicator: indicator.clone(),
                corroborating: corroborating.clone(),
            }],
            primary_only: vec![StoreExposurePair {
                primary: primary.clone(),
                indicator: indicator.clone(),
            }],
            corroborating_only: vec![StoreExposureCorroboratingOnly {
                corroborating: corroborating.clone(),
                indicator: indicator.clone(),
            }],
            accounts: vec![StoreExposureAccount {
                account,
                primary_entities: 9,
                corroborating_observations: 10,
            }],
            completeness: StoreExposureCompleteness {
                type_counts_truncated: true,
                overlaps_truncated: true,
                primary_only_truncated: true,
                corroborating_only_truncated: true,
                accounts_truncated: true,
            },
        });

        assert_eq!(response.tenant_id, "tenant-a");
        assert_eq!(response.graph_revision, 42);
        assert_eq!(response.counts.as_option().unwrap().ip_indicators, 4);
        assert_eq!(response.type_counts[0].count, 8);
        assert_eq!(
            response.overlaps[0].primary.as_option().unwrap().entity_id,
            primary.agent_key
        );
        assert_eq!(response.primary_only.len(), 1);
        assert_eq!(response.corroborating_only.len(), 1);
        assert_eq!(response.accounts[0].corroborating_observations, 10);
        assert!(
            response
                .completeness
                .as_option()
                .unwrap()
                .accounts_truncated
        );
    }

    #[test]
    fn catalog_filter_and_pages_preserve_closed_fields_and_cursor_direction() {
        let filter = EntityCatalogFilter {
            tenant_id: "tenant-a".to_owned(),
            source_id: "source-a".to_owned(),
            runtime_ids: vec!["runtime-a".to_owned()],
            exact_agent_key: "urn:cerebro:tenant-a:service:one".to_owned(),
            include_kinds: vec!["service".to_owned()],
            include_kind_prefixes: vec!["service.".to_owned()],
            exclude_kinds: vec!["service.retired".to_owned()],
            exclude_kind_prefixes: vec!["internal.".to_owned()],
            query: "checkout".to_owned(),
            expected_graph_revision: 41,
            query_attributes: true,
            relation_counts: EntityRelationCountFilter {
                directions: vec![
                    EntityRelationDirection::Incoming.into(),
                    EntityRelationDirection::Outgoing.into(),
                ],
                relations: vec!["owns".to_owned()],
                neighbor_kinds: vec!["team".to_owned()],
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let encoded = filter.encode_to_vec();
        let view = EntityCatalogFilter::decode_view(&encoded).unwrap();
        let mapped = catalog_filter(&view);
        assert_eq!(mapped.source_id, "source-a");
        assert_eq!(mapped.runtime_ids, ["runtime-a"]);
        assert_eq!(mapped.include_kind_prefixes, ["service."]);
        assert_eq!(mapped.exclude_kinds, ["service.retired"]);
        assert!(mapped.search_attributes);
        assert_eq!(mapped.expected_graph_revision, 41);
        assert_eq!(
            mapped.relation_counts.unwrap().directions,
            [
                StoreCatalogDirection::Incoming,
                StoreCatalogDirection::Outgoing
            ]
        );

        let entity = context_entity("entity-a", "service");
        let page = catalog_page_response(StoreCatalogPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            entities: vec![entity.clone()],
            truncated: true,
            next_after_agent_key: entity.agent_key.clone(),
            relation_counts: vec![EntityCatalogRelationCount {
                agent_key: entity.agent_key.clone(),
                direction: StoreCatalogDirection::Incoming,
                relation: "owns".to_owned(),
                neighbor_kind: "team".to_owned(),
                count: 3,
            }],
        });
        assert_eq!(page.entities[0].provider_id, "entity-a");
        assert_eq!(page.relation_counts[0].count, 3);
        assert_eq!(
            page.relation_counts[0].direction.as_known(),
            Some(EntityRelationDirection::Incoming)
        );

        let kinds = catalog_kind_response(StoreCatalogKindPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            counts: vec![EntityCatalogKindCount {
                entity_kind: "service".to_owned(),
                count: 4,
            }],
            truncated: true,
            next_after_entity_kind: "service".to_owned(),
        });
        assert_eq!(kinds.counts[0].count, 4);
        assert_eq!(kinds.next_after_entity_kind, "service");

        let relation_kinds = catalog_relation_kind_response(StoreCatalogRelationKindPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            counts: vec![
                cerebro_organizational_store::EntityCatalogRelationKindCount {
                    relation: "has_finding".to_owned(),
                    count: 5,
                },
            ],
            truncated: true,
            next_after_relation: "has_finding".to_owned(),
        });
        assert_eq!(relation_kinds.counts[0].relation, "has_finding");
        assert_eq!(relation_kinds.counts[0].count, 5);
        assert_eq!(relation_kinds.next_after_relation, "has_finding");

        let access_paths = person_access_path_response(StorePersonAccessPathPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            paths: vec![StorePersonAccessPath {
                person: context_entity("person-a", "person"),
                identity: context_entity("identity-a", "identity.email"),
                principal: context_entity("principal-a", "okta.user"),
                access_target: context_entity("target-a", "aws.role"),
                relation_chain: vec!["assigned_to".to_owned()],
            }],
            truncated: true,
        });
        assert_eq!(access_paths.graph_revision, 42);
        assert_eq!(access_paths.paths[0].access_target.entity_kind, "aws.role");
        assert_eq!(access_paths.paths[0].relation_chain, ["assigned_to"]);
        assert!(access_paths.truncated);

        let node = |suffix: &str, kind: &str| StoreCloudAttackPathNode {
            urn: format!("urn:cerebro:tenant-a:{kind}:{suffix}"),
            entity_kind: kind.to_owned(),
            label: suffix.to_owned(),
        };
        let public = node("public", "aws.public_principal");
        let exposed = node("eni", "aws.network.interface");
        let account = node("account", "cloud.account");
        let principal = node("role", "aws.role");
        let permission = node("policy", "aws.policy");
        let edge = |from: StoreCloudAttackPathNode,
                    relation: &str,
                    to: StoreCloudAttackPathNode,
                    direction: &str|
         -> StoreCloudAttackPathEdge {
            StoreCloudAttackPathEdge {
                from,
                relation: relation.to_owned(),
                to,
                direction: direction.to_owned(),
                source_id: "aws".to_owned(),
                source_runtime_id: "runtime-a".to_owned(),
                assertion_runtime_ids: vec!["runtime-a".to_owned()],
                attributes_json: "{}".to_owned(),
            }
        };
        let attack_paths = cloud_attack_path_response(StoreCloudAttackPathPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            counts: StoreCloudAttackPathCounts {
                paths: 1,
                exposed_resources: 1,
                privileged_principals: 1,
                cloud_accounts: 1,
            },
            paths: vec![StoreCloudAttackPath {
                public_principal: public.clone(),
                exposed_resource: exposed.clone(),
                cloud_account: account.clone(),
                principal: principal.clone(),
                permission: permission.clone(),
                ownerships: vec![StoreCloudAttackPathOwnership {
                    owner: node("team", "team"),
                    edge: edge(exposed.clone(), "owned_by", node("team", "team"), "forward"),
                }],
                reach_relation: "can_reach".to_owned(),
                access_relation: "can_admin".to_owned(),
                relation_chain: vec!["attached_to".to_owned()],
                exposure_edge: edge(public, "can_reach", exposed.clone(), "forward"),
                resource_account_edge: edge(
                    exposed.clone(),
                    "belongs_to",
                    account.clone(),
                    "forward",
                ),
                traversal_edges: vec![edge(exposed, "attached_to", principal.clone(), "forward")],
                privilege_edge: edge(principal, "can_admin", permission.clone(), "forward"),
                permission_account_edge: edge(permission, "belongs_to", account, "forward"),
            }],
            truncated: false,
        });
        assert_eq!(attack_paths.counts.as_option().unwrap().paths, 1);
        assert_eq!(attack_paths.paths[0].access_relation, "can_admin");
        assert_eq!(attack_paths.paths[0].traversal_edges.len(), 1);

        for direction in [
            StoreCatalogDirection::Incoming,
            StoreCatalogDirection::Outgoing,
        ] {
            let relations = catalog_relation_response(StoreCatalogRelationPage {
                tenant_id: "tenant-a".to_owned(),
                graph_revision: 42,
                relations: vec![EntityCatalogRelation {
                    direction,
                    relation: "owns".to_owned(),
                    entity: entity.clone(),
                }],
                truncated: true,
                next_after_agent_key: entity.agent_key.clone(),
                next_after_relation: "owns".to_owned(),
                next_after_direction: Some(direction),
            });
            assert_eq!(
                relations.relations[0].direction.as_known(),
                match direction {
                    StoreCatalogDirection::Incoming => Some(EntityRelationDirection::Incoming),
                    StoreCatalogDirection::Outgoing => Some(EntityRelationDirection::Outgoing),
                }
            );
            assert_ne!(
                relations.next_after_direction.as_known(),
                Some(EntityRelationDirection::Unspecified)
            );
        }
        let first_page = catalog_relation_response(StoreCatalogRelationPage {
            tenant_id: "tenant-a".to_owned(),
            graph_revision: 42,
            relations: Vec::new(),
            truncated: false,
            next_after_agent_key: String::new(),
            next_after_relation: String::new(),
            next_after_direction: None,
        });
        assert_eq!(
            first_page.next_after_direction.as_known(),
            Some(EntityRelationDirection::Unspecified)
        );
    }

    #[test]
    fn graph_projection_helpers_preserve_identity_bindings_and_query_variables() {
        let entity_a = context_entity("entity-a", "service");
        let entity_b = context_entity("entity-b", "team");
        let edge = context_edge("assertion-a");

        let projected_entity = graph_entity(entity_a.clone());
        assert_eq!(projected_entity.authority, "provider");
        assert_eq!(projected_entity.source_runtime_id, "runtime-a");
        assert_eq!(
            projected_entity
                .properties
                .get("region")
                .map(String::as_str),
            Some("us-west-2")
        );
        let projected_edge = graph_edge(edge.clone());
        assert_eq!(projected_edge.assertion_id, "assertion-a");
        assert_eq!(projected_edge.relation, "owns");

        let path = graph_path(ContextPath {
            entities: vec![entity_a.clone(), entity_b.clone()],
            edges: vec![edge.clone()],
        });
        assert_eq!(path.entities.len(), 2);
        assert_eq!(path.edges.len(), 1);

        let matched = query_match(ContextQueryMatch {
            entities: BTreeMap::from([("service".to_owned(), entity_a.clone())]),
            edges: BTreeMap::from([("ownership".to_owned(), edge.clone())]),
        });
        assert_eq!(matched.entities[0].variable, "service");
        assert_eq!(matched.edges[0].variable, "ownership");

        let expanded = expand_response(Neighborhood {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            graph_revision: 42,
            root: entity_a,
            entities: vec![entity_b],
            edges: vec![edge],
            truncated: true,
        });
        assert_eq!(expanded.tenant_id, "tenant-a");
        assert_eq!(expanded.graph_revision, 42);
        assert!(expanded.truncated);
        assert_eq!(expanded.entities.len(), 1);
    }

    #[test]
    fn rpc_error_mappers_keep_client_faults_distinct_from_backend_failures() {
        for message in [
            "invalid exposure coverage profile",
            "exposure coverage limit must be positive",
            "exposure coverage requires an indicator",
        ] {
            assert_eq!(
                exposure_store_error(StoreError::Conflict(message.to_owned())).code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            exposure_store_error(StoreError::Conflict("projection changed".to_owned())).code,
            ErrorCode::Unavailable
        );

        for message in [
            "invalid entity catalog request",
            "catalog limit must be positive",
            "filter contains duplicates",
            "filter exceeds its bound",
            "catalog cursor is incomplete",
            "key is not tenant scoped",
            "catalog directions are invalid",
        ] {
            assert_eq!(
                catalog_store_error(StoreError::Conflict(message.to_owned())).code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            catalog_store_error(StoreError::Conflict("entity was not found".to_owned())).code,
            ErrorCode::NotFound
        );
        assert_eq!(
            catalog_store_error(StoreError::Conflict("projection changed".to_owned())).code,
            ErrorCode::Unavailable
        );

        assert_eq!(
            context_error(ContextError::EntityNotFound).code,
            ErrorCode::NotFound
        );
        assert_eq!(
            context_error(ContextError::BackendUnavailable("offline".to_owned())).code,
            ErrorCode::Unavailable
        );
        assert_eq!(
            context_error(ContextError::InvalidLimit).code,
            ErrorCode::InvalidArgument
        );
    }
}
