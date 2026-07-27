use std::{future::Future, sync::Arc, time::Duration};

use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, FactQuery, GraphPath as ContextPath,
    Neighborhood, QueryAbsentEdge as ContextQueryAbsentEdge,
    QueryDirection as ContextQueryDirection, QueryEdge as ContextQueryEdge,
    QueryMatch as ContextQueryMatch, QueryNode as ContextQueryNode,
};
use cerebro_organizational_model::{AssertionId, EntityId, TenantId};
use cerebro_security_lifecycle::{
    LifecycleQuery, LifecycleState, ProjectedResource, QueryResult as LifecycleQueryResult,
    QuerySource, SubjectKind, SubjectLocator, canonical_resource_urn, query_records_with_source,
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

pub(crate) fn router(
    graph: Arc<dyn AgentGraph>,
    catalog_summary: Option<CatalogSummary>,
    tenant_auth: TenantRequestAuth,
) -> Router {
    let service = Arc::new(GraphRpc {
        graph,
        catalog_summary,
        tenant_auth,
    });
    let router = OrganizationalGraphServiceExt::register(Arc::clone(&service), Router::new());
    SecurityLifecycleServiceExt::register(service, router)
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

    async fn lifecycle_records(
        &self,
        tenant: &TenantId,
        query: &LifecycleQuery,
    ) -> Result<LifecycleQueryResult, ConnectError> {
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
}
