#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Bounded, tenant-scoped graph operations for agents and product surfaces.
//!
//! This crate translates the organizational graph into stable context records
//! and exposes two read paths:
//!
//! - [`AgentContext`] provides synchronous operations over an in-process
//!   [`GraphRead`] implementation;
//! - [`AgentGraph`] defines the asynchronous backend contract used by hosts,
//!   with [`MemoryAgentGraph`] as the in-memory implementation.
//!
//! All traversal, search, and typed-query operations require an explicit tenant
//! and enforce hard depth, result, root, node, edge, and absence-check bounds.
//! Query construction is typed and validated; this crate does not accept Cypher,
//! execute arbitrary procedures, cross tenant boundaries, mutate the graph, or
//! claim that a truncated result is complete. Backends own durable availability
//! and revision truth, while callers own authorization to expose returned facts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use cerebro_organizational_graph::GraphRead;
use cerebro_organizational_model::{
    AssertionId, Entity, EntityId, EntityKind, GraphAssertion, TenantId,
};
use serde::Serialize;
use tokio::sync::RwLock;

const MAX_DEPTH: usize = 6;
const MAX_RESULTS: usize = 500;
const MAX_ROOTS: usize = 100;
const MAX_QUERY_NODES: usize = 8;
const MAX_QUERY_EDGES: usize = 12;
const MAX_QUERY_ABSENCE_CHECKS: usize = 8;
const MAX_QUERY_KEYS_PER_NODE: usize = 100;
const MAX_QUERY_KINDS: usize = 29;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Rejection produced by the bounded context or backend contract.
pub enum ContextError {
    /// Requested result limit is outside the inclusive range `1..=500`.
    InvalidLimit,
    /// Requested traversal depth is outside the inclusive range `1..=6`.
    InvalidDepth,
    /// A batched root key is empty or not already whitespace-normalized.
    InvalidRootKey,
    /// Batched root count is outside the inclusive range `1..=100`.
    InvalidRootCount,
    /// Requested entity, assertion, or stable key is absent in the tenant graph.
    EntityNotFound,
    /// Typed fact query violates a structural, schema, or semantic constraint.
    InvalidQuery(String),
    /// Backend could not provide an authoritative read.
    BackendUnavailable(String),
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("result limit must be between 1 and 500"),
            Self::InvalidDepth => formatter.write_str("graph depth must be between 1 and 6"),
            Self::InvalidRootKey => {
                formatter.write_str("graph root keys must be non-empty and normalized")
            }
            Self::InvalidRootCount => {
                formatter.write_str("graph root count must be between 1 and 100")
            }
            Self::EntityNotFound => formatter.write_str("entity was not found"),
            Self::InvalidQuery(message) => write!(formatter, "invalid graph query: {message}"),
            Self::BackendUnavailable(message) => {
                write!(formatter, "graph backend unavailable: {message}")
            }
        }
    }
}

impl Error for ContextError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Source-attributed directed assertion exposed to an agent.
pub struct ContextEdge {
    /// Stable assertion identity used for explanation and deterministic ordering.
    pub assertion_id: AssertionId,
    /// Source entity of the directed assertion.
    pub from: EntityId,
    /// Organizational relation wire name, or `represents` for identity bindings.
    pub relation: String,
    /// Destination entity of the directed assertion.
    pub to: EntityId,
    /// Collector runtime whose evidence supports the assertion.
    pub source_runtime_id: String,
    /// Trusted Cerebro application workspace shared by the edge endpoints.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub application_workspace_id: String,
    /// Whether this edge projects an identity-binding assertion.
    pub identity_binding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Agent-facing projection of one tenant-scoped domain entity.
pub struct ContextEntity {
    /// Native graph identity, scoped by the enclosing tenant operation.
    pub entity_id: EntityId,
    /// Stable provider-facing or canonical key suitable for later resolution.
    pub agent_key: String,
    /// Organizational entity-kind wire name.
    pub entity_kind: String,
    /// Structured authority that owns the entity's identity namespace.
    pub authority: serde_json::Value,
    /// Human-readable label; never used as stable identity.
    pub label: String,
    /// Deterministically ordered source properties plus the stable `entity_urn`.
    pub properties: std::collections::BTreeMap<String, String>,
}

impl ContextEntity {
    /// Projects a domain entity into the bounded agent-facing representation.
    ///
    /// The stable agent key is also inserted as the `entity_urn` property. A
    /// validated `entity_type` presentation property preserves provider-specific
    /// catalog kinds; otherwise the sealed domain kind is used. An authority
    /// serialization failure degrades only that display projection to JSON
    /// `null`; it does not change the native entity identity.
    pub fn from_domain(entity: &Entity) -> Self {
        let agent_key = entity.agent_key();
        let mut properties = entity.properties().clone();
        properties.insert("entity_urn".to_owned(), agent_key.clone());
        Self {
            entity_id: entity.id().clone(),
            agent_key,
            entity_kind: entity
                .properties()
                .get("entity_type")
                .filter(|value| {
                    !value.is_empty()
                        && value.trim() == value.as_str()
                        && !value.chars().any(char::is_control)
                })
                .cloned()
                .unwrap_or_else(|| entity.kind().as_str().to_owned()),
            authority: serde_json::to_value(entity.authority()).unwrap_or(serde_json::Value::Null),
            label: entity.label().to_owned(),
            properties,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Bounded neighborhood around one root entity at one graph revision.
pub struct Neighborhood {
    /// Tenant from which every entity and edge was read.
    pub tenant_id: TenantId,
    /// Backend graph revision observed for this response.
    pub graph_revision: u64,
    /// Requested root, returned separately even when no edges are reachable.
    pub root: ContextEntity,
    /// Non-root endpoints required to interpret the retained edges.
    pub entities: Vec<ContextEntity>,
    /// Retained reachable assertions, ordered by assertion identity.
    pub edges: Vec<ContextEdge>,
    /// Whether at least one additional reachable edge existed beyond the limit.
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One directed, simple path through the tenant graph.
pub struct GraphPath {
    /// Ordered path entities from source through destination.
    pub entities: Vec<ContextEntity>,
    /// Ordered directed assertions connecting adjacent entities.
    pub edges: Vec<ContextEdge>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Direction in which an absent-edge constraint is evaluated.
pub enum QueryDirection {
    /// Reject a match when the bound node has a matching outgoing assertion.
    Outgoing,
    /// Reject a match when the bound node has a matching incoming assertion.
    Incoming,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Entity pattern bound to one variable in a typed fact query.
pub struct QueryNode {
    /// Unique lower-snake-case variable used by edges and result bindings.
    pub variable: String,
    /// Allowed entity-kind wire names; empty means any kind.
    pub kinds: Vec<String>,
    /// Allowed native IDs or stable agent keys; empty means any key.
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Required directed assertion pattern in a typed fact query.
pub struct QueryEdge {
    /// Unique lower-snake-case variable for the matched assertion.
    pub variable: String,
    /// Previously declared source-node variable.
    pub from_variable: String,
    /// Organizational relation wire name, including `represents`.
    pub relation: String,
    /// Previously declared destination-node variable.
    pub to_variable: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Negative assertion constraint applied after positive bindings are complete.
pub struct QueryAbsentEdge {
    /// Declared node variable from which absence is evaluated.
    pub bound_variable: String,
    /// Incoming or outgoing direction relative to the bound node.
    pub direction: QueryDirection,
    /// Organizational relation whose presence would reject the match.
    pub relation: String,
    /// Allowed kind of the unbound endpoint; empty means any kind.
    pub other_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Validated, bounded graph-pattern query.
///
/// Queries contain at most eight nodes, twelve required edges, eight absence
/// checks, and 500 results. A query without edges must have exactly one node;
/// otherwise its positive edge graph must connect every declared node. Fields
/// are private so a validated query cannot be mutated into an invalid shape.
pub struct FactQuery {
    nodes: Vec<QueryNode>,
    edges: Vec<QueryEdge>,
    absent_edges: Vec<QueryAbsentEdge>,
    limit: usize,
}

impl FactQuery {
    /// Validates and constructs a typed fact query.
    ///
    /// Node and edge variables must be unique lower snake case. Kinds and
    /// relations must be known organizational-model wire names, required edges
    /// must be type-compatible, node keys must be unique and normalized, and
    /// the positive pattern must be connected.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidLimit`] for a result bound outside
    /// `1..=500`, or [`ContextError::InvalidQuery`] for any invalid query shape.
    pub fn new(
        nodes: Vec<QueryNode>,
        edges: Vec<QueryEdge>,
        absent_edges: Vec<QueryAbsentEdge>,
        limit: usize,
    ) -> Result<Self, ContextError> {
        validate_query(&nodes, &edges, &absent_edges, limit)?;
        Ok(Self {
            nodes,
            edges,
            absent_edges,
            limit,
        })
    }

    /// Returns the validated node patterns in caller-supplied order.
    pub fn nodes(&self) -> &[QueryNode] {
        &self.nodes
    }

    /// Returns the validated required-edge patterns in caller-supplied order.
    pub fn edges(&self) -> &[QueryEdge] {
        &self.edges
    }

    /// Returns the validated negative-edge constraints in caller-supplied order.
    pub fn absent_edges(&self) -> &[QueryAbsentEdge] {
        &self.absent_edges
    }

    /// Returns the maximum number of matches that execution may return.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One complete variable binding produced by a typed fact query.
pub struct QueryMatch {
    /// Node variables mapped to their tenant-scoped entities.
    pub entities: BTreeMap<String, ContextEntity>,
    /// Edge variables mapped to their source-attributed assertions.
    pub edges: BTreeMap<String, ContextEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Bounded, deterministic result of executing a [`FactQuery`].
pub struct QueryResult {
    /// Tenant from which every binding was read.
    pub tenant_id: TenantId,
    /// Backend graph revision observed for this query.
    pub graph_revision: u64,
    /// Deterministically ordered, deduplicated variable bindings.
    pub matches: Vec<QueryMatch>,
    /// Whether at least one additional distinct match existed beyond the limit.
    pub truncated: bool,
}

/// Synchronous bounded-context facade over one borrowed graph reader.
///
/// Every operation receives an explicit tenant. The facade performs no caching
/// or authorization and never reads across tenants.
pub struct AgentContext<'a, Reader: GraphRead> {
    reader: &'a Reader,
}

impl<'a, Reader: GraphRead> AgentContext<'a, Reader> {
    /// Borrows a graph reader for bounded synchronous operations.
    pub fn new(reader: &'a Reader) -> Self {
        Self { reader }
    }

    /// Searches entity label and native identity within one tenant.
    ///
    /// Matching is case-insensitive. An empty query matches all entities, and an
    /// empty `kinds` slice disables kind filtering. Results follow the reader's
    /// deterministic entity order and stop at `limit`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidLimit`] unless `limit` is in `1..=500`.
    pub fn search(
        &self,
        tenant_id: &TenantId,
        query: &str,
        kinds: &[EntityKind],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError> {
        validate_limit(limit)?;
        let query = query.trim().to_lowercase();
        let mut result = Vec::new();
        for entity in self.reader.entities(tenant_id) {
            if !kinds.is_empty() && !kinds.contains(entity.kind()) {
                continue;
            }
            if query.is_empty()
                || entity.label().to_lowercase().contains(&query)
                || entity.id().as_str().to_lowercase().contains(&query)
            {
                result.push(ContextEntity::from_domain(&entity));
                if result.len() == limit {
                    break;
                }
            }
        }
        Ok(result)
    }

    /// Returns one entity by native identity within the supplied tenant.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EntityNotFound`] when that tenant does not contain
    /// the entity.
    pub fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError> {
        self.reader
            .entity(tenant_id, entity_id)
            .map(|entity| ContextEntity::from_domain(&entity))
            .ok_or(ContextError::EntityNotFound)
    }

    /// Expands an undirected neighborhood around one root entity.
    ///
    /// Traversal treats assertions as adjacent in either direction, while the
    /// returned edges preserve their source direction. Edges are deduplicated
    /// and ordered by assertion identity before the result bound is applied.
    /// Only non-root endpoints needed to interpret retained edges are returned.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidDepth`] or [`ContextError::InvalidLimit`]
    /// for bounds outside `1..=6` and `1..=500`, respectively, or
    /// [`ContextError::EntityNotFound`] when the root is absent.
    pub fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError> {
        validate_depth(depth)?;
        validate_limit(limit)?;
        let root = self.get(tenant_id, root_id)?;
        let all_entities = self.reader.entities(tenant_id);
        let all_assertions = self.reader.assertions(tenant_id);
        let edges: Vec<_> = all_assertions.iter().map(context_edge).collect();
        let mut seen = BTreeSet::from([root_id.clone()]);
        let mut frontier = BTreeSet::from([root_id.clone()]);
        let mut selected_edges = Vec::new();

        for _ in 0..depth {
            let mut next = BTreeSet::new();
            for edge in &edges {
                if frontier.contains(&edge.from) || frontier.contains(&edge.to) {
                    selected_edges.push(edge.clone());
                    let candidate = if frontier.contains(&edge.from) {
                        &edge.to
                    } else {
                        &edge.from
                    };
                    if seen.insert(candidate.clone()) {
                        next.insert(candidate.clone());
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        selected_edges.sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        selected_edges.dedup_by(|left, right| left.assertion_id == right.assertion_id);
        let truncated = selected_edges.len() > limit;
        selected_edges.truncate(limit);
        let retained_entities = selected_edges
            .iter()
            .flat_map(|edge| [&edge.from, &edge.to])
            .cloned()
            .collect::<BTreeSet<_>>();
        let entities = all_entities
            .into_iter()
            .filter(|entity| retained_entities.contains(entity.id()) && entity.id() != root_id)
            .map(|entity| ContextEntity::from_domain(&entity))
            .collect();
        Ok(Neighborhood {
            tenant_id: tenant_id.clone(),
            graph_revision: self.reader.graph_revision(tenant_id),
            root,
            entities,
            edges: selected_edges,
            truncated,
        })
    }

    /// Finds bounded directed simple paths from one entity to another.
    ///
    /// Paths are considered by increasing edge count and then by assertion
    /// identity. Cycles are excluded within each candidate path. Both endpoints
    /// must exist before traversal begins.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidDepth`] or [`ContextError::InvalidLimit`]
    /// for invalid bounds, or [`ContextError::EntityNotFound`] when either
    /// endpoint is absent.
    pub fn find_paths(
        &self,
        tenant_id: &TenantId,
        from: &EntityId,
        to: &EntityId,
        max_depth: usize,
        limit: usize,
    ) -> Result<Vec<GraphPath>, ContextError> {
        validate_depth(max_depth)?;
        validate_limit(limit)?;
        self.get(tenant_id, from)?;
        self.get(tenant_id, to)?;
        let mut edges: Vec<_> = self
            .reader
            .assertions(tenant_id)
            .iter()
            .map(context_edge)
            .collect();
        edges.sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        let mut paths = Vec::new();
        for path_depth in 1..=max_depth {
            let mut visited = BTreeSet::from([from.clone()]);
            let mut edge_path = Vec::new();
            self.walk_paths(
                tenant_id,
                from,
                to,
                path_depth,
                limit,
                &edges,
                &mut visited,
                &mut edge_path,
                &mut paths,
            );
            if paths.len() == limit {
                break;
            }
        }
        Ok(paths)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_paths(
        &self,
        tenant_id: &TenantId,
        current: &EntityId,
        target: &EntityId,
        depth_remaining: usize,
        limit: usize,
        edges: &[ContextEdge],
        visited: &mut BTreeSet<EntityId>,
        edge_path: &mut Vec<ContextEdge>,
        result: &mut Vec<GraphPath>,
    ) {
        if result.len() >= limit || depth_remaining == 0 {
            return;
        }
        for edge in edges {
            if &edge.from != current {
                continue;
            }
            if !visited.insert(edge.to.clone()) {
                continue;
            }
            edge_path.push(edge.clone());
            if &edge.to == target {
                if depth_remaining == 1 {
                    let mut ids = Vec::with_capacity(edge_path.len() + 1);
                    ids.push(edge_path[0].from.clone());
                    ids.extend(edge_path.iter().map(|item| item.to.clone()));
                    let entities = ids
                        .iter()
                        .filter_map(|id| self.reader.entity(tenant_id, id))
                        .map(|entity| ContextEntity::from_domain(&entity))
                        .collect();
                    result.push(GraphPath {
                        entities,
                        edges: edge_path.clone(),
                    });
                }
            } else if depth_remaining > 1 {
                self.walk_paths(
                    tenant_id,
                    &edge.to,
                    target,
                    depth_remaining - 1,
                    limit,
                    edges,
                    visited,
                    edge_path,
                    result,
                );
            }
            edge_path.pop();
            visited.remove(&edge.to);
            if result.len() >= limit {
                break;
            }
        }
    }

    /// Returns the source-attributed edge for one assertion in the tenant graph.
    ///
    /// Returns `None` when the assertion is absent; it never searches another
    /// tenant for a matching identifier.
    pub fn explain(&self, tenant_id: &TenantId, assertion_id: &AssertionId) -> Option<ContextEdge> {
        self.reader
            .assertions(tenant_id)
            .iter()
            .find(|item| item.id() == assertion_id)
            .map(context_edge)
    }

    /// Executes a previously validated typed fact query against one tenant.
    ///
    /// Matches are sorted and deduplicated before the query limit is applied.
    /// Negative constraints test absence only against the same tenant snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if query execution encounters an invalid binding
    /// state. Query construction errors are normally rejected by [`FactQuery::new`].
    pub fn query(
        &self,
        tenant_id: &TenantId,
        query: &FactQuery,
    ) -> Result<QueryResult, ContextError> {
        let entities = self
            .reader
            .entities(tenant_id)
            .into_iter()
            .map(|entity| {
                let context = ContextEntity::from_domain(&entity);
                (context.entity_id.clone(), context)
            })
            .collect::<BTreeMap<_, _>>();
        let mut edges = self
            .reader
            .assertions(tenant_id)
            .iter()
            .map(context_edge)
            .collect::<Vec<_>>();
        edges.sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        execute_query(
            tenant_id,
            self.reader.graph_revision(tenant_id),
            query,
            &entities,
            &edges,
        )
    }
}

#[async_trait]
/// Asynchronous backend contract for bounded, tenant-scoped agent graph reads.
///
/// Implementations must preserve tenant isolation, enforce the documented hard
/// bounds, return the durable revision they actually observed, and use
/// [`ContextError::BackendUnavailable`] rather than returning partial success as
/// authoritative data. Methods never grant a caller permission to expose facts.
pub trait AgentGraph: Send + Sync {
    /// Verifies that the backend can serve authoritative reads.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::BackendUnavailable`] or another backend-specific
    /// context error when reads should not proceed.
    async fn health(&self) -> Result<(), ContextError>;

    /// Returns the durable tenant graph revision observed by the backend.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the revision cannot be read authoritatively.
    async fn revision(&self, tenant_id: &TenantId) -> Result<u64, ContextError>;

    /// Searches bounded entity labels and stable identities within one tenant.
    ///
    /// An empty `kinds` slice disables kind filtering. Implementations must apply
    /// filters before the result bound and return deterministic ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidLimit`] for an invalid bound or a backend
    /// error when the search cannot be completed authoritatively.
    async fn search(
        &self,
        tenant_id: &TenantId,
        query: &str,
        kinds: &[String],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError>;

    /// Returns one entity by native identity within the supplied tenant.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EntityNotFound`] when absent, or a backend error.
    async fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError>;

    /// Resolves either a native entity ID or a stable provider-facing key.
    ///
    /// Arbitrary property values are not resolution keys. Implementations must
    /// reject ambiguous external keys rather than selecting one match.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EntityNotFound`] when no stable key matches,
    /// [`ContextError::BackendUnavailable`] when a key is ambiguous, or another
    /// backend error.
    async fn resolve(&self, tenant_id: &TenantId, key: &str)
    -> Result<ContextEntity, ContextError>;

    /// Returns at most `limit` assertion edges and only the entity endpoints
    /// needed to interpret those edges. `truncated` is true only when another
    /// reachable edge exists beyond that bound.
    ///
    /// # Errors
    ///
    /// Returns an invalid-bound error, [`ContextError::EntityNotFound`] for an
    /// absent root, or a backend error.
    async fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError>;

    /// Expands multiple normalized root keys under one tenant and shared bounds.
    ///
    /// Missing roots are omitted from the returned map. Any other root error
    /// aborts the batch, preventing a mixed authoritative/failed result. Keys in
    /// the map are the exact validated request keys.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidRootCount`],
    /// [`ContextError::InvalidRootKey`], an invalid depth/limit error, or the
    /// first non-absence error returned by resolution or expansion.
    async fn expand_many(
        &self,
        tenant_id: &TenantId,
        root_keys: &[String],
        depth: usize,
        limit: usize,
    ) -> Result<BTreeMap<String, Neighborhood>, ContextError> {
        validate_root_keys(root_keys)?;
        validate_depth(depth)?;
        validate_limit(limit)?;
        let mut neighborhoods = BTreeMap::new();
        for root_key in root_keys {
            let root = match self.resolve(tenant_id, root_key).await {
                Ok(root) => root,
                Err(ContextError::EntityNotFound) => continue,
                Err(error) => return Err(error),
            };
            neighborhoods.insert(
                root_key.clone(),
                self.expand(tenant_id, &root.entity_id, depth, limit)
                    .await?,
            );
        }
        Ok(neighborhoods)
    }

    /// Finds bounded directed simple paths between two tenant entities.
    ///
    /// # Errors
    ///
    /// Returns an invalid-bound or missing-entity error, or a backend error.
    async fn find_paths(
        &self,
        tenant_id: &TenantId,
        from: &EntityId,
        to: &EntityId,
        max_depth: usize,
        limit: usize,
    ) -> Result<Vec<GraphPath>, ContextError>;

    /// Resolves one assertion into its source-attributed context edge.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EntityNotFound`] when absent, or a backend error.
    async fn explain(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionId,
    ) -> Result<ContextEdge, ContextError>;

    /// Executes one validated typed fact query against one tenant revision.
    ///
    /// # Errors
    ///
    /// Returns a query or backend error when no authoritative result can be
    /// produced.
    async fn query(
        &self,
        tenant_id: &TenantId,
        query: &FactQuery,
    ) -> Result<QueryResult, ContextError>;
}

#[derive(Clone)]
/// Concurrent in-memory [`AgentGraph`] backed by an organizational graph.
///
/// This implementation is useful for embedded runtimes and deterministic tests.
/// Its health check confirms only in-process availability; it is not proof of
/// external source freshness or durable persistence.
pub struct MemoryAgentGraph {
    graph: Arc<RwLock<cerebro_organizational_graph::OrganizationalGraph>>,
}

impl MemoryAgentGraph {
    /// Wraps an organizational graph in an asynchronous read/write lock.
    pub fn new(graph: cerebro_organizational_graph::OrganizationalGraph) -> Self {
        Self {
            graph: Arc::new(RwLock::new(graph)),
        }
    }
}

#[async_trait]
impl AgentGraph for MemoryAgentGraph {
    async fn health(&self) -> Result<(), ContextError> {
        Ok(())
    }

    async fn revision(&self, tenant_id: &TenantId) -> Result<u64, ContextError> {
        Ok(self.graph.read().await.graph_revision(tenant_id))
    }

    async fn search(
        &self,
        tenant_id: &TenantId,
        query: &str,
        kinds: &[String],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError> {
        validate_limit(limit)?;
        let graph = self.graph.read().await;
        let query = query.trim().to_lowercase();
        let mut entities = BTreeMap::new();
        for entity in graph.entities(tenant_id) {
            let entity = ContextEntity::from_domain(&entity);
            if !kinds.is_empty() && !kinds.contains(&entity.entity_kind) {
                continue;
            }
            if query.is_empty()
                || entity.label.to_lowercase().contains(&query)
                || entity.entity_id.as_str().to_lowercase().contains(&query)
            {
                entities.insert((entity.label.clone(), entity.entity_id.clone()), entity);
                if entities.len() > limit {
                    entities.pop_last();
                }
            }
        }
        Ok(entities.into_values().collect())
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph).get(tenant_id, entity_id)
    }

    async fn resolve(
        &self,
        tenant_id: &TenantId,
        key: &str,
    ) -> Result<ContextEntity, ContextError> {
        let graph = self.graph.read().await;
        let key = key.trim();
        let mut matches = graph
            .entities(tenant_id)
            .into_iter()
            .filter(|entity| entity.id().as_str() == key || entity.agent_key() == key)
            .take(2)
            .map(|entity| ContextEntity::from_domain(&entity));
        let entity = matches.next().ok_or(ContextError::EntityNotFound)?;
        if matches.next().is_some() {
            return Err(ContextError::BackendUnavailable(
                "external entity key is ambiguous".to_owned(),
            ));
        }
        Ok(entity)
    }

    async fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph).expand(tenant_id, root_id, depth, limit)
    }

    async fn find_paths(
        &self,
        tenant_id: &TenantId,
        from: &EntityId,
        to: &EntityId,
        max_depth: usize,
        limit: usize,
    ) -> Result<Vec<GraphPath>, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph).find_paths(tenant_id, from, to, max_depth, limit)
    }

    async fn explain(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionId,
    ) -> Result<ContextEdge, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph)
            .explain(tenant_id, assertion_id)
            .ok_or(ContextError::EntityNotFound)
    }

    async fn query(
        &self,
        tenant_id: &TenantId,
        query: &FactQuery,
    ) -> Result<QueryResult, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph).query(tenant_id, query)
    }
}

fn execute_query(
    tenant_id: &TenantId,
    graph_revision: u64,
    query: &FactQuery,
    entities: &BTreeMap<EntityId, ContextEntity>,
    edges: &[ContextEdge],
) -> Result<QueryResult, ContextError> {
    let node_patterns = query
        .nodes
        .iter()
        .map(|node| (node.variable.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let target = query.limit.saturating_add(1);
    let mut matches = Vec::new();
    if query.edges.is_empty() {
        let node = &query.nodes[0];
        for entity in entities
            .values()
            .filter(|entity| node_matches(node, entity))
        {
            matches.push(QueryMatch {
                entities: BTreeMap::from([(node.variable.clone(), entity.clone())]),
                edges: BTreeMap::new(),
            });
            if matches.len() == target {
                break;
            }
        }
    } else {
        let mut used_edges = vec![false; query.edges.len()];
        collect_query_matches(
            query,
            &node_patterns,
            entities,
            edges,
            &mut used_edges,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
            &mut matches,
            target,
        );
    }
    matches.sort_by(query_match_order);
    matches.dedup();
    let truncated = matches.len() > query.limit;
    matches.truncate(query.limit);
    Ok(QueryResult {
        tenant_id: tenant_id.clone(),
        graph_revision,
        matches,
        truncated,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_query_matches(
    query: &FactQuery,
    node_patterns: &BTreeMap<&str, &QueryNode>,
    entities: &BTreeMap<EntityId, ContextEntity>,
    graph_edges: &[ContextEdge],
    used_edges: &mut [bool],
    entity_bindings: &mut BTreeMap<String, EntityId>,
    edge_bindings: &mut BTreeMap<String, ContextEdge>,
    matches: &mut Vec<QueryMatch>,
    target: usize,
) {
    if matches.len() >= target {
        return;
    }
    let Some(edge_index) = next_query_edge(query, used_edges, entity_bindings) else {
        if !query_absence_holds(query, node_patterns, entities, graph_edges, entity_bindings) {
            return;
        }
        let bound_entities = entity_bindings
            .iter()
            .filter_map(|(variable, entity_id)| {
                entities
                    .get(entity_id)
                    .cloned()
                    .map(|entity| (variable.clone(), entity))
            })
            .collect::<BTreeMap<_, _>>();
        if bound_entities.len() == query.nodes.len() {
            matches.push(QueryMatch {
                entities: bound_entities,
                edges: edge_bindings.clone(),
            });
        }
        return;
    };
    let pattern = &query.edges[edge_index];
    let from_pattern = node_patterns[pattern.from_variable.as_str()];
    let to_pattern = node_patterns[pattern.to_variable.as_str()];
    used_edges[edge_index] = true;
    for edge in graph_edges
        .iter()
        .filter(|edge| edge.relation == pattern.relation)
    {
        if entity_bindings
            .get(&pattern.from_variable)
            .is_some_and(|entity_id| entity_id != &edge.from)
            || entity_bindings
                .get(&pattern.to_variable)
                .is_some_and(|entity_id| entity_id != &edge.to)
        {
            continue;
        }
        let (Some(from), Some(to)) = (entities.get(&edge.from), entities.get(&edge.to)) else {
            continue;
        };
        if !node_matches(from_pattern, from) || !node_matches(to_pattern, to) {
            continue;
        }
        let inserted_from = entity_bindings
            .insert(pattern.from_variable.clone(), edge.from.clone())
            .is_none();
        let inserted_to = entity_bindings
            .insert(pattern.to_variable.clone(), edge.to.clone())
            .is_none();
        edge_bindings.insert(pattern.variable.clone(), edge.clone());
        collect_query_matches(
            query,
            node_patterns,
            entities,
            graph_edges,
            used_edges,
            entity_bindings,
            edge_bindings,
            matches,
            target,
        );
        edge_bindings.remove(&pattern.variable);
        if inserted_to {
            entity_bindings.remove(&pattern.to_variable);
        }
        if inserted_from {
            entity_bindings.remove(&pattern.from_variable);
        }
        if matches.len() >= target {
            break;
        }
    }
    used_edges[edge_index] = false;
}

fn next_query_edge(
    query: &FactQuery,
    used: &[bool],
    bindings: &BTreeMap<String, EntityId>,
) -> Option<usize> {
    query
        .edges
        .iter()
        .enumerate()
        .filter(|(index, _)| !used[*index])
        .max_by_key(|(_, edge)| {
            usize::from(bindings.contains_key(&edge.from_variable))
                + usize::from(bindings.contains_key(&edge.to_variable))
        })
        .map(|(index, _)| index)
}

fn query_absence_holds(
    query: &FactQuery,
    node_patterns: &BTreeMap<&str, &QueryNode>,
    entities: &BTreeMap<EntityId, ContextEntity>,
    edges: &[ContextEdge],
    bindings: &BTreeMap<String, EntityId>,
) -> bool {
    query.absent_edges.iter().all(|absence| {
        let Some(bound) = bindings.get(&absence.bound_variable) else {
            return false;
        };
        !edges.iter().any(|edge| {
            if edge.relation != absence.relation {
                return false;
            }
            let other = match absence.direction {
                QueryDirection::Outgoing if &edge.from == bound => entities.get(&edge.to),
                QueryDirection::Incoming if &edge.to == bound => entities.get(&edge.from),
                _ => None,
            };
            other.is_some_and(|entity| {
                absence.other_kinds.is_empty()
                    || absence
                        .other_kinds
                        .iter()
                        .any(|kind| kind == &entity.entity_kind)
            })
        })
    }) && node_patterns
        .keys()
        .all(|variable| bindings.contains_key(*variable))
}

fn node_matches(pattern: &QueryNode, entity: &ContextEntity) -> bool {
    (pattern.kinds.is_empty() || pattern.kinds.contains(&entity.entity_kind))
        && (pattern.keys.is_empty()
            || pattern
                .keys
                .iter()
                .any(|key| key == entity.entity_id.as_str() || key == entity.agent_key.as_str()))
}

fn query_match_order(left: &QueryMatch, right: &QueryMatch) -> std::cmp::Ordering {
    let left_entities = left
        .entities
        .iter()
        .map(|(variable, entity)| (variable, &entity.entity_id))
        .collect::<Vec<_>>();
    let right_entities = right
        .entities
        .iter()
        .map(|(variable, entity)| (variable, &entity.entity_id))
        .collect::<Vec<_>>();
    left_entities.cmp(&right_entities).then_with(|| {
        left.edges
            .iter()
            .map(|(variable, edge)| (variable, &edge.assertion_id))
            .collect::<Vec<_>>()
            .cmp(
                &right
                    .edges
                    .iter()
                    .map(|(variable, edge)| (variable, &edge.assertion_id))
                    .collect::<Vec<_>>(),
            )
    })
}

fn validate_query(
    nodes: &[QueryNode],
    edges: &[QueryEdge],
    absent_edges: &[QueryAbsentEdge],
    limit: usize,
) -> Result<(), ContextError> {
    if nodes.is_empty() || nodes.len() > MAX_QUERY_NODES {
        return Err(ContextError::InvalidQuery(format!(
            "node count must be between 1 and {MAX_QUERY_NODES}"
        )));
    }
    if edges.len() > MAX_QUERY_EDGES {
        return Err(ContextError::InvalidQuery(format!(
            "edge count must not exceed {MAX_QUERY_EDGES}"
        )));
    }
    if absent_edges.len() > MAX_QUERY_ABSENCE_CHECKS {
        return Err(ContextError::InvalidQuery(format!(
            "absence check count must not exceed {MAX_QUERY_ABSENCE_CHECKS}"
        )));
    }
    validate_limit(limit)?;
    let mut node_variables = BTreeSet::new();
    let mut node_patterns = BTreeMap::new();
    for node in nodes {
        validate_query_variable(&node.variable)?;
        if !node_variables.insert(node.variable.as_str()) {
            return Err(ContextError::InvalidQuery(format!(
                "duplicate node variable {:?}",
                node.variable
            )));
        }
        validate_query_kinds(&node.kinds)?;
        node_patterns.insert(node.variable.as_str(), node);
        if node.keys.len() > MAX_QUERY_KEYS_PER_NODE
            || node
                .keys
                .iter()
                .any(|key| key.is_empty() || key.trim() != key || key.len() > 512)
            || node.keys.iter().collect::<BTreeSet<_>>().len() != node.keys.len()
        {
            return Err(ContextError::InvalidQuery(format!(
                "node {:?} has an invalid key",
                node.variable
            )));
        }
    }
    let mut edge_variables = BTreeSet::new();
    for edge in edges {
        validate_query_variable(&edge.variable)?;
        if !edge_variables.insert(edge.variable.as_str()) {
            return Err(ContextError::InvalidQuery(format!(
                "duplicate edge variable {:?}",
                edge.variable
            )));
        }
        if !node_variables.contains(edge.from_variable.as_str())
            || !node_variables.contains(edge.to_variable.as_str())
        {
            return Err(ContextError::InvalidQuery(format!(
                "edge {:?} references an unknown node variable",
                edge.variable
            )));
        }
        validate_query_relation(&edge.relation)?;
        let from = node_patterns[edge.from_variable.as_str()];
        let to = node_patterns[edge.to_variable.as_str()];
        if !from.kinds.is_empty()
            && !to.kinds.is_empty()
            && !from.kinds.iter().any(|from_kind| {
                to.kinds
                    .iter()
                    .any(|to_kind| query_relation_accepts(&edge.relation, from_kind, to_kind))
            })
        {
            return Err(ContextError::InvalidQuery(format!(
                "relation {:?} cannot connect node kinds {:?} to {:?}",
                edge.relation, from.kinds, to.kinds
            )));
        }
    }
    for absence in absent_edges {
        if !node_variables.contains(absence.bound_variable.as_str()) {
            return Err(ContextError::InvalidQuery(format!(
                "absence check references unknown node variable {:?}",
                absence.bound_variable
            )));
        }
        validate_query_relation(&absence.relation)?;
        validate_query_kinds(&absence.other_kinds)?;
        let bound = node_patterns[absence.bound_variable.as_str()];
        if !bound.kinds.is_empty()
            && !absence.other_kinds.is_empty()
            && !bound.kinds.iter().any(|bound_kind| {
                absence.other_kinds.iter().any(|other_kind| {
                    let (from, to) = match absence.direction {
                        QueryDirection::Outgoing => (bound_kind, other_kind),
                        QueryDirection::Incoming => (other_kind, bound_kind),
                    };
                    query_relation_accepts(&absence.relation, from, to)
                })
            })
        {
            return Err(ContextError::InvalidQuery(format!(
                "absence relation {:?} cannot connect node kinds {:?} and {:?}",
                absence.relation, bound.kinds, absence.other_kinds
            )));
        }
    }
    if edges.is_empty() {
        if nodes.len() != 1 {
            return Err(ContextError::InvalidQuery(
                "a query without edges must contain exactly one node".to_owned(),
            ));
        }
    } else {
        validate_connected_query(&node_variables, edges)?;
    }
    Ok(())
}

fn validate_query_variable(value: &str) -> Result<(), ContextError> {
    let mut chars = value.chars();
    if value.len() > 64
        || !chars.next().is_some_and(|first| first.is_ascii_lowercase())
        || !chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return Err(ContextError::InvalidQuery(format!(
            "variable {value:?} must be lower snake case"
        )));
    }
    Ok(())
}

fn validate_query_kinds(kinds: &[String]) -> Result<(), ContextError> {
    if kinds.len() > MAX_QUERY_KINDS
        || kinds
            .iter()
            .any(|kind| !EntityKind::is_wire_name(kind.as_str()))
        || kinds.iter().collect::<BTreeSet<_>>().len() != kinds.len()
    {
        return Err(ContextError::InvalidQuery(
            "query contains an unknown entity kind".to_owned(),
        ));
    }
    Ok(())
}

fn validate_query_relation(relation: &str) -> Result<(), ContextError> {
    if relation != "represents"
        && cerebro_organizational_model::RelationKind::from_wire(relation).is_none()
    {
        return Err(ContextError::InvalidQuery(format!(
            "unknown relation {relation:?}"
        )));
    }
    Ok(())
}

fn query_relation_accepts(relation: &str, from: &str, to: &str) -> bool {
    if relation == "represents" {
        return matches!(from, "identity" | "provider") && to == "person";
    }
    let Some(relation) = cerebro_organizational_model::RelationKind::from_wire(relation) else {
        return false;
    };
    let (Some(from), Some(to)) = (query_entity_kind(from), query_entity_kind(to)) else {
        return false;
    };
    relation.accepts(&from, &to)
}

fn query_entity_kind(value: &str) -> Option<EntityKind> {
    Some(match value {
        "person" => EntityKind::Person,
        "identity" => EntityKind::Identity,
        "team" => EntityKind::Team,
        "organization" => EntityKind::Organization,
        "repository" => EntityKind::Repository,
        "service" => EntityKind::Service,
        "application" => EntityKind::Application,
        "environment" => EntityKind::Environment,
        "account" => EntityKind::Account,
        "resource" => EntityKind::Resource,
        "group" => EntityKind::Group,
        "role" => EntityKind::Role,
        "policy" => EntityKind::Policy,
        "control" => EntityKind::Control,
        "finding" => EntityKind::Finding,
        "framework" => EntityKind::Framework,
        "program" => EntityKind::Program,
        "objective" => EntityKind::Objective,
        "rule" => EntityKind::Rule,
        "evidence" => EntityKind::Evidence,
        "assessment_run" => EntityKind::AssessmentRun,
        "assessment_result" => EntityKind::AssessmentResult,
        "assessment_snapshot" => EntityKind::AssessmentSnapshot,
        "remediation" => EntityKind::Remediation,
        "verification" => EntityKind::Verification,
        "work_item" => EntityKind::WorkItem,
        "provider" => EntityKind::Provider(
            cerebro_organizational_model::ProviderKind::parse("query.provider")
                .expect("fixed provider query kind"),
        ),
        _ => return None,
    })
}

fn validate_connected_query(
    variables: &BTreeSet<&str>,
    edges: &[QueryEdge],
) -> Result<(), ContextError> {
    let mut visited = BTreeSet::from([edges[0].from_variable.as_str()]);
    loop {
        let before = visited.len();
        for edge in edges {
            if visited.contains(edge.from_variable.as_str())
                || visited.contains(edge.to_variable.as_str())
            {
                visited.insert(edge.from_variable.as_str());
                visited.insert(edge.to_variable.as_str());
            }
        }
        if visited.len() == before {
            break;
        }
    }
    if &visited != variables {
        return Err(ContextError::InvalidQuery(
            "positive query graph must be connected".to_owned(),
        ));
    }
    Ok(())
}

fn context_edge(assertion: &GraphAssertion) -> ContextEdge {
    match assertion {
        GraphAssertion::Relationship(value) => ContextEdge {
            assertion_id: value.id().clone(),
            from: value.from().clone(),
            relation: value.relation().as_str().to_owned(),
            to: value.to().clone(),
            source_runtime_id: value.provenance().source_runtime_id().to_string(),
            application_workspace_id: value.application_workspace_id().to_owned(),
            identity_binding: false,
        },
        GraphAssertion::IdentityBinding(value) => ContextEdge {
            assertion_id: value.id().clone(),
            from: value.provider_identity().clone(),
            relation: "represents".to_owned(),
            to: value.canonical_identity().clone(),
            source_runtime_id: value.provenance().source_runtime_id().to_string(),
            application_workspace_id: String::new(),
            identity_binding: true,
        },
    }
}

fn validate_limit(limit: usize) -> Result<(), ContextError> {
    if !(1..=MAX_RESULTS).contains(&limit) {
        return Err(ContextError::InvalidLimit);
    }
    Ok(())
}

fn validate_depth(depth: usize) -> Result<(), ContextError> {
    if !(1..=MAX_DEPTH).contains(&depth) {
        return Err(ContextError::InvalidDepth);
    }
    Ok(())
}

/// Validates the closed root-key boundary used by batched expansion.
///
/// A batch must contain between one and 100 keys. Every key must be non-empty
/// and already trimmed so that the response map preserves an unambiguous exact
/// request key.
///
/// # Errors
///
/// Returns [`ContextError::InvalidRootCount`] for an invalid batch size or
/// [`ContextError::InvalidRootKey`] for an empty or non-normalized key.
pub fn validate_root_keys(root_keys: &[String]) -> Result<(), ContextError> {
    if !(1..=MAX_ROOTS).contains(&root_keys.len()) {
        return Err(ContextError::InvalidRootCount);
    }
    if root_keys
        .iter()
        .any(|root_key| root_key.is_empty() || root_key.trim() != root_key)
    {
        return Err(ContextError::InvalidRootKey);
    }
    Ok(())
}

/// Validates shared traversal depth and result limits.
///
/// # Errors
///
/// Returns [`ContextError::InvalidDepth`] unless depth is in `1..=6`, then
/// [`ContextError::InvalidLimit`] unless limit is in `1..=500`.
pub fn validate_bounds(depth: usize, limit: usize) -> Result<(), ContextError> {
    validate_depth(depth)?;
    validate_limit(limit)
}

#[cfg(test)]
mod tests {
    use cerebro_organizational_graph::OrganizationalGraph;
    use cerebro_organizational_model::{
        AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, GraphAssertion,
        IdentityBindingAssertion, IdentityBindingState, IdentityClaim, IdentityResolutionMethod,
        ObservationId, ObservationRef, ProviderIdentity, ProviderKind, RelationKind,
        RelationshipAssertion, SourceRuntimeId,
    };

    use super::*;

    #[test]
    fn finds_bounded_multi_hop_path() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("inventory").unwrap(),
            CollectionId::parse("collection-1").unwrap(),
            "inventory",
            10,
        )
        .unwrap();
        let evidence = || {
            AssertionProvenance::direct(
                vec![
                    ObservationRef::new(
                        collection.receipt(),
                        ObservationId::parse("observation-1").unwrap(),
                        "record-1",
                    )
                    .unwrap(),
                ],
                "test-mapper",
                "v1",
            )
            .unwrap()
        };
        let team = Entity::canonical(
            tenant.clone(),
            EntityId::parse("team-1").unwrap(),
            EntityKind::Team,
            "Team",
        )
        .unwrap();
        let repository = Entity::canonical(
            tenant.clone(),
            EntityId::parse("repository-1").unwrap(),
            EntityKind::Repository,
            "Repository",
        )
        .unwrap();
        let service = Entity::canonical(
            tenant.clone(),
            EntityId::parse("service-1").unwrap(),
            EntityKind::Service,
            "Service",
        )
        .unwrap();
        let environment = Entity::canonical(
            tenant.clone(),
            EntityId::parse("environment-1").unwrap(),
            EntityKind::Environment,
            "Production",
        )
        .unwrap();
        let assertions = [
            RelationshipAssertion::new(&team, RelationKind::Owns, &repository, evidence(), 10)
                .unwrap(),
            RelationshipAssertion::new(&repository, RelationKind::Builds, &service, evidence(), 10)
                .unwrap(),
            RelationshipAssertion::new(
                &service,
                RelationKind::RunsIn,
                &environment,
                evidence(),
                10,
            )
            .unwrap(),
            RelationshipAssertion::new(&team, RelationKind::Maintains, &service, evidence(), 10)
                .unwrap(),
        ];
        let mut builder = collection.begin_delta();
        for entity in [&team, &repository, &service, &environment] {
            builder.add_entity(entity.clone()).unwrap();
        }
        for assertion in assertions {
            builder
                .add_assertion(GraphAssertion::Relationship(assertion))
                .unwrap();
        }
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();

        let bounded = AgentContext::new(&graph)
            .expand(&tenant, team.id(), 4, 2)
            .unwrap();
        assert_eq!(bounded.edges.len(), 2);
        assert!(bounded.truncated);
        assert!(bounded.entities.len() <= 3);
        let exact = AgentContext::new(&graph)
            .expand(&tenant, team.id(), 4, 4)
            .unwrap();
        assert_eq!(exact.edges.len(), 4);
        assert!(!exact.truncated);

        let paths = AgentContext::new(&graph)
            .find_paths(&tenant, team.id(), service.id(), 4, 10)
            .unwrap();
        assert_eq!(
            paths
                .iter()
                .map(|path| path.edges.len())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let limited = AgentContext::new(&graph)
            .find_paths(&tenant, team.id(), service.id(), 4, 1)
            .unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].edges.len(), 1);
    }

    #[test]
    fn traversal_depth_is_hard_bounded() {
        let graph = OrganizationalGraph::new();
        assert_eq!(
            AgentContext::new(&graph).expand(
                &TenantId::parse("tenant-a").unwrap(),
                &EntityId::parse("entity-1").unwrap(),
                7,
                10,
            ),
            Err(ContextError::InvalidDepth)
        );
    }

    #[test]
    fn batched_graph_reads_have_a_closed_root_boundary() {
        assert_eq!(validate_root_keys(&[]), Err(ContextError::InvalidRootCount));
        assert_eq!(
            validate_root_keys(&vec!["root".to_owned(); 101]),
            Err(ContextError::InvalidRootCount)
        );
        assert_eq!(
            validate_root_keys(&[" root".to_owned()]),
            Err(ContextError::InvalidRootKey)
        );
        assert!(validate_root_keys(&["root".to_owned()]).is_ok());
    }

    #[tokio::test]
    async fn memory_graph_filters_before_the_bound_and_resolves_derived_agent_keys() {
        let tenant = TenantId::parse("tenant-memory").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("memory-test").unwrap(),
            CollectionId::parse("memory-search-collection").unwrap(),
            "memory.search",
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        for index in 0..501 {
            builder
                .add_entity(
                    Entity::canonical(
                        tenant.clone(),
                        EntityId::parse(format!("service-{index:04}")).unwrap(),
                        EntityKind::Service,
                        format!("Service {index}"),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let person = Entity::canonical(
            tenant.clone(),
            EntityId::parse("zz-person").unwrap(),
            EntityKind::Person,
            "Person Beyond Internal Bound",
        )
        .unwrap();
        let agent_key = person.agent_key();
        builder.add_entity(person.clone()).unwrap();
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();
        let graph = MemoryAgentGraph::new(graph);

        let found = graph
            .search(&tenant, "", &["person".to_owned()], 10)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entity_id, person.id().clone());

        let resolved = graph.resolve(&tenant, &agent_key).await.unwrap();
        assert_eq!(resolved.entity_id, person.id().clone());
        assert_eq!(resolved.agent_key, agent_key);
        assert_eq!(
            resolved.properties.get("entity_urn"),
            Some(&resolved.agent_key)
        );
    }

    #[test]
    fn provider_extensions_keep_their_catalog_kind() {
        let tenant = TenantId::parse("tenant-provider-kind").unwrap();
        let vendor_kind = ProviderKind::parse("demo.vendor").unwrap();
        let vendor = Entity::provider(
            tenant,
            SourceRuntimeId::parse("vendor-runtime").unwrap(),
            vendor_kind.clone(),
            "vendor-1",
            EntityKind::Provider(vendor_kind),
            "Vendor One",
        )
        .unwrap()
        .with_property("entity_type", "vendor")
        .unwrap();

        let projected = ContextEntity::from_domain(&vendor);

        assert_eq!(projected.entity_kind, "vendor");
        assert_eq!(projected.authority["provider_kind"], "demo.vendor");
    }

    #[tokio::test]
    async fn memory_graph_search_matches_durable_order_and_stable_keys_only() {
        let tenant = TenantId::parse("tenant-memory-order").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("memory-order-test").unwrap(),
            CollectionId::parse("memory-order-collection").unwrap(),
            "memory.order",
            10,
        )
        .unwrap();
        let alpha = Entity::canonical(
            tenant.clone(),
            EntityId::parse("entity-z").unwrap(),
            EntityKind::Team,
            "Alpha",
        )
        .unwrap()
        .with_property("shared_value", "not-a-stable-key")
        .unwrap();
        let zulu = Entity::canonical(
            tenant.clone(),
            EntityId::parse("entity-a").unwrap(),
            EntityKind::Team,
            "Zulu",
        )
        .unwrap()
        .with_property("shared_value", "not-a-stable-key")
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(alpha.clone()).unwrap();
        builder.add_entity(zulu).unwrap();
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();
        let graph = MemoryAgentGraph::new(graph);

        let found = graph.search(&tenant, "", &[], 1).await.unwrap();
        assert_eq!(found[0].entity_id, alpha.id().clone());
        assert_eq!(
            graph.resolve(&tenant, "not-a-stable-key").await,
            Err(ContextError::EntityNotFound)
        );
    }

    #[test]
    fn follows_slack_person_directory_group_github_team_repository_path() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let okta_collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            CollectionId::parse("okta-collection").unwrap(),
            "okta.identity_spine",
            10,
        )
        .unwrap();
        let okta_evidence = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    okta_collection.receipt(),
                    ObservationId::parse("okta-observation").unwrap(),
                    "okta.user:00u1",
                )
                .unwrap(),
            ],
            "identity-spine",
            "v1",
        )
        .unwrap();
        let employee_claim = IdentityClaim::employee_id("employee-1").unwrap();
        let email_claim = IdentityClaim::verified_email("person@example.com").unwrap();
        let person =
            CanonicalIdentity::for_claim(tenant.clone(), &employee_claim, "Person One").unwrap();
        let okta_identity = ProviderIdentity::new(
            tenant.clone(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            ProviderKind::parse("okta.identity_user").unwrap(),
            "00u1",
            "Person One",
        )
        .unwrap();
        let okta_group = Entity::provider(
            tenant.clone(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            ProviderKind::parse("okta.identity_group").unwrap(),
            "group-1",
            EntityKind::Group,
            "Engineering",
        )
        .unwrap();
        let employee_binding = IdentityBindingAssertion::new(
            &okta_identity,
            &person,
            IdentityResolutionMethod::AuthoritativeEmployeeId,
            Some(employee_claim),
            IdentityBindingState::Confirmed,
            okta_evidence.clone(),
            10,
        )
        .unwrap();
        let email_binding = IdentityBindingAssertion::new(
            &okta_identity,
            &person,
            IdentityResolutionMethod::VerifiedEmail,
            Some(email_claim.clone()),
            IdentityBindingState::Confirmed,
            okta_evidence.clone(),
            10,
        )
        .unwrap();
        let membership = RelationshipAssertion::new(
            person.entity(),
            RelationKind::MemberOf,
            &okta_group,
            okta_evidence.clone(),
            10,
        )
        .unwrap();
        let github_team = Entity::provider(
            tenant.clone(),
            SourceRuntimeId::parse("github-prod").unwrap(),
            ProviderKind::parse("github.team").unwrap(),
            "team-1",
            EntityKind::Team,
            "Platform",
        )
        .unwrap();
        let repository = Entity::provider(
            tenant.clone(),
            SourceRuntimeId::parse("github-prod").unwrap(),
            ProviderKind::parse("github.repository").unwrap(),
            "repository-1",
            EntityKind::Repository,
            "control-plane",
        )
        .unwrap();
        let provisioned = RelationshipAssertion::new(
            &okta_group,
            RelationKind::ProvisionedAs,
            &github_team,
            okta_evidence.clone(),
            10,
        )
        .unwrap();
        let grant = RelationshipAssertion::new(
            &github_team,
            RelationKind::Grants,
            &repository,
            okta_evidence,
            10,
        )
        .unwrap();
        let mut okta_builder = okta_collection.begin_delta();
        for entity in [
            okta_identity.clone().into_entity(),
            person.clone().into_entity(),
            okta_group,
            github_team,
            repository.clone(),
        ] {
            okta_builder.add_entity(entity).unwrap();
        }
        for assertion in [
            GraphAssertion::IdentityBinding(employee_binding),
            GraphAssertion::IdentityBinding(email_binding),
            GraphAssertion::Relationship(membership),
            GraphAssertion::Relationship(provisioned),
            GraphAssertion::Relationship(grant),
        ] {
            okta_builder.add_assertion(assertion).unwrap();
        }
        let mut graph = OrganizationalGraph::new();
        graph.apply(okta_builder.build()).unwrap();

        let slack_collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("slack-prod").unwrap(),
            CollectionId::parse("slack-collection").unwrap(),
            "slack.users",
            20,
        )
        .unwrap();
        let slack_identity = ProviderIdentity::new(
            tenant.clone(),
            SourceRuntimeId::parse("slack-prod").unwrap(),
            ProviderKind::parse("slack.identity_user").unwrap(),
            "U1",
            "person",
        )
        .unwrap();
        let slack_evidence = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    slack_collection.receipt(),
                    ObservationId::parse("slack-observation").unwrap(),
                    "slack.user:U1",
                )
                .unwrap(),
            ],
            "identity-spine",
            "v1",
        )
        .unwrap();
        let slack_binding = IdentityBindingAssertion::new(
            &slack_identity,
            &person,
            IdentityResolutionMethod::ExistingClaimMatch,
            Some(email_claim),
            IdentityBindingState::Confirmed,
            slack_evidence,
            20,
        )
        .unwrap();
        let slack_id = slack_identity.entity().id().clone();
        let mut slack_builder = slack_collection.begin_delta();
        slack_builder
            .add_entity(slack_identity.into_entity())
            .unwrap();
        slack_builder.add_entity(person.into_entity()).unwrap();
        slack_builder
            .add_assertion(GraphAssertion::IdentityBinding(slack_binding))
            .unwrap();
        graph.apply(slack_builder.build()).unwrap();

        let paths = AgentContext::new(&graph)
            .find_paths(&tenant, &slack_id, repository.id(), 4, 10)
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0]
                .edges
                .iter()
                .map(|edge| edge.relation.as_str())
                .collect::<Vec<_>>(),
            ["represents", "member_of", "provisioned_as", "grants"]
        );
    }

    #[tokio::test]
    async fn typed_query_joins_compliance_facts_and_enforces_evidence_absence() {
        let tenant = TenantId::parse("tenant-compliance").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("compliance-runtime").unwrap(),
            CollectionId::parse("compliance-collection").unwrap(),
            "compliance.current",
            10,
        )
        .unwrap();
        let evidence = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse("compliance-observation").unwrap(),
                    "compliance.snapshot:1",
                )
                .unwrap(),
            ],
            "compliance-projector",
            "v1",
        )
        .unwrap();
        let control = Entity::canonical(
            tenant.clone(),
            EntityId::parse("control-cc6-1").unwrap(),
            EntityKind::Control,
            "SOC 2 CC6.1",
        )
        .unwrap();
        let resource = Entity::canonical(
            tenant.clone(),
            EntityId::parse("resource-production").unwrap(),
            EntityKind::Resource,
            "Production",
        )
        .unwrap();
        let unsupported = Entity::canonical(
            tenant.clone(),
            EntityId::parse("finding-unsupported").unwrap(),
            EntityKind::Finding,
            "Missing access evidence",
        )
        .unwrap();
        let supported = Entity::canonical(
            tenant.clone(),
            EntityId::parse("finding-supported").unwrap(),
            EntityKind::Finding,
            "Reviewed access evidence",
        )
        .unwrap();
        let evidence_record = Entity::canonical(
            tenant.clone(),
            EntityId::parse("evidence-1").unwrap(),
            EntityKind::Evidence,
            "Access review receipt",
        )
        .unwrap();
        let relationships = [
            RelationshipAssertion::new(
                &unsupported,
                RelationKind::MappedToControl,
                &control,
                evidence.clone(),
                10,
            )
            .unwrap(),
            RelationshipAssertion::new(
                &unsupported,
                RelationKind::Affects,
                &resource,
                evidence.clone(),
                10,
            )
            .unwrap(),
            RelationshipAssertion::new(
                &supported,
                RelationKind::MappedToControl,
                &control,
                evidence.clone(),
                10,
            )
            .unwrap(),
            RelationshipAssertion::new(
                &supported,
                RelationKind::Affects,
                &resource,
                evidence.clone(),
                10,
            )
            .unwrap(),
            RelationshipAssertion::new(
                &evidence_record,
                RelationKind::EvidenceFor,
                &supported,
                evidence,
                10,
            )
            .unwrap(),
        ];
        let mut builder = collection.begin_delta();
        for entity in [
            control,
            resource,
            unsupported.clone(),
            supported,
            evidence_record,
        ] {
            builder.add_entity(entity).unwrap();
        }
        for relationship in relationships {
            builder
                .add_assertion(GraphAssertion::Relationship(relationship))
                .unwrap();
        }
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();
        let graph = MemoryAgentGraph::new(graph);
        let query = FactQuery::new(
            vec![
                QueryNode {
                    variable: "finding".to_owned(),
                    kinds: vec!["finding".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "control".to_owned(),
                    kinds: vec!["control".to_owned()],
                    keys: vec!["control-cc6-1".to_owned()],
                },
                QueryNode {
                    variable: "resource".to_owned(),
                    kinds: vec!["resource".to_owned()],
                    keys: Vec::new(),
                },
            ],
            vec![
                QueryEdge {
                    variable: "control_mapping".to_owned(),
                    from_variable: "finding".to_owned(),
                    relation: "mapped_to_control".to_owned(),
                    to_variable: "control".to_owned(),
                },
                QueryEdge {
                    variable: "affected_resource".to_owned(),
                    from_variable: "finding".to_owned(),
                    relation: "affects".to_owned(),
                    to_variable: "resource".to_owned(),
                },
            ],
            vec![QueryAbsentEdge {
                bound_variable: "finding".to_owned(),
                direction: QueryDirection::Incoming,
                relation: "evidence_for".to_owned(),
                other_kinds: vec!["evidence".to_owned()],
            }],
            10,
        )
        .unwrap();

        let result = graph.query(&tenant, &query).await.unwrap();

        assert_eq!(result.graph_revision, 1);
        assert!(!result.truncated);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(
            result.matches[0].entities["finding"].entity_id,
            unsupported.id().clone()
        );
        assert_eq!(
            result.matches[0].edges.keys().cloned().collect::<Vec<_>>(),
            ["affected_resource", "control_mapping"]
        );
    }

    #[test]
    fn typed_query_rejects_unknown_schema_and_disconnected_patterns() {
        let unknown = FactQuery::new(
            vec![
                QueryNode {
                    variable: "finding".to_owned(),
                    kinds: vec!["finding".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "control".to_owned(),
                    kinds: vec!["control".to_owned()],
                    keys: Vec::new(),
                },
            ],
            vec![QueryEdge {
                variable: "edge".to_owned(),
                from_variable: "finding".to_owned(),
                relation: "arbitrary_cypher_relation".to_owned(),
                to_variable: "control".to_owned(),
            }],
            Vec::new(),
            10,
        );
        assert!(matches!(unknown, Err(ContextError::InvalidQuery(_))));

        let invalid_endpoints = FactQuery::new(
            vec![
                QueryNode {
                    variable: "person".to_owned(),
                    kinds: vec!["person".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "finding".to_owned(),
                    kinds: vec!["finding".to_owned()],
                    keys: Vec::new(),
                },
            ],
            vec![QueryEdge {
                variable: "verification".to_owned(),
                from_variable: "person".to_owned(),
                relation: "verifies".to_owned(),
                to_variable: "finding".to_owned(),
            }],
            Vec::new(),
            10,
        );
        assert!(matches!(
            invalid_endpoints,
            Err(ContextError::InvalidQuery(_))
        ));

        let invalid_absence_endpoints = FactQuery::new(
            vec![QueryNode {
                variable: "person".to_owned(),
                kinds: vec!["person".to_owned()],
                keys: Vec::new(),
            }],
            Vec::new(),
            vec![QueryAbsentEdge {
                bound_variable: "person".to_owned(),
                direction: QueryDirection::Incoming,
                relation: "verifies".to_owned(),
                other_kinds: vec!["person".to_owned()],
            }],
            10,
        );
        assert!(matches!(
            invalid_absence_endpoints,
            Err(ContextError::InvalidQuery(_))
        ));

        let too_many_keys = FactQuery::new(
            vec![QueryNode {
                variable: "finding".to_owned(),
                kinds: vec!["finding".to_owned()],
                keys: (0..=MAX_QUERY_KEYS_PER_NODE)
                    .map(|index| format!("finding-{index}"))
                    .collect(),
            }],
            Vec::new(),
            Vec::new(),
            10,
        );
        assert!(matches!(too_many_keys, Err(ContextError::InvalidQuery(_))));

        let disconnected = FactQuery::new(
            vec![
                QueryNode {
                    variable: "finding".to_owned(),
                    kinds: vec!["finding".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "control".to_owned(),
                    kinds: vec!["control".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "resource".to_owned(),
                    kinds: vec!["resource".to_owned()],
                    keys: Vec::new(),
                },
            ],
            vec![QueryEdge {
                variable: "edge".to_owned(),
                from_variable: "finding".to_owned(),
                relation: "mapped_to_control".to_owned(),
                to_variable: "control".to_owned(),
            }],
            Vec::new(),
            10,
        );
        assert!(matches!(disconnected, Err(ContextError::InvalidQuery(_))));
    }
}
