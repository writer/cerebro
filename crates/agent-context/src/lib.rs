#![forbid(unsafe_code)]

//! Bounded graph operations presented to agents and product surfaces.

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
pub enum ContextError {
    InvalidLimit,
    InvalidDepth,
    InvalidRootKey,
    InvalidRootCount,
    EntityNotFound,
    InvalidQuery(String),
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
pub struct ContextEdge {
    pub assertion_id: AssertionId,
    pub from: EntityId,
    pub relation: String,
    pub to: EntityId,
    pub source_runtime_id: String,
    pub identity_binding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextEntity {
    pub entity_id: EntityId,
    pub agent_key: String,
    pub entity_kind: String,
    pub authority: serde_json::Value,
    pub label: String,
    pub properties: std::collections::BTreeMap<String, String>,
}

impl ContextEntity {
    pub fn from_domain(entity: &Entity) -> Self {
        let agent_key = entity.agent_key();
        let mut properties = entity.properties().clone();
        properties.insert("entity_urn".to_owned(), agent_key.clone());
        Self {
            entity_id: entity.id().clone(),
            agent_key,
            entity_kind: serde_json::to_value(entity.kind())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "provider".to_owned()),
            authority: serde_json::to_value(entity.authority()).unwrap_or(serde_json::Value::Null),
            label: entity.label().to_owned(),
            properties,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Neighborhood {
    pub tenant_id: TenantId,
    pub graph_revision: u64,
    pub root: ContextEntity,
    pub entities: Vec<ContextEntity>,
    pub edges: Vec<ContextEdge>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphPath {
    pub entities: Vec<ContextEntity>,
    pub edges: Vec<ContextEdge>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryDirection {
    Outgoing,
    Incoming,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryNode {
    pub variable: String,
    pub kinds: Vec<String>,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryEdge {
    pub variable: String,
    pub from_variable: String,
    pub relation: String,
    pub to_variable: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryAbsentEdge {
    pub bound_variable: String,
    pub direction: QueryDirection,
    pub relation: String,
    pub other_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FactQuery {
    nodes: Vec<QueryNode>,
    edges: Vec<QueryEdge>,
    absent_edges: Vec<QueryAbsentEdge>,
    limit: usize,
}

impl FactQuery {
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

    pub fn nodes(&self) -> &[QueryNode] {
        &self.nodes
    }

    pub fn edges(&self) -> &[QueryEdge] {
        &self.edges
    }

    pub fn absent_edges(&self) -> &[QueryAbsentEdge] {
        &self.absent_edges
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryMatch {
    pub entities: BTreeMap<String, ContextEntity>,
    pub edges: BTreeMap<String, ContextEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResult {
    pub tenant_id: TenantId,
    pub graph_revision: u64,
    pub matches: Vec<QueryMatch>,
    pub truncated: bool,
}

pub struct AgentContext<'a, Reader: GraphRead> {
    reader: &'a Reader,
}

impl<'a, Reader: GraphRead> AgentContext<'a, Reader> {
    pub fn new(reader: &'a Reader) -> Self {
        Self { reader }
    }

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

    pub fn explain(&self, tenant_id: &TenantId, assertion_id: &AssertionId) -> Option<ContextEdge> {
        self.reader
            .assertions(tenant_id)
            .iter()
            .find(|item| item.id() == assertion_id)
            .map(context_edge)
    }

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
pub trait AgentGraph: Send + Sync {
    async fn health(&self) -> Result<(), ContextError>;

    /// Returns the durable tenant graph revision observed by the backend.
    async fn revision(&self, tenant_id: &TenantId) -> Result<u64, ContextError>;

    async fn search(
        &self,
        tenant_id: &TenantId,
        query: &str,
        kinds: &[String],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError>;

    async fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError>;

    /// Resolves either a native entity ID or a stable provider-facing key.
    async fn resolve(&self, tenant_id: &TenantId, key: &str)
    -> Result<ContextEntity, ContextError>;

    /// Returns at most `limit` assertion edges and only the entity endpoints
    /// needed to interpret those edges. `truncated` is true only when another
    /// reachable edge exists beyond that bound.
    async fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError>;

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

    async fn find_paths(
        &self,
        tenant_id: &TenantId,
        from: &EntityId,
        to: &EntityId,
        max_depth: usize,
        limit: usize,
    ) -> Result<Vec<GraphPath>, ContextError>;

    async fn explain(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionId,
    ) -> Result<ContextEdge, ContextError>;

    async fn query(
        &self,
        tenant_id: &TenantId,
        query: &FactQuery,
    ) -> Result<QueryResult, ContextError>;
}

#[derive(Clone)]
pub struct MemoryAgentGraph {
    graph: Arc<RwLock<cerebro_organizational_graph::OrganizationalGraph>>,
}

impl MemoryAgentGraph {
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
            identity_binding: false,
        },
        GraphAssertion::IdentityBinding(value) => ContextEdge {
            assertion_id: value.id().clone(),
            from: value.provider_identity().clone(),
            relation: "represents".to_owned(),
            to: value.canonical_identity().clone(),
            source_runtime_id: value.provenance().source_runtime_id().to_string(),
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
