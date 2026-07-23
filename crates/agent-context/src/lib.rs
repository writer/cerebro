#![forbid(unsafe_code)]

//! Bounded graph operations presented to agents and product surfaces.

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use cerebro_organizational_graph::GraphRead;
use cerebro_organizational_model::{
    AssertionId, Entity, EntityId, EntityKind, GraphAssertion, TenantId,
};
use serde::Serialize;
use tokio::sync::RwLock;

const MAX_DEPTH: usize = 6;
const MAX_RESULTS: usize = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextError {
    InvalidLimit,
    InvalidDepth,
    EntityNotFound,
    BackendUnavailable(String),
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("result limit must be between 1 and 500"),
            Self::InvalidDepth => formatter.write_str("graph depth must be between 1 and 6"),
            Self::EntityNotFound => formatter.write_str("entity was not found"),
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
    pub entity_kind: String,
    pub authority: serde_json::Value,
    pub label: String,
    pub properties: std::collections::BTreeMap<String, String>,
}

impl ContextEntity {
    pub fn from_domain(entity: &Entity) -> Self {
        Self {
            entity_id: entity.id().clone(),
            entity_kind: serde_json::to_value(entity.kind())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "provider".to_owned()),
            authority: serde_json::to_value(entity.authority()).unwrap_or(serde_json::Value::Null),
            label: entity.label().to_owned(),
            properties: entity.properties().clone(),
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
        let mut truncated = false;

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
                    if seen.len() >= limit {
                        truncated = true;
                        break;
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() || truncated {
                break;
            }
        }

        selected_edges.sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        selected_edges.dedup_by(|left, right| left.assertion_id == right.assertion_id);
        let entities = all_entities
            .into_iter()
            .filter(|entity| seen.contains(entity.id()) && entity.id() != root_id)
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
        let edges: Vec<_> = self
            .reader
            .assertions(tenant_id)
            .iter()
            .map(context_edge)
            .collect();
        let mut paths = Vec::new();
        let mut visited = BTreeSet::from([from.clone()]);
        let mut edge_path = Vec::new();
        self.walk_paths(
            tenant_id,
            from,
            to,
            max_depth,
            limit,
            &edges,
            &mut visited,
            &mut edge_path,
            &mut paths,
        );
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
            } else {
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
}

#[async_trait]
pub trait AgentGraph: Send + Sync {
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

    async fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError>;

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
    async fn search(
        &self,
        tenant_id: &TenantId,
        query: &str,
        kinds: &[String],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError> {
        validate_limit(limit)?;
        let graph = self.graph.read().await;
        let mut entities = AgentContext::new(&*graph).search(tenant_id, query, &[], MAX_RESULTS)?;
        if !kinds.is_empty() {
            entities.retain(|entity| kinds.contains(&entity.entity_kind));
        }
        entities.truncate(limit);
        Ok(entities)
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError> {
        let graph = self.graph.read().await;
        AgentContext::new(&*graph).get(tenant_id, entity_id)
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

pub fn validate_bounds(depth: usize, limit: usize) -> Result<(), ContextError> {
    validate_depth(depth)?;
    validate_limit(limit)
}

#[cfg(test)]
mod tests {
    use cerebro_organizational_graph::OrganizationalGraph;
    use cerebro_organizational_model::{
        AssertionProvenance, CollectionId, CompleteCollection, GraphAssertion, ObservationId,
        ObservationRef, RelationKind, RelationshipAssertion, SourceRuntimeId,
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

        let paths = AgentContext::new(&graph)
            .find_paths(&tenant, team.id(), environment.id(), 4, 10)
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].edges.len(), 3);
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
}
