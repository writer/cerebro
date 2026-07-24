use std::time::Duration;

use async_trait::async_trait;
use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, FactQuery, GraphPath, Neighborhood,
    QueryDirection, QueryMatch, QueryResult, validate_bounds, validate_root_keys,
};
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{AssertionId, EntityId, GraphDelta, TenantId};
use neo4rs::{BoltList, BoltMap, BoltType, Graph, query};

use crate::{
    StoreError,
    postgres::{
        ProjectionAssertion, ProjectionCommit, ProjectionEntity, ProjectionRetraction,
        projection_commit,
    },
};

const ENTITY_QUERY: &str = r#"
UNWIND $rows AS row
MERGE (entity:OrganizationalEntity {
  tenant_id: $tenant_id,
  entity_id: row.entity_id
})
SET entity.entity_kind = row.entity_kind,
    entity.authority_json = row.authority_json,
    entity.label = row.label,
    entity.properties_json = row.properties_json,
    entity.external_id = row.external_id,
    entity.graph_revision = $graph_revision
"#;

const ASSERTION_QUERY: &str = r#"
UNWIND $rows AS row
MATCH (source:OrganizationalEntity {
  tenant_id: $tenant_id,
  entity_id: row.from_entity_id
})
MATCH (target:OrganizationalEntity {
  tenant_id: $tenant_id,
  entity_id: row.to_entity_id
})
MERGE (source)-[assertion:ORGANIZATIONAL_RELATION {
  tenant_id: $tenant_id,
  assertion_id: row.assertion_id
}]->(target)
SET assertion.relation = row.relation,
    assertion.source_runtime_id = row.source_runtime_id,
    assertion.state = row.state,
    assertion.provenance_json = row.provenance_json,
    assertion.observed_at_unix_ms = row.observed_at_unix_ms,
    assertion.graph_revision = $graph_revision
"#;

const RETRACTION_QUERY: &str = r#"
UNWIND $rows AS row
MATCH ()-[assertion:ORGANIZATIONAL_RELATION {
  tenant_id: $tenant_id,
  assertion_id: row.assertion_id
}]->()
DELETE assertion
"#;

const REVISION_QUERY: &str = r#"
MERGE (revision:OrganizationalGraphRevision {tenant_id: $tenant_id})
SET revision.graph_revision = $graph_revision,
    revision.delta_digest = $delta_digest
"#;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

const ONE_HOP_BATCH_QUERY: &str = r#"
UNWIND $root_keys AS root_key
CALL {
  WITH root_key
  OPTIONAL MATCH (candidate:OrganizationalEntity {tenant_id: $tenant_id})
  WHERE candidate.entity_id = root_key OR candidate.external_id = root_key
  WITH root_key, [candidate IN collect(candidate) WHERE candidate IS NOT NULL] AS candidates
  WITH root_key,
       size(candidates) AS match_count,
       CASE WHEN size(candidates) = 1 THEN candidates[0] ELSE null END AS root
  OPTIONAL MATCH (root)-[edge:ORGANIZATIONAL_RELATION]-(neighbor:OrganizationalEntity)
  WITH root_key, match_count, root, edge
  ORDER BY edge.assertion_id
  LIMIT $row_limit
  RETURN match_count, root, edge, startNode(edge) AS source, endNode(edge) AS target
}
OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id})
RETURN root_key,
       match_count,
       coalesce(root.entity_id, '') AS root_id,
       coalesce(root.entity_kind, '') AS root_kind,
       coalesce(root.authority_json, 'null') AS root_authority,
       coalesce(root.label, '') AS root_label,
       coalesce(root.properties_json, '{}') AS root_properties,
       coalesce(source.entity_id, '') AS from_id,
       coalesce(source.entity_kind, '') AS from_kind,
       coalesce(source.authority_json, 'null') AS from_authority,
       coalesce(source.label, '') AS from_label,
       coalesce(source.properties_json, '{}') AS from_properties,
       coalesce(target.entity_id, '') AS to_id,
       coalesce(target.entity_kind, '') AS to_kind,
       coalesce(target.authority_json, 'null') AS to_authority,
       coalesce(target.label, '') AS to_label,
       coalesce(target.properties_json, '{}') AS to_properties,
       coalesce(edge.assertion_id, '') AS assertion_id,
       coalesce(edge.relation, '') AS relation,
       coalesce(edge.source_runtime_id, '') AS source_runtime_id,
       coalesce(revision.graph_revision, 0) AS graph_revision
ORDER BY root_key, assertion_id
"#;

fn expand_statement(depth: usize) -> String {
    format!(
        "MATCH path=(root:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $root_id}})-[:ORGANIZATIONAL_RELATION*1..{depth}]-(node:OrganizationalEntity) WITH relationships(path) AS relations UNWIND relations AS edge WITH DISTINCT edge MATCH (source)-[edge]->(target) WHERE source.tenant_id = $tenant_id AND target.tenant_id = $tenant_id RETURN source.entity_id AS from_id, source.entity_kind AS from_kind, source.authority_json AS from_authority, source.label AS from_label, source.properties_json AS from_properties, target.entity_id AS to_id, target.entity_kind AS to_kind, target.authority_json AS to_authority, target.label AS to_label, target.properties_json AS to_properties, edge.assertion_id AS assertion_id, edge.relation AS relation, edge.source_runtime_id AS source_runtime_id ORDER BY assertion_id LIMIT $row_limit"
    )
}

fn paths_statement(max_depth: usize) -> String {
    format!(
        "MATCH path=(source:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $from_id}})-[:ORGANIZATIONAL_RELATION*1..{max_depth}]->(target:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $to_id}}) WHERE all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(node IN nodes(path) WHERE single(other IN nodes(path) WHERE other = node)) RETURN [node IN nodes(path) | node.entity_id] AS entity_ids, [node IN nodes(path) | node.entity_kind] AS entity_kinds, [node IN nodes(path) | node.authority_json] AS authorities, [node IN nodes(path) | node.label] AS labels, [node IN nodes(path) | node.properties_json] AS properties, [edge IN relationships(path) | edge.assertion_id] AS assertion_ids, [edge IN relationships(path) | edge.relation] AS relations, [edge IN relationships(path) | edge.source_runtime_id] AS runtime_ids ORDER BY length(path), assertion_ids LIMIT $limit"
    )
}

fn fact_query_statement(fact_query: &FactQuery) -> String {
    let node_indexes = fact_query
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| (node.variable.as_str(), index))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut parts = vec![
        "MATCH (query_revision:OrganizationalGraphRevision {tenant_id: $tenant_id})".to_owned(),
    ];
    for index in 0..fact_query.nodes().len() {
        parts.push(format!(
            "MATCH (node_{index}:OrganizationalEntity {{tenant_id: $tenant_id}})"
        ));
    }
    for (index, edge) in fact_query.edges().iter().enumerate() {
        let from = node_indexes[edge.from_variable.as_str()];
        let to = node_indexes[edge.to_variable.as_str()];
        parts.push(format!(
            "MATCH (node_{from})-[edge_{index}:ORGANIZATIONAL_RELATION]->(node_{to})"
        ));
    }
    let mut predicates = Vec::new();
    for index in 0..fact_query.nodes().len() {
        predicates.push(format!(
            "(size($node_{index}_kinds) = 0 OR node_{index}.entity_kind IN $node_{index}_kinds)"
        ));
        predicates.push(format!(
            "(size($node_{index}_keys) = 0 OR node_{index}.entity_id IN $node_{index}_keys OR node_{index}.external_id IN $node_{index}_keys)"
        ));
    }
    for index in 0..fact_query.edges().len() {
        predicates.push(format!(
            "edge_{index}.tenant_id = $tenant_id AND edge_{index}.relation = $edge_{index}_relation"
        ));
    }
    for (index, absence) in fact_query.absent_edges().iter().enumerate() {
        let bound = node_indexes[absence.bound_variable.as_str()];
        let pattern = match absence.direction {
            QueryDirection::Outgoing => format!(
                "(node_{bound})-[absence_edge_{index}:ORGANIZATIONAL_RELATION]->(absence_other_{index}:OrganizationalEntity)"
            ),
            QueryDirection::Incoming => format!(
                "(absence_other_{index}:OrganizationalEntity)-[absence_edge_{index}:ORGANIZATIONAL_RELATION]->(node_{bound})"
            ),
        };
        predicates.push(format!(
            "NOT EXISTS {{ MATCH {pattern} WHERE absence_edge_{index}.tenant_id = $tenant_id AND absence_edge_{index}.relation = $absence_{index}_relation AND absence_other_{index}.tenant_id = $tenant_id AND (size($absence_{index}_kinds) = 0 OR absence_other_{index}.entity_kind IN $absence_{index}_kinds) }}"
        ));
    }
    parts.push(format!("WHERE {}", predicates.join(" AND ")));
    let mut returns = vec!["query_revision.graph_revision AS graph_revision".to_owned()];
    let mut order = Vec::new();
    for index in 0..fact_query.nodes().len() {
        returns.extend([
            format!("node_{index}.entity_id AS node_{index}_id"),
            format!("node_{index}.entity_kind AS node_{index}_kind"),
            format!("node_{index}.authority_json AS node_{index}_authority"),
            format!("node_{index}.label AS node_{index}_label"),
            format!("node_{index}.properties_json AS node_{index}_properties"),
        ]);
        order.push(format!("node_{index}.entity_id"));
    }
    for (index, edge) in fact_query.edges().iter().enumerate() {
        let from = node_indexes[edge.from_variable.as_str()];
        let to = node_indexes[edge.to_variable.as_str()];
        returns.extend([
            format!("edge_{index}.assertion_id AS edge_{index}_assertion_id"),
            format!("node_{from}.entity_id AS edge_{index}_from_id"),
            format!("edge_{index}.relation AS edge_{index}_relation"),
            format!("node_{to}.entity_id AS edge_{index}_to_id"),
            format!("edge_{index}.source_runtime_id AS edge_{index}_source_runtime_id"),
        ]);
        order.push(format!("edge_{index}.assertion_id"));
    }
    parts.push(format!("RETURN DISTINCT {}", returns.join(", ")));
    parts.push(format!("ORDER BY {}", order.join(", ")));
    parts.push("LIMIT $row_limit".to_owned());
    parts.join(" ")
}

const PATH_ENDPOINTS_STATEMENT: &str = r#"
OPTIONAL MATCH (source:OrganizationalEntity {
    tenant_id: $tenant_id,
    entity_id: $from_id
})
OPTIONAL MATCH (target:OrganizationalEntity {
    tenant_id: $tenant_id,
    entity_id: $to_id
})
RETURN source IS NOT NULL AND target IS NOT NULL AS endpoints_exist
"#;

const NEO4J_SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT organizational_entity_identity IF NOT EXISTS FOR (entity:OrganizationalEntity) REQUIRE (entity.tenant_id, entity.entity_id) IS UNIQUE",
    "CREATE CONSTRAINT organizational_revision_tenant IF NOT EXISTS FOR (revision:OrganizationalGraphRevision) REQUIRE revision.tenant_id IS UNIQUE",
    "CREATE INDEX organizational_entity_external_id IF NOT EXISTS FOR (entity:OrganizationalEntity) ON (entity.tenant_id, entity.external_id)",
    "CREATE INDEX organizational_relation_identity IF NOT EXISTS FOR ()-[assertion:ORGANIZATIONAL_RELATION]-() ON (assertion.tenant_id, assertion.assertion_id)",
    "CREATE INDEX organizational_relation_kind IF NOT EXISTS FOR ()-[assertion:ORGANIZATIONAL_RELATION]-() ON (assertion.tenant_id, assertion.relation)",
];

#[derive(Clone)]
pub struct Neo4jProjector {
    graph: Graph,
}

impl Neo4jProjector {
    pub fn from_graph(graph: Graph) -> Self {
        Self { graph }
    }

    pub async fn connect(uri: &str, username: &str, password: &str) -> Result<Self, StoreError> {
        Ok(Self {
            graph: Graph::new(uri, username, password).await?,
        })
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        for statement in NEO4J_SCHEMA {
            self.graph.run(query(statement)).await?;
        }
        Ok(())
    }

    pub async fn project(
        &self,
        delta: &GraphDelta,
        receipt: &GraphWriteReceipt,
    ) -> Result<(), StoreError> {
        if delta.collection().tenant_id() != &receipt.tenant_id
            || delta.digest() != receipt.delta_digest
        {
            return Err(StoreError::Conflict(
                "projection receipt does not match graph delta".to_owned(),
            ));
        }
        self.project_wire(&projection_commit(delta, receipt.graph_revision)?)
            .await
    }

    pub(crate) async fn project_wire(&self, commit: &ProjectionCommit) -> Result<(), StoreError> {
        let mut transaction = self.graph.start_txn().await?;
        let graph_revision = i64::try_from(commit.graph_revision)
            .map_err(|_| StoreError::Conflict("graph revision overflow".to_owned()))?;
        if !commit.entities.is_empty() {
            transaction
                .run(
                    query(ENTITY_QUERY)
                        .param("tenant_id", commit.tenant_id.clone())
                        .param("graph_revision", graph_revision)
                        .param("rows", rows(commit.entities.iter().map(entity_row))),
                )
                .await?;
        }
        if !commit.assertions.is_empty() {
            transaction
                .run(
                    query(ASSERTION_QUERY)
                        .param("tenant_id", commit.tenant_id.clone())
                        .param("graph_revision", graph_revision)
                        .param("rows", rows(commit.assertions.iter().map(assertion_row))),
                )
                .await?;
        }
        if !commit.retractions.is_empty() {
            transaction
                .run(
                    query(RETRACTION_QUERY)
                        .param("tenant_id", commit.tenant_id.clone())
                        .param("rows", rows(commit.retractions.iter().map(retraction_row))),
                )
                .await?;
        }
        transaction
            .run(
                query(REVISION_QUERY)
                    .param("tenant_id", commit.tenant_id.clone())
                    .param("graph_revision", graph_revision)
                    .param("delta_digest", commit.delta_digest.clone()),
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl AgentGraph for Neo4jProjector {
    async fn health(&self) -> Result<(), ContextError> {
        tokio::time::timeout(HEALTH_TIMEOUT, self.graph.run(query("RETURN 1")))
            .await
            .map_err(|_| {
                ContextError::BackendUnavailable(
                    "Neo4j readiness query exceeded 2 seconds".to_owned(),
                )
            })?
            .map_err(context_backend)
    }

    async fn revision(&self, tenant_id: &TenantId) -> Result<u64, ContextError> {
        Neo4jProjector::revision(self, tenant_id).await
    }

    async fn search(
        &self,
        tenant_id: &TenantId,
        search: &str,
        kinds: &[String],
        limit: usize,
    ) -> Result<Vec<ContextEntity>, ContextError> {
        validate_bounds(1, limit)?;
        let mut stream = self
            .graph
            .execute(
                query("MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id}) WHERE (size($kinds) = 0 OR entity.entity_kind IN $kinds) AND ($search = '' OR toLower(entity.label) CONTAINS toLower($search) OR toLower(entity.entity_id) CONTAINS toLower($search)) RETURN entity.entity_id AS entity_id, entity.entity_kind AS entity_kind, entity.authority_json AS authority_json, entity.label AS label, entity.properties_json AS properties_json ORDER BY entity.label, entity.entity_id LIMIT $limit")
                    .param("tenant_id", tenant_id.as_str())
                    .param("search", search.trim())
                    .param("kinds", string_list(kinds))
                    .param("limit", i64::try_from(limit).unwrap_or(500)),
            )
            .await
            .map_err(context_backend)?;
        let mut entities = Vec::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            entities.push(context_entity(&row)?);
        }
        Ok(entities)
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ContextEntity, ContextError> {
        let mut stream = self
            .graph
            .execute(
                query(
                    "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id, entity_id: $entity_id}) RETURN entity.entity_id AS entity_id, entity.entity_kind AS entity_kind, entity.authority_json AS authority_json, entity.label AS label, entity.properties_json AS properties_json",
                )
                .param("tenant_id", tenant_id.as_str())
                .param("entity_id", entity_id.as_str()),
            )
            .await
            .map_err(context_backend)?;
        let row = stream
            .next()
            .await
            .map_err(context_backend)?
            .ok_or(ContextError::EntityNotFound)?;
        context_entity(&row)
    }

    async fn resolve(
        &self,
        tenant_id: &TenantId,
        key: &str,
    ) -> Result<ContextEntity, ContextError> {
        let mut stream = self
            .graph
            .execute(
                query(
                    "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id}) WHERE entity.entity_id = $key OR entity.external_id = $key RETURN entity.entity_id AS entity_id, entity.entity_kind AS entity_kind, entity.authority_json AS authority_json, entity.label AS label, entity.properties_json AS properties_json ORDER BY entity.entity_id LIMIT 2",
                )
                .param("tenant_id", tenant_id.as_str())
                .param("key", key.trim()),
            )
            .await
            .map_err(context_backend)?;
        let row = stream
            .next()
            .await
            .map_err(context_backend)?
            .ok_or(ContextError::EntityNotFound)?;
        let entity = context_entity(&row)?;
        if stream.next().await.map_err(context_backend)?.is_some() {
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
        validate_bounds(depth, limit)?;
        let root = self.get(tenant_id, root_id).await?;
        let statement = expand_statement(depth);
        let mut stream = self
            .graph
            .execute(
                query(&statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_id", root_id.as_str())
                    .param("row_limit", row_limit(limit)),
            )
            .await
            .map_err(context_backend)?;
        let mut entities = std::collections::BTreeMap::new();
        let mut edges = Vec::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let from = context_entity_prefix(&row, "from")?;
            let to = context_entity_prefix(&row, "to")?;
            entities.insert(from.entity_id.clone(), from);
            entities.insert(to.entity_id.clone(), to);
            edges.push(ContextEdge {
                assertion_id: AssertionId::parse(row_string(&row, "assertion_id")?)
                    .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                from: EntityId::parse(row_string(&row, "from_id")?)
                    .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                relation: row_string(&row, "relation")?,
                to: EntityId::parse(row_string(&row, "to_id")?)
                    .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                source_runtime_id: row_string(&row, "source_runtime_id")?,
                identity_binding: row_string(&row, "relation")? == "represents",
            });
        }
        let truncated = truncate_to_limit(&mut edges, limit);
        retain_edge_entities(&mut entities, &edges);
        entities.remove(root_id);
        Ok(Neighborhood {
            tenant_id: tenant_id.clone(),
            graph_revision: self.revision(tenant_id).await?,
            root,
            entities: entities.into_values().collect(),
            edges,
            truncated,
        })
    }

    async fn expand_many(
        &self,
        tenant_id: &TenantId,
        root_keys: &[String],
        depth: usize,
        limit: usize,
    ) -> Result<std::collections::BTreeMap<String, Neighborhood>, ContextError> {
        validate_root_keys(root_keys)?;
        validate_bounds(depth, limit)?;
        if depth != 1 {
            let mut neighborhoods = std::collections::BTreeMap::new();
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
            return Ok(neighborhoods);
        }

        self.expand_one_hop_many(tenant_id, root_keys, limit).await
    }

    async fn find_paths(
        &self,
        tenant_id: &TenantId,
        from: &EntityId,
        to: &EntityId,
        max_depth: usize,
        limit: usize,
    ) -> Result<Vec<GraphPath>, ContextError> {
        validate_bounds(max_depth, limit)?;
        let statement = paths_statement(max_depth);
        let mut stream = self
            .graph
            .execute(
                query(&statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("from_id", from.as_str())
                    .param("to_id", to.as_str())
                    .param("limit", i64::try_from(limit).unwrap_or(500)),
            )
            .await
            .map_err(context_backend)?;
        let mut paths = Vec::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let entity_ids: Vec<String> = row.get("entity_ids").map_err(context_decode)?;
            let entity_kinds: Vec<String> = row.get("entity_kinds").map_err(context_decode)?;
            let authorities: Vec<String> = row.get("authorities").map_err(context_decode)?;
            let labels: Vec<String> = row.get("labels").map_err(context_decode)?;
            let properties: Vec<String> = row.get("properties").map_err(context_decode)?;
            let assertion_ids: Vec<String> = row.get("assertion_ids").map_err(context_decode)?;
            let relations: Vec<String> = row.get("relations").map_err(context_decode)?;
            let runtime_ids: Vec<String> = row.get("runtime_ids").map_err(context_decode)?;
            if !same_len(&[
                entity_ids.len(),
                entity_kinds.len(),
                authorities.len(),
                labels.len(),
                properties.len(),
            ]) || entity_ids.len() != assertion_ids.len().saturating_add(1)
                || !same_len(&[assertion_ids.len(), relations.len(), runtime_ids.len()])
            {
                return Err(ContextError::BackendUnavailable(
                    "Neo4j path columns have inconsistent lengths".to_owned(),
                ));
            }
            let mut entities = Vec::with_capacity(entity_ids.len());
            for index in 0..entity_ids.len() {
                let entity_properties = parse_json(&properties[index])?;
                entities.push(ContextEntity {
                    entity_id: EntityId::parse(&entity_ids[index])
                        .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                    agent_key: context_agent_key(&entity_properties)?,
                    entity_kind: entity_kinds[index].clone(),
                    authority: parse_json(&authorities[index])?,
                    label: labels[index].clone(),
                    properties: entity_properties,
                });
            }
            let mut edges = Vec::with_capacity(assertion_ids.len());
            for index in 0..assertion_ids.len() {
                edges.push(ContextEdge {
                    assertion_id: AssertionId::parse(&assertion_ids[index])
                        .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                    from: entities[index].entity_id.clone(),
                    relation: relations[index].clone(),
                    to: entities[index + 1].entity_id.clone(),
                    source_runtime_id: runtime_ids[index].clone(),
                    identity_binding: relations[index] == "represents",
                });
            }
            paths.push(GraphPath { entities, edges });
        }
        if paths.is_empty() {
            let mut endpoint_stream = self
                .graph
                .execute(
                    query(PATH_ENDPOINTS_STATEMENT)
                        .param("tenant_id", tenant_id.as_str())
                        .param("from_id", from.as_str())
                        .param("to_id", to.as_str()),
                )
                .await
                .map_err(context_backend)?;
            let endpoints_exist = endpoint_stream
                .next()
                .await
                .map_err(context_backend)?
                .map(|row| row.get::<bool>("endpoints_exist"))
                .transpose()
                .map_err(context_decode)?
                .unwrap_or(false);
            if !endpoints_exist {
                return Err(ContextError::EntityNotFound);
            }
        }
        Ok(paths)
    }

    async fn explain(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionId,
    ) -> Result<ContextEdge, ContextError> {
        let mut stream = self
            .graph
            .execute(
                query("MATCH (source:OrganizationalEntity)-[edge:ORGANIZATIONAL_RELATION {tenant_id: $tenant_id, assertion_id: $assertion_id}]->(target:OrganizationalEntity) RETURN source.entity_id AS from_id, target.entity_id AS to_id, edge.relation AS relation, edge.source_runtime_id AS source_runtime_id")
                    .param("tenant_id", tenant_id.as_str())
                    .param("assertion_id", assertion_id.as_str()),
            )
            .await
            .map_err(context_backend)?;
        let row = stream
            .next()
            .await
            .map_err(context_backend)?
            .ok_or(ContextError::EntityNotFound)?;
        let relation = row_string(&row, "relation")?;
        Ok(ContextEdge {
            assertion_id: assertion_id.clone(),
            from: EntityId::parse(row_string(&row, "from_id")?)
                .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
            relation: relation.clone(),
            to: EntityId::parse(row_string(&row, "to_id")?)
                .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
            source_runtime_id: row_string(&row, "source_runtime_id")?,
            identity_binding: relation == "represents",
        })
    }

    async fn query(
        &self,
        tenant_id: &TenantId,
        fact_query: &FactQuery,
    ) -> Result<QueryResult, ContextError> {
        let statement = fact_query_statement(fact_query);
        let mut query_value = query(&statement).param("tenant_id", tenant_id.as_str());
        for (index, node) in fact_query.nodes().iter().enumerate() {
            query_value = query_value
                .param(&format!("node_{index}_kinds"), string_list(&node.kinds))
                .param(&format!("node_{index}_keys"), string_list(&node.keys));
        }
        for (index, edge) in fact_query.edges().iter().enumerate() {
            query_value =
                query_value.param(&format!("edge_{index}_relation"), edge.relation.as_str());
        }
        for (index, absence) in fact_query.absent_edges().iter().enumerate() {
            query_value = query_value
                .param(
                    &format!("absence_{index}_relation"),
                    absence.relation.as_str(),
                )
                .param(
                    &format!("absence_{index}_kinds"),
                    string_list(&absence.other_kinds),
                );
        }
        query_value = query_value.param("row_limit", row_limit(fact_query.limit()));
        let mut stream = self
            .graph
            .execute(query_value)
            .await
            .map_err(context_backend)?;
        let mut matches = Vec::new();
        let mut query_revision = None;
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let row_revision: i64 = row.get("graph_revision").map_err(context_decode)?;
            let row_revision = u64::try_from(row_revision).map_err(|_| {
                ContextError::BackendUnavailable("Neo4j graph revision is negative".to_owned())
            })?;
            if query_revision
                .replace(row_revision)
                .is_some_and(|revision| revision != row_revision)
            {
                return Err(ContextError::BackendUnavailable(
                    "Neo4j graph revision changed within one fact query".to_owned(),
                ));
            }
            let mut entities = std::collections::BTreeMap::new();
            for (index, node) in fact_query.nodes().iter().enumerate() {
                entities.insert(
                    node.variable.clone(),
                    context_entity_prefix(&row, &format!("node_{index}"))?,
                );
            }
            let mut edges = std::collections::BTreeMap::new();
            for (index, pattern) in fact_query.edges().iter().enumerate() {
                let relation = row_string(&row, &format!("edge_{index}_relation"))?;
                edges.insert(
                    pattern.variable.clone(),
                    ContextEdge {
                        assertion_id: AssertionId::parse(row_string(
                            &row,
                            &format!("edge_{index}_assertion_id"),
                        )?)
                        .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                        from: EntityId::parse(row_string(&row, &format!("edge_{index}_from_id"))?)
                            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                        relation: relation.clone(),
                        to: EntityId::parse(row_string(&row, &format!("edge_{index}_to_id"))?)
                            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                        source_runtime_id: row_string(
                            &row,
                            &format!("edge_{index}_source_runtime_id"),
                        )?,
                        identity_binding: relation == "represents",
                    },
                );
            }
            matches.push(QueryMatch { entities, edges });
        }
        let truncated = truncate_to_limit(&mut matches, fact_query.limit());
        let graph_revision = match query_revision {
            Some(revision) => revision,
            None => self.revision(tenant_id).await?,
        };
        Ok(QueryResult {
            tenant_id: tenant_id.clone(),
            graph_revision,
            matches,
            truncated,
        })
    }
}

impl Neo4jProjector {
    async fn expand_one_hop_many(
        &self,
        tenant_id: &TenantId,
        root_keys: &[String],
        limit: usize,
    ) -> Result<std::collections::BTreeMap<String, Neighborhood>, ContextError> {
        let mut stream = self
            .graph
            .execute(
                query(ONE_HOP_BATCH_QUERY)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_keys", string_list(root_keys))
                    .param("row_limit", row_limit(limit)),
            )
            .await
            .map_err(context_backend)?;
        let mut accumulators = std::collections::BTreeMap::<String, NeighborhoodAccumulator>::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let root_key = row_string(&row, "root_key")?;
            let match_count: i64 = row.get("match_count").map_err(context_decode)?;
            if match_count > 1 {
                return Err(ContextError::BackendUnavailable(format!(
                    "external entity key {root_key:?} is ambiguous"
                )));
            }
            if match_count == 0 {
                continue;
            }
            let graph_revision: i64 = row.get("graph_revision").map_err(context_decode)?;
            let graph_revision = u64::try_from(graph_revision).map_err(|_| {
                ContextError::BackendUnavailable("Neo4j graph revision is negative".to_owned())
            })?;
            let root = context_entity_prefix(&row, "root")?;
            let accumulator =
                accumulators
                    .entry(root_key)
                    .or_insert_with(|| NeighborhoodAccumulator {
                        root,
                        entities: std::collections::BTreeMap::new(),
                        edges: Vec::new(),
                        graph_revision,
                    });
            if accumulator.graph_revision != graph_revision {
                return Err(ContextError::BackendUnavailable(
                    "Neo4j graph revision changed during one read".to_owned(),
                ));
            }
            let assertion_id = row_string(&row, "assertion_id")?;
            if assertion_id.is_empty() {
                continue;
            }
            let from = context_entity_prefix(&row, "from")?;
            let to = context_entity_prefix(&row, "to")?;
            let relation = row_string(&row, "relation")?;
            let edge = ContextEdge {
                assertion_id: AssertionId::parse(assertion_id)
                    .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                from: from.entity_id.clone(),
                relation: relation.clone(),
                to: to.entity_id.clone(),
                source_runtime_id: row_string(&row, "source_runtime_id")?,
                identity_binding: relation == "represents",
            };
            accumulator.entities.insert(from.entity_id.clone(), from);
            accumulator.entities.insert(to.entity_id.clone(), to);
            accumulator.edges.push(edge);
        }
        Ok(accumulators
            .into_iter()
            .map(|(root_key, mut accumulator)| {
                let truncated = truncate_to_limit(&mut accumulator.edges, limit);
                retain_edge_entities(&mut accumulator.entities, &accumulator.edges);
                accumulator.entities.remove(&accumulator.root.entity_id);
                (
                    root_key,
                    Neighborhood {
                        tenant_id: tenant_id.clone(),
                        graph_revision: accumulator.graph_revision,
                        root: accumulator.root,
                        entities: accumulator.entities.into_values().collect(),
                        edges: accumulator.edges,
                        truncated,
                    },
                )
            })
            .collect())
    }

    async fn revision(&self, tenant_id: &TenantId) -> Result<u64, ContextError> {
        let mut stream = self
            .graph
            .execute(
                query("MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) RETURN revision.graph_revision AS graph_revision")
                    .param("tenant_id", tenant_id.as_str()),
            )
            .await
            .map_err(context_backend)?;
        let Some(row) = stream.next().await.map_err(context_backend)? else {
            return Ok(0);
        };
        let value: i64 = row.get("graph_revision").map_err(context_decode)?;
        u64::try_from(value).map_err(|_| {
            ContextError::BackendUnavailable("Neo4j graph revision is negative".to_owned())
        })
    }
}

struct NeighborhoodAccumulator {
    root: ContextEntity,
    entities: std::collections::BTreeMap<EntityId, ContextEntity>,
    edges: Vec<ContextEdge>,
    graph_revision: u64,
}

fn row_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

fn truncate_to_limit<T>(values: &mut Vec<T>, limit: usize) -> bool {
    let truncated = values.len() > limit;
    values.truncate(limit);
    truncated
}

fn retain_edge_entities(
    entities: &mut std::collections::BTreeMap<EntityId, ContextEntity>,
    edges: &[ContextEdge],
) {
    let retained = edges
        .iter()
        .flat_map(|edge| [&edge.from, &edge.to])
        .collect::<std::collections::BTreeSet<_>>();
    entities.retain(|entity_id, _| retained.contains(entity_id));
}

fn context_entity(row: &neo4rs::Row) -> Result<ContextEntity, ContextError> {
    let properties = parse_json(&row_string(row, "properties_json")?)?;
    Ok(ContextEntity {
        entity_id: EntityId::parse(row_string(row, "entity_id")?)
            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
        agent_key: context_agent_key(&properties)?,
        entity_kind: row_string(row, "entity_kind")?,
        authority: parse_json(&row_string(row, "authority_json")?)?,
        label: row_string(row, "label")?,
        properties,
    })
}

fn context_entity_prefix(row: &neo4rs::Row, prefix: &str) -> Result<ContextEntity, ContextError> {
    let properties = parse_json(&row_string(row, &format!("{prefix}_properties"))?)?;
    Ok(ContextEntity {
        entity_id: EntityId::parse(row_string(row, &format!("{prefix}_id"))?)
            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
        agent_key: context_agent_key(&properties)?,
        entity_kind: row_string(row, &format!("{prefix}_kind"))?,
        authority: parse_json(&row_string(row, &format!("{prefix}_authority"))?)?,
        label: row_string(row, &format!("{prefix}_label"))?,
        properties,
    })
}

fn context_agent_key(
    properties: &std::collections::BTreeMap<String, String>,
) -> Result<String, ContextError> {
    properties
        .get("entity_urn")
        .or_else(|| properties.get("resource_urn"))
        .or_else(|| properties.get("urn"))
        .filter(|value| value.starts_with("urn:cerebro:"))
        .cloned()
        .ok_or_else(|| {
            ContextError::BackendUnavailable(
                "projected entity is missing its tenant-scoped agent key".to_owned(),
            )
        })
}

fn row_string(row: &neo4rs::Row, field: &str) -> Result<String, ContextError> {
    row.get(field).map_err(context_decode)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, ContextError> {
    serde_json::from_str(value).map_err(|error| ContextError::BackendUnavailable(error.to_string()))
}

fn context_backend(error: neo4rs::Error) -> ContextError {
    ContextError::BackendUnavailable(error.to_string())
}

fn context_decode(error: neo4rs::DeError) -> ContextError {
    ContextError::BackendUnavailable(error.to_string())
}

fn same_len(values: &[usize]) -> bool {
    values
        .first()
        .is_none_or(|first| values.iter().all(|value| value == first))
}

fn rows(values: impl IntoIterator<Item = BoltMap>) -> BoltType {
    BoltType::List(BoltList::from(
        values.into_iter().map(BoltType::Map).collect::<Vec<_>>(),
    ))
}

fn string_list(values: &[String]) -> BoltType {
    BoltType::List(BoltList::from(
        values
            .iter()
            .cloned()
            .map(BoltType::from)
            .collect::<Vec<_>>(),
    ))
}

fn entity_row(entity: &ProjectionEntity) -> BoltMap {
    map([
        ("entity_id", entity.entity_id.clone().into()),
        ("entity_kind", entity.entity_kind.clone().into()),
        ("authority_json", entity.authority_json.clone().into()),
        ("label", entity.label.clone().into()),
        ("properties_json", entity.properties_json.clone().into()),
        (
            "external_id",
            entity.external_id.clone().unwrap_or_default().into(),
        ),
    ])
}

fn assertion_row(assertion: &ProjectionAssertion) -> BoltMap {
    map([
        ("assertion_id", assertion.assertion_id.clone().into()),
        ("from_entity_id", assertion.from_entity_id.clone().into()),
        ("to_entity_id", assertion.to_entity_id.clone().into()),
        ("relation", assertion.relation.clone().into()),
        (
            "source_runtime_id",
            assertion.source_runtime_id.clone().into(),
        ),
        ("state", assertion.state.clone().into()),
        ("provenance_json", assertion.provenance_json.clone().into()),
        ("observed_at_unix_ms", assertion.observed_at_unix_ms.into()),
    ])
}

fn retraction_row(retraction: &ProjectionRetraction) -> BoltMap {
    map([("assertion_id", retraction.assertion_id.clone().into())])
}

fn map<const N: usize>(values: [(&str, BoltType); N]) -> BoltMap {
    let mut result = BoltMap::with_capacity(N);
    for (key, value) in values {
        result.put(key.into(), value);
    }
    result
}

#[cfg(test)]
mod tests {
    use cerebro_agent_context::{FactQuery, QueryAbsentEdge, QueryDirection, QueryEdge, QueryNode};

    use super::*;

    #[test]
    fn projection_is_tenant_scoped_batched_and_uses_generic_relation_edges() {
        for query in [ENTITY_QUERY, ASSERTION_QUERY, RETRACTION_QUERY] {
            assert!(query.contains("UNWIND $rows"));
            assert!(query.contains("$tenant_id"));
            assert!(!query.contains("row.tenant_id"));
        }
        for query in [ENTITY_QUERY, ASSERTION_QUERY] {
            assert!(query.contains("$graph_revision"));
            assert!(!query.contains("row.graph_revision"));
        }
        assert!(ASSERTION_QUERY.contains("ORGANIZATIONAL_RELATION"));
        assert!(
            NEO4J_SCHEMA
                .iter()
                .any(|statement| statement.contains("IS UNIQUE"))
        );
    }

    #[test]
    fn graph_queries_enforce_edge_bounds_and_simple_paths() {
        assert!(ONE_HOP_BATCH_QUERY.contains("LIMIT $row_limit"));
        assert!(expand_statement(3).contains("LIMIT $row_limit"));
        let paths = paths_statement(3);
        assert!(paths.contains("single(other IN nodes(path) WHERE other = node)"));
        assert!(paths.contains("node.tenant_id = $tenant_id"));
        assert!(PATH_ENDPOINTS_STATEMENT.contains("source IS NOT NULL"));
        assert!(PATH_ENDPOINTS_STATEMENT.contains("target IS NOT NULL"));

        let mut exact = vec![1, 2];
        assert!(!truncate_to_limit(&mut exact, 2));
        assert_eq!(exact, [1, 2]);
        let mut overflow = vec![1, 2, 3];
        assert!(truncate_to_limit(&mut overflow, 2));
        assert_eq!(overflow, [1, 2]);
        assert_eq!(row_limit(500), 501);
    }

    #[test]
    fn fact_query_compiles_only_validated_structure_and_hard_bounds() {
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
                    keys: vec!["control-1".to_owned()],
                },
            ],
            vec![QueryEdge {
                variable: "mapping".to_owned(),
                from_variable: "finding".to_owned(),
                relation: "mapped_to_control".to_owned(),
                to_variable: "control".to_owned(),
            }],
            vec![QueryAbsentEdge {
                bound_variable: "finding".to_owned(),
                direction: QueryDirection::Incoming,
                relation: "evidence_for".to_owned(),
                other_kinds: vec!["evidence".to_owned()],
            }],
            25,
        )
        .unwrap();

        let statement = fact_query_statement(&query);

        assert!(statement.contains("MATCH (node_0:OrganizationalEntity"));
        assert!(statement.contains("MATCH (node_0)-[edge_0:ORGANIZATIONAL_RELATION]->(node_1)"));
        assert!(statement.contains("NOT EXISTS"));
        assert!(statement.contains("$edge_0_relation"));
        assert!(statement.contains("$absence_0_relation"));
        assert!(statement.ends_with("LIMIT $row_limit"));
        assert!(!statement.contains("mapped_to_control"));
        assert!(!statement.contains("control-1"));
    }
}
