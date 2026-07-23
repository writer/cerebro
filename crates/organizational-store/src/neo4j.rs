use async_trait::async_trait;
use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, GraphPath, Neighborhood, validate_bounds,
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
  tenant_id: row.tenant_id,
  entity_id: row.entity_id
})
SET entity.entity_kind = row.entity_kind,
    entity.authority_json = row.authority_json,
    entity.label = row.label,
    entity.properties_json = row.properties_json,
    entity.graph_revision = row.graph_revision
"#;

const ASSERTION_QUERY: &str = r#"
UNWIND $rows AS row
MATCH (source:OrganizationalEntity {
  tenant_id: row.tenant_id,
  entity_id: row.from_entity_id
})
MATCH (target:OrganizationalEntity {
  tenant_id: row.tenant_id,
  entity_id: row.to_entity_id
})
MERGE (source)-[assertion:ORGANIZATIONAL_RELATION {
  tenant_id: row.tenant_id,
  assertion_id: row.assertion_id
}]->(target)
SET assertion.relation = row.relation,
    assertion.source_runtime_id = row.source_runtime_id,
    assertion.state = row.state,
    assertion.provenance_json = row.provenance_json,
    assertion.observed_at_unix_ms = row.observed_at_unix_ms,
    assertion.graph_revision = row.graph_revision
"#;

const RETRACTION_QUERY: &str = r#"
UNWIND $rows AS row
MATCH ()-[assertion:ORGANIZATIONAL_RELATION {
  tenant_id: row.tenant_id,
  assertion_id: row.assertion_id
}]->()
DELETE assertion
"#;

const REVISION_QUERY: &str = r#"
MERGE (revision:OrganizationalGraphRevision {tenant_id: $tenant_id})
SET revision.graph_revision = $graph_revision,
    revision.delta_digest = $delta_digest
"#;

const NEO4J_SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT organizational_entity_identity IF NOT EXISTS FOR (entity:OrganizationalEntity) REQUIRE (entity.tenant_id, entity.entity_id) IS UNIQUE",
    "CREATE CONSTRAINT organizational_revision_tenant IF NOT EXISTS FOR (revision:OrganizationalGraphRevision) REQUIRE revision.tenant_id IS UNIQUE",
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
        if !commit.entities.is_empty() {
            transaction
                .run(
                    query(ENTITY_QUERY).param(
                        "rows",
                        rows(
                            commit
                                .entities
                                .iter()
                                .map(|entity| entity_row(commit, entity)),
                        ),
                    ),
                )
                .await?;
        }
        if !commit.assertions.is_empty() {
            transaction
                .run(
                    query(ASSERTION_QUERY).param(
                        "rows",
                        rows(
                            commit
                                .assertions
                                .iter()
                                .map(|assertion| assertion_row(commit, assertion)),
                        ),
                    ),
                )
                .await?;
        }
        if !commit.retractions.is_empty() {
            transaction
                .run(
                    query(RETRACTION_QUERY).param(
                        "rows",
                        rows(
                            commit
                                .retractions
                                .iter()
                                .map(|retraction| retraction_row(commit, retraction)),
                        ),
                    ),
                )
                .await?;
        }
        let graph_revision = i64::try_from(commit.graph_revision)
            .map_err(|_| StoreError::Conflict("graph revision overflow".to_owned()))?;
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

    async fn expand(
        &self,
        tenant_id: &TenantId,
        root_id: &EntityId,
        depth: usize,
        limit: usize,
    ) -> Result<Neighborhood, ContextError> {
        validate_bounds(depth, limit)?;
        let root = self.get(tenant_id, root_id).await?;
        let statement = format!(
            "MATCH path=(root:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $root_id}})-[:ORGANIZATIONAL_RELATION*1..{depth}]-(node:OrganizationalEntity) WITH relationships(path) AS relations UNWIND relations AS edge WITH DISTINCT edge MATCH (source)-[edge]->(target) WHERE source.tenant_id = $tenant_id AND target.tenant_id = $tenant_id RETURN source.entity_id AS from_id, source.entity_kind AS from_kind, source.authority_json AS from_authority, source.label AS from_label, source.properties_json AS from_properties, target.entity_id AS to_id, target.entity_kind AS to_kind, target.authority_json AS to_authority, target.label AS to_label, target.properties_json AS to_properties, edge.assertion_id AS assertion_id, edge.relation AS relation, edge.source_runtime_id AS source_runtime_id ORDER BY assertion_id LIMIT $limit"
        );
        let mut stream = self
            .graph
            .execute(
                query(&statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_id", root_id.as_str())
                    .param("limit", i64::try_from(limit).unwrap_or(500)),
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
        entities.remove(root_id);
        let truncated = edges.len() == limit;
        Ok(Neighborhood {
            tenant_id: tenant_id.clone(),
            graph_revision: self.revision(tenant_id).await?,
            root,
            entities: entities.into_values().collect(),
            edges,
            truncated,
        })
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
        let statement = format!(
            "MATCH path=(source:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $from_id}})-[:ORGANIZATIONAL_RELATION*1..{max_depth}]->(target:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $to_id}}) RETURN [node IN nodes(path) | node.entity_id] AS entity_ids, [node IN nodes(path) | node.entity_kind] AS entity_kinds, [node IN nodes(path) | node.authority_json] AS authorities, [node IN nodes(path) | node.label] AS labels, [node IN nodes(path) | node.properties_json] AS properties, [edge IN relationships(path) | edge.assertion_id] AS assertion_ids, [edge IN relationships(path) | edge.relation] AS relations, [edge IN relationships(path) | edge.source_runtime_id] AS runtime_ids ORDER BY length(path), assertion_ids LIMIT $limit"
        );
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
                entities.push(ContextEntity {
                    entity_id: EntityId::parse(&entity_ids[index])
                        .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
                    entity_kind: entity_kinds[index].clone(),
                    authority: parse_json(&authorities[index])?,
                    label: labels[index].clone(),
                    properties: parse_json(&properties[index])?,
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
}

impl Neo4jProjector {
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

fn context_entity(row: &neo4rs::Row) -> Result<ContextEntity, ContextError> {
    Ok(ContextEntity {
        entity_id: EntityId::parse(row_string(row, "entity_id")?)
            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
        entity_kind: row_string(row, "entity_kind")?,
        authority: parse_json(&row_string(row, "authority_json")?)?,
        label: row_string(row, "label")?,
        properties: parse_json(&row_string(row, "properties_json")?)?,
    })
}

fn context_entity_prefix(row: &neo4rs::Row, prefix: &str) -> Result<ContextEntity, ContextError> {
    Ok(ContextEntity {
        entity_id: EntityId::parse(row_string(row, &format!("{prefix}_id"))?)
            .map_err(|error| ContextError::BackendUnavailable(error.to_string()))?,
        entity_kind: row_string(row, &format!("{prefix}_kind"))?,
        authority: parse_json(&row_string(row, &format!("{prefix}_authority"))?)?,
        label: row_string(row, &format!("{prefix}_label"))?,
        properties: parse_json(&row_string(row, &format!("{prefix}_properties"))?)?,
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

fn entity_row(commit: &ProjectionCommit, entity: &ProjectionEntity) -> BoltMap {
    map([
        ("tenant_id", commit.tenant_id.clone().into()),
        ("entity_id", entity.entity_id.clone().into()),
        ("entity_kind", entity.entity_kind.clone().into()),
        ("authority_json", entity.authority_json.clone().into()),
        ("label", entity.label.clone().into()),
        ("properties_json", entity.properties_json.clone().into()),
        ("graph_revision", revision_value(commit.graph_revision)),
    ])
}

fn assertion_row(commit: &ProjectionCommit, assertion: &ProjectionAssertion) -> BoltMap {
    map([
        ("tenant_id", commit.tenant_id.clone().into()),
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
        ("graph_revision", revision_value(commit.graph_revision)),
    ])
}

fn retraction_row(commit: &ProjectionCommit, retraction: &ProjectionRetraction) -> BoltMap {
    map([
        ("tenant_id", commit.tenant_id.clone().into()),
        ("assertion_id", retraction.assertion_id.clone().into()),
    ])
}

fn revision_value(revision: u64) -> BoltType {
    i64::try_from(revision).unwrap_or(i64::MAX).into()
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
    use super::*;

    #[test]
    fn projection_is_tenant_scoped_batched_and_uses_generic_relation_edges() {
        for query in [ENTITY_QUERY, ASSERTION_QUERY, RETRACTION_QUERY] {
            assert!(query.contains("UNWIND $rows"));
            assert!(query.contains("tenant_id"));
        }
        assert!(ASSERTION_QUERY.contains("ORGANIZATIONAL_RELATION"));
        assert!(
            NEO4J_SCHEMA
                .iter()
                .any(|statement| statement.contains("IS UNIQUE"))
        );
    }
}
