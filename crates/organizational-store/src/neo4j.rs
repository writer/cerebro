use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, FactQuery, GraphPath, Neighborhood,
    QueryDirection, QueryMatch, QueryResult, validate_bounds, validate_root_keys,
};
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{AssertionId, EntityId, GraphDelta, TenantId};
use cerebro_security_lifecycle::{
    IndexedLifecyclePage, KeysetDirection, LifecycleAggregates, LifecycleState, PolicyState,
    PolicyStateCount, PreparedLifecycleQuery, ProjectedResource, StateCount, SubjectKind,
    SubjectKindCount,
};
use neo4rs::{BoltList, BoltMap, BoltType, Graph, Row, query};

use crate::{
    StoreError,
    postgres::{
        ProjectionAssertion, ProjectionCommit, ProjectionEntity, ProjectionRetraction,
        lifecycle_finding_projection, lifecycle_projection, projection_commit,
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
    entity.graph_revision = $graph_revision,
    entity.lifecycle_subject_urn = CASE WHEN row.lifecycle_subject THEN row.lifecycle_subject_urn ELSE null END,
    entity.lifecycle_subject_kind = CASE WHEN row.lifecycle_subject THEN row.lifecycle_subject_kind ELSE null END,
    entity.lifecycle_observed_state = CASE WHEN row.lifecycle_subject THEN row.lifecycle_observed_state ELSE null END,
    entity.lifecycle_owner_urn = CASE WHEN row.lifecycle_owner_urn = '' THEN null ELSE row.lifecycle_owner_urn END,
    entity.lifecycle_observed_at_unix_ms = CASE WHEN row.lifecycle_subject THEN row.lifecycle_observed_at_unix_ms ELSE null END,
    entity.lifecycle_expires_at_unix_ms = CASE WHEN row.lifecycle_expires_at_unix_ms < 0 THEN null ELSE row.lifecycle_expires_at_unix_ms END,
    entity.lifecycle_source_runtime_id = CASE WHEN row.lifecycle_projected AND row.lifecycle_source_runtime_id <> '' THEN row.lifecycle_source_runtime_id ELSE null END,
    entity.lifecycle_source_collection_id = CASE WHEN row.lifecycle_projected AND row.lifecycle_source_collection_id <> '' THEN row.lifecycle_source_collection_id ELSE null END
FOREACH (_ IN CASE WHEN row.lifecycle_subject THEN [1] ELSE [] END |
  SET entity:SecurityLifecycleSubject
)
FOREACH (_ IN CASE WHEN row.lifecycle_subject THEN [] ELSE [1] END |
  REMOVE entity:SecurityLifecycleSubject
)
FOREACH (_ IN CASE WHEN row.lifecycle_finding THEN [1] ELSE [] END |
  SET entity:SecurityLifecycleFinding
)
FOREACH (_ IN CASE WHEN row.lifecycle_finding THEN [] ELSE [1] END |
  REMOVE entity:SecurityLifecycleFinding
)
SET entity.lifecycle_finding_urn = CASE WHEN row.lifecycle_finding THEN row.lifecycle_finding_urn ELSE null END
"#;

const REBUILD_LIFECYCLE_ENTITY_QUERY: &str = r#"
MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id})
WHERE revision.graph_revision = $graph_revision
WITH revision
UNWIND $rows AS row
MATCH (entity:OrganizationalEntity {
  tenant_id: $tenant_id,
  entity_id: row.entity_id
})
WHERE coalesce(entity.graph_revision, 0) = row.source_graph_revision
SET entity.lifecycle_subject_urn = CASE WHEN row.lifecycle_subject THEN row.lifecycle_subject_urn ELSE null END,
    entity.lifecycle_subject_kind = CASE WHEN row.lifecycle_subject THEN row.lifecycle_subject_kind ELSE null END,
    entity.lifecycle_observed_state = CASE WHEN row.lifecycle_subject THEN row.lifecycle_observed_state ELSE null END,
    entity.lifecycle_owner_urn = CASE WHEN row.lifecycle_owner_urn = '' THEN null ELSE row.lifecycle_owner_urn END,
    entity.lifecycle_observed_at_unix_ms = CASE WHEN row.lifecycle_subject THEN row.lifecycle_observed_at_unix_ms ELSE null END,
    entity.lifecycle_expires_at_unix_ms = CASE WHEN row.lifecycle_expires_at_unix_ms < 0 THEN null ELSE row.lifecycle_expires_at_unix_ms END,
    entity.lifecycle_source_runtime_id = CASE WHEN row.lifecycle_projected AND row.lifecycle_source_runtime_id <> '' THEN row.lifecycle_source_runtime_id ELSE null END,
    entity.lifecycle_source_collection_id = CASE WHEN row.lifecycle_projected AND row.lifecycle_source_collection_id <> '' THEN row.lifecycle_source_collection_id ELSE null END
FOREACH (_ IN CASE WHEN row.lifecycle_subject THEN [1] ELSE [] END |
  SET entity:SecurityLifecycleSubject
)
FOREACH (_ IN CASE WHEN row.lifecycle_subject THEN [] ELSE [1] END |
  REMOVE entity:SecurityLifecycleSubject
)
FOREACH (_ IN CASE WHEN row.lifecycle_finding THEN [1] ELSE [] END |
  SET entity:SecurityLifecycleFinding
)
FOREACH (_ IN CASE WHEN row.lifecycle_finding THEN [] ELSE [1] END |
  REMOVE entity:SecurityLifecycleFinding
)
SET entity.lifecycle_finding_urn = CASE WHEN row.lifecycle_finding THEN row.lifecycle_finding_urn ELSE null END
RETURN count(entity) AS rebuilt
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

const ADVANCE_LIFECYCLE_PROJECTION_QUERY: &str = r#"
MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id})
WHERE state.ready = true
  AND state.schema_version = 1
  AND state.graph_revision IN [$graph_revision, $graph_revision - 1]
SET state.graph_revision = $graph_revision
"#;

// A fresh ECS task can spend several seconds establishing the first routed Bolt
// connection. Keep readiness bounded, but do not kill an otherwise healthy
// authority during that one-time connection warm-up.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
const PROJECTION_BATCH_SIZE: usize = 1_000;

const LIFECYCLE_FILTER: &str = r#"
(size($subject_kinds) = 0 OR entity.lifecycle_subject_kind IN $subject_kinds)
AND (size($states) = 0 OR entity.lifecycle_observed_state IN $states)
AND (size($owner_urns) = 0 OR entity.lifecycle_owner_urn IN $owner_urns)
AND ($expires_before_unix_ms < 0 OR (
  entity.lifecycle_expires_at_unix_ms IS NOT NULL
  AND entity.lifecycle_expires_at_unix_ms < $expires_before_unix_ms
))
AND ($locator_urn = '' OR entity.lifecycle_subject_urn = $locator_urn)
AND (NOT $findings_only OR (
  entity.lifecycle_observed_state IN ['expiring', 'expired']
  OR (
    entity.lifecycle_observed_state = 'active'
    AND entity.lifecycle_expires_at_unix_ms IS NOT NULL
    AND entity.lifecycle_expires_at_unix_ms <= $warning_cutoff_unix_ms
  )
))
"#;

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
    "CREATE CONSTRAINT security_lifecycle_subject_identity IF NOT EXISTS FOR (entity:SecurityLifecycleSubject) REQUIRE (entity.tenant_id, entity.lifecycle_subject_urn) IS UNIQUE",
    "CREATE INDEX security_lifecycle_subject_kind IF NOT EXISTS FOR (entity:SecurityLifecycleSubject) ON (entity.tenant_id, entity.lifecycle_subject_kind)",
    "CREATE INDEX security_lifecycle_observed_state IF NOT EXISTS FOR (entity:SecurityLifecycleSubject) ON (entity.tenant_id, entity.lifecycle_observed_state)",
    "CREATE INDEX security_lifecycle_owner IF NOT EXISTS FOR (entity:SecurityLifecycleSubject) ON (entity.tenant_id, entity.lifecycle_owner_urn)",
    "CREATE INDEX security_lifecycle_expiry IF NOT EXISTS FOR (entity:SecurityLifecycleSubject) ON (entity.tenant_id, entity.lifecycle_expires_at_unix_ms)",
    "CREATE CONSTRAINT security_lifecycle_finding_identity IF NOT EXISTS FOR (finding:SecurityLifecycleFinding) REQUIRE (finding.tenant_id, finding.lifecycle_finding_urn) IS UNIQUE",
    "CREATE CONSTRAINT security_lifecycle_projection_state IF NOT EXISTS FOR (state:SecurityLifecycleProjectionState) REQUIRE state.tenant_id IS UNIQUE",
];

#[derive(Clone)]
pub struct Neo4jProjector {
    graph: Graph,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedLifecycleFinding {
    pub resource: ProjectedResource,
    pub graph_revision: u64,
    pub source_runtime_id: String,
    pub source_collection_id: String,
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

    pub async fn query_lifecycle(
        &self,
        tenant_id: &TenantId,
        prepared: &PreparedLifecycleQuery,
    ) -> Result<IndexedLifecyclePage, StoreError> {
        let mut transaction = self.graph.start_txn().await?;
        let mut revision_rows = transaction
            .execute(
                query(
                    "OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) OPTIONAL MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision, coalesce(state.ready, false) AS projection_ready, coalesce(state.schema_version, 0) AS schema_version, coalesce(state.graph_revision, -1) AS projection_revision",
                )
                .param("tenant_id", tenant_id.as_str()),
            )
            .await?;
        let revision_row = revision_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict(
                    "lifecycle projection revision query returned no row".to_owned(),
                )
            })?;
        drop(revision_rows);
        let start_graph_revision = u64::try_from(
            revision_row
                .get::<i64>("graph_revision")
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .map_err(|_| StoreError::Conflict("lifecycle graph revision is negative".to_owned()))?;
        let projection_ready: bool = revision_row
            .get("projection_ready")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let schema_version: i64 = revision_row
            .get("schema_version")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let projection_revision: i64 = revision_row
            .get("projection_revision")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if !projection_ready
            || schema_version != 1
            || projection_revision < 0
            || u64::try_from(projection_revision).ok() != Some(start_graph_revision)
        {
            return Err(StoreError::LifecycleProjectionUnavailable {
                graph_revision: start_graph_revision,
                projection_revision: projection_ready
                    .then(|| u64::try_from(projection_revision).ok())
                    .flatten(),
            });
        }

        let subject_kinds = prepared
            .subject_kinds()
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect::<Vec<_>>();
        let states = prepared
            .states()
            .iter()
            .map(|state| cerebro_security_lifecycle::lifecycle_state_name(*state).to_owned())
            .collect::<Vec<_>>();
        let aggregate_statement = format!(
            r#"
MATCH (entity:SecurityLifecycleSubject {{tenant_id: $tenant_id}})
WHERE {LIFECYCLE_FILTER}
RETURN count(entity) AS matched_records,
       coalesce(sum(CASE WHEN entity.lifecycle_subject_kind = 'credential' THEN 1 ELSE 0 END), 0) AS credential_count,
       coalesce(sum(CASE WHEN entity.lifecycle_subject_kind = 'certificate' THEN 1 ELSE 0 END), 0) AS certificate_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'active' THEN 1 ELSE 0 END), 0) AS active_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'expiring' THEN 1 ELSE 0 END), 0) AS expiring_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'expired' THEN 1 ELSE 0 END), 0) AS expired_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'rotated' THEN 1 ELSE 0 END), 0) AS rotated_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'revoked' THEN 1 ELSE 0 END), 0) AS revoked_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'inactive' THEN 1 ELSE 0 END), 0) AS inactive_count,
       coalesce(sum(CASE WHEN entity.lifecycle_observed_state = 'unknown' THEN 1 ELSE 0 END), 0) AS unknown_count,
       coalesce(sum(CASE WHEN (
         entity.lifecycle_observed_state IN ['rotated', 'revoked', 'inactive']
         OR (
           entity.lifecycle_observed_state = 'active'
           AND entity.lifecycle_expires_at_unix_ms > $warning_cutoff_unix_ms
         )
       ) THEN 1 ELSE 0 END), 0) AS policy_compliant_count,
       coalesce(sum(CASE WHEN (
         entity.lifecycle_observed_state = 'expiring'
         OR (
           entity.lifecycle_observed_state = 'active'
           AND entity.lifecycle_expires_at_unix_ms > $as_of_unix_ms
           AND entity.lifecycle_expires_at_unix_ms <= $warning_cutoff_unix_ms
         )
       ) THEN 1 ELSE 0 END), 0) AS policy_expiring_count,
       coalesce(sum(CASE WHEN (
         entity.lifecycle_observed_state = 'expired'
         OR (
           entity.lifecycle_observed_state = 'active'
           AND entity.lifecycle_expires_at_unix_ms <= $as_of_unix_ms
         )
       ) THEN 1 ELSE 0 END), 0) AS policy_expired_count,
       coalesce(sum(CASE WHEN (
         entity.lifecycle_observed_state = 'unknown'
         OR (
           entity.lifecycle_observed_state = 'active'
           AND entity.lifecycle_expires_at_unix_ms IS NULL
         )
       ) THEN 1 ELSE 0 END), 0) AS policy_unknown_count,
       coalesce(sum(CASE WHEN (
         entity.lifecycle_observed_state IN ['expiring', 'expired']
         OR (
           entity.lifecycle_observed_state = 'active'
           AND entity.lifecycle_expires_at_unix_ms IS NOT NULL
           AND entity.lifecycle_expires_at_unix_ms <= $warning_cutoff_unix_ms
         )
       ) THEN 1 ELSE 0 END), 0) AS matched_findings,
       coalesce(min(entity.lifecycle_observed_at_unix_ms), -1) AS oldest_observed_at,
       coalesce(max(entity.lifecycle_observed_at_unix_ms), -1) AS newest_observed_at
"#
        );
        let mut aggregate_rows = transaction
            .execute(
                query(&aggregate_statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("subject_kinds", string_list(&subject_kinds))
                    .param("states", string_list(&states))
                    .param("owner_urns", string_list(prepared.owner_urns()))
                    .param(
                        "expires_before_unix_ms",
                        prepared.expires_before_unix_ms().unwrap_or(-1),
                    )
                    .param("locator_urn", prepared.locator_urn().unwrap_or(""))
                    .param("findings_only", prepared.findings_only())
                    .param("as_of_unix_ms", prepared.effective_as_of_unix_ms())
                    .param("warning_cutoff_unix_ms", prepared.warning_cutoff_unix_ms()),
            )
            .await?;
        let aggregate = aggregate_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict("lifecycle aggregate query returned no row".to_owned())
            })?;
        drop(aggregate_rows);

        let mut lifecycle_count_rows = transaction
            .execute(
                query(
                    "MATCH (entity:SecurityLifecycleSubject {tenant_id: $tenant_id}) RETURN count(entity) AS lifecycle_entities",
                )
                .param("tenant_id", tenant_id.as_str()),
            )
            .await?;
        let lifecycle_count_row = lifecycle_count_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict("lifecycle entity count query returned no row".to_owned())
            })?;
        drop(lifecycle_count_rows);
        let lifecycle_entities = row_u64(&lifecycle_count_row, "lifecycle_entities")?;

        let keyset_predicate = match (
            prepared.direction(),
            prepared.cursor_subject_urn().is_some(),
        ) {
            (KeysetDirection::Forward, true) => {
                "AND entity.lifecycle_subject_urn > $cursor_subject_urn"
            }
            (KeysetDirection::Backward, true) => {
                "AND entity.lifecycle_subject_urn < $cursor_subject_urn"
            }
            _ => "",
        };
        let order = match prepared.direction() {
            KeysetDirection::Forward => "ASC",
            KeysetDirection::Backward => "DESC",
        };
        let page_statement = format!(
            r#"
MATCH (entity:SecurityLifecycleSubject {{tenant_id: $tenant_id}})
WHERE {LIFECYCLE_FILTER}
{keyset_predicate}
RETURN entity.lifecycle_subject_urn AS subject_urn,
       entity.label AS label,
       entity.properties_json AS properties_json,
       entity.lifecycle_source_runtime_id AS source_runtime_id,
       entity.lifecycle_source_collection_id AS source_collection_id
ORDER BY entity.lifecycle_subject_urn {order}
LIMIT $row_limit
"#
        );
        let mut page_rows = transaction
            .execute(
                query(&page_statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("subject_kinds", string_list(&subject_kinds))
                    .param("states", string_list(&states))
                    .param("owner_urns", string_list(prepared.owner_urns()))
                    .param(
                        "expires_before_unix_ms",
                        prepared.expires_before_unix_ms().unwrap_or(-1),
                    )
                    .param("locator_urn", prepared.locator_urn().unwrap_or(""))
                    .param("findings_only", prepared.findings_only())
                    .param("as_of_unix_ms", prepared.effective_as_of_unix_ms())
                    .param("warning_cutoff_unix_ms", prepared.warning_cutoff_unix_ms())
                    .param(
                        "cursor_subject_urn",
                        prepared.cursor_subject_urn().unwrap_or(""),
                    )
                    .param("row_limit", row_limit(prepared.limit())),
            )
            .await?;
        let mut resources = Vec::with_capacity(prepared.limit().saturating_add(1));
        while let Some(row) = page_rows.next(transaction.handle()).await? {
            let subject_urn: String = row
                .get("subject_urn")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let label: String = row
                .get("label")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let properties_json: String = row
                .get("properties_json")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let mut properties: BTreeMap<String, String> = serde_json::from_str(&properties_json)?;
            if let Some(source_runtime_id) = row
                .get::<Option<String>>("source_runtime_id")
                .map_err(|error| StoreError::Conflict(error.to_string()))?
            {
                properties.insert("source_runtime_id".to_owned(), source_runtime_id);
            }
            if let Some(source_collection_id) = row
                .get::<Option<String>>("source_collection_id")
                .map_err(|error| StoreError::Conflict(error.to_string()))?
            {
                properties.insert("source_collection_id".to_owned(), source_collection_id);
            }
            resources.push(ProjectedResource {
                agent_key: subject_urn,
                label,
                properties,
            });
        }
        drop(page_rows);
        let mut end_revision_rows = transaction
            .execute(
                query(
                    "OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) OPTIONAL MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision, coalesce(state.ready, false) AS projection_ready, coalesce(state.schema_version, 0) AS schema_version, coalesce(state.graph_revision, -1) AS projection_revision",
                )
                .param("tenant_id", tenant_id.as_str()),
            )
            .await?;
        let end_revision_row = end_revision_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict(
                    "lifecycle projection end revision query returned no row".to_owned(),
                )
            })?;
        let graph_revision = u64::try_from(
            end_revision_row
                .get::<i64>("graph_revision")
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .map_err(|_| StoreError::Conflict("lifecycle graph revision is negative".to_owned()))?;
        let end_projection_ready: bool = end_revision_row
            .get("projection_ready")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let end_schema_version: i64 = end_revision_row
            .get("schema_version")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let end_projection_revision: i64 = end_revision_row
            .get("projection_revision")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let projection_changed = !end_projection_ready
            || end_schema_version != 1
            || u64::try_from(end_projection_revision).ok() != Some(graph_revision);
        drop(end_revision_rows);
        transaction.commit().await?;

        let extra_row = resources.len() > prepared.limit();
        resources.truncate(prepared.limit());
        let cursor_present = prepared.cursor_subject_urn().is_some();
        let (has_previous, has_next) = match prepared.direction() {
            KeysetDirection::Forward => (cursor_present, extra_row),
            KeysetDirection::Backward => {
                resources.reverse();
                (extra_row, cursor_present)
            }
        };
        let oldest_observed_at = optional_timestamp(&aggregate, "oldest_observed_at")?;
        let newest_observed_at = optional_timestamp(&aggregate, "newest_observed_at")?;
        Ok(IndexedLifecyclePage {
            resources,
            aggregates: LifecycleAggregates {
                counts_are_exact: start_graph_revision == graph_revision
                    && graph_revision == prepared.graph_revision()
                    && !projection_changed,
                matched_records: row_u64(&aggregate, "matched_records")?,
                matched_findings: row_u64(&aggregate, "matched_findings")?,
                subject_kind_counts: vec![
                    SubjectKindCount {
                        subject_kind: SubjectKind::Credential,
                        count: row_u64(&aggregate, "credential_count")?,
                    },
                    SubjectKindCount {
                        subject_kind: SubjectKind::Certificate,
                        count: row_u64(&aggregate, "certificate_count")?,
                    },
                ],
                state_counts: [
                    (LifecycleState::Active, "active_count"),
                    (LifecycleState::Expiring, "expiring_count"),
                    (LifecycleState::Expired, "expired_count"),
                    (LifecycleState::Rotated, "rotated_count"),
                    (LifecycleState::Revoked, "revoked_count"),
                    (LifecycleState::Inactive, "inactive_count"),
                    (LifecycleState::Unknown, "unknown_count"),
                ]
                .into_iter()
                .map(|(state, field)| {
                    Ok(StateCount {
                        state,
                        count: row_u64(&aggregate, field)?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
                policy_state_counts: [
                    (PolicyState::Compliant, "policy_compliant_count"),
                    (PolicyState::Expiring, "policy_expiring_count"),
                    (PolicyState::Expired, "policy_expired_count"),
                    (PolicyState::Unknown, "policy_unknown_count"),
                ]
                .into_iter()
                .map(|(policy_state, field)| {
                    Ok(PolicyStateCount {
                        policy_state,
                        count: row_u64(&aggregate, field)?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
            },
            lifecycle_entities,
            oldest_observed_at,
            newest_observed_at,
            has_previous,
            has_next,
            graph_revision,
            graph_changed: start_graph_revision != graph_revision || projection_changed,
        })
    }

    pub async fn rebuild_lifecycle_projection(
        &self,
        tenant_id: &TenantId,
        batch_size: usize,
    ) -> Result<usize, StoreError> {
        let batch_size = batch_size.clamp(1, 1_000);
        let start_revision = self
            .revision(tenant_id)
            .await
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let graph_revision = i64::try_from(start_revision)
            .map_err(|_| StoreError::Conflict("graph revision overflow".to_owned()))?;
        let mut invalidate_transaction = self.graph.start_txn().await?;
        let mut invalidation_rows = invalidate_transaction
            .execute(
                query(
                    "MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) WHERE revision.graph_revision = $graph_revision MERGE (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) SET state.schema_version = 1, state.graph_revision = $graph_revision, state.ready = false RETURN state.ready AS ready",
                )
                .param("tenant_id", tenant_id.as_str())
                .param("graph_revision", graph_revision),
            )
            .await?;
        let invalidated = invalidation_rows
            .next(invalidate_transaction.handle())
            .await?
            .map(|row| {
                row.get::<bool>("ready")
                    .map(|ready| !ready)
                    .map_err(|error| StoreError::Conflict(error.to_string()))
            })
            .transpose()?
            .unwrap_or(false);
        drop(invalidation_rows);
        if !invalidated {
            return Err(StoreError::Conflict(
                "graph revision changed before lifecycle projection rebuild".to_owned(),
            ));
        }
        invalidate_transaction.commit().await?;
        let mut after_entity_id = String::new();
        let mut rebuilt = 0_usize;
        loop {
            let mut stream = self
                .graph
                .execute(
                    query(
                        "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id}) WHERE entity.entity_kind IN ['resource', 'finding'] AND entity.entity_id > $after_entity_id RETURN entity.entity_id AS entity_id, entity.entity_kind AS entity_kind, entity.authority_json AS authority_json, entity.label AS label, entity.properties_json AS properties_json, entity.external_id AS external_id, coalesce(entity.graph_revision, 0) AS source_graph_revision ORDER BY entity.entity_id LIMIT $limit",
                    )
                    .param("tenant_id", tenant_id.as_str())
                    .param("after_entity_id", after_entity_id.clone())
                    .param("limit", i64::try_from(batch_size).unwrap_or(1_000)),
                )
                .await?;
            let mut entities = Vec::with_capacity(batch_size);
            while let Some(row) = stream.next().await? {
                let entity_id: String = row
                    .get("entity_id")
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
                after_entity_id = entity_id.clone();
                entities.push((
                    ProjectionEntity {
                        entity_id,
                        entity_kind: row
                            .get("entity_kind")
                            .map_err(|error| StoreError::Conflict(error.to_string()))?,
                        authority_json: row
                            .get("authority_json")
                            .map_err(|error| StoreError::Conflict(error.to_string()))?,
                        label: row
                            .get("label")
                            .map_err(|error| StoreError::Conflict(error.to_string()))?,
                        properties_json: row
                            .get("properties_json")
                            .map_err(|error| StoreError::Conflict(error.to_string()))?,
                        external_id: Some(
                            row.get("external_id")
                                .map_err(|error| StoreError::Conflict(error.to_string()))?,
                        ),
                        lifecycle: None,
                        lifecycle_finding_urn: None,
                        lifecycle_source_runtime_id: None,
                        lifecycle_source_collection_id: None,
                    },
                    row.get::<i64>("source_graph_revision")
                        .map_err(|error| StoreError::Conflict(error.to_string()))?,
                ));
            }
            if entities.is_empty() {
                break;
            }
            let row_count = entities.len();
            let entity_rows = entities
                .iter()
                .map(|(entity, source_graph_revision)| {
                    let mut row = refreshed_entity_row(tenant_id, entity)?;
                    row.put(
                        "source_graph_revision".into(),
                        (*source_graph_revision).into(),
                    );
                    Ok(row)
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            let mut transaction = self.graph.start_txn().await?;
            let mut rebuilt_rows = transaction
                .execute(
                    query(REBUILD_LIFECYCLE_ENTITY_QUERY)
                        .param("tenant_id", tenant_id.as_str())
                        .param("graph_revision", graph_revision)
                        .param("rows", rows(entity_rows)),
                )
                .await?;
            let rebuilt_batch = rebuilt_rows
                .next(transaction.handle())
                .await?
                .map(|row| {
                    row.get::<i64>("rebuilt")
                        .map_err(|error| StoreError::Conflict(error.to_string()))
                })
                .transpose()?
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            drop(rebuilt_rows);
            if rebuilt_batch != row_count {
                transaction.rollback().await?;
                return Err(StoreError::Conflict(
                    "graph revision or entity changed during lifecycle projection rebuild"
                        .to_owned(),
                ));
            }
            transaction.commit().await?;
            rebuilt = rebuilt.saturating_add(row_count);
            if row_count < batch_size {
                break;
            }
        }
        let end_revision = self
            .revision(tenant_id)
            .await
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if start_revision != end_revision {
            return Err(StoreError::Conflict(
                "graph revision changed during lifecycle projection rebuild".to_owned(),
            ));
        }
        let mut transaction = self.graph.start_txn().await?;
        let mut readiness_rows = transaction
            .execute(
                query(
                    "MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) WHERE revision.graph_revision = $graph_revision MERGE (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) SET state.schema_version = 1, state.graph_revision = $graph_revision, state.ready = true RETURN state.graph_revision AS graph_revision",
                )
                .param("tenant_id", tenant_id.as_str())
                .param("graph_revision", graph_revision),
            )
            .await?;
        let readiness_set = readiness_rows.next(transaction.handle()).await?.is_some();
        drop(readiness_rows);
        if !readiness_set {
            return Err(StoreError::Conflict(
                "graph revision changed before lifecycle projection readiness".to_owned(),
            ));
        }
        transaction.commit().await?;
        let verified_revision = self
            .revision(tenant_id)
            .await
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if verified_revision != start_revision {
            return Err(StoreError::Conflict(
                "graph revision changed while lifecycle projection became ready".to_owned(),
            ));
        }
        Ok(rebuilt)
    }

    pub async fn resolve_lifecycle_finding(
        &self,
        tenant_id: &TenantId,
        finding_urn: &str,
    ) -> Result<Option<ResolvedLifecycleFinding>, StoreError> {
        let expected_prefix =
            cerebro_security_lifecycle::canonical_finding_urn_prefix(tenant_id.as_str())
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if finding_urn.len() > 4_096 || !finding_urn.starts_with(&expected_prefix) {
            return Err(StoreError::Conflict(
                "invalid tenant-scoped lifecycle finding URN".to_owned(),
            ));
        }
        let mut transaction = self.graph.start_txn().await?;
        let mut start_rows = transaction
            .execute(
                query(
                    "OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) OPTIONAL MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision, coalesce(state.ready, false) AS projection_ready, coalesce(state.schema_version, 0) AS schema_version, coalesce(state.graph_revision, -1) AS projection_revision",
                )
                .param("tenant_id", tenant_id.as_str()),
            )
            .await?;
        let start = start_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict("lifecycle finding revision query returned no row".to_owned())
            })?;
        drop(start_rows);
        let graph_revision = row_u64(&start, "graph_revision")?;
        let projection_ready: bool = start
            .get("projection_ready")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let schema_version: i64 = start
            .get("schema_version")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let projection_revision: i64 = start
            .get("projection_revision")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if !projection_ready
            || schema_version != 1
            || u64::try_from(projection_revision).ok() != Some(graph_revision)
        {
            return Err(StoreError::LifecycleProjectionUnavailable {
                graph_revision,
                projection_revision: projection_ready
                    .then(|| u64::try_from(projection_revision).ok())
                    .flatten(),
            });
        }
        let mut finding_rows = transaction
            .execute(
                query(
                    "MATCH (finding:SecurityLifecycleFinding {tenant_id: $tenant_id, lifecycle_finding_urn: $finding_urn})-[assertion:ORGANIZATIONAL_RELATION]->(subject:SecurityLifecycleSubject {tenant_id: $tenant_id}) WHERE assertion.tenant_id = $tenant_id AND assertion.relation = 'affects' AND assertion.observed_at_unix_ms = subject.lifecycle_observed_at_unix_ms RETURN finding.properties_json AS finding_properties_json, finding.lifecycle_source_runtime_id AS finding_source_runtime_id, assertion.source_runtime_id AS assertion_source_runtime_id, subject.lifecycle_source_runtime_id AS subject_source_runtime_id, finding.lifecycle_source_collection_id AS finding_source_collection_id, subject.lifecycle_source_collection_id AS subject_source_collection_id, subject.lifecycle_subject_urn AS subject_urn, subject.label AS label, subject.properties_json AS properties_json ORDER BY assertion.assertion_id LIMIT 2",
                )
                .param("tenant_id", tenant_id.as_str())
                .param("finding_urn", finding_urn),
            )
            .await?;
        let mut resolved = Vec::with_capacity(2);
        while let Some(row) = finding_rows.next(transaction.handle()).await? {
            let finding_properties_json: String = row
                .get("finding_properties_json")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let finding_properties: std::collections::BTreeMap<String, String> =
                serde_json::from_str(&finding_properties_json)?;
            if finding_properties.get("resource_urn").map(String::as_str) != Some(finding_urn)
                || finding_properties.get("policy_id").map(String::as_str)
                    != Some(cerebro_security_lifecycle::EXPIRY_POLICY_ID)
            {
                return Err(StoreError::Conflict(
                    "lifecycle finding projection does not match its durable identity".to_owned(),
                ));
            }
            let properties_json: String = row
                .get("properties_json")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let source_runtime_id: String = row
                .get("assertion_source_runtime_id")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            if source_runtime_id.trim().is_empty() {
                return Err(StoreError::Conflict(
                    "lifecycle finding has no source runtime provenance".to_owned(),
                ));
            }
            for field in ["finding_source_runtime_id", "subject_source_runtime_id"] {
                let projected: Option<String> = row
                    .get(field)
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
                if projected
                    .as_deref()
                    .is_some_and(|projected| projected != source_runtime_id)
                {
                    return Err(StoreError::Conflict(format!(
                        "lifecycle finding {field} does not match assertion provenance"
                    )));
                }
            }
            let finding_source_collection_id: Option<String> = row
                .get("finding_source_collection_id")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let subject_source_collection_id: Option<String> = row
                .get("subject_source_collection_id")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            if finding_source_collection_id.is_some()
                && subject_source_collection_id.is_some()
                && finding_source_collection_id != subject_source_collection_id
            {
                return Err(StoreError::Conflict(
                    "lifecycle finding source collection provenance does not match its subject"
                        .to_owned(),
                ));
            }
            let source_collection_id = subject_source_collection_id
                .or(finding_source_collection_id)
                .unwrap_or_default();
            let mut properties: BTreeMap<String, String> = serde_json::from_str(&properties_json)?;
            properties.insert("source_runtime_id".to_owned(), source_runtime_id.clone());
            if !source_collection_id.is_empty() {
                properties.insert(
                    "source_collection_id".to_owned(),
                    source_collection_id.clone(),
                );
            }
            resolved.push((
                ProjectedResource {
                    agent_key: row
                        .get("subject_urn")
                        .map_err(|error| StoreError::Conflict(error.to_string()))?,
                    label: row
                        .get("label")
                        .map_err(|error| StoreError::Conflict(error.to_string()))?,
                    properties,
                },
                source_runtime_id,
                source_collection_id,
            ));
        }
        drop(finding_rows);
        if resolved.len() > 1 {
            return Err(StoreError::Conflict(
                "lifecycle finding resolves to multiple subjects".to_owned(),
            ));
        }
        let mut end_rows = transaction
            .execute(
                query(
                    "OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) OPTIONAL MATCH (state:SecurityLifecycleProjectionState {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision, coalesce(state.ready, false) AS projection_ready, coalesce(state.schema_version, 0) AS schema_version, coalesce(state.graph_revision, -1) AS projection_revision",
                )
                .param("tenant_id", tenant_id.as_str()),
            )
            .await?;
        let end = end_rows.next(transaction.handle()).await?.ok_or_else(|| {
            StoreError::Conflict("lifecycle finding end revision query returned no row".to_owned())
        })?;
        let end_revision = row_u64(&end, "graph_revision")?;
        let end_ready: bool = end
            .get("projection_ready")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let end_schema: i64 = end
            .get("schema_version")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let end_projection_revision: i64 = end
            .get("projection_revision")
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        drop(end_rows);
        transaction.commit().await?;
        if end_revision != graph_revision
            || !end_ready
            || end_schema != 1
            || u64::try_from(end_projection_revision).ok() != Some(end_revision)
        {
            return Err(StoreError::LifecycleProjectionUnavailable {
                graph_revision: end_revision,
                projection_revision: end_ready
                    .then(|| u64::try_from(end_projection_revision).ok())
                    .flatten(),
            });
        }
        Ok(resolved
            .pop()
            .map(
                |(resource, source_runtime_id, source_collection_id)| ResolvedLifecycleFinding {
                    resource,
                    graph_revision,
                    source_runtime_id,
                    source_collection_id,
                },
            ))
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
        let mut lifecycle_runtime_by_entity = BTreeMap::<&str, &str>::new();
        for assertion in commit
            .assertions
            .iter()
            .filter(|assertion| assertion.relation == "affects")
        {
            for entity_id in [
                assertion.from_entity_id.as_str(),
                assertion.to_entity_id.as_str(),
            ] {
                if let Some(existing) = lifecycle_runtime_by_entity
                    .insert(entity_id, assertion.source_runtime_id.as_str())
                    && existing != assertion.source_runtime_id
                {
                    return Err(StoreError::Conflict(format!(
                        "lifecycle entity {entity_id} has ambiguous source runtime provenance"
                    )));
                }
            }
        }
        if !commit.entities.is_empty() {
            let tenant_id = TenantId::parse(commit.tenant_id.clone())
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            for batch in commit.entities.chunks(PROJECTION_BATCH_SIZE) {
                let entity_rows = batch
                    .iter()
                    .map(|entity| {
                        let mut entity = entity.clone();
                        if entity.lifecycle_source_runtime_id.is_none() {
                            entity.lifecycle_source_runtime_id = lifecycle_runtime_by_entity
                                .get(entity.entity_id.as_str())
                                .map(|runtime_id| (*runtime_id).to_owned());
                        }
                        refreshed_entity_row(&tenant_id, &entity)
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                transaction
                    .run(
                        query(ENTITY_QUERY)
                            .param("tenant_id", commit.tenant_id.clone())
                            .param("graph_revision", graph_revision)
                            .param("rows", rows(entity_rows)),
                    )
                    .await?;
            }
        }
        if !commit.assertions.is_empty() {
            for batch in commit.assertions.chunks(PROJECTION_BATCH_SIZE) {
                transaction
                    .run(
                        query(ASSERTION_QUERY)
                            .param("tenant_id", commit.tenant_id.clone())
                            .param("graph_revision", graph_revision)
                            .param("rows", rows(batch.iter().map(assertion_row))),
                    )
                    .await?;
            }
        }
        if !commit.retractions.is_empty() {
            for batch in commit.retractions.chunks(PROJECTION_BATCH_SIZE) {
                transaction
                    .run(
                        query(RETRACTION_QUERY)
                            .param("tenant_id", commit.tenant_id.clone())
                            .param("rows", rows(batch.iter().map(retraction_row))),
                    )
                    .await?;
            }
        }
        transaction
            .run(
                query(REVISION_QUERY)
                    .param("tenant_id", commit.tenant_id.clone())
                    .param("graph_revision", graph_revision)
                    .param("delta_digest", commit.delta_digest.clone()),
            )
            .await?;
        transaction
            .run(
                query(ADVANCE_LIFECYCLE_PROJECTION_QUERY)
                    .param("tenant_id", commit.tenant_id.clone())
                    .param("graph_revision", graph_revision),
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
                    "Neo4j readiness query exceeded 10 seconds".to_owned(),
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

fn row_u64(row: &Row, field: &str) -> Result<u64, StoreError> {
    let value: i64 = row
        .get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    u64::try_from(value)
        .map_err(|_| StoreError::Conflict(format!("{field} is negative or exceeds u64")))
}

fn optional_timestamp(row: &Row, field: &str) -> Result<Option<String>, StoreError> {
    let value: i64 = row
        .get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    (value >= 0)
        .then(|| cerebro_security_lifecycle::rfc3339_from_timestamp_millis(value))
        .transpose()
        .map_err(|error| StoreError::Conflict(format!("invalid {field}: {error}")))
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
    let lifecycle = entity.lifecycle.as_ref();
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
        ("lifecycle_subject", lifecycle.is_some().into()),
        (
            "lifecycle_subject_urn",
            lifecycle
                .map(|value| value.subject_urn.clone())
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_subject_kind",
            lifecycle
                .map(|value| value.subject_kind.clone())
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_observed_state",
            lifecycle
                .map(|value| value.observed_state.clone())
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_owner_urn",
            lifecycle
                .and_then(|value| value.owner_urn.clone())
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_observed_at_unix_ms",
            lifecycle
                .map(|value| value.observed_at_unix_ms)
                .unwrap_or(-1)
                .into(),
        ),
        (
            "lifecycle_expires_at_unix_ms",
            lifecycle
                .and_then(|value| value.expires_at_unix_ms)
                .unwrap_or(-1)
                .into(),
        ),
        (
            "lifecycle_finding",
            entity.lifecycle_finding_urn.is_some().into(),
        ),
        (
            "lifecycle_finding_urn",
            entity
                .lifecycle_finding_urn
                .clone()
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_projected",
            (entity.lifecycle.is_some() || entity.lifecycle_finding_urn.is_some()).into(),
        ),
        (
            "lifecycle_source_runtime_id",
            entity
                .lifecycle_source_runtime_id
                .clone()
                .unwrap_or_default()
                .into(),
        ),
        (
            "lifecycle_source_collection_id",
            entity
                .lifecycle_source_collection_id
                .clone()
                .unwrap_or_default()
                .into(),
        ),
    ])
}

fn refreshed_entity_row(
    tenant_id: &TenantId,
    entity: &ProjectionEntity,
) -> Result<BoltMap, StoreError> {
    let properties = serde_json::from_str(&entity.properties_json)?;
    let mut refreshed = entity.clone();
    let agent_key = refreshed
        .external_id
        .as_deref()
        .unwrap_or(refreshed.entity_id.as_str());
    refreshed.lifecycle =
        lifecycle_projection(tenant_id, agent_key, &refreshed.label, &properties)?;
    refreshed.lifecycle_finding_urn =
        lifecycle_finding_projection(tenant_id, &refreshed.entity_kind, &properties)?;
    if refreshed.lifecycle.is_some() || refreshed.lifecycle_finding_urn.is_some() {
        refreshed.lifecycle_source_runtime_id = refreshed
            .lifecycle_source_runtime_id
            .or_else(|| properties.get("source_runtime_id").cloned());
        refreshed.lifecycle_source_collection_id = properties.get("source_collection_id").cloned();
    } else {
        refreshed.lifecycle_source_runtime_id = None;
        refreshed.lifecycle_source_collection_id = None;
    }
    Ok(entity_row(&refreshed))
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
    use std::{env, error::Error};

    use cerebro_agent_context::{FactQuery, QueryAbsentEdge, QueryDirection, QueryEdge, QueryNode};

    use super::*;

    #[test]
    fn readiness_allows_one_bounded_connection_warmup() {
        assert_eq!(HEALTH_TIMEOUT, Duration::from_secs(10));
    }

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
        assert!(
            REBUILD_LIFECYCLE_ENTITY_QUERY
                .contains("WHERE revision.graph_revision = $graph_revision")
        );
        assert!(
            REBUILD_LIFECYCLE_ENTITY_QUERY
                .contains("coalesce(entity.graph_revision, 0) = row.source_graph_revision")
        );
        assert!(REBUILD_LIFECYCLE_ENTITY_QUERY.contains("RETURN count(entity) AS rebuilt"));
        assert!(!REBUILD_LIFECYCLE_ENTITY_QUERY.contains("entity.properties_json ="));
        assert!(!REBUILD_LIFECYCLE_ENTITY_QUERY.contains("entity.label ="));
        assert!(!REBUILD_LIFECYCLE_ENTITY_QUERY.contains("entity.authority_json ="));
        assert!(ASSERTION_QUERY.contains("ORGANIZATIONAL_RELATION"));
        assert!(
            NEO4J_SCHEMA
                .iter()
                .any(|statement| statement.contains("IS UNIQUE"))
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable Neo4j instance"]
    async fn lifecycle_rebuild_batch_rejects_revision_drift_without_base_overwrite()
    -> Result<(), Box<dyn Error>> {
        let graph = Graph::new(
            env::var("CEREBRO_TEST_NEO4J_URI")?,
            env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
            env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
        )
        .await?;
        let tenant_id = format!("tenant-lifecycle-rebuild-race-{}", std::process::id());
        graph
            .run(
                query(
                    "CREATE (:OrganizationalGraphRevision {tenant_id: $tenant_id, graph_revision: 1}) CREATE (:OrganizationalEntity {tenant_id: $tenant_id, entity_id: 'resource-1', entity_kind: 'resource', authority_json: '{\"current\":false}', label: 'Old label', properties_json: '{\"current\":false}', external_id: 'resource-1', graph_revision: 1})",
                )
                .param("tenant_id", tenant_id.clone()),
            )
            .await?;
        graph
            .run(
                query(
                    "MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) SET revision.graph_revision = 2 WITH revision MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id, entity_id: 'resource-1'}) SET entity.graph_revision = 2, entity.authority_json = '{\"current\":true}', entity.label = 'Current label', entity.properties_json = '{\"current\":true}'",
                )
                .param("tenant_id", tenant_id.clone()),
            )
            .await?;

        let rebuild_row = || {
            map([
                ("entity_id", "resource-1".into()),
                ("source_graph_revision", 1_i64.into()),
                ("lifecycle_subject", false.into()),
                ("lifecycle_subject_urn", "".into()),
                ("lifecycle_subject_kind", "".into()),
                ("lifecycle_observed_state", "".into()),
                ("lifecycle_owner_urn", "".into()),
                ("lifecycle_observed_at_unix_ms", (-1_i64).into()),
                ("lifecycle_expires_at_unix_ms", (-1_i64).into()),
                ("lifecycle_projected", false.into()),
                ("lifecycle_source_runtime_id", "".into()),
                ("lifecycle_source_collection_id", "".into()),
                ("lifecycle_finding", false.into()),
                ("lifecycle_finding_urn", "".into()),
            ])
        };
        let mut transaction = graph.start_txn().await?;
        let mut result = transaction
            .execute(
                query(REBUILD_LIFECYCLE_ENTITY_QUERY)
                    .param("tenant_id", tenant_id.clone())
                    .param("graph_revision", 1_i64)
                    .param("rows", rows(vec![rebuild_row()])),
            )
            .await?;
        let rebuilt = result
            .next(transaction.handle())
            .await?
            .expect("aggregate row")
            .get::<i64>("rebuilt")?;
        assert_eq!(
            rebuilt, 0,
            "a changed tenant revision must prevent the batch from matching"
        );
        drop(result);
        transaction.rollback().await?;

        graph
            .run(
                query(
                    "MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) SET revision.graph_revision = 1",
                )
                .param("tenant_id", tenant_id.clone()),
            )
            .await?;
        let mut transaction = graph.start_txn().await?;
        let mut result = transaction
            .execute(
                query(REBUILD_LIFECYCLE_ENTITY_QUERY)
                    .param("tenant_id", tenant_id.clone())
                    .param("graph_revision", 1_i64)
                    .param("rows", rows(vec![rebuild_row()])),
            )
            .await?;
        let rebuilt = result
            .next(transaction.handle())
            .await?
            .expect("aggregate row")
            .get::<i64>("rebuilt")?;
        assert_eq!(rebuilt, 0, "a changed entity revision must reject the row");
        drop(result);
        transaction.rollback().await?;

        let mut result = graph
            .execute(
                query(
                    "MATCH (entity:OrganizationalEntity {tenant_id: $tenant_id, entity_id: 'resource-1'}) RETURN entity.graph_revision AS graph_revision, entity.authority_json AS authority_json, entity.label AS label, entity.properties_json AS properties_json, entity:SecurityLifecycleSubject AS lifecycle_subject",
                )
                .param("tenant_id", tenant_id.clone()),
            )
            .await?;
        let entity = result.next().await?.expect("current entity");
        assert_eq!(entity.get::<i64>("graph_revision")?, 2);
        assert_eq!(
            entity.get::<String>("authority_json")?,
            "{\"current\":true}"
        );
        assert_eq!(entity.get::<String>("label")?, "Current label");
        assert_eq!(
            entity.get::<String>("properties_json")?,
            "{\"current\":true}"
        );
        assert!(!entity.get::<bool>("lifecycle_subject")?);
        graph
            .run(
                query("MATCH (node {tenant_id: $tenant_id}) DETACH DELETE node")
                    .param("tenant_id", tenant_id),
            )
            .await?;
        Ok(())
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
