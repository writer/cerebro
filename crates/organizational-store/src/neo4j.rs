#![deny(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use async_trait::async_trait;
use cerebro_agent_context::{
    AgentGraph, ContextEdge, ContextEntity, ContextError, FactQuery, GraphPath, Neighborhood,
    QueryDirection, QueryMatch, QueryResult, validate_bounds, validate_root_keys,
};
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    AssertionId, EntityId, EntityKind, GraphDelta, RelationKind, TenantId,
};
use cerebro_security_lifecycle::{
    IndexedLifecyclePage, KeysetDirection, LifecycleAggregates, LifecycleState, PolicyState,
    PolicyStateCount, PreparedLifecycleQuery, ProjectedResource, StateCount, SubjectKind,
    SubjectKindCount,
};
use neo4rs::{BoltList, BoltMap, BoltType, Graph, Query, Row, Txn, query};
use sha2::{Digest, Sha256};

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
    assertion.application_workspace_id = row.application_workspace_id,
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

const EXPOSURE_PRIMARY_FILTER: &str = r#"
endpoint.entity_type STARTS WITH $primary_kind_prefix
  AND indicator.entity_type IN $indicator_kinds
  AND ($account_id = '' OR coalesce(endpoint.attributes_json, '') CONTAINS ('"domain":"' + $account_id + '"'))
  AND ($region = '' OR endpoint.urn CONTAINS (':' + $region + ':') OR coalesce(endpoint.attributes_json, '') CONTAINS ('"' + $region + '"'))
  AND ($search = '' OR toLower(coalesce(endpoint.urn, '') + ' ' + coalesce(endpoint.label, '') + ' ' + coalesce(indicator.urn, '') + ' ' + coalesce(indicator.label, '')) CONTAINS $search)
"#;

const EXPOSURE_ACCOUNT_FILTER: &str = r#"
endpoint.entity_type STARTS WITH $primary_kind_prefix
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id OR coalesce(endpoint.attributes_json, '') CONTAINS ('"domain":"' + $account_id + '"'))
  AND ($region = '' OR endpoint.urn CONTAINS (':' + $region + ':') OR coalesce(endpoint.attributes_json, '') CONTAINS ('"' + $region + '"'))
  AND ($search = '' OR toLower(coalesce(endpoint.urn, '') + ' ' + coalesce(endpoint.label, '') + ' ' + coalesce(account.urn, '') + ' ' + coalesce(account.label, '')) CONTAINS $search)
"#;

const COMPLIANCE_IMPACT_FACT_STATEMENT: &str = r#"
MATCH (fact:Entity {
  tenant_id: $tenant_id,
  urn: $agent_key,
  entity_type: $entity_kind
})
RETURN fact.urn AS entity_key,
       coalesce(fact.attributes_json, '{}') AS entity_properties
LIMIT 2
"#;

const COMPLIANCE_IMPACT_REVISION_URN_KIND: &str = "compliance_impact_revision";

const COMPLIANCE_IMPACT_DEPENDENCY_COUNT_STATEMENT: &str = r#"
MATCH (fact:Entity {
  tenant_id: $tenant_id,
  urn: $agent_key,
  entity_type: $entity_kind
})
OPTIONAL MATCH (fact)-[edge:RELATION {
  tenant_id: $tenant_id,
  relation: $relation
}]->(dependency:Entity {
  tenant_id: $tenant_id,
  entity_type: $entity_kind
})
RETURN count(edge) AS dependency_count
"#;

const COMPLIANCE_IMPACT_DEPENDENCIES_STATEMENT: &str = r#"
MATCH (fact:Entity {
  tenant_id: $tenant_id,
  urn: $agent_key,
  entity_type: $entity_kind
})-[edge:RELATION {
  tenant_id: $tenant_id,
  relation: $relation
}]->(dependency:Entity {
  tenant_id: $tenant_id,
  entity_type: $entity_kind
})
RETURN dependency.urn AS entity_key,
       coalesce(dependency.attributes_json, '{}') AS entity_properties,
       coalesce(edge.attributes_json, '{}') AS edge_properties
ORDER BY dependency.urn, edge.attributes_json
LIMIT $row_limit
"#;

const COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT: &str = r#"
MATCH (dependent:Entity {
  tenant_id: $tenant_id,
  entity_type: $entity_kind
})-[edge:RELATION {
  tenant_id: $tenant_id,
  relation: $relation
}]->(dependency:Entity {
  tenant_id: $tenant_id,
  urn: $dependency_key,
  entity_type: $entity_kind
})
WHERE dependent.urn > $after_key
RETURN DISTINCT dependent.urn AS entity_key,
       coalesce(dependent.attributes_json, '{}') AS entity_properties
ORDER BY entity_key
LIMIT $row_limit
"#;

fn exposure_counts_statement() -> String {
    format!(
        "OPTIONAL MATCH (revision:OrganizationalGraphRevision {{tenant_id: $tenant_id}}) WITH coalesce(revision.graph_revision, 0) AS graph_revision CALL {{ MATCH (endpoint:Entity {{tenant_id: $tenant_id, source_id: $primary_source_id}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator:Entity {{tenant_id: $tenant_id}}) WHERE {EXPOSURE_PRIMARY_FILTER} OPTIONAL MATCH (asset:Entity {{tenant_id: $tenant_id, source_id: $corroborating_source_id, entity_type: $corroborating_kind}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator) RETURN count(DISTINCT endpoint) AS primary_count, count(DISTINCT indicator) AS indicator_count, count(DISTINCT CASE WHEN indicator.entity_type = 'internet.host' THEN indicator END) AS host_count, count(DISTINCT CASE WHEN indicator.entity_type = 'internet.ip' THEN indicator END) AS ip_count, count(DISTINCT CASE WHEN asset IS NOT NULL THEN endpoint END) AS overlapping_primary_count, count(DISTINCT CASE WHEN asset IS NOT NULL THEN indicator END) AS overlapping_indicator_count, count(DISTINCT asset) AS overlapping_corroborating_count }} RETURN graph_revision, primary_count, indicator_count, host_count, ip_count, overlapping_primary_count, overlapping_indicator_count, overlapping_corroborating_count"
    )
}

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

// A fresh ECS task can encounter transient failures while establishing its
// first routed Bolt connection. neo4rs retries those failures for up to 60
// seconds, so keep the outer bound above that horizon while still failing
// closed on a stalled backend.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(75);
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
       coalesce(edge.application_workspace_id, '') AS application_workspace_id,
       coalesce(revision.graph_revision, 0) AS graph_revision
ORDER BY root_key, assertion_id
"#;

fn expand_statement(depth: usize) -> String {
    format!(
        "MATCH path=(root:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $root_id}})-[:ORGANIZATIONAL_RELATION*1..{depth}]-(node:OrganizationalEntity) WITH relationships(path) AS relations UNWIND relations AS edge WITH DISTINCT edge MATCH (source)-[edge]->(target) WHERE source.tenant_id = $tenant_id AND target.tenant_id = $tenant_id RETURN source.entity_id AS from_id, source.entity_kind AS from_kind, source.authority_json AS from_authority, source.label AS from_label, source.properties_json AS from_properties, target.entity_id AS to_id, target.entity_kind AS to_kind, target.authority_json AS to_authority, target.label AS to_label, target.properties_json AS to_properties, edge.assertion_id AS assertion_id, edge.relation AS relation, edge.source_runtime_id AS source_runtime_id, coalesce(edge.application_workspace_id, '') AS application_workspace_id ORDER BY assertion_id LIMIT $row_limit"
    )
}

fn paths_statement(max_depth: usize) -> String {
    format!(
        "MATCH path=(source:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $from_id}})-[:ORGANIZATIONAL_RELATION*1..{max_depth}]->(target:OrganizationalEntity {{tenant_id: $tenant_id, entity_id: $to_id}}) WHERE all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(node IN nodes(path) WHERE single(other IN nodes(path) WHERE other = node)) RETURN [node IN nodes(path) | node.entity_id] AS entity_ids, [node IN nodes(path) | node.entity_kind] AS entity_kinds, [node IN nodes(path) | node.authority_json] AS authorities, [node IN nodes(path) | node.label] AS labels, [node IN nodes(path) | node.properties_json] AS properties, [edge IN relationships(path) | edge.assertion_id] AS assertion_ids, [edge IN relationships(path) | edge.relation] AS relations, [edge IN relationships(path) | edge.source_runtime_id] AS runtime_ids, [edge IN relationships(path) | coalesce(edge.application_workspace_id, '')] AS application_workspace_ids ORDER BY length(path), assertion_ids LIMIT $limit"
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
            format!("coalesce(edge_{index}.application_workspace_id, '') AS edge_{index}_application_workspace_id"),
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

const LEGACY_ROOT_COVERAGE_STATEMENT: &str = r#"
MATCH (legacy:Entity)
WHERE legacy.tenant_id = $tenant_id OR legacy.urn STARTS WITH $urn_prefix
WITH legacy, coalesce(legacy.entity_type, 'unknown') AS entity_type
OPTIONAL MATCH (current:OrganizationalEntity {tenant_id: $tenant_id})
WHERE current.entity_id = legacy.urn OR current.external_id = legacy.urn
WITH entity_type, legacy, count(current) > 0 AS covered
RETURN entity_type,
       count(legacy) AS legacy_roots,
       sum(CASE WHEN covered THEN 1 ELSE 0 END) AS covered_roots
ORDER BY entity_type
"#;

const LEGACY_ROOTS_STATEMENT: &str = r#"
UNWIND $root_urns AS root_urn
MATCH (root:Entity {tenant_id: $tenant_id, urn: root_urn})
WITH root_urn, collect(root) AS roots
RETURN root_urn, size(roots) AS match_count,
       coalesce(roots[0].entity_type, 'unknown') AS root_kind,
       coalesce(roots[0].label, root_urn) AS root_label,
       coalesce(roots[0].attributes_json, '{}') AS root_properties,
       coalesce(roots[0].source_id, '') AS root_source_id,
       coalesce(roots[0].runtime_id, '') AS root_runtime_id
ORDER BY root_urn
"#;

const LEGACY_OUTGOING_STATEMENT: &str = r#"
UNWIND $root_urns AS root_urn
MATCH (root:Entity {tenant_id: $tenant_id, urn: root_urn})
CALL {
  WITH root
  MATCH (root)-[relation:RELATION]->(neighbor:Entity {tenant_id: $tenant_id})
  WHERE coalesce(relation.tenant_id, '') IN ['', $tenant_id]
  WITH root, neighbor, relation.relation AS relation_kind,
       collect(DISTINCT coalesce(relation.tenant_id, '')) AS relation_tenant_ids,
       collect(DISTINCT coalesce(relation.runtime_id, '')) AS typed_runtime_ids,
       collect(DISTINCT coalesce(relation.application_workspace_id, '')) AS typed_application_workspace_ids,
       collect(DISTINCT coalesce(relation.attributes_json, '{}')) AS relation_properties_values
  RETURN neighbor.urn AS neighbor_urn,
         coalesce(neighbor.entity_type, 'unknown') AS neighbor_kind,
         coalesce(neighbor.label, neighbor.urn) AS neighbor_label,
         coalesce(neighbor.attributes_json, '{}') AS neighbor_properties,
         coalesce(neighbor.source_id, '') AS neighbor_source_id,
         coalesce(neighbor.runtime_id, '') AS neighbor_runtime_id,
         root.urn AS from_urn,
         relation_kind,
         neighbor.urn AS to_urn,
         relation_tenant_ids,
         typed_runtime_ids,
         typed_application_workspace_ids,
         relation_properties_values
  ORDER BY neighbor.urn, relation_kind, neighbor.entity_type, neighbor.label
  LIMIT $row_limit
}
RETURN root_urn, neighbor_urn, neighbor_kind, neighbor_label, neighbor_properties,
       neighbor_source_id, neighbor_runtime_id,
       from_urn, relation_kind, to_urn, relation_tenant_ids, typed_runtime_ids, typed_application_workspace_ids, relation_properties_values
ORDER BY root_urn, neighbor_urn, relation_kind
"#;

const LEGACY_INCOMING_STATEMENT: &str = r#"
UNWIND $root_urns AS root_urn
MATCH (root:Entity {tenant_id: $tenant_id, urn: root_urn})
CALL {
  WITH root
  MATCH (neighbor:Entity {tenant_id: $tenant_id})-[relation:RELATION]->(root)
  WHERE coalesce(relation.tenant_id, '') IN ['', $tenant_id]
  WITH root, neighbor, relation.relation AS relation_kind,
       collect(DISTINCT coalesce(relation.tenant_id, '')) AS relation_tenant_ids,
       collect(DISTINCT coalesce(relation.runtime_id, '')) AS typed_runtime_ids,
       collect(DISTINCT coalesce(relation.application_workspace_id, '')) AS typed_application_workspace_ids,
       collect(DISTINCT coalesce(relation.attributes_json, '{}')) AS relation_properties_values
  RETURN neighbor.urn AS neighbor_urn,
         coalesce(neighbor.entity_type, 'unknown') AS neighbor_kind,
         coalesce(neighbor.label, neighbor.urn) AS neighbor_label,
         coalesce(neighbor.attributes_json, '{}') AS neighbor_properties,
         coalesce(neighbor.source_id, '') AS neighbor_source_id,
         coalesce(neighbor.runtime_id, '') AS neighbor_runtime_id,
         neighbor.urn AS from_urn,
         relation_kind,
         root.urn AS to_urn,
         relation_tenant_ids,
         typed_runtime_ids,
         typed_application_workspace_ids,
         relation_properties_values
  ORDER BY neighbor.urn, relation_kind, neighbor.entity_type, neighbor.label
  LIMIT $row_limit
}
RETURN root_urn, neighbor_urn, neighbor_kind, neighbor_label, neighbor_properties,
       neighbor_source_id, neighbor_runtime_id,
       from_urn, relation_kind, to_urn, relation_tenant_ids, typed_runtime_ids, typed_application_workspace_ids, relation_properties_values
ORDER BY root_urn, neighbor_urn, relation_kind
"#;

const LEGACY_NEIGHBOR_SCOPE_STATEMENT: &str = r#"
UNWIND $root_urns AS root_urn
MATCH (root:Entity {tenant_id: $tenant_id, urn: root_urn})-[relation:RELATION]-(neighbor:Entity)
WHERE (coalesce(relation.tenant_id, '') <> '' AND relation.tenant_id <> $tenant_id)
   OR coalesce(neighbor.tenant_id, '') <> $tenant_id
RETURN count(*) AS violations
"#;

const NEO4J_SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT organizational_entity_identity IF NOT EXISTS FOR (entity:OrganizationalEntity) REQUIRE (entity.tenant_id, entity.entity_id) IS UNIQUE",
    "CREATE CONSTRAINT organizational_revision_tenant IF NOT EXISTS FOR (revision:OrganizationalGraphRevision) REQUIRE revision.tenant_id IS UNIQUE",
    "CREATE INDEX organizational_entity_external_id IF NOT EXISTS FOR (entity:OrganizationalEntity) ON (entity.tenant_id, entity.external_id)",
    "CREATE INDEX cerebro_entity_tenant_application_workspace_type IF NOT EXISTS FOR (entity:Entity) ON (entity.tenant_id, entity.application_workspace_id, entity.entity_type)",
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
/// Rebuildable Neo4j projection and tenant-consistent graph reader.
///
/// This type never owns graph truth. Writes must already have a durable ledger
/// receipt, and lifecycle reads fail closed unless the projection is ready at
/// the current authoritative graph revision.
pub struct Neo4jProjector {
    graph: Graph,
}

/// Latest secret-free graph ingest evidence for one source runtime.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SourceRuntimeGraphObservation {
    /// Runtime whose graph ingest was observed.
    pub runtime_id: String,
    /// Running, completed, or failed graph ingest status.
    pub status: String,
    /// Continuation retained by the graph run, when present.
    pub checkpoint_cursor: String,
    /// Explicit terminal checkpoint state; `None` for legacy records.
    pub checkpoint_complete: Option<bool>,
    /// Graph run start time in RFC 3339 form, when observed.
    pub started_at: String,
    /// Graph run finish time in RFC 3339 form, when observed.
    pub finished_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A lifecycle finding resolved to its affected resource and source coordinates.
pub struct ResolvedLifecycleFinding {
    /// Affected lifecycle resource reconstructed from the projection.
    pub resource: ProjectedResource,
    /// Graph revision at which the finding and resource were resolved.
    pub graph_revision: u64,
    /// Runtime that supplied the finding relationship and lifecycle entity.
    pub source_runtime_id: String,
    /// Source collection that supplied the projected lifecycle records.
    pub source_collection_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
/// Aggregate coverage for one legacy graph entity type.
pub struct LegacyRootCoverageKind {
    /// Legacy entity type, or `unknown` when the legacy node omitted it.
    pub entity_type: String,
    /// Distinct legacy roots observed for this type.
    pub legacy_roots: u64,
    /// Legacy roots addressable through the Rust organizational projection.
    pub covered_roots: u64,
    /// Legacy roots that the Rust organizational projection cannot resolve.
    pub missing_roots: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
/// Tenant-scoped aggregate coverage of legacy graph roots by the Rust projection.
pub struct LegacyRootCoverage {
    /// Tenant whose legacy and Rust projection roots were compared.
    pub tenant_id: String,
    /// Total distinct legacy roots observed for the tenant.
    pub legacy_roots: u64,
    /// Total legacy roots addressable through the Rust organizational projection.
    pub covered_roots: u64,
    /// Total legacy roots that the Rust organizational projection cannot resolve.
    pub missing_roots: u64,
    /// Coverage grouped by the legacy entity type without exposing entity identifiers.
    pub entity_types: Vec<LegacyRootCoverageKind>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// Closed filters shared by typed legacy entity-catalog reads.
pub struct EntityCatalogFilter {
    /// Optional Cerebro application workspace identifier. This is distinct
    /// from provider-owned workspace identifiers.
    pub application_workspace_id: String,
    /// Optional source identifier.
    pub source_id: String,
    /// Optional closed runtime identifiers.
    pub runtime_ids: Vec<String>,
    /// Optional exact tenant-scoped agent key.
    pub exact_agent_key: String,
    /// Exact admitted entity kinds.
    pub include_kinds: Vec<String>,
    /// Admitted entity-kind prefixes.
    pub include_kind_prefixes: Vec<String>,
    /// Exact excluded entity kinds.
    pub exclude_kinds: Vec<String>,
    /// Excluded entity-kind prefixes.
    pub exclude_kind_prefixes: Vec<String>,
    /// Optional case-insensitive catalog search.
    pub search: String,
    /// Whether catalog search may inspect stored attributes.
    pub search_attributes: bool,
    /// Case-insensitive OR predicates applied only to stored attribute JSON.
    pub attribute_substrings_any: Vec<String>,
    /// Optional closed relation-count projection for each returned entity.
    pub relation_counts: Option<EntityCatalogRelationCountFilter>,
    /// Required revision for continuation pages, or zero for the first page.
    pub expected_graph_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded entity-catalog page.
pub struct EntityCatalogPage {
    /// Tenant whose catalog was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Stable catalog entities ordered by agent key.
    pub entities: Vec<ContextEntity>,
    /// Whether another page exists.
    pub truncated: bool,
    /// Stable key after which the next page begins.
    pub next_after_agent_key: String,
    /// Complete grouped relation counts for the returned page.
    pub relation_counts: Vec<EntityCatalogRelationCount>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One exact compliance revision and its direct dependency relations.
pub struct ComplianceImpactFact {
    /// Tenant whose fact was read.
    pub tenant_id: String,
    /// Graph revision shared by the fact and dependencies.
    pub graph_revision: u64,
    /// Exact immutable fact revision.
    pub fact: ContextEntity,
    /// Scalar dependency count read before the dependency list.
    pub dependency_count: u32,
    /// Ordered dependency revisions.
    pub dependencies: Vec<ComplianceImpactDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One exact compliance dependency plus its domain relation property.
pub struct ComplianceImpactDependency {
    /// Exact dependency revision.
    pub entity: ContextEntity,
    /// Domain-level dependency relation stored on the fixed graph edge.
    pub relation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One keyset-paged reverse compliance-dependency result.
pub struct ComplianceImpactPage {
    /// Tenant whose graph was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Exact dependent revisions in key order.
    pub dependents: Vec<ContextEntity>,
    /// Whether another dependent exists.
    pub truncated: bool,
    /// Key after which the next page begins.
    pub next_after_agent_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed grouped relation-count selector.
pub struct EntityCatalogRelationCountFilter {
    /// Directions relative to each returned entity.
    pub directions: Vec<EntityCatalogDirection>,
    /// Stored relation kinds.
    pub relations: Vec<String>,
    /// Neighbor entity kinds.
    pub neighbor_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One complete grouped relation count for a catalog entity.
pub struct EntityCatalogRelationCount {
    /// Stable catalog entity key.
    pub agent_key: String,
    /// Direction relative to the catalog entity.
    pub direction: EntityCatalogDirection,
    /// Stored relation kind.
    pub relation: String,
    /// Neighbor entity kind.
    pub neighbor_kind: String,
    /// Distinct matching neighbors.
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Aggregate count for one catalog entity kind.
pub struct EntityCatalogKindCount {
    /// Entity kind.
    pub entity_kind: String,
    /// Tenant-scoped entity count.
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded entity-kind count page.
pub struct EntityCatalogKindPage {
    /// Tenant whose catalog was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Counts ordered by entity kind.
    pub counts: Vec<EntityCatalogKindCount>,
    /// Whether another page exists.
    pub truncated: bool,
    /// Entity kind after which the next page begins.
    pub next_after_entity_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Aggregate count for one legacy relation kind.
pub struct EntityCatalogRelationKindCount {
    /// Stored relation kind.
    pub relation: String,
    /// Tenant-scoped relation count.
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded relation-count page.
pub struct EntityCatalogRelationKindPage {
    /// Tenant whose catalog was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Counts ordered by relation kind.
    pub counts: Vec<EntityCatalogRelationKindCount>,
    /// Whether another page exists.
    pub truncated: bool,
    /// Relation kind after which the next page begins.
    pub next_after_relation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One person-to-access-target path from the legacy projection.
pub struct PersonAccessPath {
    /// Human subject whose access was resolved.
    pub person: ContextEntity,
    /// Identity bound to the person.
    pub identity: ContextEntity,
    /// Principal that represents the identity.
    pub principal: ContextEntity,
    /// Reached access target.
    pub access_target: ContextEntity,
    /// Ordered relationship kinds from principal to target.
    pub relation_chain: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded page of person access paths.
pub struct PersonAccessPathPage {
    /// Tenant whose graph was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Bounded paths ordered by person, principal, and target label.
    pub paths: Vec<PersonAccessPath>,
    /// Whether another path exists beyond the requested limit.
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One source-backed edge in an effective-access proof.
pub struct EffectiveAccessPathEdge {
    /// Source entity.
    pub from: ContextEntity,
    /// Closed relation kind.
    pub relation: String,
    /// Target entity.
    pub to: ContextEntity,
    /// Source connector identifier.
    pub source_id: String,
    /// Source runtime identifier.
    pub runtime_id: String,
    /// Bounded source attributes preserved for lineage qualification.
    pub attributes_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded identity-to-capability effective-access proof.
pub struct EffectiveAccessPath {
    /// Caller-selected identity.
    pub identity: ContextEntity,
    /// Provider principal granting the access.
    pub principal: ContextEntity,
    /// Optional group mediating the assignment.
    pub mediator: Option<ContextEntity>,
    /// Application or role receiving the assignment.
    pub access_target: ContextEntity,
    /// Entitlement granted by the target.
    pub entitlement: ContextEntity,
    /// Capability conferred by the entitlement.
    pub capability: ContextEntity,
    /// Closed assignment variant.
    pub assignment_kind: String,
    /// Ordered identity-to-principal relation kinds.
    pub identity_relation_chain: Vec<String>,
    /// Ordered identity-to-principal edges.
    pub identity_edges: Vec<EffectiveAccessPathEdge>,
    /// Ordered principal-to-capability relation kinds.
    pub relation_chain: Vec<String>,
    /// Ordered principal-to-capability edges.
    pub edges: Vec<EffectiveAccessPathEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One revision-bound page of effective-access proofs.
pub struct EffectiveAccessPathPage {
    /// Authorized tenant.
    pub tenant_id: String,
    /// Durable graph revision read by the query.
    pub graph_revision: u64,
    /// Bounded effective-access proofs.
    pub paths: Vec<EffectiveAccessPath>,
    /// True when more paths matched than the requested bound.
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One node in a cloud attack path.
pub struct CloudAttackPathNode {
    /// Stable tenant-scoped entity URN.
    pub urn: String,
    /// Legacy entity type.
    pub entity_kind: String,
    /// Human-readable label.
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One source-backed edge in a cloud attack path.
pub struct CloudAttackPathEdge {
    /// Edge source.
    pub from: CloudAttackPathNode,
    /// Legacy relation kind.
    pub relation: String,
    /// Edge target.
    pub to: CloudAttackPathNode,
    /// Direction relative to the emitted proof path.
    pub direction: String,
    /// Source identifier.
    pub source_id: String,
    /// Source runtime identifier.
    pub source_runtime_id: String,
    /// Runtime IDs whose assertions contributed to this material edge.
    pub assertion_runtime_ids: Vec<String>,
    /// Raw edge attributes retained for the Go compatibility view.
    pub attributes_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One ownership assignment on an exposed resource.
pub struct CloudAttackPathOwnership {
    /// Observed owner.
    pub owner: CloudAttackPathNode,
    /// Edge that established ownership.
    pub edge: CloudAttackPathEdge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One public-exposure-to-privilege path.
pub struct CloudAttackPath {
    /// Public principal that can reach the resource.
    pub public_principal: CloudAttackPathNode,
    /// Publicly exposed cloud resource.
    pub exposed_resource: CloudAttackPathNode,
    /// Cloud account containing the resource and permission.
    pub cloud_account: CloudAttackPathNode,
    /// Principal reached from the exposed resource.
    pub principal: CloudAttackPathNode,
    /// Privileged permission granted to the principal.
    pub permission: CloudAttackPathNode,
    /// Explicit ownership observations.
    pub ownerships: Vec<CloudAttackPathOwnership>,
    /// Boundary reach relation.
    pub reach_relation: String,
    /// Privilege relation.
    pub access_relation: String,
    /// Traversal relation chain.
    pub relation_chain: Vec<String>,
    /// Public reachability proof edge.
    pub exposure_edge: CloudAttackPathEdge,
    /// Resource-to-account proof edge.
    pub resource_account_edge: CloudAttackPathEdge,
    /// Traversal proof edges.
    pub traversal_edges: Vec<CloudAttackPathEdge>,
    /// Principal-to-permission proof edge.
    pub privilege_edge: CloudAttackPathEdge,
    /// Permission-to-account proof edge.
    pub permission_account_edge: CloudAttackPathEdge,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// Aggregates for the current cloud attack path query.
pub struct CloudAttackPathCounts {
    /// Total material paths.
    pub paths: u64,
    /// Distinct exposed resources.
    pub exposed_resources: u64,
    /// Distinct privileged principals.
    pub privileged_principals: u64,
    /// Distinct cloud accounts.
    pub cloud_accounts: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Bounded cloud attack paths at one graph revision.
pub struct CloudAttackPathPage {
    /// Tenant whose graph was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Aggregate counts for the query.
    pub counts: CloudAttackPathCounts,
    /// Bounded sample paths.
    pub paths: Vec<CloudAttackPath>,
    /// Whether another sample path exists beyond the requested limit.
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Direction of a direct entity-catalog relation.
pub enum EntityCatalogDirection {
    /// Neighbor points to the requested entity.
    Incoming,
    /// Requested entity points to the neighbor.
    Outgoing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One direct entity-catalog relation and its neighbor.
pub struct EntityCatalogRelation {
    /// Direction relative to the requested entity.
    pub direction: EntityCatalogDirection,
    /// Stored relation kind.
    pub relation: String,
    /// Neighbor entity.
    pub entity: ContextEntity,
    /// Source that projected the relation.
    pub source_id: String,
    /// Canonical relation attributes from the legacy projection.
    pub attributes_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded direct-relation page.
pub struct EntityCatalogRelationPage {
    /// Tenant whose catalog was read.
    pub tenant_id: String,
    /// Graph revision shared by the page.
    pub graph_revision: u64,
    /// Relations ordered by neighbor agent key.
    pub relations: Vec<EntityCatalogRelation>,
    /// Whether another page exists.
    pub truncated: bool,
    /// Stable neighbor key after which the next page begins.
    pub next_after_agent_key: String,
    /// Relation kind paired with the continuation neighbor key.
    pub next_after_relation: String,
    /// Direction paired with the continuation neighbor key.
    pub next_after_direction: Option<EntityCatalogDirection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed source and entity-kind filters for one exposure coverage comparison.
pub struct ExposureCoverageProfile {
    /// Source that owns the primary endpoint observations.
    pub primary_source_id: String,
    /// Entity-kind prefix admitted for primary endpoints.
    pub primary_entity_kind_prefix: String,
    /// Independent source used to corroborate primary observations.
    pub corroborating_source_id: String,
    /// Entity kind emitted by the corroborating source.
    pub corroborating_entity_kind: String,
    /// Closed indicator kinds shared between both sources.
    pub indicator_kinds: Vec<String>,
    /// Entity kind used for account grouping.
    pub account_kind: String,
    /// Corroborating observation kind linked to accounts.
    pub corroborating_observation_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Bounded tenant-scoped exposure coverage query.
pub struct ExposureCoverageQuery {
    /// Closed comparison profile.
    pub profile: ExposureCoverageProfile,
    /// Optional account identifier filter.
    pub account_id: String,
    /// Optional region filter.
    pub region: String,
    /// Optional case-insensitive label or identity search.
    pub search: String,
    /// Maximum rows returned by each sample collection.
    pub limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Stable entity identity returned by an exposure coverage read.
pub struct ExposureCoverageEntity {
    /// Tenant-scoped stable graph key.
    pub agent_key: String,
    /// Entity kind.
    pub entity_kind: String,
    /// Human-readable label.
    pub label: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// Complete aggregate counts for one exposure comparison.
pub struct ExposureCoverageCounts {
    /// Primary endpoint observations.
    pub primary_entities: u64,
    /// Distinct shared indicators.
    pub indicators: u64,
    /// Host indicators.
    pub host_indicators: u64,
    /// IP indicators.
    pub ip_indicators: u64,
    /// Primary endpoints also observed by the corroborating source.
    pub overlapping_primary_entities: u64,
    /// Shared indicators observed by both sources.
    pub overlapping_indicators: u64,
    /// Corroborating entities that overlap primary observations.
    pub overlapping_corroborating_entities: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Count for one primary entity kind.
pub struct ExposureCoverageKindCount {
    /// Primary entity kind.
    pub entity_kind: String,
    /// Distinct primary entities of this kind.
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One primary observation corroborated by an independent source.
pub struct ExposureCoverageOverlap {
    /// Primary observation.
    pub primary: ExposureCoverageEntity,
    /// Shared indicator.
    pub indicator: ExposureCoverageEntity,
    /// Corroborating observation.
    pub corroborating: ExposureCoverageEntity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One primary observation without corroboration.
pub struct ExposureCoveragePair {
    /// Primary observation.
    pub primary: ExposureCoverageEntity,
    /// Shared indicator.
    pub indicator: ExposureCoverageEntity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One corroborating observation missing from the primary source.
pub struct ExposureCoverageCorroboratingOnly {
    /// Corroborating observation.
    pub corroborating: ExposureCoverageEntity,
    /// Shared indicator.
    pub indicator: ExposureCoverageEntity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Per-account exposure coverage counts.
pub struct ExposureCoverageAccount {
    /// Account entity.
    pub account: ExposureCoverageEntity,
    /// Distinct primary endpoint observations.
    pub primary_entities: u64,
    /// Distinct corroborating observations.
    pub corroborating_observations: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// Explicit completeness state for every bounded collection.
pub struct ExposureCoverageCompleteness {
    /// Primary kind counts exceeded their server bound.
    pub type_counts_truncated: bool,
    /// Overlap samples exceeded the request bound.
    pub overlaps_truncated: bool,
    /// Primary-only samples exceeded the request bound.
    pub primary_only_truncated: bool,
    /// Corroborating-only samples exceeded the request bound.
    pub corroborating_only_truncated: bool,
    /// Account samples exceeded the request bound.
    pub accounts_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Revision-bound result of one typed exposure coverage comparison.
pub struct ExposureCoverageResult {
    /// Tenant whose projection was queried.
    pub tenant_id: String,
    /// Durable graph revision shared by every returned value.
    pub graph_revision: u64,
    /// Complete aggregate counts.
    pub counts: ExposureCoverageCounts,
    /// Bounded primary entity-kind counts.
    pub type_counts: Vec<ExposureCoverageKindCount>,
    /// Bounded overlap samples.
    pub overlaps: Vec<ExposureCoverageOverlap>,
    /// Bounded primary-only samples.
    pub primary_only: Vec<ExposureCoveragePair>,
    /// Bounded corroborating-only samples.
    pub corroborating_only: Vec<ExposureCoverageCorroboratingOnly>,
    /// Bounded per-account samples.
    pub accounts: Vec<ExposureCoverageAccount>,
    /// Explicit collection completeness state.
    pub completeness: ExposureCoverageCompleteness,
}

impl Neo4jProjector {
    /// Wraps an existing Neo4j client graph.
    pub fn from_graph(graph: Graph) -> Self {
        Self { graph }
    }

    /// Connects to a Neo4j endpoint with the supplied database credentials.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Neo4j`] when the client cannot connect.
    pub async fn connect(uri: &str, username: &str, password: &str) -> Result<Self, StoreError> {
        Ok(Self {
            graph: Graph::new(uri, username, password).await?,
        })
    }

    /// Idempotently creates the projection constraints and indexes.
    ///
    /// This does not rebuild data or mark a lifecycle projection ready.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Neo4j`] when any schema statement fails.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        for statement in NEO4J_SCHEMA {
            self.graph.run(query(statement)).await?;
        }
        Ok(())
    }

    /// Returns the latest graph ingest observation for each requested runtime.
    pub async fn source_runtime_graph_observations(
        &self,
        runtime_ids: &[String],
    ) -> Result<Vec<SourceRuntimeGraphObservation>, StoreError> {
        if runtime_ids.is_empty() {
            return Ok(Vec::new());
        }
        if runtime_ids.len() > 500 || runtime_ids.iter().any(|value| value.trim().is_empty()) {
            return Err(StoreError::Conflict(
                "source runtime graph observation scope is invalid".to_owned(),
            ));
        }
        let mut stream = self
            .graph
            .execute(
                query(
                    r#"
MATCH (run:IngestRun)
WHERE run.runtime_id IN $runtime_ids
WITH run
ORDER BY run.started_at DESC, run.id DESC
WITH run.runtime_id AS runtime_id, collect(run)[0] AS latest
RETURN runtime_id,
       coalesce(latest.status, '') AS status,
       coalesce(latest.checkpoint_cursor, '') AS checkpoint_cursor,
       latest.checkpoint_complete IS NOT NULL AS checkpoint_complete_known,
       coalesce(latest.checkpoint_complete, false) AS checkpoint_complete,
       coalesce(latest.started_at, '') AS started_at,
       coalesce(latest.finished_at, '') AS finished_at
ORDER BY runtime_id
"#,
                )
                .param("runtime_ids", string_list(runtime_ids)),
            )
            .await?;
        let mut observations = Vec::new();
        while let Some(row) = stream.next().await? {
            let decode = |field: &str| {
                row.get::<String>(field).map_err(|error| {
                    StoreError::Conflict(format!(
                        "decode source runtime graph observation {field}: {error}"
                    ))
                })
            };
            let checkpoint_complete_known =
                row.get::<bool>("checkpoint_complete_known")
                    .map_err(|error| {
                        StoreError::Conflict(format!(
                            "decode source runtime graph checkpoint presence: {error}"
                        ))
                    })?;
            let checkpoint_complete = row.get::<bool>("checkpoint_complete").map_err(|error| {
                StoreError::Conflict(format!("decode source runtime graph checkpoint: {error}"))
            })?;
            observations.push(SourceRuntimeGraphObservation {
                runtime_id: decode("runtime_id")?,
                status: decode("status")?,
                checkpoint_cursor: decode("checkpoint_cursor")?,
                checkpoint_complete: checkpoint_complete_known.then_some(checkpoint_complete),
                started_at: decode("started_at")?,
                finished_at: decode("finished_at")?,
            });
        }
        Ok(observations)
    }

    /// Compares tenant-scoped legacy graph roots with the Rust organizational projection.
    ///
    /// The receipt contains counts by legacy entity type. It never returns entity URNs,
    /// provider identifiers, labels, properties, or credentials.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Neo4j`] when the aggregate query fails and
    /// [`StoreError::Conflict`] when Neo4j returns invalid negative counts.
    pub async fn legacy_root_coverage(
        &self,
        tenant_id: &TenantId,
    ) -> Result<LegacyRootCoverage, StoreError> {
        let mut stream = self
            .graph
            .execute(
                query(LEGACY_ROOT_COVERAGE_STATEMENT)
                    .param("tenant_id", tenant_id.as_str())
                    .param("urn_prefix", format!("urn:cerebro:{}:", tenant_id.as_str())),
            )
            .await?;
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await? {
            let entity_type: String = row.get("entity_type").map_err(|error| {
                StoreError::Conflict(format!("decode legacy entity type: {error}"))
            })?;
            let legacy: i64 = row.get("legacy_roots").map_err(|error| {
                StoreError::Conflict(format!("decode legacy root count: {error}"))
            })?;
            let covered: i64 = row.get("covered_roots").map_err(|error| {
                StoreError::Conflict(format!("decode covered root count: {error}"))
            })?;
            rows.push((entity_type, legacy, covered));
        }
        aggregate_legacy_root_coverage(tenant_id, rows)
    }

    /// Lists one revision-bound page from the legacy entity catalog.
    pub async fn list_catalog_entities(
        &self,
        tenant_id: &TenantId,
        filter: &EntityCatalogFilter,
        limit: usize,
        after_agent_key: &str,
    ) -> Result<EntityCatalogPage, StoreError> {
        validate_catalog_request(tenant_id, filter, limit, after_agent_key)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(filter.expected_graph_revision, revision)?;
        let statement = format!(
            "{} RETURN entity.urn AS entity_key, coalesce(entity.entity_type, 'unknown') AS entity_kind, coalesce(entity.label, entity.urn) AS entity_label, coalesce(entity.attributes_json, '{{}}') AS entity_properties, coalesce(entity.source_id, '') AS entity_source_id, coalesce(entity.runtime_id, '') AS entity_runtime_id ORDER BY entity.urn LIMIT $row_limit",
            catalog_entity_match(filter, CatalogCursor::AgentKey(after_agent_key)),
        );
        let mut rows = transaction
            .execute(
                catalog_query(&statement, tenant_id, filter)
                    .param("after_key", after_agent_key)
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut entities = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            entities.push(
                legacy_context_entity(
                    tenant_id,
                    &catalog_row_string(&row, "entity_key")?,
                    catalog_row_string(&row, "entity_kind")?,
                    catalog_row_string(&row, "entity_label")?,
                    catalog_row_string(&row, "entity_properties")?,
                    catalog_row_string(&row, "entity_source_id")?,
                    catalog_row_string(&row, "entity_runtime_id")?,
                )
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
            );
        }
        drop(rows);
        if !filter.exact_agent_key.is_empty() && entities.len() > 1 {
            return Err(StoreError::Conflict(
                "entity catalog exact key is ambiguous".to_owned(),
            ));
        }
        let relation_counts = if let Some(count_filter) = &filter.relation_counts {
            let root_keys = entities
                .iter()
                .take(limit)
                .map(|entity| entity.agent_key.clone())
                .collect::<Vec<_>>();
            catalog_relation_counts(
                &mut transaction,
                tenant_id,
                &root_keys,
                &filter.application_workspace_id,
                count_filter,
            )
            .await?
        } else {
            Vec::new()
        };
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut entities, limit);
        let next_after_agent_key = truncated
            .then(|| entities.last().map(|entity| entity.agent_key.clone()))
            .flatten()
            .unwrap_or_default();
        Ok(EntityCatalogPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            entities,
            truncated,
            next_after_agent_key,
            relation_counts,
        })
    }

    /// Resolves one exact compliance revision and its direct dependencies.
    pub async fn get_compliance_impact_fact(
        &self,
        tenant_id: &TenantId,
        agent_key: &str,
    ) -> Result<Option<ComplianceImpactFact>, StoreError> {
        validate_compliance_impact_key(tenant_id, "agent_key", agent_key, true)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        let mut fact_rows = transaction
            .execute(
                compliance_impact_query(COMPLIANCE_IMPACT_FACT_STATEMENT, tenant_id)
                    .param("agent_key", agent_key),
            )
            .await?;
        let mut facts = Vec::new();
        while let Some(row) = fact_rows.next(transaction.handle()).await? {
            facts.push(compliance_impact_entity(tenant_id, &row)?);
        }
        drop(fact_rows);
        if facts.is_empty() {
            let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
            transaction.commit().await?;
            require_same_catalog_revision(revision, end_revision)?;
            return Ok(None);
        }
        if facts.len() != 1 {
            return Err(StoreError::Conflict(
                "compliance impact exact revision is ambiguous".to_owned(),
            ));
        }

        let mut count_rows = transaction
            .execute(
                compliance_impact_query(COMPLIANCE_IMPACT_DEPENDENCY_COUNT_STATEMENT, tenant_id)
                    .param("agent_key", agent_key),
            )
            .await?;
        let count_row = count_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict("compliance impact dependency count is unavailable".to_owned())
            })?;
        let dependency_count = catalog_row_u64(&count_row, "dependency_count")?;
        if count_rows.next(transaction.handle()).await?.is_some() || dependency_count > 2_999 {
            return Err(StoreError::Conflict(
                "compliance impact dependency count is invalid".to_owned(),
            ));
        }
        drop(count_rows);

        let mut dependencies = Vec::with_capacity(dependency_count as usize);
        if let Some(dependency_row_limit) = compliance_impact_dependency_row_limit(dependency_count)
        {
            let mut identities = BTreeSet::new();
            let mut last_order_key = None;
            let mut dependency_rows = transaction
                .execute(
                    compliance_impact_query(COMPLIANCE_IMPACT_DEPENDENCIES_STATEMENT, tenant_id)
                        .param("agent_key", agent_key)
                        .param("row_limit", dependency_row_limit),
                )
                .await?;
            while let Some(row) = dependency_rows.next(transaction.handle()).await? {
                let entity = compliance_impact_entity(tenant_id, &row)?;
                let edge_properties_json = catalog_row_string(&row, "edge_properties")?;
                let edge_properties: BTreeMap<String, String> =
                    parse_json(&edge_properties_json)
                        .map_err(|error| StoreError::Conflict(error.to_string()))?;
                let canonical_edge_properties = serde_json::to_string(&edge_properties)
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
                if canonical_edge_properties != edge_properties_json {
                    return Err(StoreError::Conflict(
                        "compliance impact dependency attributes are not canonical".to_owned(),
                    ));
                }
                let relation = edge_properties
                    .get("dependency_relation")
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        StoreError::Conflict(
                            "compliance impact dependency relation is missing".to_owned(),
                        )
                    })?
                    .to_owned();
                let identity = (entity.agent_key.clone(), relation.clone());
                if !identities.insert(identity) {
                    return Err(StoreError::Conflict(
                        "compliance impact dependency rows contain a duplicate".to_owned(),
                    ));
                }
                let order_key = (entity.agent_key.clone(), canonical_edge_properties);
                if last_order_key
                    .as_ref()
                    .is_some_and(|last| last >= &order_key)
                {
                    return Err(StoreError::Conflict(
                        "compliance impact dependency rows are not strictly ordered".to_owned(),
                    ));
                }
                last_order_key = Some(order_key);
                dependencies.push(ComplianceImpactDependency { entity, relation });
            }
            drop(dependency_rows);
            if dependencies.len() != dependency_count as usize {
                return Err(StoreError::Conflict(
                    "compliance impact dependency count changed during the read".to_owned(),
                ));
            }
        }
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        Ok(Some(ComplianceImpactFact {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            fact: facts.remove(0),
            dependency_count: u32::try_from(dependency_count).unwrap_or(u32::MAX),
            dependencies,
        }))
    }

    /// Lists one keyset-paged reverse compliance-dependency page.
    pub async fn list_compliance_impact_dependents(
        &self,
        tenant_id: &TenantId,
        dependency_key: &str,
        after_agent_key: &str,
        limit: usize,
    ) -> Result<ComplianceImpactPage, StoreError> {
        validate_compliance_impact_key(tenant_id, "dependency_key", dependency_key, true)?;
        validate_compliance_impact_key(tenant_id, "after_agent_key", after_agent_key, false)?;
        if !(1..=2_999).contains(&limit) {
            return Err(StoreError::Conflict(
                "compliance impact dependent limit must be between 1 and 2999".to_owned(),
            ));
        }
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        let mut rows = transaction
            .execute(
                compliance_impact_query(COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT, tenant_id)
                    .param("dependency_key", dependency_key)
                    .param("after_key", after_agent_key)
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut dependents = Vec::new();
        let mut last_key = after_agent_key.to_owned();
        while let Some(row) = rows.next(transaction.handle()).await? {
            let entity = compliance_impact_entity(tenant_id, &row)?;
            if entity.agent_key <= last_key {
                return Err(StoreError::Conflict(
                    "compliance impact dependent cursor is not strictly monotonic".to_owned(),
                ));
            }
            last_key.clone_from(&entity.agent_key);
            dependents.push(entity);
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut dependents, limit);
        let next_after_agent_key = truncated
            .then(|| dependents.last().map(|entity| entity.agent_key.clone()))
            .flatten()
            .unwrap_or_default();
        Ok(ComplianceImpactPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            dependents,
            truncated,
            next_after_agent_key,
        })
    }

    /// Counts entity kinds in one revision-bound catalog page.
    pub async fn count_catalog_entity_kinds(
        &self,
        tenant_id: &TenantId,
        filter: &EntityCatalogFilter,
        limit: usize,
        after_entity_kind: &str,
    ) -> Result<EntityCatalogKindPage, StoreError> {
        validate_catalog_request(tenant_id, filter, limit, "")?;
        validate_catalog_text("after_entity_kind", after_entity_kind, 256, false)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(filter.expected_graph_revision, revision)?;
        let statement = format!(
            "{} RETURN entity.entity_type AS entity_kind, count(entity) AS entity_count ORDER BY entity.entity_type LIMIT $row_limit",
            catalog_entity_match(filter, CatalogCursor::EntityKind),
        );
        let mut rows = transaction
            .execute(
                catalog_query(&statement, tenant_id, filter)
                    .param("after_kind", after_entity_kind)
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut counts = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            counts.push(EntityCatalogKindCount {
                entity_kind: catalog_row_string(&row, "entity_kind")?,
                count: catalog_row_u64(&row, "entity_count")?,
            });
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut counts, limit);
        let next_after_entity_kind = truncated
            .then(|| counts.last().map(|count| count.entity_kind.clone()))
            .flatten()
            .unwrap_or_default();
        Ok(EntityCatalogKindPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            counts,
            truncated,
            next_after_entity_kind,
        })
    }

    /// Counts relation kinds in one revision-bound catalog page.
    pub async fn count_catalog_relations(
        &self,
        tenant_id: &TenantId,
        limit: usize,
        after_relation: &str,
        expected_graph_revision: u64,
    ) -> Result<EntityCatalogRelationKindPage, StoreError> {
        if !(1..=500).contains(&limit) {
            return Err(StoreError::Conflict(
                "entity catalog relation-count limit must be between 1 and 500".to_owned(),
            ));
        }
        validate_catalog_text("after_relation", after_relation, 128, false)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(expected_graph_revision, revision)?;
        let statement = "MATCH (:Entity {tenant_id: $tenant_id})-[edge:RELATION {tenant_id: $tenant_id}]->(:Entity {tenant_id: $tenant_id}) WITH coalesce(edge.relation, 'unknown') AS relation WHERE relation > $after_relation RETURN relation, count(edge) AS relation_count ORDER BY relation LIMIT $row_limit";
        let mut rows = transaction
            .execute(
                query(statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("after_relation", after_relation)
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut counts = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            counts.push(EntityCatalogRelationKindCount {
                relation: catalog_row_string(&row, "relation")?,
                count: catalog_row_u64(&row, "relation_count")?,
            });
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut counts, limit);
        let next_after_relation = truncated
            .then(|| counts.last().map(|count| count.relation.clone()))
            .flatten()
            .unwrap_or_default();
        Ok(EntityCatalogRelationKindPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            counts,
            truncated,
            next_after_relation,
        })
    }

    /// Lists bounded person access paths using a Rust-owned legacy projection query.
    pub async fn list_person_access_paths(
        &self,
        tenant_id: &TenantId,
        person_urn: &str,
        person_query: &str,
        limit: usize,
        depth: usize,
        expected_graph_revision: u64,
    ) -> Result<PersonAccessPathPage, StoreError> {
        validate_person_access_request(tenant_id, person_urn, person_query, limit, depth)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(expected_graph_revision, revision)?;
        let access_relations = vec![
            "assigned_to".to_owned(),
            "member_of".to_owned(),
            "can_admin".to_owned(),
            "can_perform".to_owned(),
            "can_assume".to_owned(),
            "can_impersonate".to_owned(),
            "runs_as".to_owned(),
        ];
        let statement = format!(
            "MATCH (person:Entity {{tenant_id: $tenant_id, entity_type: 'person'}}) WHERE ($person_urn = '' OR person.urn = $person_urn) AND ($person_query = '' OR toLower(coalesce(person.label, '')) CONTAINS $person_query OR toLower(coalesce(person.attributes_json, '')) CONTAINS $person_query) MATCH (person)-[person_identity:RELATION {{relation: 'same_actor'}}]-(identity:Entity {{tenant_id: $tenant_id}}) MATCH (principal:Entity {{tenant_id: $tenant_id}})-[principal_identity:RELATION {{relation: 'represents_identity'}}]->(identity) MATCH path = (principal)-[:RELATION*1..{depth}]->(target:Entity {{tenant_id: $tenant_id}}) WHERE person_identity.tenant_id = $tenant_id AND principal_identity.tenant_id = $tenant_id AND all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $access_relations) AND target.urn <> person.urn AND target.urn <> identity.urn RETURN person.urn AS person_key, coalesce(person.entity_type, 'unknown') AS person_kind, coalesce(person.label, person.urn) AS person_label, coalesce(person.attributes_json, '{{}}') AS person_properties, coalesce(person.source_id, '') AS person_source_id, coalesce(person.runtime_id, '') AS person_runtime_id, identity.urn AS identity_key, coalesce(identity.entity_type, 'unknown') AS identity_kind, coalesce(identity.label, identity.urn) AS identity_label, coalesce(identity.attributes_json, '{{}}') AS identity_properties, coalesce(identity.source_id, '') AS identity_source_id, coalesce(identity.runtime_id, '') AS identity_runtime_id, principal.urn AS principal_key, coalesce(principal.entity_type, 'unknown') AS principal_kind, coalesce(principal.label, principal.urn) AS principal_label, coalesce(principal.attributes_json, '{{}}') AS principal_properties, coalesce(principal.source_id, '') AS principal_source_id, coalesce(principal.runtime_id, '') AS principal_runtime_id, target.urn AS target_key, coalesce(target.entity_type, 'unknown') AS target_kind, coalesce(target.label, target.urn) AS target_label, coalesce(target.attributes_json, '{{}}') AS target_properties, coalesce(target.source_id, '') AS target_source_id, coalesce(target.runtime_id, '') AS target_runtime_id, [rel IN relationships(path) | rel.relation] AS relation_chain ORDER BY person.label, principal.label, target.label LIMIT $row_limit"
        );
        let mut rows = transaction
            .execute(
                query(&statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("person_urn", person_urn)
                    .param("person_query", person_query)
                    .param("access_relations", string_list(&access_relations))
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut paths = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            let relation_chain: Vec<String> = row
                .get("relation_chain")
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            if relation_chain.is_empty()
                || relation_chain.len() > depth
                || relation_chain
                    .iter()
                    .any(|relation| !access_relations.contains(relation))
            {
                return Err(StoreError::Conflict(
                    "person access path relation chain is invalid".to_owned(),
                ));
            }
            paths.push(PersonAccessPath {
                person: legacy_context_entity_from_row_prefix(tenant_id, &row, "person")?,
                identity: legacy_context_entity_from_row_prefix(tenant_id, &row, "identity")?,
                principal: legacy_context_entity_from_row_prefix(tenant_id, &row, "principal")?,
                access_target: legacy_context_entity_from_row_prefix(tenant_id, &row, "target")?,
                relation_chain,
            });
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut paths, limit);
        Ok(PersonAccessPathPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            paths,
            truncated,
        })
    }

    /// Lists bounded identity-to-capability effective-access proofs using one
    /// closed Rust-owned union query.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_effective_access_paths(
        &self,
        tenant_id: &TenantId,
        identity_urn: &str,
        identity_query: &str,
        application_urn: &str,
        capability_urn: &str,
        capability_id: &str,
        limit: usize,
        expected_graph_revision: u64,
    ) -> Result<EffectiveAccessPathPage, StoreError> {
        validate_effective_access_request(
            tenant_id,
            identity_urn,
            identity_query,
            application_urn,
            capability_urn,
            capability_id,
            limit,
        )?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(expected_graph_revision, revision)?;
        let mut rows = transaction
            .execute(
                query(effective_access_path_statement())
                    .param("tenant_id", tenant_id.as_str())
                    .param("identity_urn", identity_urn)
                    .param("identity_query", identity_query)
                    .param("application_urn", application_urn)
                    .param("capability_urn", capability_urn)
                    .param("capability_id", capability_id)
                    .param("sample_limit", i64::try_from(limit).unwrap_or(i64::MAX))
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut paths = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            paths.push(effective_access_path_from_row(tenant_id, &row)?);
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut paths, limit);
        Ok(EffectiveAccessPathPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            paths,
            truncated,
        })
    }

    /// Lists bounded cloud attack paths using a Rust-owned legacy projection query.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_cloud_attack_paths(
        &self,
        tenant_id: &TenantId,
        account_id: &str,
        runtime_id: &str,
        require_assertion_proof: bool,
        limit: usize,
        depth: usize,
        expected_graph_revision: u64,
    ) -> Result<CloudAttackPathPage, StoreError> {
        validate_cloud_attack_path_request(account_id, runtime_id, limit, depth)?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(expected_graph_revision, revision)?;
        let relation_type = if require_assertion_proof {
            "RELATION_ASSERTION"
        } else {
            "RELATION"
        };
        let traversal_relations = cloud_attack_path_traversal_relations();
        let access_relations = cloud_attack_path_access_relations();
        let counts_statement = cloud_attack_path_counts_statement(depth, relation_type);
        let mut count_rows = transaction
            .execute(
                query(&counts_statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("account_id", account_id)
                    .param("runtime_id", runtime_id)
                    .param("traversal_relations", string_list(&traversal_relations))
                    .param("access_relations", string_list(&access_relations)),
            )
            .await?;
        let counts = if let Some(row) = count_rows.next(transaction.handle()).await? {
            CloudAttackPathCounts {
                paths: catalog_row_u64(&row, "path_count")?,
                exposed_resources: catalog_row_u64(&row, "exposed_resource_count")?,
                privileged_principals: catalog_row_u64(&row, "privileged_principal_count")?,
                cloud_accounts: catalog_row_u64(&row, "cloud_account_count")?,
            }
        } else {
            CloudAttackPathCounts::default()
        };
        drop(count_rows);
        let samples_statement = cloud_attack_path_samples_statement(depth, relation_type);
        let mut rows = transaction
            .execute(
                query(&samples_statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("account_id", account_id)
                    .param("runtime_id", runtime_id)
                    .param("traversal_relations", string_list(&traversal_relations))
                    .param("access_relations", string_list(&access_relations))
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut paths = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            paths.push(cloud_attack_path_from_row(&row)?);
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut paths, limit);
        Ok(CloudAttackPathPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            counts,
            paths,
            truncated,
        })
    }

    /// Lists one revision-bound page of direct catalog relations.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_catalog_relations(
        &self,
        tenant_id: &TenantId,
        agent_key: &str,
        directions: &[EntityCatalogDirection],
        relations: &[String],
        neighbor_kinds: &[String],
        neighbor_agent_keys: &[String],
        neighbor_application_workspace_id: &str,
        limit: usize,
        after_agent_key: &str,
        after_relation: &str,
        after_direction: Option<EntityCatalogDirection>,
        expected_graph_revision: u64,
    ) -> Result<EntityCatalogRelationPage, StoreError> {
        validate_catalog_relation_request(
            tenant_id,
            agent_key,
            directions,
            relations,
            neighbor_kinds,
            neighbor_agent_keys,
            neighbor_application_workspace_id,
            limit,
            CatalogRelationCursor {
                agent_key: after_agent_key,
                relation: after_relation,
                direction: after_direction,
            },
        )?;
        let mut transaction = self.graph.start_txn().await?;
        let revision = catalog_revision(&mut transaction, tenant_id).await?;
        require_catalog_revision(expected_graph_revision, revision)?;
        let mut root_rows = transaction.execute(query("MATCH (root:Entity {tenant_id: $tenant_id, urn: $agent_key}) RETURN count(root) AS root_count").param("tenant_id", tenant_id.as_str()).param("agent_key", agent_key)).await?;
        let root_count = catalog_row_u64(
            &root_rows.next(transaction.handle()).await?.ok_or_else(|| {
                StoreError::Conflict("entity catalog root count returned no row".to_owned())
            })?,
            "root_count",
        )?;
        drop(root_rows);
        if root_count == 0 {
            return Err(StoreError::Conflict(
                "entity catalog root was not found".to_owned(),
            ));
        }
        if root_count != 1 {
            return Err(StoreError::Conflict(
                "entity catalog root is ambiguous".to_owned(),
            ));
        }
        let mut scope_rows = transaction.execute(query("MATCH (root:Entity {tenant_id: $tenant_id, urn: $agent_key})-[edge:RELATION]-(neighbor:Entity) WHERE coalesce(edge.tenant_id, '') <> $tenant_id OR coalesce(neighbor.tenant_id, '') <> $tenant_id RETURN count(*) AS violations").param("tenant_id", tenant_id.as_str()).param("agent_key", agent_key)).await?;
        let violations = catalog_row_u64(
            &scope_rows
                .next(transaction.handle())
                .await?
                .ok_or_else(|| {
                    StoreError::Conflict("entity catalog relation scope returned no row".to_owned())
                })?,
            "violations",
        )?;
        drop(scope_rows);
        if violations != 0 {
            return Err(StoreError::Conflict(
                "entity catalog contains cross-tenant relations".to_owned(),
            ));
        }
        let direction_names = directions
            .iter()
            .map(|direction| match direction {
                EntityCatalogDirection::Incoming => "incoming".to_owned(),
                EntityCatalogDirection::Outgoing => "outgoing".to_owned(),
            })
            .collect::<Vec<_>>();
        let after_direction_name = after_direction
            .map(|direction| match direction {
                EntityCatalogDirection::Incoming => "incoming",
                EntityCatalogDirection::Outgoing => "outgoing",
            })
            .unwrap_or("");
        let statement = "MATCH (root:Entity {tenant_id: $tenant_id, urn: $agent_key}) MATCH (root)-[edge:RELATION {tenant_id: $tenant_id}]-(neighbor:Entity {tenant_id: $tenant_id}) WITH root, edge, neighbor, CASE WHEN startNode(edge) = root THEN 'outgoing' ELSE 'incoming' END AS direction WHERE (size($directions) = 0 OR direction IN $directions) AND (size($relations) = 0 OR edge.relation IN $relations) AND (size($neighbor_kinds) = 0 OR neighbor.entity_type IN $neighbor_kinds) AND (size($neighbor_agent_keys) = 0 OR neighbor.urn IN $neighbor_agent_keys) AND ($neighbor_application_workspace_id = '' OR coalesce(neighbor.application_workspace_id, '') = $neighbor_application_workspace_id) AND ($after_key = '' OR neighbor.urn > $after_key OR (neighbor.urn = $after_key AND edge.relation > $after_relation) OR (neighbor.urn = $after_key AND edge.relation = $after_relation AND direction > $after_direction)) RETURN direction, edge.relation AS relation, coalesce(edge.source_id, '') AS edge_source_id, coalesce(edge.attributes_json, '{}') AS edge_attributes_json, neighbor.urn AS entity_key, coalesce(neighbor.entity_type, 'unknown') AS entity_kind, coalesce(neighbor.label, neighbor.urn) AS entity_label, coalesce(neighbor.attributes_json, '{}') AS entity_properties, coalesce(neighbor.source_id, '') AS entity_source_id, coalesce(neighbor.runtime_id, '') AS entity_runtime_id ORDER BY neighbor.urn, edge.relation, direction LIMIT $row_limit";
        let mut rows = transaction
            .execute(
                query(statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("agent_key", agent_key)
                    .param("directions", string_list(&direction_names))
                    .param("relations", string_list(relations))
                    .param("neighbor_kinds", string_list(neighbor_kinds))
                    .param("neighbor_agent_keys", string_list(neighbor_agent_keys))
                    .param(
                        "neighbor_application_workspace_id",
                        neighbor_application_workspace_id,
                    )
                    .param("after_key", after_agent_key)
                    .param("after_relation", after_relation)
                    .param("after_direction", after_direction_name)
                    .param("row_limit", row_limit(limit)),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next(transaction.handle()).await? {
            let direction = match catalog_row_string(&row, "direction")?.as_str() {
                "incoming" => EntityCatalogDirection::Incoming,
                "outgoing" => EntityCatalogDirection::Outgoing,
                _ => {
                    return Err(StoreError::Conflict(
                        "entity catalog relation direction is invalid".to_owned(),
                    ));
                }
            };
            values.push(EntityCatalogRelation {
                direction,
                relation: catalog_row_string(&row, "relation")?,
                source_id: catalog_row_string(&row, "edge_source_id")?,
                attributes_json: catalog_row_string(&row, "edge_attributes_json")?,
                entity: legacy_context_entity(
                    tenant_id,
                    &catalog_row_string(&row, "entity_key")?,
                    catalog_row_string(&row, "entity_kind")?,
                    catalog_row_string(&row, "entity_label")?,
                    catalog_row_string(&row, "entity_properties")?,
                    catalog_row_string(&row, "entity_source_id")?,
                    catalog_row_string(&row, "entity_runtime_id")?,
                )
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
            });
        }
        drop(rows);
        let end_revision = catalog_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        require_same_catalog_revision(revision, end_revision)?;
        let truncated = truncate_to_limit(&mut values, limit);
        let continuation = truncated
            .then(|| {
                values.last().map(|value| {
                    (
                        value.entity.agent_key.clone(),
                        value.relation.clone(),
                        value.direction,
                    )
                })
            })
            .flatten();
        Ok(EntityCatalogRelationPage {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: revision,
            relations: values,
            truncated,
            next_after_agent_key: continuation
                .as_ref()
                .map(|value| value.0.clone())
                .unwrap_or_default(),
            next_after_relation: continuation
                .as_ref()
                .map(|value| value.1.clone())
                .unwrap_or_default(),
            next_after_direction: continuation.map(|value| value.2),
        })
    }

    /// Compares two bounded exposure observation sets inside one tenant-scoped
    /// read transaction. Callers select only source IDs and entity kinds; the
    /// graph labels and relation shapes remain fixed by this store operation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] for invalid bounds, filters, malformed
    /// projected rows, or revision drift. Neo4j failures are returned as
    /// [`StoreError::Neo4j`].
    pub async fn compare_exposure_coverage(
        &self,
        tenant_id: &TenantId,
        request: &ExposureCoverageQuery,
    ) -> Result<ExposureCoverageResult, StoreError> {
        validate_exposure_coverage_query(request)?;
        let sample_limit = i64::try_from(request.limit + 1)
            .map_err(|_| StoreError::Conflict("exposure coverage limit overflow".to_owned()))?;
        let params = |statement: &str| {
            query(statement)
                .param("tenant_id", tenant_id.as_str())
                .param(
                    "primary_source_id",
                    request.profile.primary_source_id.as_str(),
                )
                .param(
                    "primary_kind_prefix",
                    request.profile.primary_entity_kind_prefix.as_str(),
                )
                .param(
                    "corroborating_source_id",
                    request.profile.corroborating_source_id.as_str(),
                )
                .param(
                    "corroborating_kind",
                    request.profile.corroborating_entity_kind.as_str(),
                )
                .param(
                    "indicator_kinds",
                    string_list(&request.profile.indicator_kinds),
                )
                .param("account_kind", request.profile.account_kind.as_str())
                .param(
                    "corroborating_observation_kind",
                    request.profile.corroborating_observation_kind.as_str(),
                )
                .param("account_id", request.account_id.as_str())
                .param("region", request.region.as_str())
                .param("search", request.search.to_lowercase())
                .param("sample_limit", sample_limit)
        };

        let mut transaction = self.graph.start_txn().await?;
        let counts_statement = exposure_counts_statement();
        let mut counts_rows = transaction.execute(params(&counts_statement)).await?;
        let counts_row = counts_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict("exposure coverage counts returned no row".to_owned())
            })?;
        let start_revision = row_u64(&counts_row, "graph_revision")?;
        let counts = ExposureCoverageCounts {
            primary_entities: row_u64(&counts_row, "primary_count")?,
            indicators: row_u64(&counts_row, "indicator_count")?,
            host_indicators: row_u64(&counts_row, "host_count")?,
            ip_indicators: row_u64(&counts_row, "ip_count")?,
            overlapping_primary_entities: row_u64(&counts_row, "overlapping_primary_count")?,
            overlapping_indicators: row_u64(&counts_row, "overlapping_indicator_count")?,
            overlapping_corroborating_entities: row_u64(
                &counts_row,
                "overlapping_corroborating_count",
            )?,
        };
        drop(counts_rows);

        let type_statement = format!(
            "MATCH (endpoint:Entity {{tenant_id: $tenant_id, source_id: $primary_source_id}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator:Entity {{tenant_id: $tenant_id}}) WHERE {EXPOSURE_PRIMARY_FILTER} RETURN endpoint.entity_type AS entity_kind, count(DISTINCT endpoint) AS count ORDER BY count DESC, entity_kind LIMIT 51"
        );
        let mut type_rows = transaction.execute(params(&type_statement)).await?;
        let mut type_counts = Vec::new();
        while let Some(row) = type_rows.next(transaction.handle()).await? {
            type_counts.push(ExposureCoverageKindCount {
                entity_kind: row
                    .get("entity_kind")
                    .map_err(|error| StoreError::Conflict(error.to_string()))?,
                count: row_u64(&row, "count")?,
            });
        }
        drop(type_rows);

        let overlap_statement = format!(
            "MATCH (endpoint:Entity {{tenant_id: $tenant_id, source_id: $primary_source_id}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator:Entity {{tenant_id: $tenant_id}}) WHERE {EXPOSURE_PRIMARY_FILTER} MATCH (asset:Entity {{tenant_id: $tenant_id, source_id: $corroborating_source_id, entity_type: $corroborating_kind}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator) RETURN endpoint.urn AS primary_key, endpoint.entity_type AS primary_kind, endpoint.label AS primary_label, indicator.urn AS indicator_key, indicator.entity_type AS indicator_kind, indicator.label AS indicator_label, asset.urn AS corroborating_key, asset.entity_type AS corroborating_kind, asset.label AS corroborating_label ORDER BY indicator.label, endpoint.label, asset.label, indicator.urn, endpoint.urn, asset.urn LIMIT $sample_limit"
        );
        let mut overlap_rows = transaction.execute(params(&overlap_statement)).await?;
        let mut overlaps = Vec::new();
        while let Some(row) = overlap_rows.next(transaction.handle()).await? {
            overlaps.push(ExposureCoverageOverlap {
                primary: exposure_entity(&row, "primary", tenant_id)?,
                indicator: exposure_entity(&row, "indicator", tenant_id)?,
                corroborating: exposure_entity(&row, "corroborating", tenant_id)?,
            });
        }
        drop(overlap_rows);

        let primary_only_statement = format!(
            "MATCH (endpoint:Entity {{tenant_id: $tenant_id, source_id: $primary_source_id}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator:Entity {{tenant_id: $tenant_id}}) WHERE {EXPOSURE_PRIMARY_FILTER} AND NOT EXISTS {{ MATCH (:Entity {{tenant_id: $tenant_id, source_id: $corroborating_source_id, entity_type: $corroborating_kind}})-[:RELATION {{tenant_id: $tenant_id, relation: 'represents'}}]->(indicator) }} RETURN endpoint.urn AS primary_key, endpoint.entity_type AS primary_kind, endpoint.label AS primary_label, indicator.urn AS indicator_key, indicator.entity_type AS indicator_kind, indicator.label AS indicator_label ORDER BY indicator.label, endpoint.label, indicator.urn, endpoint.urn LIMIT $sample_limit"
        );
        let mut primary_only_rows = transaction.execute(params(&primary_only_statement)).await?;
        let mut primary_only = Vec::new();
        while let Some(row) = primary_only_rows.next(transaction.handle()).await? {
            primary_only.push(ExposureCoveragePair {
                primary: exposure_entity(&row, "primary", tenant_id)?,
                indicator: exposure_entity(&row, "indicator", tenant_id)?,
            });
        }
        drop(primary_only_rows);

        let mut corroborating_only = Vec::new();
        if should_query_corroborating_only(request) {
            let corroborating_only_statement = "MATCH (asset:Entity {tenant_id: $tenant_id, source_id: $corroborating_source_id, entity_type: $corroborating_kind})-[:RELATION {tenant_id: $tenant_id, relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id}) WHERE indicator.entity_type IN $indicator_kinds AND ($search = '' OR toLower(coalesce(asset.urn, '') + ' ' + coalesce(asset.label, '') + ' ' + coalesce(indicator.urn, '') + ' ' + coalesce(indicator.label, '')) CONTAINS $search) AND NOT EXISTS { MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: $primary_source_id})-[:RELATION {tenant_id: $tenant_id, relation: 'represents'}]->(indicator) WHERE endpoint.entity_type STARTS WITH $primary_kind_prefix } RETURN asset.urn AS corroborating_key, asset.entity_type AS corroborating_kind, asset.label AS corroborating_label, indicator.urn AS indicator_key, indicator.entity_type AS indicator_kind, indicator.label AS indicator_label ORDER BY indicator.label, asset.label, indicator.urn, asset.urn LIMIT $sample_limit";
            let mut corroborating_only_rows = transaction
                .execute(params(corroborating_only_statement))
                .await?;
            while let Some(row) = corroborating_only_rows.next(transaction.handle()).await? {
                corroborating_only.push(ExposureCoverageCorroboratingOnly {
                    corroborating: exposure_entity(&row, "corroborating", tenant_id)?,
                    indicator: exposure_entity(&row, "indicator", tenant_id)?,
                });
            }
            drop(corroborating_only_rows);
        }

        let account_statement = format!(
            "MATCH (endpoint:Entity {{tenant_id: $tenant_id, source_id: $primary_source_id}})-[:RELATION {{tenant_id: $tenant_id, relation: 'belongs_to'}}]->(account:Entity {{tenant_id: $tenant_id, entity_type: $account_kind}}) WHERE {EXPOSURE_ACCOUNT_FILTER} OPTIONAL MATCH (scan:Entity {{tenant_id: $tenant_id, source_id: $corroborating_source_id, entity_type: $corroborating_observation_kind}})-[:RELATION {{tenant_id: $tenant_id, relation: 'belongs_to'}}]->(account) RETURN account.urn AS account_key, account.entity_type AS account_kind, account.label AS account_label, count(DISTINCT endpoint) AS primary_count, count(DISTINCT scan) AS corroborating_count ORDER BY primary_count DESC, account.label, account.urn LIMIT $sample_limit"
        );
        let mut account_rows = transaction.execute(params(&account_statement)).await?;
        let mut accounts = Vec::new();
        while let Some(row) = account_rows.next(transaction.handle()).await? {
            accounts.push(ExposureCoverageAccount {
                account: exposure_entity(&row, "account", tenant_id)?,
                primary_entities: row_u64(&row, "primary_count")?,
                corroborating_observations: row_u64(&row, "corroborating_count")?,
            });
        }
        drop(account_rows);

        let end_revision = transaction_graph_revision(&mut transaction, tenant_id).await?;
        transaction.commit().await?;
        if start_revision != end_revision {
            return Err(StoreError::Conflict(
                "exposure coverage graph revision changed during the read".to_owned(),
            ));
        }

        let completeness = ExposureCoverageCompleteness {
            type_counts_truncated: truncate_to_limit(&mut type_counts, 50),
            overlaps_truncated: truncate_to_limit(&mut overlaps, request.limit),
            primary_only_truncated: truncate_to_limit(&mut primary_only, request.limit),
            corroborating_only_truncated: truncate_to_limit(&mut corroborating_only, request.limit),
            accounts_truncated: truncate_to_limit(&mut accounts, request.limit),
        };
        Ok(ExposureCoverageResult {
            tenant_id: tenant_id.as_str().to_owned(),
            graph_revision: start_revision,
            counts,
            type_counts,
            overlaps,
            primary_only,
            corroborating_only,
            accounts,
            completeness,
        })
    }

    async fn expand_legacy_one_hop_many(
        &self,
        tenant_id: &TenantId,
        root_keys: &[String],
        limit: usize,
    ) -> Result<BTreeMap<String, Neighborhood>, ContextError> {
        let urn_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
        let legacy_keys = root_keys
            .iter()
            .filter(|root_key| root_key.starts_with(&urn_prefix))
            .cloned()
            .collect::<Vec<_>>();
        if legacy_keys.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut root_stream = self
            .graph
            .execute(
                query(LEGACY_ROOTS_STATEMENT)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_urns", string_list(&legacy_keys)),
            )
            .await
            .map_err(context_backend)?;
        let mut accumulators = BTreeMap::new();
        while let Some(row) = root_stream.next().await.map_err(context_backend)? {
            let root_key = row_string(&row, "root_urn")?;
            let match_count: i64 = row.get("match_count").map_err(context_decode)?;
            if match_count != 1 {
                return Err(ContextError::BackendUnavailable(format!(
                    "legacy graph root {root_key:?} is ambiguous"
                )));
            }
            let root = legacy_context_entity(
                tenant_id,
                &root_key,
                row_string(&row, "root_kind")?,
                row_string(&row, "root_label")?,
                row_string(&row, "root_properties")?,
                row_string(&row, "root_source_id")?,
                row_string(&row, "root_runtime_id")?,
            )?;
            accumulators.insert(root_key, LegacyNeighborhoodAccumulator::new(root));
        }
        if accumulators.is_empty() {
            return Ok(BTreeMap::new());
        }

        let present_keys = legacy_keys
            .into_iter()
            .filter(|root_key| accumulators.contains_key(root_key))
            .collect::<Vec<_>>();
        let mut scope_stream = self
            .graph
            .execute(
                query(LEGACY_NEIGHBOR_SCOPE_STATEMENT)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_urns", string_list(&present_keys)),
            )
            .await
            .map_err(context_backend)?;
        let violations = scope_stream
            .next()
            .await
            .map_err(context_backend)?
            .ok_or_else(|| {
                ContextError::BackendUnavailable(
                    "legacy graph scope query returned no row".to_owned(),
                )
            })?
            .get::<i64>("violations")
            .map_err(context_decode)?;
        if violations != 0 {
            return Err(ContextError::BackendUnavailable(
                "legacy graph contains cross-tenant neighborhood data".to_owned(),
            ));
        }
        self.read_legacy_edge_phase(
            tenant_id,
            LEGACY_OUTGOING_STATEMENT,
            &present_keys,
            limit,
            &mut accumulators,
        )
        .await?;
        let mut incoming_by_limit = BTreeMap::<usize, Vec<String>>::new();
        for root_key in &present_keys {
            let accumulator = &accumulators[root_key];
            if accumulator.truncated {
                continue;
            }
            let remaining = limit.saturating_sub(accumulator.edges.len());
            incoming_by_limit
                .entry(remaining)
                .or_default()
                .push(root_key.clone());
        }
        for (remaining, roots) in incoming_by_limit {
            self.read_legacy_edge_phase(
                tenant_id,
                LEGACY_INCOMING_STATEMENT,
                &roots,
                remaining,
                &mut accumulators,
            )
            .await?;
        }

        Ok(accumulators
            .into_iter()
            .map(|(root_key, accumulator)| {
                (
                    root_key,
                    Neighborhood {
                        tenant_id: tenant_id.clone(),
                        graph_revision: 0,
                        root: accumulator.root,
                        entities: accumulator.entities.into_values().collect(),
                        edges: accumulator.edges,
                        truncated: accumulator.truncated,
                    },
                )
            })
            .collect())
    }

    async fn any_legacy_root_exists(
        &self,
        tenant_id: &TenantId,
        root_keys: &[String],
    ) -> Result<bool, ContextError> {
        let urn_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
        let legacy_keys = root_keys
            .iter()
            .filter(|root_key| root_key.starts_with(&urn_prefix))
            .cloned()
            .collect::<Vec<_>>();
        if legacy_keys.is_empty() {
            return Ok(false);
        }
        let mut stream = self
            .graph
            .execute(
                query(LEGACY_ROOTS_STATEMENT)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_urns", string_list(&legacy_keys)),
            )
            .await
            .map_err(context_backend)?;
        if let Some(row) = stream.next().await.map_err(context_backend)? {
            let match_count: i64 = row.get("match_count").map_err(context_decode)?;
            if match_count != 1 {
                return Err(ContextError::BackendUnavailable(
                    "legacy graph root is ambiguous".to_owned(),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn read_legacy_edge_phase(
        &self,
        tenant_id: &TenantId,
        statement: &str,
        root_keys: &[String],
        limit: usize,
        accumulators: &mut BTreeMap<String, LegacyNeighborhoodAccumulator>,
    ) -> Result<(), ContextError> {
        let row_limit = limit.checked_add(1).ok_or_else(|| {
            ContextError::BackendUnavailable("legacy graph limit overflowed".to_owned())
        })?;
        let mut stream = self
            .graph
            .execute(
                query(statement)
                    .param("tenant_id", tenant_id.as_str())
                    .param("root_urns", string_list(root_keys))
                    .param("row_limit", i64::try_from(row_limit).unwrap_or(501)),
            )
            .await
            .map_err(context_backend)?;
        let mut phase_counts = BTreeMap::<String, usize>::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let root_key = row_string(&row, "root_urn")?;
            let Some(accumulator) = accumulators.get_mut(&root_key) else {
                return Err(ContextError::BackendUnavailable(
                    "legacy graph returned an unrequested root".to_owned(),
                ));
            };
            let count = phase_counts.entry(root_key).or_default();
            *count = count.saturating_add(1);
            if *count > limit {
                accumulator.truncated = true;
                continue;
            }
            let neighbor_urn = row_string(&row, "neighbor_urn")?;
            let neighbor = legacy_context_entity(
                tenant_id,
                &neighbor_urn,
                row_string(&row, "neighbor_kind")?,
                row_string(&row, "neighbor_label")?,
                row_string(&row, "neighbor_properties")?,
                row_string(&row, "neighbor_source_id")?,
                row_string(&row, "neighbor_runtime_id")?,
            )?;
            let relation = row_string(&row, "relation_kind")?;
            let from = row_string(&row, "from_urn")?;
            let to = row_string(&row, "to_urn")?;
            let edge_key = format!("{from}\0{relation}\0{to}");
            if accumulator.seen_edges.insert(edge_key) {
                accumulator.entities.insert(neighbor_urn, neighbor);
                accumulator.edges.push(legacy_context_edge(
                    tenant_id,
                    from,
                    relation,
                    to,
                    LegacyEdgeMetadata {
                        tenant_ids: row.get("relation_tenant_ids").map_err(context_decode)?,
                        runtime_ids: row.get("typed_runtime_ids").map_err(context_decode)?,
                        application_workspace_ids: row
                            .get("typed_application_workspace_ids")
                            .map_err(context_decode)?,
                        properties_values: row
                            .get("relation_properties_values")
                            .map_err(context_decode)?,
                    },
                )?);
            }
        }
        Ok(())
    }

    /// Executes a prepared lifecycle query against a current tenant projection.
    ///
    /// Before reading, the method requires a ready schema-v1 lifecycle projection
    /// at the current graph revision. It checks the revision again before return;
    /// [`IndexedLifecyclePage::graph_changed`] reports a concurrent revision so
    /// clients can discard or restart pagination.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LifecycleProjectionUnavailable`] for absent, stale,
    /// or rebuilding projection state. Backend failures and malformed projected
    /// records are returned as other [`StoreError`] variants.
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

    /// Rebuilds one tenant's lifecycle read model from organizational entities.
    ///
    /// The projection is marked unavailable before batches are rebuilt and ready
    /// only after the starting graph revision is rechecked. `batch_size` is
    /// clamped to `1..=1_000`. The return value is the number of entities rebuilt.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] if the graph revision changes before,
    /// during, or while publishing rebuild readiness. Neo4j failures are returned
    /// as [`StoreError::Neo4j`]. A failed rebuild remains unavailable to readers.
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

    /// Resolves a tenant-scoped lifecycle finding to exactly one affected resource.
    ///
    /// The finding URN must use the tenant's canonical lifecycle prefix. The
    /// projection must remain ready at one graph revision for the entire read;
    /// no match returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LifecycleProjectionUnavailable`] for stale or
    /// rebuilding state, [`StoreError::Conflict`] for invalid or ambiguous
    /// projected data, and [`StoreError::Neo4j`] for backend failures.
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

    /// Projects an admitted delta under its matching durable write receipt.
    ///
    /// Tenant identity and delta digest must match the receipt before any Neo4j
    /// mutation begins. Projection is idempotent at graph revision boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] when the receipt does not identify the
    /// delta or projected provenance is ambiguous, and [`StoreError::Neo4j`] for
    /// transaction failures.
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
                    "Neo4j readiness query exceeded 75 seconds".to_owned(),
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
                application_workspace_id: row_string(&row, "application_workspace_id")?,
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
            let mut missing_root_keys = Vec::new();
            for root_key in root_keys {
                let root = match self.resolve(tenant_id, root_key).await {
                    Ok(root) => root,
                    Err(ContextError::EntityNotFound) => {
                        missing_root_keys.push(root_key.clone());
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                neighborhoods.insert(
                    root_key.clone(),
                    self.expand(tenant_id, &root.entity_id, depth, limit)
                        .await?,
                );
            }
            if self
                .any_legacy_root_exists(tenant_id, &missing_root_keys)
                .await?
            {
                return Err(ContextError::BackendUnavailable(
                    "legacy graph compatibility supports depth one only".to_owned(),
                ));
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
            let application_workspace_ids: Vec<String> = row
                .get("application_workspace_ids")
                .map_err(context_decode)?;
            if !same_len(&[
                entity_ids.len(),
                entity_kinds.len(),
                authorities.len(),
                labels.len(),
                properties.len(),
            ]) || entity_ids.len() != assertion_ids.len().saturating_add(1)
                || !same_len(&[
                    assertion_ids.len(),
                    relations.len(),
                    runtime_ids.len(),
                    application_workspace_ids.len(),
                ])
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
                    application_workspace_id: application_workspace_ids[index].clone(),
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
                query("MATCH (source:OrganizationalEntity)-[edge:ORGANIZATIONAL_RELATION {tenant_id: $tenant_id, assertion_id: $assertion_id}]->(target:OrganizationalEntity) RETURN source.entity_id AS from_id, target.entity_id AS to_id, edge.relation AS relation, edge.source_runtime_id AS source_runtime_id, coalesce(edge.application_workspace_id, '') AS application_workspace_id")
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
            application_workspace_id: row_string(&row, "application_workspace_id")?,
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
                        application_workspace_id: row_string(
                            &row,
                            &format!("edge_{index}_application_workspace_id"),
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
        let mut missing_root_keys = Vec::new();
        while let Some(row) = stream.next().await.map_err(context_backend)? {
            let root_key = row_string(&row, "root_key")?;
            let match_count: i64 = row.get("match_count").map_err(context_decode)?;
            if match_count > 1 {
                return Err(ContextError::BackendUnavailable(format!(
                    "external entity key {root_key:?} is ambiguous"
                )));
            }
            if match_count == 0 {
                missing_root_keys.push(root_key);
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
                application_workspace_id: row_string(&row, "application_workspace_id")?,
                identity_binding: relation == "represents",
            };
            accumulator.entities.insert(from.entity_id.clone(), from);
            accumulator.entities.insert(to.entity_id.clone(), to);
            accumulator.edges.push(edge);
        }
        let mut neighborhoods = accumulators
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
            .collect::<BTreeMap<_, _>>();
        if !missing_root_keys.is_empty() {
            neighborhoods.extend(
                self.expand_legacy_one_hop_many(tenant_id, &missing_root_keys, limit)
                    .await?,
            );
        }
        Ok(neighborhoods)
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

#[derive(Clone, Copy)]
enum CatalogCursor<'a> {
    AgentKey(&'a str),
    EntityKind,
}

fn catalog_entity_match(filter: &EntityCatalogFilter, cursor: CatalogCursor<'_>) -> String {
    let single_exact_kind = filter.include_kind_prefixes.is_empty()
        && filter.include_kinds.len() == 1
        && !filter.include_kinds[0].is_empty();
    let mut properties = vec!["tenant_id: $tenant_id"];
    if !filter.application_workspace_id.is_empty() {
        properties.push("application_workspace_id: $application_workspace_id");
    }
    if !filter.exact_agent_key.is_empty() {
        properties.push("urn: $exact_key");
    }
    if !filter.source_id.is_empty() {
        properties.push("source_id: $source_id");
    }
    if single_exact_kind {
        properties.push("entity_type: $single_include_kind");
    }

    let mut predicates = Vec::new();
    if !filter.runtime_ids.is_empty() {
        predicates.push("entity.runtime_id IN $runtime_ids");
    }
    if !single_exact_kind
        && (!filter.include_kinds.is_empty() || !filter.include_kind_prefixes.is_empty())
    {
        predicates.push("(entity.entity_type IN $include_kinds OR any(prefix IN $include_prefixes WHERE entity.entity_type STARTS WITH prefix))");
    }
    if !filter.exclude_kinds.is_empty() {
        predicates.push("NOT entity.entity_type IN $exclude_kinds");
    }
    if !filter.exclude_kind_prefixes.is_empty() {
        predicates
            .push("none(prefix IN $exclude_prefixes WHERE entity.entity_type STARTS WITH prefix)");
    }
    if !filter.search.is_empty() {
        predicates.push("(toLower(coalesce(entity.urn, '') + ' ' + coalesce(entity.label, '')) CONTAINS $search OR ($search_attributes AND toLower(coalesce(entity.attributes_json, '')) CONTAINS $search))");
    }
    if !filter.attribute_substrings_any.is_empty() {
        predicates.push("any(fragment IN $attribute_substrings_any WHERE toLower(coalesce(entity.attributes_json, '')) CONTAINS fragment)");
    }
    match cursor {
        CatalogCursor::AgentKey(after_agent_key) if !after_agent_key.is_empty() => {
            predicates.push("entity.urn > $after_key");
        }
        CatalogCursor::EntityKind => predicates.push("entity.entity_type > $after_kind"),
        CatalogCursor::AgentKey(_) => {}
    }

    let mut statement = format!("MATCH (entity:Entity {{{}}})", properties.join(", "));
    if !predicates.is_empty() {
        statement.push_str(" WHERE ");
        statement.push_str(&predicates.join(" AND "));
    }
    statement
}

fn catalog_query(statement: &str, tenant_id: &TenantId, filter: &EntityCatalogFilter) -> Query {
    query(statement)
        .param("tenant_id", tenant_id.as_str())
        .param(
            "application_workspace_id",
            filter.application_workspace_id.as_str(),
        )
        .param("source_id", filter.source_id.as_str())
        .param("runtime_ids", string_list(&filter.runtime_ids))
        .param("exact_key", filter.exact_agent_key.as_str())
        .param("include_kinds", string_list(&filter.include_kinds))
        .param(
            "include_prefixes",
            string_list(&filter.include_kind_prefixes),
        )
        .param(
            "single_include_kind",
            filter.include_kinds.first().map_or("", String::as_str),
        )
        .param("exclude_kinds", string_list(&filter.exclude_kinds))
        .param(
            "exclude_prefixes",
            string_list(&filter.exclude_kind_prefixes),
        )
        .param("search", filter.search.to_lowercase())
        .param("search_attributes", filter.search_attributes)
        .param(
            "attribute_substrings_any",
            string_list(
                &filter
                    .attribute_substrings_any
                    .iter()
                    .map(|value| value.to_lowercase())
                    .collect::<Vec<_>>(),
            ),
        )
}

async fn catalog_relation_counts(
    transaction: &mut Txn,
    tenant_id: &TenantId,
    root_keys: &[String],
    application_workspace_id: &str,
    filter: &EntityCatalogRelationCountFilter,
) -> Result<Vec<EntityCatalogRelationCount>, StoreError> {
    if root_keys.is_empty() {
        return Ok(Vec::new());
    }
    let direction_names = filter
        .directions
        .iter()
        .map(|direction| match direction {
            EntityCatalogDirection::Incoming => "incoming".to_owned(),
            EntityCatalogDirection::Outgoing => "outgoing".to_owned(),
        })
        .collect::<Vec<_>>();
    let mut scope_rows = transaction
        .execute(
            query("UNWIND $root_keys AS root_key MATCH (root:Entity {tenant_id: $tenant_id, urn: root_key})-[edge:RELATION]-(neighbor:Entity) WHERE coalesce(edge.tenant_id, '') <> $tenant_id OR coalesce(neighbor.tenant_id, '') <> $tenant_id RETURN count(*) AS violations")
                .param("tenant_id", tenant_id.as_str())
                .param("root_keys", string_list(root_keys)),
        )
        .await?;
    let violations = catalog_row_u64(
        &scope_rows
            .next(transaction.handle())
            .await?
            .ok_or_else(|| {
                StoreError::Conflict(
                    "entity catalog relation-count scope returned no row".to_owned(),
                )
            })?,
        "violations",
    )?;
    drop(scope_rows);
    if violations != 0 {
        return Err(StoreError::Conflict(
            "entity catalog contains cross-tenant relation counts".to_owned(),
        ));
    }
    let statement =
        catalog_relation_count_statement(&filter.directions, !application_workspace_id.is_empty());

    let mut rows = transaction
        .execute(
            query(&statement)
                .param("tenant_id", tenant_id.as_str())
                .param("root_keys", string_list(root_keys))
                .param("application_workspace_id", application_workspace_id)
                .param("directions", string_list(&direction_names))
                .param("relations", string_list(&filter.relations))
                .param("neighbor_kinds", string_list(&filter.neighbor_kinds)),
        )
        .await?;
    let mut counts = Vec::new();
    while let Some(row) = rows.next(transaction.handle()).await? {
        let direction = match catalog_row_string(&row, "direction")?.as_str() {
            "incoming" => EntityCatalogDirection::Incoming,
            "outgoing" => EntityCatalogDirection::Outgoing,
            _ => {
                return Err(StoreError::Conflict(
                    "entity catalog relation-count direction is invalid".to_owned(),
                ));
            }
        };
        counts.push(EntityCatalogRelationCount {
            agent_key: catalog_row_string(&row, "agent_key")?,
            direction,
            relation: catalog_row_string(&row, "relation")?,
            neighbor_kind: catalog_row_string(&row, "neighbor_kind")?,
            count: catalog_row_u64(&row, "entity_count")?,
        });
    }
    Ok(counts)
}

fn catalog_relation_count_statement(
    directions: &[EntityCatalogDirection],
    application_workspace_scoped: bool,
) -> String {
    let workspace_property = if application_workspace_scoped {
        ", application_workspace_id: $application_workspace_id"
    } else {
        ""
    };
    match directions {
        [EntityCatalogDirection::Incoming] => format!(
            "UNWIND $root_keys AS root_key MATCH (neighbor:Entity {{tenant_id: $tenant_id{workspace_property}}})-[edge:RELATION {{tenant_id: $tenant_id{workspace_property}}}]->(root:Entity {{tenant_id: $tenant_id{workspace_property}, urn: root_key}}) WHERE edge.relation IN $relations AND neighbor.entity_type IN $neighbor_kinds WITH root, edge, neighbor, 'incoming' AS direction RETURN root.urn AS agent_key, direction, edge.relation AS relation, neighbor.entity_type AS neighbor_kind, count(DISTINCT neighbor) AS entity_count ORDER BY agent_key, direction, relation, neighbor_kind"
        ),
        [EntityCatalogDirection::Outgoing] => format!(
            "UNWIND $root_keys AS root_key MATCH (root:Entity {{tenant_id: $tenant_id{workspace_property}, urn: root_key}})-[edge:RELATION {{tenant_id: $tenant_id{workspace_property}}}]->(neighbor:Entity {{tenant_id: $tenant_id{workspace_property}}}) WHERE edge.relation IN $relations AND neighbor.entity_type IN $neighbor_kinds WITH root, edge, neighbor, 'outgoing' AS direction RETURN root.urn AS agent_key, direction, edge.relation AS relation, neighbor.entity_type AS neighbor_kind, count(DISTINCT neighbor) AS entity_count ORDER BY agent_key, direction, relation, neighbor_kind"
        ),
        _ => format!(
            "UNWIND $root_keys AS root_key MATCH (root:Entity {{tenant_id: $tenant_id{workspace_property}, urn: root_key}})-[edge:RELATION {{tenant_id: $tenant_id{workspace_property}}}]-(neighbor:Entity {{tenant_id: $tenant_id{workspace_property}}}) WHERE edge.relation IN $relations AND neighbor.entity_type IN $neighbor_kinds WITH root, edge, neighbor, CASE WHEN startNode(edge) = root THEN 'outgoing' ELSE 'incoming' END AS direction WHERE direction IN $directions RETURN root.urn AS agent_key, direction, edge.relation AS relation, neighbor.entity_type AS neighbor_kind, count(DISTINCT neighbor) AS entity_count ORDER BY agent_key, direction, relation, neighbor_kind"
        ),
    }
}

fn validate_catalog_request(
    tenant_id: &TenantId,
    filter: &EntityCatalogFilter,
    limit: usize,
    after_agent_key: &str,
) -> Result<(), StoreError> {
    if !(1..=500).contains(&limit) {
        return Err(StoreError::Conflict(
            "entity catalog limit must be between 1 and 500".to_owned(),
        ));
    }
    validate_catalog_text("source_id", &filter.source_id, 128, false)?;
    validate_catalog_text(
        "application_workspace_id",
        &filter.application_workspace_id,
        128,
        false,
    )?;
    validate_catalog_text("query", &filter.search, 512, false)?;
    validate_catalog_list("runtime_ids", &filter.runtime_ids, 100)?;
    validate_catalog_list("include_kinds", &filter.include_kinds, 500)?;
    validate_catalog_list("include_kind_prefixes", &filter.include_kind_prefixes, 500)?;
    validate_catalog_list("exclude_kinds", &filter.exclude_kinds, 500)?;
    validate_catalog_list("exclude_kind_prefixes", &filter.exclude_kind_prefixes, 500)?;
    validate_catalog_list(
        "attribute_substrings_any",
        &filter.attribute_substrings_any,
        64,
    )?;
    if let Some(counts) = &filter.relation_counts {
        validate_catalog_list("relation_count_relations", &counts.relations, 16)?;
        validate_catalog_list("relation_count_neighbor_kinds", &counts.neighbor_kinds, 32)?;
        if counts.directions.is_empty()
            || counts.relations.is_empty()
            || counts.neighbor_kinds.is_empty()
            || counts.directions.len() > 2
            || counts.directions.iter().collect::<BTreeSet<_>>().len() != counts.directions.len()
        {
            return Err(StoreError::Conflict(
                "entity catalog relation-count filter is incomplete or invalid".to_owned(),
            ));
        }
    }
    for (name, key) in [
        ("exact_agent_key", filter.exact_agent_key.as_str()),
        ("after_agent_key", after_agent_key),
    ] {
        validate_catalog_text(name, key, 4096, false)?;
        if !key.is_empty() && !key.starts_with(&format!("urn:cerebro:{}:", tenant_id.as_str())) {
            return Err(StoreError::Conflict(format!(
                "entity catalog {name} is not tenant scoped"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CatalogRelationCursor<'a> {
    agent_key: &'a str,
    relation: &'a str,
    direction: Option<EntityCatalogDirection>,
}

#[allow(clippy::too_many_arguments)]
fn validate_catalog_relation_request(
    tenant_id: &TenantId,
    agent_key: &str,
    directions: &[EntityCatalogDirection],
    relations: &[String],
    neighbor_kinds: &[String],
    neighbor_agent_keys: &[String],
    neighbor_application_workspace_id: &str,
    limit: usize,
    cursor: CatalogRelationCursor<'_>,
) -> Result<(), StoreError> {
    validate_catalog_request(
        tenant_id,
        &EntityCatalogFilter::default(),
        limit,
        cursor.agent_key,
    )?;
    validate_catalog_text("agent_key", agent_key, 4096, true)?;
    if !agent_key.starts_with(&format!("urn:cerebro:{}:", tenant_id.as_str())) {
        return Err(StoreError::Conflict(
            "entity catalog agent_key is not tenant scoped".to_owned(),
        ));
    }
    validate_catalog_list("relations", relations, 64)?;
    validate_catalog_list("neighbor_kinds", neighbor_kinds, 500)?;
    validate_catalog_list("neighbor_agent_keys", neighbor_agent_keys, 500)?;
    validate_catalog_text(
        "neighbor_application_workspace_id",
        neighbor_application_workspace_id,
        128,
        false,
    )?;
    let tenant_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
    if neighbor_agent_keys
        .iter()
        .any(|key| !key.starts_with(&tenant_prefix))
    {
        return Err(StoreError::Conflict(
            "entity catalog neighbor_agent_keys are not tenant scoped".to_owned(),
        ));
    }
    if directions.len() > 2 || directions.iter().collect::<BTreeSet<_>>().len() != directions.len()
    {
        return Err(StoreError::Conflict(
            "entity catalog directions are invalid".to_owned(),
        ));
    }
    validate_catalog_text("after_relation", cursor.relation, 128, false)?;
    let cursor_fields = (
        !cursor.agent_key.is_empty(),
        !cursor.relation.is_empty(),
        cursor.direction.is_some(),
    );
    if cursor_fields != (false, false, false) && cursor_fields != (true, true, true) {
        return Err(StoreError::Conflict(
            "entity catalog relation cursor is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn effective_access_path_statement() -> &'static str {
    r#"MATCH (subject:Entity {tenant_id: $tenant_id})
WHERE ($identity_urn = '' OR subject.urn = $identity_urn)
  AND ($identity_query = ''
       OR toLower(coalesce(subject.urn, '')) CONTAINS $identity_query
       OR toLower(coalesce(subject.label, '')) CONTAINS $identity_query
       OR toLower(coalesce(subject.attributes_json, '')) CONTAINS $identity_query)
WITH subject
ORDER BY subject.label, subject.urn
LIMIT $sample_limit
CALL {
  WITH subject
  RETURN subject AS principal, [] AS identity_rels, [subject] AS identity_nodes
  UNION
  WITH subject
  MATCH (principal:Entity {tenant_id: $tenant_id})-[identity_link:RELATION]->(subject)
  WHERE identity_link.tenant_id = $tenant_id
    AND identity_link.relation IN ['represents_identity', 'same_actor']
  RETURN principal, [identity_link] AS identity_rels, [subject, principal] AS identity_nodes
  UNION
  WITH subject
  MATCH (subject)-[identity_link:RELATION]->(principal:Entity {tenant_id: $tenant_id})
  WHERE identity_link.tenant_id = $tenant_id
    AND identity_link.relation = 'same_actor'
  RETURN principal, [identity_link] AS identity_rels, [subject, principal] AS identity_nodes
  UNION
  WITH subject
  MATCH (subject)-[subject_link:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})<-[principal_link:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
  WHERE subject_link.tenant_id = $tenant_id
    AND principal_link.tenant_id = $tenant_id
  RETURN principal, [subject_link, principal_link] AS identity_rels, [subject, identity, principal] AS identity_nodes
  UNION
  WITH subject
  MATCH (subject)-[same_actor:RELATION {relation: 'same_actor'}]-(identity:Entity {tenant_id: $tenant_id})<-[principal_link:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
  WHERE same_actor.tenant_id = $tenant_id
    AND principal_link.tenant_id = $tenant_id
  RETURN principal, [same_actor, principal_link] AS identity_rels, [subject, identity, principal] AS identity_nodes
}
WITH DISTINCT subject, principal, identity_rels, identity_nodes
WHERE principal.tenant_id = $tenant_id
CALL {
  WITH subject, principal
  MATCH (principal)-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE assignment.tenant_id = $tenant_id
    AND target.entity_type ENDS WITH '.application'
    AND ($application_urn = '' OR target.urn = $application_urn)
  MATCH (target)-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  RETURN null AS mediator, target, entitlement, capability,
         'direct_app_assignment' AS assignment_kind,
         [assignment, grant, confers] AS rels,
         [principal, target, entitlement, capability] AS path_nodes
  UNION
  WITH subject, principal
  MATCH (principal)-[membership:RELATION {relation: 'member_of'}]->(mediator:Entity {tenant_id: $tenant_id})-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE membership.tenant_id = $tenant_id
    AND assignment.tenant_id = $tenant_id
    AND target.entity_type ENDS WITH '.application'
    AND ($application_urn = '' OR target.urn = $application_urn)
  MATCH (target)-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  RETURN mediator, target, entitlement, capability,
         'group_app_assignment' AS assignment_kind,
         [membership, assignment, grant, confers] AS rels,
         [principal, mediator, target, entitlement, capability] AS path_nodes
  UNION
  WITH subject, principal
  MATCH (principal)-[role_assignment:RELATION]->(target:Entity {tenant_id: $tenant_id})-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE $application_urn = ''
    AND role_assignment.tenant_id = $tenant_id
    AND role_assignment.relation IN ['assigned_to', 'can_admin']
    AND grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND (target.entity_type ENDS WITH '.role' OR target.entity_type ENDS WITH '.admin_role')
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  RETURN null AS mediator, target, entitlement, capability,
         CASE WHEN role_assignment.relation = 'can_admin' THEN 'admin_role_assignment' ELSE 'role_assignment' END AS assignment_kind,
         [role_assignment, grant, confers] AS rels,
         [principal, target, entitlement, capability] AS path_nodes
}
RETURN subject.urn AS identity_key,
       coalesce(subject.entity_type, 'unknown') AS identity_kind,
       coalesce(subject.label, subject.urn) AS identity_label,
       coalesce(subject.attributes_json, '{}') AS identity_properties,
       coalesce(subject.source_id, '') AS identity_source_id,
       coalesce(subject.runtime_id, '') AS identity_runtime_id,
       principal.urn AS principal_key,
       coalesce(principal.entity_type, 'unknown') AS principal_kind,
       coalesce(principal.label, principal.urn) AS principal_label,
       coalesce(principal.attributes_json, '{}') AS principal_properties,
       coalesce(principal.source_id, '') AS principal_source_id,
       coalesce(principal.runtime_id, '') AS principal_runtime_id,
       coalesce(mediator.urn, '') AS mediator_key,
       coalesce(mediator.entity_type, '') AS mediator_kind,
       coalesce(mediator.label, '') AS mediator_label,
       coalesce(mediator.attributes_json, '{}') AS mediator_properties,
       coalesce(mediator.source_id, '') AS mediator_source_id,
       coalesce(mediator.runtime_id, '') AS mediator_runtime_id,
       target.urn AS target_key,
       coalesce(target.entity_type, 'unknown') AS target_kind,
       coalesce(target.label, target.urn) AS target_label,
       coalesce(target.attributes_json, '{}') AS target_properties,
       coalesce(target.source_id, '') AS target_source_id,
       coalesce(target.runtime_id, '') AS target_runtime_id,
       entitlement.urn AS entitlement_key,
       coalesce(entitlement.entity_type, 'unknown') AS entitlement_kind,
       coalesce(entitlement.label, entitlement.urn) AS entitlement_label,
       coalesce(entitlement.attributes_json, '{}') AS entitlement_properties,
       coalesce(entitlement.source_id, '') AS entitlement_source_id,
       coalesce(entitlement.runtime_id, '') AS entitlement_runtime_id,
       capability.urn AS capability_key,
       coalesce(capability.entity_type, 'unknown') AS capability_kind,
       coalesce(capability.label, capability.urn) AS capability_label,
       coalesce(capability.attributes_json, '{}') AS capability_properties,
       coalesce(capability.source_id, '') AS capability_source_id,
       coalesce(capability.runtime_id, '') AS capability_runtime_id,
       assignment_kind,
       [rel IN identity_rels | rel.relation] AS identity_relation_chain,
       [idx IN range(0, size(identity_rels) - 1) | identity_nodes[idx].urn] AS identity_edge_from_urns,
       [idx IN range(0, size(identity_rels) - 1) | coalesce(identity_nodes[idx].entity_type, 'unknown')] AS identity_edge_from_kinds,
       [idx IN range(0, size(identity_rels) - 1) | coalesce(identity_nodes[idx].label, identity_nodes[idx].urn)] AS identity_edge_from_labels,
       [idx IN range(0, size(identity_rels) - 1) | identity_nodes[idx + 1].urn] AS identity_edge_to_urns,
       [idx IN range(0, size(identity_rels) - 1) | coalesce(identity_nodes[idx + 1].entity_type, 'unknown')] AS identity_edge_to_kinds,
       [idx IN range(0, size(identity_rels) - 1) | coalesce(identity_nodes[idx + 1].label, identity_nodes[idx + 1].urn)] AS identity_edge_to_labels,
       [rel IN identity_rels | coalesce(rel.source_id, '')] AS identity_edge_source_ids,
       [rel IN identity_rels | coalesce(rel.runtime_id, '')] AS identity_edge_runtime_ids,
       [rel IN identity_rels | coalesce(rel.attributes_json, '{}')] AS identity_edge_attributes,
       [rel IN rels | rel.relation] AS relation_chain,
       [idx IN range(0, size(rels) - 1) | path_nodes[idx].urn] AS edge_from_urns,
       [idx IN range(0, size(rels) - 1) | coalesce(path_nodes[idx].entity_type, 'unknown')] AS edge_from_kinds,
       [idx IN range(0, size(rels) - 1) | coalesce(path_nodes[idx].label, path_nodes[idx].urn)] AS edge_from_labels,
       [idx IN range(0, size(rels) - 1) | path_nodes[idx + 1].urn] AS edge_to_urns,
       [idx IN range(0, size(rels) - 1) | coalesce(path_nodes[idx + 1].entity_type, 'unknown')] AS edge_to_kinds,
       [idx IN range(0, size(rels) - 1) | coalesce(path_nodes[idx + 1].label, path_nodes[idx + 1].urn)] AS edge_to_labels,
       [rel IN rels | coalesce(rel.source_id, '')] AS edge_source_ids,
       [rel IN rels | coalesce(rel.runtime_id, '')] AS edge_runtime_ids,
       [rel IN rels | coalesce(rel.attributes_json, '{}')] AS edge_attributes
ORDER BY identity_label, principal_label, assignment_kind, target_label, entitlement_label, capability_label
LIMIT $row_limit"#
}

fn validate_effective_access_request(
    tenant_id: &TenantId,
    identity_urn: &str,
    identity_query: &str,
    application_urn: &str,
    capability_urn: &str,
    capability_id: &str,
    limit: usize,
) -> Result<(), StoreError> {
    if !(1..=100).contains(&limit) {
        return Err(StoreError::Conflict(
            "effective access path limit must be between 1 and 100".to_owned(),
        ));
    }
    validate_catalog_text("identity_urn", identity_urn, 4096, false)?;
    validate_catalog_text("identity_query", identity_query, 512, false)?;
    validate_catalog_text("application_urn", application_urn, 4096, false)?;
    validate_catalog_text("capability_urn", capability_urn, 4096, false)?;
    validate_catalog_text("capability_id", capability_id, 256, false)?;
    if identity_urn.is_empty() && identity_query.is_empty() {
        return Err(StoreError::Conflict(
            "effective access identity selector is required".to_owned(),
        ));
    }
    let tenant_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
    for (name, urn) in [
        ("identity_urn", identity_urn),
        ("application_urn", application_urn),
        ("capability_urn", capability_urn),
    ] {
        if !urn.is_empty() && !urn.starts_with(&tenant_prefix) {
            return Err(StoreError::Conflict(format!(
                "effective access {name} is not tenant scoped"
            )));
        }
    }
    Ok(())
}

fn effective_access_path_from_row(
    tenant_id: &TenantId,
    row: &Row,
) -> Result<EffectiveAccessPath, StoreError> {
    let mediator = if catalog_row_string(row, "mediator_key")?.is_empty() {
        None
    } else {
        Some(legacy_context_entity_from_row_prefix(
            tenant_id, row, "mediator",
        )?)
    };
    let identity_relation_chain = catalog_row_string_list(row, "identity_relation_chain")?;
    let relation_chain = catalog_row_string_list(row, "relation_chain")?;
    let path = EffectiveAccessPath {
        identity: legacy_context_entity_from_row_prefix(tenant_id, row, "identity")?,
        principal: legacy_context_entity_from_row_prefix(tenant_id, row, "principal")?,
        mediator,
        access_target: legacy_context_entity_from_row_prefix(tenant_id, row, "target")?,
        entitlement: legacy_context_entity_from_row_prefix(tenant_id, row, "entitlement")?,
        capability: legacy_context_entity_from_row_prefix(tenant_id, row, "capability")?,
        assignment_kind: catalog_row_string(row, "assignment_kind")?,
        identity_edges: effective_access_edges_from_row(
            tenant_id,
            row,
            "identity_edge",
            &identity_relation_chain,
        )?,
        identity_relation_chain,
        edges: effective_access_edges_from_row(tenant_id, row, "edge", &relation_chain)?,
        relation_chain,
    };
    validate_effective_access_path(tenant_id, &path)?;
    Ok(path)
}

fn effective_access_edges_from_row(
    tenant_id: &TenantId,
    row: &Row,
    prefix: &str,
    relations: &[String],
) -> Result<Vec<EffectiveAccessPathEdge>, StoreError> {
    let from_urns = catalog_row_string_list(row, &format!("{prefix}_from_urns"))?;
    let from_kinds = catalog_row_string_list(row, &format!("{prefix}_from_kinds"))?;
    let from_labels = catalog_row_string_list(row, &format!("{prefix}_from_labels"))?;
    let to_urns = catalog_row_string_list(row, &format!("{prefix}_to_urns"))?;
    let to_kinds = catalog_row_string_list(row, &format!("{prefix}_to_kinds"))?;
    let to_labels = catalog_row_string_list(row, &format!("{prefix}_to_labels"))?;
    let source_ids = catalog_row_string_list(row, &format!("{prefix}_source_ids"))?;
    let runtime_ids = catalog_row_string_list(row, &format!("{prefix}_runtime_ids"))?;
    let attributes = catalog_row_string_list(row, &format!("{prefix}_attributes"))?;
    if !same_len(&[
        from_urns.len(),
        from_kinds.len(),
        from_labels.len(),
        to_urns.len(),
        to_kinds.len(),
        to_labels.len(),
        source_ids.len(),
        runtime_ids.len(),
        attributes.len(),
        relations.len(),
    ]) {
        return Err(StoreError::Conflict(
            "effective access edge fields are misaligned".to_owned(),
        ));
    }
    let mut edges = Vec::with_capacity(from_urns.len());
    for index in 0..from_urns.len() {
        validate_catalog_text(
            "effective access edge attributes",
            &attributes[index],
            16_384,
            false,
        )?;
        edges.push(EffectiveAccessPathEdge {
            from: legacy_context_entity(
                tenant_id,
                &from_urns[index],
                from_kinds[index].clone(),
                from_labels[index].clone(),
                "{}".to_owned(),
                String::new(),
                String::new(),
            )
            .map_err(|error| StoreError::Conflict(error.to_string()))?,
            relation: relations[index].clone(),
            to: legacy_context_entity(
                tenant_id,
                &to_urns[index],
                to_kinds[index].clone(),
                to_labels[index].clone(),
                "{}".to_owned(),
                String::new(),
                String::new(),
            )
            .map_err(|error| StoreError::Conflict(error.to_string()))?,
            source_id: source_ids[index].clone(),
            runtime_id: runtime_ids[index].clone(),
            attributes_json: attributes[index].clone(),
        });
    }
    Ok(edges)
}

fn validate_effective_access_path(
    tenant_id: &TenantId,
    path: &EffectiveAccessPath,
) -> Result<(), StoreError> {
    let tenant_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
    if path.identity_relation_chain.len() != path.identity_edges.len()
        || path.relation_chain.len() != path.edges.len()
        || path.relation_chain.is_empty()
    {
        return Err(StoreError::Conflict(
            "effective access relation and edge chains are misaligned".to_owned(),
        ));
    }
    for (edge, relation) in path
        .identity_edges
        .iter()
        .zip(path.identity_relation_chain.iter())
    {
        if !matches!(relation.as_str(), "same_actor" | "represents_identity") {
            return Err(StoreError::Conflict(
                "effective access identity relation is outside the whitelist".to_owned(),
            ));
        }
        if !edge.from.agent_key.starts_with(&tenant_prefix)
            || !edge.to.agent_key.starts_with(&tenant_prefix)
        {
            return Err(StoreError::Conflict(
                "effective access identity edge escaped tenant scope".to_owned(),
            ));
        }
    }
    let expected: &[&str] = match path.assignment_kind.as_str() {
        "direct_app_assignment" => &["assigned_to", "grants_entitlement", "confers_capability"],
        "group_app_assignment" => &[
            "member_of",
            "assigned_to",
            "grants_entitlement",
            "confers_capability",
        ],
        "role_assignment" => &["assigned_to", "grants_entitlement", "confers_capability"],
        "admin_role_assignment" => &["can_admin", "grants_entitlement", "confers_capability"],
        _ => {
            return Err(StoreError::Conflict(
                "effective access assignment kind is invalid".to_owned(),
            ));
        }
    };
    if path
        .relation_chain
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected
    {
        return Err(StoreError::Conflict(
            "effective access relation chain is outside the whitelist".to_owned(),
        ));
    }
    if path.edges.iter().any(|edge| {
        !edge.from.agent_key.starts_with(&tenant_prefix)
            || !edge.to.agent_key.starts_with(&tenant_prefix)
    }) {
        return Err(StoreError::Conflict(
            "effective access edge escaped tenant scope".to_owned(),
        ));
    }
    Ok(())
}

fn validate_person_access_request(
    tenant_id: &TenantId,
    person_urn: &str,
    person_query: &str,
    limit: usize,
    depth: usize,
) -> Result<(), StoreError> {
    if !(1..=100).contains(&limit) {
        return Err(StoreError::Conflict(
            "person access path limit must be between 1 and 100".to_owned(),
        ));
    }
    if !(1..=4).contains(&depth) {
        return Err(StoreError::Conflict(
            "person access path depth must be between 1 and 4".to_owned(),
        ));
    }
    validate_catalog_text("person_urn", person_urn, 4096, false)?;
    validate_catalog_text("person_query", person_query, 512, false)?;
    if person_urn.is_empty() && person_query.is_empty() {
        return Err(StoreError::Conflict(
            "person access path selector is required".to_owned(),
        ));
    }
    if !person_urn.is_empty()
        && !person_urn.starts_with(&format!("urn:cerebro:{}:", tenant_id.as_str()))
    {
        return Err(StoreError::Conflict(
            "person access path person_urn is not tenant scoped".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cloud_attack_path_request(
    account_id: &str,
    runtime_id: &str,
    limit: usize,
    depth: usize,
) -> Result<(), StoreError> {
    if !(1..=100).contains(&limit) {
        return Err(StoreError::Conflict(
            "cloud attack path limit must be between 1 and 100".to_owned(),
        ));
    }
    if !(1..=6).contains(&depth) {
        return Err(StoreError::Conflict(
            "cloud attack path depth must be between 1 and 6".to_owned(),
        ));
    }
    validate_catalog_text("account_id", account_id, 256, false)?;
    validate_catalog_text("runtime_id", runtime_id, 256, false)?;
    Ok(())
}

fn cloud_attack_path_traversal_relations() -> Vec<String> {
    vec![
        "assigned_to".to_owned(),
        "attached_to".to_owned(),
        "can_assume".to_owned(),
        "can_impersonate".to_owned(),
        "depends_on".to_owned(),
        "member_of".to_owned(),
        "runs_as".to_owned(),
    ]
}

fn cloud_attack_path_access_relations() -> Vec<String> {
    vec![
        "can_admin".to_owned(),
        "can_perform".to_owned(),
        "can_assume".to_owned(),
        "can_impersonate".to_owned(),
    ]
}

fn cloud_attack_path_counts_statement(depth: usize, relation_type: &str) -> String {
    format!(
        "{}\nRETURN count(*) AS path_count, count(DISTINCT exposed) AS exposed_resource_count, count(DISTINCT principal) AS privileged_principal_count, count(DISTINCT account) AS cloud_account_count",
        cloud_attack_path_pattern(depth, relation_type)
    )
}

fn cloud_attack_path_samples_statement(depth: usize, relation_type: &str) -> String {
    format!(
        r#"{}
CALL {{
  WITH exposed
  OPTIONAL MATCH (exposed)-[ownership:__RELATION_TYPE__ {{tenant_id: $tenant_id, relation: 'owned_by'}}]->(candidate_owner:Entity {{tenant_id: $tenant_id}})
  WHERE $runtime_id = '' OR ownership.runtime_id = $runtime_id
  WITH exposed, candidate_owner, collect(ownership) AS ownership_assertions
  WITH exposed, candidate_owner, head(ownership_assertions) AS ownership,
       [assertion IN ownership_assertions WHERE assertion.runtime_id IS NOT NULL | assertion.runtime_id] AS ownership_assertion_runtime_ids
  ORDER BY candidate_owner.urn, candidate_owner.entity_type, candidate_owner.label
  WITH [item IN collect({{
    owner_urn: candidate_owner.urn,
    owner_entity_type: candidate_owner.entity_type,
    owner_label: candidate_owner.label,
    from_urn: exposed.urn,
    from_entity_type: exposed.entity_type,
    from_label: exposed.label,
    relation: ownership.relation,
    to_urn: candidate_owner.urn,
    to_entity_type: candidate_owner.entity_type,
    to_label: candidate_owner.label,
    direction: 'forward',
    source_id: ownership.source_id,
    source_runtime_id: ownership.runtime_id,
    assertion_runtime_ids: ownership_assertion_runtime_ids,
    attributes_json: ownership.attributes_json
  }}) WHERE item.owner_urn IS NOT NULL] AS ownerships
  RETURN [item IN ownerships | coalesce(item.owner_urn, '')] AS ownership_owner_urns,
         [item IN ownerships | coalesce(item.owner_entity_type, 'unknown')] AS ownership_owner_entity_types,
         [item IN ownerships | coalesce(item.owner_label, item.owner_urn)] AS ownership_owner_labels,
         [item IN ownerships | coalesce(item.from_urn, '')] AS ownership_from_urns,
         [item IN ownerships | coalesce(item.from_entity_type, 'unknown')] AS ownership_from_entity_types,
         [item IN ownerships | coalesce(item.from_label, item.from_urn)] AS ownership_from_labels,
         [item IN ownerships | coalesce(item.relation, '')] AS ownership_relations,
         [item IN ownerships | coalesce(item.to_urn, '')] AS ownership_to_urns,
         [item IN ownerships | coalesce(item.to_entity_type, 'unknown')] AS ownership_to_entity_types,
         [item IN ownerships | coalesce(item.to_label, item.to_urn)] AS ownership_to_labels,
         [item IN ownerships | coalesce(item.direction, '')] AS ownership_directions,
         [item IN ownerships | coalesce(item.source_id, '')] AS ownership_source_ids,
         [item IN ownerships | coalesce(item.source_runtime_id, '')] AS ownership_source_runtime_ids,
         [item IN ownerships | reduce(text = '', id IN item.assertion_runtime_ids | text + CASE WHEN text = '' THEN '' ELSE '\u001f' END + coalesce(id, ''))] AS ownership_assertion_runtime_id_sets,
         [item IN ownerships | coalesce(item.attributes_json, '{{}}')] AS ownership_attributes_jsons
}}
RETURN public.urn AS public_urn,
       coalesce(public.entity_type, 'unknown') AS public_entity_type,
       coalesce(public.label, public.urn) AS public_label,
       exposed.urn AS exposed_urn,
       coalesce(exposed.entity_type, 'unknown') AS exposed_entity_type,
       coalesce(exposed.label, exposed.urn) AS exposed_label,
       account.urn AS account_urn,
       coalesce(account.entity_type, 'unknown') AS account_entity_type,
       coalesce(account.label, account.urn) AS account_label,
       principal.urn AS principal_urn,
       coalesce(principal.entity_type, 'unknown') AS principal_entity_type,
       coalesce(principal.label, principal.urn) AS principal_label,
       permission.urn AS permission_urn,
       coalesce(permission.entity_type, 'unknown') AS permission_entity_type,
       coalesce(permission.label, permission.urn) AS permission_label,
       ownership_owner_urns, ownership_owner_entity_types, ownership_owner_labels,
       ownership_from_urns, ownership_from_entity_types, ownership_from_labels, ownership_relations,
       ownership_to_urns, ownership_to_entity_types, ownership_to_labels, ownership_directions,
       ownership_source_ids, ownership_source_runtime_ids, ownership_assertion_runtime_id_sets, ownership_attributes_jsons,
       reach.relation AS reach_relation,
       access.relation AS access_relation,
       proof_relations AS relation_chain,
       public.urn AS exposure_from_urn,
       coalesce(public.entity_type, 'unknown') AS exposure_from_entity_type,
       coalesce(public.label, public.urn) AS exposure_from_label,
       reach.relation AS exposure_relation,
       exposed.urn AS exposure_to_urn,
       coalesce(exposed.entity_type, 'unknown') AS exposure_to_entity_type,
       coalesce(exposed.label, exposed.urn) AS exposure_to_label,
       'forward' AS exposure_direction,
       coalesce(reach.source_id, '') AS exposure_source_id,
       coalesce(reach.runtime_id, '') AS exposure_source_runtime_id,
       [id IN reach_assertion_runtime_ids WHERE id IS NOT NULL | id] AS exposure_assertion_runtime_ids,
       coalesce(reach.attributes_json, '{{}}') AS exposure_attributes_json,
       exposed.urn AS resource_account_from_urn,
       coalesce(exposed.entity_type, 'unknown') AS resource_account_from_entity_type,
       coalesce(exposed.label, exposed.urn) AS resource_account_from_label,
       resource_account.relation AS resource_account_relation,
       account.urn AS resource_account_to_urn,
       coalesce(account.entity_type, 'unknown') AS resource_account_to_entity_type,
       coalesce(account.label, account.urn) AS resource_account_to_label,
       'forward' AS resource_account_direction,
       coalesce(resource_account.source_id, '') AS resource_account_source_id,
       coalesce(resource_account.runtime_id, '') AS resource_account_source_runtime_id,
       [id IN resource_account_assertion_runtime_ids WHERE id IS NOT NULL | id] AS resource_account_assertion_runtime_ids,
       coalesce(resource_account.attributes_json, '{{}}') AS resource_account_attributes_json,
       [idx IN range(0, length(proof_path) - 1) | nodes(proof_path)[idx].urn] AS traversal_from_urns,
       [idx IN range(0, length(proof_path) - 1) | coalesce(nodes(proof_path)[idx].entity_type, 'unknown')] AS traversal_from_entity_types,
       [idx IN range(0, length(proof_path) - 1) | coalesce(nodes(proof_path)[idx].label, nodes(proof_path)[idx].urn)] AS traversal_from_labels,
       [idx IN range(0, length(proof_path) - 1) | relationships(proof_path)[idx].relation] AS traversal_relations,
       [idx IN range(0, length(proof_path) - 1) | nodes(proof_path)[idx + 1].urn] AS traversal_to_urns,
       [idx IN range(0, length(proof_path) - 1) | coalesce(nodes(proof_path)[idx + 1].entity_type, 'unknown')] AS traversal_to_entity_types,
       [idx IN range(0, length(proof_path) - 1) | coalesce(nodes(proof_path)[idx + 1].label, nodes(proof_path)[idx + 1].urn)] AS traversal_to_labels,
       [idx IN range(0, length(proof_path) - 1) | CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END] AS traversal_directions,
       [idx IN range(0, length(proof_path) - 1) | coalesce(relationships(proof_path)[idx].source_id, '')] AS traversal_source_ids,
       [idx IN range(0, length(proof_path) - 1) | coalesce(relationships(proof_path)[idx].runtime_id, '')] AS traversal_source_runtime_ids,
       [ids IN traversal_assertion_runtime_ids | reduce(text = '', id IN ids | text + CASE WHEN text = '' THEN '' ELSE '\u001f' END + coalesce(id, ''))] AS traversal_assertion_runtime_id_sets,
       [idx IN range(0, length(proof_path) - 1) | coalesce(relationships(proof_path)[idx].attributes_json, '{{}}')] AS traversal_attributes_jsons,
       principal.urn AS privilege_from_urn,
       coalesce(principal.entity_type, 'unknown') AS privilege_from_entity_type,
       coalesce(principal.label, principal.urn) AS privilege_from_label,
       access.relation AS privilege_relation,
       permission.urn AS privilege_to_urn,
       coalesce(permission.entity_type, 'unknown') AS privilege_to_entity_type,
       coalesce(permission.label, permission.urn) AS privilege_to_label,
       'forward' AS privilege_direction,
       coalesce(access.source_id, '') AS privilege_source_id,
       coalesce(access.runtime_id, '') AS privilege_source_runtime_id,
       [id IN access_assertion_runtime_ids WHERE id IS NOT NULL | id] AS privilege_assertion_runtime_ids,
       coalesce(access.attributes_json, '{{}}') AS privilege_attributes_json,
       permission.urn AS permission_account_from_urn,
       coalesce(permission.entity_type, 'unknown') AS permission_account_from_entity_type,
       coalesce(permission.label, permission.urn) AS permission_account_from_label,
       permission_account.relation AS permission_account_relation,
       account.urn AS permission_account_to_urn,
       coalesce(account.entity_type, 'unknown') AS permission_account_to_entity_type,
       coalesce(account.label, account.urn) AS permission_account_to_label,
       'forward' AS permission_account_direction,
       coalesce(permission_account.source_id, '') AS permission_account_source_id,
       coalesce(permission_account.runtime_id, '') AS permission_account_source_runtime_id,
       [id IN permission_account_assertion_runtime_ids WHERE id IS NOT NULL | id] AS permission_account_assertion_runtime_ids,
       coalesce(permission_account.attributes_json, '{{}}') AS permission_account_attributes_json
ORDER BY account.label, exposed.label, principal.label, permission.label
LIMIT $row_limit"#,
        cloud_attack_path_pattern(depth, relation_type)
    )
    .replace("__RELATION_TYPE__", relation_type)
}

fn cloud_attack_path_pattern(depth: usize, relation_type: &str) -> String {
    let pattern = r#"MATCH (public:Entity {tenant_id: $tenant_id})-[reach:__RELATION_TYPE__ {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[resource_account:__RELATION_TYPE__ {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id)
MATCH proof_path = (exposed)-[:__RELATION_TYPE__*1..__DEPTH__]-(principal:Entity {tenant_id: $tenant_id})
WHERE all(node IN nodes(proof_path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(proof_path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $traversal_relations)
  AND all(idx IN range(0, length(proof_path) - 1) WHERE
    (
      relationships(proof_path)[idx].relation = 'member_of'
      AND startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx + 1]
    )
    OR (
      relationships(proof_path)[idx].relation <> 'member_of'
      AND startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx]
    )
  )
MATCH (principal)-[access:__RELATION_TYPE__]->(permission:Entity {tenant_id: $tenant_id})-[permission_account:__RELATION_TYPE__ {relation: 'belongs_to'}]->(account)
WHERE access.relation IN $access_relations
  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
  )
  AND ($runtime_id = '' OR (
    reach.runtime_id = $runtime_id
    AND resource_account.runtime_id = $runtime_id
    AND access.runtime_id = $runtime_id
    AND permission_account.runtime_id = $runtime_id
    AND all(rel IN relationships(proof_path) WHERE rel.runtime_id = $runtime_id)
  ))
WITH public, reach, exposed, resource_account, account, principal, access, permission, permission_account, proof_path,
     reach.relation AS reach_relation, access.relation AS access_relation,
     [node IN nodes(proof_path) | node.urn] AS proof_node_urns,
     [rel IN relationships(proof_path) | rel.relation] AS proof_relations,
     [idx IN range(0, length(proof_path) - 1) |
       CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END
     ] AS proof_directions
ORDER BY length(proof_path), principal.label, principal.urn, permission.label, permission.urn,
         reach.runtime_id, resource_account.runtime_id, access.runtime_id, permission_account.runtime_id
WITH public, exposed, account, principal, permission, reach_relation, access_relation,
     proof_node_urns, proof_relations, proof_directions,
     collect(reach) AS reach_assertions,
     collect(resource_account) AS resource_account_assertions,
     collect(access) AS access_assertions,
     collect(permission_account) AS permission_account_assertions,
     collect(proof_path) AS proof_paths
WITH public, exposed, account, principal, permission, reach_relation, access_relation, proof_relations,
     head(reach_assertions) AS reach,
     head(resource_account_assertions) AS resource_account,
     head(access_assertions) AS access,
     head(permission_account_assertions) AS permission_account,
     head(proof_paths) AS proof_path,
     [assertion IN reach_assertions WHERE assertion.runtime_id IS NOT NULL | assertion.runtime_id] AS reach_assertion_runtime_ids,
     [assertion IN resource_account_assertions WHERE assertion.runtime_id IS NOT NULL | assertion.runtime_id] AS resource_account_assertion_runtime_ids,
     [assertion IN access_assertions WHERE assertion.runtime_id IS NOT NULL | assertion.runtime_id] AS access_assertion_runtime_ids,
     [assertion IN permission_account_assertions WHERE assertion.runtime_id IS NOT NULL | assertion.runtime_id] AS permission_account_assertion_runtime_ids,
     [idx IN range(0, size(proof_relations) - 1) |
       [candidate_path IN proof_paths WHERE relationships(candidate_path)[idx].runtime_id IS NOT NULL | relationships(candidate_path)[idx].runtime_id]
     ] AS traversal_assertion_runtime_ids"#;
    pattern
        .replace("__RELATION_TYPE__", relation_type)
        .replace("__DEPTH__", &depth.to_string())
}

fn validate_catalog_list(name: &str, values: &[String], max: usize) -> Result<(), StoreError> {
    if values.len() > max {
        return Err(StoreError::Conflict(format!(
            "entity catalog {name} exceeds its bound"
        )));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_catalog_text(name, value, 256, true)?;
        if !seen.insert(value) {
            return Err(StoreError::Conflict(format!(
                "entity catalog {name} contains duplicates"
            )));
        }
    }
    Ok(())
}

fn compliance_impact_query(statement: &'static str, tenant_id: &TenantId) -> Query {
    query(statement)
        .param("tenant_id", tenant_id.as_str())
        .param("entity_kind", EntityKind::ComplianceImpactRevision.as_str())
        .param("relation", RelationKind::ComplianceDependsOn.as_str())
}

fn compliance_impact_dependency_row_limit(dependency_count: u64) -> Option<i64> {
    (dependency_count != 0).then(|| i64::try_from(dependency_count).unwrap_or(i64::MAX))
}

fn validate_compliance_impact_key(
    tenant_id: &TenantId,
    name: &str,
    value: &str,
    required: bool,
) -> Result<(), StoreError> {
    validate_catalog_text(name, value, 4096, required)?;
    if value.is_empty() {
        return Ok(());
    }
    let parts = value.split(':').collect::<Vec<_>>();
    let valid_identity = parts.len() == 9
        && parts[0] == "urn"
        && parts[1] == "cerebro"
        && parts[2] == tenant_id.as_str()
        && parts[3] == COMPLIANCE_IMPACT_REVISION_URN_KIND
        && parts[8].len() == 35
        && parts[8].starts_with("id-")
        && parts[8][3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_identity {
        return Err(StoreError::Conflict(format!(
            "compliance impact {name} is not a canonical revision key"
        )));
    }
    let domain = decode_compliance_impact_segment(parts[4])?;
    let fact_kind = decode_compliance_impact_segment(parts[5])?;
    for part in &parts[6..8] {
        let decoded = decode_compliance_impact_segment(part)?;
        validate_catalog_text(name, &decoded, 4096, true)?;
    }
    if !valid_compliance_impact_domain(&domain) || !valid_compliance_impact_fact_kind(&fact_kind) {
        return Err(StoreError::Conflict(format!(
            "compliance impact {name} has invalid authority segments"
        )));
    }
    Ok(())
}

fn compliance_impact_entity(tenant_id: &TenantId, row: &Row) -> Result<ContextEntity, StoreError> {
    let agent_key = catalog_row_string(row, "entity_key")?;
    validate_compliance_impact_key(tenant_id, "result key", &agent_key, true)?;
    let entity = legacy_context_entity(
        tenant_id,
        &agent_key,
        EntityKind::ComplianceImpactRevision.as_str().to_owned(),
        agent_key.clone(),
        catalog_row_string(row, "entity_properties")?,
        "compliance".to_owned(),
        String::new(),
    )
    .map_err(|error| StoreError::Conflict(error.to_string()))?;
    if canonical_compliance_impact_key(tenant_id, &entity.properties)? != agent_key {
        return Err(StoreError::Conflict(
            "compliance impact revision key does not match canonical properties".to_owned(),
        ));
    }
    Ok(entity)
}

fn canonical_compliance_impact_key(
    tenant_id: &TenantId,
    properties: &BTreeMap<String, String>,
) -> Result<String, StoreError> {
    let required = |name: &str| {
        let value = properties.get(name).ok_or_else(|| {
            StoreError::Conflict(format!(
                "compliance impact revision property {name} is missing"
            ))
        })?;
        validate_catalog_text(name, value, 4096, true)?;
        Ok::<&str, StoreError>(value)
    };
    if required("tenant_id")? != tenant_id.as_str() {
        return Err(StoreError::Conflict(
            "compliance impact revision tenant is invalid".to_owned(),
        ));
    }
    let domain = required("domain")?;
    let fact_kind = required("fact_kind")?;
    let stable_id = required("stable_id")?;
    let revision_id = required("revision_id")?;
    let revision_version = required("revision_version")?;
    let content_digest = required("content_digest")?;
    let last_modified = required("last_modified")?;
    if !valid_compliance_impact_domain(domain)
        || !valid_compliance_impact_fact_kind(fact_kind)
        || !valid_compliance_impact_digest(content_digest)
    {
        return Err(StoreError::Conflict(
            "compliance impact revision properties are invalid".to_owned(),
        ));
    }
    let version = revision_version.parse::<u64>().map_err(|_| {
        StoreError::Conflict("compliance impact revision version is invalid".to_owned())
    })?;
    if version == 0 || version.to_string() != revision_version {
        return Err(StoreError::Conflict(
            "compliance impact revision version is not canonical".to_owned(),
        ));
    }
    let parsed = time::OffsetDateTime::parse(
        last_modified,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| {
        StoreError::Conflict("compliance impact revision timestamp is invalid".to_owned())
    })?;
    if parsed.offset() != time::UtcOffset::UTC
        || parsed.nanosecond() % 1_000_000 != 0
        || canonical_compliance_impact_timestamp(parsed) != last_modified
    {
        return Err(StoreError::Conflict(
            "compliance impact revision timestamp is not canonical".to_owned(),
        ));
    }
    let exact_key = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        tenant_id.as_str(),
        domain,
        fact_kind,
        stable_id,
        revision_id,
        version,
        content_digest,
        last_modified
    );
    let digest = Sha256::digest(exact_key.as_bytes());
    let mut external_id = String::from("id-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest[..16] {
        external_id.push(HEX[(byte >> 4) as usize] as char);
        external_id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(format!(
        "urn:cerebro:{}:{}:{}:{}:{}:{}:{}",
        tenant_id.as_str(),
        COMPLIANCE_IMPACT_REVISION_URN_KIND,
        encode_compliance_impact_segment(domain),
        encode_compliance_impact_segment(fact_kind),
        encode_compliance_impact_segment(stable_id),
        encode_compliance_impact_segment(revision_id),
        external_id
    ))
}

fn canonical_compliance_impact_timestamp(value: time::OffsetDateTime) -> String {
    let month = u8::from(value.month());
    let mut result = format!(
        "{:04}-{month:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    let nanosecond = value.nanosecond();
    if nanosecond != 0 {
        let fraction = format!("{nanosecond:09}");
        result.push('.');
        result.push_str(fraction.trim_end_matches('0'));
    }
    result.push('Z');
    result
}

fn valid_compliance_impact_domain(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn valid_compliance_impact_fact_kind(value: &str) -> bool {
    matches!(
        value,
        "catalog"
            | "mapping"
            | "source_coverage"
            | "inventory"
            | "policy"
            | "vendor"
            | "claim"
            | "finding"
            | "program"
            | "assessment_plan"
            | "objective"
            | "audit_package"
            | "work_item"
            | "projection"
            | "questionnaire_answer"
    )
}

fn valid_compliance_impact_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_compliance_impact_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.' | b'_' | b'~' | b'$' | b'&' | b'+' | b'=' | b'@'
            )
        {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn decode_compliance_impact_segment(value: &str) -> Result<String, StoreError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(StoreError::Conflict(
                "compliance impact revision key has an invalid escape".to_owned(),
            ));
        }
        let high = decode_hex(bytes[index + 1]).ok_or_else(|| {
            StoreError::Conflict("compliance impact revision key has an invalid escape".to_owned())
        })?;
        let low = decode_hex(bytes[index + 2]).ok_or_else(|| {
            StoreError::Conflict("compliance impact revision key has an invalid escape".to_owned())
        })?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    let decoded = String::from_utf8(decoded).map_err(|_| {
        StoreError::Conflict("compliance impact revision key is not UTF-8".to_owned())
    })?;
    if decoded.trim() != decoded || encode_compliance_impact_segment(&decoded) != value {
        return Err(StoreError::Conflict(
            "compliance impact revision key is not round-trippable".to_owned(),
        ));
    }
    Ok(decoded)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_catalog_text(
    name: &str,
    value: &str,
    limit: usize,
    required: bool,
) -> Result<(), StoreError> {
    if (required && value.is_empty())
        || value.trim() != value
        || value.len() > limit
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::Conflict(format!(
            "invalid entity catalog {name}"
        )));
    }
    Ok(())
}

async fn catalog_revision(transaction: &mut Txn, tenant_id: &TenantId) -> Result<u64, StoreError> {
    let mut rows = transaction.execute(query("OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision").param("tenant_id", tenant_id.as_str())).await?;
    let row = rows.next(transaction.handle()).await?.ok_or_else(|| {
        StoreError::Conflict("entity catalog revision returned no row".to_owned())
    })?;
    let revision = catalog_row_u64(&row, "graph_revision")?;
    drop(rows);
    Ok(revision)
}

fn require_catalog_revision(expected: u64, actual: u64) -> Result<(), StoreError> {
    if expected != 0 && expected != actual {
        return Err(StoreError::Conflict(
            "entity catalog revision changed before continuation".to_owned(),
        ));
    }
    Ok(())
}

fn require_same_catalog_revision(start: u64, end: u64) -> Result<(), StoreError> {
    if start != end {
        return Err(StoreError::Conflict(
            "entity catalog revision changed during the read".to_owned(),
        ));
    }
    Ok(())
}

fn catalog_row_string(row: &Row, field: &str) -> Result<String, StoreError> {
    row.get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))
}
fn catalog_row_u64(row: &Row, field: &str) -> Result<u64, StoreError> {
    let value: i64 = row
        .get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    u64::try_from(value)
        .map_err(|_| StoreError::Conflict(format!("entity catalog {field} is negative")))
}

fn catalog_row_string_list(row: &Row, field: &str) -> Result<Vec<String>, StoreError> {
    row.get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))
}

fn cloud_attack_path_from_row(row: &Row) -> Result<CloudAttackPath, StoreError> {
    Ok(CloudAttackPath {
        public_principal: cloud_attack_path_node(row, "public")?,
        exposed_resource: cloud_attack_path_node(row, "exposed")?,
        cloud_account: cloud_attack_path_node(row, "account")?,
        principal: cloud_attack_path_node(row, "principal")?,
        permission: cloud_attack_path_node(row, "permission")?,
        ownerships: cloud_attack_path_ownerships(row)?,
        reach_relation: catalog_row_string(row, "reach_relation")?,
        access_relation: catalog_row_string(row, "access_relation")?,
        relation_chain: catalog_row_string_list(row, "relation_chain")?,
        exposure_edge: cloud_attack_path_edge(row, "exposure")?,
        resource_account_edge: cloud_attack_path_edge(row, "resource_account")?,
        traversal_edges: cloud_attack_path_traversal_edges(row)?,
        privilege_edge: cloud_attack_path_edge(row, "privilege")?,
        permission_account_edge: cloud_attack_path_edge(row, "permission_account")?,
    })
}

fn cloud_attack_path_node(row: &Row, prefix: &str) -> Result<CloudAttackPathNode, StoreError> {
    Ok(CloudAttackPathNode {
        urn: catalog_row_string(row, &format!("{prefix}_urn"))?,
        entity_kind: catalog_row_string(row, &format!("{prefix}_entity_type"))?,
        label: catalog_row_string(row, &format!("{prefix}_label"))?,
    })
}

fn cloud_attack_path_edge(row: &Row, prefix: &str) -> Result<CloudAttackPathEdge, StoreError> {
    Ok(CloudAttackPathEdge {
        from: cloud_attack_path_node(row, &format!("{prefix}_from"))?,
        relation: catalog_row_string(row, &format!("{prefix}_relation"))?,
        to: cloud_attack_path_node(row, &format!("{prefix}_to"))?,
        direction: catalog_row_string(row, &format!("{prefix}_direction"))?,
        source_id: catalog_row_string(row, &format!("{prefix}_source_id"))?,
        source_runtime_id: catalog_row_string(row, &format!("{prefix}_source_runtime_id"))?,
        assertion_runtime_ids: catalog_row_string_list(
            row,
            &format!("{prefix}_assertion_runtime_ids"),
        )?,
        attributes_json: catalog_row_string(row, &format!("{prefix}_attributes_json"))?,
    })
}

fn cloud_attack_path_ownerships(row: &Row) -> Result<Vec<CloudAttackPathOwnership>, StoreError> {
    let owner_urns = catalog_row_string_list(row, "ownership_owner_urns")?;
    let owner_entity_types = catalog_row_string_list(row, "ownership_owner_entity_types")?;
    let owner_labels = catalog_row_string_list(row, "ownership_owner_labels")?;
    let from_urns = catalog_row_string_list(row, "ownership_from_urns")?;
    let from_entity_types = catalog_row_string_list(row, "ownership_from_entity_types")?;
    let from_labels = catalog_row_string_list(row, "ownership_from_labels")?;
    let relations = catalog_row_string_list(row, "ownership_relations")?;
    let to_urns = catalog_row_string_list(row, "ownership_to_urns")?;
    let to_entity_types = catalog_row_string_list(row, "ownership_to_entity_types")?;
    let to_labels = catalog_row_string_list(row, "ownership_to_labels")?;
    let directions = catalog_row_string_list(row, "ownership_directions")?;
    let source_ids = catalog_row_string_list(row, "ownership_source_ids")?;
    let source_runtime_ids = catalog_row_string_list(row, "ownership_source_runtime_ids")?;
    let assertion_sets = catalog_row_string_list(row, "ownership_assertion_runtime_id_sets")?;
    let attributes = catalog_row_string_list(row, "ownership_attributes_jsons")?;
    if !same_len(&[
        owner_urns.len(),
        owner_entity_types.len(),
        owner_labels.len(),
        from_urns.len(),
        from_entity_types.len(),
        from_labels.len(),
        relations.len(),
        to_urns.len(),
        to_entity_types.len(),
        to_labels.len(),
        directions.len(),
        source_ids.len(),
        source_runtime_ids.len(),
        assertion_sets.len(),
        attributes.len(),
    ]) {
        return Err(StoreError::Conflict(
            "cloud attack path ownership fields are misaligned".to_owned(),
        ));
    }
    let mut ownerships = Vec::with_capacity(owner_urns.len());
    for index in 0..owner_urns.len() {
        ownerships.push(CloudAttackPathOwnership {
            owner: CloudAttackPathNode {
                urn: owner_urns[index].clone(),
                entity_kind: owner_entity_types[index].clone(),
                label: owner_labels[index].clone(),
            },
            edge: CloudAttackPathEdge {
                from: CloudAttackPathNode {
                    urn: from_urns[index].clone(),
                    entity_kind: from_entity_types[index].clone(),
                    label: from_labels[index].clone(),
                },
                relation: relations[index].clone(),
                to: CloudAttackPathNode {
                    urn: to_urns[index].clone(),
                    entity_kind: to_entity_types[index].clone(),
                    label: to_labels[index].clone(),
                },
                direction: directions[index].clone(),
                source_id: source_ids[index].clone(),
                source_runtime_id: source_runtime_ids[index].clone(),
                assertion_runtime_ids: split_runtime_id_set(&assertion_sets[index]),
                attributes_json: attributes[index].clone(),
            },
        });
    }
    Ok(ownerships)
}

fn cloud_attack_path_traversal_edges(row: &Row) -> Result<Vec<CloudAttackPathEdge>, StoreError> {
    let from_urns = catalog_row_string_list(row, "traversal_from_urns")?;
    let from_entity_types = catalog_row_string_list(row, "traversal_from_entity_types")?;
    let from_labels = catalog_row_string_list(row, "traversal_from_labels")?;
    let relations = catalog_row_string_list(row, "traversal_relations")?;
    let to_urns = catalog_row_string_list(row, "traversal_to_urns")?;
    let to_entity_types = catalog_row_string_list(row, "traversal_to_entity_types")?;
    let to_labels = catalog_row_string_list(row, "traversal_to_labels")?;
    let directions = catalog_row_string_list(row, "traversal_directions")?;
    let source_ids = catalog_row_string_list(row, "traversal_source_ids")?;
    let source_runtime_ids = catalog_row_string_list(row, "traversal_source_runtime_ids")?;
    let assertion_sets = catalog_row_string_list(row, "traversal_assertion_runtime_id_sets")?;
    let attributes = catalog_row_string_list(row, "traversal_attributes_jsons")?;
    if !same_len(&[
        from_urns.len(),
        from_entity_types.len(),
        from_labels.len(),
        relations.len(),
        to_urns.len(),
        to_entity_types.len(),
        to_labels.len(),
        directions.len(),
        source_ids.len(),
        source_runtime_ids.len(),
        assertion_sets.len(),
        attributes.len(),
    ]) {
        return Err(StoreError::Conflict(
            "cloud attack path traversal fields are misaligned".to_owned(),
        ));
    }
    let mut edges = Vec::with_capacity(relations.len());
    for index in 0..relations.len() {
        edges.push(CloudAttackPathEdge {
            from: CloudAttackPathNode {
                urn: from_urns[index].clone(),
                entity_kind: from_entity_types[index].clone(),
                label: from_labels[index].clone(),
            },
            relation: relations[index].clone(),
            to: CloudAttackPathNode {
                urn: to_urns[index].clone(),
                entity_kind: to_entity_types[index].clone(),
                label: to_labels[index].clone(),
            },
            direction: directions[index].clone(),
            source_id: source_ids[index].clone(),
            source_runtime_id: source_runtime_ids[index].clone(),
            assertion_runtime_ids: split_runtime_id_set(&assertion_sets[index]),
            attributes_json: attributes[index].clone(),
        });
    }
    Ok(edges)
}

fn split_runtime_id_set(value: &str) -> Vec<String> {
    value
        .split('\u{1f}')
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn row_u64(row: &Row, field: &str) -> Result<u64, StoreError> {
    let value: i64 = row
        .get(field)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    u64::try_from(value)
        .map_err(|_| StoreError::Conflict(format!("{field} is negative or exceeds u64")))
}

fn validate_exposure_coverage_query(request: &ExposureCoverageQuery) -> Result<(), StoreError> {
    if !(1..=100).contains(&request.limit) {
        return Err(StoreError::Conflict(
            "exposure coverage limit must be between 1 and 100".to_owned(),
        ));
    }
    for (name, value, limit) in [
        (
            "primary_source_id",
            request.profile.primary_source_id.as_str(),
            128,
        ),
        (
            "primary_entity_kind_prefix",
            request.profile.primary_entity_kind_prefix.as_str(),
            128,
        ),
        (
            "corroborating_source_id",
            request.profile.corroborating_source_id.as_str(),
            128,
        ),
        (
            "corroborating_entity_kind",
            request.profile.corroborating_entity_kind.as_str(),
            128,
        ),
        ("account_kind", request.profile.account_kind.as_str(), 128),
        (
            "corroborating_observation_kind",
            request.profile.corroborating_observation_kind.as_str(),
            128,
        ),
    ] {
        validate_exposure_text(name, value, limit, true)?;
    }
    validate_exposure_text("account_id", &request.account_id, 256, false)?;
    validate_exposure_text("region", &request.region, 128, false)?;
    validate_exposure_text("query", &request.search, 512, false)?;
    if request.profile.indicator_kinds.is_empty() || request.profile.indicator_kinds.len() > 8 {
        return Err(StoreError::Conflict(
            "exposure coverage requires 1 to 8 indicator kinds".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for kind in &request.profile.indicator_kinds {
        validate_exposure_text("indicator_kind", kind, 128, true)?;
        if !seen.insert(kind) {
            return Err(StoreError::Conflict(
                "exposure coverage indicator kinds must be unique".to_owned(),
            ));
        }
    }
    Ok(())
}

fn should_query_corroborating_only(request: &ExposureCoverageQuery) -> bool {
    request.account_id.is_empty() && request.region.is_empty()
}

fn validate_exposure_text(
    name: &str,
    value: &str,
    limit: usize,
    required: bool,
) -> Result<(), StoreError> {
    if (required && value.is_empty())
        || value.trim() != value
        || value.len() > limit
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::Conflict(format!(
            "invalid exposure coverage {name}"
        )));
    }
    Ok(())
}

async fn transaction_graph_revision(
    transaction: &mut Txn,
    tenant_id: &TenantId,
) -> Result<u64, StoreError> {
    let mut rows = transaction
        .execute(
            query("OPTIONAL MATCH (revision:OrganizationalGraphRevision {tenant_id: $tenant_id}) RETURN coalesce(revision.graph_revision, 0) AS graph_revision")
                .param("tenant_id", tenant_id.as_str()),
        )
        .await?;
    let row = rows
        .next(transaction.handle())
        .await?
        .ok_or_else(|| StoreError::Conflict("graph revision query returned no row".to_owned()))?;
    let revision = row_u64(&row, "graph_revision")?;
    drop(rows);
    Ok(revision)
}

fn exposure_entity(
    row: &Row,
    prefix: &str,
    tenant_id: &TenantId,
) -> Result<ExposureCoverageEntity, StoreError> {
    let agent_key: String = row
        .get(&format!("{prefix}_key"))
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    if !agent_key.starts_with(&format!("urn:cerebro:{}:", tenant_id.as_str())) {
        return Err(StoreError::Conflict(format!(
            "exposure coverage {prefix} key is not tenant scoped"
        )));
    }
    let entity_kind = row
        .get(&format!("{prefix}_kind"))
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    let label = row
        .get(&format!("{prefix}_label"))
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    Ok(ExposureCoverageEntity {
        agent_key,
        entity_kind,
        label,
    })
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

fn aggregate_legacy_root_coverage(
    tenant_id: &TenantId,
    rows: impl IntoIterator<Item = (String, i64, i64)>,
) -> Result<LegacyRootCoverage, StoreError> {
    let mut entity_types = Vec::new();
    let mut legacy_roots = 0_u64;
    let mut covered_roots = 0_u64;
    for (entity_type, legacy, covered) in rows {
        let legacy = u64::try_from(legacy).map_err(|_| {
            StoreError::Conflict("legacy root coverage count is negative".to_owned())
        })?;
        let covered = u64::try_from(covered)
            .map_err(|_| StoreError::Conflict("covered root count is negative".to_owned()))?;
        if covered > legacy {
            return Err(StoreError::Conflict(
                "covered root count exceeds legacy root count".to_owned(),
            ));
        }
        legacy_roots = legacy_roots.checked_add(legacy).ok_or_else(|| {
            StoreError::Conflict("legacy root coverage count overflowed".to_owned())
        })?;
        covered_roots = covered_roots
            .checked_add(covered)
            .ok_or_else(|| StoreError::Conflict("covered root count overflowed".to_owned()))?;
        entity_types.push(LegacyRootCoverageKind {
            entity_type,
            legacy_roots: legacy,
            covered_roots: covered,
            missing_roots: legacy - covered,
        });
    }
    Ok(LegacyRootCoverage {
        tenant_id: tenant_id.as_str().to_owned(),
        legacy_roots,
        covered_roots,
        missing_roots: legacy_roots - covered_roots,
        entity_types,
    })
}

struct LegacyNeighborhoodAccumulator {
    root: ContextEntity,
    entities: BTreeMap<String, ContextEntity>,
    edges: Vec<ContextEdge>,
    seen_edges: BTreeSet<String>,
    truncated: bool,
}

impl LegacyNeighborhoodAccumulator {
    fn new(root: ContextEntity) -> Self {
        Self {
            root,
            entities: BTreeMap::new(),
            edges: Vec::new(),
            seen_edges: BTreeSet::new(),
            truncated: false,
        }
    }
}

fn legacy_context_entity(
    tenant_id: &TenantId,
    urn: &str,
    entity_kind: String,
    label: String,
    properties_json: String,
    source_id: String,
    runtime_id: String,
) -> Result<ContextEntity, ContextError> {
    let expected_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
    if !urn.starts_with(&expected_prefix) {
        return Err(ContextError::BackendUnavailable(
            "legacy graph returned a cross-tenant entity".to_owned(),
        ));
    }
    let mut properties: BTreeMap<String, String> = parse_json(&properties_json)?;
    properties.insert("entity_urn".to_owned(), urn.to_owned());
    properties.insert("entity_type".to_owned(), entity_kind.clone());
    if !source_id.is_empty() {
        properties.insert("source_id".to_owned(), source_id.clone());
    }
    let attributes_runtime_id = properties
        .get("source_runtime_id")
        .or_else(|| properties.get("runtime_id"))
        .cloned()
        .unwrap_or_default();
    if !runtime_id.is_empty()
        && !attributes_runtime_id.is_empty()
        && runtime_id != attributes_runtime_id
    {
        return Err(ContextError::BackendUnavailable(
            "legacy entity runtime provenance conflicts".to_owned(),
        ));
    }
    let source_runtime_id = if runtime_id.is_empty() {
        attributes_runtime_id
    } else {
        runtime_id.clone()
    };
    if !source_runtime_id.is_empty() {
        properties.insert("source_runtime_id".to_owned(), source_runtime_id.clone());
    }
    let provider_kind = properties
        .get("provider_kind")
        .cloned()
        .unwrap_or_else(|| entity_kind.clone());
    let provider_id = properties
        .get("provider_id")
        .cloned()
        .unwrap_or_else(|| urn.to_owned());
    Ok(ContextEntity {
        entity_id: legacy_entity_id(tenant_id, urn),
        agent_key: urn.to_owned(),
        entity_kind,
        authority: serde_json::json!({
            "authority": "legacy_projection",
            "source_runtime_id": source_runtime_id,
            "provider_kind": provider_kind,
            "provider_id": provider_id,
        }),
        label,
        properties,
    })
}

fn legacy_context_entity_from_row_prefix(
    tenant_id: &TenantId,
    row: &Row,
    prefix: &str,
) -> Result<ContextEntity, StoreError> {
    legacy_context_entity(
        tenant_id,
        &catalog_row_string(row, &format!("{prefix}_key"))?,
        catalog_row_string(row, &format!("{prefix}_kind"))?,
        catalog_row_string(row, &format!("{prefix}_label"))?,
        catalog_row_string(row, &format!("{prefix}_properties"))?,
        catalog_row_string(row, &format!("{prefix}_source_id"))?,
        catalog_row_string(row, &format!("{prefix}_runtime_id"))?,
    )
    .map_err(|error| StoreError::Conflict(error.to_string()))
}

struct LegacyEdgeMetadata {
    tenant_ids: Vec<String>,
    runtime_ids: Vec<String>,
    application_workspace_ids: Vec<String>,
    properties_values: Vec<String>,
}

fn legacy_context_edge(
    tenant_id: &TenantId,
    from: String,
    relation: String,
    to: String,
    metadata: LegacyEdgeMetadata,
) -> Result<ContextEdge, ContextError> {
    let expected_prefix = format!("urn:cerebro:{}:", tenant_id.as_str());
    if !from.starts_with(&expected_prefix) || !to.starts_with(&expected_prefix) {
        return Err(ContextError::BackendUnavailable(
            "legacy graph returned a cross-tenant relation".to_owned(),
        ));
    }
    if metadata
        .tenant_ids
        .iter()
        .any(|value| !value.is_empty() && value != tenant_id.as_str())
    {
        return Err(ContextError::BackendUnavailable(
            "legacy graph returned a cross-tenant relation".to_owned(),
        ));
    }
    if metadata.runtime_ids.len() > 1
        || metadata.application_workspace_ids.len() > 1
        || metadata.properties_values.len() > 1
    {
        return Err(ContextError::BackendUnavailable(
            "legacy relation metadata conflicts".to_owned(),
        ));
    }
    let properties: BTreeMap<String, String> = parse_json(
        metadata
            .properties_values
            .first()
            .map(String::as_str)
            .unwrap_or("{}"),
    )?;
    let typed_runtime_id = metadata
        .runtime_ids
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    let application_workspace_id = metadata
        .application_workspace_ids
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    if application_workspace_id.len() > 128
        || application_workspace_id.trim() != application_workspace_id
        || application_workspace_id == "*"
        || application_workspace_id.contains(',')
        || application_workspace_id.chars().any(char::is_control)
    {
        return Err(ContextError::BackendUnavailable(
            "legacy relation application workspace is invalid".to_owned(),
        ));
    }
    let attributes_runtime_id = properties
        .get("source_runtime_id")
        .or_else(|| properties.get("runtime_id"))
        .map(String::as_str)
        .unwrap_or_default();
    if !typed_runtime_id.is_empty()
        && !attributes_runtime_id.is_empty()
        && typed_runtime_id != attributes_runtime_id
    {
        return Err(ContextError::BackendUnavailable(
            "legacy relation runtime provenance conflicts".to_owned(),
        ));
    }
    let source_runtime_id = if typed_runtime_id.is_empty() {
        attributes_runtime_id.to_owned()
    } else {
        typed_runtime_id.to_owned()
    };
    let identity_binding = relation == "represents"
        || properties
            .get("identity_binding")
            .is_some_and(|value| value == "true");
    let assertion_id = legacy_assertion_id(tenant_id, &from, &relation, &to);
    Ok(ContextEdge {
        assertion_id,
        from: legacy_entity_id(tenant_id, &from),
        relation,
        to: legacy_entity_id(tenant_id, &to),
        source_runtime_id,
        application_workspace_id: application_workspace_id.to_owned(),
        identity_binding,
    })
}

fn legacy_entity_id(tenant_id: &TenantId, urn: &str) -> EntityId {
    EntityId::parse(legacy_digest("legacy-entity", [tenant_id.as_str(), urn]))
        .expect("legacy entity digest is a valid identifier")
}

fn legacy_assertion_id(tenant_id: &TenantId, from: &str, relation: &str, to: &str) -> AssertionId {
    AssertionId::parse(legacy_digest(
        "legacy-edge",
        [tenant_id.as_str(), from, relation, to],
    ))
    .expect("legacy assertion digest is a valid identifier")
}

fn legacy_digest<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut value = String::with_capacity(prefix.len() + 1 + bytes.len() * 2);
    value.push_str(prefix);
    value.push(':');
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
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
        (
            "application_workspace_id",
            assertion.application_workspace_id.clone().into(),
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
        assert_eq!(HEALTH_TIMEOUT, Duration::from_secs(75));
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

    #[tokio::test]
    #[ignore = "requires a disposable Neo4j instance"]
    async fn legacy_root_is_served_by_rust_with_outgoing_first_bounds() -> Result<(), Box<dyn Error>>
    {
        let graph = Graph::new(
            env::var("CEREBRO_TEST_NEO4J_URI")?,
            env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
            env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
        )
        .await?;
        let tenant = format!("tenant-legacy-rust-{}", std::process::id());
        let root_urn = format!("urn:cerebro:{tenant}:asset:root#1@example");
        let organizational_urn = format!("urn:cerebro:{tenant}:asset:organizational");
        graph
            .run(
                query(
                    "CREATE (root:Entity {tenant_id: $tenant, urn: $root, entity_type: 'asset', label: 'Root', attributes_json: '{}'}) WITH root UNWIND range(1, 4) AS index CREATE (out:Entity {tenant_id: $tenant, urn: $prefix + 'out-' + toString(index), entity_type: 'finding', label: 'Outgoing', attributes_json: '{}'}), (root)-[edge:RELATION {relation: 'has_finding', runtime_id: 'runtime-a', attributes_json: '{\"source_runtime_id\":\"runtime-a\"}'}]->(out) SET edge.tenant_id = CASE WHEN index = 1 THEN null ELSE $tenant END WITH DISTINCT root CREATE (incoming:Entity {tenant_id: $tenant, urn: $prefix + 'incoming', entity_type: 'identity', label: 'Incoming', attributes_json: '{}'}), (incoming)-[:RELATION {tenant_id: $tenant, relation: 'owns', runtime_id: 'runtime-a', attributes_json: '{\"source_runtime_id\":\"runtime-a\"}'}]->(root)",
                )
                .param("tenant", tenant.clone())
                .param("root", root_urn.clone())
                .param("prefix", format!("urn:cerebro:{tenant}:fixture:")),
            )
            .await?;
        graph
            .run(
                query("CREATE (:OrganizationalGraphRevision {tenant_id: $tenant, graph_revision: 7}), (:OrganizationalEntity {tenant_id: $tenant, entity_id: 'organizational-root', entity_kind: 'resource', authority_json: '{}', label: 'Organizational root', properties_json: $properties, external_id: $urn, graph_revision: 7})")
                    .param("tenant", tenant.clone())
                    .param("urn", organizational_urn.clone())
                    .param("properties", format!(r#"{{"entity_urn":"{organizational_urn}"}}"#)),
            )
            .await?;

        let projector = Neo4jProjector::from_graph(graph.clone());
        let tenant_id = TenantId::parse(tenant.clone())?;
        let neighborhoods = projector
            .expand_many(
                &tenant_id,
                &[root_urn.clone(), organizational_urn.clone()],
                1,
                3,
            )
            .await?;
        let neighborhood = &neighborhoods[&root_urn];
        assert_eq!(neighborhood.root.agent_key, root_urn);
        assert_eq!(neighborhood.graph_revision, 0);
        assert_eq!(neighborhood.edges.len(), 3);
        assert!(neighborhood.truncated);
        assert!(
            neighborhood
                .edges
                .iter()
                .all(|edge| edge.relation == "has_finding")
        );
        assert!(
            neighborhood
                .entities
                .iter()
                .all(|entity| entity.properties["entity_type"] == "finding")
        );
        let organizational = &neighborhoods[&organizational_urn];
        assert_eq!(organizational.graph_revision, 7);
        assert_eq!(
            organizational.root.entity_id.as_str(),
            "organizational-root"
        );
        assert!(
            projector
                .expand_many(&tenant_id, std::slice::from_ref(&root_urn), 2, 3)
                .await
                .is_err(),
            "legacy roots must not silently degrade a deeper traversal to one hop"
        );

        graph
            .run(
                query("MATCH (node {tenant_id: $tenant}) DETACH DELETE node")
                    .param("tenant", tenant),
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires a disposable Neo4j instance"]
    async fn legacy_root_rejects_explicit_cross_tenant_relation_metadata()
    -> Result<(), Box<dyn Error>> {
        let graph = Graph::new(
            env::var("CEREBRO_TEST_NEO4J_URI")?,
            env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
            env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
        )
        .await?;
        let tenant = format!("tenant-legacy-scope-{}", std::process::id());
        let root_urn = format!("urn:cerebro:{tenant}:asset:root");
        graph
            .run(
                query("CREATE (root:Entity {tenant_id: $tenant, urn: $root, entity_type: 'asset', label: 'Root', attributes_json: '{}'}), (neighbor:Entity {tenant_id: $tenant, urn: $neighbor, entity_type: 'finding', label: 'Finding', attributes_json: '{}'}), (root)-[:RELATION {tenant_id: 'other', relation: 'has_finding'}]->(neighbor)")
                    .param("tenant", tenant.clone())
                    .param("root", root_urn.clone())
                    .param("neighbor", format!("urn:cerebro:{tenant}:finding:one")),
            )
            .await?;
        let projector = Neo4jProjector::from_graph(graph.clone());
        let tenant_id = TenantId::parse(tenant.clone())?;
        assert!(
            projector
                .expand_many(&tenant_id, std::slice::from_ref(&root_urn), 1, 10)
                .await
                .is_err()
        );
        graph
            .run(
                query("MATCH (node {tenant_id: $tenant}) DETACH DELETE node")
                    .param("tenant", tenant),
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
    fn compliance_impact_queries_are_fixed_tenant_scoped_and_bounded() {
        assert!(COMPLIANCE_IMPACT_FACT_STATEMENT.contains("LIMIT 2"));
        assert!(COMPLIANCE_IMPACT_FACT_STATEMENT.contains("tenant_id: $tenant_id"));
        assert!(COMPLIANCE_IMPACT_FACT_STATEMENT.contains("entity_type: $entity_kind"));

        assert!(COMPLIANCE_IMPACT_DEPENDENCY_COUNT_STATEMENT.contains("count(edge)"));
        assert!(COMPLIANCE_IMPACT_DEPENDENCY_COUNT_STATEMENT.contains("relation: $relation"));
        assert!(COMPLIANCE_IMPACT_DEPENDENCIES_STATEMENT.contains("edge.attributes_json"));
        assert!(COMPLIANCE_IMPACT_DEPENDENCIES_STATEMENT.contains("ORDER BY dependency.urn"));
        assert!(COMPLIANCE_IMPACT_DEPENDENCIES_STATEMENT.contains("LIMIT $row_limit"));

        assert!(COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT.contains("RETURN DISTINCT dependent.urn"));
        assert!(COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT.contains("dependent.urn > $after_key"));
        assert!(COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT.contains("ORDER BY entity_key"));
        assert!(COMPLIANCE_IMPACT_DEPENDENTS_STATEMENT.contains("LIMIT $row_limit"));

        let tenant = TenantId::parse("tenant-a").expect("tenant");
        let properties = BTreeMap::from([
            ("tenant_id".to_owned(), "tenant-a".to_owned()),
            ("domain".to_owned(), "grc".to_owned()),
            ("fact_kind".to_owned(), "assessment_plan".to_owned()),
            ("stable_id".to_owned(), "plan:1".to_owned()),
            ("revision_id".to_owned(), "plan/1 revision".to_owned()),
            ("revision_version".to_owned(), "3".to_owned()),
            (
                "content_digest".to_owned(),
                format!("sha256:{}", "a".repeat(64)),
            ),
            (
                "last_modified".to_owned(),
                "2026-08-25T12:00:00.123Z".to_owned(),
            ),
        ]);
        let canonical_key =
            canonical_compliance_impact_key(&tenant, &properties).expect("canonical key");
        assert_eq!(
            canonical_key,
            "urn:cerebro:tenant-a:compliance_impact_revision:grc:assessment_plan:plan%3A1:plan%2F1%20revision:id-8f17cc1b53746447564d0ce320463097"
        );
        assert!(validate_compliance_impact_key(&tenant, "agent_key", &canonical_key, true).is_ok());
        assert!(
            validate_compliance_impact_key(
                &tenant,
                "agent_key",
                &canonical_key.replacen("tenant-a", "tenant-b", 1),
                true,
            )
            .is_err()
        );
        assert!(
            validate_compliance_impact_key(
                &tenant,
                "agent_key",
                &canonical_key.replace("%3A", "%3a"),
                true,
            )
            .is_err()
        );
        assert!(
            validate_compliance_impact_key(
                &tenant,
                "agent_key",
                "urn:cerebro:tenant-a:compliance_impact_revision:one",
                true,
            )
            .is_err()
        );
        let mut invalid_properties = properties.clone();
        invalid_properties.insert(
            "content_digest".to_owned(),
            format!("sha256:{}", "A".repeat(64)),
        );
        assert!(canonical_compliance_impact_key(&tenant, &invalid_properties).is_err());
        invalid_properties = properties.clone();
        invalid_properties.insert(
            "last_modified".to_owned(),
            "2026-08-25T12:00:00.123400Z".to_owned(),
        );
        assert!(canonical_compliance_impact_key(&tenant, &invalid_properties).is_err());
        assert!(validate_compliance_impact_key(&tenant, "agent_key", "", true).is_err());
        assert!(validate_compliance_impact_key(&tenant, "after_agent_key", "", false).is_ok());
        assert_eq!(row_limit(2_999), 3_000);
    }

    #[test]
    fn compliance_impact_zero_dependency_fact_skips_dependency_list_query() {
        let mut dependency_list_queries = 0;
        if compliance_impact_dependency_row_limit(0).is_some() {
            dependency_list_queries += 1;
        }
        assert_eq!(dependency_list_queries, 0);
        assert_eq!(compliance_impact_dependency_row_limit(2_999), Some(2_999));
    }

    #[test]
    fn entity_catalog_rejects_unbounded_ambiguous_or_cross_tenant_requests() {
        let tenant = TenantId::parse("writer").expect("tenant");
        let mut filter = EntityCatalogFilter {
            include_kinds: vec!["vendor".to_owned()],
            relation_counts: Some(EntityCatalogRelationCountFilter {
                directions: vec![EntityCatalogDirection::Incoming],
                relations: vec!["associated_with".to_owned()],
                neighbor_kinds: vec!["contract".to_owned()],
            }),
            ..Default::default()
        };
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_ok());

        filter.application_workspace_id = "workspace-a".to_owned();
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_ok());
        filter.application_workspace_id = " workspace-a".to_owned();
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_err());
        filter.application_workspace_id = "w".repeat(128);
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_ok());
        filter.application_workspace_id = "w".repeat(129);
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_err());
        filter.application_workspace_id.clear();
        filter.attribute_substrings_any = vec!["\"policy_id\":\"".to_owned()];
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_ok());
        filter
            .attribute_substrings_any
            .push("\"policy_id\":\"".to_owned());
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_err());
        filter.attribute_substrings_any.pop();
        assert!(validate_catalog_request(&tenant, &filter, 0, "").is_err());
        assert!(
            validate_catalog_request(&tenant, &filter, 100, "urn:cerebro:other:vendor:example")
                .is_err()
        );

        filter.include_kinds.push("vendor".to_owned());
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_err());
        filter.include_kinds.pop();
        filter
            .relation_counts
            .as_mut()
            .expect("relation counts")
            .directions
            .push(EntityCatalogDirection::Incoming);
        assert!(validate_catalog_request(&tenant, &filter, 100, "").is_err());

        assert!(
            validate_catalog_relation_request(
                &tenant,
                "urn:cerebro:writer:vendor:example",
                &[EntityCatalogDirection::Incoming],
                &["associated_with".to_owned()],
                &["contract".to_owned()],
                &[],
                "",
                100,
                CatalogRelationCursor {
                    agent_key: "urn:cerebro:writer:contract:one",
                    relation: "",
                    direction: None,
                },
            )
            .is_err(),
            "all composite cursor fields are required"
        );
        assert!(
            validate_catalog_relation_request(
                &tenant,
                "urn:cerebro:writer:vendor:example",
                &[EntityCatalogDirection::Outgoing],
                &[],
                &[],
                &["urn:cerebro:other:contract:one".to_owned()],
                "",
                100,
                CatalogRelationCursor {
                    agent_key: "",
                    relation: "",
                    direction: None,
                },
            )
            .is_err(),
            "neighbor keys must remain tenant scoped"
        );
    }

    #[test]
    fn entity_catalog_queries_only_compile_active_filters() {
        assert!(NEO4J_SCHEMA.iter().any(|statement| {
            statement
                .contains("(entity.tenant_id, entity.application_workspace_id, entity.entity_type)")
        }));
        let default_filter = EntityCatalogFilter::default();
        assert_eq!(
            catalog_entity_match(&default_filter, CatalogCursor::AgentKey("")),
            "MATCH (entity:Entity {tenant_id: $tenant_id})"
        );
        assert_eq!(
            catalog_entity_match(&default_filter, CatalogCursor::EntityKind),
            "MATCH (entity:Entity {tenant_id: $tenant_id}) WHERE entity.entity_type > $after_kind"
        );

        let vendor_filter = EntityCatalogFilter {
            application_workspace_id: "workspace-a".to_owned(),
            source_id: "servicenow".to_owned(),
            include_kinds: vec!["vendor".to_owned()],
            ..Default::default()
        };
        let vendor_statement = catalog_entity_match(&vendor_filter, CatalogCursor::AgentKey(""));
        assert_eq!(
            vendor_statement,
            "MATCH (entity:Entity {tenant_id: $tenant_id, application_workspace_id: $application_workspace_id, source_id: $source_id, entity_type: $single_include_kind})"
        );
        assert!(!vendor_statement.contains("size("));
        assert!(!vendor_statement.contains(" OR "));

        let mixed_filter = EntityCatalogFilter {
            runtime_ids: vec!["runtime-a".to_owned()],
            include_kinds: vec!["vendor".to_owned()],
            include_kind_prefixes: vec!["vendor.".to_owned()],
            exclude_kinds: vec!["vendor.discovery".to_owned()],
            exclude_kind_prefixes: vec!["vendor.internal.".to_owned()],
            search: "acme".to_owned(),
            search_attributes: true,
            attribute_substrings_any: vec!["\"policy_id\":\"".to_owned()],
            ..Default::default()
        };
        let mixed_statement =
            catalog_entity_match(&mixed_filter, CatalogCursor::AgentKey("urn:next"));
        assert!(mixed_statement.starts_with(
            "MATCH (entity:Entity {tenant_id: $tenant_id}) WHERE entity.runtime_id IN $runtime_ids"
        ));
        assert!(mixed_statement.contains("entity.entity_type IN $include_kinds"));
        assert!(mixed_statement.contains("NOT entity.entity_type IN $exclude_kinds"));
        assert!(mixed_statement.contains("none(prefix IN $exclude_prefixes"));
        assert!(mixed_statement.contains("CONTAINS $search"));
        assert!(mixed_statement.contains("$attribute_substrings_any"));
        assert!(mixed_statement.ends_with("entity.urn > $after_key"));
    }

    #[test]
    fn entity_catalog_relation_counts_use_directed_root_lookups() {
        let incoming = catalog_relation_count_statement(&[EntityCatalogDirection::Incoming], false);
        assert!(incoming.starts_with("UNWIND $root_keys AS root_key"));
        assert!(incoming.contains("]->(root:Entity {tenant_id: $tenant_id, urn: root_key})"));
        assert!(!incoming.contains("startNode"));

        let outgoing = catalog_relation_count_statement(&[EntityCatalogDirection::Outgoing], false);
        assert!(outgoing.contains("urn: root_key})-[edge:RELATION"));
        assert!(!outgoing.contains("startNode"));

        let both = catalog_relation_count_statement(
            &[
                EntityCatalogDirection::Incoming,
                EntityCatalogDirection::Outgoing,
            ],
            false,
        );
        assert!(both.contains("startNode(edge) = root"));
        assert!(both.contains("direction IN $directions"));

        for directions in [
            vec![EntityCatalogDirection::Incoming],
            vec![EntityCatalogDirection::Outgoing],
            vec![
                EntityCatalogDirection::Incoming,
                EntityCatalogDirection::Outgoing,
            ],
        ] {
            let workspace = catalog_relation_count_statement(&directions, true);
            assert_eq!(
                workspace
                    .matches("application_workspace_id: $application_workspace_id")
                    .count(),
                3
            );
            assert!(workspace.contains("neighbor:Entity {tenant_id: $tenant_id, application_workspace_id: $application_workspace_id}"));
            assert!(workspace.contains("edge:RELATION {tenant_id: $tenant_id, application_workspace_id: $application_workspace_id}"));
            assert!(workspace.contains("root:Entity {tenant_id: $tenant_id, application_workspace_id: $application_workspace_id, urn: root_key}"));
        }
    }

    #[test]
    fn exposure_coverage_rejects_unbounded_or_ambiguous_profiles() {
        let valid = || ExposureCoverageQuery {
            profile: ExposureCoverageProfile {
                primary_source_id: "aws".to_owned(),
                primary_entity_kind_prefix: "aws.".to_owned(),
                corroborating_source_id: "vulnview".to_owned(),
                corroborating_entity_kind: "external.asset".to_owned(),
                indicator_kinds: vec!["internet.host".to_owned(), "internet.ip".to_owned()],
                account_kind: "cloud.account".to_owned(),
                corroborating_observation_kind: "vulnview.scan".to_owned(),
            },
            account_id: String::new(),
            region: String::new(),
            search: String::new(),
            limit: 100,
        };

        assert!(validate_exposure_coverage_query(&valid()).is_ok());
        assert!(should_query_corroborating_only(&valid()));
        let counts_statement = exposure_counts_statement();
        assert!(counts_statement.starts_with("OPTIONAL MATCH (revision:"));
        assert!(counts_statement.contains("CALL { MATCH (endpoint:Entity"));
        assert!(counts_statement.contains("RETURN graph_revision, primary_count"));

        let mut account_filtered = valid();
        account_filtered.account_id = "123456789012".to_owned();
        assert!(!should_query_corroborating_only(&account_filtered));

        let mut region_filtered = valid();
        region_filtered.region = "us-west-2".to_owned();
        assert!(!should_query_corroborating_only(&region_filtered));

        let mut search_filtered = valid();
        search_filtered.search = "example.com".to_owned();
        assert!(should_query_corroborating_only(&search_filtered));

        let mut zero = valid();
        zero.limit = 0;
        assert!(validate_exposure_coverage_query(&zero).is_err());

        let mut over = valid();
        over.limit = 101;
        assert!(validate_exposure_coverage_query(&over).is_err());

        let mut duplicate = valid();
        duplicate.profile.indicator_kinds = vec!["internet.host".to_owned(); 2];
        assert!(validate_exposure_coverage_query(&duplicate).is_err());

        let mut control = valid();
        control.search = "unsafe\nquery".to_owned();
        assert!(validate_exposure_coverage_query(&control).is_err());

        let mut truncated = vec![1, 2, 3];
        assert!(truncate_to_limit(&mut truncated, 2));
        assert_eq!(truncated, [1, 2]);
    }

    #[test]
    fn legacy_root_coverage_is_tenant_scoped_and_identifier_free() {
        assert!(LEGACY_ROOT_COVERAGE_STATEMENT.contains("$tenant_id"));
        assert!(LEGACY_ROOT_COVERAGE_STATEMENT.contains("$urn_prefix"));
        assert!(LEGACY_ROOT_COVERAGE_STATEMENT.contains("RETURN entity_type"));
        assert!(!LEGACY_ROOT_COVERAGE_STATEMENT.contains("RETURN legacy"));
        assert!(!LEGACY_ROOT_COVERAGE_STATEMENT.contains("legacy.urn AS"));

        let tenant_id = TenantId::parse("writer").expect("tenant");
        let coverage = aggregate_legacy_root_coverage(
            &tenant_id,
            [("finding".to_owned(), 7, 5), ("resource".to_owned(), 3, 3)],
        )
        .expect("valid aggregate");
        assert_eq!(coverage.legacy_roots, 10);
        assert_eq!(coverage.covered_roots, 8);
        assert_eq!(coverage.missing_roots, 2);
        assert_eq!(coverage.entity_types[0].missing_roots, 2);

        let json = serde_json::to_value(&coverage).expect("serialize receipt");
        assert_eq!(json["tenant_id"], "writer");
        assert_eq!(json["missing_roots"], 2);
        let object = json.as_object().expect("receipt object");
        assert_eq!(object.len(), 5, "receipt must remain aggregate-only");
    }

    #[test]
    fn legacy_root_coverage_rejects_impossible_counts() {
        let tenant_id = TenantId::parse("writer").expect("tenant");
        for rows in [
            vec![("resource".to_owned(), -1, 0)],
            vec![("resource".to_owned(), 1, -1)],
            vec![("resource".to_owned(), 1, 2)],
        ] {
            assert!(aggregate_legacy_root_coverage(&tenant_id, rows).is_err());
        }
    }

    #[test]
    fn legacy_compatibility_ids_are_tenant_bound_and_urn_safe() {
        let tenant_id = TenantId::parse("writer").expect("tenant");
        let other_tenant = TenantId::parse("other").expect("tenant");
        let urn = format!(
            "urn:cerebro:writer:github_pull_request:{}#{}@{}",
            "repository".repeat(40),
            2288,
            "example"
        );
        let first = legacy_entity_id(&tenant_id, &urn);
        assert_eq!(first, legacy_entity_id(&tenant_id, &urn));
        assert_ne!(first, legacy_entity_id(&other_tenant, &urn));
        assert!(first.as_str().starts_with("legacy-entity:"));
        assert!(first.as_str().len() < 100);
    }

    #[test]
    fn legacy_entity_preserves_product_type_and_rejects_cross_tenant_data() {
        let tenant_id = TenantId::parse("writer").expect("tenant");
        let urn = "urn:cerebro:writer:internet_host:example";
        let entity = legacy_context_entity(
            &tenant_id,
            urn,
            "internet_host".to_owned(),
            "example".to_owned(),
            r#"{"source_runtime_id":"runtime-a"}"#.to_owned(),
            "internet".to_owned(),
            "runtime-a".to_owned(),
        )
        .expect("legacy entity");
        assert_eq!(entity.agent_key, urn);
        assert_eq!(entity.properties["entity_type"], "internet_host");
        assert_eq!(entity.properties["source_id"], "internet");
        assert_eq!(entity.properties["source_runtime_id"], "runtime-a");

        assert!(
            legacy_context_entity(
                &tenant_id,
                "urn:cerebro:other:internet_host:example",
                "internet_host".to_owned(),
                "example".to_owned(),
                "{}".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_edges_preserve_provenance_and_fail_closed_on_conflict() {
        let tenant_id = TenantId::parse("writer").expect("tenant");
        let from = "urn:cerebro:writer:asset:one";
        let to = "urn:cerebro:writer:finding:two";
        let edge = legacy_context_edge(
            &tenant_id,
            from.to_owned(),
            "represents".to_owned(),
            to.to_owned(),
            LegacyEdgeMetadata {
                tenant_ids: vec![String::new()],
                runtime_ids: vec!["runtime-a".to_owned()],
                application_workspace_ids: vec!["workspace-a".to_owned()],
                properties_values: vec![
                    r#"{"source_runtime_id":"runtime-a","identity_binding":"true"}"#.to_owned(),
                ],
            },
        )
        .expect("legacy edge");
        assert_eq!(edge.source_runtime_id, "runtime-a");
        assert_eq!(edge.application_workspace_id, "workspace-a");
        assert!(edge.identity_binding);
        assert_eq!(
            edge.assertion_id,
            legacy_assertion_id(&tenant_id, from, "represents", to)
        );

        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                to.to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec!["writer".to_owned()],
                    runtime_ids: vec!["runtime-a".to_owned(), "runtime-b".to_owned()],
                    application_workspace_ids: vec![String::new()],
                    properties_values: vec!["{}".to_owned()],
                },
            )
            .is_err()
        );
        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                to.to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec!["writer".to_owned()],
                    runtime_ids: vec!["runtime-a".to_owned()],
                    application_workspace_ids: vec![
                        "workspace-a".to_owned(),
                        "workspace-b".to_owned(),
                    ],
                    properties_values: vec!["{}".to_owned()],
                },
            )
            .is_err()
        );
        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                to.to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec!["writer".to_owned()],
                    runtime_ids: vec!["runtime-a".to_owned()],
                    application_workspace_ids: vec!["w".repeat(129)],
                    properties_values: vec!["{}".to_owned()],
                },
            )
            .is_err()
        );
        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                to.to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec!["writer".to_owned()],
                    runtime_ids: vec!["runtime-a".to_owned()],
                    application_workspace_ids: vec![String::new()],
                    properties_values: vec![r#"{"source_runtime_id":"runtime-b"}"#.to_owned()],
                },
            )
            .is_err()
        );
        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                to.to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec!["other".to_owned()],
                    runtime_ids: vec!["runtime-a".to_owned()],
                    application_workspace_ids: vec![String::new()],
                    properties_values: vec!["{}".to_owned()],
                },
            )
            .is_err()
        );
        assert!(
            legacy_context_edge(
                &tenant_id,
                from.to_owned(),
                "owns".to_owned(),
                "urn:cerebro:other:finding:two".to_owned(),
                LegacyEdgeMetadata {
                    tenant_ids: vec![String::new()],
                    runtime_ids: vec!["runtime-a".to_owned()],
                    application_workspace_ids: vec![String::new()],
                    properties_values: vec!["{}".to_owned()],
                },
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_queries_are_tenant_scoped_and_preserve_go_edge_order() {
        assert!(LEGACY_ROOTS_STATEMENT.contains("tenant_id: $tenant_id"));
        for statement in [LEGACY_OUTGOING_STATEMENT, LEGACY_INCOMING_STATEMENT] {
            assert!(statement.contains("Entity {tenant_id: $tenant_id"));
            assert!(statement.contains("[relation:RELATION]"));
            assert!(statement.contains("coalesce(relation.tenant_id, '') IN ['', $tenant_id]"));
            assert!(statement.contains("relation_tenant_ids"));
            assert!(statement.contains("typed_application_workspace_ids"));
            assert!(statement.contains("LIMIT $row_limit"));
            assert!(statement.contains("ORDER BY neighbor.urn, relation_kind"));
        }
        assert!(!LEGACY_OUTGOING_STATEMENT.contains("UNION"));
        assert!(!LEGACY_INCOMING_STATEMENT.contains("UNION"));
        assert!(LEGACY_NEIGHBOR_SCOPE_STATEMENT.contains("relation.tenant_id"));
        assert!(LEGACY_NEIGHBOR_SCOPE_STATEMENT.contains("relation.tenant_id <> $tenant_id"));
        assert!(LEGACY_NEIGHBOR_SCOPE_STATEMENT.contains("coalesce(relation.tenant_id, '') <> ''"));
        assert!(LEGACY_NEIGHBOR_SCOPE_STATEMENT.contains("neighbor.tenant_id"));
    }

    #[test]
    fn cloud_attack_path_query_is_closed_tenant_scoped_and_bounded() {
        let tenant = TenantId::parse("writer").expect("tenant");
        assert!(validate_cloud_attack_path_request("", "", 1, 1).is_ok());
        assert!(validate_cloud_attack_path_request("prod", "runtime-a", 100, 6).is_ok());
        assert!(validate_cloud_attack_path_request("", "", 0, 4).is_err());
        assert!(validate_cloud_attack_path_request("", "", 101, 4).is_err());
        assert!(validate_cloud_attack_path_request("", "", 10, 0).is_err());
        assert!(validate_cloud_attack_path_request("", "", 10, 7).is_err());
        assert!(validate_cloud_attack_path_request(&"a".repeat(257), "", 10, 4).is_err());
        assert!(tenant.as_str().starts_with("writer"));

        for relation_type in ["RELATION", "RELATION_ASSERTION"] {
            let counts = cloud_attack_path_counts_statement(6, relation_type);
            let samples = cloud_attack_path_samples_statement(6, relation_type);
            for statement in [&counts, &samples] {
                assert!(statement.contains("tenant_id: $tenant_id"));
                assert!(statement.contains(&format!("[:{relation_type}*1..6]")));
                assert!(statement.contains("rel.relation IN $traversal_relations"));
                assert!(statement.contains("access.relation IN $access_relations"));
                assert!(statement.contains("$runtime_id = ''"));
                assert!(!statement.contains("__RELATION_TYPE__"));
                assert!(!statement.contains("__DEPTH__"));
            }
            assert!(counts.contains("count(DISTINCT exposed)"));
            assert!(samples.contains("relation: 'owned_by'"));
            assert!(samples.contains(
                "ORDER BY account.label, exposed.label, principal.label, permission.label"
            ));
            assert!(samples.ends_with("LIMIT $row_limit"));
        }
        assert_eq!(cloud_attack_path_traversal_relations().len(), 7);
        assert_eq!(cloud_attack_path_access_relations().len(), 4);
    }

    #[tokio::test]
    #[ignore = "requires a disposable Neo4j instance"]
    async fn cloud_attack_path_fixture_is_served_by_typed_rust_read() -> Result<(), Box<dyn Error>>
    {
        let graph = Graph::new(
            env::var("CEREBRO_TEST_NEO4J_URI")?,
            env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
            env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
        )
        .await?;
        let tenant = format!("tenant-cloud-attack-path-{}", std::process::id());
        let tenant_id = TenantId::parse(tenant.clone())?;
        let runtime = "runtime-cloud-a";
        let public = format!("urn:cerebro:{tenant}:public:internet");
        let exposed = format!("urn:cerebro:{tenant}:resource:eni-1");
        let account = format!("urn:cerebro:{tenant}:account:prod");
        let principal = format!("urn:cerebro:{tenant}:principal:admin");
        let permission = format!("urn:cerebro:{tenant}:permission:admin");
        let owner = format!("urn:cerebro:{tenant}:team:security");
        graph
            .run(
                query(
                    r#"CREATE (public:Entity {tenant_id: $tenant, urn: $public, entity_type: 'aws.public_principal', label: 'public internet'})
CREATE (exposed:Entity {tenant_id: $tenant, urn: $exposed, entity_type: 'aws.network.interface', label: 'eni-1'})
CREATE (account:Entity {tenant_id: $tenant, urn: $account, entity_type: 'cloud.account', label: 'prod'})
CREATE (principal:Entity {tenant_id: $tenant, urn: $principal, entity_type: 'aws.role', label: 'admin'})
CREATE (permission:Entity {tenant_id: $tenant, urn: $permission, entity_type: 'aws.policy', label: 'AdministratorAccess'})
CREATE (owner:Entity {tenant_id: $tenant, urn: $owner, entity_type: 'team', label: 'Security'})
CREATE (public)-[:RELATION {tenant_id: $tenant, relation: 'can_reach', source_id: 'aws', runtime_id: $runtime, attributes_json: '{"source_event_id":"event-exposure","at":"2026-08-31T12:00:00Z"}'}]->(exposed)
CREATE (exposed)-[:RELATION {tenant_id: $tenant, relation: 'belongs_to', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(account)
CREATE (exposed)-[:RELATION {tenant_id: $tenant, relation: 'runs_as', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(principal)
CREATE (principal)-[:RELATION {tenant_id: $tenant, relation: 'can_admin', source_id: 'aws', runtime_id: $runtime, attributes_json: '{"is_admin":"true"}'}]->(permission)
CREATE (permission)-[:RELATION {tenant_id: $tenant, relation: 'belongs_to', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(account)
CREATE (exposed)-[:RELATION {tenant_id: $tenant, relation: 'owned_by', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(owner)
CREATE (public)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'can_reach', source_id: 'aws', runtime_id: $runtime, attributes_json: '{"source_event_id":"event-exposure","at":"2026-08-31T12:00:00Z"}'}]->(exposed)
CREATE (exposed)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'belongs_to', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(account)
CREATE (exposed)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'runs_as', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(principal)
CREATE (principal)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'can_admin', source_id: 'aws', runtime_id: $runtime, attributes_json: '{"is_admin":"true"}'}]->(permission)
CREATE (permission)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'belongs_to', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(account)
CREATE (exposed)-[:RELATION_ASSERTION {tenant_id: $tenant, relation: 'owned_by', source_id: 'aws', runtime_id: $runtime, attributes_json: '{}'}]->(owner)
CREATE (:OrganizationalGraphRevision {tenant_id: $tenant, graph_revision: 42})"#,
                )
                .param("tenant", tenant.clone())
                .param("runtime", runtime)
                .param("public", public.clone())
                .param("exposed", exposed.clone())
                .param("account", account.clone())
                .param("principal", principal.clone())
                .param("permission", permission.clone())
                .param("owner", owner.clone()),
            )
            .await?;

        let projector = Neo4jProjector::from_graph(graph.clone());
        let page = projector
            .list_cloud_attack_paths(&tenant_id, "prod", runtime, true, 10, 4, 42)
            .await?;
        assert_eq!(page.tenant_id, tenant);
        assert_eq!(page.graph_revision, 42);
        assert_eq!(page.counts.paths, 1);
        assert_eq!(page.paths.len(), 1);
        assert!(!page.truncated);
        let path = &page.paths[0];
        assert_eq!(path.public_principal.urn, public);
        assert_eq!(path.exposed_resource.urn, exposed);
        assert_eq!(path.cloud_account.urn, account);
        assert_eq!(path.principal.urn, principal);
        assert_eq!(path.permission.urn, permission);
        assert_eq!(path.relation_chain, ["runs_as".to_owned()]);
        assert_eq!(path.ownerships.len(), 1);
        assert_eq!(path.ownerships[0].owner.urn, owner);
        assert_eq!(
            path.exposure_edge.assertion_runtime_ids,
            [runtime.to_owned()]
        );
        assert!(
            path.exposure_edge
                .attributes_json
                .contains("event-exposure")
        );

        let logical = projector
            .list_cloud_attack_paths(&tenant_id, "", "", false, 10, 4, 42)
            .await?;
        assert_eq!(logical.counts.paths, 1);
        assert_eq!(logical.paths.len(), 1);
        let unrelated = projector
            .list_cloud_attack_paths(&tenant_id, "", "runtime-other", true, 10, 4, 42)
            .await?;
        assert_eq!(unrelated.counts.paths, 0);
        assert!(unrelated.paths.is_empty());
        assert!(
            projector
                .list_cloud_attack_paths(&tenant_id, "", "", true, 10, 4, 41)
                .await
                .is_err()
        );

        graph
            .run(
                query("MATCH (node {tenant_id: $tenant}) DETACH DELETE node")
                    .param("tenant", tenant),
            )
            .await?;
        Ok(())
    }

    #[test]
    fn effective_access_query_is_closed_tenant_scoped_and_bounded() {
        let statement = effective_access_path_statement();
        assert_eq!(statement.matches("\n  UNION\n").count(), 6);
        assert!(statement.starts_with("MATCH (subject:Entity {tenant_id: $tenant_id})"));
        assert!(
            statement.contains("ORDER BY subject.label, subject.urn\nLIMIT $sample_limit\nCALL")
        );
        assert!(statement.ends_with("LIMIT $row_limit"));
        assert!(
            statement.contains("identity_link.relation IN ['represents_identity', 'same_actor']")
        );
        assert!(statement.contains("role_assignment.relation IN ['assigned_to', 'can_admin']"));
        for relation in [
            "same_actor",
            "represents_identity",
            "assigned_to",
            "member_of",
            "can_admin",
            "grants_entitlement",
            "confers_capability",
        ] {
            assert!(statement.contains(relation));
        }
        assert!(statement.contains("toLower(coalesce(subject.urn, '')) CONTAINS $identity_query"));
        assert!(
            statement.contains("toLower(coalesce(subject.label, '')) CONTAINS $identity_query")
        );
        assert!(
            statement.contains(
                "toLower(coalesce(subject.attributes_json, '')) CONTAINS $identity_query"
            )
        );
        assert!(!statement.contains("[*"));
    }

    #[test]
    fn effective_access_request_rejects_unbounded_and_cross_tenant_selectors() {
        let tenant_id = TenantId::parse("writer").expect("tenant");
        assert!(
            validate_effective_access_request(
                &tenant_id,
                "urn:cerebro:writer:identity:one",
                "",
                "",
                "",
                "read",
                25,
            )
            .is_ok()
        );
        assert!(
            validate_effective_access_request(
                &tenant_id,
                "urn:cerebro:other:identity:one",
                "",
                "",
                "",
                "read",
                25,
            )
            .is_err()
        );
        assert!(validate_effective_access_request(
            &tenant_id,
            "",
            &"q".repeat(513),
            "",
            "",
            "read",
            25,
        )
        .is_err());
        assert!(
            validate_effective_access_request(
                &tenant_id,
                "urn:cerebro:writer:identity:one",
                "",
                "",
                "",
                "read",
                101,
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable Neo4j instance"]
    async fn effective_access_fixture_matches_bounded_typed_page_on_disposable_graph()
    -> Result<(), Box<dyn Error>> {
        let graph = Graph::new(
            env::var("CEREBRO_TEST_NEO4J_URI")?,
            env::var("CEREBRO_TEST_NEO4J_USERNAME")?,
            env::var("CEREBRO_TEST_NEO4J_PASSWORD")?,
        )
        .await?;
        let tenant = format!("tenant-effective-access-{}", std::process::id());
        let other_tenant = format!("{tenant}-other");
        let tenant_id = TenantId::parse(tenant.clone())?;
        let subject_urn = format!("urn:cerebro:{tenant}:identity:subject-live");
        let principal_urn = format!("urn:cerebro:{tenant}:principal:subject-live");
        let group_urn = format!("urn:cerebro:{tenant}:group:engineering");
        let application_urn = format!("urn:cerebro:{tenant}:application:console");
        let entitlement_urn = format!("urn:cerebro:{tenant}:entitlement:reader-a");
        let capability_urn = format!("urn:cerebro:{tenant}:capability:read");
        let other_entitlement_urn = format!("urn:cerebro:{tenant}:entitlement:reader-b");
        let other_capability_urn = format!("urn:cerebro:{tenant}:capability:secondary:read");

        graph
            .run(
                query(
                    r#"CREATE (subject:Entity {tenant_id: $tenant, urn: $subject, entity_type: 'identity.person', label: 'Subject Live', attributes_json: '{\"email\":\"subject@example.com\"}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (principal:Entity {tenant_id: $tenant, urn: $principal, entity_type: 'identity.principal', label: 'Subject Principal', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (group:Entity {tenant_id: $tenant, urn: $group, entity_type: 'identity.group', label: 'Engineering', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (application:Entity {tenant_id: $tenant, urn: $application, entity_type: 'okta.application', label: 'Console', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (entitlement:Entity {tenant_id: $tenant, urn: $entitlement, entity_type: 'okta.entitlement', label: 'Reader A', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (capability:Entity {tenant_id: $tenant, urn: $capability, entity_type: 'okta.capability', label: 'Capability A', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (other_entitlement:Entity {tenant_id: $tenant, urn: $other_entitlement, entity_type: 'okta.entitlement', label: 'Reader B', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (other_capability:Entity {tenant_id: $tenant, urn: $other_capability, entity_type: 'okta.capability', label: 'Capability B', attributes_json: '{}', source_id: 'okta', runtime_id: 'okta-live'})
CREATE (principal)-[:RELATION {tenant_id: $tenant, relation: 'represents_identity', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(subject)
CREATE (principal)-[:RELATION {tenant_id: $tenant, relation: 'member_of', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(group)
CREATE (group)-[:RELATION {tenant_id: $tenant, relation: 'assigned_to', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{\"assignment_id\":\"assignment-live\"}'}]->(application)
CREATE (application)-[:RELATION {tenant_id: $tenant, relation: 'grants_entitlement', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(entitlement)
CREATE (entitlement)-[:RELATION {tenant_id: $tenant, relation: 'confers_capability', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(capability)
CREATE (application)-[:RELATION {tenant_id: $tenant, relation: 'grants_entitlement', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(other_entitlement)
CREATE (other_entitlement)-[:RELATION {tenant_id: $tenant, relation: 'confers_capability', source_id: 'okta', runtime_id: 'okta-live', attributes_json: '{}'}]->(other_capability)
CREATE (:OrganizationalGraphRevision {tenant_id: $tenant, graph_revision: 42})
CREATE (:Entity {tenant_id: $other_tenant, urn: $other_subject, entity_type: 'identity.person', label: 'Subject Live', attributes_json: '{}'})"#,
                )
                .param("tenant", tenant.clone())
                .param("other_tenant", other_tenant.clone())
                .param(
                    "other_subject",
                    format!("urn:cerebro:{other_tenant}:identity:subject-live"),
                )
                .param("subject", subject_urn.clone())
                .param("principal", principal_urn.clone())
                .param("group", group_urn.clone())
                .param("application", application_urn.clone())
                .param("entitlement", entitlement_urn.clone())
                .param("capability", capability_urn.clone())
                .param("other_entitlement", other_entitlement_urn)
                .param("other_capability", other_capability_urn),
            )
            .await?;

        let projector = Neo4jProjector::from_graph(graph.clone());
        let page = projector
            .list_effective_access_paths(
                &tenant_id,
                "",
                "subject live",
                &application_urn,
                "",
                "read",
                1,
                42,
            )
            .await?;
        assert_eq!(page.tenant_id, tenant);
        assert_eq!(page.graph_revision, 42);
        assert!(page.truncated);
        assert_eq!(page.paths.len(), 1);
        let path = &page.paths[0];
        assert_eq!(path.identity.agent_key, subject_urn);
        assert_eq!(path.principal.agent_key, principal_urn);
        assert_eq!(path.assignment_kind, "group_app_assignment");
        assert_eq!(
            path.identity_relation_chain,
            ["represents_identity".to_owned()]
        );
        assert_eq!(
            path.relation_chain,
            [
                "member_of".to_owned(),
                "assigned_to".to_owned(),
                "grants_entitlement".to_owned(),
                "confers_capability".to_owned(),
            ]
        );
        assert_eq!(path.edges.len(), 4);
        assert_eq!(path.capability.agent_key, capability_urn);
        assert_eq!(path.edges[1].runtime_id, "okta-live");
        assert!(path.edges[1].attributes_json.contains("assignment-live"));
        assert!(
            projector
                .list_effective_access_paths(&tenant_id, &subject_urn, "", "", "", "read", 1, 41,)
                .await
                .is_err()
        );

        graph
            .run(
                query(
                    "MATCH (node) WHERE node.tenant_id IN [$tenant, $other_tenant] DETACH DELETE node",
                )
                .param("tenant", tenant)
                .param("other_tenant", other_tenant),
            )
            .await?;
        Ok(())
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
