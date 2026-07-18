export interface GraphQueryTemplate {
  id: string;
  purpose: string;
  cypher: string;
  notes: string[];
}

export interface GraphCypherGuide {
  contract: {
    nodeLabel: string;
    relationshipType: string;
    requiredNodeScope: string;
    requiredLimit: string;
    rowLimit: number;
    forbidden: string[];
  };
  ontology: {
    nodeProperties: string[];
    relationProperties: string[];
    importantEntityTypes: string[];
    importantRelations: string[];
  };
  draftingRules: string[];
  templates: GraphQueryTemplate[];
}

export function cerebroGraphCypherGuide(): GraphCypherGuide {
  return {
    contract: {
      nodeLabel: "Entity",
      relationshipType: "RELATION",
      requiredNodeScope: "Every node pattern must use `:Entity {tenant_id: $tenant_id}` or otherwise inline `tenant_id: $tenant_id`.",
      requiredLimit: "Every query must include a numeric LIMIT at or below 100.",
      rowLimit: 100,
      forbidden: [
        "CREATE, MERGE, SET, DELETE, DETACH, REMOVE, DROP, FOREACH",
        "LOAD CSV and USING PERIODIC COMMIT",
        "CALL procedures, APOC functions/procedures, db.* procedures",
        "UNWIND, range(), collect(), broad unscoped MATCH clauses, and all-node scans",
      ],
    },
    ontology: {
      nodeProperties: [
        "tenant_id",
        "urn",
        "source_id",
        "runtime_id",
        "entity_type",
        "label",
        "attributes_json",
        "internet_exposed",
        "privileged_identity",
        "mfa_disabled",
      ],
      relationProperties: ["tenant_id", "source_id", "runtime_id", "relation", "attributes_json"],
      importantEntityTypes: [
        "finding",
        "source",
        "person",
        "identity.email",
        "identity.login",
        "github.code.repository",
        "github.org",
        "cloud.account",
        "aws.ec2.instance",
        "aws.public_principal",
        "gcp.public_principal",
        "azure.public_principal",
      ],
      importantRelations: [
        "has_finding",
        "belongs_to",
        "has_identifier",
        "represents_identity",
        "same_actor",
        "can_admin",
        "can_perform",
        "can_assume",
        "can_impersonate",
        "runs_as",
        "can_reach",
        "assigned_to",
        "member_of",
      ],
    },
    draftingRules: [
      "Use `:Entity`, never labels such as `:Finding`, `:Repository`, `:Identity`, or `:Connector`.",
      "Use `:RELATION {relation: 'has_finding'}`. Do not use relationship types such as `:HAS_FINDING`.",
      "Treat most rich fields as JSON text in `attributes_json`; prefer top-level typed fields only when the backend promotes them.",
      "Prefer deterministic backend intents before raw Cypher: top_risk_findings, aggregate_findings_by_source, explain_finding, identity_bridge, connector_health.",
      "For findings, start from `(resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})`.",
      "For identity questions, bridge concrete principals through `represents_identity` and `same_actor`; do not assume an `email` top-level property.",
      "For cloud attack paths, combine `can_reach` with privileged relations such as `can_admin`, `can_perform`, `can_assume`, and `can_impersonate` scoped to the same `cloud.account`.",
      "Return URNs, labels, entity types, relation names, and the minimum attributes needed to cite the answer.",
    ],
    templates: graphQueryTemplates(),
  };
}

export function graphQueryTemplates(): GraphQueryTemplate[] {
  return [
    {
      id: "graph_shape_probe",
      purpose: "Inspect the available entity types or relation names before choosing a narrower query.",
      cypher: `MATCH (n:Entity {tenant_id: $tenant_id})
RETURN n.entity_type AS name, count(n) AS count
ORDER BY count DESC, name
LIMIT 20`,
      notes: ["Use relation probe by matching `(:Entity {tenant_id: $tenant_id})-[r:RELATION]->(:Entity {tenant_id: $tenant_id})` and returning `r.relation`."],
    },
    {
      id: "top_open_findings",
      purpose: "List open findings with affected resources.",
      cypher: `MATCH (resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE coalesce(finding.attributes_json, '') CONTAINS '"status":"open"'
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       resource.urn AS resource_urn,
       coalesce(resource.label, resource.urn) AS resource_label,
       resource.entity_type AS resource_type,
       coalesce(finding.attributes_json, '') AS finding_attributes_json
ORDER BY finding_urn
LIMIT 25`,
      notes: ["If status lives on relation attributes for a rule, backend deterministic templates can recover it."],
    },
    {
      id: "findings_by_source",
      purpose: "Group findings by source/runtime family.",
      cypher: `MATCH (resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WITH DISTINCT finding
RETURN finding.source_id AS source_id, count(finding) AS finding_count
ORDER BY finding_count DESC, source_id
LIMIT 25`,
      notes: ["Backend post-processing can extract `source_family` from finding attributes when available."],
    },
    {
      id: "identity_bridge",
      purpose: "Find concrete principals that represent the same canonical identity across systems.",
      cypher: `MATCH (left:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})
MATCH (right:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})
WHERE left.urn < right.urn
  AND left.entity_type <> right.entity_type
  AND NOT left.entity_type STARTS WITH 'identity'
  AND NOT right.entity_type STARTS WITH 'identity'
RETURN identity.urn AS identity_urn,
       coalesce(identity.label, identity.urn) AS identity_label,
       left.urn AS left_urn,
       left.entity_type AS left_type,
       coalesce(left.label, left.urn) AS left_label,
       right.urn AS right_urn,
       right.entity_type AS right_type,
       coalesce(right.label, right.urn) AS right_label
ORDER BY identity_label, left_urn, right_urn
LIMIT 25`,
      notes: ["Use this for Okta/GitHub/account-linkage questions."],
    },
    {
      id: "connector_health_nodes",
      purpose: "Read source/runtime nodes projected into the graph.",
      cypher: `MATCH (source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
RETURN source.urn AS source_urn,
       coalesce(source.label, source.urn) AS source_label,
       source.source_id AS source_id,
       source.runtime_id AS runtime_id,
       coalesce(source.attributes_json, '') AS source_attributes_json
ORDER BY source_label, source_urn
LIMIT 50`,
      notes: ["Use runtime health API for operational health; graph source nodes help connect sources to entities."],
    },
    {
      id: "cloud_attack_path_sample",
      purpose: "Sample public-to-privileged cloud paths.",
      cypher: `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
MATCH (principal:Entity {tenant_id: $tenant_id})-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND access.relation IN ['can_admin', 'can_perform', 'can_assume', 'can_impersonate']
RETURN public.urn AS public_urn,
       exposed.urn AS exposed_urn,
       account.urn AS account_urn,
       principal.urn AS principal_urn,
       permission.urn AS permission_urn,
       reach.relation AS reach_relation,
       access.relation AS access_relation
ORDER BY account.urn, exposed.urn, principal.urn
LIMIT 25`,
      notes: ["For `can_perform`, inspect relation attributes for admin-level permissions before calling it privileged."],
    },
  ];
}

export function graphGuideForPrompt(): string {
  const guide = cerebroGraphCypherGuide();
  return [
    "Cerebro graph Cypher contract:",
    `- Nodes: :${guide.contract.nodeLabel}; relationships: :${guide.contract.relationshipType} with lowercase relation property.`,
    `- Scope: ${guide.contract.requiredNodeScope}`,
    `- Limit: ${guide.contract.requiredLimit}`,
    `- Entity types: ${guide.ontology.importantEntityTypes.join(", ")}.`,
    `- Relations: ${guide.ontology.importantRelations.join(", ")}.`,
    "- Use cerebro_graph_cypher_schema before drafting custom graph questions.",
    "- Use cerebro_graph_cypher_investigate to let Cerebro validate, execute, and return Cypher plus rows.",
  ].join("\n");
}
