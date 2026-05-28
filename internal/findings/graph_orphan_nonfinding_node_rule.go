package findings

import "github.com/writer/cerebro/internal/ports"

const graphOrphanNonFindingNodeRuleID = "graph-orphan-nonfinding-node"

func newGraphOrphanNonFindingNodeRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          graphOrphanNonFindingNodeRuleID,
		Name:        "Graph Orphan Non-Finding Node",
		Description: "Detect non-finding graph nodes with no relationships, indicating source projection or enrichment gaps.",
		SourceID:    "graph",
		EventKinds:  []string{"graph"},
		OutputKind:  "finding.graph_orphan_nonfinding_node",
		Severity:    "LOW",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"graph", "graph-hygiene", "orphan", "enrichment"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Some source records may intentionally be inventory-only and not yet connected to the rest of the graph.",
		},
		Runbook:           "Review the source projection for the entity type and add ownership, source, identity, or resource relations where appropriate.",
		FingerprintFields: []string{"orphan_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.35"},
		},
	}, nil, `MATCH (entity:Entity {tenant_id: $tenant_id})
WHERE entity.entity_type <> 'finding'
  AND NOT (entity)-[:RELATION]-()
RETURN entity.urn AS primary_urn,
       entity.label AS primary_label,
       entity.entity_type AS primary_type,
       entity.urn AS fingerprint_key,
       'LOW' AS severity,
       'Graph entity ' + coalesce(entity.label, entity.urn) + ' has no relationships' AS summary,
       'Add projection relationships or document why the entity is intentionally inventory-only' AS action,
       [entity.urn] AS resource_urns,
       [] AS evidence
ORDER BY entity.entity_type, entity.label, entity.urn
LIMIT $row_limit`, nil)
}
