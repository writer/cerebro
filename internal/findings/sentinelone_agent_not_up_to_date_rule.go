package findings

const sentinelOneAgentNotUpToDateRuleID = "sentinelone-agent-not-up-to-date"

func newSentinelOneAgentNotUpToDateRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          sentinelOneAgentNotUpToDateRuleID,
		Name:        "SentinelOne Agent Not Up To Date",
		Description: "Detect active SentinelOne agents whose protection agent version is not up to date.",
		SourceID:    "sentinelone",
		EventKinds:  []string{sentinelOneAgentEntityType},
		OutputKind:  "finding.sentinelone_agent_not_up_to_date",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"sentinelone", "endpoint", "coverage", "agent-version", "graph-rule"},
		References:  []string{"https://docs.sentinelone.com/"},
		FalsePositives: []string{
			"Endpoint is in a documented rollout ring, maintenance window, or decommissioning workflow not yet reflected in inventory.",
		},
		Runbook:           "Update the SentinelOne agent, confirm policy assignment, or document a temporary exception for the endpoint rollout ring.",
		FingerprintFields: []string{"agent_urn"},
		ControlRefs:       cloneFindingControlRefs(sentinelOneEndpointCoverageControlRefs),
	}, map[string][]string{"sentinelone": {"agent"}}, `MATCH (agent:Entity {tenant_id: $tenant_id, entity_type: 'sentinelone.agent'})
WHERE coalesce(agent.attributes_json, '') CONTAINS '"is_up_to_date":"false"'
  AND NOT coalesce(agent.attributes_json, '') CONTAINS '"is_decommissioned":"true"'
  AND coalesce(agent.attributes_json, '') CONTAINS '"is_active":"true"'
  AND NOT coalesce(agent.attributes_json, '') CONTAINS '"is_uninstalled":"true"'
  AND NOT coalesce(agent.attributes_json, '') CONTAINS '"is_pending_uninstall":"true"'
RETURN agent.urn AS primary_urn,
       agent.label AS primary_label,
       agent.entity_type AS primary_type,
       agent.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'SentinelOne agent ' + coalesce(agent.label, agent.urn) + ' is not up to date' AS summary,
       'Update the endpoint agent or document a temporary rollout exception' AS action,
       [agent.urn] AS resource_urns,
       [] AS evidence
ORDER BY agent.label, agent.urn
LIMIT $row_limit`, nil)
}
