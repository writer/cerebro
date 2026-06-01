package findings

const sentinelOneUnmitigatedThreatRuleID = "sentinelone-unmitigated-threat"

func newSentinelOneUnmitigatedThreatRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          sentinelOneUnmitigatedThreatRuleID,
		Name:        "SentinelOne Unmitigated Threat",
		Description: "Detect current SentinelOne threats that remain unresolved or not mitigated in the projected graph.",
		SourceID:    "sentinelone",
		EventKinds:  []string{sentinelOneThreatEntityType},
		OutputKind:  "finding.sentinelone_unmitigated_threat_current",
		Severity:    "HIGH",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"sentinelone", "threat", "mitigation", "malware", "graph-rule"},
		References:  []string{"https://docs.sentinelone.com/"},
		FalsePositives: []string{
			"Benign or false-positive verdicts not yet synchronized into the graph.",
		},
		Runbook:           "Review the SentinelOne incident, mitigation status, endpoint context, and analyst verdict; mitigate or mark benign in SentinelOne.",
		FingerprintFields: []string{"threat_urn"},
		ControlRefs:       cloneFindingControlRefs(sentinelOneThreatResponseControlRefs),
	}, map[string][]string{"sentinelone": {"threat"}}, `MATCH (threat:Entity {tenant_id: $tenant_id, entity_type: 'sentinelone.threat'})
OPTIONAL MATCH (agent:Entity {tenant_id: $tenant_id, entity_type: 'sentinelone.agent'})-[affected:RELATION {relation: 'affected_by'}]->(threat)
WHERE NOT (
    coalesce(threat.attributes_json, '') CONTAINS '"analyst_verdict":"false_positive"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"analyst_verdict_norm":"false_positive"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"classification":"Benign"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"classification_norm":"benign"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"automatically_resolved":"true"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status":"mitigated"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status_norm":"mitigated"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status":"marked_as_benign"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status_norm":"marked_as_benign"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"incident_status":"resolved"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"incident_status_norm":"resolved"'
  )
  AND (
    coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status":"not_mitigated"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"mitigation_status_norm":"not_mitigated"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"incident_status":"unresolved"'
    OR coalesce(threat.attributes_json, '') CONTAINS '"incident_status_norm":"unresolved"'
  )
RETURN threat.urn AS primary_urn,
       threat.label AS primary_label,
       threat.entity_type AS primary_type,
       threat.urn AS fingerprint_key,
       CASE
         WHEN coalesce(threat.attributes_json, '') CONTAINS '"classification":"Ransomware"' OR coalesce(threat.attributes_json, '') CONTAINS '"classification":"Infostealer"' THEN 'CRITICAL'
         ELSE 'HIGH'
       END AS severity,
       'SentinelOne threat ' + coalesce(threat.label, threat.urn) + ' remains unresolved or not mitigated' AS summary,
       'Mitigate the threat in SentinelOne or document a benign/false-positive verdict' AS action,
       CASE WHEN agent.urn IS NULL THEN [threat.urn] ELSE [threat.urn, agent.urn] END AS resource_urns,
       CASE WHEN agent.urn IS NULL THEN [] ELSE [{urn: agent.urn, label: agent.label, entity_type: agent.entity_type, relation: 'affected_by', attributes_json: coalesce(affected.attributes_json, '')}] END AS evidence
ORDER BY severity DESC, threat.label, threat.urn
LIMIT $row_limit`, nil)
}
