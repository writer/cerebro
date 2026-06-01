package findings

import "github.com/writer/cerebro/internal/ports"

const oktaThreatInsightNotBlockingRuleID = "identity-okta-threat-insight-not-blocking"

func newOktaThreatInsightNotBlockingRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          oktaThreatInsightNotBlockingRuleID,
		Name:        "Okta ThreatInsight Not Blocking",
		Description: "Detect Okta ThreatInsight configuration that is set to audit-only or disabled, leaving the org without automated brute-force and credential-stuffing protection.",
		SourceID:    "okta",
		EventKinds:  []string{"okta.threat_insight"},
		OutputKind:  "finding.identity_okta_threat_insight_not_blocking",
		Severity:    "HIGH",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"identity", "okta", "threat-insight", "brute-force", "graph-rule", "attack.t1110"},
		References: []string{
			"https://help.okta.com/en-us/content/topics/security/threat-insight/configure-threatinsight-system-log.htm",
		},
		FalsePositives:    []string{"Org intentionally running ThreatInsight in audit mode during initial rollout or policy evaluation period."},
		Runbook:           "Review ThreatInsight configuration and set action to 'block' to enable automated brute-force protection. Verify exclude zones are intentional.",
		FingerprintFields: []string{"threat_insight_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.16"},
		},
	}, map[string][]string{"okta": {"threat_insight"}}, `MATCH (ti:Entity {tenant_id: $tenant_id, entity_type: 'okta.threat_insight'})
WHERE NOT coalesce(ti.attributes_json, '') CONTAINS '"action":"block"'
RETURN ti.urn AS primary_urn,
       ti.label AS primary_label,
       ti.entity_type AS primary_type,
       ti.urn AS fingerprint_key,
       'HIGH' AS severity,
       'Okta ThreatInsight is not set to block — brute-force protection is disabled or audit-only' AS summary,
       'Set ThreatInsight action to block to enable automated credential-stuffing and brute-force protection' AS action,
       [ti.urn] AS resource_urns,
       [] AS evidence
ORDER BY ti.urn
LIMIT $row_limit`, nil)
}
