package findings

import "github.com/writer/cerebro/internal/ports"

const githubOrgOwnerConcentrationRuleID = "github-org-owner-role-review-needed"

func newGitHubOrgOwnerConcentrationRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          githubOrgOwnerConcentrationRuleID,
		Name:        "GitHub Organization Owner Needs Review",
		Description: "Detect GitHub organization members with the owner role, which grants unrestricted administrative access including billing, membership, and security settings.",
		SourceID:    "github",
		EventKinds:  []string{"github.org_member"},
		OutputKind:  "finding.github_org_owner_role_review_needed",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"github", "identity", "privilege", "org-owner", "graph-rule", "attack.t1098"},
		References: []string{
			"https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization",
		},
		FalsePositives:    []string{"Designated org owners with documented need for administrative access and active operational responsibilities."},
		Runbook:           "Validate each org owner has a documented business need for the owner role. Demote members to the member role where administrative access is not required. Ensure owner accounts have MFA and are not shared.",
		FingerprintFields: []string{"member_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.3"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"},
		},
	}, map[string][]string{"github": {"org_inventory"}}, `MATCH (member:Entity {tenant_id: $tenant_id, entity_type: 'github.user'})
WHERE coalesce(member.attributes_json, '') CONTAINS '"role":"admin"'
RETURN member.urn AS primary_urn,
       member.label AS primary_label,
       member.entity_type AS primary_type,
       member.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'GitHub org owner ' + coalesce(member.label, member.urn) + ' has unrestricted administrative access' AS summary,
       'Validate business need for owner role; demote to member where administrative access is not required' AS action,
       [member.urn] AS resource_urns,
       [] AS evidence
ORDER BY member.label, member.urn
LIMIT $row_limit`, nil)
}
