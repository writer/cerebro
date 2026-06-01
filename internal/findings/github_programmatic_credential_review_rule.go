package findings

import "github.com/writer/cerebro/internal/ports"

const githubProgrammaticCredentialReviewRuleID = "github-programmatic-credential-review-needed"

func newGitHubProgrammaticCredentialReviewRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          githubProgrammaticCredentialReviewRuleID,
		Name:        "GitHub Programmatic Credential Needs Review",
		Description: "Detect current GitHub programmatic credentials, integrations, OAuth apps, and credential authorizations that should have explicit ownership and review.",
		SourceID:    "github",
		EventKinds:  []string{"github.audit"},
		OutputKind:  "finding.github_programmatic_credential_review_needed",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"github", "credential", "programmatic-access", "graph-rule", "attack.t1098"},
		References: []string{
			"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
			"https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps",
		},
		FalsePositives: []string{"Approved deploy keys, service accounts, or GitHub Apps with documented owner, scope, and rotation process."},
		Runbook:        "Confirm owner, scope, last-use/need, and rotation for the credential or integration; remove unused access or document the exception.",
		FingerprintFields: []string{
			"github_credential_urn",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
		},
	}, map[string][]string{"github": {"audit"}}, `MATCH (resource:Entity {tenant_id: $tenant_id, entity_type: 'github.credential'})
WHERE (
    coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"personal_access_token"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"org_credential_authorization"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"integration_installation"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"integration_installation_request"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"oauth_application"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"integration"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"credential_type":"public_key"'
  )
  AND NOT coalesce(resource.attributes_json, '') CONTAINS '"status":"inactive"'
RETURN resource.urn AS primary_urn,
       resource.label AS primary_label,
       resource.entity_type AS primary_type,
       resource.urn AS fingerprint_key,
       CASE
         WHEN coalesce(resource.attributes_json, '') CONTAINS '"resource_type":"personal_access_token"' THEN 'HIGH'
         ELSE 'MEDIUM'
       END AS severity,
       'GitHub programmatic access resource ' + coalesce(resource.label, resource.urn) + ' needs owner/scope review' AS summary,
       'Review owner, scopes, last use, and rotation; revoke unused or undocumented programmatic access' AS action,
       [resource.urn] AS resource_urns,
       [] AS evidence
ORDER BY severity DESC, resource.entity_type, resource.label, resource.urn
LIMIT $row_limit`, nil)
}
