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
		FalsePositives:    []string{"Approved deploy keys, service accounts, or GitHub Apps with documented owner, scope, and rotation process."},
		Runbook:           "Confirm owner, scope, last-use/need, and rotation for the credential or integration; remove unused access or document the exception.",
		FingerprintFields: []string{"github_credential_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
		},
	}, map[string][]string{"github": {"audit"}}, `MATCH (resource:Entity {tenant_id: $tenant_id, entity_type: 'github.credential'})
WITH resource, coalesce(resource.attributes_json, '') AS attrs
WHERE attrs CONTAINS '"status":"active"'
  AND NOT attrs CONTAINS '"credential_type":"public_key"'
  AND (
    attrs CONTAINS '"resource_type":"personal_access_token"'
    OR attrs CONTAINS '"resource_type":"org_credential_authorization"'
    OR attrs CONTAINS '"resource_type":"integration_installation"'
    OR attrs CONTAINS '"resource_type":"integration_installation_request"'
    OR attrs CONTAINS '"resource_type":"oauth_application"'
    OR attrs CONTAINS '"resource_type":"integration"'
  )
WITH resource,
     attrs,
     CASE
       WHEN attrs CONTAINS '"resource_type":"personal_access_token"' THEN 'personal_access_token'
       WHEN attrs CONTAINS '"resource_type":"org_credential_authorization"' THEN 'org_credential_authorization'
       WHEN attrs CONTAINS '"resource_type":"integration_installation_request"' THEN 'integration_installation_request'
       WHEN attrs CONTAINS '"resource_type":"integration_installation"' THEN 'integration_installation'
       WHEN attrs CONTAINS '"resource_type":"oauth_application"' THEN 'oauth_application'
       ELSE 'integration'
     END AS credential_type,
     CASE
       WHEN attrs CONTAINS '"resource_type":"personal_access_token"' THEN 'personal access token'
       WHEN attrs CONTAINS '"resource_type":"org_credential_authorization"' THEN 'organization credential authorization'
       WHEN attrs CONTAINS '"resource_type":"integration_installation_request"' THEN 'App installation request'
       WHEN attrs CONTAINS '"resource_type":"integration_installation"' THEN 'App installation'
       WHEN attrs CONTAINS '"resource_type":"oauth_application"' THEN 'OAuth application'
       ELSE 'integration'
     END AS credential_label
OPTIONAL MATCH (resource)-[scopeRel:RELATION {relation: 'belongs_to'}]->(scopeEntity:Entity {tenant_id: $tenant_id})
OPTIONAL MATCH (resource)-[actedRel:RELATION {relation: 'acted_on'}]->(targetEntity:Entity {tenant_id: $tenant_id})
WITH resource,
     attrs,
     credential_type,
     credential_label,
     collect(DISTINCT {urn: scopeEntity.urn, label: scopeEntity.label, entity_type: scopeEntity.entity_type, relation: 'belongs_to', attributes_json: coalesce(scopeRel.attributes_json, '')}) AS scope_evidence,
     collect(DISTINCT {urn: targetEntity.urn, label: targetEntity.label, entity_type: targetEntity.entity_type, relation: 'acted_on', attributes_json: coalesce(actedRel.attributes_json, '')}) AS target_evidence
WITH resource,
     attrs,
     credential_type,
     credential_label,
     [scope IN scope_evidence WHERE scope.urn IS NOT NULL | scope] AS scope_evidence,
     [target IN target_evidence WHERE target.urn IS NOT NULL | target] AS target_evidence
RETURN resource.urn AS primary_urn,
       resource.label AS primary_label,
       resource.entity_type AS primary_type,
       resource.urn AS fingerprint_key,
       CASE
         WHEN credential_type = 'personal_access_token' THEN 'HIGH'
         ELSE 'MEDIUM'
       END AS severity,
       'Active GitHub ' + credential_label + ' ' + coalesce(resource.label, resource.urn) + ' needs owner, scope, and rotation review' AS summary,
       'Validate owner, business need, org/repo boundary, scopes in evidence, last use, and rotation; revoke unused or undocumented programmatic access' AS action,
       [resource.urn] + [scope IN scope_evidence | scope.urn] + [target IN target_evidence | target.urn] AS resource_urns,
       [{urn: resource.urn, label: resource.label, entity_type: resource.entity_type, relation: 'credential', attributes_json: attrs}] + scope_evidence + target_evidence AS evidence,
       {
         github_credential_urn: resource.urn,
         credential_type: credential_type,
         credential_status: 'active',
         credential_scope_source: CASE
           WHEN attrs CONTAINS '"scope":"' THEN 'scope_attribute'
           WHEN attrs CONTAINS '"repository":"' THEN 'repository_attribute'
           WHEN attrs CONTAINS '"org":"' THEN 'org_attribute'
           ELSE 'graph_relationship'
         END
       } AS finding_attributes
ORDER BY severity DESC, credential_type, resource.label, resource.urn
LIMIT $row_limit`, nil)
}
