package findings

import "github.com/writer/cerebro/internal/ports"

const oktaOAuthPublicClientReviewRuleID = "identity-okta-oauth-public-client-review-needed"

func newOktaOAuthPublicClientReviewRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          oktaOAuthPublicClientReviewRuleID,
		Name:        "Okta OAuth Or Public Client Needs Review",
		Description: "Detect active Okta OAuth/OIDC applications and public-client actors that should have owner, grant, and scope review.",
		SourceID:    "okta",
		EventKinds:  []string{"okta.application", "okta.publicclientapp"},
		OutputKind:  "finding.identity_okta_oauth_public_client_review_needed",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"identity", "okta", "oauth", "public-client", "graph-rule", "attack.t1098"},
		References: []string{
			"https://help.okta.com/",
			"https://datatracker.ietf.org/doc/html/rfc6749",
		},
		FalsePositives: []string{"Approved first-party Okta clients, documented public clients, or applications reviewed by identity/security."},
		Runbook:        "Validate app owner, OAuth grants, public-client status, redirect URIs, assignments, and whether the client is still needed.",
		FingerprintFields: []string{
			"okta_client_urn",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.17"},
		},
	}, map[string][]string{"okta": {"application", "audit"}}, `MATCH (client:Entity {tenant_id: $tenant_id})
WHERE client.entity_type IN ['okta.application', 'okta.publicclientapp', 'okta.publicclientappentity']
  AND (
    client.entity_type <> 'okta.application'
    OR (
      coalesce(client.attributes_json, '') CONTAINS '"status":"ACTIVE"'
      AND (
        coalesce(client.attributes_json, '') CONTAINS '"oauth2":"true"'
        OR coalesce(client.attributes_json, '') CONTAINS '"oauth_client_type":"PublicClientApp"'
        OR coalesce(client.attributes_json, '') CONTAINS '"oauth_client_type":"PublicClientAppEntity"'
        OR coalesce(client.attributes_json, '') CONTAINS '"oauth_public_client":"true"'
        OR coalesce(client.attributes_json, '') CONTAINS '"sign_on_mode":"OPENID_CONNECT"'
      )
    )
  )
RETURN client.urn AS primary_urn,
       client.label AS primary_label,
       client.entity_type AS primary_type,
       client.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'Okta OAuth/public client ' + coalesce(client.label, client.urn) + ' needs security review' AS summary,
       'Review OAuth/public-client posture, ownership, grants, assignments, and documented exception status' AS action,
       [client.urn] AS resource_urns,
       [] AS evidence
ORDER BY client.entity_type, client.label, client.urn
LIMIT $row_limit`, nil)
}
