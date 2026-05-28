package findings

import "github.com/writer/cerebro/internal/ports"

const oktaAuthenticatorWeakFactorRuleID = "identity-okta-authenticator-weak-factor-enabled"

func newOktaAuthenticatorWeakFactorRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          oktaAuthenticatorWeakFactorRuleID,
		Name:        "Okta Authenticator Weak Factor Enabled",
		Description: "Detect active Okta authenticators using phishing-susceptible factor types such as SMS, voice call, or email, which weaken org-wide MFA posture.",
		SourceID:    "okta",
		EventKinds:  []string{"okta.authenticator"},
		OutputKind:  "finding.identity_okta_authenticator_weak_factor_enabled",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"identity", "okta", "mfa", "authenticator", "phishing", "graph-rule", "attack.t1111"},
		References: []string{
			"https://help.okta.com/en-us/content/topics/security/authenticators/about-authenticators.htm",
			"https://pages.nist.gov/800-63-3/sp800-63b.html",
		},
		FalsePositives:    []string{"Org intentionally enables SMS/voice as a fallback for users who cannot use hardware tokens or mobile apps."},
		Runbook:           "Review the active authenticator and migrate users to phishing-resistant factors (FIDO2/WebAuthn, Okta Verify with push). Disable weak factors once migration is complete.",
		FingerprintFields: []string{"authenticator_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.5"},
		},
	}, map[string][]string{"okta": {"authenticator"}}, `MATCH (auth:Entity {tenant_id: $tenant_id, entity_type: 'okta.authenticator'})
WHERE coalesce(auth.attributes_json, '') CONTAINS '"status":"ACTIVE"'
  AND (
    coalesce(auth.attributes_json, '') CONTAINS '"key":"phone_number"'
    OR coalesce(auth.attributes_json, '') CONTAINS '"key":"sms"'
    OR coalesce(auth.attributes_json, '') CONTAINS '"key":"call"'
    OR coalesce(auth.attributes_json, '') CONTAINS '"key":"email"'
  )
RETURN auth.urn AS primary_urn,
       auth.label AS primary_label,
       auth.entity_type AS primary_type,
       auth.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'Okta authenticator ' + coalesce(auth.label, auth.urn) + ' uses a phishing-susceptible factor type' AS summary,
       'Migrate users to phishing-resistant factors (FIDO2, Okta Verify push) and disable weak factor types' AS action,
       [auth.urn] AS resource_urns,
       [] AS evidence
ORDER BY auth.label, auth.urn
LIMIT $row_limit`, nil)
}
