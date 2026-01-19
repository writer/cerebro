package policy

import "strings"

// InferRiskCategories derives risk categories based on policy metadata.
func InferRiskCategories(p *Policy) []string {
	if p == nil {
		return nil
	}

	all := strings.ToLower(strings.Join(p.Tags, " ") + " " + p.Description + " " + p.Name)
	seen := make(map[string]bool)
	var categories []string
	add := func(value string) {
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		categories = append(categories, value)
	}

	if containsAnyText(all, "public", "internet", "exposure", "external", "internet-facing") {
		add(RiskExternalExposure)
	}
	if containsAnyText(all, "sensitive", "data", "encryption", "unencrypted", "cleartext", "secrets") {
		add(RiskUnprotectedData)
	}
	if containsAnyText(all, "iam", "identity", "authentication", "mfa", "admin", "privileged", "root") {
		add(RiskIdentityRisk)
	}
	if containsAnyText(all, "misconfiguration", "disabled", "missing", "not enabled", "should") {
		add(RiskMisconfiguration)
	}
	if containsAnyText(all, "vulnerability", "cve", "exploit", "patch") {
		add(RiskVulnerability)
	}
	if containsAnyText(all, "lateral", "cross-account", "trust", "assume") {
		add(RiskLateralMovement)
	}
	if containsAnyText(all, "privilege", "escalation", "wildcard", "admin") {
		add(RiskPrivilegeEscalation)
	}

	return categories
}

// InferMitreAttack derives MITRE ATT&CK mappings based on policy metadata.
func InferMitreAttack(p *Policy) []MitreMapping {
	if p == nil {
		return nil
	}

	all := strings.ToLower(strings.Join(p.Tags, " ") + " " + p.Description)
	var mappings []MitreMapping

	// Initial Access
	if containsAnyText(all, "public", "internet", "exposure", "external") {
		mappings = append(mappings, MitreMapping{Tactic: "Initial Access", Technique: "T1190"})
	}
	if containsAnyText(all, "phishing", "credential") {
		mappings = append(mappings, MitreMapping{Tactic: "Initial Access", Technique: "T1078"})
	}

	// Execution
	if containsAnyText(all, "lambda", "function", "script", "code") {
		mappings = append(mappings, MitreMapping{Tactic: "Execution", Technique: "T1059"})
	}

	// Persistence
	if containsAnyText(all, "iam", "user", "role", "access key") {
		mappings = append(mappings, MitreMapping{Tactic: "Persistence", Technique: "T1098"})
	}

	// Privilege Escalation
	if containsAnyText(all, "privilege", "escalation", "admin", "root", "wildcard") {
		mappings = append(mappings, MitreMapping{Tactic: "Privilege Escalation", Technique: "T1078"})
	}

	// Defense Evasion
	if containsAnyText(all, "logging", "audit", "disable", "trail") {
		mappings = append(mappings, MitreMapping{Tactic: "Defense Evasion", Technique: "T1562"})
	}

	// Credential Access
	if containsAnyText(all, "secret", "password", "key", "credential", "token") {
		mappings = append(mappings, MitreMapping{Tactic: "Credential Access", Technique: "T1552"})
	}

	// Discovery
	if containsAnyText(all, "enumerat", "discover", "list") {
		mappings = append(mappings, MitreMapping{Tactic: "Discovery", Technique: "T1087"})
	}

	// Lateral Movement
	if containsAnyText(all, "lateral", "cross-account", "trust", "assume") {
		mappings = append(mappings, MitreMapping{Tactic: "Lateral Movement", Technique: "T1021"})
	}

	// Collection
	if containsAnyText(all, "data", "s3", "storage", "bucket", "sensitive") {
		mappings = append(mappings, MitreMapping{Tactic: "Collection", Technique: "T1530"})
	}

	// Exfiltration
	if containsAnyText(all, "exfiltrat", "transfer", "public bucket") {
		mappings = append(mappings, MitreMapping{Tactic: "Exfiltration", Technique: "T1537"})
	}

	return mappings
}

func containsAnyText(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
