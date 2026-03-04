// Command policy-enhancer adds compliance framework mappings and risk categories to policies
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Policy struct {
	ID               string             `json:"id"`
	WizControlID     string             `json:"wiz_control_id,omitempty"`
	Name             string             `json:"name"`
	Description      string             `json:"description"`
	Effect           string             `json:"effect"`
	Resource         string             `json:"resource"`
	Conditions       []string           `json:"conditions"`
	Severity         string             `json:"severity"`
	Remediation      string             `json:"remediation,omitempty"`
	RemediationSteps []string           `json:"remediation_steps,omitempty"`
	Tags             []string           `json:"tags"`
	RiskCategories   []string           `json:"risk_categories,omitempty"`
	Frameworks       []FrameworkMapping `json:"frameworks,omitempty"`
	MitreAttack      []MitreMapping     `json:"mitre_attack,omitempty"`
}

type FrameworkMapping struct {
	Name     string   `json:"name"`
	Controls []string `json:"controls"`
}

type MitreMapping struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
}

func main() {
	dir := flag.String("dir", "policies", "Policies directory")
	dryRun := flag.Bool("dry-run", false, "Don't write files, just show what would change")
	flag.Parse()

	if err := filepath.Walk(*dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path) // #nosec G304,G122 -- path is enumerated via filepath.Walk under operator-supplied directory
		if err != nil {
			log.Printf("Error reading %s: %v", path, err)
			return nil
		}

		var policy Policy
		if unmarshalErr := json.Unmarshal(data, &policy); unmarshalErr != nil {
			log.Printf("Error parsing %s: %v", path, unmarshalErr)
			return nil
		}

		// Skip if already has frameworks
		if len(policy.Frameworks) > 0 {
			return nil
		}

		enhanced := enhancePolicy(&policy)
		if !enhanced {
			return nil
		}

		if *dryRun {
			fmt.Printf("Would enhance: %s\n", path)
			fmt.Printf("  Risk categories: %v\n", policy.RiskCategories)
			fmt.Printf("  Frameworks: %v\n", policy.Frameworks)
			return nil
		}

		// Write enhanced policy
		output, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			log.Printf("Error marshaling %s: %v", path, err)
			return nil
		}

		if err := os.WriteFile(path, output, 0600); err != nil { // #nosec G122 -- path is enumerated via filepath.Walk under operator-supplied directory
			log.Printf("Error writing %s: %v", path, err)
			return nil
		}

		fmt.Printf("Enhanced: %s\n", path)
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func enhancePolicy(p *Policy) bool {
	enhanced := false

	// Add risk categories based on tags and content
	if len(p.RiskCategories) == 0 {
		p.RiskCategories = inferRiskCategories(p)
		if len(p.RiskCategories) > 0 {
			enhanced = true
		}
	}

	// Add compliance frameworks based on tags
	if len(p.Frameworks) == 0 {
		p.Frameworks = inferFrameworks(p)
		if len(p.Frameworks) > 0 {
			enhanced = true
		}
	}

	// Add MITRE ATT&CK mappings
	if len(p.MitreAttack) == 0 {
		p.MitreAttack = inferMitreAttack(p)
		if len(p.MitreAttack) > 0 {
			enhanced = true
		}
	}

	return enhanced
}

func inferRiskCategories(p *Policy) []string {
	categories := []string{}
	tags := strings.Join(p.Tags, " ")
	desc := strings.ToLower(p.Description + " " + p.Name)
	all := tags + " " + desc

	// External exposure
	if containsAny(all, "public", "internet", "exposure", "external", "internet-facing") {
		categories = append(categories, "EXTERNAL_EXPOSURE")
	}

	// Data protection
	if containsAny(all, "sensitive", "data", "encryption", "unencrypted", "cleartext", "secrets") {
		categories = append(categories, "UNPROTECTED_DATA")
	}

	// Identity/access
	if containsAny(all, "iam", "identity", "authentication", "mfa", "admin", "privileged", "root") {
		categories = append(categories, "IDENTITY_RISK")
	}

	// Misconfiguration
	if containsAny(all, "misconfiguration", "disabled", "missing", "not enabled", "should") {
		categories = append(categories, "MISCONFIGURATION")
	}

	// Vulnerability
	if containsAny(all, "vulnerability", "cve", "exploit", "patch") {
		categories = append(categories, "VULNERABILITY")
	}

	// Lateral movement
	if containsAny(all, "lateral", "cross-account", "trust", "assume") {
		categories = append(categories, "LATERAL_MOVEMENT")
	}

	// Privilege escalation
	if containsAny(all, "privilege", "escalation", "wildcard", "admin") {
		categories = append(categories, "PRIVILEGE_ESCALATION")
	}

	return categories
}

func inferFrameworks(p *Policy) []FrameworkMapping {
	mappings := []FrameworkMapping{}
	tags := strings.Join(p.Tags, " ")

	// CIS AWS mappings from tags
	for _, tag := range p.Tags {
		if strings.HasPrefix(tag, "cis-aws-") {
			controlID := strings.TrimPrefix(tag, "cis-aws-")
			mappings = appendFramework(mappings, "CIS AWS Foundations Benchmark v2.0", controlID)
		}
		if strings.HasPrefix(tag, "cis-k8s-") {
			controlID := strings.TrimPrefix(tag, "cis-k8s-")
			mappings = appendFramework(mappings, "CIS Kubernetes Benchmark", controlID)
		}
		if strings.HasPrefix(tag, "cis-github-") {
			controlID := strings.TrimPrefix(tag, "cis-github-")
			mappings = appendFramework(mappings, "CIS GitHub Benchmark", controlID)
		}
	}

	// Infer from severity and content
	all := tags + " " + strings.ToLower(p.Description)

	// High/Critical public access -> network controls
	if (p.Severity == "critical" || p.Severity == "high") && containsAny(all, "public", "internet", "exposure") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "AC-3", "SC-7")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "1.3", "1.4")
		mappings = appendFramework(mappings, "SOC 2", "CC6")
		mappings = appendFramework(mappings, "CIS Controls v8", "12", "13")
	}

	// Authentication/MFA
	if containsAny(all, "mfa", "authentication", "password") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "IA-2", "IA-5")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "8.3", "8.4")
		mappings = appendFramework(mappings, "CIS Controls v8", "6")
	}

	// Encryption
	if containsAny(all, "encryption", "encrypted", "kms", "tls", "ssl") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "SC-12", "SC-13", "SC-28")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "3.5", "4.2")
		mappings = appendFramework(mappings, "CIS Controls v8", "3")
	}

	// Logging/Audit
	if containsAny(all, "logging", "audit", "cloudtrail", "monitoring") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "AU-2", "AU-12")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "10.2", "10.3")
		mappings = appendFramework(mappings, "SOC 2", "CC4", "CC7")
		mappings = appendFramework(mappings, "CIS Controls v8", "8")
	}

	// IAM/Access control
	if containsAny(all, "iam", "access", "permission", "privilege", "least") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "AC-2", "AC-6")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "7.2")
		mappings = appendFramework(mappings, "SOC 2", "CC6")
		mappings = appendFramework(mappings, "CIS Controls v8", "5", "6")
	}

	// Vulnerability management
	if containsAny(all, "vulnerability", "cve", "patch", "update") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "RA-5", "SI-2")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "6.3", "11.3")
		mappings = appendFramework(mappings, "CIS Controls v8", "7")
	}

	// Secrets management
	if containsAny(all, "secret", "credential", "key", "token") {
		mappings = appendFramework(mappings, "NIST 800-53 r5", "IA-5", "SC-12")
		mappings = appendFramework(mappings, "PCI DSS v4.0.1", "3.5", "8.6")
	}

	return mappings
}

func inferMitreAttack(p *Policy) []MitreMapping {
	mappings := []MitreMapping{}
	all := strings.ToLower(strings.Join(p.Tags, " ") + " " + p.Description)

	// Initial Access
	if containsAny(all, "public", "internet", "exposure", "external") {
		mappings = append(mappings, MitreMapping{Tactic: "Initial Access", Technique: "T1190"})
	}
	if containsAny(all, "phishing", "credential") {
		mappings = append(mappings, MitreMapping{Tactic: "Initial Access", Technique: "T1078"})
	}

	// Execution
	if containsAny(all, "lambda", "function", "script", "code") {
		mappings = append(mappings, MitreMapping{Tactic: "Execution", Technique: "T1059"})
	}

	// Persistence
	if containsAny(all, "iam", "user", "role", "access key") {
		mappings = append(mappings, MitreMapping{Tactic: "Persistence", Technique: "T1098"})
	}

	// Privilege Escalation
	if containsAny(all, "privilege", "escalation", "admin", "root", "wildcard") {
		mappings = append(mappings, MitreMapping{Tactic: "Privilege Escalation", Technique: "T1078"})
	}

	// Defense Evasion
	if containsAny(all, "logging", "audit", "disable", "trail") {
		mappings = append(mappings, MitreMapping{Tactic: "Defense Evasion", Technique: "T1562"})
	}

	// Credential Access
	if containsAny(all, "secret", "password", "key", "credential", "token") {
		mappings = append(mappings, MitreMapping{Tactic: "Credential Access", Technique: "T1552"})
	}

	// Discovery
	if containsAny(all, "enumerat", "discover", "list") {
		mappings = append(mappings, MitreMapping{Tactic: "Discovery", Technique: "T1087"})
	}

	// Lateral Movement
	if containsAny(all, "lateral", "cross-account", "trust", "assume") {
		mappings = append(mappings, MitreMapping{Tactic: "Lateral Movement", Technique: "T1021"})
	}

	// Collection
	if containsAny(all, "data", "s3", "storage", "bucket", "sensitive") {
		mappings = append(mappings, MitreMapping{Tactic: "Collection", Technique: "T1530"})
	}

	// Exfiltration
	if containsAny(all, "exfiltrat", "transfer", "public bucket") {
		mappings = append(mappings, MitreMapping{Tactic: "Exfiltration", Technique: "T1537"})
	}

	return mappings
}

func containsAny(s string, substrs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func appendFramework(mappings []FrameworkMapping, name string, controls ...string) []FrameworkMapping {
	for i := range mappings {
		if mappings[i].Name == name {
			// Deduplicate controls
			for _, c := range controls {
				found := false
				for _, existing := range mappings[i].Controls {
					if existing == c {
						found = true
						break
					}
				}
				if !found {
					mappings[i].Controls = append(mappings[i].Controls, c)
				}
			}
			return mappings
		}
	}
	return append(mappings, FrameworkMapping{Name: name, Controls: controls})
}
