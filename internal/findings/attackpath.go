package findings

import (
	"fmt"
	"sort"
	"strings"
)

// AttackPath represents a potential attack path combining multiple findings
type AttackPath struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	RiskScore   int      `json:"risk_score"` // 0-100
	Steps       []AttackStep `json:"steps"`
	FindingIDs  []string `json:"finding_ids"`
	Resources   []string `json:"resources"`
	Mitigations []string `json:"mitigations"`
}

// AttackStep represents a single step in an attack path
type AttackStep struct {
	Order       int    `json:"order"`
	Name        string `json:"name"`
	Description string `json:"description"`
	FindingID   string `json:"finding_id,omitempty"`
	Tactic      string `json:"tactic,omitempty"`
	Technique   string `json:"technique,omitempty"`
}

// ToxicCombination represents a dangerous combination of findings
type ToxicCombination struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Categories  []string `json:"categories"` // Risk categories involved
	Findings    []*Finding `json:"findings"`
}

// AttackPathAnalyzer identifies attack paths from findings
type AttackPathAnalyzer struct {
	store FindingStore
}

// NewAttackPathAnalyzer creates a new attack path analyzer
func NewAttackPathAnalyzer(store FindingStore) *AttackPathAnalyzer {
	return &AttackPathAnalyzer{store: store}
}

// FindToxicCombinations identifies dangerous combinations of findings
func (a *AttackPathAnalyzer) FindToxicCombinations() []ToxicCombination {
	findings := a.store.List(FindingFilter{})
	combinations := []ToxicCombination{}

	// Group findings by resource
	byResource := make(map[string][]*Finding)
	for _, f := range findings {
		if f.Status != "OPEN" && f.Status != "open" {
			continue
		}
		byResource[f.ResourceID] = append(byResource[f.ResourceID], f)
	}

	// Check each resource for toxic combinations
	for resourceID, resourceFindings := range byResource {
		if len(resourceFindings) < 2 {
			continue
		}

		// Check for specific toxic combinations
		combo := a.checkToxicCombination(resourceID, resourceFindings)
		if combo != nil {
			combinations = append(combinations, *combo)
		}
	}

	// Sort by severity
	sort.Slice(combinations, func(i, j int) bool {
		return severityRank(combinations[i].Severity) > severityRank(combinations[j].Severity)
	})

	return combinations
}

func (a *AttackPathAnalyzer) checkToxicCombination(resourceID string, findings []*Finding) *ToxicCombination {
	categories := make(map[string]bool)
	var hasExternalExposure, hasPrivilegedAccess, hasVulnerability, hasDataAccess bool

	for _, f := range findings {
		for _, cat := range f.RiskCategories {
			categories[cat] = true
			switch cat {
			case "EXTERNAL_EXPOSURE":
				hasExternalExposure = true
			case "PRIVILEGE_ESCALATION", "IDENTITY_RISK":
				hasPrivilegedAccess = true
			case "VULNERABILITY":
				hasVulnerability = true
			case "UNPROTECTED_DATA":
				hasDataAccess = true
			}
		}
	}

	// Internet-facing + vulnerability = critical
	if hasExternalExposure && hasVulnerability {
		return &ToxicCombination{
			Name:        "Internet-Facing Resource with Known Vulnerabilities",
			Description: fmt.Sprintf("Resource %s is exposed to the internet and has known vulnerabilities that could be exploited for initial access", resourceID),
			Severity:    "critical",
			Categories:  []string{"EXTERNAL_EXPOSURE", "VULNERABILITY"},
			Findings:    findings,
		}
	}

	// Internet-facing + privileged access = critical
	if hasExternalExposure && hasPrivilegedAccess {
		return &ToxicCombination{
			Name:        "Internet-Facing Resource with Excessive Privileges",
			Description: fmt.Sprintf("Resource %s is exposed to the internet and has excessive privileges that could be exploited for lateral movement", resourceID),
			Severity:    "critical",
			Categories:  []string{"EXTERNAL_EXPOSURE", "PRIVILEGE_ESCALATION"},
			Findings:    findings,
		}
	}

	// Internet-facing + data access = critical
	if hasExternalExposure && hasDataAccess {
		return &ToxicCombination{
			Name:        "Internet-Facing Resource with Sensitive Data Access",
			Description: fmt.Sprintf("Resource %s is exposed to the internet and has access to sensitive data", resourceID),
			Severity:    "critical",
			Categories:  []string{"EXTERNAL_EXPOSURE", "UNPROTECTED_DATA"},
			Findings:    findings,
		}
	}

	// Privileged + vulnerability = high
	if hasPrivilegedAccess && hasVulnerability {
		return &ToxicCombination{
			Name:        "Privileged Resource with Known Vulnerabilities",
			Description: fmt.Sprintf("Resource %s has excessive privileges and known vulnerabilities", resourceID),
			Severity:    "high",
			Categories:  []string{"PRIVILEGE_ESCALATION", "VULNERABILITY"},
			Findings:    findings,
		}
	}

	// Multiple high severity = high
	highCount := 0
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			highCount++
		}
	}
	if highCount >= 2 {
		cats := make([]string, 0)
		for c := range categories {
			cats = append(cats, c)
		}
		return &ToxicCombination{
			Name:        "Multiple High-Severity Issues",
			Description: fmt.Sprintf("Resource %s has multiple high-severity security issues that compound risk", resourceID),
			Severity:    "high",
			Categories:  cats,
			Findings:    findings,
		}
	}

	return nil
}

// GenerateAttackPaths identifies potential attack paths
func (a *AttackPathAnalyzer) GenerateAttackPaths() []AttackPath {
	combinations := a.FindToxicCombinations()
	paths := []AttackPath{}

	for i, combo := range combinations {
		steps := a.buildAttackSteps(combo)
		findingIDs := make([]string, len(combo.Findings))
		resources := make(map[string]bool)

		for j, f := range combo.Findings {
			findingIDs[j] = f.ID
			resources[f.ResourceID] = true
		}

		resourceList := make([]string, 0, len(resources))
		for r := range resources {
			resourceList = append(resourceList, r)
		}

		path := AttackPath{
			ID:          fmt.Sprintf("path-%d", i+1),
			Name:        combo.Name,
			Description: combo.Description,
			Severity:    combo.Severity,
			RiskScore:   calculateRiskScore(combo.Severity, len(combo.Findings)),
			Steps:       steps,
			FindingIDs:  findingIDs,
			Resources:   resourceList,
			Mitigations: a.suggestMitigations(combo),
		}
		paths = append(paths, path)
	}

	return paths
}

func (a *AttackPathAnalyzer) buildAttackSteps(combo ToxicCombination) []AttackStep {
	steps := []AttackStep{}
	order := 1

	// Build steps based on categories
	for _, cat := range combo.Categories {
		switch cat {
		case "EXTERNAL_EXPOSURE":
			steps = append(steps, AttackStep{
				Order:       order,
				Name:        "Initial Access",
				Description: "Attacker discovers and accesses the internet-facing resource",
				Tactic:      "Initial Access",
				Technique:   "T1190",
			})
			order++

		case "VULNERABILITY":
			steps = append(steps, AttackStep{
				Order:       order,
				Name:        "Exploitation",
				Description: "Attacker exploits known vulnerabilities to gain code execution",
				Tactic:      "Execution",
				Technique:   "T1203",
			})
			order++

		case "PRIVILEGE_ESCALATION", "IDENTITY_RISK":
			steps = append(steps, AttackStep{
				Order:       order,
				Name:        "Privilege Escalation",
				Description: "Attacker leverages excessive permissions to escalate privileges",
				Tactic:      "Privilege Escalation",
				Technique:   "T1078",
			})
			order++

		case "UNPROTECTED_DATA":
			steps = append(steps, AttackStep{
				Order:       order,
				Name:        "Data Access",
				Description: "Attacker accesses sensitive data",
				Tactic:      "Collection",
				Technique:   "T1530",
			})
			order++

		case "LATERAL_MOVEMENT":
			steps = append(steps, AttackStep{
				Order:       order,
				Name:        "Lateral Movement",
				Description: "Attacker moves to other resources using trust relationships",
				Tactic:      "Lateral Movement",
				Technique:   "T1021",
			})
			order++
		}
	}

	return steps
}

func (a *AttackPathAnalyzer) suggestMitigations(combo ToxicCombination) []string {
	mitigations := []string{}

	for _, cat := range combo.Categories {
		switch cat {
		case "EXTERNAL_EXPOSURE":
			mitigations = append(mitigations, "Restrict network access to only required sources")
			mitigations = append(mitigations, "Implement WAF or similar protection")
		case "VULNERABILITY":
			mitigations = append(mitigations, "Apply security patches immediately")
			mitigations = append(mitigations, "Implement vulnerability scanning in CI/CD")
		case "PRIVILEGE_ESCALATION", "IDENTITY_RISK":
			mitigations = append(mitigations, "Apply principle of least privilege")
			mitigations = append(mitigations, "Review and reduce IAM permissions")
		case "UNPROTECTED_DATA":
			mitigations = append(mitigations, "Enable encryption at rest and in transit")
			mitigations = append(mitigations, "Implement data classification and access controls")
		case "LATERAL_MOVEMENT":
			mitigations = append(mitigations, "Review trust relationships and cross-account access")
			mitigations = append(mitigations, "Implement network segmentation")
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, m := range mitigations {
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}

	return unique
}

func calculateRiskScore(severity string, findingCount int) int {
	baseScore := 0
	switch severity {
	case "critical":
		baseScore = 80
	case "high":
		baseScore = 60
	case "medium":
		baseScore = 40
	case "low":
		baseScore = 20
	}

	// Add 5 points per additional finding (max 20)
	bonus := (findingCount - 1) * 5
	if bonus > 20 {
		bonus = 20
	}

	score := baseScore + bonus
	if score > 100 {
		score = 100
	}
	return score
}

// GroupFindingsByCategory groups findings by risk category
func GroupFindingsByCategory(findings []*Finding) map[string][]*Finding {
	groups := make(map[string][]*Finding)
	for _, f := range findings {
		for _, cat := range f.RiskCategories {
			groups[cat] = append(groups[cat], f)
		}
	}
	return groups
}

// GetThreatSummary returns a summary of threats based on findings
func GetThreatSummary(findings []*Finding) map[string]int {
	threats := make(map[string]int)

	for _, f := range findings {
		if f.Status != "OPEN" && f.Status != "open" {
			continue
		}

		for _, cat := range f.RiskCategories {
			threat := categoryToThreat(cat)
			if threat != "" {
				threats[threat]++
			}
		}
	}

	return threats
}

func categoryToThreat(category string) string {
	switch category {
	case "EXTERNAL_EXPOSURE":
		return "External Attack Surface"
	case "VULNERABILITY":
		return "Exploitable Vulnerabilities"
	case "IDENTITY_RISK", "PRIVILEGE_ESCALATION":
		return "Identity & Access Risks"
	case "UNPROTECTED_DATA":
		return "Data Exposure Risk"
	case "LATERAL_MOVEMENT":
		return "Lateral Movement Risk"
	case "MISCONFIGURATION":
		return "Configuration Drift"
	}
	return ""
}

// FindingsWithToxicCombinations returns findings that are part of toxic combinations
func (a *AttackPathAnalyzer) FindingsWithToxicCombinations() []*Finding {
	combinations := a.FindToxicCombinations()
	findingSet := make(map[string]*Finding)

	for _, combo := range combinations {
		for _, f := range combo.Findings {
			findingSet[f.ID] = f
		}
	}

	result := make([]*Finding, 0, len(findingSet))
	for _, f := range findingSet {
		result = append(result, f)
	}

	// Sort by severity
	sort.Slice(result, func(i, j int) bool {
		if result[i].Severity != result[j].Severity {
			return severityRank(result[i].Severity) > severityRank(result[j].Severity)
		}
		return strings.Compare(result[i].ID, result[j].ID) < 0
	})

	return result
}
