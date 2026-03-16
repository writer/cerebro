package findings

import (
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/policy"
)

// PolicyCatalog captures the policy lookups required for compliance reporting.
type PolicyCatalog interface {
	ListPolicies() []*policy.Policy
	GetPolicy(id string) (*policy.Policy, bool)
}

var _ PolicyCatalog = (*policy.Engine)(nil)

// ComplianceReport summarizes findings by compliance framework
type ComplianceReport struct {
	Framework           string                   `json:"framework"`
	TotalControls       int                      `json:"total_controls"`
	AssessedControls    int                      `json:"assessed_controls"`
	PassingControls     int                      `json:"passing_controls"`
	FailingControls     int                      `json:"failing_controls"`
	NotAssessedControls int                      `json:"not_assessed_controls"`
	CoveragePercent     float64                  `json:"coverage_percent"`
	CompliancePercent   float64                  `json:"compliance_percent"`
	ControlStatus       map[string]ControlStatus `json:"control_status"`
	FindingsByControl   map[string][]string      `json:"findings_by_control"`
}

// ControlStatus tracks the status of a specific control
type ControlStatus struct {
	ControlID   string   `json:"control_id"`
	ControlName string   `json:"control_name,omitempty"`
	Status      string   `json:"status"` // PASS, FAIL, NOT_ASSESSED
	Findings    int      `json:"findings"`
	Severity    string   `json:"max_severity,omitempty"`
	PolicyIDs   []string `json:"policy_ids,omitempty"`
}

// RiskSummary summarizes findings by risk category
type RiskSummary struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

// ComplianceReporter generates compliance reports from findings
type ComplianceReporter struct {
	store    FindingStore
	policies PolicyCatalog
	registry *policy.ComplianceRegistry
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(store FindingStore, policies PolicyCatalog) *ComplianceReporter {
	return &ComplianceReporter{
		store:    store,
		policies: policies,
		registry: policy.NewComplianceRegistry(),
	}
}

// GenerateFrameworkReport generates a compliance report for a specific framework
func (r *ComplianceReporter) GenerateFrameworkReport(framework string) *ComplianceReport {
	findings := r.store.List(FindingFilter{})
	frameworkDef, _ := r.registry.FindFramework(framework)

	report := &ComplianceReport{
		Framework:         framework,
		ControlStatus:     make(map[string]ControlStatus),
		FindingsByControl: make(map[string][]string),
	}

	// Seed control statuses from registry if available
	if frameworkDef != nil {
		for controlID, control := range frameworkDef.Controls {
			report.ControlStatus[controlID] = ControlStatus{
				ControlID:   controlID,
				ControlName: control.Name,
				Status:      "NOT_ASSESSED",
			}
		}
	}

	if r.policies != nil {
		for _, p := range r.policies.ListPolicies() {
			for _, mapping := range p.Frameworks {
				if !frameworkMatches(framework, frameworkDef, mapping.Name) {
					continue
				}
				for _, controlID := range mapping.Controls {
					status := report.ControlStatus[controlID]
					status.ControlID = controlID
					if status.ControlName == "" && frameworkDef != nil {
						if control, ok := frameworkDef.Controls[controlID]; ok {
							status.ControlName = control.Name
						}
					}
					if status.Status == "" || status.Status == "NOT_ASSESSED" {
						status.Status = "PASS"
					}
					status.PolicyIDs = appendUnique(status.PolicyIDs, p.ID)
					report.ControlStatus[controlID] = status
				}
			}
		}
	}

	for _, f := range findings {
		if normalizeStatus(f.Status) != "OPEN" {
			continue
		}

		mappings := f.ComplianceMappings
		if r.policies != nil {
			if p, ok := r.policies.GetPolicy(f.PolicyID); ok {
				mappings = p.Frameworks
			}
		}

		for _, mapping := range mappings {
			if !frameworkMatches(framework, frameworkDef, mapping.Name) {
				continue
			}
			for _, controlID := range mapping.Controls {
				status := report.ControlStatus[controlID]
				status.ControlID = controlID
				status.Status = "FAIL"
				status.Findings++
				status.PolicyIDs = appendUnique(status.PolicyIDs, f.PolicyID)
				status.Severity = maxSeverity(status.Severity, f.Severity)
				if status.ControlName == "" && frameworkDef != nil {
					if control, ok := frameworkDef.Controls[controlID]; ok {
						status.ControlName = control.Name
					}
				}
				report.ControlStatus[controlID] = status
				report.FindingsByControl[controlID] = append(report.FindingsByControl[controlID], f.ID)
			}
		}
	}

	for _, status := range report.ControlStatus {
		switch status.Status {
		case "FAIL":
			report.FailingControls++
		case "PASS":
			report.PassingControls++
		case "NOT_ASSESSED":
			report.NotAssessedControls++
		}
	}

	if frameworkDef != nil {
		report.TotalControls = len(frameworkDef.Controls)
		report.AssessedControls = report.PassingControls + report.FailingControls
		report.NotAssessedControls = report.TotalControls - report.AssessedControls
	} else {
		report.TotalControls = len(report.ControlStatus)
		report.AssessedControls = report.PassingControls + report.FailingControls
		report.NotAssessedControls = report.TotalControls - report.AssessedControls
	}

	if report.TotalControls > 0 {
		report.CoveragePercent = float64(report.AssessedControls) / float64(report.TotalControls) * 100
	}
	if report.AssessedControls > 0 {
		report.CompliancePercent = float64(report.PassingControls) / float64(report.AssessedControls) * 100
	}

	return report
}

// GenerateRiskSummary generates a summary of findings by risk category
func (r *ComplianceReporter) GenerateRiskSummary() []RiskSummary {
	findings := r.store.List(FindingFilter{})

	// Count by category
	categoryStats := make(map[string]*RiskSummary)

	for _, f := range findings {
		if normalizeStatus(f.Status) != "OPEN" {
			continue
		}

		for _, cat := range f.RiskCategories {
			if _, ok := categoryStats[cat]; !ok {
				categoryStats[cat] = &RiskSummary{Category: cat}
			}
			s := categoryStats[cat]
			s.Count++
			switch f.Severity {
			case "critical":
				s.Critical++
			case "high":
				s.High++
			case "medium":
				s.Medium++
			case "low":
				s.Low++
			}
		}
	}

	// Convert to slice and sort
	result := make([]RiskSummary, 0, len(categoryStats))
	for _, s := range categoryStats {
		result = append(result, *s)
	}
	sort.Slice(result, func(i, j int) bool {
		// Sort by critical, then high, then total count
		if result[i].Critical != result[j].Critical {
			return result[i].Critical > result[j].Critical
		}
		if result[i].High != result[j].High {
			return result[i].High > result[j].High
		}
		return result[i].Count > result[j].Count
	})

	return result
}

// GenerateExecutiveSummary generates a high-level summary for executives
func (r *ComplianceReporter) GenerateExecutiveSummary() *ExecutiveSummary {
	findings := r.store.List(FindingFilter{})
	stats := r.store.Stats()

	summary := &ExecutiveSummary{
		TotalFindings:      stats.Total,
		OpenFindings:       stats.ByStatus["OPEN"],
		ResolvedFindings:   stats.ByStatus["RESOLVED"],
		SuppressedFindings: stats.ByStatus["SUPPRESSED"],
		BySeverity: SeverityBreakdown{
			Critical: stats.BySeverity["critical"],
			High:     stats.BySeverity["high"],
			Medium:   stats.BySeverity["medium"],
			Low:      stats.BySeverity["low"],
		},
	}

	// Calculate risk score (0-100)
	// Weight: critical=40, high=25, medium=10, low=5
	riskScore := float64(summary.BySeverity.Critical*40 +
		summary.BySeverity.High*25 +
		summary.BySeverity.Medium*10 +
		summary.BySeverity.Low*5)

	// Normalize to 0-100 (cap at 100)
	maxRisk := float64(len(findings)) * 40 // Assume all could be critical
	if maxRisk > 0 {
		summary.RiskScore = int(riskScore / maxRisk * 100)
		if summary.RiskScore > 100 {
			summary.RiskScore = 100
		}
	}

	// Get top risks
	risks := r.GenerateRiskSummary()
	if len(risks) > 5 {
		risks = risks[:5]
	}
	for _, risk := range risks {
		summary.TopRisks = append(summary.TopRisks, risk.Category)
	}

	return summary
}

// ExecutiveSummary provides a high-level overview for executives
type ExecutiveSummary struct {
	TotalFindings      int               `json:"total_findings"`
	OpenFindings       int               `json:"open_findings"`
	ResolvedFindings   int               `json:"resolved_findings"`
	SuppressedFindings int               `json:"suppressed_findings"`
	RiskScore          int               `json:"risk_score"` // 0-100
	BySeverity         SeverityBreakdown `json:"by_severity"`
	TopRisks           []string          `json:"top_risks"`
}

// SeverityBreakdown shows findings count by severity
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func maxSeverity(current, candidate string) string {
	if current == "" {
		return candidate
	}
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func frameworkMatches(target string, def *policy.ComplianceFramework, mappingName string) bool {
	if strings.EqualFold(mappingName, target) {
		return true
	}
	if def != nil {
		if strings.EqualFold(mappingName, def.Name) || strings.EqualFold(mappingName, def.ID) {
			return true
		}
		if strings.EqualFold(mappingName, def.Name+" "+def.Version) || strings.EqualFold(mappingName, def.Name+" v"+def.Version) {
			return true
		}
	}
	return normalizeFrameworkLabel(mappingName) == normalizeFrameworkLabel(target)
}

func normalizeFrameworkLabel(label string) string {
	cleaned := strings.ToLower(strings.TrimSpace(label))
	return strings.Join(strings.Fields(cleaned), " ")
}
