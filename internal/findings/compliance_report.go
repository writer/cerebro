package findings

import (
	"sort"
)

// ComplianceReport summarizes findings by compliance framework
type ComplianceReport struct {
	Framework       string                   `json:"framework"`
	TotalControls   int                      `json:"total_controls"`
	PassingControls int                      `json:"passing_controls"`
	FailingControls int                      `json:"failing_controls"`
	CoveragePercent float64                  `json:"coverage_percent"`
	ControlStatus   map[string]ControlStatus `json:"control_status"`
	FindingsByControl map[string][]string    `json:"findings_by_control"`
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
	store FindingStore
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(store FindingStore) *ComplianceReporter {
	return &ComplianceReporter{store: store}
}

// GenerateFrameworkReport generates a compliance report for a specific framework
func (r *ComplianceReporter) GenerateFrameworkReport(framework string) *ComplianceReport {
	findings := r.store.List(FindingFilter{})

	report := &ComplianceReport{
		Framework:         framework,
		ControlStatus:     make(map[string]ControlStatus),
		FindingsByControl: make(map[string][]string),
	}

	// Track controls that have findings
	controlFindings := make(map[string][]*Finding)

	for _, f := range findings {
		if f.Status != "OPEN" && f.Status != "open" {
			continue // Only count open findings
		}

		// Check if finding maps to this framework
		for _, fw := range f.SecurityFrameworks {
			if fw == framework {
				// This finding applies to this framework
				// We need policy data to get control mappings
				// For now, track by policy
				controlFindings[f.PolicyID] = append(controlFindings[f.PolicyID], f)
			}
		}
	}

	// Build control status
	for policyID, policyFindings := range controlFindings {
		maxSeverity := "low"
		for _, f := range policyFindings {
			if severityRank(f.Severity) > severityRank(maxSeverity) {
				maxSeverity = f.Severity
			}
			report.FindingsByControl[policyID] = append(report.FindingsByControl[policyID], f.ID)
		}

		report.ControlStatus[policyID] = ControlStatus{
			ControlID: policyID,
			Status:    "FAIL",
			Findings:  len(policyFindings),
			Severity:  maxSeverity,
		}
		report.FailingControls++
	}

	report.TotalControls = report.PassingControls + report.FailingControls
	if report.TotalControls > 0 {
		report.CoveragePercent = float64(report.PassingControls) / float64(report.TotalControls) * 100
	}

	return report
}

// GenerateRiskSummary generates a summary of findings by risk category
func (r *ComplianceReporter) GenerateRiskSummary() []RiskSummary {
	findings := r.store.List(FindingFilter{})

	// Count by category
	categoryStats := make(map[string]*RiskSummary)

	for _, f := range findings {
		if f.Status != "OPEN" && f.Status != "open" {
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
		TotalFindings:   stats.Total,
		OpenFindings:    stats.ByStatus["OPEN"] + stats.ByStatus["open"],
		ResolvedFindings: stats.ByStatus["RESOLVED"] + stats.ByStatus["resolved"],
		SuppressedFindings: stats.ByStatus["SUPPRESSED"] + stats.ByStatus["suppressed"],
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
