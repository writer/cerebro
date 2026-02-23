package policy

import (
	"os"
	"strconv"
	"strings"
)

const coverageThresholdEnv = "CEREBRO_POLICY_COVERAGE_MIN"
const orphanThresholdEnv = "CEREBRO_POLICY_ORPHAN_TABLES_MAX"

// CoverageReport explains policy coverage against available tables.
type CoverageReport struct {
	TotalPolicies           int                 `json:"total_policies"`
	CoveredPolicies         int                 `json:"covered_policies"`
	UncoveredPolicies       int                 `json:"uncovered_policies"`
	UnknownResourcePolicies int                 `json:"unknown_resource_policies"`
	CoveragePercent         float64             `json:"coverage_percent"`
	KnownCoveragePercent    float64             `json:"known_coverage_percent"`
	MissingTables           map[string]int      `json:"missing_tables"`
	MissingByProvider       map[string]int      `json:"missing_by_provider"`
	Gaps                    []PolicyCoverageGap `json:"gaps"`
}

// CoverageReport returns a detailed coverage report for the provided tables.
func (e *Engine) CoverageReport(availableTables []string) CoverageReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := CoverageReport{
		TotalPolicies:     len(e.policies),
		MissingTables:     make(map[string]int),
		MissingByProvider: make(map[string]int),
	}

	tableSet := make(map[string]bool)
	for _, t := range availableTables {
		tableSet[t] = true
	}

	for _, p := range e.policies {
		required := p.GetRequiredTables()
		if len(required) == 0 {
			report.UnknownResourcePolicies++
			continue
		}
		if hasWildcardTable(required) {
			report.CoveredPolicies++
			continue
		}

		var missing []string
		for _, table := range required {
			if !tableSet[table] {
				missing = append(missing, table)
				report.MissingTables[table]++
			}
		}

		if len(missing) == 0 {
			report.CoveredPolicies++
			continue
		}

		report.Gaps = append(report.Gaps, PolicyCoverageGap{
			PolicyID:      p.ID,
			PolicyName:    p.Name,
			Resource:      p.Resource,
			MissingTables: missing,
		})
		report.MissingByProvider[resourceProvider(p.Resource)]++
	}

	report.UncoveredPolicies = report.TotalPolicies - report.CoveredPolicies - report.UnknownResourcePolicies
	if report.TotalPolicies > 0 {
		report.CoveragePercent = float64(report.CoveredPolicies) / float64(report.TotalPolicies) * 100
	}
	knownPolicies := report.TotalPolicies - report.UnknownResourcePolicies
	if knownPolicies > 0 {
		report.KnownCoveragePercent = float64(report.CoveredPolicies) / float64(knownPolicies) * 100
	}

	return report
}

// CoverageThresholdFromEnv returns a coverage percentage threshold if configured.
func CoverageThresholdFromEnv() (float64, bool, error) {
	raw := strings.TrimSpace(os.Getenv(coverageThresholdEnv))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false, err
	}
	if value < 0 {
		value = 0
	}
	return value, true, nil
}

// OrphanTableThresholdFromEnv returns max allowed orphan native tables, if configured.
func OrphanTableThresholdFromEnv() (int, bool, error) {
	raw := strings.TrimSpace(os.Getenv(orphanThresholdEnv))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, err
	}
	if value < 0 {
		value = 0
	}
	return value, true, nil
}

func resourceProvider(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "unknown"
	}
	if strings.Contains(resource, "::") {
		parts := strings.Split(resource, "::")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	if strings.Contains(resource, "_") {
		return "custom"
	}
	return "unknown"
}
