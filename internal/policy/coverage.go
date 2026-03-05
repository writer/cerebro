package policy

import (
	"os"
	"strconv"
	"strings"
)

const coverageThresholdEnv = "CEREBRO_POLICY_COVERAGE_MIN"
const orphanThresholdEnv = "CEREBRO_POLICY_ORPHAN_TABLES_MAX"
const explicitMappingsOnlyEnv = "CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY"

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
		normalized := strings.ToLower(strings.TrimSpace(t))
		if normalized == "" {
			continue
		}
		tableSet[normalized] = true
	}

	for _, p := range e.policies {
		isQueryPolicy := strings.TrimSpace(p.Query) != ""
		required := p.GetRequiredTables()
		if len(required) == 0 {
			required = ExtractQueryTableReferences(p.Query)
		}
		if len(required) == 0 {
			report.UnknownResourcePolicies++
			continue
		}
		if hasWildcardTable(required) {
			report.CoveredPolicies++
			continue
		}

		var missing []string
		availableCount := 0
		for _, table := range required {
			normalized := strings.ToLower(strings.TrimSpace(table))
			if tableSet[normalized] {
				availableCount++
				continue
			}
			missing = append(missing, normalized)
		}

		covered := false
		if isQueryPolicy {
			covered = len(missing) == 0
		} else {
			covered = availableCount > 0
		}

		if covered {
			report.CoveredPolicies++
			continue
		}

		for _, table := range missing {
			report.MissingTables[table]++
		}

		report.Gaps = append(report.Gaps, PolicyCoverageGap{
			PolicyID:      p.ID,
			PolicyName:    p.Name,
			Resource:      p.Resource,
			MissingTables: missing,
		})

		provider := resourceProvider(p.Resource)
		if provider == "unknown" && isQueryPolicy {
			for _, table := range missing {
				report.MissingByProvider[tableProvider(table)]++
			}
		} else {
			report.MissingByProvider[provider]++
		}
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

// ExplicitMappingsOnlyFromEnv returns whether fallback table heuristics are disabled.
func ExplicitMappingsOnlyFromEnv() (bool, error) {
	raw := strings.TrimSpace(os.Getenv(explicitMappingsOnlyEnv))
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}
	return value, nil
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

func tableProvider(table string) string {
	table = strings.ToLower(strings.TrimSpace(table))
	if table == "" {
		return "unknown"
	}

	prefixes := []string{
		"google_workspace_",
		"terraform_cloud_",
		"oracle_idcs_",
		"cloudtrail_",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(table, prefix) {
			return strings.TrimSuffix(prefix, "_")
		}
	}

	if idx := strings.IndexByte(table, '_'); idx > 0 {
		return table[:idx]
	}

	return table
}
