package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/snowflake"
)

func sevRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func parseRiskCategories(raw string) []string {
	return scanner.ParseRiskCategories(raw)
}

func canonicalizeSQLRiskCategories(raw string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(scanner.ParseRiskCategories(raw))
}

func canonicalizeGraphRiskCategories(categories []string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(categories)
}

func canonicalizeRiskCategories(categories []string) map[string]bool {
	return scanner.CanonicalizeRiskCategories(categories)
}

func shouldSkipGraphToxicCombination(resourceID string, graphRisks map[string]bool, sqlRiskSets map[string][]map[string]bool) bool {
	return scanner.ShouldSkipGraphToxicCombination(resourceID, graphRisks, sqlRiskSets)
}

func normalizeResourceID(id string) string {
	return scanner.NormalizeResourceID(id)
}

type toxicComboSummary struct {
	Total          int                         `json:"total"`
	ResourceCount  int                         `json:"resource_count"`
	SeverityCounts map[string]int              `json:"severity_counts"`
	TopResources   []toxicComboResourceSummary `json:"top_resources"`
}

type toxicComboResourceSummary struct {
	ResourceID      string `json:"resource_id"`
	ResourceName    string `json:"resource_name"`
	Count           int    `json:"count"`
	HighestSeverity string `json:"highest_severity"`
	DevEnvironment  bool   `json:"dev_environment"`
}

type policyHotspotSummary struct {
	PolicyID        string `json:"policy_id"`
	PolicyName      string `json:"policy_name,omitempty"`
	Title           string `json:"title,omitempty"`
	Count           int    `json:"count"`
	HighestSeverity string `json:"highest_severity"`
	ResourceCount   int    `json:"resource_count"`
	SampleResource  string `json:"sample_resource,omitempty"`
}

type remediationActionSummary struct {
	Remediation     string   `json:"remediation"`
	Count           int      `json:"count"`
	HighestSeverity string   `json:"highest_severity"`
	PolicyIDs       []string `json:"policy_ids,omitempty"`
	ExampleResource string   `json:"example_resource,omitempty"`
}

func summarizePolicyHotspots(findings []map[string]interface{}, limit int) []policyHotspotSummary {
	if limit <= 0 || len(findings) == 0 {
		return nil
	}

	type aggregate struct {
		summary     policyHotspotSummary
		resourceSet map[string]struct{}
	}

	aggregates := make(map[string]*aggregate)
	for _, finding := range findings {
		policyID := strings.TrimSpace(toString(finding["policy_id"]))
		if policyID == "" {
			continue
		}

		agg := aggregates[policyID]
		if agg == nil {
			title := strings.TrimSpace(toString(finding["title"]))
			if title == "" {
				title = policyID
			}
			agg = &aggregate{
				summary: policyHotspotSummary{
					PolicyID:        policyID,
					PolicyName:      strings.TrimSpace(toString(finding["policy_name"])),
					Title:           title,
					HighestSeverity: strings.ToUpper(strings.TrimSpace(toString(finding["severity"]))),
				},
				resourceSet: make(map[string]struct{}),
			}
			aggregates[policyID] = agg
		}

		agg.summary.Count++
		severity := strings.ToUpper(strings.TrimSpace(toString(finding["severity"])))
		if sevRank(severity) > sevRank(agg.summary.HighestSeverity) {
			agg.summary.HighestSeverity = severity
		}
		if agg.summary.PolicyName == "" {
			agg.summary.PolicyName = strings.TrimSpace(toString(finding["policy_name"]))
		}

		resourceID := normalizeResourceID(toString(finding["resource_id"]))
		if resourceID != "" {
			agg.resourceSet[resourceID] = struct{}{}
			if agg.summary.SampleResource == "" {
				resourceName := strings.TrimSpace(toString(finding["resource_name"]))
				if resourceName == "" {
					resourceName = resourceID
				}
				agg.summary.SampleResource = resourceName
			}
		}
	}

	if len(aggregates) == 0 {
		return nil
	}

	summary := make([]policyHotspotSummary, 0, len(aggregates))
	for _, agg := range aggregates {
		agg.summary.ResourceCount = len(agg.resourceSet)
		summary = append(summary, agg.summary)
	}

	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count == summary[j].Count {
			if sevRank(summary[i].HighestSeverity) == sevRank(summary[j].HighestSeverity) {
				return summary[i].PolicyID < summary[j].PolicyID
			}
			return sevRank(summary[i].HighestSeverity) > sevRank(summary[j].HighestSeverity)
		}
		return summary[i].Count > summary[j].Count
	})

	if len(summary) > limit {
		summary = summary[:limit]
	}

	return summary
}

func summarizeRemediationActions(findings []map[string]interface{}, limit int) []remediationActionSummary {
	if limit <= 0 || len(findings) == 0 {
		return nil
	}

	type aggregate struct {
		summary   remediationActionSummary
		policySet map[string]struct{}
	}

	aggregates := make(map[string]*aggregate)
	for _, finding := range findings {
		remediation := strings.TrimSpace(toString(finding["remediation"]))
		if remediation == "" {
			continue
		}

		key := strings.ToLower(remediation)
		agg := aggregates[key]
		if agg == nil {
			agg = &aggregate{
				summary: remediationActionSummary{
					Remediation:     remediation,
					HighestSeverity: strings.ToUpper(strings.TrimSpace(toString(finding["severity"]))),
				},
				policySet: make(map[string]struct{}),
			}
			aggregates[key] = agg
		}

		agg.summary.Count++
		severity := strings.ToUpper(strings.TrimSpace(toString(finding["severity"])))
		if sevRank(severity) > sevRank(agg.summary.HighestSeverity) {
			agg.summary.HighestSeverity = severity
		}

		if policyID := strings.TrimSpace(toString(finding["policy_id"])); policyID != "" {
			agg.policySet[policyID] = struct{}{}
		}

		if agg.summary.ExampleResource == "" {
			resourceLabel := strings.TrimSpace(toString(finding["resource_name"]))
			if resourceLabel == "" {
				resourceLabel = normalizeResourceID(toString(finding["resource_id"]))
			}
			agg.summary.ExampleResource = resourceLabel
		}
	}

	if len(aggregates) == 0 {
		return nil
	}

	summary := make([]remediationActionSummary, 0, len(aggregates))
	for _, agg := range aggregates {
		policyIDs := make([]string, 0, len(agg.policySet))
		for policyID := range agg.policySet {
			policyIDs = append(policyIDs, policyID)
		}
		sort.Strings(policyIDs)
		if len(policyIDs) > defaultRemediationPolicyIDLimit {
			policyIDs = policyIDs[:defaultRemediationPolicyIDLimit]
		}
		agg.summary.PolicyIDs = policyIDs
		summary = append(summary, agg.summary)
	}

	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count == summary[j].Count {
			if sevRank(summary[i].HighestSeverity) == sevRank(summary[j].HighestSeverity) {
				return summary[i].Remediation < summary[j].Remediation
			}
			return sevRank(summary[i].HighestSeverity) > sevRank(summary[j].HighestSeverity)
		}
		return summary[i].Count > summary[j].Count
	})

	if len(summary) > limit {
		summary = summary[:limit]
	}

	return summary
}

func policyFindingToMap(f policy.Finding, source string, extras map[string]interface{}) map[string]interface{} {
	finding := map[string]interface{}{
		"id":              strings.TrimSpace(f.ID),
		"policy_id":       strings.TrimSpace(f.PolicyID),
		"policy_name":     strings.TrimSpace(f.PolicyName),
		"title":           strings.TrimSpace(f.Title),
		"description":     strings.TrimSpace(f.Description),
		"severity":        strings.TrimSpace(f.Severity),
		"resource_type":   strings.TrimSpace(f.ResourceType),
		"resource_id":     strings.TrimSpace(f.ResourceID),
		"resource_name":   strings.TrimSpace(f.ResourceName),
		"risk_categories": f.RiskCategories,
		"remediation":     strings.TrimSpace(f.Remediation),
		"control_id":      strings.TrimSpace(f.ControlID),
		"source":          strings.TrimSpace(source),
	}
	if len(f.Frameworks) > 0 {
		finding["frameworks"] = f.Frameworks
	}
	if len(f.MitreAttack) > 0 {
		finding["mitre_attack"] = f.MitreAttack
	}
	for key, value := range extras {
		finding[key] = value
	}
	return compactMap(finding)
}

func compactMap(input map[string]interface{}) map[string]interface{} {
	if len(input) == 0 {
		return map[string]interface{}{}
	}

	output := make(map[string]interface{}, len(input))
	for key, value := range input {
		switch v := value.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(v) == "" {
				continue
			}
		case []string:
			if len(v) == 0 {
				continue
			}
		case []interface{}:
			if len(v) == 0 {
				continue
			}
		}
		output[key] = value
	}

	return output
}

func findingRiskString(finding map[string]interface{}) string {
	if risks := strings.TrimSpace(toString(finding["risks"])); risks != "" {
		return risks
	}
	categories := extractRiskCategories(finding)
	if len(categories) == 0 {
		return ""
	}
	return strings.Join(categories, ", ")
}

func severityLabel(severity string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	if sev == "" {
		sev = "UNKNOWN"
	}
	var colorCode string
	switch sev {
	case "CRITICAL":
		colorCode = colorRed
	case "HIGH":
		colorCode = colorYellow
	case "MEDIUM":
		colorCode = colorBlue
	case "LOW":
		colorCode = colorGray
	default:
		colorCode = colorCyan
	}
	return color(colorCode, "["+sev+"]")
}

func summarizeToxicCombos(findings []map[string]interface{}) toxicComboSummary {
	summary := toxicComboSummary{
		SeverityCounts: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
	}
	unique := make(map[string]struct{})
	resources := make(map[string]*toxicComboResourceSummary)
	for _, f := range findings {
		tc, _ := f["toxic_combo"].(bool)
		if !tc {
			continue
		}
		resourceID := normalizeResourceID(toString(f["resource_id"]))
		if resourceID == "" {
			continue
		}
		riskSig := riskSignature(extractRiskCategories(f), toString(f["policy_id"]))
		if riskSig == "" {
			riskSig = strings.ToLower(strings.TrimSpace(toString(f["title"])))
		}
		if riskSig == "" {
			continue
		}
		key := resourceID + "|" + riskSig
		if _, ok := unique[key]; ok {
			continue
		}
		unique[key] = struct{}{}
		summary.Total++

		sev := strings.ToUpper(toString(f["severity"]))
		if sev == "" {
			sev = "UNKNOWN"
		}
		if _, ok := summary.SeverityCounts[sev]; ok {
			summary.SeverityCounts[sev]++
		} else {
			summary.SeverityCounts["UNKNOWN"]++
		}

		resource := resources[resourceID]
		if resource == nil {
			resource = &toxicComboResourceSummary{
				ResourceID:      resourceID,
				ResourceName:    strings.TrimSpace(toString(f["resource_name"])),
				HighestSeverity: sev,
				DevEnvironment:  isDevResource(resourceID),
			}
			resources[resourceID] = resource
		}
		resource.Count++
		if resource.ResourceName == "" {
			resource.ResourceName = strings.TrimSpace(toString(f["resource_name"]))
		}
		if sevRank(sev) > sevRank(resource.HighestSeverity) {
			resource.HighestSeverity = sev
		}
	}

	summary.ResourceCount = len(resources)
	if len(resources) == 0 {
		return summary
	}

	top := make([]toxicComboResourceSummary, 0, len(resources))
	for _, resource := range resources {
		top = append(top, *resource)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count == top[j].Count {
			return sevRank(top[i].HighestSeverity) > sevRank(top[j].HighestSeverity)
		}
		return top[i].Count > top[j].Count
	})
	if len(top) > 5 {
		top = top[:5]
	}
	summary.TopResources = top
	return summary
}

func extractRiskCategories(f map[string]interface{}) []string {
	if raw := toString(f["risks"]); raw != "" {
		return parseRiskCategories(raw)
	}
	if raw, ok := f["risk_categories"]; ok {
		switch v := raw.(type) {
		case []string:
			return v
		case []interface{}:
			categories := make([]string, 0, len(v))
			for _, item := range v {
				if s := toString(item); s != "" {
					categories = append(categories, s)
				}
			}
			return categories
		default:
			if s := toString(raw); s != "" {
				return parseRiskCategories(s)
			}
		}
	}
	return nil
}

func riskSignature(categories []string, fallback string) string {
	canon := canonicalizeRiskCategories(categories)
	if len(canon) == 0 {
		return strings.ToLower(strings.TrimSpace(fallback))
	}
	keys := make([]string, 0, len(canon))
	for key := range canon {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func formatPathLengthDistribution(counts map[int]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]int, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		label := "hops"
		if key == 1 {
			label = "hop"
		}
		parts = append(parts, fmt.Sprintf("%d %s: %d", key, label, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func topMissingTables(counts map[string]int, limit int) []string {
	if limit <= 0 || len(counts) == 0 {
		return nil
	}
	type entry struct {
		table string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for table, count := range counts {
		entries = append(entries, entry{table: table, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].table < entries[j].table
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	results := make([]string, 0, len(entries))
	for _, entry := range entries {
		results = append(results, fmt.Sprintf("%s (%d)", entry.table, entry.count))
	}
	return results
}

// toString safely converts interface{} to string
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case float32:
		return int(val)
	case float64:
		return int(val)
	case string:
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return 0
}

func filterCDCEvents(events []snowflake.CDCEvent) ([]string, time.Time) {
	ids := make([]string, 0, len(events))
	var maxTime time.Time
	for _, event := range events {
		if event.EventTime.After(maxTime) {
			maxTime = event.EventTime
		}
		if isRemovalEvent(event.ChangeType) {
			continue
		}
		if event.ResourceID != "" {
			ids = append(ids, event.ResourceID)
		}
	}

	return dedupeStrings(ids), maxTime
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func retryCount(attempts int) int {
	if attempts > 1 {
		return attempts - 1
	}
	return 0
}

func relationshipFindingToMap(f scanner.RelationshipToxicFinding) map[string]interface{} {
	return map[string]interface{}{
		"severity":        f.Severity,
		"policy_id":       f.PolicyID,
		"title":           f.Title,
		"resource_id":     f.ResourceID,
		"resource_name":   f.ResourceName,
		"url":             f.URL,
		"service_account": f.ServiceAccount,
		"description":     f.Description,
		"risks":           f.Risks,
		"toxic_combo":     true,
		"source":          findingSourceToxicRelationship,
	}
}

func adjustAdaptiveConcurrency(limiter *scanner.AdaptiveLimiter, tuning app.ScanTuning, profile scanner.TableScanProfile) {
	limit := limiter.Limit()
	newLimit := limit
	slow := profile.TimedOut || profile.FetchErrors > 0 || profile.RetryAttempts > 0 || profile.Duration >= tuning.SlowTableThreshold
	fast := !slow && profile.Duration > 0 && profile.Duration <= tuning.FastTableThreshold
	if slow {
		newLimit = limit - 1
	} else if fast {
		newLimit = limit + 1
	}
	if newLimit == limit {
		return
	}
	adjusted := limiter.Adjust(newLimit)
	if adjusted == limit {
		return
	}
	Info("Adjusting scan concurrency: %d -> %d (table=%s, duration=%s, retries=%d, errors=%d)",
		limit,
		adjusted,
		profile.Table,
		profile.Duration.Round(time.Second),
		profile.RetryAttempts,
		profile.FetchErrors,
	)
}

func printScanProfiling(profiles []scanner.TableScanProfile, slowThreshold time.Duration) {
	if len(profiles) == 0 {
		return
	}
	sorted := scanner.SortTableProfilesByDuration(profiles)
	maxRows := 5
	if len(sorted) < maxRows {
		maxRows = len(sorted)
	}
	if maxRows == 0 {
		return
	}
	fmt.Println("\nScan profiling:")
	for i := 0; i < maxRows; i++ {
		profile := sorted[i]
		status := ""
		if profile.TimedOut {
			status = " (timeout)"
		}
		fmt.Printf("  %s: %s scanned=%d violations=%d retries=%d errors=%d%s\n",
			profile.Table,
			profile.Duration.Round(time.Second),
			profile.Scanned,
			profile.Violations,
			profile.RetryAttempts,
			profile.FetchErrors,
			status,
		)
	}
	slowTables := scanner.FilterSlowTables(profiles, slowThreshold)
	if len(slowTables) > 0 {
		names := make([]string, 0, len(slowTables))
		for _, profile := range slowTables {
			names = append(names, profile.Table)
		}
		fmt.Printf("  Slow tables (>%s): %s\n", slowThreshold, strings.Join(names, ", "))
	}
}

func scanProfilePayload(summary scanner.ScanProfileSummary, slowTables []scanner.TableScanProfile, slowThreshold time.Duration) map[string]interface{} {
	profiles := make([]map[string]interface{}, 0, len(summary.Tables))
	for _, profile := range summary.Tables {
		profiles = append(profiles, map[string]interface{}{
			"table":          profile.Table,
			"duration":       profile.Duration.String(),
			"scanned":        profile.Scanned,
			"violations":     profile.Violations,
			"cache_skipped":  profile.CacheSkipped,
			"batches":        profile.Batches,
			"retry_attempts": profile.RetryAttempts,
			"fetch_errors":   profile.FetchErrors,
			"scan_errors":    profile.ScanErrors,
			"timed_out":      profile.TimedOut,
		})
	}
	slow := make([]map[string]interface{}, 0, len(slowTables))
	for _, profile := range slowTables {
		slow = append(slow, map[string]interface{}{
			"table":     profile.Table,
			"duration":  profile.Duration.String(),
			"timed_out": profile.TimedOut,
		})
	}
	return map[string]interface{}{
		"total_scanned":    summary.TotalScanned,
		"total_violations": summary.TotalViolations,
		"total_skipped":    summary.TotalSkipped,
		"total_duration":   summary.TotalDuration.String(),
		"slow_threshold":   slowThreshold.String(),
		"tables":           profiles,
		"slow_tables":      slow,
	}
}
