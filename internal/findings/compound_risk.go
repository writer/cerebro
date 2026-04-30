package findings

import (
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	compoundRiskKindActor      = "actor"
	compoundRiskKindResource   = "resource"
	compoundRiskKindRepository = "repository"
	compoundRiskKindSource     = "source"
	compoundRiskKindType       = "resource_type"
)

// CompoundRiskOptions scopes how many correlated risk groups and samples are returned.
type CompoundRiskOptions struct {
	Limit       int
	SampleLimit int
}

// CompoundRiskReport summarizes correlated findings across common graph dimensions.
type CompoundRiskReport struct {
	Actors        []CompoundRiskGroup `json:"actors"`
	Resources     []CompoundRiskGroup `json:"resources"`
	Repositories  []CompoundRiskGroup `json:"repositories"`
	Sources       []CompoundRiskGroup `json:"sources"`
	ResourceTypes []CompoundRiskGroup `json:"resource_types"`
}

// CompoundRiskGroup captures one correlated set of findings sharing the same dimension.
type CompoundRiskGroup struct {
	Kind            string                `json:"kind"`
	Key             string                `json:"key"`
	Label           string                `json:"label,omitempty"`
	Score           int                   `json:"score"`
	ContextScore    int                   `json:"context_score"`
	RiskReasons     []string              `json:"risk_reasons,omitempty"`
	FindingCount    int                   `json:"finding_count"`
	RuleIDs         []string              `json:"rule_ids"`
	Severities      []CompoundRiskCount   `json:"severities"`
	Actions         []CompoundRiskCount   `json:"actions"`
	SampleSummaries []string              `json:"sample_summaries"`
	Evidence        FindingEvidenceBundle `json:"evidence"`
}

// CompoundRiskCount is one deterministic value/count pair.
type CompoundRiskCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type compoundRiskBucket struct {
	key      string
	label    string
	kind     string
	findings []*ports.FindingRecord
}

// AnalyzeCompoundRisks groups findings into source-agnostic actor, resource, repository, source, and resource-type clusters.
func AnalyzeCompoundRisks(records []*ports.FindingRecord, options CompoundRiskOptions) CompoundRiskReport {
	records = dedupeCompoundRiskFindings(records)
	return CompoundRiskReport{
		Actors:        buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindActor), options),
		Resources:     buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindResource), options),
		Repositories:  buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindRepository), options),
		Sources:       buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindSource), options),
		ResourceTypes: buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindType), options),
	}
}

func dedupeCompoundRiskFindings(records []*ports.FindingRecord) []*ports.FindingRecord {
	seen := map[string]struct{}{}
	unique := make([]*ports.FindingRecord, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		key := strings.TrimSpace(record.ID)
		if key == "" {
			key = strings.TrimSpace(record.Fingerprint)
		}
		if key == "" {
			key = strings.Join(append([]string{record.RuleID}, record.EventIDs...), "|")
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, record)
	}
	return unique
}

func groupCompoundRiskFindings(records []*ports.FindingRecord, kind string) []compoundRiskBucket {
	groups := map[string]*compoundRiskBucket{}
	for _, record := range records {
		dimension := compoundRiskDimensionFor(record, kind)
		if dimension.key == "" {
			continue
		}
		group, ok := groups[dimension.key]
		if !ok {
			group = &compoundRiskBucket{key: dimension.key, label: dimension.label, kind: kind}
			groups[dimension.key] = group
		}
		if group.label == "" {
			group.label = dimension.label
		}
		group.findings = append(group.findings, record)
	}
	buckets := make([]compoundRiskBucket, 0, len(groups))
	for _, group := range groups {
		buckets = append(buckets, *group)
	}
	return buckets
}

type compoundRiskDimension struct {
	key   string
	label string
}

func compoundRiskDimensionFor(record *ports.FindingRecord, kind string) compoundRiskDimension {
	if record == nil {
		return compoundRiskDimension{}
	}
	attributes := record.Attributes
	switch kind {
	case compoundRiskKindActor:
		key := firstNonEmpty(
			attributes["primary_actor_urn"],
			attributes["actor_urn"],
			attributes["actor"],
			attributes["actor_alternate_id"],
			attributes["user"],
		)
		return compoundRiskDimension{
			key:   key,
			label: firstNonEmpty(attributes["actor"], attributes["actor_alternate_id"], attributes["user"], key),
		}
	case compoundRiskKindRepository:
		key := repositoryFromFinding(record)
		return compoundRiskDimension{key: key, label: key}
	case compoundRiskKindResource:
		key := firstNonEmpty(attributes["primary_resource_urn"], firstFindingResourceURN(record))
		return compoundRiskDimension{
			key:   key,
			label: firstNonEmpty(attributes["resource_label"], attributes["repo"], attributes["repository"], attributes["resource_id"], attributes["policy_id"], key),
		}
	case compoundRiskKindSource:
		key := sourceIDForFinding(record)
		return compoundRiskDimension{key: key, label: key}
	case compoundRiskKindType:
		key := genericResourceType(record)
		return compoundRiskDimension{key: key, label: key}
	}
	return compoundRiskDimension{}
}

func buildCompoundRiskGroups(buckets []compoundRiskBucket, options CompoundRiskOptions) []CompoundRiskGroup {
	groups := make([]CompoundRiskGroup, 0, len(buckets))
	for _, bucket := range buckets {
		group := newCompoundRiskGroup(bucket, options)
		if group.FindingCount == 0 || !compoundRiskGroupIsInteresting(group) {
			continue
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i int, j int) bool {
		left := groups[i]
		right := groups[j]
		switch {
		case left.Score != right.Score:
			return left.Score > right.Score
		case left.FindingCount != right.FindingCount:
			return left.FindingCount > right.FindingCount
		default:
			return left.Key < right.Key
		}
	})
	if options.Limit > 0 && len(groups) > options.Limit {
		groups = groups[:options.Limit]
	}
	return groups
}

func newCompoundRiskGroup(bucket compoundRiskBucket, options CompoundRiskOptions) CompoundRiskGroup {
	rules := map[string]int{}
	severities := map[string]int{}
	actions := map[string]int{}
	score := 0
	maxSeverity := 0
	samples := make([]string, 0, compoundRiskSampleLimit(options))
	context := riskContextForFindings(bucket.findings)
	for _, finding := range bucket.findings {
		if finding == nil {
			continue
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID != "" {
			rules[ruleID]++
		}
		severity := strings.ToUpper(strings.TrimSpace(finding.Severity))
		if severity != "" {
			severities[severity]++
		}
		action := compoundRiskAction(finding)
		if action != "" {
			actions[action]++
		}
		severityScore := compoundRiskSeverityScore(severity)
		score += severityScore
		if severityScore > maxSeverity {
			maxSeverity = severityScore
		}
		if summary := strings.TrimSpace(finding.Summary); summary != "" && len(samples) < compoundRiskSampleLimit(options) {
			samples = append(samples, summary)
		}
	}
	ruleIDs := sortedCompoundRiskKeys(rules)
	score += 3 * max(0, len(ruleIDs)-1)
	score += context.Score
	group := CompoundRiskGroup{
		Kind:            bucket.kind,
		Key:             bucket.key,
		Label:           bucket.label,
		Score:           score,
		ContextScore:    context.Score,
		RiskReasons:     context.Reasons,
		FindingCount:    len(bucket.findings),
		RuleIDs:         ruleIDs,
		Severities:      sortedCompoundRiskCounts(severities),
		Actions:         sortedCompoundRiskCounts(actions),
		SampleSummaries: samples,
		Evidence:        newFindingEvidenceBundle(bucket.findings),
	}
	if maxSeverity >= compoundRiskSeverityScore("HIGH") {
		return group
	}
	if len(ruleIDs) > 1 {
		return group
	}
	if len(bucket.findings) > 1 {
		return group
	}
	return CompoundRiskGroup{}
}

func compoundRiskGroupIsInteresting(group CompoundRiskGroup) bool {
	if len(group.RuleIDs) > 1 {
		return true
	}
	if group.FindingCount > 1 {
		for _, severity := range group.Severities {
			if compoundRiskSeverityScore(severity.Value) >= compoundRiskSeverityScore("HIGH") {
				return true
			}
		}
	}
	return false
}

func compoundRiskSampleLimit(options CompoundRiskOptions) int {
	if options.SampleLimit > 0 {
		return options.SampleLimit
	}
	return 3
}

func compoundRiskSeverityScore(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
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

func compoundRiskAction(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	attributes := finding.Attributes
	return firstNonEmpty(attributes["action"], attributes["event_type"], attributes["operation_type"], attributes["state"], finding.CheckID, finding.RuleID)
}

func firstFindingResourceURN(record *ports.FindingRecord) string {
	if record == nil {
		return ""
	}
	for _, resourceURN := range record.ResourceURNs {
		if trimmed := strings.TrimSpace(resourceURN); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func repositoryFromFinding(record *ports.FindingRecord) string {
	if record == nil {
		return ""
	}
	attributes := record.Attributes
	if repository := firstNonEmpty(
		attributes["repo"],
		attributes["repository"],
		attributes["repository_name"],
		attributes["project"],
		attributes["project_key"],
		attributes["service"],
		attributes["service_name"],
	); repository != "" {
		return repository
	}
	for _, resourceURN := range record.ResourceURNs {
		if repository := repositoryFromURN(resourceURN); repository != "" {
			return repository
		}
	}
	return repositoryFromURN(record.Attributes["primary_resource_urn"])
}

func repositoryFromURN(value string) string {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 5 {
		return ""
	}
	resourceType := parts[3]
	if !strings.Contains(resourceType, "repo") &&
		!strings.Contains(resourceType, "repository") &&
		!strings.Contains(resourceType, "project") &&
		!strings.Contains(resourceType, "service") &&
		!strings.Contains(resourceType, "pull_request") &&
		!strings.Contains(resourceType, "dependabot_alert") {
		return ""
	}
	repository := strings.Join(parts[4:], ":")
	if strings.Contains(resourceType, "alert") {
		if idx := strings.LastIndex(repository, ":"); idx > 0 {
			repository = repository[:idx]
		}
	}
	if idx := strings.Index(repository, "#"); idx > 0 {
		repository = repository[:idx]
	}
	if strings.Contains(repository, "/") {
		return repository
	}
	return ""
}

func resourceTypeFromURN(value string) string {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 4 {
		return ""
	}
	return strings.TrimSpace(parts[3])
}

func sourceIDFromRuntime(runtimeID string) string {
	value := strings.ToLower(strings.TrimSpace(runtimeID))
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == '/' || r == '_' || r == '-'
	})
	candidate := ""
	for _, part := range parts {
		if part == "" || part == "live" || part == "audit" || part == "runtime" || part == "source" {
			continue
		}
		candidate = part
	}
	if candidate != "" {
		return candidate
	}
	return value
}

func sourceIDFromRule(ruleID string) string {
	value := strings.ToLower(strings.TrimSpace(ruleID))
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "-"); idx > 0 {
		return value[:idx]
	}
	return value
}

func sortedCompoundRiskKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedCompoundRiskCounts(values map[string]int) []CompoundRiskCount {
	counts := make([]CompoundRiskCount, 0, len(values))
	for value, count := range values {
		counts = append(counts, CompoundRiskCount{Value: value, Count: count})
	}
	sort.Slice(counts, func(i int, j int) bool {
		left := counts[i]
		right := counts[j]
		switch {
		case left.Count != right.Count:
			return left.Count > right.Count
		default:
			return left.Value < right.Value
		}
	})
	return counts
}
