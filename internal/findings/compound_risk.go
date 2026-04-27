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
)

// CompoundRiskOptions scopes how many correlated risk groups and samples are returned.
type CompoundRiskOptions struct {
	Limit       int
	SampleLimit int
}

// CompoundRiskReport summarizes correlated findings across common graph dimensions.
type CompoundRiskReport struct {
	Actors       []CompoundRiskGroup `json:"actors"`
	Resources    []CompoundRiskGroup `json:"resources"`
	Repositories []CompoundRiskGroup `json:"repositories"`
}

// CompoundRiskGroup captures one correlated set of findings sharing the same dimension.
type CompoundRiskGroup struct {
	Kind            string              `json:"kind"`
	Key             string              `json:"key"`
	Score           int                 `json:"score"`
	FindingCount    int                 `json:"finding_count"`
	RuleIDs         []string            `json:"rule_ids"`
	Severities      []CompoundRiskCount `json:"severities"`
	Actions         []CompoundRiskCount `json:"actions"`
	SampleSummaries []string            `json:"sample_summaries"`
}

// CompoundRiskCount is one deterministic value/count pair.
type CompoundRiskCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type compoundRiskBucket struct {
	key      string
	kind     string
	findings []*ports.FindingRecord
}

// AnalyzeCompoundRisks groups findings into actor, resource, and repository clusters.
func AnalyzeCompoundRisks(records []*ports.FindingRecord, options CompoundRiskOptions) CompoundRiskReport {
	records = dedupeCompoundRiskFindings(records)
	return CompoundRiskReport{
		Actors:       buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindActor), options),
		Resources:    buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindResource), options),
		Repositories: buildCompoundRiskGroups(groupCompoundRiskFindings(records, compoundRiskKindRepository), options),
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
		key := compoundRiskGroupKey(record, kind)
		if key == "" {
			continue
		}
		group, ok := groups[key]
		if !ok {
			group = &compoundRiskBucket{key: key, kind: kind}
			groups[key] = group
		}
		group.findings = append(group.findings, record)
	}
	buckets := make([]compoundRiskBucket, 0, len(groups))
	for _, group := range groups {
		buckets = append(buckets, *group)
	}
	return buckets
}

func compoundRiskGroupKey(record *ports.FindingRecord, kind string) string {
	if record == nil {
		return ""
	}
	attributes := record.Attributes
	switch kind {
	case compoundRiskKindActor:
		return strings.TrimSpace(attributes["actor"])
	case compoundRiskKindRepository:
		return strings.TrimSpace(attributes["repo"])
	case compoundRiskKindResource:
		if resourceURN := strings.TrimSpace(attributes["primary_resource_urn"]); resourceURN != "" {
			return resourceURN
		}
		for _, resourceURN := range record.ResourceURNs {
			if trimmed := strings.TrimSpace(resourceURN); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
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
		action := strings.TrimSpace(finding.Attributes["action"])
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
	group := CompoundRiskGroup{
		Kind:            bucket.kind,
		Key:             bucket.key,
		Score:           score,
		FindingCount:    len(bucket.findings),
		RuleIDs:         ruleIDs,
		Severities:      sortedCompoundRiskCounts(severities),
		Actions:         sortedCompoundRiskCounts(actions),
		SampleSummaries: samples,
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
