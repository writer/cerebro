package reports

import (
	"math"
	"sort"
	"strings"
	"time"
)

const defaultGraphMetadataTopKinds = 25

// GraphMetadataQualityReportOptions controls metadata-quality report generation.
type GraphMetadataQualityReportOptions struct {
	Now      time.Time
	TopKinds int
}

// GraphMetadataQualitySummary contains top-line metadata quality KPIs.
type GraphMetadataQualitySummary struct {
	Nodes                      int     `json:"nodes"`
	ProfiledKinds              int     `json:"profiled_kinds"`
	ProfiledNodes              int     `json:"profiled_nodes"`
	UnprofiledNodes            int     `json:"unprofiled_nodes"`
	RequiredKeyCoveragePercent float64 `json:"required_key_coverage_percent"`
	TimestampValidityPercent   float64 `json:"timestamp_validity_percent"`
	EnumValidityPercent        float64 `json:"enum_validity_percent"`
}

// GraphMetadataKindQuality captures metadata quality metrics for one node kind.
type GraphMetadataKindQuality struct {
	Kind                string         `json:"kind"`
	Nodes               int            `json:"nodes"`
	RequiredKeys        []string       `json:"required_keys,omitempty"`
	MissingRequired     map[string]int `json:"missing_required,omitempty"`
	InvalidTimestamps   map[string]int `json:"invalid_timestamps,omitempty"`
	InvalidEnums        map[string]int `json:"invalid_enums,omitempty"`
	CompletenessPercent float64        `json:"completeness_percent"`
}

// GraphMetadataRecommendation describes one actionable metadata-quality recommendation.
type GraphMetadataRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// GraphMetadataQualityReport summarizes metadata quality by kind and globally.
type GraphMetadataQualityReport struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	Summary         GraphMetadataQualitySummary   `json:"summary"`
	Kinds           []GraphMetadataKindQuality    `json:"kinds,omitempty"`
	UnprofiledKinds []SchemaKindCount             `json:"unprofiled_kinds,omitempty"`
	Recommendations []GraphMetadataRecommendation `json:"recommendations,omitempty"`
}

type metadataKindAccumulator struct {
	Kind              string
	Nodes             int
	RequiredKeys      []string
	MissingRequired   map[string]int
	InvalidTimestamps map[string]int
	InvalidEnums      map[string]int
	ChecksTotal       int
	ChecksFailed      int
}

// BuildGraphMetadataQualityReport computes per-kind metadata quality and recommendations.
func BuildGraphMetadataQualityReport(g *Graph, opts GraphMetadataQualityReportOptions) GraphMetadataQualityReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	topKinds := opts.TopKinds
	if topKinds <= 0 {
		topKinds = defaultGraphMetadataTopKinds
	}
	if topKinds > 200 {
		topKinds = 200
	}

	report := GraphMetadataQualityReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []GraphMetadataRecommendation{{
			Priority:        "high",
			Category:        "graph_unavailable",
			Title:           "Graph platform is not initialized",
			Detail:          "No metadata quality metrics are available because the graph is nil.",
			SuggestedAction: "Initialize and populate the graph before requesting metadata quality insights.",
		}}
		return report
	}

	reg := GlobalSchemaRegistry()
	nodes := g.GetAllNodes()
	report.Summary.Nodes = len(nodes)

	allKindCounts := make(map[string]int)
	profiledKinds := make(map[string]*metadataKindAccumulator)
	profiledKindSet := make(map[string]struct{})

	requiredChecks := 0
	requiredMissing := 0
	timestampChecks := 0
	timestampInvalid := 0
	enumChecks := 0
	enumInvalid := 0

	for _, node := range nodes {
		if node == nil {
			continue
		}
		kind := strings.TrimSpace(string(node.Kind))
		if kind == "" {
			kind = "<empty>"
		}
		allKindCounts[kind]++

		def, ok := reg.NodeKindDefinition(node.Kind)
		if !ok {
			continue
		}
		profile := normalizeNodeMetadataProfile(def.MetadataProfile)
		if !hasNodeMetadataProfile(profile) {
			continue
		}

		acc, ok := profiledKinds[kind]
		if !ok {
			acc = &metadataKindAccumulator{
				Kind:              kind,
				RequiredKeys:      append([]string(nil), profile.RequiredKeys...),
				MissingRequired:   make(map[string]int),
				InvalidTimestamps: make(map[string]int),
				InvalidEnums:      make(map[string]int),
			}
			profiledKinds[kind] = acc
			profiledKindSet[kind] = struct{}{}
		}
		acc.Nodes++
		report.Summary.ProfiledNodes++

		for _, key := range profile.RequiredKeys {
			requiredChecks++
			acc.ChecksTotal++
			if metadataValuePresent(node.Properties, key) {
				continue
			}
			requiredMissing++
			acc.ChecksFailed++
			acc.MissingRequired[key]++
		}

		for _, key := range profile.TimestampKeys {
			if node.Properties == nil {
				continue
			}
			value, ok := node.Properties[key]
			if !ok || value == nil {
				continue
			}
			timestampChecks++
			acc.ChecksTotal++
			if matchesPropertyType(value, "timestamp") {
				continue
			}
			timestampInvalid++
			acc.ChecksFailed++
			acc.InvalidTimestamps[key]++
		}

		for key, allowed := range profile.EnumValues {
			if node.Properties == nil {
				continue
			}
			value, ok := node.Properties[key]
			if !ok || value == nil {
				continue
			}
			enumChecks++
			acc.ChecksTotal++
			if metadataValueInEnum(value, allowed) {
				continue
			}
			enumInvalid++
			acc.ChecksFailed++
			acc.InvalidEnums[key]++
		}
	}

	report.Summary.ProfiledKinds = len(profiledKinds)
	report.Summary.RequiredKeyCoveragePercent = round1Metadata(metadataPercent(requiredChecks-requiredMissing, requiredChecks))
	report.Summary.TimestampValidityPercent = round1Metadata(metadataPercent(timestampChecks-timestampInvalid, timestampChecks))
	report.Summary.EnumValidityPercent = round1Metadata(metadataPercent(enumChecks-enumInvalid, enumChecks))

	unprofiledNodes := 0
	unprofiledKindCounts := make(map[string]int)
	for kind, count := range allKindCounts {
		if _, profiled := profiledKindSet[kind]; profiled {
			continue
		}
		unprofiledNodes += count
		unprofiledKindCounts[kind] = count
	}
	report.Summary.UnprofiledNodes = unprofiledNodes
	report.UnprofiledKinds = sortedSchemaKindCounts(unprofiledKindCounts)
	if len(report.UnprofiledKinds) > topKinds {
		report.UnprofiledKinds = report.UnprofiledKinds[:topKinds]
	}

	kindRows := make([]GraphMetadataKindQuality, 0, len(profiledKinds))
	for _, acc := range profiledKinds {
		kindRows = append(kindRows, GraphMetadataKindQuality{
			Kind:                acc.Kind,
			Nodes:               acc.Nodes,
			RequiredKeys:        append([]string(nil), acc.RequiredKeys...),
			MissingRequired:     normalizeIntMap(acc.MissingRequired),
			InvalidTimestamps:   normalizeIntMap(acc.InvalidTimestamps),
			InvalidEnums:        normalizeIntMap(acc.InvalidEnums),
			CompletenessPercent: round1Metadata(metadataPercent(acc.ChecksTotal-acc.ChecksFailed, acc.ChecksTotal)),
		})
	}
	sort.Slice(kindRows, func(i, j int) bool {
		if kindRows[i].Nodes == kindRows[j].Nodes {
			return kindRows[i].Kind < kindRows[j].Kind
		}
		return kindRows[i].Nodes > kindRows[j].Nodes
	})
	if len(kindRows) > topKinds {
		kindRows = kindRows[:topKinds]
	}
	report.Kinds = kindRows
	report.Recommendations = buildGraphMetadataRecommendations(report)

	return report
}

func buildGraphMetadataRecommendations(report GraphMetadataQualityReport) []GraphMetadataRecommendation {
	recommendations := make([]GraphMetadataRecommendation, 0, 6)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, GraphMetadataRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if report.Summary.ProfiledKinds == 0 {
		add(
			"high",
			"metadata_profiles",
			"Add metadata profiles to ontology kinds",
			"No node kinds currently have metadata profiles, so metadata quality cannot be enforced or trended.",
			"Define NodeMetadataProfile contracts for priority ontology kinds with required keys, timestamp keys, and enum constraints.",
		)
		return recommendations
	}

	if report.Summary.RequiredKeyCoveragePercent < 95 {
		priority := "medium"
		if report.Summary.RequiredKeyCoveragePercent < 80 {
			priority = "high"
		}
		add(
			priority,
			"required_keys",
			"Backfill missing required metadata keys",
			"Required metadata keys are missing on profiled node kinds, reducing traceability and replay safety.",
			"Ensure source_system, source_event_id, observed_at, and valid_from are emitted on all profiled writes.",
		)
	}

	if report.Summary.TimestampValidityPercent < 99 {
		priority := "medium"
		if report.Summary.TimestampValidityPercent < 90 {
			priority = "high"
		}
		add(
			priority,
			"timestamp_validity",
			"Normalize metadata timestamps",
			"Some metadata timestamp fields are not RFC3339 compatible, which weakens temporal queries and freshness logic.",
			"Normalize all observed_at/valid_from/valid_to writes through shared metadata helpers.",
		)
	}

	if report.Summary.EnumValidityPercent < 99 {
		priority := "medium"
		if report.Summary.EnumValidityPercent < 90 {
			priority = "high"
		}
		add(
			priority,
			"enum_normalization",
			"Map source states into canonical enums",
			"Metadata enum mismatches are present across profiled kinds and can fragment analytics by spelling/variant drift.",
			"Normalize upstream values to canonical ontology enums before writes.",
		)
	}

	if report.Summary.UnprofiledNodes > 0 {
		add(
			"medium",
			"profile_coverage",
			"Expand metadata profile coverage",
			"A subset of graph nodes are from kinds without metadata profiles, limiting metadata enforcement scope.",
			"Add metadata profiles to high-volume unprofiled kinds first.",
		)
	}

	if len(recommendations) == 0 {
		add(
			"low",
			"steady_state",
			"Maintain metadata quality baseline",
			"Profiled metadata quality signals are healthy across required keys, timestamp validity, and enum consistency.",
			"Keep metadata profile checks in CI and monitor these KPIs for regression.",
		)
	}

	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Priority == recommendations[j].Priority {
			if recommendations[i].Category == recommendations[j].Category {
				return recommendations[i].Title < recommendations[j].Title
			}
			return recommendations[i].Category < recommendations[j].Category
		}
		return metadataPriorityRank(recommendations[i].Priority) < metadataPriorityRank(recommendations[j].Priority)
	})
	return recommendations
}

func metadataPriorityRank(priority string) int {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func metadataValuePresent(properties map[string]any, key string) bool {
	if properties == nil {
		return false
	}
	value, ok := properties[key]
	if !ok || value == nil {
		return false
	}
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed) != ""
	}
	return true
}

func metadataValueInEnum(value any, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	stringValue, ok := value.(string)
	if !ok {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(stringValue))
	if normalized == "" {
		return false
	}
	return sliceContainsString(allowed, normalized)
}

func normalizeIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]int, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" || value <= 0 {
			continue
		}
		normalized[key] = value
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func metadataPercent(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return (float64(numerator) / float64(denominator)) * 100
}

func round1Metadata(value float64) float64 {
	return math.Round(value*10) / 10
}
