package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaKindCount counts entities by kind.
type SchemaKindCount struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// SchemaIssueCount counts conformance issues by code/detail.
type SchemaIssueCount struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Count  int    `json:"count"`
}

// SchemaRecommendation describes one actionable ontology improvement.
type SchemaRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// SchemaEntityCoverage summarizes coverage/conformance for one entity type.
type SchemaEntityCoverage struct {
	Total          int `json:"total"`
	RegisteredKind int `json:"registered_kind"`
	UnknownKind    int `json:"unknown_kind"`
	Conformant     int `json:"conformant"`
}

// SchemaHealthReport captures ontology coverage, conformance, and drift.
type SchemaHealthReport struct {
	GeneratedAt    time.Time            `json:"generated_at"`
	SchemaVersion  int64                `json:"schema_version"`
	SinceVersion   int64                `json:"since_version"`
	ValidationMode SchemaValidationMode `json:"validation_mode"`

	Nodes SchemaEntityCoverage `json:"nodes"`
	Edges SchemaEntityCoverage `json:"edges"`

	NodeKindCoveragePercent float64 `json:"node_kind_coverage_percent"`
	EdgeKindCoveragePercent float64 `json:"edge_kind_coverage_percent"`
	NodeConformancePercent  float64 `json:"node_conformance_percent"`
	EdgeConformancePercent  float64 `json:"edge_conformance_percent"`

	UnknownNodeKinds          []SchemaKindCount  `json:"unknown_node_kinds,omitempty"`
	UnknownEdgeKinds          []SchemaKindCount  `json:"unknown_edge_kinds,omitempty"`
	MissingRequiredProperties []SchemaIssueCount `json:"missing_required_properties,omitempty"`
	InvalidPropertyTypes      []SchemaIssueCount `json:"invalid_property_types,omitempty"`
	MissingMetadataKeys       []SchemaIssueCount `json:"missing_metadata_keys,omitempty"`
	InvalidMetadataEnums      []SchemaIssueCount `json:"invalid_metadata_enums,omitempty"`
	InvalidMetadataTS         []SchemaIssueCount `json:"invalid_metadata_timestamps,omitempty"`
	InvalidRelationships      []SchemaIssueCount `json:"invalid_relationships,omitempty"`

	Drift             SchemaDriftReport      `json:"drift"`
	RecentChanges     []SchemaChange         `json:"recent_changes,omitempty"`
	RuntimeValidation SchemaValidationStats  `json:"runtime_validation"`
	Recommendations   []SchemaRecommendation `json:"recommendations,omitempty"`
}

// AnalyzeSchemaHealth evaluates ontology quality against one graph snapshot.
func AnalyzeSchemaHealth(g *Graph, historyLimit int, sinceVersion int64) SchemaHealthReport {
	reg := GlobalSchemaRegistry()
	version := reg.Version()
	recent := reg.History(historyLimit)

	if sinceVersion <= 0 {
		sinceVersion = version
		if len(recent) > 0 {
			sinceVersion = recent[0].Version - 1
		}
		if sinceVersion < 1 {
			sinceVersion = 1
		}
	}

	report := SchemaHealthReport{
		GeneratedAt:    time.Now().UTC(),
		SchemaVersion:  version,
		SinceVersion:   sinceVersion,
		ValidationMode: SchemaValidationWarn,
		RecentChanges:  recent,
		Drift:          reg.DriftSince(sinceVersion),
	}
	if g == nil {
		return report
	}

	report.ValidationMode = g.SchemaValidationMode()
	report.RuntimeValidation = g.SchemaValidationStats()

	nodes := g.GetAllNodes()
	report.Nodes.Total = len(nodes)
	nodeByID := make(map[string]*Node, len(nodes))

	unknownNodeKinds := make(map[string]int)
	missingRequired := make(map[string]*SchemaIssueCount)
	invalidPropTypes := make(map[string]*SchemaIssueCount)
	missingMetadata := make(map[string]*SchemaIssueCount)
	invalidMetadataEnums := make(map[string]*SchemaIssueCount)
	invalidMetadataTS := make(map[string]*SchemaIssueCount)

	for _, node := range nodes {
		if node == nil {
			continue
		}
		nodeByID[node.ID] = node
		if reg.IsNodeKindRegistered(node.Kind) {
			report.Nodes.RegisteredKind++
		} else {
			report.Nodes.UnknownKind++
			unknownNodeKinds[string(node.Kind)]++
		}

		issues := reg.ValidateNode(node)
		if len(issues) == 0 {
			report.Nodes.Conformant++
			continue
		}
		for _, issue := range issues {
			switch issue.Code {
			case SchemaIssueMissingRequiredProperty:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(missingRequired, string(issue.Code), detail)
			case SchemaIssueInvalidPropertyType:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(invalidPropTypes, string(issue.Code), detail)
			case SchemaIssueMissingMetadataKey:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(missingMetadata, string(issue.Code), detail)
			case SchemaIssueInvalidMetadataEnum:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(invalidMetadataEnums, string(issue.Code), detail)
			case SchemaIssueInvalidMetadataTS:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(invalidMetadataTS, string(issue.Code), detail)
			}
		}
	}

	unknownEdgeKinds := make(map[string]int)
	invalidRelationships := make(map[string]*SchemaIssueCount)

	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			report.Edges.Total++
			if reg.IsEdgeKindRegistered(edge.Kind) {
				report.Edges.RegisteredKind++
			} else {
				report.Edges.UnknownKind++
				unknownEdgeKinds[string(edge.Kind)]++
			}

			issues := reg.ValidateEdge(edge, nodeByID[edge.Source], nodeByID[edge.Target])
			if len(issues) == 0 {
				report.Edges.Conformant++
				continue
			}
			for _, issue := range issues {
				switch issue.Code {
				case SchemaIssueRelationshipNotAllowed,
					SchemaIssueMissingSourceNode,
					SchemaIssueMissingTargetNode,
					SchemaIssueUnknownSourceKind,
					SchemaIssueUnknownTargetKind:
					addSchemaIssueCount(invalidRelationships, string(issue.Code), issue.Message)
				}
			}
		}
	}

	report.NodeKindCoveragePercent = percent(report.Nodes.RegisteredKind, report.Nodes.Total)
	report.EdgeKindCoveragePercent = percent(report.Edges.RegisteredKind, report.Edges.Total)
	report.NodeConformancePercent = percent(report.Nodes.Conformant, report.Nodes.Total)
	report.EdgeConformancePercent = percent(report.Edges.Conformant, report.Edges.Total)
	report.UnknownNodeKinds = sortedSchemaKindCounts(unknownNodeKinds)
	report.UnknownEdgeKinds = sortedSchemaKindCounts(unknownEdgeKinds)
	report.MissingRequiredProperties = sortedSchemaIssueCounts(missingRequired)
	report.InvalidPropertyTypes = sortedSchemaIssueCounts(invalidPropTypes)
	report.MissingMetadataKeys = sortedSchemaIssueCounts(missingMetadata)
	report.InvalidMetadataEnums = sortedSchemaIssueCounts(invalidMetadataEnums)
	report.InvalidMetadataTS = sortedSchemaIssueCounts(invalidMetadataTS)
	report.InvalidRelationships = sortedSchemaIssueCounts(invalidRelationships)
	report.Recommendations = buildSchemaRecommendations(report)
	return report
}

func buildSchemaRecommendations(report SchemaHealthReport) []SchemaRecommendation {
	recommendations := make([]SchemaRecommendation, 0, 8)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, SchemaRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if report.Nodes.UnknownKind > 0 {
		add(
			"high",
			"node_kind_coverage",
			"Register unknown node kinds",
			fmt.Sprintf("%d node(s) use unregistered kinds. Top kinds: %s.", report.Nodes.UnknownKind, summarizeSchemaKindCounts(report.UnknownNodeKinds, 3)),
			"Add node kind definitions through /api/v1/graph/schema/register or TAP schema metadata.",
		)
	}

	if report.Edges.UnknownKind > 0 {
		add(
			"high",
			"edge_kind_coverage",
			"Register unknown edge kinds",
			fmt.Sprintf("%d edge(s) use unregistered kinds. Top kinds: %s.", report.Edges.UnknownKind, summarizeSchemaKindCounts(report.UnknownEdgeKinds, 3)),
			"Register missing edge kinds and map integration relationship names to known ontology kinds.",
		)
	}

	if len(report.MissingRequiredProperties) > 0 {
		add(
			"high",
			"required_properties",
			"Backfill required node properties",
			fmt.Sprintf("Missing required properties detected on %d distinct key(s). Top gaps: %s.", len(report.MissingRequiredProperties), summarizeSchemaIssueCounts(report.MissingRequiredProperties, 3)),
			"Fix upstream enrichers to emit required properties or relax overly strict requirements in the schema.",
		)
	}

	if len(report.InvalidPropertyTypes) > 0 {
		add(
			"medium",
			"property_types",
			"Normalize property types",
			fmt.Sprintf("Property type mismatches detected on %d distinct key(s). Top mismatches: %s.", len(report.InvalidPropertyTypes), summarizeSchemaIssueCounts(report.InvalidPropertyTypes, 3)),
			"Coerce source values to the declared ontology types before ingest.",
		)
	}

	if len(report.MissingMetadataKeys) > 0 {
		add(
			"high",
			"metadata_required_keys",
			"Backfill required metadata keys",
			fmt.Sprintf("Missing metadata keys detected on %d distinct key(s). Top gaps: %s.", len(report.MissingMetadataKeys), summarizeSchemaIssueCounts(report.MissingMetadataKeys, 3)),
			"Populate required metadata keys (source_system, source_event_id, observed_at, valid_from) for profiled kinds before writes.",
		)
	}

	if len(report.InvalidMetadataEnums) > 0 {
		add(
			"medium",
			"metadata_enums",
			"Normalize metadata enum values",
			fmt.Sprintf("Metadata enum mismatches detected on %d distinct key(s). Top mismatches: %s.", len(report.InvalidMetadataEnums), summarizeSchemaIssueCounts(report.InvalidMetadataEnums, 3)),
			"Map source states/severities/statuses to canonical enum values in mapping and writeback paths.",
		)
	}

	if len(report.InvalidMetadataTS) > 0 {
		add(
			"medium",
			"metadata_timestamps",
			"Normalize metadata timestamps",
			fmt.Sprintf("Metadata timestamp parsing failures detected on %d distinct key(s). Top failures: %s.", len(report.InvalidMetadataTS), summarizeSchemaIssueCounts(report.InvalidMetadataTS, 3)),
			"Emit RFC3339 timestamps consistently for all temporal metadata keys.",
		)
	}

	if len(report.InvalidRelationships) > 0 {
		add(
			"high",
			"relationship_contracts",
			"Align edge relationships with source kind contracts",
			fmt.Sprintf("Invalid relationships detected across %d distinct pattern(s). Top patterns: %s.", len(report.InvalidRelationships), summarizeSchemaIssueCounts(report.InvalidRelationships, 3)),
			"Expand allowed relationships for valid use cases, or remap edge kinds to the intended relationship.",
		)
	}

	if (report.Nodes.Total > 0 && report.NodeConformancePercent < 95) || (report.Edges.Total > 0 && report.EdgeConformancePercent < 95) {
		add(
			"medium",
			"conformance",
			"Raise ontology conformance",
			fmt.Sprintf("Current conformance is %.1f%% for nodes and %.1f%% for edges.", report.NodeConformancePercent, report.EdgeConformancePercent),
			"Prioritize fixes for the highest-volume issue categories first to improve conformance quickly.",
		)
	}

	totalIssues := (report.Nodes.Total - report.Nodes.Conformant) + (report.Edges.Total - report.Edges.Conformant)
	if report.ValidationMode != SchemaValidationEnforce && totalIssues > 0 {
		add(
			"medium",
			"validation_mode",
			"Enable enforce mode in controlled environments",
			fmt.Sprintf("Validation mode is %q while %d entity conformance issue(s) exist.", report.ValidationMode, totalIssues),
			"Use GRAPH_SCHEMA_VALIDATION_MODE=enforce in CI/staging to block ontology drift before production.",
		)
	}

	if len(report.Drift.CompatibilityWarnings) > 0 {
		add(
			"high",
			"schema_drift",
			"Review potentially breaking schema changes",
			fmt.Sprintf("%d compatibility warning(s) were introduced since schema version %d.", len(report.Drift.CompatibilityWarnings), report.SinceVersion),
			"Version data contracts with producers and plan backfills before enforcing new requirements.",
		)
	}

	if len(recommendations) == 0 {
		add(
			"low",
			"steady_state",
			"Maintain ontology quality",
			"Coverage and conformance are strong with no immediate high-impact ontology gaps detected.",
			"Keep schema health checks in CI and continue registering new kinds before new feeds are enabled.",
		)
	}

	return recommendations
}

func addSchemaIssueCount(target map[string]*SchemaIssueCount, code, detail string) {
	code = strings.TrimSpace(code)
	detail = strings.TrimSpace(detail)
	key := code + "|" + detail
	if issue, ok := target[key]; ok {
		issue.Count++
		return
	}
	target[key] = &SchemaIssueCount{
		Code:   code,
		Detail: detail,
		Count:  1,
	}
}

func sortedSchemaKindCounts(values map[string]int) []SchemaKindCount {
	if len(values) == 0 {
		return nil
	}
	out := make([]SchemaKindCount, 0, len(values))
	for kind, count := range values {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			kind = "<empty>"
		}
		out = append(out, SchemaKindCount{Kind: kind, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func sortedSchemaIssueCounts(values map[string]*SchemaIssueCount) []SchemaIssueCount {
	if len(values) == 0 {
		return nil
	}
	out := make([]SchemaIssueCount, 0, len(values))
	for _, issue := range values {
		if issue == nil {
			continue
		}
		out = append(out, *issue)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			if out[i].Code == out[j].Code {
				return out[i].Detail < out[j].Detail
			}
			return out[i].Code < out[j].Code
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func summarizeSchemaKindCounts(values []SchemaKindCount, limit int) string {
	if len(values) == 0 {
		return "none"
	}
	if limit <= 0 || limit > len(values) {
		limit = len(values)
	}
	parts := make([]string, 0, limit)
	for _, value := range values[:limit] {
		parts = append(parts, fmt.Sprintf("%s (%d)", value.Kind, value.Count))
	}
	return strings.Join(parts, ", ")
}

func summarizeSchemaIssueCounts(values []SchemaIssueCount, limit int) string {
	if len(values) == 0 {
		return "none"
	}
	if limit <= 0 || limit > len(values) {
		limit = len(values)
	}
	parts := make([]string, 0, limit)
	for _, value := range values[:limit] {
		detail := strings.TrimSpace(value.Detail)
		if detail == "" {
			detail = strings.TrimSpace(value.Code)
		}
		if detail == "" {
			detail = "unspecified"
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", detail, value.Count))
	}
	return strings.Join(parts, ", ")
}

func percent(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return (float64(numerator) / float64(denominator)) * 100
}
