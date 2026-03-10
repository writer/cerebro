package graph

import (
	"sort"
	"strings"
	"time"
)

// ReportSectionEnvelopeDefinition describes one typed section-envelope contract for report authoring.
type ReportSectionEnvelopeDefinition struct {
	ID                     string         `json:"id"`
	Version                string         `json:"version"`
	Title                  string         `json:"title"`
	Description            string         `json:"description,omitempty"`
	SchemaName             string         `json:"schema_name"`
	SchemaURL              string         `json:"schema_url"`
	CompatibleSectionKinds []string       `json:"compatible_section_kinds,omitempty"`
	JSONSchema             map[string]any `json:"json_schema,omitempty"`
}

// ReportSectionEnvelopeCatalog is the discoverable registry payload for section-envelope contracts.
type ReportSectionEnvelopeCatalog struct {
	GeneratedAt time.Time                         `json:"generated_at"`
	Count       int                               `json:"count"`
	Envelopes   []ReportSectionEnvelopeDefinition `json:"envelopes"`
}

// BenchmarkBand captures one threshold band inside a benchmark pack.
type BenchmarkBand struct {
	Label       string   `json:"label"`
	Status      string   `json:"status"`
	MinValue    *float64 `json:"min_value,omitempty"`
	MaxValue    *float64 `json:"max_value,omitempty"`
	Description string   `json:"description,omitempty"`
}

// BenchmarkMeasureBinding captures how one measure is evaluated within a benchmark pack.
type BenchmarkMeasureBinding struct {
	MeasureID   string          `json:"measure_id"`
	Direction   string          `json:"direction"`
	Unit        string          `json:"unit,omitempty"`
	Bands       []BenchmarkBand `json:"bands,omitempty"`
	Description string          `json:"description,omitempty"`
}

// BenchmarkPack describes one reusable threshold-pack contract for report overlays.
type BenchmarkPack struct {
	ID              string                    `json:"id"`
	Version         string                    `json:"version"`
	Title           string                    `json:"title"`
	Scope           string                    `json:"scope"`
	Description     string                    `json:"description,omitempty"`
	SchemaName      string                    `json:"schema_name"`
	SchemaURL       string                    `json:"schema_url"`
	MeasureBindings []BenchmarkMeasureBinding `json:"measure_bindings,omitempty"`
}

// BenchmarkPackCatalog is the discoverable registry payload for benchmark packs.
type BenchmarkPackCatalog struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Count       int             `json:"count"`
	Packs       []BenchmarkPack `json:"packs"`
}

var defaultReportSectionEnvelopeDefinitions = []ReportSectionEnvelopeDefinition{
	{
		ID:          "summary",
		Version:     "1.0.0",
		Title:       "Summary Envelope",
		Description: "Headline summary with typed measures and optional highlights.",
		SchemaName:  "PlatformSummaryEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:summary:v1",
		CompatibleSectionKinds: []string{
			"context", "scorecard", "health_summary", "calibration_summary", "freshness_summary", "readiness_summary", "capability_summary", "backtest_summary",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"headline", "measures"},
			"properties": map[string]any{
				"headline": map[string]any{"type": "string"},
				"highlights": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
				"measures": map[string]any{
					"type":  "array",
					"items": reportMeasureValueSchema(),
				},
			},
		},
	},
	{
		ID:          "timeseries",
		Version:     "1.0.0",
		Title:       "Timeseries Envelope",
		Description: "Time-indexed series with typed measure values per point.",
		SchemaName:  "PlatformTimeseriesEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:timeseries:v1",
		CompatibleSectionKinds: []string{
			"timeseries_summary",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"points"},
			"properties": map[string]any{
				"points": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"timestamp", "values"},
						"properties": map[string]any{
							"timestamp": map[string]any{"type": "string", "format": "date-time"},
							"values": map[string]any{
								"type":  "array",
								"items": reportMeasureValueSchema(),
							},
						},
					},
				},
			},
		},
	},
	{
		ID:          "distribution",
		Version:     "1.0.0",
		Title:       "Distribution Envelope",
		Description: "Dimension-to-measure breakdown for categorical or grouped sections.",
		SchemaName:  "PlatformDistributionEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:distribution:v1",
		CompatibleSectionKinds: []string{
			"distribution", "coverage_breakdown", "health_breakdown", "breakdown_table",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"items"},
			"properties": map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"dimension", "measures"},
						"properties": map[string]any{
							"dimension": map[string]any{"type": "string"},
							"measures": map[string]any{
								"type":  "array",
								"items": reportMeasureValueSchema(),
							},
						},
					},
				},
			},
		},
	},
	{
		ID:          "ranking",
		Version:     "1.0.0",
		Title:       "Ranking Envelope",
		Description: "Ranked findings, backlog items, or action candidates with scores.",
		SchemaName:  "PlatformRankingEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:ranking:v1",
		CompatibleSectionKinds: []string{
			"ranked_findings", "ranked_backlog", "action_list",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"items"},
			"properties": map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"id", "title", "rank"},
						"properties": map[string]any{
							"id":      map[string]any{"type": "string"},
							"title":   map[string]any{"type": "string"},
							"rank":    map[string]any{"type": "integer"},
							"score":   map[string]any{"type": "number"},
							"summary": map[string]any{"type": "string"},
							"measure_values": map[string]any{
								"type":  "array",
								"items": reportMeasureValueSchema(),
							},
						},
					},
				},
			},
		},
	},
	{
		ID:          "network_slice",
		Version:     "1.0.0",
		Title:       "Network Slice Envelope",
		Description: "Localized graph slice with typed node and edge summaries.",
		SchemaName:  "PlatformNetworkSliceEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:network_slice:v1",
		CompatibleSectionKinds: []string{
			"embedded_report",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"nodes", "edges"},
			"properties": map[string]any{
				"nodes": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"id", "kind"},
						"properties": map[string]any{
							"id":   map[string]any{"type": "string"},
							"kind": map[string]any{"type": "string"},
							"name": map[string]any{"type": "string"},
						},
					},
				},
				"edges": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"source", "target", "kind"},
						"properties": map[string]any{
							"source": map[string]any{"type": "string"},
							"target": map[string]any{"type": "string"},
							"kind":   map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	},
	{
		ID:          "recommendations",
		Version:     "1.0.0",
		Title:       "Recommendations Envelope",
		Description: "Typed recommendation list with target linkage and optional benchmark-pack binding.",
		SchemaName:  "PlatformRecommendationsEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:recommendations:v1",
		CompatibleSectionKinds: []string{
			"action_list",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"items"},
			"properties": map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"id", "title", "priority"},
						"properties": map[string]any{
							"id":       map[string]any{"type": "string"},
							"title":    map[string]any{"type": "string"},
							"priority": map[string]any{"type": "string"},
							"summary":  map[string]any{"type": "string"},
							"target_ids": map[string]any{
								"type":  "array",
								"items": map[string]any{"type": "string"},
							},
							"benchmark_pack_id": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	},
	{
		ID:          "evidence_list",
		Version:     "1.0.0",
		Title:       "Evidence List Envelope",
		Description: "Evidence rows with source, timestamps, and confidence metadata.",
		SchemaName:  "PlatformEvidenceListEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:evidence_list:v1",
		CompatibleSectionKinds: []string{
			"contradiction_groups", "ranked_findings",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"items"},
			"properties": map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"evidence_id", "source_system"},
						"properties": map[string]any{
							"evidence_id":   map[string]any{"type": "string"},
							"source_system": map[string]any{"type": "string"},
							"summary":       map[string]any{"type": "string"},
							"observed_at":   map[string]any{"type": "string", "format": "date-time"},
							"confidence":    map[string]any{"type": "number"},
						},
					},
				},
			},
		},
	},
	{
		ID:          "narrative_block",
		Version:     "1.0.0",
		Title:       "Narrative Block Envelope",
		Description: "Curated narrative block with citations and optional document references.",
		SchemaName:  "PlatformNarrativeBlockEnvelope",
		SchemaURL:   "urn:cerebro:report-envelope:narrative_block:v1",
		CompatibleSectionKinds: []string{
			"context", "embedded_report",
		},
		JSONSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"body"},
			"properties": map[string]any{
				"title": map[string]any{"type": "string"},
				"body":  map[string]any{"type": "string"},
				"citations": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
				"document_id": map[string]any{"type": "string"},
			},
		},
	},
}

var defaultBenchmarkPacks = []BenchmarkPack{
	{
		ID:          "decision-intelligence.default",
		Version:     "1.0.0",
		Title:       "Decision Intelligence Default Thresholds",
		Scope:       "report",
		Description: "Default confidence, coverage, and freshness bands for intelligence reports.",
		SchemaName:  "PlatformDecisionIntelligenceBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:decision-intelligence.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "risk_score", Direction: "lower_is_better", Unit: "score", Bands: benchmarkBands(
				band("healthy", "good", nil, float64Ptr(30), "Low modeled risk."),
				band("watch", "warn", float64Ptr(30), float64Ptr(70), "Rising modeled risk."),
				band("critical", "critical", float64Ptr(70), nil, "High modeled risk."),
			)},
			{MeasureID: "coverage", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("critical_gap", "critical", nil, float64Ptr(60), "Coverage is too low for decision-grade output."),
				band("developing", "warn", float64Ptr(60), float64Ptr(85), "Coverage is usable but incomplete."),
				band("strong", "good", float64Ptr(85), nil, "Coverage is strong enough for decision support."),
			)},
			{MeasureID: "confidence", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("low_confidence", "critical", nil, float64Ptr(60), "Confidence is too weak for operator action."),
				band("moderate_confidence", "warn", float64Ptr(60), float64Ptr(80), "Confidence is improving but still conditional."),
				band("high_confidence", "good", float64Ptr(80), nil, "Confidence is strong."),
			)},
		},
	},
	{
		ID:          "graph-quality.default",
		Version:     "1.0.0",
		Title:       "Graph Quality Default Thresholds",
		Scope:       "report",
		Description: "Default benchmark bands for graph maturity and health measures.",
		SchemaName:  "PlatformGraphQualityBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:graph-quality.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "maturity_score", Direction: "higher_is_better", Unit: "score", Bands: benchmarkBands(
				band("fragile", "critical", nil, float64Ptr(60), "Graph quality is too fragile."),
				band("developing", "warn", float64Ptr(60), float64Ptr(80), "Graph quality is improving."),
				band("durable", "good", float64Ptr(80), nil, "Graph quality is durable."),
			)},
			{MeasureID: "coverage_percent", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("insufficient", "critical", nil, float64Ptr(70), "Coverage is below the substrate bar."),
				band("partial", "warn", float64Ptr(70), float64Ptr(90), "Coverage is serviceable but partial."),
				band("strong", "good", float64Ptr(90), nil, "Coverage is strong."),
			)},
			{MeasureID: "closure_rate_percent", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("open_loop", "critical", nil, float64Ptr(50), "Too many decisions lack outcomes."),
				band("mixed", "warn", float64Ptr(50), float64Ptr(80), "Closure is improving but incomplete."),
				band("closed_loop", "good", float64Ptr(80), nil, "Decision loops are closing."),
			)},
		},
	},
	{
		ID:          "metadata-quality.default",
		Version:     "1.0.0",
		Title:       "Metadata Quality Default Thresholds",
		Scope:       "report",
		Description: "Default threshold bands for metadata completeness and validity.",
		SchemaName:  "PlatformMetadataQualityBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:metadata-quality.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "required_key_coverage_percent", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("missing", "critical", nil, float64Ptr(75), "Required metadata coverage is too low."),
				band("partial", "warn", float64Ptr(75), float64Ptr(92), "Required coverage is improving."),
				band("strong", "good", float64Ptr(92), nil, "Required coverage is strong."),
			)},
			{MeasureID: "timestamp_validity_percent", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("invalid", "critical", nil, float64Ptr(90), "Too many invalid timestamps."),
				band("watch", "warn", float64Ptr(90), float64Ptr(98), "Timestamp quality needs tightening."),
				band("valid", "good", float64Ptr(98), nil, "Timestamp quality is strong."),
			)},
		},
	},
	{
		ID:          "claim-conflicts.default",
		Version:     "1.0.0",
		Title:       "Claim Conflict Default Thresholds",
		Scope:       "report",
		Description: "Default thresholds for contradiction, supportability, and source attribution.",
		SchemaName:  "PlatformClaimConflictBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:claim-conflicts.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "conflict_groups", Direction: "lower_is_better", Bands: benchmarkBands(
				band("quiet", "good", nil, float64Ptr(5), "Conflict volume is bounded."),
				band("watch", "warn", float64Ptr(5), float64Ptr(20), "Conflict volume is rising."),
				band("noisy", "critical", float64Ptr(20), nil, "Conflict volume is too high."),
			)},
			{MeasureID: "unsupported_claims", Direction: "lower_is_better", Bands: benchmarkBands(
				band("supported", "good", nil, float64Ptr(3), "Most claims are supported."),
				band("watch", "warn", float64Ptr(3), float64Ptr(10), "Unsupported claims need cleanup."),
				band("unsupported", "critical", float64Ptr(10), nil, "Too many unsupported claims."),
			)},
		},
	},
	{
		ID:          "graph-leverage.default",
		Version:     "1.0.0",
		Title:       "Graph Leverage Default Thresholds",
		Scope:       "report",
		Description: "Default thresholds for leverage, actuation readiness, and closure.",
		SchemaName:  "PlatformGraphLeverageBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:graph-leverage.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "leverage_score", Direction: "higher_is_better", Unit: "score", Bands: benchmarkBands(
				band("low", "critical", nil, float64Ptr(55), "The graph is not yet highly leveraged."),
				band("growing", "warn", float64Ptr(55), float64Ptr(80), "Leverage is growing."),
				band("high", "good", float64Ptr(80), nil, "The graph is highly leveraged."),
			)},
		},
	},
	{
		ID:          "weekly-calibration.default",
		Version:     "1.0.0",
		Title:       "Weekly Calibration Default Thresholds",
		Scope:       "report",
		Description: "Default calibration thresholds for outcome feedback and model confidence.",
		SchemaName:  "PlatformWeeklyCalibrationBenchmarkPack",
		SchemaURL:   "urn:cerebro:benchmark-pack:weekly-calibration.default:v1",
		MeasureBindings: []BenchmarkMeasureBinding{
			{MeasureID: "decision_accuracy_percent", Direction: "higher_is_better", Unit: "percent", Bands: benchmarkBands(
				band("off_target", "critical", nil, float64Ptr(60), "Calibration is off target."),
				band("stabilizing", "warn", float64Ptr(60), float64Ptr(80), "Calibration is improving."),
				band("calibrated", "good", float64Ptr(80), nil, "Calibration is strong."),
			)},
		},
	},
}

// ListReportSectionEnvelopeDefinitions returns the built-in typed section-envelope contracts.
func ListReportSectionEnvelopeDefinitions() []ReportSectionEnvelopeDefinition {
	envelopes := make([]ReportSectionEnvelopeDefinition, 0, len(defaultReportSectionEnvelopeDefinitions))
	for _, envelope := range defaultReportSectionEnvelopeDefinitions {
		cloned := envelope
		cloned.CompatibleSectionKinds = append([]string(nil), envelope.CompatibleSectionKinds...)
		cloned.JSONSchema = cloneAnyMap(envelope.JSONSchema)
		envelopes = append(envelopes, cloned)
	}
	sort.Slice(envelopes, func(i, j int) bool { return envelopes[i].ID < envelopes[j].ID })
	return envelopes
}

// GetReportSectionEnvelopeDefinition returns one section-envelope contract by id.
func GetReportSectionEnvelopeDefinition(id string) (ReportSectionEnvelopeDefinition, bool) {
	id = strings.TrimSpace(id)
	for _, envelope := range defaultReportSectionEnvelopeDefinitions {
		if envelope.ID == id {
			cloned := envelope
			cloned.CompatibleSectionKinds = append([]string(nil), envelope.CompatibleSectionKinds...)
			cloned.JSONSchema = cloneAnyMap(envelope.JSONSchema)
			return cloned, true
		}
	}
	return ReportSectionEnvelopeDefinition{}, false
}

// ReportSectionEnvelopeCatalogSnapshot returns a timestamped view of the section-envelope registry.
func ReportSectionEnvelopeCatalogSnapshot(now time.Time) ReportSectionEnvelopeCatalog {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	envelopes := ListReportSectionEnvelopeDefinitions()
	return ReportSectionEnvelopeCatalog{
		GeneratedAt: now,
		Count:       len(envelopes),
		Envelopes:   envelopes,
	}
}

// ListBenchmarkPacks returns the built-in benchmark pack catalog.
func ListBenchmarkPacks() []BenchmarkPack {
	packs := make([]BenchmarkPack, 0, len(defaultBenchmarkPacks))
	for _, pack := range defaultBenchmarkPacks {
		cloned := pack
		cloned.MeasureBindings = CloneBenchmarkMeasureBindings(pack.MeasureBindings)
		packs = append(packs, cloned)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	return packs
}

// GetBenchmarkPack returns one benchmark pack by id.
func GetBenchmarkPack(id string) (BenchmarkPack, bool) {
	id = strings.TrimSpace(id)
	for _, pack := range defaultBenchmarkPacks {
		if pack.ID == id {
			cloned := pack
			cloned.MeasureBindings = CloneBenchmarkMeasureBindings(pack.MeasureBindings)
			return cloned, true
		}
	}
	return BenchmarkPack{}, false
}

// BenchmarkPackCatalogSnapshot returns a timestamped view of the benchmark-pack registry.
func BenchmarkPackCatalogSnapshot(now time.Time) BenchmarkPackCatalog {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	packs := ListBenchmarkPacks()
	return BenchmarkPackCatalog{
		GeneratedAt: now,
		Count:       len(packs),
		Packs:       packs,
	}
}

// CloneBenchmarkMeasureBindings returns a deep copy of benchmark measure bindings.
func CloneBenchmarkMeasureBindings(values []BenchmarkMeasureBinding) []BenchmarkMeasureBinding {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]BenchmarkMeasureBinding(nil), values...)
	for i := range cloned {
		cloned[i].Bands = CloneBenchmarkBands(values[i].Bands)
	}
	return cloned
}

// CloneBenchmarkBands returns a deep copy of benchmark bands.
func CloneBenchmarkBands(values []BenchmarkBand) []BenchmarkBand {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]BenchmarkBand(nil), values...)
	for i := range cloned {
		if values[i].MinValue != nil {
			value := *values[i].MinValue
			cloned[i].MinValue = &value
		}
		if values[i].MaxValue != nil {
			value := *values[i].MaxValue
			cloned[i].MaxValue = &value
		}
	}
	return cloned
}

func reportMeasureValueSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"id", "label", "value_type"},
		"properties": map[string]any{
			"id":         map[string]any{"type": "string"},
			"label":      map[string]any{"type": "string"},
			"value_type": map[string]any{"type": "string"},
			"unit":       map[string]any{"type": "string"},
			"value": map[string]any{
				"oneOf": []any{
					map[string]any{"type": "string"},
					map[string]any{"type": "number"},
					map[string]any{"type": "integer"},
					map[string]any{"type": "boolean"},
				},
			},
			"status": map[string]any{"type": "string"},
		},
	}
}

func band(label, status string, minValue, maxValue *float64, description string) BenchmarkBand {
	return BenchmarkBand{
		Label:       label,
		Status:      status,
		MinValue:    minValue,
		MaxValue:    maxValue,
		Description: description,
	}
}

func benchmarkBands(values ...BenchmarkBand) []BenchmarkBand {
	return append([]BenchmarkBand(nil), values...)
}

func float64Ptr(value float64) *float64 {
	return &value
}
