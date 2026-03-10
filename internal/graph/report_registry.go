package graph

import (
	"sort"
	"time"
)

// ReportEndpoint describes how one report is exposed over the API.
type ReportEndpoint struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	Synchronous     bool   `json:"synchronous"`
	JobCapable      bool   `json:"job_capable,omitempty"`
	RunMethod       string `json:"run_method,omitempty"`
	RunPathTemplate string `json:"run_path_template,omitempty"`
}

// ReportParameter describes one typed request input for a report definition.
type ReportParameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	ValueType   string `json:"value_type"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// ReportMeasure describes one reusable metric surfaced by a report.
type ReportMeasure struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	ValueType   string `json:"value_type"`
	Unit        string `json:"unit,omitempty"`
	Description string `json:"description,omitempty"`
}

// ReportSection describes one composable section in a report payload.
type ReportSection struct {
	Key         string   `json:"key"`
	Title       string   `json:"title"`
	Kind        string   `json:"kind"`
	Description string   `json:"description,omitempty"`
	Measures    []string `json:"measures,omitempty"`
}

// ReportCheck describes one reusable quality or health check embodied by a report.
type ReportCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
}

// ReportExtensionPoint describes where namespaced extensions may attach to a report.
type ReportExtensionPoint struct {
	Key         string `json:"key"`
	Scope       string `json:"scope"`
	Description string `json:"description,omitempty"`
}

// ReportDefinition describes one built-in, extensible report surface.
type ReportDefinition struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Category        string                 `json:"category"`
	Description     string                 `json:"description,omitempty"`
	ResultSchema    string                 `json:"result_schema"`
	Endpoint        ReportEndpoint         `json:"endpoint"`
	TemporalModes   []string               `json:"temporal_modes,omitempty"`
	Parameters      []ReportParameter      `json:"parameters,omitempty"`
	Measures        []ReportMeasure        `json:"measures,omitempty"`
	Sections        []ReportSection        `json:"sections,omitempty"`
	Checks          []ReportCheck          `json:"checks,omitempty"`
	ExtensionPoints []ReportExtensionPoint `json:"extension_points,omitempty"`
}

// ReportCatalog is the discoverable registry payload for built-in reports.
type ReportCatalog struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Count       int                `json:"count"`
	Reports     []ReportDefinition `json:"reports"`
}

// ReportMeasureCatalog is the discoverable registry payload for reusable report measures.
type ReportMeasureCatalog struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Count       int             `json:"count"`
	Measures    []ReportMeasure `json:"measures"`
}

// ReportCheckCatalog is the discoverable registry payload for reusable report checks.
type ReportCheckCatalog struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Count       int           `json:"count"`
	Checks      []ReportCheck `json:"checks"`
}

var defaultReportDefinitions = []ReportDefinition{
	{
		ID:           "insights",
		Title:        "Decision Intelligence",
		Category:     "decision_support",
		Description:  "Prioritized decision-grade insights with evidence, coverage, confidence, and optional counterfactual context.",
		ResultSchema: "graph.IntelligenceReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/insights",
			Synchronous: true,
		},
		TemporalModes: []string{"window", "snapshot_diff"},
		Parameters: []ReportParameter{
			{Name: "entity_id", In: "query", ValueType: "string", Description: "Optional entity focus for entity-centric evidence and scoring."},
			{Name: "window_days", In: "query", ValueType: "integer", Description: "Outcome feedback window in days."},
			{Name: "history_limit", In: "query", ValueType: "integer", Description: "Schema history samples to include."},
			{Name: "since_version", In: "query", ValueType: "integer", Description: "Optional schema drift baseline version."},
			{Name: "max_insights", In: "query", ValueType: "integer", Description: "Maximum number of prioritized insights."},
			{Name: "include_counterfactual", In: "query", ValueType: "boolean", Description: "Include precomputed what-if scenarios."},
			{Name: "from", In: "query", ValueType: "date-time", Description: "Lower bound snapshot timestamp for temporal diff context."},
			{Name: "to", In: "query", ValueType: "date-time", Description: "Upper bound snapshot timestamp for temporal diff context."},
		},
		Measures: []ReportMeasure{
			{ID: "risk_score", Label: "Risk Score", ValueType: "number", Unit: "score", Description: "Top-line modeled risk score for the selected scope."},
			{ID: "coverage", Label: "Coverage", ValueType: "number", Unit: "percent", Description: "How much of the selected scope is covered by the available graph evidence."},
			{ID: "confidence", Label: "Confidence", ValueType: "number", Unit: "percent", Description: "Overall confidence after freshness, conformance, and evidence weighting."},
			{ID: "freshness_percent", Label: "Freshness", ValueType: "number", Unit: "percent", Description: "Recency-adjusted freshness for the selected scope."},
		},
		Sections: []ReportSection{
			{Key: "scope", Title: "Scope", Kind: "context", Description: "Selected entity and time-window context."},
			{Key: "schema_health", Title: "Schema Health", Kind: "health_summary", Description: "Ontology and schema drift context for the current run."},
			{Key: "outcome_feedback", Title: "Outcome Feedback", Kind: "calibration_summary", Description: "Observed outcome feedback feeding intelligence confidence."},
			{Key: "insights", Title: "Insights", Kind: "ranked_findings", Description: "Prioritized insights with evidence and suggested actions.", Measures: []string{"risk_score", "coverage", "confidence"}},
		},
		Checks: []ReportCheck{
			{ID: "schema_conformance", Title: "Schema Conformance", Severity: "high", Description: "Confidence should be reduced when ontology writes are invalid or drifting."},
			{ID: "freshness", Title: "Freshness", Severity: "high", Description: "Insights depend on recent graph observations and outcome feedback."},
			{ID: "counterfactual_readiness", Title: "Counterfactual Readiness", Severity: "medium", Description: "Counterfactual output depends on simulation-ready graph coverage."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "report.narrative", Scope: "report", Description: "Attach generated narratives or operator notes with explicit provenance."},
			{Key: "insights.overlays", Scope: "insights[]", Description: "Attach namespaced benchmark or scenario overlays to individual insights."},
		},
	},
	{
		ID:           "quality",
		Title:        "Graph Quality",
		Category:     "quality",
		Description:  "Graph operability view spanning ontology health, identity linkage, temporal completeness, and closed-loop write-back maturity.",
		ResultSchema: "graph.GraphQualityReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/quality",
			Synchronous: true,
		},
		TemporalModes: []string{"snapshot"},
		Parameters: []ReportParameter{
			{Name: "history_limit", In: "query", ValueType: "integer", Description: "Schema history samples to include."},
			{Name: "since_version", In: "query", ValueType: "integer", Description: "Optional schema drift baseline version."},
			{Name: "stale_after_hours", In: "query", ValueType: "integer", Description: "Freshness threshold in hours."},
		},
		Measures: []ReportMeasure{
			{ID: "maturity_score", Label: "Maturity Score", ValueType: "number", Unit: "score", Description: "Composite graph quality score."},
			{ID: "coverage_percent", Label: "Coverage", ValueType: "number", Unit: "percent", Description: "Ontology coverage across node and edge kinds."},
			{ID: "conformance_percent", Label: "Conformance", ValueType: "number", Unit: "percent", Description: "Schema conformance across graph writes."},
			{ID: "linkage_percent", Label: "Identity Linkage", ValueType: "number", Unit: "percent", Description: "Share of alias identities linked to canonical entities."},
			{ID: "metadata_completeness_percent", Label: "Metadata Completeness", ValueType: "number", Unit: "percent", Description: "Coverage for required temporal metadata keys."},
			{ID: "closure_rate_percent", Label: "Closure Rate", ValueType: "number", Unit: "percent", Description: "Share of decisions linked to outcomes or evaluations."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"maturity_score"}},
			{Key: "ontology", Title: "Ontology", Kind: "health_breakdown", Measures: []string{"coverage_percent", "conformance_percent"}},
			{Key: "identity", Title: "Identity", Kind: "health_breakdown", Measures: []string{"linkage_percent"}},
			{Key: "temporal", Title: "Temporal", Kind: "health_breakdown", Measures: []string{"metadata_completeness_percent"}},
			{Key: "writeback", Title: "Write-Back", Kind: "health_breakdown", Measures: []string{"closure_rate_percent"}},
			{Key: "domain_coverage", Title: "Domain Coverage", Kind: "distribution"},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
		Checks: []ReportCheck{
			{ID: "ontology_conformance", Title: "Ontology Conformance", Severity: "high", Description: "Unknown or invalid kinds should fail the graph quality bar."},
			{ID: "identity_linkage", Title: "Identity Linkage", Severity: "high", Description: "Unlinked aliases reduce graph trust and downstream personalization."},
			{ID: "temporal_metadata", Title: "Temporal Metadata", Severity: "high", Description: "Missing observed and valid timestamps weaken point-in-time reasoning."},
			{ID: "closed_loop", Title: "Closed Loop", Severity: "medium", Description: "Decisions without outcomes leave the intelligence loop incomplete."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "summary.overlays", Scope: "summary", Description: "Attach benchmark overlays or tenant-specific thresholds to quality summaries."},
			{Key: "recommendations.packs", Scope: "recommendations", Description: "Attach additional remediation packs or playbooks."},
		},
	},
	{
		ID:           "metadata-quality",
		Title:        "Metadata Quality",
		Category:     "quality",
		Description:  "Metadata-profile coverage view over required keys, timestamp validity, enum normalization, and the highest-volume unprofiled kinds.",
		ResultSchema: "graph.GraphMetadataQualityReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/metadata-quality",
			Synchronous: true,
		},
		TemporalModes: []string{"snapshot"},
		Parameters: []ReportParameter{
			{Name: "top_kinds", In: "query", ValueType: "integer", Description: "Maximum number of profiled and unprofiled kinds to include."},
		},
		Measures: []ReportMeasure{
			{ID: "required_key_coverage_percent", Label: "Required Key Coverage", ValueType: "number", Unit: "percent", Description: "Coverage for metadata keys marked required by ontology profiles."},
			{ID: "timestamp_validity_percent", Label: "Timestamp Validity", ValueType: "number", Unit: "percent", Description: "Share of timestamp fields matching the expected timestamp type."},
			{ID: "enum_validity_percent", Label: "Enum Validity", ValueType: "number", Unit: "percent", Description: "Share of enum-like values matching the allowed value set."},
			{ID: "profiled_kinds", Label: "Profiled Kinds", ValueType: "integer", Description: "Number of kinds with explicit metadata profiles."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"required_key_coverage_percent", "timestamp_validity_percent", "enum_validity_percent", "profiled_kinds"}},
			{Key: "kinds", Title: "Per-Kind Quality", Kind: "breakdown_table", Description: "Per-kind metadata completeness and validation errors."},
			{Key: "unprofiled_kinds", Title: "Unprofiled Kinds", Kind: "ranked_backlog", Description: "High-volume kinds missing metadata profiles."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
		Checks: []ReportCheck{
			{ID: "metadata_profiles", Title: "Metadata Profiles", Severity: "high", Description: "Priority kinds should define required keys, timestamp keys, and enum constraints."},
			{ID: "required_keys", Title: "Required Keys", Severity: "high", Description: "Required metadata keys should be present across profiled writes."},
			{ID: "timestamp_validity", Title: "Timestamp Validity", Severity: "medium", Description: "Timestamp fields should remain valid for bitemporal reasoning."},
			{ID: "enum_validity", Title: "Enum Validity", Severity: "medium", Description: "Ontology-enumerated values should be normalized consistently."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "kinds.annotations", Scope: "kinds[]", Description: "Attach source-specific repair hints or owner routing information."},
		},
	},
	{
		ID:           "claim-conflicts",
		Title:        "Claim Conflicts",
		Category:     "knowledge",
		Description:  "Knowledge-layer contradiction report grouped by subject and predicate, including supportability, source attribution, and truncation transparency.",
		ResultSchema: "graph.ClaimConflictReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/claim-conflicts",
			Synchronous: true,
		},
		TemporalModes: []string{"fact_time", "system_time", "bitemporal"},
		Parameters: []ReportParameter{
			{Name: "max_conflicts", In: "query", ValueType: "integer", Description: "Maximum contradiction groups to return."},
			{Name: "include_resolved", In: "query", ValueType: "boolean", Description: "Include resolved or superseded claims."},
			{Name: "stale_after_hours", In: "query", ValueType: "integer", Description: "Optional stale-claim threshold in hours."},
			{Name: "valid_at", In: "query", ValueType: "date-time", Description: "Fact-time slice for contradictions."},
			{Name: "recorded_at", In: "query", ValueType: "date-time", Description: "System-time slice for contradictions."},
		},
		Measures: []ReportMeasure{
			{ID: "conflict_groups", Label: "Conflict Groups", ValueType: "integer", Description: "Returned contradictory subject/predicate groups."},
			{ID: "conflicting_claims", Label: "Conflicting Claims", ValueType: "integer", Description: "Returned conflicting claims across the result set."},
			{ID: "unsupported_claims", Label: "Unsupported Claims", ValueType: "integer", Description: "Active claims with no evidence support."},
			{ID: "sourceless_claims", Label: "Sourceless Claims", ValueType: "integer", Description: "Active claims with no source attribution."},
			{ID: "stale_claims", Label: "Stale Claims", ValueType: "integer", Description: "Claims beyond the requested staleness threshold."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"conflict_groups", "conflicting_claims", "unsupported_claims", "sourceless_claims", "stale_claims"}},
			{Key: "conflicts", Title: "Conflict Groups", Kind: "contradiction_groups", Description: "Subject/predicate contradiction groups with conflicting values, sources, and timestamps."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
		Checks: []ReportCheck{
			{ID: "supportability", Title: "Supportability", Severity: "high", Description: "Claims should be backed by evidence nodes or observations."},
			{ID: "source_attribution", Title: "Source Attribution", Severity: "high", Description: "Claims should link back to first-class sources."},
			{ID: "contradiction_density", Title: "Contradiction Density", Severity: "medium", Description: "Contradiction groups should remain bounded for key subject predicates."},
			{ID: "truncation_transparency", Title: "Truncation Transparency", Severity: "medium", Description: "When contradiction output is truncated, total counts must remain explicit."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "conflicts.adjudication", Scope: "conflicts[]", Description: "Attach adjudication queue metadata, reviewer ownership, or downstream workflow links."},
		},
	},
	{
		ID:           "leverage",
		Title:        "Graph Leverage",
		Category:     "operating_model",
		Description:  "Combined operating view across quality, identity calibration, ingestion breadth, temporal freshness, predictive readiness, query readiness, and actuation closure.",
		ResultSchema: "graph.GraphLeverageReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/leverage",
			Synchronous: true,
		},
		TemporalModes: []string{"snapshot", "short_term_trend"},
		Parameters: []ReportParameter{
			{Name: "history_limit", In: "query", ValueType: "integer", Description: "Schema history samples to include."},
			{Name: "since_version", In: "query", ValueType: "integer", Description: "Optional schema drift baseline version."},
			{Name: "stale_after_hours", In: "query", ValueType: "integer", Description: "Freshness threshold in hours."},
			{Name: "recent_window_hours", In: "query", ValueType: "integer", Description: "Recent activity window in hours."},
			{Name: "decision_sla_days", In: "query", ValueType: "integer", Description: "Decision outcome SLA in days."},
			{Name: "identity_suggest_threshold", In: "query", ValueType: "number", Description: "Identity review suggestion threshold."},
			{Name: "identity_queue_limit", In: "query", ValueType: "integer", Description: "Maximum identity queue entries to return."},
		},
		Measures: []ReportMeasure{
			{ID: "leverage_score", Label: "Leverage Score", ValueType: "number", Unit: "score", Description: "Composite operating score for graph leverage."},
			{ID: "coverage_percent", Label: "Ingestion Coverage", ValueType: "number", Unit: "percent", Description: "Observed source-system coverage against expected ingest breadth."},
			{ID: "canonical_kind_coverage_percent", Label: "Canonical Kind Coverage", ValueType: "number", Unit: "percent", Description: "Share of nodes using canonical ontology kinds."},
			{ID: "schema_valid_write_percent", Label: "Schema Valid Writes", ValueType: "number", Unit: "percent", Description: "Share of writes conforming to schema contracts."},
			{ID: "closure_rate_percent", Label: "Closed Loop", ValueType: "number", Unit: "percent", Description: "Share of decisions linked to outcomes."},
			{ID: "readiness_score", Label: "Predictive Readiness", ValueType: "number", Unit: "score", Description: "Readiness for prediction and calibration based on evidence and labeled outcomes."},
			{ID: "actuation_coverage_percent", Label: "Actuation Coverage", ValueType: "number", Unit: "percent", Description: "Share of actions linked to targets, decisions, and outcomes."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"leverage_score"}},
			{Key: "quality", Title: "Quality", Kind: "embedded_report"},
			{Key: "identity", Title: "Identity", Kind: "embedded_report"},
			{Key: "ingestion", Title: "Ingestion", Kind: "coverage_breakdown", Measures: []string{"coverage_percent"}},
			{Key: "ontology", Title: "Ontology SLO", Kind: "timeseries_summary", Measures: []string{"canonical_kind_coverage_percent", "schema_valid_write_percent"}},
			{Key: "temporal", Title: "Temporal", Kind: "freshness_summary"},
			{Key: "closed_loop", Title: "Closed Loop", Kind: "health_breakdown", Measures: []string{"closure_rate_percent"}},
			{Key: "predictive", Title: "Predictive", Kind: "readiness_summary", Measures: []string{"readiness_score"}},
			{Key: "query", Title: "Query", Kind: "capability_summary"},
			{Key: "actuation", Title: "Actuation", Kind: "readiness_summary", Measures: []string{"actuation_coverage_percent"}},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
		Checks: []ReportCheck{
			{ID: "source_coverage", Title: "Source Coverage", Severity: "high", Description: "Leverage weakens quickly when ingest breadth misses core operating systems."},
			{ID: "identity_precision", Title: "Identity Precision", Severity: "high", Description: "Low-confidence identity linkage erodes cross-source graph trust."},
			{ID: "ontology_trust", Title: "Ontology Trust", Severity: "high", Description: "Canonical kind coverage and valid writes are prerequisite for reuse."},
			{ID: "actuation_closure", Title: "Actuation Closure", Severity: "medium", Description: "Actions should land with targets, decisions, and outcomes."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "ingestion.expectations", Scope: "ingestion", Description: "Attach tenant-specific required-source sets or benchmarks."},
			{Key: "recommendations.playbooks", Scope: "recommendations", Description: "Attach workflow playbooks for leverage remediation."},
		},
	},
	{
		ID:           "calibration-weekly",
		Title:        "Weekly Calibration",
		Category:     "calibration",
		Description:  "Weekly slice combining outcome backtest, identity calibration status, and ontology trend context.",
		ResultSchema: "graph.WeeklyCalibrationReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/calibration/weekly",
			Synchronous: true,
		},
		TemporalModes: []string{"window", "trend"},
		Parameters: []ReportParameter{
			{Name: "window_days", In: "query", ValueType: "integer", Description: "Feedback observation window in days."},
			{Name: "trend_days", In: "query", ValueType: "integer", Description: "Ontology trend horizon in days."},
			{Name: "profile", In: "query", ValueType: "string", Description: "Optional risk profile selector."},
			{Name: "include_queue", In: "query", ValueType: "boolean", Description: "Include identity review queue details."},
			{Name: "queue_limit", In: "query", ValueType: "integer", Description: "Maximum identity review queue entries."},
		},
		Measures: []ReportMeasure{
			{ID: "outcome_count", Label: "Observed Outcomes", ValueType: "integer", Description: "Number of outcomes in the calibration window."},
			{ID: "rule_signal_count", Label: "Rule Signals", ValueType: "integer", Description: "Number of rule signals available for backtesting."},
			{ID: "precision_percent", Label: "Identity Precision", ValueType: "number", Unit: "percent", Description: "Accepted identity review precision over the selected calibration slice."},
			{ID: "review_coverage_percent", Label: "Review Coverage", ValueType: "number", Unit: "percent", Description: "Share of aliases reviewed in the identity calibration slice."},
			{ID: "canonical_kind_coverage_percent", Label: "Canonical Kind Coverage", ValueType: "number", Unit: "percent", Description: "Ontology trend coverage for the selected trend horizon."},
		},
		Sections: []ReportSection{
			{Key: "risk_feedback", Title: "Risk Feedback", Kind: "backtest_summary", Measures: []string{"outcome_count", "rule_signal_count"}},
			{Key: "identity", Title: "Identity", Kind: "calibration_summary", Measures: []string{"precision_percent", "review_coverage_percent"}},
			{Key: "ontology", Title: "Ontology Trend", Kind: "timeseries_summary", Measures: []string{"canonical_kind_coverage_percent"}},
		},
		Checks: []ReportCheck{
			{ID: "outcome_backtest", Title: "Outcome Backtest", Severity: "high", Description: "Outcome coverage and signal backtesting must remain large enough for calibration."},
			{ID: "identity_review_coverage", Title: "Identity Review Coverage", Severity: "medium", Description: "Identity calibration requires regular reviewer decisions."},
			{ID: "ontology_trend", Title: "Ontology Trend", Severity: "medium", Description: "Weekly calibration should include a non-empty ontology trend slice."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "risk_feedback.benchmarks", Scope: "risk_feedback", Description: "Attach historical benchmark bands or model baselines."},
		},
	},
}

// ListReportDefinitions returns the built-in report definitions for the platform intelligence layer.
func ListReportDefinitions() []ReportDefinition {
	definitions := make([]ReportDefinition, 0, len(defaultReportDefinitions))
	for _, definition := range defaultReportDefinitions {
		definitions = append(definitions, normalizeReportDefinition(cloneReportDefinition(definition)))
	}
	return definitions
}

// GetReportDefinition returns one built-in report definition by ID.
func GetReportDefinition(id string) (ReportDefinition, bool) {
	for _, definition := range defaultReportDefinitions {
		if definition.ID == id {
			return normalizeReportDefinition(cloneReportDefinition(definition)), true
		}
	}
	return ReportDefinition{}, false
}

// ReportCatalogSnapshot returns a timestamped view of the built-in report registry.
func ReportCatalogSnapshot(now time.Time) ReportCatalog {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reports := ListReportDefinitions()
	return ReportCatalog{
		GeneratedAt: now,
		Count:       len(reports),
		Reports:     reports,
	}
}

// ListReportMeasures returns the deduplicated reusable measure catalog across built-in reports.
func ListReportMeasures() []ReportMeasure {
	byID := make(map[string]ReportMeasure)
	for _, definition := range ListReportDefinitions() {
		for _, measure := range definition.Measures {
			if _, ok := byID[measure.ID]; ok {
				continue
			}
			byID[measure.ID] = measure
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	measures := make([]ReportMeasure, 0, len(ids))
	for _, id := range ids {
		measures = append(measures, byID[id])
	}
	return measures
}

// ListReportChecks returns the deduplicated reusable check catalog across built-in reports.
func ListReportChecks() []ReportCheck {
	byID := make(map[string]ReportCheck)
	for _, definition := range ListReportDefinitions() {
		for _, check := range definition.Checks {
			if _, ok := byID[check.ID]; ok {
				continue
			}
			byID[check.ID] = check
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	checks := make([]ReportCheck, 0, len(ids))
	for _, id := range ids {
		checks = append(checks, byID[id])
	}
	return checks
}

// ReportMeasureCatalogSnapshot returns a timestamped view of the reusable measure registry.
func ReportMeasureCatalogSnapshot(now time.Time) ReportMeasureCatalog {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	measures := ListReportMeasures()
	return ReportMeasureCatalog{
		GeneratedAt: now,
		Count:       len(measures),
		Measures:    measures,
	}
}

// ReportCheckCatalogSnapshot returns a timestamped view of the reusable check registry.
func ReportCheckCatalogSnapshot(now time.Time) ReportCheckCatalog {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	checks := ListReportChecks()
	return ReportCheckCatalog{
		GeneratedAt: now,
		Count:       len(checks),
		Checks:      checks,
	}
}

func cloneReportDefinition(definition ReportDefinition) ReportDefinition {
	cloned := definition
	cloned.TemporalModes = append([]string(nil), definition.TemporalModes...)
	cloned.Parameters = append([]ReportParameter(nil), definition.Parameters...)
	cloned.Measures = append([]ReportMeasure(nil), definition.Measures...)
	cloned.Sections = append([]ReportSection(nil), definition.Sections...)
	for i := range cloned.Sections {
		cloned.Sections[i].Measures = append([]string(nil), definition.Sections[i].Measures...)
	}
	cloned.Checks = append([]ReportCheck(nil), definition.Checks...)
	cloned.ExtensionPoints = append([]ReportExtensionPoint(nil), definition.ExtensionPoints...)
	return cloned
}

func normalizeReportDefinition(definition ReportDefinition) ReportDefinition {
	if !definition.Endpoint.JobCapable {
		definition.Endpoint.JobCapable = true
	}
	if definition.Endpoint.RunMethod == "" {
		definition.Endpoint.RunMethod = "POST"
	}
	if definition.Endpoint.RunPathTemplate == "" {
		definition.Endpoint.RunPathTemplate = "/api/v1/platform/intelligence/reports/{id}/runs"
	}
	return definition
}
