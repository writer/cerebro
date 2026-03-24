package reports

import (
	"sort"
	"strings"
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
	Key              string   `json:"key"`
	Title            string   `json:"title"`
	Kind             string   `json:"kind"`
	EnvelopeKind     string   `json:"envelope_kind,omitempty"`
	EnvelopeSchema   string   `json:"envelope_schema,omitempty"`
	Description      string   `json:"description,omitempty"`
	Measures         []string `json:"measures,omitempty"`
	BenchmarkPackIDs []string `json:"benchmark_pack_ids,omitempty"`
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
	Version         string                 `json:"version,omitempty"`
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
		ID:           "agent-action-effectiveness",
		Title:        "Agent Action Effectiveness",
		Category:     "decision_support",
		Description:  "Evaluation rollups showing successful versus reversed actions, cost-to-outcome efficiency, and correctness trends across agents and time windows.",
		ResultSchema: "reports.AgentActionEffectivenessReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/agent-action-effectiveness",
			Synchronous: true,
		},
		TemporalModes: []string{"window"},
		Parameters: []ReportParameter{
			{Name: "window_days", In: "query", ValueType: "integer", Description: "Conversation window in days to include in the report."},
			{Name: "trend_days", In: "query", ValueType: "integer", Description: "Number of daily buckets to include in the trend output."},
			{Name: "max_agents", In: "query", ValueType: "integer", Description: "Maximum number of agent rollups to return."},
		},
		Measures: []ReportMeasure{
			{ID: "conversation_count", Label: "Conversations", ValueType: "integer", Description: "Evaluation conversations included in the selected window."},
			{ID: "successful_action_count", Label: "Successful Actions", ValueType: "integer", Description: "Agent actions that aligned with positive conversation outcomes."},
			{ID: "reversed_action_count", Label: "Reversed Actions", ValueType: "integer", Description: "Actions explicitly reverted or later invalidated by negative outcomes."},
			{ID: "cost_per_successful_conversation_usd", Label: "Cost Per Successful Conversation", ValueType: "number", Unit: "usd", Description: "Total evaluation cost divided by positive conversation outcomes."},
			{ID: "correctness_percent", Label: "Correctness", ValueType: "number", Unit: "percent", Description: "Share of evaluation conversations that ended in positive outcomes."},
			{ID: "average_quality_score", Label: "Average Quality Score", ValueType: "number", Unit: "score", Description: "Average conversation quality score from evaluation outcomes."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"conversation_count", "successful_action_count", "reversed_action_count", "cost_per_successful_conversation_usd", "correctness_percent", "average_quality_score"}},
			{Key: "agents", Title: "Agent Rollups", Kind: "breakdown_table", Description: "Per-agent outcome, cost, and reversal rollups."},
			{Key: "trends", Title: "Correctness Trends", Kind: "timeseries", Description: "Daily correctness, reversal, and cost-to-outcome trends."},
			{Key: "reversals", Title: "Reversals", Kind: "ranked_findings", Description: "Most recent reversed or later-invalidated actions."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", Description: "Suggested remediation or tuning actions for weak-performing agent flows."},
		},
		Checks: []ReportCheck{
			{ID: "agent_correctness", Title: "Agent Correctness", Severity: "high", Description: "Agent actions should consistently lead to positive conversation outcomes."},
			{ID: "action_reversals", Title: "Action Reversals", Severity: "high", Description: "Explicit reversals and negative post-action outcomes should remain low."},
			{ID: "cost_efficiency", Title: "Cost Efficiency", Severity: "medium", Description: "Cost per successful conversation should remain within the expected operating envelope."},
		},
	},
	{
		ID:           "playbook-effectiveness",
		Title:        "Playbook Effectiveness",
		Category:     "decision_support",
		Description:  "Workflow execution rollups showing completion, outcome durability, approval friction, repeated remediation, and failure hot spots across playbooks, targets, and tenants.",
		ResultSchema: "reports.PlaybookEffectivenessReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/playbook-effectiveness",
			Synchronous: true,
		},
		TemporalModes: []string{"window"},
		Parameters: []ReportParameter{
			{Name: "window_days", In: "query", ValueType: "integer", Description: "Run window in days to include in the report."},
			{Name: "playbook_id", In: "query", ValueType: "string", Description: "Optional playbook identifier to scope one playbook."},
			{Name: "tenant_id", In: "query", ValueType: "string", Description: "Optional tenant identifier to scope one tenant."},
			{Name: "target_kind", In: "query", ValueType: "string", Description: "Optional ontology target kind to scope runs that touched that kind."},
			{Name: "max_playbooks", In: "query", ValueType: "integer", Description: "Maximum number of per-playbook rollups to return."},
		},
		Measures: []ReportMeasure{
			{ID: "playbook_run_count", Label: "Runs", ValueType: "integer", Description: "Playbook runs included in the selected window."},
			{ID: "playbook_completion_rate_percent", Label: "Completion Rate", ValueType: "number", Unit: "percent", Description: "Share of playbook runs with terminal outcomes."},
			{ID: "playbook_success_rate_percent", Label: "Success Rate", ValueType: "number", Unit: "percent", Description: "Share of playbook runs ending in positive outcomes."},
			{ID: "playbook_rollback_rate_percent", Label: "Rollback Rate", ValueType: "number", Unit: "percent", Description: "Share of completed playbook runs ending in rollback or reversal signals."},
			{ID: "playbook_average_completion_minutes", Label: "Average Completion Time", ValueType: "number", Unit: "minutes", Description: "Average time between run start and terminal outcome."},
			{ID: "playbook_approval_bottleneck_count", Label: "Approval Bottlenecks", ValueType: "integer", Description: "Approval-required stages that created friction or blocked progress."},
			{ID: "playbook_repeat_execution_rate_percent", Label: "Repeat Execution Rate", ValueType: "number", Unit: "percent", Description: "Share of runs that repeated remediation on the same targets."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"playbook_run_count", "playbook_completion_rate_percent", "playbook_success_rate_percent", "playbook_rollback_rate_percent", "playbook_average_completion_minutes", "playbook_approval_bottleneck_count", "playbook_repeat_execution_rate_percent"}},
			{Key: "playbooks", Title: "Playbooks", Kind: "breakdown_table", Description: "Per-playbook execution quality, rollback, and repeat-target rollups."},
			{Key: "stages", Title: "Stages", Kind: "breakdown_table", Description: "Per-stage failure and approval-friction rollups."},
			{Key: "target_kinds", Title: "Target Kinds", Kind: "breakdown_table", Description: "Effectiveness breakdown by targeted ontology kind."},
			{Key: "tenants", Title: "Tenants", Kind: "breakdown_table", Description: "Effectiveness breakdown by tenant."},
			{Key: "failure_steps", Title: "Failure Steps", Kind: "ranked_findings", Description: "Stages that most often failed across the selected playbook runs."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", Description: "Suggested remediation for unstable or high-friction playbooks."},
		},
		Checks: []ReportCheck{
			{ID: "playbook_completion", Title: "Playbook Completion", Severity: "high", Description: "Playbook runs should reliably reach terminal outcomes."},
			{ID: "playbook_rollbacks", Title: "Playbook Rollbacks", Severity: "high", Description: "Completed playbooks should not frequently require rollback or reversal."},
			{ID: "playbook_approval_friction", Title: "Playbook Approval Friction", Severity: "medium", Description: "Approval-required stages should not become a systemic bottleneck."},
		},
	},
	{
		ID:           "unified-execution-timeline",
		Title:        "Unified Execution Timeline",
		Category:     "knowledge",
		Description:  "Chronological workflow timeline across evaluation and playbook runs, including scoped communication threads, stage decisions, actions, outcomes, and directly supporting evidence and claims.",
		ResultSchema: "reports.UnifiedExecutionTimelineReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/unified-execution-timeline",
			Synchronous: true,
		},
		TemporalModes: []string{"window", "bitemporal"},
		Parameters: []ReportParameter{
			{Name: "window_days", In: "query", ValueType: "integer", Description: "Timeline window in days to include."},
			{Name: "tenant_id", In: "query", ValueType: "string", Description: "Optional tenant identifier to scope one tenant."},
			{Name: "target_kind", In: "query", ValueType: "string", Description: "Optional ontology target kind to scope one workflow family."},
			{Name: "playbook_id", In: "query", ValueType: "string", Description: "Optional playbook identifier to scope playbook runs."},
			{Name: "evaluation_run_id", In: "query", ValueType: "string", Description: "Optional evaluation run identifier to scope one evaluation run."},
			{Name: "max_events", In: "query", ValueType: "integer", Description: "Maximum number of timeline events to return."},
		},
		Measures: []ReportMeasure{
			{ID: "timeline_event_count", Label: "Timeline Events", ValueType: "integer", Description: "Returned chronological events after scope and limit filters."},
			{ID: "timeline_evaluation_run_count", Label: "Evaluation Runs", ValueType: "integer", Description: "Evaluation runs represented in the returned timeline."},
			{ID: "timeline_playbook_run_count", Label: "Playbook Runs", ValueType: "integer", Description: "Playbook runs represented in the returned timeline."},
			{ID: "timeline_claim_count", Label: "Claims", ValueType: "integer", Description: "Claim events represented in the returned timeline."},
			{ID: "timeline_evidence_count", Label: "Evidence", ValueType: "integer", Description: "Direct evidence events represented in the returned timeline."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"timeline_event_count", "timeline_evaluation_run_count", "timeline_playbook_run_count", "timeline_claim_count", "timeline_evidence_count"}},
			{Key: "events", Title: "Timeline", Kind: "timeline_collection", Description: "Chronological workflow events across the selected evaluation and playbook scopes."},
		},
		Checks: []ReportCheck{
			{ID: "timeline_scope_isolation", Title: "Timeline Scope Isolation", Severity: "high", Description: "Tenant and workflow filters should isolate timeline output cleanly."},
			{ID: "timeline_support_coverage", Title: "Timeline Support Coverage", Severity: "medium", Description: "Workflow timelines should include directly supporting claims and evidence when available."},
			{ID: "timeline_stage_continuity", Title: "Timeline Stage Continuity", Severity: "medium", Description: "Missing stage identifiers should not drop workflow events from the timeline."},
		},
	},
	{
		ID:           "insights",
		Title:        "Decision Intelligence",
		Category:     "decision_support",
		Description:  "Prioritized decision-grade insights with evidence, coverage, confidence, and optional counterfactual context.",
		ResultSchema: "reports.IntelligenceReport",
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
			{Key: "insights", Title: "Insights", Kind: "ranked_findings", Description: "Prioritized insights with evidence and suggested actions.", Measures: []string{"risk_score", "coverage", "confidence"}, BenchmarkPackIDs: []string{"decision-intelligence.default"}},
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
		ResultSchema: "reports.GraphQualityReport",
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
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"maturity_score"}, BenchmarkPackIDs: []string{"graph-quality.default"}},
			{Key: "ontology", Title: "Ontology", Kind: "health_breakdown", Measures: []string{"coverage_percent", "conformance_percent"}},
			{Key: "identity", Title: "Identity", Kind: "health_breakdown", Measures: []string{"linkage_percent"}},
			{Key: "temporal", Title: "Temporal", Kind: "health_breakdown", Measures: []string{"metadata_completeness_percent"}},
			{Key: "writeback", Title: "Write-Back", Kind: "health_breakdown", Measures: []string{"closure_rate_percent"}},
			{Key: "domain_coverage", Title: "Domain Coverage", Kind: "distribution"},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", BenchmarkPackIDs: []string{"graph-quality.default"}},
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
		ID:           "ai-workloads",
		Title:        "AI Workload Inventory",
		Category:     "security_posture",
		Description:  "Inventory graph-detected AI workloads across cloud-managed services, self-hosted frameworks, vector stores, data exposure, and shadow AI signals.",
		ResultSchema: "reports.AIWorkloadInventoryReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/ai-workloads",
			Synchronous: true,
		},
		Parameters: []ReportParameter{
			{Name: "max_workloads", In: "query", ValueType: "integer", Description: "Maximum AI workloads to return (1-200)."},
			{Name: "min_risk_score", In: "query", ValueType: "integer", Description: "Minimum AI workload risk score to include (0-100)."},
			{Name: "include_shadow", In: "query", ValueType: "boolean", Description: "When false, filter self-hosted shadow AI workloads out of the returned inventory."},
		},
		Measures: []ReportMeasure{
			{ID: "workload_count", Label: "AI Workloads", ValueType: "integer", Description: "Total detected AI workloads before filtering."},
			{ID: "high_risk_workload_count", Label: "High-Risk AI Workloads", ValueType: "integer", Description: "Detected AI workloads with critical or high risk posture."},
			{ID: "shadow_ai_workload_count", Label: "Shadow AI", ValueType: "integer", Description: "Self-hosted AI workloads outside the cloud-managed AI service footprint."},
			{ID: "internet_exposed_workload_count", Label: "Internet-Exposed AI", ValueType: "integer", Description: "Detected AI workloads reachable from the internet."},
			{ID: "sensitive_data_workload_count", Label: "Sensitive Data Reach", ValueType: "integer", Description: "Detected AI workloads with graph-visible access into sensitive data stores."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"workload_count", "high_risk_workload_count", "shadow_ai_workload_count", "internet_exposed_workload_count", "sensitive_data_workload_count"}},
			{Key: "workloads", Title: "Inventory", Kind: "ranked_findings", Description: "Detected AI workloads sorted by graph-derived risk posture."},
			{Key: "data_exposures", Title: "Data Exposure", Kind: "breakdown_table", Description: "AI workloads with sensitive data reach, public exposure, or plaintext provider-key signals."},
			{Key: "shadow_ai_workloads", Title: "Shadow AI", Kind: "ranked_findings", Description: "Self-hosted AI workloads inferred from framework, runtime, vector-store, or credential indicators."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", Description: "Prioritized AI-SPM remediation guidance derived from graph posture."},
		},
		Checks: []ReportCheck{
			{ID: "internet_exposure", Title: "Internet Exposure", Severity: "high", Description: "AI-serving paths should not be exposed without strong ingress controls."},
			{ID: "plaintext_provider_keys", Title: "Provider Key Hygiene", Severity: "high", Description: "AI provider credentials should not appear directly on workload metadata."},
			{ID: "shadow_ai", Title: "Shadow AI Detection", Severity: "medium", Description: "Self-hosted AI indicators should be inventoried and owned."},
			{ID: "sensitive_data_scope", Title: "Sensitive Data Scope", Severity: "medium", Description: "AI workloads should be scoped away from unnecessary sensitive data stores."},
		},
	},
	{
		ID:           "metadata-quality",
		Title:        "Metadata Quality",
		Category:     "quality",
		Description:  "Metadata-profile coverage view over required keys, timestamp validity, enum normalization, and the highest-volume unprofiled kinds.",
		ResultSchema: "reports.GraphMetadataQualityReport",
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
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"required_key_coverage_percent", "timestamp_validity_percent", "enum_validity_percent", "profiled_kinds"}, BenchmarkPackIDs: []string{"metadata-quality.default"}},
			{Key: "kinds", Title: "Per-Kind Quality", Kind: "breakdown_table", Description: "Per-kind metadata completeness and validation errors."},
			{Key: "unprofiled_kinds", Title: "Unprofiled Kinds", Kind: "ranked_backlog", Description: "High-volume kinds missing metadata profiles."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", BenchmarkPackIDs: []string{"metadata-quality.default"}},
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
		ID:           "evaluation-temporal-analysis",
		Title:        "Evaluation Temporal Analysis",
		Category:     "knowledge",
		Description:  "Evaluation-run contradiction, supersession, and pre/post action world-state diff analysis over scoped claims and evidence timelines.",
		ResultSchema: "reports.EvaluationTemporalAnalysisReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/evaluation-temporal-analysis",
			Synchronous: true,
		},
		TemporalModes: []string{"bitemporal", "window"},
		Parameters: []ReportParameter{
			{Name: "evaluation_run_id", In: "query", ValueType: "string", Required: true, Description: "Evaluation run identifier to analyze."},
			{Name: "conversation_id", In: "query", ValueType: "string", Description: "Optional conversation identifier to scope one conversation inside the run."},
			{Name: "stage_id", In: "query", ValueType: "string", Description: "Optional stage identifier to scope one evaluation stage inside the selected conversation or run."},
			{Name: "timeline_limit", In: "query", ValueType: "integer", Description: "Maximum timeline entries to include per scoped claim."},
		},
		Measures: []ReportMeasure{
			{ID: "evaluation_claim_count", Label: "Scoped Claims", ValueType: "integer", Description: "Claims linked to the selected evaluation scope."},
			{ID: "evaluation_contradicted_claim_count", Label: "Contradicted Claims", ValueType: "integer", Description: "Scoped claims contradicted by later world-model facts."},
			{ID: "evaluation_superseded_claim_count", Label: "Superseded Claims", ValueType: "integer", Description: "Scoped claims later superseded by newer claims."},
			{ID: "evaluation_reversed_action_count", Label: "Reversed Actions", ValueType: "integer", Description: "Evaluation actions explicitly reversed or rolled back."},
			{ID: "evaluation_added_claim_count", Label: "Added Claims", ValueType: "integer", Description: "Claims added between the pre-action and post-action world-state slices."},
		},
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"evaluation_claim_count", "evaluation_contradicted_claim_count", "evaluation_superseded_claim_count", "evaluation_reversed_action_count", "evaluation_added_claim_count"}},
			{Key: "diff", Title: "World Diff", Kind: "knowledge_diff", Description: "Knowledge-layer changes between the pre-action and post-action world-state slices."},
			{Key: "conflicts", Title: "Conflicts", Kind: "contradiction_groups", Description: "Contradictions and supportability issues in the scoped claim set."},
			{Key: "claims", Title: "Claim Timelines", Kind: "timeline_collection", Description: "Scoped claim explanations and timelines linked to the evaluation run."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", Description: "Suggested remediation or adjudication steps for scoped eval contradictions."},
		},
		Checks: []ReportCheck{
			{ID: "evaluation_contradictions", Title: "Evaluation Contradictions", Severity: "high", Description: "Evaluation-linked claims should not be contradicted by later world facts."},
			{ID: "evaluation_supersessions", Title: "Evaluation Supersessions", Severity: "medium", Description: "Earlier evaluation claims being superseded indicates the agent model drifted over time."},
			{ID: "evaluation_reversals", Title: "Evaluation Reversals", Severity: "high", Description: "Agent-driven actions should not require later reversal."},
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
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"conflict_groups", "conflicting_claims", "unsupported_claims", "sourceless_claims", "stale_claims"}, BenchmarkPackIDs: []string{"claim-conflicts.default"}},
			{Key: "conflicts", Title: "Conflict Groups", Kind: "contradiction_groups", Description: "Subject/predicate contradiction groups with conflicting values, sources, and timestamps."},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", BenchmarkPackIDs: []string{"claim-conflicts.default"}},
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
		ID:           "entity-summary",
		Title:        "Entity Summary",
		Category:     "entity",
		Description:  "Report-level entity view composed from canonical identity, facet modules, posture claims, topology, and support coverage.",
		ResultSchema: "reports.EntitySummaryReport",
		Endpoint: ReportEndpoint{
			Method:          "GET",
			Path:            "/api/v1/platform/intelligence/entity-summary",
			Synchronous:     true,
			JobCapable:      true,
			RunMethod:       "POST",
			RunPathTemplate: "/api/v1/platform/intelligence/reports/entity-summary/runs",
		},
		TemporalModes: []string{"bitemporal"},
		Parameters: []ReportParameter{
			{Name: "entity_id", In: "query", ValueType: "string", Required: true, Description: "Entity to summarize."},
			{Name: "valid_at", In: "query", ValueType: "date-time", Description: "Fact-time slice for the entity summary."},
			{Name: "recorded_at", In: "query", ValueType: "date-time", Description: "System-time slice for the entity summary."},
			{Name: "max_posture_claims", In: "query", ValueType: "integer", Description: "Maximum posture claims to include inline."},
		},
		Measures: []ReportMeasure{
			{ID: "risk_score", Label: "Risk Score", ValueType: "number", Unit: "score", Description: "Normalized risk score derived from the entity risk level."},
			{ID: "facet_coverage_percent", Label: "Facet Coverage", ValueType: "number", Unit: "percent", Description: "Share of applicable built-in facets materialized on the entity."},
			{ID: "subresource_count", Label: "Subresources", ValueType: "integer", Description: "Promoted subresources attached to the entity for explanation and provenance."},
			{ID: "supported_claims", Label: "Supported Claims", ValueType: "integer", Description: "Active posture claims with evidence support."},
			{ID: "disputed_claims", Label: "Disputed Claims", ValueType: "integer", Description: "Active posture claims with contradictory support."},
			{ID: "evidence_count", Label: "Evidence", ValueType: "integer", Description: "Evidence artifacts attached to the entity support surface."},
		},
		Sections: []ReportSection{
			{Key: "overview", Title: "Overview", Kind: "entity_overview", Description: "Canonical identity and top-line coverage measures."},
			{Key: "topology", Title: "Topology", Kind: "entity_topology", Description: "Grouped relationships and immediate graph context."},
			{Key: "facets", Title: "Facets", Kind: "entity_facets", Description: "Typed facet modules derived from properties and claims."},
			{Key: "subresources", Title: "Subresources", Kind: "entity_subresources", Description: "Promoted subresources linked for durable explanation and provenance."},
			{Key: "posture", Title: "Posture", Kind: "entity_posture", Description: "Normalized posture/support claims attached to the entity."},
			{Key: "support", Title: "Support", Kind: "entity_support", Description: "Knowledge support coverage and conflict signals."},
		},
		Checks: []ReportCheck{
			{ID: "canonical_identity", Title: "Canonical Identity", Severity: "high", Description: "Entity summaries should expose canonical refs plus source-native external refs."},
			{ID: "facet_coverage", Title: "Facet Coverage", Severity: "medium", Description: "Applicable entity facets should materialize from the available source data."},
			{ID: "subresource_promotion", Title: "Subresource Promotion", Severity: "medium", Description: "Nested asset constructs that drive explanation or remediation should be promoted into durable subresources."},
			{ID: "posture_support", Title: "Posture Support", Severity: "high", Description: "Risk posture should be backed by evidence-linked claims rather than raw properties alone."},
		},
		ExtensionPoints: []ReportExtensionPoint{
			{Key: "facets.overlays", Scope: "facets.items[]", Description: "Attach tenant-specific facet overlays or remediation links."},
			{Key: "subresources.overlays", Scope: "subresources.items[]", Description: "Attach subresource-specific remediation actions, docs, or benchmark overlays."},
			{Key: "posture.annotations", Scope: "posture.claims[]", Description: "Attach adjudication, ownership, or workflow annotations to posture claims."},
		},
	},
	{
		ID:           "leverage",
		Title:        "Graph Leverage",
		Category:     "operating_model",
		Description:  "Combined operating view across quality, identity calibration, ingestion breadth, temporal freshness, predictive readiness, query readiness, and actuation closure.",
		ResultSchema: "reports.GraphLeverageReport",
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
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"leverage_score"}, BenchmarkPackIDs: []string{"graph-leverage.default"}},
			{Key: "quality", Title: "Quality", Kind: "embedded_report"},
			{Key: "identity", Title: "Identity", Kind: "embedded_report"},
			{Key: "ingestion", Title: "Ingestion", Kind: "coverage_breakdown", Measures: []string{"coverage_percent"}},
			{Key: "ontology", Title: "Ontology SLO", Kind: "timeseries_summary", Measures: []string{"canonical_kind_coverage_percent", "schema_valid_write_percent"}},
			{Key: "temporal", Title: "Temporal", Kind: "freshness_summary"},
			{Key: "closed_loop", Title: "Closed Loop", Kind: "health_breakdown", Measures: []string{"closure_rate_percent"}},
			{Key: "predictive", Title: "Predictive", Kind: "readiness_summary", Measures: []string{"readiness_score"}},
			{Key: "query", Title: "Query", Kind: "capability_summary"},
			{Key: "actuation", Title: "Actuation", Kind: "readiness_summary", Measures: []string{"actuation_coverage_percent"}},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list", BenchmarkPackIDs: []string{"graph-leverage.default"}},
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
		Description:  "Weekly slice combining outcome backtest, identity calibration status, ontology trend context, and a temporal changelog summary.",
		ResultSchema: "reports.WeeklyCalibrationReport",
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
			{ID: "change_count", Label: "Tracked Changes", ValueType: "integer", Description: "Number of graph changelog entries captured in the weekly window."},
		},
		Sections: []ReportSection{
			{Key: "risk_feedback", Title: "Risk Feedback", Kind: "backtest_summary", Measures: []string{"outcome_count", "rule_signal_count"}, BenchmarkPackIDs: []string{"weekly-calibration.default"}},
			{Key: "identity", Title: "Identity", Kind: "calibration_summary", Measures: []string{"precision_percent", "review_coverage_percent"}},
			{Key: "ontology", Title: "Ontology Trend", Kind: "timeseries_summary", Measures: []string{"canonical_kind_coverage_percent"}},
			{Key: "temporal", Title: "Temporal Changelog", Kind: "changelog_summary", Measures: []string{"change_count"}},
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
	{
		ID:           "key-person-risk",
		Title:        "Key Person Risk",
		Category:     "business_context",
		Description:  "Rank likely single-person failures by orphaned systems, customer exposure, ARR at risk, and recovery drag.",
		ResultSchema: "reports.KeyPersonRiskReport",
		Endpoint: ReportEndpoint{
			Method:      "GET",
			Path:        "/api/v1/platform/intelligence/key-person-risk",
			Synchronous: true,
		},
		TemporalModes: []string{"snapshot"},
		Parameters: []ReportParameter{
			{Name: "person_id", In: "query", ValueType: "string", Description: "Optional person identifier to focus the report on one departure scenario."},
			{Name: "limit", In: "query", ValueType: "integer", Description: "Maximum ranked people to include."},
		},
		Measures: []ReportMeasure{
			{ID: "score", Label: "Risk Score", ValueType: "number", Unit: "score", Description: "Composite single-person-failure score."},
			{ID: "affected_arr", Label: "Affected ARR", ValueType: "number", Unit: "currency", Description: "ARR tied to customers that would lose a direct owner."},
			{ID: "systems_bus_factor_0", Label: "Orphaned Systems", ValueType: "integer", Description: "Systems that would drop to zero active owners."},
			{ID: "customers_no_contact", Label: "Customers Without Contact", ValueType: "integer", Description: "Customers that would lose a direct human contact."},
		},
		Sections: []ReportSection{
			{Key: "items", Title: "Ranked People", Kind: "ranked_backlog", Measures: []string{"score", "affected_arr", "systems_bus_factor_0", "customers_no_contact"}},
		},
		Checks: []ReportCheck{
			{ID: "single_person_failure", Title: "Single Person Failure", Severity: "high", Description: "Critical systems and customer relationships should not hinge on one person."},
			{ID: "customer_exposure", Title: "Customer Exposure", Severity: "high", Description: "Person departures that strand customer ownership or ARR should be escalated."},
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
		cloned.Sections[i].BenchmarkPackIDs = append([]string(nil), definition.Sections[i].BenchmarkPackIDs...)
	}
	cloned.Checks = append([]ReportCheck(nil), definition.Checks...)
	cloned.ExtensionPoints = append([]ReportExtensionPoint(nil), definition.ExtensionPoints...)
	return cloned
}

func normalizeReportDefinition(definition ReportDefinition) ReportDefinition {
	if strings.TrimSpace(definition.Version) == "" {
		definition.Version = DefaultReportDefinitionVersion
	}
	if !definition.Endpoint.JobCapable {
		definition.Endpoint.JobCapable = true
	}
	if definition.Endpoint.RunMethod == "" {
		definition.Endpoint.RunMethod = "POST"
	}
	if definition.Endpoint.RunPathTemplate == "" {
		definition.Endpoint.RunPathTemplate = "/api/v1/platform/intelligence/reports/{id}/runs"
	}
	for i := range definition.Sections {
		if strings.TrimSpace(definition.Sections[i].EnvelopeKind) == "" {
			definition.Sections[i].EnvelopeKind = reportEnvelopeKindForSection(definition.Sections[i].Kind)
		}
		if envelope, ok := GetReportSectionEnvelopeDefinition(definition.Sections[i].EnvelopeKind); ok && strings.TrimSpace(definition.Sections[i].EnvelopeSchema) == "" {
			definition.Sections[i].EnvelopeSchema = envelope.SchemaName
		}
	}
	return definition
}
