package reports

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultLeverageRecentWindow = 24 * time.Hour
	defaultLeverageDecisionSLA  = 14 * 24 * time.Hour
)

var leverageExpectedSources = []string{
	"github",
	"slack",
	"jira",
	"ci",
	"calendar",
	"docs",
	"incident",
	"support",
	"sales",
	"crm",
}

// GraphLeverageReportOptions controls leverage report generation.
type GraphLeverageReportOptions struct {
	Now                      time.Time
	FreshnessStaleAfter      time.Duration
	SchemaHistoryLimit       int
	SchemaSinceVersion       int64
	IdentitySuggestThreshold float64
	IdentityQueueLimit       int
	RecentWindow             time.Duration
	DecisionStaleAfter       time.Duration
}

// GraphLeverageSummary contains top-line graph leverage KPIs.
type GraphLeverageSummary struct {
	LeverageScore float64 `json:"leverage_score"`
	Grade         string  `json:"grade"`
	CriticalGaps  int     `json:"critical_gaps"`
	Healthy       bool    `json:"healthy"`
}

// GraphSourceCoverage summarizes ingestion footprint for one source system.
type GraphSourceCoverage struct {
	SourceSystem string `json:"source_system"`
	NodeCount    int    `json:"node_count"`
	EdgeCount    int    `json:"edge_count"`
	Total        int    `json:"total"`
}

// GraphIngestionCoverage summarizes source breadth and gaps.
type GraphIngestionCoverage struct {
	ExpectedSources []string              `json:"expected_sources"`
	ObservedSources int                   `json:"observed_sources"`
	CoveragePercent float64               `json:"coverage_percent"`
	MissingSources  []string              `json:"missing_sources,omitempty"`
	SourceCounts    []GraphSourceCoverage `json:"source_counts,omitempty"`
}

// GraphTemporalLeverage summarizes recency and time-window activity quality.
type GraphTemporalLeverage struct {
	Freshness               FreshnessMetrics `json:"freshness"`
	RecentWindowHours       int              `json:"recent_window_hours"`
	RecentNodes             int              `json:"recent_nodes"`
	RecentEdges             int              `json:"recent_edges"`
	ActivityCoveragePercent float64          `json:"activity_coverage_percent"`
}

// GraphOntologySLOPoint captures one daily ontology quality sample.
type GraphOntologySLOPoint struct {
	Date                         string  `json:"date"`
	CanonicalKindCoveragePercent float64 `json:"canonical_kind_coverage_percent"`
	FallbackActivityPercent      float64 `json:"fallback_activity_percent"`
	SchemaValidWritePercent      float64 `json:"schema_valid_write_percent"`
	Samples                      int     `json:"samples"`
}

// GraphOntologySLO summarizes ontology quality SLOs and short-term trend.
type GraphOntologySLO struct {
	CanonicalKindCoveragePercent float64                 `json:"canonical_kind_coverage_percent"`
	FallbackActivityPercent      float64                 `json:"fallback_activity_percent"`
	SchemaValidWritePercent      float64                 `json:"schema_valid_write_percent"`
	Trend                        []GraphOntologySLOPoint `json:"trend,omitempty"`
}

// GraphClosedLoopLeverage summarizes decision-to-outcome closure maturity.
type GraphClosedLoopLeverage struct {
	DecisionNodes                int     `json:"decision_nodes"`
	OutcomeNodes                 int     `json:"outcome_nodes"`
	DecisionsWithOutcomes        int     `json:"decisions_with_outcomes"`
	ClosureRatePercent           float64 `json:"closure_rate_percent"`
	StaleDecisionsWithoutOutcome int     `json:"stale_decisions_without_outcome"`
}

// GraphPredictiveReadiness summarizes data readiness for prediction and calibration.
type GraphPredictiveReadiness struct {
	LabeledOutcomes        int     `json:"labeled_outcomes"`
	EvidenceNodes          int     `json:"evidence_nodes"`
	FeatureCoveragePercent float64 `json:"feature_coverage_percent"`
	ReadinessScore         float64 `json:"readiness_score"`
}

// GraphQueryReadiness summarizes analyst query interface readiness.
type GraphQueryReadiness struct {
	TemplateCount   int                  `json:"template_count"`
	TemporalCapable bool                 `json:"temporal_capable"`
	Templates       []GraphQueryTemplate `json:"templates,omitempty"`
}

// GraphActuationReadiness summarizes actionability and write-back maturity.
type GraphActuationReadiness struct {
	ActionNodes              int     `json:"action_nodes"`
	AutomatedActions         int     `json:"automated_actions"`
	ActionsWithTargets       int     `json:"actions_with_targets"`
	ActionsLinkedToDecisions int     `json:"actions_linked_to_decisions"`
	ActionsWithOutcomes      int     `json:"actions_with_outcomes"`
	OutcomeCompletionRate    float64 `json:"outcome_completion_rate_percent"`
	MedianOutcomeLatencyHrs  float64 `json:"median_outcome_latency_hours"`
	StaleActionsNoOutcome    int     `json:"stale_actions_without_outcome"`
	ActuationCoveragePercent float64 `json:"actuation_coverage_percent"`
}

// GraphLeverageRecommendation describes one prioritized leverage improvement.
type GraphLeverageRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// GraphLeverageReport is a unified report for graph leverage and intelligence depth.
type GraphLeverageReport struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	Summary         GraphLeverageSummary          `json:"summary"`
	Quality         GraphQualityReport            `json:"quality"`
	Identity        IdentityCalibrationReport     `json:"identity"`
	Ingestion       GraphIngestionCoverage        `json:"ingestion"`
	Ontology        GraphOntologySLO              `json:"ontology"`
	Temporal        GraphTemporalLeverage         `json:"temporal"`
	ClosedLoop      GraphClosedLoopLeverage       `json:"closed_loop"`
	Predictive      GraphPredictiveReadiness      `json:"predictive"`
	Query           GraphQueryReadiness           `json:"query"`
	Actuation       GraphActuationReadiness       `json:"actuation"`
	Recommendations []GraphLeverageRecommendation `json:"recommendations,omitempty"`
}

// BuildGraphLeverageReport builds one deep operational report for graph leverage.
func BuildGraphLeverageReport(g *Graph, opts GraphLeverageReportOptions) GraphLeverageReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	report := GraphLeverageReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []GraphLeverageRecommendation{{
			Priority:        "high",
			Category:        "graph_unavailable",
			Title:           "Graph platform is not initialized",
			Detail:          "Leverage metrics are unavailable because the graph is nil.",
			SuggestedAction: "Initialize and ingest graph data before requesting leverage reports.",
		}}
		report.Summary.CriticalGaps = 1
		report.Summary.Healthy = false
		return report
	}

	staleAfter := opts.FreshnessStaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
	}
	recentWindow := opts.RecentWindow
	if recentWindow <= 0 {
		recentWindow = defaultLeverageRecentWindow
	}
	decisionSLA := opts.DecisionStaleAfter
	if decisionSLA <= 0 {
		decisionSLA = defaultLeverageDecisionSLA
	}

	report.Quality = BuildGraphQualityReport(g, GraphQualityReportOptions{
		Now:                 now,
		FreshnessStaleAfter: staleAfter,
		SchemaHistoryLimit:  opts.SchemaHistoryLimit,
		SchemaSinceVersion:  opts.SchemaSinceVersion,
	})
	report.Identity = BuildIdentityCalibrationReport(g, IdentityCalibrationOptions{
		Now:              now,
		SuggestThreshold: opts.IdentitySuggestThreshold,
		QueueLimit:       opts.IdentityQueueLimit,
		IncludeQueue:     true,
	})
	report.Ingestion = buildGraphIngestionCoverage(g)
	report.Ontology = BuildGraphOntologySLO(g, now, 7)
	report.Temporal = buildGraphTemporalLeverage(g, now, staleAfter, recentWindow)
	report.ClosedLoop = buildGraphClosedLoopLeverage(g, now, decisionSLA)
	report.Predictive = buildGraphPredictiveReadiness(g)
	report.Query = GraphQueryReadiness{
		TemplateCount:   len(DefaultGraphQueryTemplates()),
		TemporalCapable: true,
		Templates:       DefaultGraphQueryTemplates(),
	}
	report.Actuation = buildGraphActuationReadiness(g, now, decisionSLA)
	report.Recommendations = buildGraphLeverageRecommendations(report)

	identityScore := report.Identity.PrecisionPercent / 100
	if report.Identity.AcceptedDecisions+report.Identity.RejectedDecisions == 0 {
		identityScore = report.Identity.LinkagePercent / 100
	}
	queryScore := 0.0
	if report.Query.TemplateCount > 0 {
		queryScore = math.Min(1, float64(report.Query.TemplateCount)/8)
	}
	// Weights prioritize foundational graph trust first (quality + identity + ingestion +
	// ontology conformance + freshness), then operational closure and actionability dimensions.
	report.Summary.LeverageScore = 100 * (0.20*(report.Quality.Summary.MaturityScore/100) +
		0.13*clampUnit(identityScore) +
		0.12*clampUnit(report.Ingestion.CoveragePercent/100) +
		0.12*clampUnit(report.Ontology.CanonicalKindCoveragePercent/100) +
		0.11*clampUnit(report.Ontology.SchemaValidWritePercent/100) +
		0.11*clampUnit(report.Temporal.Freshness.FreshnessPercent/100) +
		0.09*clampUnit(report.ClosedLoop.ClosureRatePercent/100) +
		0.06*clampUnit(report.Predictive.ReadinessScore/100) +
		0.03*clampUnit(queryScore) +
		0.02*clampUnit(report.Actuation.ActuationCoveragePercent/100) +
		0.01*clampUnit(report.Actuation.OutcomeCompletionRate/100))
	report.Summary.LeverageScore = math.Round(report.Summary.LeverageScore*10) / 10
	report.Summary.Grade = graphQualityGrade(report.Summary.LeverageScore)
	report.Summary.CriticalGaps = countLeveragePriority(report.Recommendations, "high")
	report.Summary.Healthy = report.Summary.CriticalGaps == 0 && report.Summary.LeverageScore >= 80
	return report
}

func buildGraphIngestionCoverage(g *Graph) GraphIngestionCoverage {
	coverage := GraphIngestionCoverage{
		ExpectedSources: append([]string(nil), leverageExpectedSources...),
	}
	if g == nil {
		return coverage
	}

	type counts struct {
		nodes int
		edges int
	}
	sourceCounts := make(map[string]*counts)

	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		source := strings.ToLower(graphNodePropertyString(node, "source_system"))
		if source == "" {
			source = strings.ToLower(strings.TrimSpace(node.Provider))
		}
		if source == "" {
			continue
		}
		entry := sourceCounts[source]
		if entry == nil {
			entry = &counts{}
			sourceCounts[source] = entry
		}
		entry.nodes++
	}

	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			source := strings.ToLower(strings.TrimSpace(identityAnyToString(edge.Properties["source_system"])))
			if source == "" {
				continue
			}
			entry := sourceCounts[source]
			if entry == nil {
				entry = &counts{}
				sourceCounts[source] = entry
			}
			entry.edges++
		}
	}

	present := make(map[string]struct{}, len(sourceCounts))
	for source, sourceCount := range sourceCounts {
		total := sourceCount.nodes + sourceCount.edges
		if total <= 0 {
			continue
		}
		present[source] = struct{}{}
		coverage.SourceCounts = append(coverage.SourceCounts, GraphSourceCoverage{
			SourceSystem: source,
			NodeCount:    sourceCount.nodes,
			EdgeCount:    sourceCount.edges,
			Total:        total,
		})
	}
	sort.Slice(coverage.SourceCounts, func(i, j int) bool {
		if coverage.SourceCounts[i].Total == coverage.SourceCounts[j].Total {
			return coverage.SourceCounts[i].SourceSystem < coverage.SourceCounts[j].SourceSystem
		}
		return coverage.SourceCounts[i].Total > coverage.SourceCounts[j].Total
	})

	for _, expected := range coverage.ExpectedSources {
		if _, ok := present[expected]; ok {
			coverage.ObservedSources++
			continue
		}
		coverage.MissingSources = append(coverage.MissingSources, expected)
	}
	if len(coverage.ExpectedSources) > 0 {
		coverage.CoveragePercent = (float64(coverage.ObservedSources) / float64(len(coverage.ExpectedSources))) * 100
	}
	coverage.CoveragePercent = math.Round(coverage.CoveragePercent*10) / 10
	return coverage
}

// BuildGraphOntologySLO returns ontology quality SLO metrics and short trend.
func BuildGraphOntologySLO(g *Graph, now time.Time, trendDays int) GraphOntologySLO {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if trendDays <= 0 {
		trendDays = 7
	}
	return buildGraphOntologySLO(g, now, trendDays)
}

func buildGraphOntologySLO(g *Graph, now time.Time, trendDays int) GraphOntologySLO {
	slo := GraphOntologySLO{}
	if g == nil {
		return slo
	}

	nodes := g.GetAllNodes()
	activityNodes := 0
	canonicalNodes := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		source := strings.ToLower(graphNodePropertyString(node, "source_system"))
		if source == "" {
			source = strings.ToLower(strings.TrimSpace(node.Provider))
		}
		if !containsString(leverageExpectedSources, source) {
			continue
		}
		if node.Kind == NodeKindActivity {
			activityNodes++
			continue
		}
		canonicalNodes++
	}

	totalOperational := activityNodes + canonicalNodes
	if totalOperational > 0 {
		slo.CanonicalKindCoveragePercent = (float64(canonicalNodes) / float64(totalOperational)) * 100
		slo.FallbackActivityPercent = (float64(activityNodes) / float64(totalOperational)) * 100
	} else {
		slo.CanonicalKindCoveragePercent = 100
		slo.FallbackActivityPercent = 0
	}
	slo.CanonicalKindCoveragePercent = math.Round(slo.CanonicalKindCoveragePercent*10) / 10
	slo.FallbackActivityPercent = math.Round(slo.FallbackActivityPercent*10) / 10

	totalEntities := len(nodes)
	invalidEntities := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if len(ValidateNodeAgainstSchema(node)) > 0 {
			invalidEntities++
		}
	}
	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			totalEntities++
			source, _ := g.GetNode(edge.Source)
			target, _ := g.GetNode(edge.Target)
			if len(ValidateEdgeAgainstSchema(edge, source, target)) > 0 {
				invalidEntities++
			}
		}
	}
	if totalEntities > 0 {
		slo.SchemaValidWritePercent = (float64(totalEntities-invalidEntities) / float64(totalEntities)) * 100
	} else {
		slo.SchemaValidWritePercent = 100
	}
	slo.SchemaValidWritePercent = math.Round(slo.SchemaValidWritePercent*10) / 10

	if trendDays <= 0 {
		return slo
	}

	dayStart := now.UTC().Truncate(24 * time.Hour)
	for i := trendDays - 1; i >= 0; i-- {
		windowStart := dayStart.Add(-time.Duration(i) * 24 * time.Hour)
		windowEnd := windowStart.Add(24 * time.Hour)

		point := GraphOntologySLOPoint{
			Date: windowStart.Format("2006-01-02"),
		}

		dayActivity := 0
		dayCanonical := 0
		daySamples := 0
		dayInvalid := 0
		for _, node := range nodes {
			if node == nil {
				continue
			}
			observedAt, ok := graphObservedAt(node)
			if !ok || observedAt.Before(windowStart) || !observedAt.Before(windowEnd) {
				continue
			}
			source := strings.ToLower(graphNodePropertyString(node, "source_system"))
			if source == "" {
				source = strings.ToLower(strings.TrimSpace(node.Provider))
			}
			if !containsString(leverageExpectedSources, source) {
				continue
			}
			daySamples++
			if node.Kind == NodeKindActivity {
				dayActivity++
			} else {
				dayCanonical++
			}
			if len(ValidateNodeAgainstSchema(node)) > 0 {
				dayInvalid++
			}
		}

		for _, edges := range g.GetAllEdges() {
			for _, edge := range edges {
				if edge == nil {
					continue
				}
				observedAt, ok := temporalPropertyTime(edge.Properties, "observed_at")
				if !ok || observedAt.Before(windowStart) || !observedAt.Before(windowEnd) {
					continue
				}
				daySamples++
				source, _ := g.GetNode(edge.Source)
				target, _ := g.GetNode(edge.Target)
				if len(ValidateEdgeAgainstSchema(edge, source, target)) > 0 {
					dayInvalid++
				}
			}
		}

		if total := dayActivity + dayCanonical; total > 0 {
			point.CanonicalKindCoveragePercent = (float64(dayCanonical) / float64(total)) * 100
			point.FallbackActivityPercent = (float64(dayActivity) / float64(total)) * 100
		} else {
			point.CanonicalKindCoveragePercent = 100
			point.FallbackActivityPercent = 0
		}
		if daySamples > 0 {
			point.SchemaValidWritePercent = (float64(daySamples-dayInvalid) / float64(daySamples)) * 100
		} else {
			point.SchemaValidWritePercent = 100
		}
		point.CanonicalKindCoveragePercent = math.Round(point.CanonicalKindCoveragePercent*10) / 10
		point.FallbackActivityPercent = math.Round(point.FallbackActivityPercent*10) / 10
		point.SchemaValidWritePercent = math.Round(point.SchemaValidWritePercent*10) / 10
		point.Samples = daySamples
		slo.Trend = append(slo.Trend, point)
	}

	return slo
}

func buildGraphTemporalLeverage(g *Graph, now time.Time, staleAfter, recentWindow time.Duration) GraphTemporalLeverage {
	leverage := GraphTemporalLeverage{
		RecentWindowHours: int(recentWindow.Hours()),
	}
	if g == nil {
		return leverage
	}
	leverage.Freshness = g.Freshness(now, staleAfter)
	cutoff := now.Add(-recentWindow)
	nodes := g.GetAllNodes()
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if observedAt, ok := graphObservedAt(node); ok && !observedAt.Before(cutoff) {
			leverage.RecentNodes++
		}
	}
	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			if observedAt, ok := temporalPropertyTime(edge.Properties, "observed_at"); ok && !observedAt.Before(cutoff) {
				leverage.RecentEdges++
			}
		}
	}
	if len(nodes) > 0 {
		leverage.ActivityCoveragePercent = (float64(leverage.RecentNodes) / float64(len(nodes))) * 100
	}
	leverage.ActivityCoveragePercent = math.Round(leverage.ActivityCoveragePercent*10) / 10
	return leverage
}

func buildGraphClosedLoopLeverage(g *Graph, now time.Time, decisionSLA time.Duration) GraphClosedLoopLeverage {
	out := GraphClosedLoopLeverage{}
	if g == nil {
		return out
	}
	decisionNodes := g.GetNodesByKind(NodeKindDecision)
	out.DecisionNodes = len(decisionNodes)
	out.OutcomeNodes = len(g.GetNodesByKind(NodeKindOutcome))

	decisionsWithOutcomes := make(map[string]struct{})
	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		for _, edge := range g.GetOutEdges(outcome.ID) {
			if edge == nil || edge.Kind != EdgeKindEvaluates {
				continue
			}
			if target, ok := g.GetNode(edge.Target); ok && target != nil && target.Kind == NodeKindDecision {
				decisionsWithOutcomes[target.ID] = struct{}{}
			}
		}
	}
	out.DecisionsWithOutcomes = len(decisionsWithOutcomes)
	if out.DecisionNodes > 0 {
		out.ClosureRatePercent = (float64(out.DecisionsWithOutcomes) / float64(out.DecisionNodes)) * 100
	} else {
		out.ClosureRatePercent = 100
	}
	out.ClosureRatePercent = math.Round(out.ClosureRatePercent*10) / 10

	staleCutoff := now.Add(-decisionSLA)
	for _, decision := range decisionNodes {
		if decision == nil {
			continue
		}
		if _, ok := decisionsWithOutcomes[decision.ID]; ok {
			continue
		}
		observedAt, ok := graphObservedAt(decision)
		if !ok {
			if ts, ok := temporalPropertyTime(decision.Properties, "valid_from"); ok {
				observedAt = ts
			} else {
				observedAt = decision.CreatedAt
			}
		}
		if observedAt.IsZero() || !observedAt.Before(staleCutoff) {
			continue
		}
		out.StaleDecisionsWithoutOutcome++
	}
	return out
}

func buildGraphPredictiveReadiness(g *Graph) GraphPredictiveReadiness {
	out := GraphPredictiveReadiness{}
	if g == nil {
		return out
	}
	out.EvidenceNodes = len(g.GetNodesByKind(NodeKindEvidence))
	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		if strings.TrimSpace(identityAnyToString(outcome.Properties["verdict"])) != "" {
			out.LabeledOutcomes++
		}
	}

	nodes := g.GetAllNodes()
	featureReady := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		hasObserved := false
		if _, ok := graphObservedAt(node); ok {
			hasObserved = true
		}
		hasSource := graphNodePropertyString(node, "source_system") != "" || strings.TrimSpace(node.Provider) != ""
		if hasObserved && hasSource {
			featureReady++
		}
	}
	if len(nodes) > 0 {
		out.FeatureCoveragePercent = (float64(featureReady) / float64(len(nodes))) * 100
	}

	labeledScore := math.Min(1, float64(out.LabeledOutcomes)/50)
	evidenceScore := math.Min(1, float64(out.EvidenceNodes)/200)
	featureScore := clampUnit(out.FeatureCoveragePercent / 100)
	out.ReadinessScore = 100 * (0.45*labeledScore + 0.25*evidenceScore + 0.30*featureScore)
	out.FeatureCoveragePercent = math.Round(out.FeatureCoveragePercent*10) / 10
	out.ReadinessScore = math.Round(out.ReadinessScore*10) / 10
	return out
}

func buildGraphActuationReadiness(g *Graph, now time.Time, outcomeSLA time.Duration) GraphActuationReadiness {
	out := GraphActuationReadiness{}
	if g == nil {
		return out
	}
	if outcomeSLA <= 0 {
		outcomeSLA = defaultLeverageDecisionSLA
	}
	actions := g.GetNodesByKind(NodeKindAction)
	out.ActionNodes = len(actions)

	decisionOutcomeAt := make(map[string]time.Time)
	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		outcomeObserved, ok := graphObservedAt(outcome)
		if !ok {
			outcomeObserved = outcome.UpdatedAt
		}
		if outcomeObserved.IsZero() {
			continue
		}
		for _, edge := range g.GetOutEdges(outcome.ID) {
			if edge == nil || edge.Kind != EdgeKindEvaluates {
				continue
			}
			decisionID := edge.Target
			if decisionID == "" {
				continue
			}
			existing, ok := decisionOutcomeAt[decisionID]
			if !ok || outcomeObserved.Before(existing) {
				decisionOutcomeAt[decisionID] = outcomeObserved
			}
		}
	}

	latenciesHours := make([]float64, 0, len(actions))
	staleCutoff := now.Add(-outcomeSLA)
	for _, action := range actions {
		if action == nil {
			continue
		}
		if auto, ok := action.Properties["auto_generated"].(bool); ok && auto {
			out.AutomatedActions++
		}
		hasTarget := false
		for _, edge := range g.GetOutEdges(action.ID) {
			if edge != nil && edge.Kind == EdgeKindTargets {
				hasTarget = true
				break
			}
		}
		if hasTarget {
			out.ActionsWithTargets++
		}
		hasDecision := false
		for _, edge := range g.GetInEdges(action.ID) {
			if edge != nil && edge.Kind == EdgeKindExecutedBy {
				hasDecision = true
				break
			}
		}
		if hasDecision {
			out.ActionsLinkedToDecisions++
		}

		actionObserved, ok := graphObservedAt(action)
		if !ok {
			actionObserved = action.UpdatedAt
		}

		linkedDecisionIDs := make([]string, 0, 2)
		for _, edge := range g.GetInEdges(action.ID) {
			if edge == nil || edge.Kind != EdgeKindExecutedBy {
				continue
			}
			linkedDecisionIDs = append(linkedDecisionIDs, edge.Source)
		}

		earliestOutcome := time.Time{}
		for _, decisionID := range linkedDecisionIDs {
			outcomeAt, ok := decisionOutcomeAt[decisionID]
			if !ok || outcomeAt.IsZero() {
				continue
			}
			if earliestOutcome.IsZero() || outcomeAt.Before(earliestOutcome) {
				earliestOutcome = outcomeAt
			}
		}
		if !earliestOutcome.IsZero() {
			out.ActionsWithOutcomes++
			if !actionObserved.IsZero() && !earliestOutcome.Before(actionObserved) {
				latenciesHours = append(latenciesHours, earliestOutcome.Sub(actionObserved).Hours())
			}
			continue
		}
		if !actionObserved.IsZero() && actionObserved.Before(staleCutoff) {
			out.StaleActionsNoOutcome++
		}
	}
	if out.ActionNodes > 0 {
		out.OutcomeCompletionRate = (float64(out.ActionsWithOutcomes) / float64(out.ActionNodes)) * 100
	} else {
		out.OutcomeCompletionRate = 100
	}
	out.OutcomeCompletionRate = math.Round(out.OutcomeCompletionRate*10) / 10
	out.MedianOutcomeLatencyHrs = math.Round(medianFloat64(latenciesHours)*10) / 10

	decisions := g.GetNodesByKind(NodeKindDecision)
	if len(decisions) > 0 {
		decisionWithActions := make(map[string]struct{})
		for _, decision := range decisions {
			if decision == nil {
				continue
			}
			for _, edge := range g.GetOutEdges(decision.ID) {
				if edge == nil || edge.Kind != EdgeKindExecutedBy {
					continue
				}
				decisionWithActions[decision.ID] = struct{}{}
			}
		}
		out.ActuationCoveragePercent = (float64(len(decisionWithActions)) / float64(len(decisions))) * 100
	} else {
		out.ActuationCoveragePercent = 100
	}
	out.ActuationCoveragePercent = math.Round(out.ActuationCoveragePercent*10) / 10
	return out
}

func buildGraphLeverageRecommendations(report GraphLeverageReport) []GraphLeverageRecommendation {
	recommendations := make([]GraphLeverageRecommendation, 0, 8)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, GraphLeverageRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if report.Identity.BacklogAliases > 0 && report.Identity.ReviewCoveragePercent < 70 {
		priority := "medium"
		if report.Identity.BacklogAliases > 25 {
			priority = "high"
		}
		add(priority, "identity_review", "Drain identity review backlog", "Alias backlog is limiting canonical identity trust and downstream recommendations.", "Prioritize reviewer queue triage and record accepted/rejected outcomes continuously.")
	}
	if report.Ingestion.CoveragePercent < 70 {
		add("high", "ingestion_breadth", "Expand event ingestion breadth", "Critical source coverage is below target, leaving significant context off-graph.", "Add declarative mappings for missing systems and enforce source onboarding SLOs.")
	}
	if report.Ontology.FallbackActivityPercent > 10 {
		priority := "medium"
		if report.Ontology.FallbackActivityPercent > 25 {
			priority = "high"
		}
		add(priority, "ontology_fallback", "Reduce generic activity fallback", "A high share of event nodes still uses generic activity kind, reducing semantic query precision.", "Route known event types to canonical ontology kinds and reserve activity for unstructured fallback only.")
	}
	if report.Ontology.SchemaValidWritePercent < 98 {
		priority := "medium"
		if report.Ontology.SchemaValidWritePercent < 90 {
			priority = "high"
		}
		add(priority, "ontology_conformance", "Increase schema-valid write rate", "Schema-invalid writes reduce confidence in graph-derived recommendations and automation.", "Enable strict ingest validation, dead-letter invalid writes, and close top validation issue classes.")
	}
	if report.Temporal.Freshness.FreshnessPercent < 80 {
		add("medium", "temporal_freshness", "Improve real-time graph freshness", "Stale graph data will degrade insight confidence and incident-time accuracy.", "Reduce sync lag for high-churn domains and enforce observed_at on all writes.")
	}
	if report.ClosedLoop.StaleDecisionsWithoutOutcome > 0 {
		add("medium", "closed_loop", "Close stale decisions with outcomes", "Decisions without outcomes prevent calibration and impact measurement.", "Backfill outcome nodes for stale decisions and enforce outcome write-back in workflows.")
	}
	if report.Predictive.ReadinessScore < 50 {
		add("medium", "predictive_readiness", "Increase labeled outcome volume", "Predictive readiness is low due sparse labels or weak feature completeness.", "Capture more verdict-bearing outcomes and ensure source + temporal metadata completeness.")
	}
	if report.Actuation.ActuationCoveragePercent < 50 {
		add("medium", "actuation", "Increase recommendation actuation coverage", "Too few decisions are linked to executable actions.", "Create action nodes for accepted recommendations and track execution state.")
	}
	if report.Actuation.OutcomeCompletionRate < 60 {
		priority := "medium"
		if report.Actuation.OutcomeCompletionRate < 35 || report.Actuation.StaleActionsNoOutcome > 0 {
			priority = "high"
		}
		add(priority, "action_outcomes", "Close action-to-outcome loop", "Many action nodes do not have linked outcomes, limiting operational feedback quality.", "Write outcomes for completed actions and enforce stale-action follow-up SLAs.")
	}
	if len(recommendations) == 0 {
		add("low", "steady_state", "Maintain leverage baseline", "Identity, ingestion, temporal, and closed-loop leverage metrics are healthy.", "Continue enforcing quality and leverage guardrails in CI and write-back flows.")
	}

	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Priority == recommendations[j].Priority {
			if recommendations[i].Category == recommendations[j].Category {
				return recommendations[i].Title < recommendations[j].Title
			}
			return recommendations[i].Category < recommendations[j].Category
		}
		return graphQualityPriorityRank(recommendations[i].Priority) < graphQualityPriorityRank(recommendations[j].Priority)
	})
	return recommendations
}

func countLeveragePriority(recommendations []GraphLeverageRecommendation, priority string) int {
	priority = strings.ToLower(strings.TrimSpace(priority))
	count := 0
	for _, recommendation := range recommendations {
		if strings.ToLower(strings.TrimSpace(recommendation.Priority)) == priority {
			count++
		}
	}
	return count
}

func medianFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}
