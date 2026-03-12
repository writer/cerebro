package graph

import (
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	defaultIntelligenceWindow      = 90 * 24 * time.Hour
	defaultIntelligenceMaxInsights = 8
)

// IntelligenceReportOptions controls graph intelligence report generation.
type IntelligenceReportOptions struct {
	EntityID              string
	OutcomeWindow         time.Duration
	FreshnessStaleAfter   time.Duration
	SchemaHistoryLimit    int
	SchemaSinceVersion    int64
	MaxInsights           int
	IncludeCounterfactual bool
	TemporalDiff          *GraphDiff
}

// IntelligenceEvidence captures supporting evidence for one insight.
type IntelligenceEvidence struct {
	Kind   string   `json:"kind"`
	ID     string   `json:"id,omitempty"`
	Title  string   `json:"title,omitempty"`
	Detail string   `json:"detail,omitempty"`
	Path   []string `json:"path,omitempty"`
	Value  any      `json:"value,omitempty"`
}

// InsightCounterfactual captures one precomputed what-if scenario.
type InsightCounterfactual struct {
	Name                           string     `json:"name"`
	Summary                        string     `json:"summary"`
	Delta                          GraphDelta `json:"delta"`
	EstimatedRiskScoreDelta        float64    `json:"estimated_risk_score_delta"`
	EstimatedBlockedAttackPaths    int        `json:"estimated_blocked_attack_paths,omitempty"`
	EstimatedRemovedToxicCombos    int        `json:"estimated_removed_toxic_combos,omitempty"`
	EstimatedCreatedAttackPaths    int        `json:"estimated_created_attack_paths,omitempty"`
	EstimatedIntroducedToxicCombos int        `json:"estimated_introduced_toxic_combos,omitempty"`
}

// DecisionInsight is a prioritized, decision-oriented insight object.
type DecisionInsight struct {
	ID               string                 `json:"id"`
	Type             string                 `json:"type"`
	Priority         int                    `json:"priority"`
	Severity         Severity               `json:"severity"`
	Title            string                 `json:"title"`
	Summary          string                 `json:"summary"`
	Confidence       float64                `json:"confidence"`
	Coverage         float64                `json:"coverage"`
	Evidence         []IntelligenceEvidence `json:"evidence,omitempty"`
	SuggestedActions []string               `json:"suggested_actions,omitempty"`
	Counterfactual   *InsightCounterfactual `json:"counterfactual,omitempty"`
}

// IntelligenceReport is the unified decision-grade intelligence payload.
type IntelligenceReport struct {
	GeneratedAt     time.Time             `json:"generated_at"`
	Scope           map[string]any        `json:"scope,omitempty"`
	RiskScore       float64               `json:"risk_score"`
	RiskLevel       RiskLevel             `json:"risk_level"`
	Coverage        float64               `json:"coverage"`
	Confidence      float64               `json:"confidence"`
	Freshness       FreshnessMetrics      `json:"freshness"`
	SchemaHealth    SchemaHealthReport    `json:"schema_health"`
	OutcomeFeedback OutcomeFeedbackReport `json:"outcome_feedback"`
	Insights        []DecisionInsight     `json:"insights,omitempty"`
}

// BuildIntelligenceReport composes risk, ontology, outcome, and drift signals.
func BuildIntelligenceReport(g *Graph, engine *RiskEngine, opts IntelligenceReportOptions) IntelligenceReport {
	report := IntelligenceReport{
		GeneratedAt: time.Now().UTC(),
		Scope:       map[string]any{},
	}
	if g == nil {
		return report
	}

	entityID := strings.TrimSpace(opts.EntityID)
	if entityID != "" {
		report.Scope["entity_id"] = entityID
	}

	historyLimit := opts.SchemaHistoryLimit
	if historyLimit <= 0 {
		historyLimit = 20
	}

	window := opts.OutcomeWindow
	if window <= 0 {
		window = defaultIntelligenceWindow
	}
	report.Scope["outcome_window_days"] = int(window.Hours() / 24)

	maxInsights := opts.MaxInsights
	if maxInsights <= 0 {
		maxInsights = defaultIntelligenceMaxInsights
	}

	report.SchemaHealth = AnalyzeSchemaHealth(g, historyLimit, opts.SchemaSinceVersion)
	report.Coverage = clampUnit((report.SchemaHealth.NodeKindCoveragePercent + report.SchemaHealth.EdgeKindCoveragePercent) / 200)
	staleAfter := opts.FreshnessStaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
	}
	report.Freshness = g.Freshness(report.GeneratedAt, staleAfter)
	report.Scope["freshness_stale_after_hours"] = int(staleAfter.Hours())

	if engine == nil {
		engine = NewRiskEngine(g)
	}

	posture := engine.Analyze()
	if posture != nil {
		report.RiskScore = posture.RiskScore
		report.RiskLevel = posture.RiskLevel
	}

	report.OutcomeFeedback = engine.OutcomeFeedback(window, "")
	report.Confidence = intelligenceBaseConfidence(report.SchemaHealth, report.OutcomeFeedback, report.Freshness)
	report.Scope["schema_version"] = report.SchemaHealth.SchemaVersion

	insights := make([]DecisionInsight, 0, maxInsights)
	priority := 1

	if entityID != "" {
		if entityInsight, ok := buildEntityInsight(g, engine, entityID, report.Coverage, report.Confidence, opts.IncludeCounterfactual); ok {
			entityInsight.Priority = priority
			priority++
			insights = append(insights, entityInsight)
		}
	}

	if posture != nil {
		for _, insight := range buildTopRiskInsights(g, posture, entityID, report.Coverage, report.Confidence, opts.IncludeCounterfactual) {
			if len(insights) >= maxInsights {
				break
			}
			insight.Priority = priority
			priority++
			insights = append(insights, insight)
		}
	}

	if len(insights) < maxInsights {
		if schemaInsight, ok := buildSchemaHealthInsight(report.SchemaHealth, report.Coverage, report.Confidence); ok {
			schemaInsight.Priority = priority
			priority++
			insights = append(insights, schemaInsight)
		}
	}

	if len(insights) < maxInsights {
		if outcomeInsight, ok := buildOutcomeFeedbackInsight(report.OutcomeFeedback, report.Coverage, report.Confidence); ok {
			outcomeInsight.Priority = priority
			priority++
			insights = append(insights, outcomeInsight)
		}
	}

	if len(insights) < maxInsights {
		if freshnessInsight, ok := buildFreshnessInsight(report.Freshness, report.Coverage, report.Confidence); ok {
			freshnessInsight.Priority = priority
			priority++
			insights = append(insights, freshnessInsight)
		}
	}

	if len(insights) < maxInsights {
		if driftInsight, ok := buildTemporalDriftInsight(opts.TemporalDiff, report.Coverage, report.Confidence); ok {
			driftInsight.Priority = priority
			insights = append(insights, driftInsight)
		}
	}

	if len(insights) == 0 {
		insights = append(insights, DecisionInsight{
			ID:         "steady-state",
			Type:       "steady_state",
			Priority:   1,
			Severity:   SeverityLow,
			Title:      "No critical intelligence deltas detected",
			Summary:    "Current graph snapshot does not expose high-priority security, ontology, or calibration regressions.",
			Confidence: report.Confidence,
			Coverage:   report.Coverage,
			SuggestedActions: []string{
				"Keep ingest coverage high and continue collecting realized outcomes for calibration.",
			},
		})
	}

	if len(insights) > maxInsights {
		insights = insights[:maxInsights]
	}
	for i := range insights {
		insights[i].Priority = i + 1
	}
	report.Insights = insights
	return report
}

func buildEntityInsight(g *Graph, engine *RiskEngine, entityID string, coverage float64, baseConfidence float64, includeCounterfactual bool) (DecisionInsight, bool) {
	scored := engine.ScoreEntity(entityID)
	if scored == nil {
		return DecisionInsight{}, false
	}

	evidence := make([]IntelligenceEvidence, 0, 6)
	actions := make([]string, 0, 4)
	for idx, factor := range scored.Factors {
		if idx >= 4 {
			break
		}
		evidence = append(evidence, IntelligenceEvidence{
			Kind:   "risk_factor",
			ID:     factor.Source,
			Title:  factor.Title,
			Detail: factor.Evidence,
			Value: map[string]any{
				"score":  factor.Score,
				"weight": factor.Weight,
			},
		})
		if strings.TrimSpace(factor.Remedy) != "" {
			actions = append(actions, factor.Remedy)
		}
	}

	confidence := clampUnit(baseConfidence * (0.65 + math.Min(0.25, float64(len(scored.Factors))*0.05)))
	insight := DecisionInsight{
		ID:               fmt.Sprintf("entity-risk:%s", scored.EntityID),
		Type:             "entity_risk",
		Severity:         scoreToSeverity(scored.Score),
		Title:            fmt.Sprintf("Entity risk concentration: %s", intelligenceFirstNonEmpty(scored.EntityName, scored.EntityID)),
		Summary:          fmt.Sprintf("Composite entity score is %.1f with trend %s (delta %.1f).", scored.Score, scored.Trend, scored.Delta),
		Confidence:       confidence,
		Coverage:         coverage,
		Evidence:         evidence,
		SuggestedActions: uniqueSortedStrings(actions),
	}

	if includeCounterfactual {
		delta := GraphDelta{Nodes: []NodeMutation{{Action: "remove", ID: scored.EntityID}}}
		if simulation, err := g.Simulate(delta); err == nil && simulation != nil {
			insight.Counterfactual = &InsightCounterfactual{
				Name:                           "remove_entity",
				Summary:                        fmt.Sprintf("Simulate removing %s from the graph to estimate dependency and risk impact.", scored.EntityID),
				Delta:                          delta,
				EstimatedRiskScoreDelta:        simulation.Delta.RiskScoreDelta,
				EstimatedBlockedAttackPaths:    len(simulation.Delta.AttackPathsBlocked),
				EstimatedRemovedToxicCombos:    len(simulation.Delta.ToxicCombosRemoved),
				EstimatedCreatedAttackPaths:    len(simulation.Delta.AttackPathsCreated),
				EstimatedIntroducedToxicCombos: len(simulation.Delta.ToxicCombosAdded),
			}
		}
	}

	return insight, true
}

func buildTopRiskInsights(g *Graph, posture *SecurityReport, entityID string, coverage float64, baseConfidence float64, includeCounterfactual bool) []DecisionInsight {
	if posture == nil || len(posture.TopRisks) == 0 {
		return nil
	}

	insights := make([]DecisionInsight, 0, 3)
	for _, ranked := range posture.TopRisks {
		if ranked == nil {
			continue
		}
		if entityID != "" && !containsStringExact(ranked.AffectedAssets, entityID) {
			continue
		}

		evidence := make([]IntelligenceEvidence, 0, 8)
		for idx, assetID := range ranked.AffectedAssets {
			if idx >= 5 {
				break
			}
			node, _ := g.GetNode(assetID)
			title := assetID
			if node != nil && strings.TrimSpace(node.Name) != "" {
				title = node.Name
			}
			evidence = append(evidence, IntelligenceEvidence{
				Kind:   "affected_asset",
				ID:     assetID,
				Title:  title,
				Detail: fmt.Sprintf("Kind=%s", nodeKindString(node)),
			})
		}
		if len(ranked.MITRE) > 0 {
			evidence = append(evidence, IntelligenceEvidence{
				Kind:  "mitre",
				Title: "MITRE techniques",
				Value: append([]string(nil), ranked.MITRE...),
			})
		}

		confidence := clampUnit(baseConfidence * (0.55 + ranked.Score/200))
		insight := DecisionInsight{
			ID:               fmt.Sprintf("top-risk:%s", ranked.ID),
			Type:             "top_risk",
			Severity:         ranked.Severity,
			Title:            ranked.Title,
			Summary:          ranked.Description,
			Confidence:       confidence,
			Coverage:         coverage,
			Evidence:         evidence,
			SuggestedActions: uniqueSortedStrings([]string{ranked.Remediation}),
		}

		if includeCounterfactual {
			if cf := buildTopRiskCounterfactual(g, posture, ranked); cf != nil {
				insight.Counterfactual = cf
			}
		}

		insights = append(insights, insight)
		if len(insights) >= 3 {
			break
		}
	}

	return insights
}

func buildTopRiskCounterfactual(g *Graph, posture *SecurityReport, ranked *RankedRisk) *InsightCounterfactual {
	if g == nil || posture == nil || ranked == nil {
		return nil
	}
	if len(posture.Chokepoints) == 0 {
		return nil
	}

	var selected *Chokepoint
	for _, cp := range posture.Chokepoints {
		if cp == nil || cp.Node == nil {
			continue
		}
		if containsStringExact(ranked.AffectedAssets, cp.Node.ID) {
			selected = cp
			break
		}
	}
	if selected == nil {
		selected = posture.Chokepoints[0]
	}
	if selected == nil || selected.Node == nil {
		return nil
	}

	delta := GraphDelta{Nodes: []NodeMutation{{Action: "remove", ID: selected.Node.ID}}}
	simulation, err := g.Simulate(delta)
	if err != nil || simulation == nil {
		return nil
	}

	return &InsightCounterfactual{
		Name:                           "remove_chokepoint",
		Summary:                        fmt.Sprintf("Simulate removing chokepoint node %s to estimate attack-path reduction.", selected.Node.ID),
		Delta:                          delta,
		EstimatedRiskScoreDelta:        simulation.Delta.RiskScoreDelta,
		EstimatedBlockedAttackPaths:    len(simulation.Delta.AttackPathsBlocked),
		EstimatedRemovedToxicCombos:    len(simulation.Delta.ToxicCombosRemoved),
		EstimatedCreatedAttackPaths:    len(simulation.Delta.AttackPathsCreated),
		EstimatedIntroducedToxicCombos: len(simulation.Delta.ToxicCombosAdded),
	}
}

func buildSchemaHealthInsight(schema SchemaHealthReport, coverage float64, baseConfidence float64) (DecisionInsight, bool) {
	hasConformanceGap := schema.Nodes.UnknownKind > 0 || schema.Edges.UnknownKind > 0 || len(schema.MissingRequiredProperties) > 0 || len(schema.InvalidRelationships) > 0 || len(schema.InvalidPropertyTypes) > 0
	if !hasConformanceGap {
		return DecisionInsight{}, false
	}

	severity := SeverityMedium
	if schema.Nodes.UnknownKind > 0 || schema.Edges.UnknownKind > 0 || len(schema.InvalidRelationships) > 0 {
		severity = SeverityHigh
	}

	evidence := []IntelligenceEvidence{
		{
			Kind:  "coverage",
			Title: "Ontology coverage",
			Value: map[string]any{
				"node_kind_coverage_percent": schema.NodeKindCoveragePercent,
				"edge_kind_coverage_percent": schema.EdgeKindCoveragePercent,
				"node_conformance_percent":   schema.NodeConformancePercent,
				"edge_conformance_percent":   schema.EdgeConformancePercent,
			},
		},
	}
	if len(schema.UnknownNodeKinds) > 0 {
		evidence = append(evidence, IntelligenceEvidence{
			Kind:   "unknown_node_kind",
			Title:  "Top unknown node kind",
			Detail: summarizeSchemaKindCounts(schema.UnknownNodeKinds, 1),
		})
	}
	if len(schema.UnknownEdgeKinds) > 0 {
		evidence = append(evidence, IntelligenceEvidence{
			Kind:   "unknown_edge_kind",
			Title:  "Top unknown edge kind",
			Detail: summarizeSchemaKindCounts(schema.UnknownEdgeKinds, 1),
		})
	}

	actions := make([]string, 0, len(schema.Recommendations))
	for _, rec := range schema.Recommendations {
		if strings.TrimSpace(rec.SuggestedAction) == "" {
			continue
		}
		actions = append(actions, rec.SuggestedAction)
		if len(actions) >= 4 {
			break
		}
	}

	return DecisionInsight{
		ID:               "ontology-conformance",
		Type:             "ontology_conformance",
		Severity:         severity,
		Title:            "Ontology conformance gaps are reducing confidence",
		Summary:          fmt.Sprintf("Node conformance %.1f%%, edge conformance %.1f%%, schema validation mode %s.", schema.NodeConformancePercent, schema.EdgeConformancePercent, schema.ValidationMode),
		Confidence:       clampUnit(baseConfidence * 0.95),
		Coverage:         coverage,
		Evidence:         evidence,
		SuggestedActions: uniqueSortedStrings(actions),
	}, true
}

func buildOutcomeFeedbackInsight(feedback OutcomeFeedbackReport, coverage float64, baseConfidence float64) (DecisionInsight, bool) {
	if feedback.OutcomeCount == 0 && feedback.RuleSignalCount == 0 {
		return DecisionInsight{}, false
	}

	severity := SeverityLow
	if feedback.Backtest.Samples >= 20 && feedback.Backtest.BrierScore > 0.30 {
		severity = SeverityMedium
	}
	if feedback.Backtest.Samples >= 40 && feedback.Backtest.PrecisionAt50 < 0.35 {
		severity = SeverityHigh
	}

	evidence := []IntelligenceEvidence{
		{
			Kind:  "backtest",
			Title: "Outcome calibration backtest",
			Value: map[string]any{
				"samples":         feedback.Backtest.Samples,
				"brier_score":     feedback.Backtest.BrierScore,
				"precision_at_50": feedback.Backtest.PrecisionAt50,
				"recall_at_50":    feedback.Backtest.RecallAt50,
			},
		},
	}
	if len(feedback.SignalDrift) > 0 {
		evidence = append(evidence, IntelligenceEvidence{
			Kind:   "signal_drift",
			Title:  "Signal drift detected",
			Detail: fmt.Sprintf("%d drifted signal families", len(feedback.SignalDrift)),
		})
	}

	actions := make([]string, 0, 4)
	for idx, adjustment := range feedback.SignalWeightAdjustments {
		if idx >= 3 {
			break
		}
		actions = append(actions, fmt.Sprintf("Adjust %s signal weight from %.2f to %.2f", adjustment.Signal, adjustment.CurrentWeight, adjustment.SuggestedWeight))
	}

	summary := fmt.Sprintf("Observed %d outcomes and %d rule signals in the last %d day(s).", feedback.OutcomeCount, feedback.RuleSignalCount, feedback.ObservationWindowDays)
	if feedback.Backtest.Samples > 0 {
		summary = fmt.Sprintf("Calibration Brier score %.3f with precision@50 %.2f across %d samples.", feedback.Backtest.BrierScore, feedback.Backtest.PrecisionAt50, feedback.Backtest.Samples)
	}

	confidenceBonus := 0.0
	if feedback.Backtest.Samples >= 20 {
		confidenceBonus = 0.1
	}

	return DecisionInsight{
		ID:               "outcome-calibration",
		Type:             "outcome_calibration",
		Severity:         severity,
		Title:            "Risk model calibration from realized outcomes",
		Summary:          summary,
		Confidence:       clampUnit(baseConfidence + confidenceBonus),
		Coverage:         coverage,
		Evidence:         evidence,
		SuggestedActions: uniqueSortedStrings(actions),
	}, true
}

func buildTemporalDriftInsight(diff *GraphDiff, coverage float64, baseConfidence float64) (DecisionInsight, bool) {
	if diff == nil {
		return DecisionInsight{}, false
	}
	changed := len(diff.NodesAdded) + len(diff.NodesRemoved) + len(diff.NodesModified) + len(diff.EdgesAdded) + len(diff.EdgesRemoved)
	if changed == 0 {
		return DecisionInsight{}, false
	}

	severity := SeverityLow
	if changed >= 25 {
		severity = SeverityMedium
	}
	if changed >= 100 {
		severity = SeverityHigh
	}

	evidence := []IntelligenceEvidence{
		{
			Kind:  "graph_diff",
			Title: "Graph structural drift",
			Value: map[string]any{
				"nodes_added":    len(diff.NodesAdded),
				"nodes_removed":  len(diff.NodesRemoved),
				"nodes_modified": len(diff.NodesModified),
				"edges_added":    len(diff.EdgesAdded),
				"edges_removed":  len(diff.EdgesRemoved),
			},
		},
	}
	if !diff.FromTimestamp.IsZero() || !diff.ToTimestamp.IsZero() {
		evidence = append(evidence, IntelligenceEvidence{
			Kind:  "time_window",
			Title: "Temporal comparison window",
			Value: map[string]any{
				"from": diff.FromTimestamp,
				"to":   diff.ToTimestamp,
			},
		})
	}

	return DecisionInsight{
		ID:         "graph-temporal-drift",
		Type:       "temporal_drift",
		Severity:   severity,
		Title:      "Meaningful graph drift detected",
		Summary:    fmt.Sprintf("Detected %d structural changes across selected snapshots.", changed),
		Confidence: clampUnit(baseConfidence * 0.9),
		Coverage:   coverage,
		Evidence:   evidence,
		SuggestedActions: []string{
			"Review newly added and removed high-risk identities/resources in the changed window.",
			"Run simulation for top changed entities before approving production rollout.",
		},
	}, true
}

func buildFreshnessInsight(freshness FreshnessMetrics, coverage float64, baseConfidence float64) (DecisionInsight, bool) {
	if freshness.TotalNodes == 0 || freshness.StaleNodes == 0 {
		return DecisionInsight{}, false
	}
	staleRatio := float64(freshness.StaleNodes) / math.Max(1, float64(freshness.TotalNodes))
	severity := SeverityLow
	if staleRatio >= 0.20 {
		severity = SeverityMedium
	}
	if staleRatio >= 0.50 {
		severity = SeverityHigh
	}

	return DecisionInsight{
		ID:         "graph-freshness",
		Type:       "graph_freshness",
		Severity:   severity,
		Title:      "Graph freshness is degrading confidence",
		Summary:    fmt.Sprintf("%d/%d node(s) are stale; freshness is %.1f%%.", freshness.StaleNodes, freshness.TotalNodes, freshness.FreshnessPercent),
		Confidence: clampUnit(baseConfidence * (1 - math.Min(0.4, staleRatio))),
		Coverage:   coverage,
		Evidence: []IntelligenceEvidence{
			{
				Kind:  "freshness",
				Title: "Observed-at recency",
				Value: map[string]any{
					"total_nodes":         freshness.TotalNodes,
					"nodes_with_observed": freshness.NodesWithObserved,
					"fresh_nodes":         freshness.FreshNodes,
					"stale_nodes":         freshness.StaleNodes,
					"freshness_percent":   freshness.FreshnessPercent,
					"median_age_hours":    freshness.MedianAgeHours,
					"p95_age_hours":       freshness.P95AgeHours,
				},
			},
		},
		SuggestedActions: []string{
			"Prioritize ingestion refresh for stale high-criticality entities.",
			"Add observed_at/valid_from metadata to feeds missing temporal context.",
		},
	}, true
}

func intelligenceBaseConfidence(schema SchemaHealthReport, feedback OutcomeFeedbackReport, freshness FreshnessMetrics) float64 {
	coverage := clampUnit((schema.NodeKindCoveragePercent + schema.EdgeKindCoveragePercent) / 200)
	conformance := clampUnit((schema.NodeConformancePercent + schema.EdgeConformancePercent) / 200)
	confidence := 0.35 + coverage*0.35 + conformance*0.20

	if feedback.Backtest.Samples >= 20 {
		// Lower Brier is better; cap penalty at 0.20.
		penalty := math.Min(0.20, math.Max(0, feedback.Backtest.BrierScore-0.10))
		confidence += 0.15 - penalty
	} else {
		confidence -= 0.05
	}

	if schema.ValidationMode == SchemaValidationEnforce {
		confidence += 0.05
	}
	if freshness.TotalNodes > 0 {
		freshnessWeight := clampUnit(freshness.FreshnessPercent / 100)
		confidence = (confidence * 0.85) + (freshnessWeight * 0.15)
	}
	return clampUnit(confidence)
}

func nodeKindString(node *Node) string {
	if node == nil {
		return "unknown"
	}
	kind := strings.TrimSpace(string(node.Kind))
	if kind == "" {
		return "unknown"
	}
	return kind
}

func intelligenceFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func containsStringExact(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}
