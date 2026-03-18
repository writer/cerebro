package reports

import (
	"math"
	"sort"
	"strings"
	"time"
)

const defaultGraphQualitySchemaHistory = 20

// GraphQualityReportOptions controls graph quality report generation.
type GraphQualityReportOptions struct {
	Now                 time.Time
	FreshnessStaleAfter time.Duration
	SchemaHistoryLimit  int
	SchemaSinceVersion  int64
}

// GraphQualitySummary contains top-line graph quality KPIs.
type GraphQualitySummary struct {
	Nodes            int     `json:"nodes"`
	Edges            int     `json:"edges"`
	MaturityScore    float64 `json:"maturity_score"`
	MaturityGrade    string  `json:"maturity_grade"`
	CriticalFindings int     `json:"critical_findings"`
	Healthy          bool    `json:"healthy"`
}

// GraphQualityOntology summarizes ontology coverage and conformance quality.
type GraphQualityOntology struct {
	SchemaHealth       SchemaHealthReport `json:"schema_health"`
	CoveragePercent    float64            `json:"coverage_percent"`
	ConformancePercent float64            `json:"conformance_percent"`
	UnknownNodeKinds   int                `json:"unknown_node_kinds"`
	UnknownEdgeKinds   int                `json:"unknown_edge_kinds"`
}

// GraphQualityIdentity summarizes identity linking quality.
type GraphQualityIdentity struct {
	PeopleNodes             int     `json:"people_nodes"`
	AliasNodes              int     `json:"alias_nodes"`
	LinkedAliases           int     `json:"linked_aliases"`
	UnlinkedAliases         int     `json:"unlinked_aliases"`
	LinkedCanonicalEntities int     `json:"linked_canonical_entities"`
	LinkagePercent          float64 `json:"linkage_percent"`
}

// GraphQualityTemporal summarizes temporal metadata and freshness quality.
type GraphQualityTemporal struct {
	Freshness                    FreshnessMetrics `json:"freshness"`
	StaleAfterHours              int              `json:"stale_after_hours"`
	NodeObservedCoveragePercent  float64          `json:"node_observed_coverage_percent"`
	NodeValidFromCoveragePercent float64          `json:"node_valid_from_coverage_percent"`
	EdgeObservedCoveragePercent  float64          `json:"edge_observed_coverage_percent"`
	EdgeValidFromCoveragePercent float64          `json:"edge_valid_from_coverage_percent"`
	MetadataCompletenessPercent  float64          `json:"metadata_completeness_percent"`
}

// GraphQualityWriteBack summarizes decision/outcome write-back loop maturity.
type GraphQualityWriteBack struct {
	DecisionNodes           int     `json:"decision_nodes"`
	OutcomeNodes            int     `json:"outcome_nodes"`
	EvidenceNodes           int     `json:"evidence_nodes"`
	ActionNodes             int     `json:"action_nodes"`
	EvaluationEdges         int     `json:"evaluation_edges"`
	DecisionsWithOutcomes   int     `json:"decisions_with_outcomes"`
	OutcomesWithEvaluations int     `json:"outcomes_with_evaluations"`
	ClosureRatePercent      float64 `json:"closure_rate_percent"`
}

// GraphQualityDomainCoverage captures node coverage for one ontology domain category.
type GraphQualityDomainCoverage struct {
	Category string  `json:"category"`
	Nodes    int     `json:"nodes"`
	Percent  float64 `json:"percent"`
}

// GraphQualityRecommendation describes one actionable graph quality improvement.
type GraphQualityRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// GraphQualityReport is a decision-oriented quality report for graph operability.
type GraphQualityReport struct {
	GeneratedAt     time.Time                    `json:"generated_at"`
	Summary         GraphQualitySummary          `json:"summary"`
	Ontology        GraphQualityOntology         `json:"ontology"`
	Identity        GraphQualityIdentity         `json:"identity"`
	Temporal        GraphQualityTemporal         `json:"temporal"`
	WriteBack       GraphQualityWriteBack        `json:"writeback"`
	DomainCoverage  []GraphQualityDomainCoverage `json:"domain_coverage,omitempty"`
	Recommendations []GraphQualityRecommendation `json:"recommendations,omitempty"`
}

// BuildGraphQualityReport computes graph quality KPIs and actionable recommendations.
func BuildGraphQualityReport(g *Graph, opts GraphQualityReportOptions) GraphQualityReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	historyLimit := opts.SchemaHistoryLimit
	if historyLimit <= 0 {
		historyLimit = defaultGraphQualitySchemaHistory
	}
	staleAfter := opts.FreshnessStaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
	}

	report := GraphQualityReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []GraphQualityRecommendation{{
			Priority:        "high",
			Category:        "graph_unavailable",
			Title:           "Graph platform is not initialized",
			Detail:          "No graph quality metrics are available because the graph is nil.",
			SuggestedAction: "Initialize and populate the graph before requesting quality insights.",
		}}
		return report
	}

	nodes := g.GetAllNodes()
	edgesBySource := g.GetAllEdges()
	edgeCount := 0
	for _, edges := range edgesBySource {
		edgeCount += len(edges)
	}
	report.Summary.Nodes = len(nodes)
	report.Summary.Edges = edgeCount

	report.Ontology.SchemaHealth = AnalyzeSchemaHealth(g, historyLimit, opts.SchemaSinceVersion)
	report.Ontology.CoveragePercent = (report.Ontology.SchemaHealth.NodeKindCoveragePercent + report.Ontology.SchemaHealth.EdgeKindCoveragePercent) / 2
	report.Ontology.ConformancePercent = (report.Ontology.SchemaHealth.NodeConformancePercent + report.Ontology.SchemaHealth.EdgeConformancePercent) / 2
	report.Ontology.UnknownNodeKinds = report.Ontology.SchemaHealth.Nodes.UnknownKind
	report.Ontology.UnknownEdgeKinds = report.Ontology.SchemaHealth.Edges.UnknownKind

	report.Identity = buildGraphIdentityQuality(g)
	report.Temporal = buildGraphTemporalQuality(g, nodes, edgesBySource, now, staleAfter)
	report.WriteBack = buildGraphWriteBackQuality(g)
	report.DomainCoverage = buildGraphDomainCoverage(nodes)

	report.Recommendations = buildGraphQualityRecommendations(report)

	identityScore := 1.0
	if report.Identity.AliasNodes > 0 {
		identityScore = clampUnit(report.Identity.LinkagePercent / 100)
	}
	temporalScore := clampUnit(report.Temporal.MetadataCompletenessPercent / 100)
	freshnessScore := clampUnit(report.Temporal.Freshness.FreshnessPercent / 100)
	closedLoopScore := 1.0
	if report.WriteBack.DecisionNodes > 0 {
		closedLoopScore = clampUnit(report.WriteBack.ClosureRatePercent / 100)
	}
	coverageScore := clampUnit(report.Ontology.CoveragePercent / 100)
	conformanceScore := clampUnit(report.Ontology.ConformancePercent / 100)

	report.Summary.MaturityScore = 100 * (0.25*coverageScore +
		0.20*conformanceScore +
		0.20*freshnessScore +
		0.15*identityScore +
		0.10*temporalScore +
		0.10*closedLoopScore)
	report.Summary.MaturityScore = math.Round(report.Summary.MaturityScore*10) / 10
	report.Summary.MaturityGrade = graphQualityGrade(report.Summary.MaturityScore)
	report.Summary.CriticalFindings = countGraphQualityPriority(report.Recommendations, "high")
	report.Summary.Healthy = report.Summary.CriticalFindings == 0 && report.Summary.MaturityScore >= 80

	return report
}

func buildGraphIdentityQuality(g *Graph) GraphQualityIdentity {
	quality := GraphQualityIdentity{}
	if g == nil {
		return quality
	}

	aliasNodes := g.GetNodesByKind(NodeKindIdentityAlias)
	peopleNodes := g.GetNodesByKind(NodeKindPerson)
	userNodes := g.GetNodesByKind(NodeKindUser)
	quality.PeopleNodes = len(peopleNodes) + len(userNodes)
	quality.AliasNodes = len(aliasNodes)

	canonicalTargets := make(map[string]struct{})
	for _, alias := range aliasNodes {
		if alias == nil {
			continue
		}
		linked := false
		for _, edge := range g.GetOutEdges(alias.ID) {
			if edge == nil || edge.Kind != EdgeKindAliasOf {
				continue
			}
			linked = true
			canonicalTargets[edge.Target] = struct{}{}
		}
		if linked {
			quality.LinkedAliases++
		}
	}

	quality.UnlinkedAliases = quality.AliasNodes - quality.LinkedAliases
	if quality.UnlinkedAliases < 0 {
		quality.UnlinkedAliases = 0
	}
	quality.LinkedCanonicalEntities = len(canonicalTargets)
	if quality.AliasNodes > 0 {
		quality.LinkagePercent = (float64(quality.LinkedAliases) / float64(quality.AliasNodes)) * 100
	}
	quality.LinkagePercent = math.Round(quality.LinkagePercent*10) / 10
	return quality
}

func buildGraphTemporalQuality(g *Graph, nodes []*Node, edgesBySource map[string][]*Edge, now time.Time, staleAfter time.Duration) GraphQualityTemporal {
	quality := GraphQualityTemporal{StaleAfterHours: int(staleAfter.Hours())}
	if g == nil {
		return quality
	}

	quality.Freshness = g.Freshness(now, staleAfter)

	nodeObserved := 0
	nodeValidFrom := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if _, ok := graphObservedAt(node); ok {
			nodeObserved++
		}
		if _, ok := temporalPropertyTime(node.Properties, "valid_from"); ok || !node.CreatedAt.IsZero() {
			nodeValidFrom++
		}
	}

	totalEdges := 0
	edgeObserved := 0
	edgeValidFrom := 0
	for _, edges := range edgesBySource {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			totalEdges++
			if _, ok := temporalPropertyTime(edge.Properties, "observed_at"); ok || !edge.CreatedAt.IsZero() {
				edgeObserved++
			}
			if _, ok := temporalPropertyTime(edge.Properties, "valid_from"); ok || !edge.CreatedAt.IsZero() {
				edgeValidFrom++
			}
		}
	}

	if len(nodes) > 0 {
		quality.NodeObservedCoveragePercent = (float64(nodeObserved) / float64(len(nodes))) * 100
		quality.NodeValidFromCoveragePercent = (float64(nodeValidFrom) / float64(len(nodes))) * 100
	}
	coverageValues := make([]float64, 0, 4)
	if len(nodes) > 0 {
		coverageValues = append(coverageValues, quality.NodeObservedCoveragePercent, quality.NodeValidFromCoveragePercent)
	}
	if totalEdges > 0 {
		quality.EdgeObservedCoveragePercent = (float64(edgeObserved) / float64(totalEdges)) * 100
		quality.EdgeValidFromCoveragePercent = (float64(edgeValidFrom) / float64(totalEdges)) * 100
		coverageValues = append(coverageValues, quality.EdgeObservedCoveragePercent, quality.EdgeValidFromCoveragePercent)
	}
	if len(coverageValues) > 0 {
		sum := 0.0
		for _, value := range coverageValues {
			sum += value
		}
		quality.MetadataCompletenessPercent = sum / float64(len(coverageValues))
	}

	quality.NodeObservedCoveragePercent = math.Round(quality.NodeObservedCoveragePercent*10) / 10
	quality.NodeValidFromCoveragePercent = math.Round(quality.NodeValidFromCoveragePercent*10) / 10
	quality.EdgeObservedCoveragePercent = math.Round(quality.EdgeObservedCoveragePercent*10) / 10
	quality.EdgeValidFromCoveragePercent = math.Round(quality.EdgeValidFromCoveragePercent*10) / 10
	quality.MetadataCompletenessPercent = math.Round(quality.MetadataCompletenessPercent*10) / 10
	return quality
}

func buildGraphWriteBackQuality(g *Graph) GraphQualityWriteBack {
	quality := GraphQualityWriteBack{}
	if g == nil {
		return quality
	}

	quality.DecisionNodes = len(g.GetNodesByKind(NodeKindDecision))
	quality.OutcomeNodes = len(g.GetNodesByKind(NodeKindOutcome))
	quality.EvidenceNodes = len(g.GetNodesByKind(NodeKindEvidence))
	quality.ActionNodes = len(g.GetNodesByKind(NodeKindAction))

	decisionsWithOutcomes := make(map[string]struct{})
	outcomesWithEvaluations := make(map[string]struct{})

	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		for _, edge := range g.GetOutEdges(outcome.ID) {
			if edge == nil || edge.Kind != EdgeKindEvaluates {
				continue
			}
			quality.EvaluationEdges++
			outcomesWithEvaluations[outcome.ID] = struct{}{}
			if target, ok := g.GetNode(edge.Target); ok && target != nil && target.Kind == NodeKindDecision {
				decisionsWithOutcomes[target.ID] = struct{}{}
			}
		}
	}

	quality.DecisionsWithOutcomes = len(decisionsWithOutcomes)
	quality.OutcomesWithEvaluations = len(outcomesWithEvaluations)
	if quality.DecisionNodes > 0 {
		quality.ClosureRatePercent = (float64(quality.DecisionsWithOutcomes) / float64(quality.DecisionNodes)) * 100
	} else {
		quality.ClosureRatePercent = 100
	}
	quality.ClosureRatePercent = math.Round(quality.ClosureRatePercent*10) / 10
	return quality
}

func buildGraphDomainCoverage(nodes []*Node) []GraphQualityDomainCoverage {
	totalNodes := len(nodes)
	if totalNodes == 0 {
		return nil
	}

	counts := map[NodeKindCategory]int{
		NodeCategoryIdentity:   0,
		NodeCategoryResource:   0,
		NodeCategoryBusiness:   0,
		NodeCategoryKubernetes: 0,
	}
	uncategorized := 0

	for _, node := range nodes {
		if node == nil {
			continue
		}
		categorized := false
		for category := range counts {
			if IsNodeKindInCategory(node.Kind, category) {
				counts[category]++
				categorized = true
			}
		}
		if !categorized {
			uncategorized++
		}
	}

	out := make([]GraphQualityDomainCoverage, 0, len(counts)+1)
	ordered := []NodeKindCategory{NodeCategoryIdentity, NodeCategoryResource, NodeCategoryBusiness, NodeCategoryKubernetes}
	for _, category := range ordered {
		nodesInCategory := counts[category]
		out = append(out, GraphQualityDomainCoverage{
			Category: string(category),
			Nodes:    nodesInCategory,
			Percent:  math.Round((float64(nodesInCategory)/float64(totalNodes))*1000) / 10,
		})
	}
	out = append(out, GraphQualityDomainCoverage{
		Category: "uncategorized",
		Nodes:    uncategorized,
		Percent:  math.Round((float64(uncategorized)/float64(totalNodes))*1000) / 10,
	})

	sort.Slice(out, func(i, j int) bool {
		if out[i].Nodes == out[j].Nodes {
			return out[i].Category < out[j].Category
		}
		return out[i].Nodes > out[j].Nodes
	})
	return out
}

func buildGraphQualityRecommendations(report GraphQualityReport) []GraphQualityRecommendation {
	recommendations := make([]GraphQualityRecommendation, 0, 8)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, GraphQualityRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if report.Ontology.UnknownNodeKinds > 0 || report.Ontology.UnknownEdgeKinds > 0 {
		add(
			"high",
			"ontology_coverage",
			"Resolve unknown ontology kinds",
			"Unknown node/edge kinds are degrading inference quality and cross-domain traversals.",
			"Register missing node/edge kinds and map ingestion events onto canonical relationships.",
		)
	}

	if report.Identity.AliasNodes > 0 && report.Identity.UnlinkedAliases > 0 {
		priority := "medium"
		if report.Identity.LinkagePercent < 70 {
			priority = "high"
		}
		add(
			priority,
			"identity_linkage",
			"Resolve unlinked identity aliases",
			"Identity aliases without canonical links fragment people-context and degrade recommendations.",
			"Increase deterministic joins (email/SCIM/SSO), review ambiguous aliases, and confirm merges.",
		)
	}

	if report.Temporal.MetadataCompletenessPercent < 85 {
		priority := "medium"
		if report.Temporal.MetadataCompletenessPercent < 70 {
			priority = "high"
		}
		add(
			priority,
			"temporal_metadata",
			"Backfill temporal metadata on graph writes",
			"Missing observed_at/valid_from metadata reduces temporal query accuracy and recency weighting quality.",
			"Require observed_at and valid_from in all ingestion and write-back surfaces, then backfill historical records.",
		)
	}

	if report.Temporal.Freshness.FreshnessPercent < 80 {
		priority := "medium"
		if report.Temporal.Freshness.FreshnessPercent < 60 {
			priority = "high"
		}
		add(
			priority,
			"freshness",
			"Increase graph refresh cadence",
			"A large stale-node population indicates intelligence confidence is likely lagging real-world changes.",
			"Reduce ingest lag, tune scanner intervals, and prioritize high-churn domains for near-real-time updates.",
		)
	}

	if report.WriteBack.DecisionNodes > 0 && report.WriteBack.ClosureRatePercent < 60 {
		add(
			"medium",
			"closed_loop",
			"Increase decision outcome coverage",
			"Decisions are being recorded without enough evaluating outcomes, limiting calibration of recommendations.",
			"Record outcomes for decision nodes and link them with evaluates edges to close feedback loops.",
		)
	}

	if len(recommendations) == 0 {
		add(
			"low",
			"steady_state",
			"Maintain graph quality baseline",
			"Ontology, identity linkage, temporal metadata, and closed-loop write-back signals are all within healthy bounds.",
			"Keep tracking these KPIs and enforce quality guardrails in CI and ingestion pipelines.",
		)
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

func graphQualityPriorityRank(priority string) int {
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

func graphQualityGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func countGraphQualityPriority(recommendations []GraphQualityRecommendation, priority string) int {
	priority = strings.ToLower(strings.TrimSpace(priority))
	count := 0
	for _, recommendation := range recommendations {
		if strings.ToLower(strings.TrimSpace(recommendation.Priority)) == priority {
			count++
		}
	}
	return count
}
