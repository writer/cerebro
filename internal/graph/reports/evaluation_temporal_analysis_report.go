package reports

import (
	"sort"
	"strings"
	"time"
)

const defaultEvaluationTemporalTimelineLimit = 25

// EvaluationTemporalAnalysisReportOptions controls evaluation-run contradiction and temporal-diff analysis.
type EvaluationTemporalAnalysisReportOptions struct {
	Now             time.Time
	EvaluationRunID string
	ConversationID  string
	StageID         string
	TimelineLimit   int
}

// EvaluationTemporalAnalysisWindow captures the derived pre/post action comparison window.
type EvaluationTemporalAnalysisWindow struct {
	PreActionAt  time.Time `json:"pre_action_at,omitempty"`
	PostActionAt time.Time `json:"post_action_at,omitempty"`
}

// EvaluationTemporalAnalysisSummary captures top-line scoped counts for one evaluation analysis.
type EvaluationTemporalAnalysisSummary struct {
	Conversations      int `json:"conversations"`
	Decisions          int `json:"decisions"`
	Actions            int `json:"actions"`
	Outcomes           int `json:"outcomes"`
	Claims             int `json:"claims"`
	ContradictedClaims int `json:"contradicted_claims"`
	SupersededClaims   int `json:"superseded_claims"`
	ReversedActions    int `json:"reversed_actions"`
}

// EvaluationScopedClaimAnalysis links one scoped claim to its explanation and timeline.
type EvaluationScopedClaimAnalysis struct {
	Claim       ClaimRecord      `json:"claim"`
	Explanation ClaimExplanation `json:"explanation"`
	Timeline    ClaimTimeline    `json:"timeline"`
}

// EvaluationTemporalAnalysisRecommendation suggests one follow-up action.
type EvaluationTemporalAnalysisRecommendation struct {
	Priority        string `json:"priority"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// EvaluationTemporalAnalysisReport packages eval-scoped world-model diffs and contradiction signals.
type EvaluationTemporalAnalysisReport struct {
	GeneratedAt     time.Time                                  `json:"generated_at"`
	EvaluationRunID string                                     `json:"evaluation_run_id"`
	ConversationID  string                                     `json:"conversation_id,omitempty"`
	StageID         string                                     `json:"stage_id,omitempty"`
	Window          EvaluationTemporalAnalysisWindow           `json:"window"`
	Summary         EvaluationTemporalAnalysisSummary          `json:"summary"`
	Diff            KnowledgeDiffCollection                    `json:"diff"`
	Conflicts       ClaimConflictReport                        `json:"conflicts"`
	Claims          []EvaluationScopedClaimAnalysis            `json:"claims,omitempty"`
	Recommendations []EvaluationTemporalAnalysisRecommendation `json:"recommendations,omitempty"`
}

// BuildEvaluationTemporalAnalysisReport derives contradiction, supersession, and world-state diff signals for one evaluation run.
func BuildEvaluationTemporalAnalysisReport(g *Graph, opts EvaluationTemporalAnalysisReportOptions) EvaluationTemporalAnalysisReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := EvaluationTemporalAnalysisReport{
		GeneratedAt:     now,
		EvaluationRunID: normalizeEvaluationTemporalIdentifier(opts.EvaluationRunID),
		ConversationID:  normalizeEvaluationTemporalIdentifier(opts.ConversationID),
		StageID:         normalizeEvaluationTemporalIdentifier(opts.StageID),
	}
	if g == nil || report.EvaluationRunID == "" {
		report.Recommendations = []EvaluationTemporalAnalysisRecommendation{{
			Priority:        "high",
			Title:           "Evaluation scope is missing or graph is unavailable",
			Detail:          "Temporal contradiction analysis requires a graph plus an evaluation_run_id.",
			SuggestedAction: "Provide a valid evaluation_run_id after the world-model graph has been initialized.",
		}}
		return report
	}

	timelineLimit := opts.TimelineLimit
	if timelineLimit <= 0 {
		timelineLimit = defaultEvaluationTemporalTimelineLimit
	}

	context := collectEvaluationTemporalContext(g, report.EvaluationRunID, report.ConversationID, report.StageID)
	report.Summary.Conversations = len(context.conversations)
	report.Summary.Decisions = len(context.decisionIDs)
	report.Summary.Actions = len(context.actionIDs)
	report.Summary.Outcomes = len(context.outcomeIDs)
	report.Summary.ReversedActions = context.reversedActions
	report.Window.PreActionAt = context.preActionAt
	report.Window.PostActionAt = context.postActionAt

	claimIDs := make([]string, 0, len(context.claimIDs))
	for claimID := range context.claimIDs {
		claimIDs = append(claimIDs, claimID)
	}
	sort.Strings(claimIDs)
	report.Summary.Claims = len(claimIDs)

	artifactIDs := make(map[string]struct{})
	conflictedClaimIDs := make(map[string]struct{})
	claimAnalyses := make([]EvaluationScopedClaimAnalysis, 0, len(claimIDs))
	for _, claimID := range claimIDs {
		explanation, ok := ExplainClaim(g, claimID, context.postActionAt, context.postActionAt)
		if !ok {
			continue
		}
		timeline, _ := GetClaimTimeline(g, claimID, ClaimTimelineOptions{
			ValidAt:    context.postActionAt,
			RecordedAt: context.postActionAt,
			Limit:      timelineLimit,
		})
		if explanation.Claim.Derived.Conflicted {
			report.Summary.ContradictedClaims++
			conflictedClaimIDs[strings.TrimSpace(explanation.Claim.ID)] = struct{}{}
		}
		if explanation.Claim.Derived.Superseded {
			report.Summary.SupersededClaims++
		}
		for _, evidence := range explanation.Evidence {
			artifactIDs[strings.TrimSpace(evidence.ID)] = struct{}{}
		}
		for _, observation := range explanation.Observations {
			artifactIDs[strings.TrimSpace(observation.ID)] = struct{}{}
		}
		claimAnalyses = append(claimAnalyses, EvaluationScopedClaimAnalysis{
			Claim:       explanation.Claim,
			Explanation: explanation,
			Timeline:    timeline,
		})
	}
	sort.Slice(claimAnalyses, func(i, j int) bool {
		if !claimAnalyses[i].Claim.ObservedAt.Equal(claimAnalyses[j].Claim.ObservedAt) {
			return claimAnalyses[i].Claim.ObservedAt.Before(claimAnalyses[j].Claim.ObservedAt)
		}
		return claimAnalyses[i].Claim.ID < claimAnalyses[j].Claim.ID
	})
	report.Claims = claimAnalyses

	report.Conflicts = filterEvaluationClaimConflicts(BuildClaimConflictReport(g, ClaimConflictReportOptions{
		ValidAt:      context.postActionAt,
		RecordedAt:   context.postActionAt,
		MaxConflicts: len(claimIDs),
	}), conflictedClaimIDs)

	preGraph := g.SubgraphBitemporal(context.preActionAt, context.preActionAt)
	postGraph := g.SubgraphBitemporal(context.postActionAt, context.postActionAt)
	report.Diff = filterEvaluationKnowledgeDiff(DiffKnowledgeGraphs(preGraph, postGraph, KnowledgeDiffQueryOptions{
		FromValidAt:    context.preActionAt,
		FromRecordedAt: context.preActionAt,
		ToValidAt:      context.postActionAt,
		ToRecordedAt:   context.postActionAt,
	}), context.claimIDs, artifactIDs)

	report.Recommendations = buildEvaluationTemporalRecommendations(report)
	return report
}

type evaluationTemporalContext struct {
	conversations   map[string]struct{}
	decisionIDs     map[string]struct{}
	actionIDs       map[string]struct{}
	outcomeIDs      map[string]struct{}
	claimIDs        map[string]struct{}
	reversedActions int
	preActionAt     time.Time
	postActionAt    time.Time
}

func collectEvaluationTemporalContext(g *Graph, evaluationRunID, conversationID, stageID string) evaluationTemporalContext {
	ctx := evaluationTemporalContext{
		conversations: make(map[string]struct{}),
		decisionIDs:   make(map[string]struct{}),
		actionIDs:     make(map[string]struct{}),
		outcomeIDs:    make(map[string]struct{}),
		claimIDs:      make(map[string]struct{}),
	}
	if g == nil {
		return ctx
	}

	updateWindow := func(ts time.Time, pre bool) {
		if ts.IsZero() {
			return
		}
		ts = ts.UTC()
		if pre {
			if ctx.preActionAt.IsZero() || ts.Before(ctx.preActionAt) {
				ctx.preActionAt = ts
			}
		}
		if ctx.postActionAt.IsZero() || ts.After(ctx.postActionAt) {
			ctx.postActionAt = ts
		}
	}

	for _, node := range g.GetNodesByKind(NodeKind("communication_thread")) {
		if !matchesEvaluationTemporalScope(node, evaluationRunID, conversationID, stageID) {
			continue
		}
		if conversation := normalizeEvaluationTemporalIdentifier(graphNodePropertyString(node, "conversation_id")); conversation != "" {
			ctx.conversations[conversation] = struct{}{}
		}
		if ts, ok := graphObservedAt(node); ok {
			updateWindow(ts, true)
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindDecision) {
		if !matchesEvaluationTemporalScope(node, evaluationRunID, conversationID, stageID) {
			continue
		}
		ctx.decisionIDs[strings.TrimSpace(node.ID)] = struct{}{}
		if ts, ok := graphObservedAt(node); ok {
			updateWindow(ts, true)
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindAction) {
		if !matchesEvaluationTemporalScope(node, evaluationRunID, conversationID, stageID) {
			continue
		}
		ctx.actionIDs[strings.TrimSpace(node.ID)] = struct{}{}
		if evaluationTemporalActionReversed(graphNodePropertyString(node, "status")) {
			ctx.reversedActions++
		}
		if ts, ok := graphObservedAt(node); ok {
			updateWindow(ts, true)
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindOutcome) {
		if !matchesEvaluationTemporalScope(node, evaluationRunID, conversationID, stageID) {
			continue
		}
		ctx.outcomeIDs[strings.TrimSpace(node.ID)] = struct{}{}
		if ts, ok := graphObservedAt(node); ok {
			updateWindow(ts, false)
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindClaim) {
		if !matchesEvaluationTemporalScope(node, evaluationRunID, conversationID, stageID) {
			continue
		}
		ctx.claimIDs[strings.TrimSpace(node.ID)] = struct{}{}
		if ts, ok := graphObservedAt(node); ok {
			updateWindow(ts, false)
		}
	}

	if ctx.preActionAt.IsZero() {
		if !ctx.postActionAt.IsZero() {
			ctx.preActionAt = ctx.postActionAt
		} else {
			ctx.preActionAt = temporalNowUTC()
		}
	}
	ctx.preActionAt = ctx.preActionAt.Add(-time.Nanosecond)
	if ctx.postActionAt.IsZero() || ctx.postActionAt.Before(ctx.preActionAt) {
		ctx.postActionAt = ctx.preActionAt.Add(time.Nanosecond)
	}
	return ctx
}

func matchesEvaluationTemporalScope(node *Node, evaluationRunID, conversationID, stageID string) bool {
	if node == nil {
		return false
	}
	if normalizeEvaluationTemporalIdentifier(graphNodePropertyString(node, "evaluation_run_id")) != evaluationRunID {
		return false
	}
	if conversationID == "" {
		if stageID == "" {
			return true
		}
		return matchesEvaluationTemporalStage(node, stageID)
	}
	if normalizeEvaluationTemporalIdentifier(graphNodePropertyString(node, "conversation_id")) != conversationID {
		return false
	}
	if stageID == "" {
		return true
	}
	return matchesEvaluationTemporalStage(node, stageID)
}

func matchesEvaluationTemporalStage(node *Node, stageID string) bool {
	if node == nil {
		return false
	}
	if node.Kind == NodeKind("communication_thread") {
		return true
	}
	if normalizeEvaluationTemporalIdentifier(graphNodePropertyString(node, "stage_id")) == stageID {
		return true
	}
	return normalizeEvaluationTemporalIdentifier(graphNodePropertyString(node, "final_stage_id")) == stageID
}

func normalizeEvaluationTemporalIdentifier(value string) string {
	return strings.TrimSpace(value)
}

func evaluationTemporalActionReversed(status string) bool {
	switch normalizeEvaluationTemporalIdentifier(strings.ToLower(status)) {
	case "reversed", "reverted", "rolled_back", "rolled-back":
		return true
	default:
		return false
	}
}

func filterEvaluationKnowledgeDiff(diff KnowledgeDiffCollection, claimIDs, artifactIDs map[string]struct{}) KnowledgeDiffCollection {
	filtered := diff
	filtered.ClaimDiffs = filtered.ClaimDiffs[:0]
	filtered.ArtifactDiffs = filtered.ArtifactDiffs[:0]
	filtered.Summary = KnowledgeDiffSummary{}
	for _, record := range diff.ClaimDiffs {
		if _, ok := claimIDs[strings.TrimSpace(record.ClaimID)]; !ok {
			continue
		}
		filtered.ClaimDiffs = append(filtered.ClaimDiffs, record)
		switch record.ChangeType {
		case "added":
			filtered.Summary.AddedClaims++
		case "removed":
			filtered.Summary.RemovedClaims++
		case "modified":
			filtered.Summary.ModifiedClaims++
		}
	}
	for _, record := range diff.ArtifactDiffs {
		if _, ok := artifactIDs[strings.TrimSpace(record.ArtifactID)]; !ok {
			continue
		}
		filtered.ArtifactDiffs = append(filtered.ArtifactDiffs, record)
		switch record.Kind {
		case NodeKindObservation:
			switch record.ChangeType {
			case "added":
				filtered.Summary.AddedObservations++
			case "removed":
				filtered.Summary.RemovedObservations++
			case "modified":
				filtered.Summary.ModifiedObservations++
			}
		default:
			switch record.ChangeType {
			case "added":
				filtered.Summary.AddedEvidence++
			case "removed":
				filtered.Summary.RemovedEvidence++
			case "modified":
				filtered.Summary.ModifiedEvidence++
			}
		}
	}
	return filtered
}

func filterEvaluationClaimConflicts(report ClaimConflictReport, claimIDs map[string]struct{}) ClaimConflictReport {
	filtered := report
	filtered.Conflicts = filtered.Conflicts[:0]
	filtered.Summary = ClaimConflictReportSummary{}
	for _, conflict := range report.Conflicts {
		include := false
		for _, claimID := range conflict.ClaimIDs {
			if _, ok := claimIDs[strings.TrimSpace(claimID)]; ok {
				include = true
				break
			}
		}
		if !include {
			continue
		}
		filtered.Conflicts = append(filtered.Conflicts, conflict)
		filtered.Summary.ConflictGroups++
		filtered.Summary.TotalConflictGroups++
		filtered.Summary.ReturnedConflictGroups++
		filtered.Summary.ConflictingClaims += len(conflict.ClaimIDs)
		filtered.Summary.TotalConflictingClaims += len(conflict.ClaimIDs)
		filtered.Summary.ReturnedConflictingClaims += len(conflict.ClaimIDs)
	}
	return filtered
}

func buildEvaluationTemporalRecommendations(report EvaluationTemporalAnalysisReport) []EvaluationTemporalAnalysisRecommendation {
	recommendations := make([]EvaluationTemporalAnalysisRecommendation, 0, 4)
	if report.Summary.Claims == 0 {
		return []EvaluationTemporalAnalysisRecommendation{{
			Priority:        "medium",
			Title:           "No evaluation-scoped claims were linked",
			Detail:          "The selected evaluation scope did not contain claim metadata needed for contradiction or temporal-diff analysis.",
			SuggestedAction: "Emit evaluation_run_id and conversation_id on any world-model claims or observations produced during evaluation runs.",
		}}
	}
	if report.Summary.ContradictedClaims > 0 {
		recommendations = append(recommendations, EvaluationTemporalAnalysisRecommendation{
			Priority:        "high",
			Title:           "Evaluation-scoped claims are contradicted",
			Detail:          "Some claims tied to this evaluation run disagree with later world-model facts.",
			SuggestedAction: "Review the conflicting claims and compare the agent decision trail against the post-action evidence timeline.",
		})
	}
	if report.Summary.SupersededClaims > 0 {
		recommendations = append(recommendations, EvaluationTemporalAnalysisRecommendation{
			Priority:        "medium",
			Title:           "Earlier evaluation claims were superseded",
			Detail:          "Claims made earlier in the evaluation run were later replaced by newer truths.",
			SuggestedAction: "Inspect the supersession chain to identify where the agent's earlier model of the world drifted from reality.",
		})
	}
	if report.Summary.ReversedActions > 0 {
		recommendations = append(recommendations, EvaluationTemporalAnalysisRecommendation{
			Priority:        "high",
			Title:           "Agent actions required reversal",
			Detail:          "One or more evaluation actions were explicitly reversed or rolled back.",
			SuggestedAction: "Correlate reversed actions with claim diffs to find which world-state assumptions were wrong at action time.",
		})
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, EvaluationTemporalAnalysisRecommendation{
			Priority:        "low",
			Title:           "No contradictions detected in the evaluation window",
			Detail:          "The selected evaluation scope does not currently show contradicted or superseded claims.",
			SuggestedAction: "Continue collecting evaluation-linked claims and observations to preserve drift visibility over time.",
		})
	}
	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].Priority == recommendations[j].Priority {
			return recommendations[i].Title < recommendations[j].Title
		}
		return evaluationTemporalRecommendationRank(recommendations[i].Priority) < evaluationTemporalRecommendationRank(recommendations[j].Priority)
	})
	return recommendations
}

func evaluationTemporalRecommendationRank(priority string) int {
	switch strings.TrimSpace(strings.ToLower(priority)) {
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
