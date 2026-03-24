package reports

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAgentActionEffectivenessWindow    = 30 * 24 * time.Hour
	defaultAgentActionEffectivenessTrendDays = 7
	defaultAgentActionEffectivenessMaxAgents = 25
)

// AgentActionEffectivenessReportOptions controls derived agent-evaluation BI report generation.
type AgentActionEffectivenessReportOptions struct {
	Now       time.Time
	Window    time.Duration
	TrendDays int
	MaxAgents int
}

// AgentActionEffectivenessSummary contains top-line evaluation effectiveness KPIs.
type AgentActionEffectivenessSummary struct {
	Conversations                 int     `json:"conversations"`
	Agents                        int     `json:"agents"`
	ToolCalls                     int     `json:"tool_calls"`
	SuccessfulActions             int     `json:"successful_actions"`
	ReversedActions               int     `json:"reversed_actions"`
	PositiveOutcomes              int     `json:"positive_outcomes"`
	NegativeOutcomes              int     `json:"negative_outcomes"`
	TotalCostUSD                  float64 `json:"total_cost_usd"`
	CostPerSuccessfulConversation float64 `json:"cost_per_successful_conversation"`
	CorrectnessPercent            float64 `json:"correctness_percent"`
	AverageQualityScore           float64 `json:"average_quality_score"`
}

// AgentActionEffectivenessRollup summarizes one agent's action effectiveness.
type AgentActionEffectivenessRollup struct {
	Agent                         string  `json:"agent"`
	Conversations                 int     `json:"conversations"`
	ToolCalls                     int     `json:"tool_calls"`
	SuccessfulActions             int     `json:"successful_actions"`
	ReversedActions               int     `json:"reversed_actions"`
	PositiveOutcomes              int     `json:"positive_outcomes"`
	NegativeOutcomes              int     `json:"negative_outcomes"`
	TotalCostUSD                  float64 `json:"total_cost_usd"`
	CostPerSuccessfulConversation float64 `json:"cost_per_successful_conversation"`
	CorrectnessPercent            float64 `json:"correctness_percent"`
	AverageQualityScore           float64 `json:"average_quality_score"`
}

// AgentActionEffectivenessTrend captures a daily rollup for BI dashboards.
type AgentActionEffectivenessTrend struct {
	Date                          string  `json:"date"`
	Conversations                 int     `json:"conversations"`
	ToolCalls                     int     `json:"tool_calls"`
	PositiveOutcomes              int     `json:"positive_outcomes"`
	ReversedActions               int     `json:"reversed_actions"`
	TotalCostUSD                  float64 `json:"total_cost_usd"`
	CostPerSuccessfulConversation float64 `json:"cost_per_successful_conversation"`
	CorrectnessPercent            float64 `json:"correctness_percent"`
	AverageQualityScore           float64 `json:"average_quality_score"`
}

// AgentActionReversal captures one reversed or later-invalidated action.
type AgentActionReversal struct {
	ActionID        string    `json:"action_id"`
	Agent           string    `json:"agent"`
	EvaluationRunID string    `json:"evaluation_run_id"`
	ConversationID  string    `json:"conversation_id"`
	Status          string    `json:"status"`
	Verdict         string    `json:"verdict"`
	ObservedAt      time.Time `json:"observed_at"`
}

// AgentActionEffectivenessRecommendation describes one suggested improvement.
type AgentActionEffectivenessRecommendation struct {
	Priority        string `json:"priority"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// AgentActionEffectivenessReport is a decision-support report for evaluation action effectiveness.
type AgentActionEffectivenessReport struct {
	GeneratedAt     time.Time                                `json:"generated_at"`
	Summary         AgentActionEffectivenessSummary          `json:"summary"`
	Agents          []AgentActionEffectivenessRollup         `json:"agents,omitempty"`
	Trends          []AgentActionEffectivenessTrend          `json:"trends,omitempty"`
	Reversals       []AgentActionReversal                    `json:"reversals,omitempty"`
	Recommendations []AgentActionEffectivenessRecommendation `json:"recommendations,omitempty"`
}

type evalConversationAggregate struct {
	Key            string
	RunID          string
	ConversationID string
	Agent          string
	ThreadAt       time.Time
	OutcomeAt      time.Time
	OutcomeNodeID  string
	ActionAt       time.Time
	CostAt         time.Time
	ObservedAt     time.Time
	Verdict        string
	QualityScore   float64
	HasQuality     bool
	TotalCostUSD   float64
	Actions        []evalActionAggregate
}

type evalActionAggregate struct {
	ID         string
	Status     string
	ObservedAt time.Time
}

type agentRollupAccumulator struct {
	Agent            string
	Conversations    int
	ToolCalls        int
	Successful       int
	Reversed         int
	Positive         int
	Negative         int
	TotalCostUSD     float64
	QualityScoreSum  float64
	QualityScoreSeen int
}

type trendAccumulator struct {
	Date             time.Time
	Conversations    int
	ToolCalls        int
	Positive         int
	Reversed         int
	TotalCostUSD     float64
	QualityScoreSum  float64
	QualityScoreSeen int
}

// BuildAgentActionEffectivenessReport derives BI-ready rollups over evaluation conversations, actions, costs, and outcomes.
func BuildAgentActionEffectivenessReport(g *Graph, opts AgentActionEffectivenessReportOptions) AgentActionEffectivenessReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	window := opts.Window
	if window <= 0 {
		window = defaultAgentActionEffectivenessWindow
	}
	trendDays := opts.TrendDays
	if trendDays <= 0 {
		trendDays = defaultAgentActionEffectivenessTrendDays
	}
	maxAgents := opts.MaxAgents
	if maxAgents <= 0 {
		maxAgents = defaultAgentActionEffectivenessMaxAgents
	}

	report := AgentActionEffectivenessReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []AgentActionEffectivenessRecommendation{{
			Priority:        "high",
			Title:           "Evaluation world-model graph is not initialized",
			Detail:          "No evaluation action effectiveness metrics are available because the graph is nil.",
			SuggestedAction: "Initialize and populate the graph with evaluation lifecycle events before requesting this report.",
		}}
		return report
	}

	conversations := buildEvaluationConversationAggregates(g)
	windowStart := now.Add(-window)
	agentAcc := make(map[string]*agentRollupAccumulator)
	trendAcc := make(map[string]*trendAccumulator)
	reversals := make([]AgentActionReversal, 0)
	seenAgents := make(map[string]struct{})
	qualitySeen := 0
	qualitySum := 0.0

	for _, conversation := range conversations {
		conversation.ObservedAt = conversation.primaryObservedAt()
		if conversation.ObservedAt.IsZero() || conversation.ObservedAt.Before(windowStart) {
			continue
		}

		report.Summary.Conversations++
		report.Summary.ToolCalls += len(conversation.Actions)
		report.Summary.TotalCostUSD += conversation.TotalCostUSD

		agentKey := normalizeEvalIdentifier(conversation.Agent)
		if agentKey == "" {
			agentKey = "unknown"
		}
		seenAgents[agentKey] = struct{}{}
		acc := agentAcc[agentKey]
		if acc == nil {
			acc = &agentRollupAccumulator{Agent: agentKey}
			agentAcc[agentKey] = acc
		}
		acc.Conversations++
		acc.ToolCalls += len(conversation.Actions)
		acc.TotalCostUSD += conversation.TotalCostUSD

		if conversation.HasQuality {
			qualitySeen++
			qualitySum += conversation.QualityScore
			acc.QualityScoreSeen++
			acc.QualityScoreSum += conversation.QualityScore
		}

		if isPositiveEvalVerdict(conversation.Verdict) {
			report.Summary.PositiveOutcomes++
			acc.Positive++
		} else if conversation.Verdict != "" {
			report.Summary.NegativeOutcomes++
			acc.Negative++
		}

		successfulActions, reversedActions, conversationReversals := evaluationActionOutcomeStats(conversation)
		report.Summary.SuccessfulActions += successfulActions
		report.Summary.ReversedActions += reversedActions
		acc.Successful += successfulActions
		acc.Reversed += reversedActions
		reversals = append(reversals, conversationReversals...)

		trendStart := now.AddDate(0, 0, -(trendDays - 1))
		if !conversation.ObservedAt.Before(trendStart) {
			bucketTime := conversation.ObservedAt.Truncate(24 * time.Hour)
			bucketKey := bucketTime.Format("2006-01-02")
			bucket := trendAcc[bucketKey]
			if bucket == nil {
				bucket = &trendAccumulator{Date: bucketTime}
				trendAcc[bucketKey] = bucket
			}
			bucket.Conversations++
			bucket.ToolCalls += len(conversation.Actions)
			bucket.TotalCostUSD += conversation.TotalCostUSD
			bucket.Positive += boolToInt(isPositiveEvalVerdict(conversation.Verdict))
			bucket.Reversed += reversedActions
			if conversation.HasQuality {
				bucket.QualityScoreSeen++
				bucket.QualityScoreSum += conversation.QualityScore
			}
		}
	}

	report.Summary.Agents = len(seenAgents)
	report.Summary.TotalCostUSD = roundMetric(report.Summary.TotalCostUSD)
	if report.Summary.PositiveOutcomes > 0 {
		report.Summary.CostPerSuccessfulConversation = roundMetric(report.Summary.TotalCostUSD / float64(report.Summary.PositiveOutcomes))
	}
	if report.Summary.Conversations > 0 {
		report.Summary.CorrectnessPercent = roundMetric((float64(report.Summary.PositiveOutcomes) / float64(report.Summary.Conversations)) * 100)
	}
	if qualitySeen > 0 {
		report.Summary.AverageQualityScore = roundMetric(qualitySum / float64(qualitySeen))
	}

	report.Agents = buildEvaluationAgentRollups(agentAcc, maxAgents)
	report.Trends = buildEvaluationTrendRollups(trendAcc)
	report.Reversals = buildEvaluationReversalRollups(reversals)
	report.Recommendations = buildAgentActionEffectivenessRecommendations(report)
	return report
}

func buildEvaluationConversationAggregates(g *Graph) map[string]*evalConversationAggregate {
	conversations := make(map[string]*evalConversationAggregate)
	for _, node := range g.GetNodesByKind(NodeKindThread) {
		if node == nil {
			continue
		}
		runID := graphNodePropertyString(node, "evaluation_run_id")
		conversationID := graphNodePropertyString(node, "conversation_id")
		key := evaluationConversationKey(runID, conversationID)
		if key == "" {
			continue
		}
		record := ensureEvaluationConversation(conversations, runID, conversationID)
		record.Agent = firstNonEmptyEval(record.Agent, graphNodePropertyString(node, "agent_email"), graphNodePropertyString(node, "agent_id"))
		if ts, ok := graphObservedAt(node); ok {
			record.ThreadAt = ts
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindOutcome) {
		if node == nil {
			continue
		}
		runID := graphNodePropertyString(node, "evaluation_run_id")
		conversationID := graphNodePropertyString(node, "conversation_id")
		key := evaluationConversationKey(runID, conversationID)
		if key == "" {
			continue
		}
		record := ensureEvaluationConversation(conversations, runID, conversationID)
		outcomeAt, _ := graphObservedAt(node)
		if shouldReplaceEvaluationOutcome(record, strings.TrimSpace(node.ID), outcomeAt) {
			record.Verdict = normalizeEvalIdentifier(graphNodePropertyString(node, "verdict"))
			record.QualityScore, record.HasQuality = graphFloatValue(node.Properties["quality_score"])
			record.OutcomeAt = outcomeAt
			record.OutcomeNodeID = strings.TrimSpace(node.ID)
		}
	}
	for _, node := range g.GetNodesByKind(NodeKindAction) {
		if node == nil {
			continue
		}
		runID := graphNodePropertyString(node, "evaluation_run_id")
		conversationID := graphNodePropertyString(node, "conversation_id")
		key := evaluationConversationKey(runID, conversationID)
		if key == "" {
			continue
		}
		record := ensureEvaluationConversation(conversations, runID, conversationID)
		record.Agent = firstNonEmptyEval(record.Agent, graphNodePropertyString(node, "agent_email"), graphNodePropertyString(node, "agent_id"), graphNodePropertyString(node, "actor_id"))
		action := evalActionAggregate{
			ID:     strings.TrimSpace(node.ID),
			Status: normalizeEvalIdentifier(graphNodePropertyString(node, "status")),
		}
		if ts, ok := graphObservedAt(node); ok {
			action.ObservedAt = ts
			record.ActionAt = maxTime(record.ActionAt, ts)
		}
		record.Actions = append(record.Actions, action)
	}
	for _, node := range g.GetNodesByKind(NodeKindObservation) {
		if node == nil || normalizeEvalIdentifier(graphNodePropertyString(node, "observation_type")) != "evaluation_cost" {
			continue
		}
		runID := graphNodePropertyString(node, "evaluation_run_id")
		conversationID := graphNodePropertyString(node, "conversation_id")
		key := evaluationConversationKey(runID, conversationID)
		if key == "" {
			continue
		}
		record := ensureEvaluationConversation(conversations, runID, conversationID)
		if amount, ok := graphFloatValue(node.Properties["amount_usd"]); ok {
			record.TotalCostUSD += amount
		}
		if ts, ok := graphObservedAt(node); ok {
			record.CostAt = maxTime(record.CostAt, ts)
		}
	}
	return conversations
}

func shouldReplaceEvaluationOutcome(record *evalConversationAggregate, outcomeNodeID string, outcomeAt time.Time) bool {
	if record == nil {
		return false
	}
	outcomeNodeID = strings.TrimSpace(outcomeNodeID)
	if record.OutcomeNodeID == "" {
		return true
	}
	switch {
	case record.OutcomeAt.IsZero() && outcomeAt.IsZero():
		return outcomeNodeID > record.OutcomeNodeID
	case record.OutcomeAt.IsZero():
		return true
	case outcomeAt.IsZero():
		return false
	case outcomeAt.After(record.OutcomeAt):
		return true
	case outcomeAt.Before(record.OutcomeAt):
		return false
	default:
		return outcomeNodeID > record.OutcomeNodeID
	}
}

func ensureEvaluationConversation(records map[string]*evalConversationAggregate, runID, conversationID string) *evalConversationAggregate {
	key := evaluationConversationKey(runID, conversationID)
	if key == "" {
		return &evalConversationAggregate{}
	}
	if record, ok := records[key]; ok {
		return record
	}
	record := &evalConversationAggregate{
		Key:            key,
		RunID:          normalizeEvalIdentifier(runID),
		ConversationID: normalizeEvalIdentifier(conversationID),
	}
	records[key] = record
	return record
}

func (c *evalConversationAggregate) primaryObservedAt() time.Time {
	latest := time.Time{}
	for _, ts := range []time.Time{c.ThreadAt, c.OutcomeAt, c.ActionAt, c.CostAt} {
		if ts.IsZero() {
			continue
		}
		if latest.IsZero() || ts.After(latest) {
			latest = ts.UTC()
		}
	}
	return latest
}

func evaluationActionOutcomeStats(conversation *evalConversationAggregate) (int, int, []AgentActionReversal) {
	if conversation == nil {
		return 0, 0, nil
	}
	successful := 0
	reversed := 0
	reversalRows := make([]AgentActionReversal, 0)
	for _, action := range conversation.Actions {
		switch {
		case isReversedActionStatus(action.Status):
			reversed++
			reversalRows = append(reversalRows, AgentActionReversal{
				ActionID:        strings.TrimSpace(action.ID),
				Agent:           normalizeEvalIdentifier(conversation.Agent),
				EvaluationRunID: normalizeEvalIdentifier(conversation.RunID),
				ConversationID:  normalizeEvalIdentifier(conversation.ConversationID),
				Status:          normalizeEvalIdentifier(action.Status),
				Verdict:         normalizeEvalIdentifier(conversation.Verdict),
				ObservedAt:      action.ObservedAt.UTC(),
			})
		case isSuccessfulActionStatus(action.Status) && isPositiveEvalVerdict(conversation.Verdict):
			successful++
		case isSuccessfulActionStatus(action.Status):
			reversed++
			reversalRows = append(reversalRows, AgentActionReversal{
				ActionID:        strings.TrimSpace(action.ID),
				Agent:           normalizeEvalIdentifier(conversation.Agent),
				EvaluationRunID: normalizeEvalIdentifier(conversation.RunID),
				ConversationID:  normalizeEvalIdentifier(conversation.ConversationID),
				Status:          normalizeEvalIdentifier(action.Status),
				Verdict:         normalizeEvalIdentifier(conversation.Verdict),
				ObservedAt:      action.ObservedAt.UTC(),
			})
		}
	}
	return successful, reversed, reversalRows
}

func buildEvaluationAgentRollups(accumulators map[string]*agentRollupAccumulator, maxAgents int) []AgentActionEffectivenessRollup {
	rollups := make([]AgentActionEffectivenessRollup, 0, len(accumulators))
	for _, acc := range accumulators {
		if acc == nil {
			continue
		}
		rollup := AgentActionEffectivenessRollup{
			Agent:             acc.Agent,
			Conversations:     acc.Conversations,
			ToolCalls:         acc.ToolCalls,
			SuccessfulActions: acc.Successful,
			ReversedActions:   acc.Reversed,
			PositiveOutcomes:  acc.Positive,
			NegativeOutcomes:  acc.Negative,
			TotalCostUSD:      roundMetric(acc.TotalCostUSD),
		}
		if acc.Positive > 0 {
			rollup.CostPerSuccessfulConversation = roundMetric(acc.TotalCostUSD / float64(acc.Positive))
		}
		if acc.Conversations > 0 {
			rollup.CorrectnessPercent = roundMetric((float64(acc.Positive) / float64(acc.Conversations)) * 100)
		}
		if acc.QualityScoreSeen > 0 {
			rollup.AverageQualityScore = roundMetric(acc.QualityScoreSum / float64(acc.QualityScoreSeen))
		}
		rollups = append(rollups, rollup)
	}
	sort.Slice(rollups, func(i, j int) bool {
		if rollups[i].CorrectnessPercent == rollups[j].CorrectnessPercent {
			return rollups[i].Agent < rollups[j].Agent
		}
		return rollups[i].CorrectnessPercent > rollups[j].CorrectnessPercent
	})
	if maxAgents > 0 && len(rollups) > maxAgents {
		rollups = rollups[:maxAgents]
	}
	return rollups
}

func buildEvaluationTrendRollups(accumulators map[string]*trendAccumulator) []AgentActionEffectivenessTrend {
	keys := make([]string, 0, len(accumulators))
	for key := range accumulators {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]AgentActionEffectivenessTrend, 0, len(keys))
	for _, key := range keys {
		acc := accumulators[key]
		if acc == nil {
			continue
		}
		trend := AgentActionEffectivenessTrend{
			Date:             acc.Date.UTC().Format("2006-01-02"),
			Conversations:    acc.Conversations,
			ToolCalls:        acc.ToolCalls,
			PositiveOutcomes: acc.Positive,
			ReversedActions:  acc.Reversed,
			TotalCostUSD:     roundMetric(acc.TotalCostUSD),
		}
		if acc.Positive > 0 {
			trend.CostPerSuccessfulConversation = roundMetric(acc.TotalCostUSD / float64(acc.Positive))
		}
		if acc.Conversations > 0 {
			trend.CorrectnessPercent = roundMetric((float64(acc.Positive) / float64(acc.Conversations)) * 100)
		}
		if acc.QualityScoreSeen > 0 {
			trend.AverageQualityScore = roundMetric(acc.QualityScoreSum / float64(acc.QualityScoreSeen))
		}
		out = append(out, trend)
	}
	return out
}

func buildEvaluationReversalRollups(reversals []AgentActionReversal) []AgentActionReversal {
	sort.Slice(reversals, func(i, j int) bool {
		if reversals[i].ObservedAt.Equal(reversals[j].ObservedAt) {
			return reversals[i].ActionID < reversals[j].ActionID
		}
		return reversals[i].ObservedAt.Before(reversals[j].ObservedAt)
	})
	return reversals
}

func buildAgentActionEffectivenessRecommendations(report AgentActionEffectivenessReport) []AgentActionEffectivenessRecommendation {
	recommendations := make([]AgentActionEffectivenessRecommendation, 0)
	switch report.Summary.Conversations {
	case 0:
		recommendations = append(recommendations, AgentActionEffectivenessRecommendation{
			Priority:        "medium",
			Title:           "No evaluation conversations in the selected window",
			Detail:          "The selected time window does not contain any evaluation conversation lifecycle records.",
			SuggestedAction: "Increase the query window or ensure the platform is emitting evaluation lifecycle events into Cerebro.",
		})
	default:
		if report.Summary.ReversedActions > 0 {
			recommendations = append(recommendations, AgentActionEffectivenessRecommendation{
				Priority:        "high",
				Title:           "Agent actions are being reversed",
				Detail:          "Some evaluation actions were explicitly reverted or later ended in negative outcomes.",
				SuggestedAction: "Review the reversal list and tighten agent decision/tool-call policies for the affected flows.",
			})
		}
		if report.Summary.CorrectnessPercent < 60 {
			recommendations = append(recommendations, AgentActionEffectivenessRecommendation{
				Priority:        "high",
				Title:           "Correctness trend is below target",
				Detail:          "Less than 60% of evaluation conversations ended in positive outcomes in the selected window.",
				SuggestedAction: "Inspect low-performing agents and prompts, and compare decision rationale against observed outcomes.",
			})
		}
		if report.Summary.CostPerSuccessfulConversation > 1 {
			recommendations = append(recommendations, AgentActionEffectivenessRecommendation{
				Priority:        "medium",
				Title:           "Cost per successful conversation is elevated",
				Detail:          "The selected window shows a high cost burden relative to the number of successful conversations.",
				SuggestedAction: "Review tool-call volume and model selection for the highest-cost agents.",
			})
		}
		if len(recommendations) == 0 {
			recommendations = append(recommendations, AgentActionEffectivenessRecommendation{
				Priority:        "low",
				Title:           "Evaluation action effectiveness is stable",
				Detail:          "The selected window shows positive outcomes with low reversal pressure.",
				SuggestedAction: "Keep monitoring trends and compare performance across tenants and time windows.",
			})
		}
	}
	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].Priority == recommendations[j].Priority {
			return recommendations[i].Title < recommendations[j].Title
		}
		return recommendationPriorityRank(recommendations[i].Priority) < recommendationPriorityRank(recommendations[j].Priority)
	})
	return recommendations
}

func evaluationConversationKey(runID, conversationID string) string {
	runID = normalizeEvalIdentifier(runID)
	conversationID = normalizeEvalIdentifier(conversationID)
	if runID == "" || conversationID == "" {
		return ""
	}
	return runID + "|" + conversationID
}

func normalizeEvalIdentifier(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func firstNonEmptyEval(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func graphFloatValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, false
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func isPositiveEvalVerdict(verdict string) bool {
	switch normalizeEvalIdentifier(verdict) {
	case "positive", "pass", "passed", "correct", "succeeded":
		return true
	default:
		return false
	}
}

func isSuccessfulActionStatus(status string) bool {
	switch normalizeEvalIdentifier(status) {
	case "succeeded", "success", "completed", "applied":
		return true
	default:
		return false
	}
}

func isReversedActionStatus(status string) bool {
	switch normalizeEvalIdentifier(status) {
	case "reverted", "reversed", "rolled_back", "rolled-back":
		return true
	default:
		return false
	}
}

func recommendationPriorityRank(priority string) int {
	switch normalizeEvalIdentifier(priority) {
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

func maxTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right.UTC()
	}
	return left.UTC()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func roundMetric(value float64) float64 {
	return math.Round(value*100) / 100
}
