package reports

import (
	"testing"
	"time"
)

func TestBuildAgentActionEffectivenessReport(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationConversationFixture(g, evaluationConversationFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		TurnID:       "turn-1",
		Agent:        "agent-a@example.com",
		ActionID:     "call-1",
		ActionStatus: "succeeded",
		Verdict:      "positive",
		QualityScore: 0.92,
		CostUSD:      0.25,
		ObservedAt:   now.Add(-12 * time.Hour),
	})
	addEvaluationConversationFixture(g, evaluationConversationFixture{
		RunID:        "run-2",
		Conversation: "conv-2",
		TurnID:       "turn-2",
		Agent:        "agent-b@example.com",
		ActionID:     "call-2",
		ActionStatus: "reverted",
		Verdict:      "negative",
		QualityScore: 0.21,
		CostUSD:      0.40,
		ObservedAt:   now.Add(-36 * time.Hour),
	})

	report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
		Now:       now,
		Window:    7 * 24 * time.Hour,
		TrendDays: 7,
		MaxAgents: 10,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.Summary.Conversations != 2 {
		t.Fatalf("expected 2 conversations, got %d", report.Summary.Conversations)
	}
	if report.Summary.PositiveOutcomes != 1 || report.Summary.NegativeOutcomes != 1 {
		t.Fatalf("unexpected outcome counts: %#v", report.Summary)
	}
	if report.Summary.SuccessfulActions != 1 {
		t.Fatalf("expected 1 successful action, got %#v", report.Summary)
	}
	if report.Summary.ReversedActions != 1 {
		t.Fatalf("expected 1 reversed action, got %#v", report.Summary)
	}
	if report.Summary.TotalCostUSD != 0.65 {
		t.Fatalf("expected total cost 0.65, got %#v", report.Summary.TotalCostUSD)
	}
	if report.Summary.CostPerSuccessfulConversation != 0.65 {
		t.Fatalf("expected cost per successful conversation 0.65, got %#v", report.Summary.CostPerSuccessfulConversation)
	}
	if report.Summary.CorrectnessPercent != 50 {
		t.Fatalf("expected correctness 50, got %#v", report.Summary.CorrectnessPercent)
	}

	if len(report.Agents) != 2 {
		t.Fatalf("expected 2 agent rollups, got %#v", report.Agents)
	}
	if report.Agents[0].Agent != "agent-a@example.com" {
		t.Fatalf("expected first agent rollup for agent-a@example.com, got %#v", report.Agents[0])
	}
	if report.Agents[0].PositiveOutcomes != 1 || report.Agents[0].ReversedActions != 0 {
		t.Fatalf("unexpected first agent rollup: %#v", report.Agents[0])
	}
	if report.Agents[1].Agent != "agent-b@example.com" || report.Agents[1].ReversedActions != 1 {
		t.Fatalf("unexpected second agent rollup: %#v", report.Agents[1])
	}

	if len(report.Trends) != 2 {
		t.Fatalf("expected 2 trend buckets, got %#v", report.Trends)
	}
	if report.Trends[0].CorrectnessPercent != 0 || report.Trends[1].CorrectnessPercent != 100 {
		t.Fatalf("unexpected correctness trends: %#v", report.Trends)
	}

	if len(report.Reversals) != 1 {
		t.Fatalf("expected one reversal, got %#v", report.Reversals)
	}
	if report.Reversals[0].ActionID != "action:evaluation:run-2:conv-2:call-2" {
		t.Fatalf("unexpected reversal payload: %#v", report.Reversals[0])
	}

	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report.Recommendations)
	}
}

func TestBuildAgentActionEffectivenessReportWindowFilter(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationConversationFixture(g, evaluationConversationFixture{
		RunID:        "run-recent",
		Conversation: "conv-recent",
		TurnID:       "turn-recent",
		Agent:        "agent-a@example.com",
		ActionID:     "call-recent",
		ActionStatus: "succeeded",
		Verdict:      "positive",
		QualityScore: 0.91,
		CostUSD:      0.10,
		ObservedAt:   now.Add(-6 * time.Hour),
	})
	addEvaluationConversationFixture(g, evaluationConversationFixture{
		RunID:        "run-old",
		Conversation: "conv-old",
		TurnID:       "turn-old",
		Agent:        "agent-b@example.com",
		ActionID:     "call-old",
		ActionStatus: "reverted",
		Verdict:      "negative",
		QualityScore: 0.10,
		CostUSD:      0.50,
		ObservedAt:   now.Add(-10 * 24 * time.Hour),
	})

	report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
		Now:       now,
		Window:    48 * time.Hour,
		TrendDays: 2,
		MaxAgents: 10,
	})

	if report.Summary.Conversations != 1 {
		t.Fatalf("expected only recent conversation inside window, got %#v", report.Summary)
	}
	if report.Summary.ReversedActions != 0 {
		t.Fatalf("expected old reversed action to be excluded by window, got %#v", report.Summary)
	}
}

func TestBuildAgentActionEffectivenessReportEmptyGraph(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)

	report := BuildAgentActionEffectivenessReport(New(), AgentActionEffectivenessReportOptions{
		Now:       now,
		Window:    7 * 24 * time.Hour,
		TrendDays: 7,
		MaxAgents: 10,
	})

	if report.Summary.Conversations != 0 || report.Summary.ToolCalls != 0 || report.Summary.TotalCostUSD != 0 {
		t.Fatalf("expected empty graph report to stay zeroed, got %#v", report.Summary)
	}
	if len(report.Agents) != 0 || len(report.Trends) != 0 || len(report.Reversals) != 0 {
		t.Fatalf("expected no rollups for empty graph, got %#v", report)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations for empty graph, got %#v", report)
	}
}

func TestBuildAgentActionEffectivenessReportIgnoresGraphsWithoutEvaluationNodes(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "payments"})

	report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
		Now:       now,
		Window:    7 * 24 * time.Hour,
		TrendDays: 7,
		MaxAgents: 10,
	})

	if report.Summary.Conversations != 0 || report.Summary.ToolCalls != 0 || report.Summary.TotalCostUSD != 0 {
		t.Fatalf("expected non-evaluation graph to be ignored, got %#v", report.Summary)
	}
	if len(report.Agents) != 0 || len(report.Trends) != 0 || len(report.Reversals) != 0 {
		t.Fatalf("expected no derived agent rollups, got %#v", report)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations when no evaluation conversations exist, got %#v", report)
	}
}

func TestBuildAgentActionEffectivenessReportUsesLatestConversationSignalForWindowing(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()
	threadObservedAt := now.Add(-10 * 24 * time.Hour)
	actionObservedAt := now.Add(-90 * time.Minute)

	g.AddNode(&Node{
		ID:   "thread:evaluation:run-latest:conv-latest",
		Kind: NodeKindThread,
		Name: "conv-latest",
		Properties: map[string]any{
			"thread_id":         "conv-latest",
			"channel_id":        "run-latest",
			"channel_name":      "evaluation",
			"conversation_id":   "conv-latest",
			"evaluation_run_id": "run-latest",
			"agent_email":       "agent@example.com",
			"observed_at":       threadObservedAt.Format(time.RFC3339),
			"valid_from":        threadObservedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "action:evaluation:run-latest:conv-latest:call-1",
		Kind: NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "reversed",
			"conversation_id":   "conv-latest",
			"evaluation_run_id": "run-latest",
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"agent_email":       "agent@example.com",
			"observed_at":       actionObservedAt.Format(time.RFC3339),
			"valid_from":        actionObservedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})

	report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
		Now:       now,
		Window:    48 * time.Hour,
		TrendDays: 2,
		MaxAgents: 10,
	})

	if report.Summary.Conversations != 1 {
		t.Fatalf("expected recent action to keep the conversation inside the reporting window, got %#v", report.Summary)
	}
	if report.Summary.ToolCalls != 1 {
		t.Fatalf("expected one tool call to be counted, got %#v", report.Summary)
	}
}

func TestBuildAgentActionEffectivenessReportUsesMostRecentOutcomePerConversation(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()
	threadObservedAt := now.Add(-2 * time.Hour)
	oldOutcomeObservedAt := now.Add(-70 * time.Minute)
	newOutcomeObservedAt := now.Add(-30 * time.Minute)

	g.AddNode(&Node{
		ID:   "thread:evaluation:run-stable:conv-stable",
		Kind: NodeKindThread,
		Name: "conv-stable",
		Properties: map[string]any{
			"thread_id":         "conv-stable",
			"channel_id":        "run-stable",
			"channel_name":      "evaluation",
			"conversation_id":   "conv-stable",
			"evaluation_run_id": "run-stable",
			"agent_email":       "agent@example.com",
			"observed_at":       threadObservedAt.Format(time.RFC3339),
			"valid_from":        threadObservedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "action:evaluation:run-stable:conv-stable:call-1",
		Kind: NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "succeeded",
			"conversation_id":   "conv-stable",
			"evaluation_run_id": "run-stable",
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"agent_email":       "agent@example.com",
			"observed_at":       now.Add(-45 * time.Minute).Format(time.RFC3339),
			"valid_from":        now.Add(-45 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-stable:conv-stable:old",
		Kind: NodeKindOutcome,
		Name: "positive",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "positive",
			"quality_score":     0.91,
			"conversation_id":   "conv-stable",
			"evaluation_run_id": "run-stable",
			"observed_at":       oldOutcomeObservedAt.Format(time.RFC3339),
			"valid_from":        oldOutcomeObservedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-stable:conv-stable:new",
		Kind: NodeKindOutcome,
		Name: "negative",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "negative",
			"quality_score":     0.12,
			"conversation_id":   "conv-stable",
			"evaluation_run_id": "run-stable",
			"observed_at":       newOutcomeObservedAt.Format(time.RFC3339),
			"valid_from":        newOutcomeObservedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})

	for i := 0; i < 64; i++ {
		report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
			Now:       now,
			Window:    24 * time.Hour,
			TrendDays: 2,
			MaxAgents: 10,
		})
		if report.Summary.Conversations != 1 {
			t.Fatalf("iteration %d: expected one conversation, got %#v", i, report.Summary)
		}
		if report.Summary.PositiveOutcomes != 0 || report.Summary.NegativeOutcomes != 1 {
			t.Fatalf("iteration %d: expected newest negative outcome to win, got %#v", i, report.Summary)
		}
		if report.Summary.AverageQualityScore != 0.12 {
			t.Fatalf("iteration %d: expected newest quality score 0.12, got %#v", i, report.Summary)
		}
	}
}

func TestBuildAgentActionEffectivenessReportUsesDeterministicTieBreakForOutcomeTimestamps(t *testing.T) {
	now := time.Date(2026, 3, 22, 18, 0, 0, 0, time.UTC)
	g := New()
	observedAt := now.Add(-30 * time.Minute)

	g.AddNode(&Node{
		ID:   "thread:evaluation:run-tie:conv-tie",
		Kind: NodeKindThread,
		Name: "conv-tie",
		Properties: map[string]any{
			"thread_id":         "conv-tie",
			"channel_id":        "run-tie",
			"channel_name":      "evaluation",
			"conversation_id":   "conv-tie",
			"evaluation_run_id": "run-tie",
			"agent_email":       "agent@example.com",
			"observed_at":       now.Add(-45 * time.Minute).Format(time.RFC3339),
			"valid_from":        now.Add(-45 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-tie:conv-tie:a",
		Kind: NodeKindOutcome,
		Name: "positive",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "positive",
			"quality_score":     0.9,
			"conversation_id":   "conv-tie",
			"evaluation_run_id": "run-tie",
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-tie:conv-tie:b",
		Kind: NodeKindOutcome,
		Name: "negative",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "negative",
			"quality_score":     0.2,
			"conversation_id":   "conv-tie",
			"evaluation_run_id": "run-tie",
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})

	for i := 0; i < 64; i++ {
		report := BuildAgentActionEffectivenessReport(g, AgentActionEffectivenessReportOptions{
			Now:       now,
			Window:    24 * time.Hour,
			TrendDays: 2,
			MaxAgents: 10,
		})
		if report.Summary.PositiveOutcomes != 0 || report.Summary.NegativeOutcomes != 1 {
			t.Fatalf("iteration %d: expected deterministic tie-break to pick outcome b, got %#v", i, report.Summary)
		}
		if report.Summary.AverageQualityScore != 0.2 {
			t.Fatalf("iteration %d: expected deterministic tie-break quality 0.2, got %#v", i, report.Summary)
		}
	}
}

type evaluationConversationFixture struct {
	RunID        string
	Conversation string
	TurnID       string
	Agent        string
	ActionID     string
	ActionStatus string
	Verdict      string
	QualityScore float64
	CostUSD      float64
	ObservedAt   time.Time
}

func addEvaluationConversationFixture(g *Graph, fixture evaluationConversationFixture) {
	if g == nil {
		return
	}
	observedAt := fixture.ObservedAt.UTC()
	g.AddNode(&Node{
		ID:   "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation,
		Kind: NodeKind("communication_thread"),
		Name: fixture.Conversation,
		Properties: map[string]any{
			"thread_id":         fixture.Conversation,
			"channel_id":        fixture.RunID,
			"channel_name":      "evaluation",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"agent_email":       fixture.Agent,
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "decision:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":" + fixture.TurnID,
		Kind: NodeKindDecision,
		Name: fixture.TurnID,
		Properties: map[string]any{
			"decision_type":     "tool_selection",
			"status":            "completed",
			"made_at":           observedAt.Format(time.RFC3339),
			"agent_email":       fixture.Agent,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           fixture.TurnID,
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":" + fixture.ActionID,
		Kind: NodeKindAction,
		Name: fixture.ActionID,
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            fixture.ActionStatus,
			"performed_at":      observedAt.Format(time.RFC3339),
			"actor_id":          fixture.Agent,
			"agent_email":       fixture.Agent,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           fixture.TurnID,
			"tool_call_id":      fixture.ActionID,
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "observation:evaluation_cost:" + fixture.RunID + ":" + fixture.Conversation + ":cost-" + fixture.ActionID,
		Kind: NodeKindObservation,
		Name: "cost",
		Properties: map[string]any{
			"observation_type":  "evaluation_cost",
			"subject_id":        "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           fixture.TurnID,
			"tool_call_id":      fixture.ActionID,
			"amount_usd":        fixture.CostUSD,
			"currency":          "USD",
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"recorded_at":       observedAt.Format(time.RFC3339),
			"transaction_from":  observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:evaluation:" + fixture.RunID + ":" + fixture.Conversation,
		Kind: NodeKindOutcome,
		Name: fixture.Verdict,
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           fixture.Verdict,
			"quality_score":     fixture.QualityScore,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddEdge(&Edge{ID: "decision-target:" + fixture.TurnID, Source: "decision:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":" + fixture.TurnID, Target: "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "action-based-on:" + fixture.ActionID, Source: "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":" + fixture.ActionID, Target: "decision:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":" + fixture.TurnID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "outcome-target:" + fixture.Conversation, Source: "outcome:evaluation:" + fixture.RunID + ":" + fixture.Conversation, Target: "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
}
