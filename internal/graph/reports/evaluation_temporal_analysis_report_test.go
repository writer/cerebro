package reports

import (
	"testing"
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestBuildEvaluationTemporalAnalysisReport(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       now.Add(-2 * time.Hour),
	})

	report := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-1",
		ConversationID:  "conv-1",
		TimelineLimit:   10,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.EvaluationRunID != "run-1" || report.ConversationID != "conv-1" {
		t.Fatalf("unexpected report scope: %#v", report)
	}
	if report.Window.PreActionAt.IsZero() || report.Window.PostActionAt.IsZero() {
		t.Fatalf("expected populated analysis window, got %#v", report.Window)
	}
	if report.Summary.Decisions != 1 {
		t.Fatalf("expected 1 decision, got %#v", report.Summary)
	}
	if report.Summary.Actions != 2 {
		t.Fatalf("expected 2 actions, got %#v", report.Summary)
	}
	if report.Summary.Outcomes != 1 {
		t.Fatalf("expected 1 outcome, got %#v", report.Summary)
	}
	if report.Summary.Claims != 4 {
		t.Fatalf("expected 4 scoped claims, got %#v", report.Summary)
	}
	if report.Summary.ContradictedClaims != 2 {
		t.Fatalf("expected 2 contradicted claims, got %#v", report.Summary)
	}
	if report.Summary.SupersededClaims != 1 {
		t.Fatalf("expected 1 superseded claim, got %#v", report.Summary)
	}
	if report.Summary.ReversedActions != 1 {
		t.Fatalf("expected 1 reversed action, got %#v", report.Summary)
	}
	if report.Diff.Summary.AddedClaims != 2 {
		t.Fatalf("expected 2 added claims across the eval window, got %#v", report.Diff.Summary)
	}
	if report.Conflicts.Summary.ConflictGroups != 1 {
		t.Fatalf("expected 1 conflict group, got %#v", report.Conflicts.Summary)
	}
	if len(report.Claims) != 4 {
		t.Fatalf("expected 4 scoped claim analyses, got %#v", report.Claims)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report.Recommendations)
	}

	var supersededClaimFound bool
	for _, claim := range report.Claims {
		if claim.Claim.ID == "claim:evaluation:run-1:conv-1:tier-before" {
			supersededClaimFound = true
			if !claim.Explanation.Claim.Derived.Superseded {
				t.Fatalf("expected tier-before claim to be superseded, got %#v", claim.Explanation.Claim)
			}
			if claim.Timeline.Summary.SupersessionEntries == 0 {
				t.Fatalf("expected supersession timeline entries, got %#v", claim.Timeline.Summary)
			}
		}
	}
	if !supersededClaimFound {
		t.Fatal("expected superseded claim analysis to be present")
	}
}

func TestBuildEvaluationTemporalAnalysisReportConversationFilter(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       now.Add(-2 * time.Hour),
	})
	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-1",
		Conversation: "conv-2",
		ServiceID:    "service:payments:conv-2",
		BaseAt:       now.Add(-90 * time.Minute),
	})

	scoped := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-1",
		ConversationID:  "conv-1",
		TimelineLimit:   10,
	})
	runWide := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-1",
		TimelineLimit:   10,
	})

	if scoped.Summary.Claims != 4 {
		t.Fatalf("expected conversation-scoped report to keep 4 claims, got %#v", scoped.Summary)
	}
	if runWide.Summary.Claims != 8 {
		t.Fatalf("expected run-wide report to include both conversations, got %#v", runWide.Summary)
	}
	if scoped.Summary.Actions != 2 || runWide.Summary.Actions != 4 {
		t.Fatalf("unexpected action counts for scoped vs run-wide report: scoped=%#v runWide=%#v", scoped.Summary, runWide.Summary)
	}
}

func TestBuildEvaluationTemporalAnalysisReportStageFilter(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       now.Add(-2 * time.Hour),
	})
	tagEvaluationTemporalStageFixture(t, g, "run-1", "conv-1")

	report := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-1",
		ConversationID:  "conv-1",
		StageID:         "stage-2",
		TimelineLimit:   10,
	})

	if report.StageID != "stage-2" {
		t.Fatalf("expected stage_id to echo stage-2, got %#v", report.StageID)
	}
	if report.Summary.Conversations != 1 {
		t.Fatalf("expected one scoped conversation, got %#v", report.Summary)
	}
	if report.Summary.Actions != 1 {
		t.Fatalf("expected only stage-2 action to remain, got %#v", report.Summary)
	}
	if report.Summary.Outcomes != 1 {
		t.Fatalf("expected final stage outcome to remain, got %#v", report.Summary)
	}
	if report.Summary.Claims != 2 {
		t.Fatalf("expected only stage-2 claims to remain, got %#v", report.Summary)
	}
	if report.Summary.ContradictedClaims != 1 {
		t.Fatalf("expected only one stage-2 contradicted claim, got %#v", report.Summary)
	}
	if report.Summary.SupersededClaims != 0 {
		t.Fatalf("expected no superseded stage-2 claims, got %#v", report.Summary)
	}
	if len(report.Claims) != 2 {
		t.Fatalf("expected 2 scoped claim analyses, got %#v", report.Claims)
	}
}

func TestBuildEvaluationTemporalAnalysisReportEmptyGraph(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)

	report := BuildEvaluationTemporalAnalysisReport(New(), EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-empty",
		TimelineLimit:   10,
	})

	if report.Summary.Conversations != 0 || report.Summary.Claims != 0 || report.Summary.Actions != 0 {
		t.Fatalf("expected empty graph report to stay zeroed, got %#v", report.Summary)
	}
	if len(report.Claims) != 0 || len(report.Diff.ClaimDiffs) != 0 || len(report.Conflicts.Conflicts) != 0 {
		t.Fatalf("expected no derived details for empty graph, got %#v", report)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations for empty evaluation graph, got %#v", report)
	}
}

func TestBuildEvaluationTemporalAnalysisReportIgnoresGraphsWithoutEvaluationNodes(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "payments",
		Properties: map[string]any{
			"service_id": "service:payments",
		},
	})

	report := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-empty",
		TimelineLimit:   10,
	})

	if report.Summary.Conversations != 0 || report.Summary.Claims != 0 || report.Summary.Actions != 0 {
		t.Fatalf("expected graph without evaluation nodes to stay zeroed, got %#v", report.Summary)
	}
	if len(report.Claims) != 0 || len(report.Diff.ClaimDiffs) != 0 || len(report.Conflicts.Conflicts) != 0 {
		t.Fatalf("expected no derived details without evaluation nodes, got %#v", report)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations when no scoped evaluation nodes exist, got %#v", report)
	}
}

func TestBuildEvaluationTemporalAnalysisReportRunWideIgnoresBlankConversationIDs(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-1",
		Conversation: "conv-1",
		ServiceID:    "service:payments:conv-1",
		BaseAt:       now.Add(-2 * time.Hour),
	})
	g.AddNode(&Node{
		ID:   "thread:evaluation:run-1:blank",
		Kind: NodeKindThread,
		Name: "blank",
		Properties: map[string]any{
			"thread_id":         "blank",
			"channel_id":        "run-1",
			"conversation_id":   "   ",
			"evaluation_run_id": "run-1",
			"observed_at":       now.Add(-30 * time.Minute).Format(time.RFC3339),
			"valid_from":        now.Add(-30 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})

	report := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-1",
		TimelineLimit:   10,
	})

	if report.Summary.Conversations != 1 {
		t.Fatalf("expected blank conversation ids to be ignored in run-wide counts, got %#v", report.Summary)
	}
}

func TestBuildEvaluationTemporalAnalysisReportUsesPostActionEvidenceForWindowFallback(t *testing.T) {
	now := time.Date(2026, 3, 22, 20, 0, 0, 0, time.UTC)
	g := New()
	observedAt := now.Add(-90 * time.Minute).UTC()

	g.AddNode(&Node{
		ID:   "outcome:evaluation:run-outcome-only:conv-1",
		Kind: NodeKindOutcome,
		Name: "positive",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "positive",
			"quality_score":     0.93,
			"conversation_id":   "conv-1",
			"evaluation_run_id": "run-outcome-only",
			"observed_at":       observedAt.Format(time.RFC3339),
			"valid_from":        observedAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})

	report := BuildEvaluationTemporalAnalysisReport(g, EvaluationTemporalAnalysisReportOptions{
		Now:             now,
		EvaluationRunID: "run-outcome-only",
		ConversationID:  "conv-1",
		TimelineLimit:   10,
	})

	if got := report.Window.PreActionAt; !got.Equal(observedAt.Add(-time.Nanosecond)) {
		t.Fatalf("expected pre-action fallback to derive from post-action evidence, got %#v", got)
	}
	if got := report.Window.PostActionAt; !got.Equal(observedAt) {
		t.Fatalf("expected post-action window to stay anchored to the outcome timestamp, got %#v", got)
	}
}

type evaluationTemporalAnalysisFixture struct {
	RunID        string
	Conversation string
	ServiceID    string
	BaseAt       time.Time
}

func addEvaluationTemporalAnalysisFixture(t *testing.T, g *Graph, fixture evaluationTemporalAnalysisFixture) {
	t.Helper()
	if g == nil {
		t.Fatal("graph is required")
	}

	baseAt := fixture.BaseAt.UTC()
	threadID := "thread:evaluation:" + fixture.RunID + ":" + fixture.Conversation
	decisionID := "decision:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":turn-1"
	actionSuccessID := "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":call-1"
	actionReversedID := "action:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":call-2"
	outcomeID := "outcome:evaluation:" + fixture.RunID + ":" + fixture.Conversation

	g.AddNode(&Node{
		ID:   fixture.ServiceID,
		Kind: NodeKindService,
		Name: fixture.ServiceID,
		Properties: map[string]any{
			"service_id":       fixture.ServiceID,
			"observed_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"valid_from":       baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"recorded_at":      baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"transaction_from": baseAt.Add(-30 * time.Minute).Format(time.RFC3339),
			"source_system":    "platform_eval",
		},
	})
	for _, evidenceID := range []string{
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after",
	} {
		g.AddNode(&Node{
			ID:   evidenceID,
			Kind: NodeKindEvidence,
			Name: evidenceID,
			Properties: map[string]any{
				"evidence_type":    "document",
				"observed_at":      baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"valid_from":       baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"recorded_at":      baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"transaction_from": baseAt.Add(-20 * time.Minute).Format(time.RFC3339),
				"source_system":    "platform_eval",
			},
		})
	}

	g.AddNode(&Node{
		ID:   threadID,
		Kind: NodeKind("communication_thread"),
		Name: fixture.Conversation,
		Properties: map[string]any{
			"thread_id":         fixture.Conversation,
			"channel_id":        fixture.RunID,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Format(time.RFC3339),
			"valid_from":        baseAt.Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   decisionID,
		Kind: NodeKindDecision,
		Name: "turn-1",
		Properties: map[string]any{
			"decision_type":     "tool_selection",
			"status":            "completed",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"agent_email":       "agent@example.com",
			"made_at":           baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"observed_at":       baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(5 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   actionSuccessID,
		Kind: NodeKindAction,
		Name: "call-1",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "succeeded",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"tool_call_id":      "call-1",
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(10 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   actionReversedID,
		Kind: NodeKindAction,
		Name: "call-2",
		Properties: map[string]any{
			"action_type":       "tool_call",
			"status":            "reversed",
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"turn_id":           "turn-1",
			"tool_call_id":      "call-2",
			"agent_email":       "agent@example.com",
			"observed_at":       baseAt.Add(12 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(12 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddNode(&Node{
		ID:   outcomeID,
		Kind: NodeKindOutcome,
		Name: "negative",
		Properties: map[string]any{
			"outcome_type":      "evaluation_conversation",
			"verdict":           "negative",
			"quality_score":     0.15,
			"conversation_id":   fixture.Conversation,
			"evaluation_run_id": fixture.RunID,
			"observed_at":       baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"valid_from":        baseAt.Add(20 * time.Minute).Format(time.RFC3339),
			"source_system":     "platform_eval",
		},
	})
	g.AddEdge(&Edge{ID: "decision-target:" + fixture.Conversation, Source: decisionID, Target: threadID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "action1-based-on:" + fixture.Conversation, Source: actionSuccessID, Target: decisionID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "action2-based-on:" + fixture.Conversation, Source: actionReversedID, Target: decisionID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "outcome-target:" + fixture.Conversation, Source: outcomeID, Target: threadID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	writeClaim := func(req graph.ClaimWriteRequest) {
		if _, err := graph.WriteClaim(g, req); err != nil {
			t.Fatalf("write claim %q: %v", req.ID, err)
		}
	}

	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before",
		SubjectID:       fixture.ServiceID,
		Predicate:       "exposure",
		ObjectValue:     "private",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-before"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(-10 * time.Minute),
		RecordedAt:      baseAt.Add(-10 * time.Minute),
		TransactionFrom: baseAt.Add(-10 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after",
		SubjectID:       fixture.ServiceID,
		Predicate:       "exposure",
		ObjectValue:     "public",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":exposure-after"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(18 * time.Minute),
		RecordedAt:      baseAt.Add(18 * time.Minute),
		TransactionFrom: baseAt.Add(18 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:              "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		SubjectID:       fixture.ServiceID,
		Predicate:       "service_tier",
		ObjectValue:     "tier1",
		EvidenceIDs:     []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before"},
		SourceName:      "eval",
		SourceType:      "system",
		SourceSystem:    "platform_eval",
		ObservedAt:      baseAt.Add(-5 * time.Minute),
		RecordedAt:      baseAt.Add(-5 * time.Minute),
		TransactionFrom: baseAt.Add(-5 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
	writeClaim(graph.ClaimWriteRequest{
		ID:                "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after",
		SubjectID:         fixture.ServiceID,
		Predicate:         "service_tier",
		ObjectValue:       "tier0",
		EvidenceIDs:       []string{"evidence:" + fixture.RunID + ":" + fixture.Conversation + ":tier-after"},
		SupersedesClaimID: "claim:evaluation:" + fixture.RunID + ":" + fixture.Conversation + ":tier-before",
		SourceName:        "eval",
		SourceType:        "system",
		SourceSystem:      "platform_eval",
		ObservedAt:        baseAt.Add(19 * time.Minute),
		RecordedAt:        baseAt.Add(19 * time.Minute),
		TransactionFrom:   baseAt.Add(19 * time.Minute),
		Metadata: map[string]any{
			"evaluation_run_id": fixture.RunID,
			"conversation_id":   fixture.Conversation,
		},
	})
}

func tagEvaluationTemporalStageFixture(t *testing.T, g *Graph, runID, conversationID string) {
	t.Helper()
	stageProperties := map[string]map[string]any{
		"decision:evaluation:" + runID + ":" + conversationID + ":turn-1": {
			"stage_id": "stage-2",
		},
		"action:evaluation:" + runID + ":" + conversationID + ":call-1": {
			"stage_id": "stage-1",
		},
		"action:evaluation:" + runID + ":" + conversationID + ":call-2": {
			"stage_id": "stage-2",
		},
		"outcome:evaluation:" + runID + ":" + conversationID: {
			"final_stage_id": "stage-2",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-before": {
			"stage_id": "stage-1",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-after": {
			"stage_id": "stage-2",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-before": {
			"stage_id": "stage-1",
		},
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-after": {
			"stage_id":             "stage-2",
			"previous_stage_id":    "stage-1",
			"supersedes_stage_id":  "stage-1",
			"contradicts_stage_id": "stage-1",
		},
	}
	for nodeID, props := range stageProperties {
		node, ok := g.GetNode(nodeID)
		if !ok {
			t.Fatalf("expected node %q to exist", nodeID)
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		for key, value := range props {
			node.Properties[key] = value
		}
	}
}
