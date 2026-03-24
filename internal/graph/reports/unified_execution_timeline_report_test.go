package reports

import (
	"slices"
	"testing"
	"time"
)

func TestBuildUnifiedExecutionTimelineReport(t *testing.T) {
	now := time.Date(2026, 3, 24, 1, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-eval",
		Conversation: "conv-1",
		ServiceID:    "service:payments:eval",
		BaseAt:       now.Add(-2 * time.Hour),
	})
	tagEvaluationTemporalStageFixture(t, g, "run-eval", "conv-1")
	tagEvaluationTimelineTenant(t, g, "run-eval", "conv-1", "tenant-eval")

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-playbook",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments:playbook",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-90 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "approve", Name: "Approve Fix", Order: 1, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", ObservedAt: now.Add(-80 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "patch", StageID: "approve", ActionType: "patch_service", Status: "succeeded", Title: "Patch Service", ObservedAt: now.Add(-75 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-70 * time.Minute),
		},
	})

	report := BuildUnifiedExecutionTimelineReport(g, UnifiedExecutionTimelineReportOptions{
		Now:       now,
		Window:    6 * time.Hour,
		MaxEvents: 50,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.Summary.EvaluationRuns != 1 || report.Summary.PlaybookRuns != 1 {
		t.Fatalf("expected one eval run and one playbook run, got %#v", report.Summary)
	}
	if report.Summary.Threads != 2 {
		t.Fatalf("expected 2 threads, got %#v", report.Summary)
	}
	if report.Summary.Decisions != 2 || report.Summary.Actions != 3 || report.Summary.Outcomes != 2 {
		t.Fatalf("unexpected core event counts: %#v", report.Summary)
	}
	if report.Summary.Claims != 4 || report.Summary.Evidence != 4 {
		t.Fatalf("expected evaluation claims/evidence to be included, got %#v", report.Summary)
	}
	if report.Summary.Events != len(report.Events) {
		t.Fatalf("expected summary event count to match payload length, summary=%d events=%d", report.Summary.Events, len(report.Events))
	}

	seenKinds := make(map[string]int)
	for i, event := range report.Events {
		seenKinds[event.Kind]++
		if i > 0 && report.Events[i-1].At.After(event.At) {
			t.Fatalf("expected timeline to stay sorted: prev=%#v current=%#v", report.Events[i-1], event)
		}
	}
	for _, kind := range []string{"communication_thread", "decision", "action", "outcome", "claim", "evidence"} {
		if seenKinds[kind] == 0 {
			t.Fatalf("expected timeline to include kind %q, got %#v", kind, seenKinds)
		}
	}

	evalClaim := timelineEventByID(report.Events, "claim:evaluation:run-eval:conv-1:exposure-before")
	if evalClaim == nil {
		t.Fatal("expected scoped evaluation claim event")
	}
	if evalClaim.Workflow != "evaluation" || evalClaim.EvaluationRunID != "run-eval" || evalClaim.ConversationID != "conv-1" {
		t.Fatalf("unexpected evaluation claim scope: %#v", evalClaim)
	}
	if !slices.Contains(evalClaim.EvidenceIDs, "evidence:run-eval:conv-1:exposure-before") {
		t.Fatalf("expected evaluation claim event to retain direct evidence ids, got %#v", evalClaim)
	}

	playbookAction := timelineEventByID(report.Events, "action:playbook:run-playbook:patch")
	if playbookAction == nil {
		t.Fatal("expected playbook action event")
	}
	if playbookAction.Workflow != "playbook" || playbookAction.PlaybookID != "pb-remediate" || playbookAction.TenantID != "tenant-acme" {
		t.Fatalf("unexpected playbook action scope: %#v", playbookAction)
	}
	if !slices.Contains(playbookAction.TargetKinds, string(NodeKindService)) {
		t.Fatalf("expected playbook action target kind to include service, got %#v", playbookAction.TargetKinds)
	}
}

func TestBuildUnifiedExecutionTimelineReportFilters(t *testing.T) {
	now := time.Date(2026, 3, 24, 1, 0, 0, 0, time.UTC)
	g := New()

	addEvaluationTemporalAnalysisFixture(t, g, evaluationTemporalAnalysisFixture{
		RunID:        "run-eval",
		Conversation: "conv-1",
		ServiceID:    "service:payments:eval",
		BaseAt:       now.Add(-2 * time.Hour),
	})
	tagEvaluationTimelineTenant(t, g, "run-eval", "conv-1", "tenant-a")

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-playbook",
		PlaybookID:   "pb-db-remediate",
		PlaybookName: "Repair Database",
		TenantID:     "tenant-b",
		TargetID:     "database:orders",
		TargetKind:   NodeKind("database"),
		StartedAt:    now.Add(-80 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "repair", Name: "Repair", Order: 1, Status: "completed", ObservedAt: now.Add(-70 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-60 * time.Minute),
		},
	})

	playbookOnly := BuildUnifiedExecutionTimelineReport(g, UnifiedExecutionTimelineReportOptions{
		Now:        now,
		Window:     6 * time.Hour,
		TenantID:   "tenant-b",
		PlaybookID: "pb-db-remediate",
		TargetKind: "database",
		MaxEvents:  50,
	})

	if playbookOnly.Summary.EvaluationRuns != 0 || playbookOnly.Summary.PlaybookRuns != 1 {
		t.Fatalf("expected only playbook scope after filtering, got %#v", playbookOnly.Summary)
	}
	for _, event := range playbookOnly.Events {
		if event.Workflow != "playbook" || event.TenantID != "tenant-b" {
			t.Fatalf("expected only tenant-b playbook events, got %#v", event)
		}
		if !slices.Contains(event.TargetKinds, "database") {
			t.Fatalf("expected database target kind after filter, got %#v", event.TargetKinds)
		}
	}

	evalOnly := BuildUnifiedExecutionTimelineReport(g, UnifiedExecutionTimelineReportOptions{
		Now:             now,
		Window:          6 * time.Hour,
		TenantID:        "tenant-a",
		EvaluationRunID: "run-eval",
		MaxEvents:       50,
	})

	if evalOnly.Summary.PlaybookRuns != 0 || evalOnly.Summary.EvaluationRuns != 1 {
		t.Fatalf("expected only eval scope after filtering, got %#v", evalOnly.Summary)
	}
	for _, event := range evalOnly.Events {
		if event.Workflow != "evaluation" || event.EvaluationRunID != "run-eval" || event.TenantID != "tenant-a" {
			t.Fatalf("expected only tenant-a evaluation events, got %#v", event)
		}
	}
}

func TestBuildUnifiedExecutionTimelineReportIncludesMissingStageIDsAndDeterministicOutcomeOrdering(t *testing.T) {
	now := time.Date(2026, 3, 24, 1, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-playbook",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-90 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "approve", Name: "Approve Fix", Order: 1, Status: "completed", ObservedAt: now.Add(-80 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "unstaged", StageID: "", ActionType: "notify", Status: "queued", Title: "Notify Owner", ObservedAt: now.Add(-75 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-60 * time.Minute),
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:playbook:run-playbook:retry",
		Kind: NodeKindOutcome,
		Name: "retry",
		Properties: map[string]any{
			"outcome_type":    "playbook_run",
			"source_system":   "platform_playbook",
			"playbook_id":     "pb-remediate",
			"playbook_name":   "Remediate Exposure",
			"playbook_run_id": "run-playbook",
			"verdict":         "neutral",
			"status":          "completed",
			"rollback_state":  "stable",
			"target_ids":      []string{"service:payments"},
			"tenant_id":       "tenant-acme",
			"observed_at":     now.Add(-60 * time.Minute).Format(time.RFC3339),
			"valid_from":      now.Add(-60 * time.Minute).Format(time.RFC3339),
		},
	})

	report := BuildUnifiedExecutionTimelineReport(g, UnifiedExecutionTimelineReportOptions{
		Now:       now,
		Window:    6 * time.Hour,
		MaxEvents: 50,
	})

	unstagedAction := timelineEventByID(report.Events, "action:playbook:run-playbook:unstaged")
	if unstagedAction == nil {
		t.Fatal("expected unstaged action to remain in the timeline")
	}
	if unstagedAction.StageID != "" {
		t.Fatalf("expected missing stage id to remain empty, got %#v", unstagedAction)
	}

	outcomeIDs := make([]string, 0, 2)
	for _, event := range report.Events {
		if event.Kind == "outcome" {
			outcomeIDs = append(outcomeIDs, event.ID)
		}
	}
	expected := []string{"outcome:playbook:run-playbook", "outcome:playbook:run-playbook:retry"}
	if !slices.Equal(outcomeIDs, expected) {
		t.Fatalf("expected deterministic outcome ordering %v, got %v", expected, outcomeIDs)
	}
}

func timelineEventByID(events []UnifiedExecutionTimelineEvent, id string) *UnifiedExecutionTimelineEvent {
	for i := range events {
		if events[i].ID == id {
			return &events[i]
		}
	}
	return nil
}

func tagEvaluationTimelineTenant(t *testing.T, g *Graph, runID, conversationID, tenantID string) {
	t.Helper()
	nodeIDs := []string{
		"service:payments:eval",
		"thread:evaluation:" + runID + ":" + conversationID,
		"decision:evaluation:" + runID + ":" + conversationID + ":turn-1",
		"action:evaluation:" + runID + ":" + conversationID + ":call-1",
		"action:evaluation:" + runID + ":" + conversationID + ":call-2",
		"outcome:evaluation:" + runID + ":" + conversationID,
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-before",
		"claim:evaluation:" + runID + ":" + conversationID + ":exposure-after",
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-before",
		"claim:evaluation:" + runID + ":" + conversationID + ":tier-after",
	}
	for _, nodeID := range nodeIDs {
		node, ok := g.GetNode(nodeID)
		if !ok {
			continue
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		node.Properties["tenant_id"] = tenantID
	}
}
