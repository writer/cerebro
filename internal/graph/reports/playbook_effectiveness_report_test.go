package reports

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildPlaybookEffectivenessReport(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-a1",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-3 * time.Hour),
		Stages: []playbookStageFixture{
			{ID: "identify", Name: "Identify Scope", Order: 1, Status: "completed", ObservedAt: now.Add(-170 * time.Minute)},
			{ID: "approve", Name: "Approve Fix", Order: 2, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", PreviousStageID: "identify", ObservedAt: now.Add(-160 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "patch", StageID: "approve", ActionType: "automation", Status: "succeeded", Title: "Apply patch", ObservedAt: now.Add(-155 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-140 * time.Minute),
		},
	})
	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-a2",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-2 * time.Hour),
		Stages: []playbookStageFixture{
			{ID: "identify", Name: "Identify Scope", Order: 1, Status: "completed", ObservedAt: now.Add(-110 * time.Minute)},
			{ID: "approve", Name: "Approve Fix", Order: 2, Status: "failed", ApprovalRequired: true, ApprovalStatus: "rejected", PreviousStageID: "identify", ObservedAt: now.Add(-95 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "rollback", StageID: "approve", ActionType: "manual", Status: "reverted", Title: "Rollback change", ObservedAt: now.Add(-90 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "negative",
			Status:        "completed",
			RollbackState: "rolled_back",
			ObservedAt:    now.Add(-80 * time.Minute),
		},
	})
	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-b1",
		PlaybookID:   "pb-investigate",
		PlaybookName: "Investigate Bucket Drift",
		TenantID:     "tenant-beta",
		TargetID:     "bucket:logs",
		TargetKind:   NodeKindBucket,
		StartedAt:    now.Add(-70 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "inspect", Name: "Inspect Drift", Order: 1, Status: "completed", ObservedAt: now.Add(-60 * time.Minute)},
		},
		Actions: []playbookActionFixture{
			{ID: "collect", StageID: "inspect", ActionType: "automation", Status: "succeeded", Title: "Collect evidence", ObservedAt: now.Add(-55 * time.Minute)},
		},
	})

	report := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.Summary.Runs != 3 {
		t.Fatalf("expected 3 runs, got %#v", report.Summary)
	}
	if report.Summary.CompletedRuns != 2 || report.Summary.SuccessfulRuns != 1 || report.Summary.FailedRuns != 1 {
		t.Fatalf("unexpected completion summary: %#v", report.Summary)
	}
	if report.Summary.RollbackRuns != 1 || report.Summary.ApprovalBottlenecks != 1 || report.Summary.RepeatedTargetExecutions != 1 {
		t.Fatalf("unexpected rollback/repeat summary: %#v", report.Summary)
	}
	if report.Summary.CompletionRatePercent != 66.67 {
		t.Fatalf("expected completion rate 66.67, got %#v", report.Summary.CompletionRatePercent)
	}
	if report.Summary.SuccessRatePercent != 33.33 {
		t.Fatalf("expected success rate 33.33, got %#v", report.Summary.SuccessRatePercent)
	}
	if report.Summary.RollbackRatePercent != 50 {
		t.Fatalf("expected rollback rate 50, got %#v", report.Summary.RollbackRatePercent)
	}
	if report.Summary.RepeatExecutionRatePercent != 33.33 {
		t.Fatalf("expected repeat execution rate 33.33, got %#v", report.Summary.RepeatExecutionRatePercent)
	}
	if report.Summary.AverageCompletionMinutes != 40 {
		t.Fatalf("expected average completion minutes 40, got %#v", report.Summary.AverageCompletionMinutes)
	}
	if report.Summary.MedianSuccessfulCompletionMinutes != 40 {
		t.Fatalf("expected median successful completion minutes 40, got %#v", report.Summary.MedianSuccessfulCompletionMinutes)
	}

	if len(report.Playbooks) != 2 {
		t.Fatalf("expected 2 playbook rollups, got %#v", report.Playbooks)
	}
	if report.Playbooks[0].PlaybookID != "pb-remediate" {
		t.Fatalf("expected pb-remediate first, got %#v", report.Playbooks[0])
	}
	if report.Playbooks[0].Runs != 2 || report.Playbooks[0].RollbackRuns != 1 || report.Playbooks[0].ApprovalBottlenecks != 1 {
		t.Fatalf("unexpected pb-remediate rollup: %#v", report.Playbooks[0])
	}

	if len(report.TargetKinds) != 2 {
		t.Fatalf("expected 2 target-kind rollups, got %#v", report.TargetKinds)
	}
	if report.TargetKinds[0].TargetKind != string(NodeKindService) || report.TargetKinds[0].Runs != 2 {
		t.Fatalf("unexpected target-kind rollup ordering: %#v", report.TargetKinds)
	}

	if len(report.Tenants) != 2 {
		t.Fatalf("expected 2 tenant rollups, got %#v", report.Tenants)
	}
	if report.Tenants[0].TenantID != "tenant-acme" || report.Tenants[0].Runs != 2 {
		t.Fatalf("unexpected tenant rollups: %#v", report.Tenants)
	}

	if len(report.FailureSteps) != 1 {
		t.Fatalf("expected one failure-step rollup, got %#v", report.FailureSteps)
	}
	if report.FailureSteps[0].StageID != "approve" || report.FailureSteps[0].Failures != 1 {
		t.Fatalf("unexpected failure-step rollup: %#v", report.FailureSteps[0])
	}

	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report.Recommendations)
	}
}

func TestBuildPlaybookEffectivenessReportFiltersPartialRunsAndParity(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-a1",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-2 * time.Hour),
		Stages: []playbookStageFixture{
			{ID: "approve", Name: "Approve Fix", Order: 1, Status: "completed", ApprovalRequired: true, ApprovalStatus: "approved", ObservedAt: now.Add(-110 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "completed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-90 * time.Minute),
		},
	})
	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-b1",
		PlaybookID:   "pb-investigate",
		PlaybookName: "Investigate Bucket Drift",
		TenantID:     "tenant-beta",
		TargetID:     "bucket:logs",
		TargetKind:   NodeKindBucket,
		StartedAt:    now.Add(-70 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "inspect", Name: "Inspect Drift", Order: 1, Status: "completed", ObservedAt: now.Add(-60 * time.Minute)},
		},
	})

	filtered := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		PlaybookID:   "pb-remediate",
		TenantID:     "tenant-acme",
		TargetKind:   string(NodeKindService),
		MaxPlaybooks: 10,
	})

	if filtered.Summary.Runs != 1 || filtered.Summary.CompletedRuns != 1 || len(filtered.Playbooks) != 1 {
		t.Fatalf("unexpected filtered report: %#v", filtered)
	}
	if filtered.Playbooks[0].PlaybookID != "pb-remediate" {
		t.Fatalf("expected filtered playbook pb-remediate, got %#v", filtered.Playbooks[0])
	}

	partial := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		TargetKind:   string(NodeKindBucket),
		MaxPlaybooks: 10,
	})
	if partial.Summary.Runs != 1 || partial.Summary.CompletedRuns != 0 || partial.Summary.CompletionRatePercent != 0 {
		t.Fatalf("expected partial run to remain incomplete, got %#v", partial.Summary)
	}

	cloned := BuildPlaybookEffectivenessReport(g.Clone(), PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})
	original := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})
	if !reflect.DeepEqual(original, cloned) {
		t.Fatalf("expected clone parity, got original=%#v cloned=%#v", original, cloned)
	}
}

func TestBuildPlaybookEffectivenessReportIgnoresRollbackSignalsOnIncompleteRuns(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-pending",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-90 * time.Minute),
		Actions: []playbookActionFixture{
			{ID: "rollback", ActionType: "manual", Status: "reverted", Title: "Rollback change", ObservedAt: now.Add(-80 * time.Minute)},
		},
	})

	report := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})

	if report.Summary.CompletedRuns != 0 || report.Summary.RollbackRuns != 0 || report.Summary.RollbackRatePercent != 0 {
		t.Fatalf("expected incomplete rollback signals to be ignored, got %#v", report.Summary)
	}
	if len(report.TargetKinds) != 1 || report.TargetKinds[0].RollbackRuns != 0 || report.TargetKinds[0].RollbackRatePercent != 0 {
		t.Fatalf("expected target-kind rollback metrics to ignore incomplete runs, got %#v", report.TargetKinds)
	}
	if len(report.Tenants) != 1 || report.Tenants[0].RollbackRuns != 0 || report.Tenants[0].RollbackRatePercent != 0 {
		t.Fatalf("expected tenant rollback metrics to ignore incomplete runs, got %#v", report.Tenants)
	}
}

func TestBuildPlaybookEffectivenessReportUsesCompletedRunsForRollbackDenominators(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-rollback",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-2 * time.Hour),
		Actions: []playbookActionFixture{
			{ID: "rollback", ActionType: "manual", Status: "reverted", Title: "Rollback change", ObservedAt: now.Add(-90 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "negative",
			Status:        "completed",
			RollbackState: "rolled_back",
			ObservedAt:    now.Add(-80 * time.Minute),
		},
	})
	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-in-flight",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-70 * time.Minute),
	})

	report := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})

	if report.Summary.Runs != 2 || report.Summary.CompletedRuns != 1 || report.Summary.RollbackRuns != 1 || report.Summary.RollbackRatePercent != 100 {
		t.Fatalf("expected summary rollback rate to use completed runs, got %#v", report.Summary)
	}
	if len(report.TargetKinds) != 1 || report.TargetKinds[0].RollbackRatePercent != 100 {
		t.Fatalf("expected target-kind rollback denominator to use completed runs, got %#v", report.TargetKinds)
	}
	if len(report.Tenants) != 1 || report.Tenants[0].RollbackRatePercent != 100 {
		t.Fatalf("expected tenant rollback denominator to use completed runs, got %#v", report.Tenants)
	}
}

func TestBuildPlaybookEffectivenessReportDoesNotCountRunAsSuccessfulWhenOutcomeStatusFailed(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	g := New()

	addPlaybookEffectivenessFixture(g, playbookRunFixture{
		RunID:        "run-conflicted",
		PlaybookID:   "pb-remediate",
		PlaybookName: "Remediate Public Exposure",
		TenantID:     "tenant-acme",
		TargetID:     "service:payments",
		TargetKind:   NodeKindService,
		StartedAt:    now.Add(-90 * time.Minute),
		Stages: []playbookStageFixture{
			{ID: "approve", Name: "Approve Fix", Order: 1, Status: "failed", ObservedAt: now.Add(-60 * time.Minute)},
		},
		Outcome: &playbookOutcomeFixture{
			Verdict:       "positive",
			Status:        "failed",
			RollbackState: "stable",
			ObservedAt:    now.Add(-30 * time.Minute),
		},
	})

	report := BuildPlaybookEffectivenessReport(g, PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})

	if report.Summary.CompletedRuns != 1 {
		t.Fatalf("expected 1 completed run, got %#v", report.Summary)
	}
	if report.Summary.SuccessfulRuns != 0 {
		t.Fatalf("expected failed status to suppress successful run count, got %#v", report.Summary)
	}
	if report.Summary.FailedRuns != 1 {
		t.Fatalf("expected failed run count, got %#v", report.Summary)
	}
	if report.Playbooks[0].SuccessfulRuns != 0 || report.Playbooks[0].FailedRuns != 1 {
		t.Fatalf("expected playbook rollup to classify conflicted outcome as failed only, got %#v", report.Playbooks[0])
	}
}

func TestBuildPlaybookEffectivenessReportEmptyGraph(t *testing.T) {
	now := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)

	report := BuildPlaybookEffectivenessReport(New(), PlaybookEffectivenessReportOptions{
		Now:          now,
		Window:       7 * 24 * time.Hour,
		MaxPlaybooks: 10,
	})

	if report.Summary.Runs != 0 || report.Summary.CompletedRuns != 0 || report.Summary.SuccessfulRuns != 0 {
		t.Fatalf("expected zeroed summary, got %#v", report.Summary)
	}
	if len(report.Playbooks) != 0 || len(report.Stages) != 0 || len(report.TargetKinds) != 0 || len(report.Tenants) != 0 || len(report.FailureSteps) != 0 {
		t.Fatalf("expected no rollups, got %#v", report)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations for empty graph, got %#v", report)
	}
}

func TestGraphNodePropertyStringsIgnoresNilItems(t *testing.T) {
	node := &Node{
		Properties: map[string]any{
			"target_ids": []any{"target-1", nil, " target-2 "},
		},
	}

	got := graphNodePropertyStrings(node, "target_ids")
	want := []string{"target-1", "target-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected nil items to be ignored, got %#v", got)
	}
}

type playbookRunFixture struct {
	RunID        string
	PlaybookID   string
	PlaybookName string
	TenantID     string
	TargetID     string
	TargetKind   NodeKind
	StartedAt    time.Time
	Stages       []playbookStageFixture
	Actions      []playbookActionFixture
	Outcome      *playbookOutcomeFixture
}

type playbookStageFixture struct {
	ID               string
	Name             string
	Order            int
	Status           string
	ApprovalRequired bool
	ApprovalStatus   string
	PreviousStageID  string
	RetryOfStageID   string
	ObservedAt       time.Time
}

type playbookActionFixture struct {
	ID         string
	StageID    string
	ActionType string
	Status     string
	Title      string
	ObservedAt time.Time
}

type playbookOutcomeFixture struct {
	Verdict       string
	Status        string
	RollbackState string
	ObservedAt    time.Time
}

func addPlaybookEffectivenessFixture(g *Graph, fixture playbookRunFixture) {
	if g == nil {
		return
	}
	if fixture.TargetID != "" {
		if _, ok := g.GetNode(fixture.TargetID); !ok {
			g.AddNode(&Node{
				ID:   fixture.TargetID,
				Kind: fixture.TargetKind,
				Name: fixture.TargetID,
				Properties: map[string]any{
					"observed_at": fixture.StartedAt.Format(time.RFC3339),
					"valid_from":  fixture.StartedAt.Format(time.RFC3339),
				},
			})
		}
	}

	targetIDs := []string{}
	if fixture.TargetID != "" {
		targetIDs = append(targetIDs, fixture.TargetID)
	}

	threadID := "thread:playbook:" + fixture.RunID
	g.AddNode(&Node{
		ID:   threadID,
		Kind: NodeKind("communication_thread"),
		Name: fixture.PlaybookName,
		Properties: map[string]any{
			"thread_id":       fixture.RunID,
			"channel_id":      fixture.PlaybookID,
			"channel_name":    "playbook",
			"source_system":   "platform_playbook",
			"source_event_id": "evt:" + fixture.RunID + ":started",
			"playbook_id":     fixture.PlaybookID,
			"playbook_name":   fixture.PlaybookName,
			"playbook_run_id": fixture.RunID,
			"status":          "started",
			"target_ids":      targetIDs,
			"tenant_id":       fixture.TenantID,
			"observed_at":     fixture.StartedAt.Format(time.RFC3339),
			"valid_from":      fixture.StartedAt.Format(time.RFC3339),
		},
	})

	lastStageID := ""
	for _, stage := range fixture.Stages {
		stageID := "decision:playbook:" + fixture.RunID + ":" + stage.ID
		g.AddNode(&Node{
			ID:   stageID,
			Kind: NodeKindDecision,
			Name: stage.Name,
			Properties: map[string]any{
				"decision_type":     "playbook_stage",
				"source_system":     "platform_playbook",
				"source_event_id":   "evt:" + fixture.RunID + ":stage:" + stage.ID,
				"playbook_id":       fixture.PlaybookID,
				"playbook_name":     fixture.PlaybookName,
				"playbook_run_id":   fixture.RunID,
				"stage_id":          stage.ID,
				"stage_name":        stage.Name,
				"stage_order":       stage.Order,
				"status":            stage.Status,
				"approval_required": stage.ApprovalRequired,
				"approval_status":   stage.ApprovalStatus,
				"previous_stage_id": stage.PreviousStageID,
				"retry_of_stage_id": stage.RetryOfStageID,
				"made_at":           stage.ObservedAt.Format(time.RFC3339),
				"target_ids":        targetIDs,
				"tenant_id":         fixture.TenantID,
				"observed_at":       stage.ObservedAt.Format(time.RFC3339),
				"valid_from":        stage.ObservedAt.Format(time.RFC3339),
			},
		})
		g.AddEdge(&Edge{ID: "decision-thread:" + fixture.RunID + ":" + stage.ID, Source: stageID, Target: threadID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
		if stage.PreviousStageID != "" {
			g.AddEdge(&Edge{ID: "decision-based-on-prev:" + fixture.RunID + ":" + stage.ID, Source: stageID, Target: "decision:playbook:" + fixture.RunID + ":" + stage.PreviousStageID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
		}
		if stage.RetryOfStageID != "" {
			g.AddEdge(&Edge{ID: "decision-based-on-retry:" + fixture.RunID + ":" + stage.ID, Source: stageID, Target: "decision:playbook:" + fixture.RunID + ":" + stage.RetryOfStageID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
		}
		lastStageID = stage.ID
	}

	for _, action := range fixture.Actions {
		actionID := "action:playbook:" + fixture.RunID + ":" + action.ID
		g.AddNode(&Node{
			ID:   actionID,
			Kind: NodeKindAction,
			Name: action.Title,
			Properties: map[string]any{
				"action_type":     action.ActionType,
				"source_system":   "platform_playbook",
				"source_event_id": "evt:" + fixture.RunID + ":action:" + action.ID,
				"playbook_id":     fixture.PlaybookID,
				"playbook_name":   fixture.PlaybookName,
				"playbook_run_id": fixture.RunID,
				"stage_id":        action.StageID,
				"action_id":       action.ID,
				"status":          action.Status,
				"title":           action.Title,
				"performed_at":    action.ObservedAt.Format(time.RFC3339),
				"target_ids":      targetIDs,
				"tenant_id":       fixture.TenantID,
				"observed_at":     action.ObservedAt.Format(time.RFC3339),
				"valid_from":      action.ObservedAt.Format(time.RFC3339),
			},
		})
		g.AddEdge(&Edge{ID: "action-thread:" + fixture.RunID + ":" + action.ID, Source: actionID, Target: threadID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
		if action.StageID != "" {
			g.AddEdge(&Edge{ID: "action-based-on:" + fixture.RunID + ":" + action.ID, Source: actionID, Target: "decision:playbook:" + fixture.RunID + ":" + action.StageID, Kind: EdgeKindBasedOn, Effect: EdgeEffectAllow})
		}
	}

	if fixture.Outcome != nil {
		outcomeID := "outcome:playbook:" + fixture.RunID
		g.AddNode(&Node{
			ID:   outcomeID,
			Kind: NodeKindOutcome,
			Name: fixture.PlaybookName + " " + fixture.Outcome.Verdict,
			Properties: map[string]any{
				"outcome_type":    "playbook_run",
				"source_system":   "platform_playbook",
				"source_event_id": "evt:" + fixture.RunID + ":completed",
				"playbook_id":     fixture.PlaybookID,
				"playbook_name":   fixture.PlaybookName,
				"playbook_run_id": fixture.RunID,
				"verdict":         fixture.Outcome.Verdict,
				"status":          fixture.Outcome.Status,
				"rollback_state":  fixture.Outcome.RollbackState,
				"target_ids":      targetIDs,
				"tenant_id":       fixture.TenantID,
				"final_stage_id":  lastStageID,
				"observed_at":     fixture.Outcome.ObservedAt.Format(time.RFC3339),
				"valid_from":      fixture.Outcome.ObservedAt.Format(time.RFC3339),
			},
		})
		g.AddEdge(&Edge{ID: "outcome-thread:" + fixture.RunID, Source: outcomeID, Target: threadID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
		if lastStageID != "" {
			g.AddEdge(&Edge{ID: "outcome-evaluates:" + fixture.RunID, Source: outcomeID, Target: "decision:playbook:" + fixture.RunID + ":" + lastStageID, Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow})
		}
	}
}
