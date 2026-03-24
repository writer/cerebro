package graphingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func TestLoadDefaultConfig(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	if len(config.Mappings) == 0 {
		t.Fatal("expected at least one mapping")
	}
}

func TestParseConfig_NormalizesContractDefaults(t *testing.T) {
	payload := []byte(`
mappings:
  - name: sample
    source: ensemble.tap.test.sample
    nodes:
      - id: service:{{data.service}}
        kind: service
`)
	config, err := ParseConfig(payload)
	if err != nil {
		t.Fatalf("parse config failed: %v", err)
	}
	if config.APIVersion != defaultMappingConfigAPIVersion {
		t.Fatalf("expected default apiVersion %q, got %q", defaultMappingConfigAPIVersion, config.APIVersion)
	}
	if config.Kind != defaultMappingConfigKind {
		t.Fatalf("expected default kind %q, got %q", defaultMappingConfigKind, config.Kind)
	}
	if len(config.Mappings) != 1 {
		t.Fatalf("expected one mapping, got %d", len(config.Mappings))
	}
	if config.Mappings[0].APIVersion != defaultMappingConfigAPIVersion {
		t.Fatalf("expected mapping apiVersion default, got %q", config.Mappings[0].APIVersion)
	}
	if config.Mappings[0].ContractVersion != defaultMappingContractVersion {
		t.Fatalf("expected mapping contractVersion default %q, got %q", defaultMappingContractVersion, config.Mappings[0].ContractVersion)
	}
}

func TestMapperApply_GithubPRMerged(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 8, 22, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-pr-1",
		Type:   "ensemble.tap.github.pull_request.merged",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"repository":      "payments-api",
			"number":          42,
			"title":           "Improve reconciliation retries",
			"merged_by":       "alice",
			"merged_by_email": "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping to match event, got %#v", result)
	}

	service, ok := g.GetNode("service:payments-api")
	if !ok || service == nil {
		t.Fatalf("expected service node to be created, got %#v", service)
	}
	if service.Kind != graph.NodeKindService {
		t.Fatalf("expected service node kind %q, got %q", graph.NodeKindService, service.Kind)
	}
	repositoryNode, ok := g.GetNode("repository:github:payments-api")
	if !ok || repositoryNode == nil {
		t.Fatalf("expected repository node to be created, got %#v", repositoryNode)
	}
	if repositoryNode.Kind != graph.NodeKindRepository {
		t.Fatalf("expected repository node kind %q, got %q", graph.NodeKindRepository, repositoryNode.Kind)
	}
	prNode, ok := g.GetNode("pull_request:payments-api:42")
	if !ok || prNode == nil {
		t.Fatalf("expected pull request node to be created, got %#v", prNode)
	}
	if prNode.Kind != graph.NodeKindPullRequest {
		t.Fatalf("expected pull request node kind %q, got %q", graph.NodeKindPullRequest, prNode.Kind)
	}
	if observedAt, ok := service.PropertyValue("observed_at"); !ok || strings.TrimSpace(stringValue(observedAt)) == "" {
		t.Fatalf("expected observed_at metadata on service node, got %#v", service.PropertyMap())
	}

	outEdges := g.GetOutEdges("person:alice@example.com")
	foundContribution := false
	for _, edge := range outEdges {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == "service:payments-api" {
			foundContribution = true
			break
		}
	}
	if !foundContribution {
		t.Fatalf("expected person -> service interacted_with edge, got %#v", outEdges)
	}
	foundRepositoryTarget := false
	for _, edge := range g.GetOutEdges("pull_request:payments-api:42") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindTargets && edge.Target == "repository:github:payments-api" {
			foundRepositoryTarget = true
			break
		}
	}
	if !foundRepositoryTarget {
		t.Fatalf("expected pull request -> repository target edge, got %#v", g.GetOutEdges("pull_request:payments-api:42"))
	}
}

func TestMapperApply_NoMatch(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(graph.New(), events.CloudEvent{
		ID:     "evt-other-1",
		Type:   "ensemble.tap.unknown.unmapped",
		Time:   time.Now().UTC(),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"repository": "payments-api"},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected mapping not to match, got %#v", result)
	}
}

func TestMapperApply_EvaluationLifecycleEvents(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	conversationTime := time.Date(2026, 3, 22, 19, 0, 0, 0, time.UTC)
	turnTime := conversationTime.Add(2 * time.Minute)
	toolTime := turnTime.Add(15 * time.Second)
	costTime := toolTime.Add(10 * time.Second)

	eventsToApply := []events.CloudEvent{
		{
			ID:     "evt-conv-1",
			Type:   "evaluation.conversation.completed",
			Time:   conversationTime,
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"evaluation_run_id": "run-1",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"summary":           "resolved the customer issue",
				"verdict":           "positive",
				"quality_score":     0.93,
				"target_ids":        []any{"service:payments", "bucket:logs"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-conv-1",
				"observed_at":       conversationTime.Format(time.RFC3339),
				"valid_from":        conversationTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-turn-1",
			Type:   "evaluation.turn.completed",
			Time:   turnTime,
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"turn_id":           "turn-1",
				"evaluation_run_id": "run-1",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"decision_type":     "tool_selection",
				"status":            "completed",
				"rationale":         "needed repository context",
				"target_ids":        []any{"service:payments", "bucket:logs"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-turn-1",
				"observed_at":       turnTime.Format(time.RFC3339),
				"valid_from":        turnTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-tool-1",
			Type:   "evaluation.agent.tool_call",
			Time:   toolTime,
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"turn_id":           "turn-1",
				"tool_call_id":      "call-1",
				"tool_name":         "repo.read_file",
				"status":            "succeeded",
				"evaluation_run_id": "run-1",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"target_ids":        []any{"service:payments", "bucket:logs"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-tool-1",
				"observed_at":       toolTime.Format(time.RFC3339),
				"valid_from":        toolTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-cost-1",
			Type:   "evaluation.agent.cost",
			Time:   costTime,
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"turn_id":           "turn-1",
				"tool_call_id":      "call-1",
				"cost_id":           "cost-1",
				"amount_usd":        0.12,
				"currency":          "USD",
				"token_count":       532,
				"model":             "gpt-5.4",
				"evaluation_run_id": "run-1",
				"target_ids":        []any{"service:payments", "bucket:logs"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-cost-1",
				"observed_at":       costTime.Format(time.RFC3339),
				"valid_from":        costTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
	}

	for _, event := range eventsToApply {
		result, err := mapper.Apply(g, event)
		if err != nil {
			t.Fatalf("mapper apply failed for %q: %v", event.Type, err)
		}
		if !result.Matched {
			t.Fatalf("expected mapping to match event %q, got %#v", event.Type, result)
		}
		if result.NodesRejected > 0 || result.EdgesRejected > 0 || result.EventsRejected > 0 {
			t.Fatalf("expected %q to be accepted, got %#v", event.Type, result)
		}
	}

	threadNode, ok := g.GetNode("thread:evaluation:run-1:conv-1")
	if !ok || threadNode == nil {
		t.Fatalf("expected evaluation conversation thread node, got %#v", threadNode)
	}
	if threadNode.Kind != graph.NodeKindThread {
		t.Fatalf("expected thread node kind %q, got %q", graph.NodeKindThread, threadNode.Kind)
	}
	if tenantID, _ := threadNode.PropertyValue("tenant_id"); stringValue(tenantID) != "tenant-a" {
		t.Fatalf("expected thread tenant_id tenant-a, got %#v", threadNode.PropertyMap())
	}

	decisionNode, ok := g.GetNode("decision:evaluation:run-1:conv-1:turn-1")
	if !ok || decisionNode == nil {
		t.Fatalf("expected evaluation decision node, got %#v", decisionNode)
	}
	if decisionNode.Kind != graph.NodeKindDecision {
		t.Fatalf("expected decision node kind %q, got %q", graph.NodeKindDecision, decisionNode.Kind)
	}
	if got := graphStringSlice(decisionNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "bucket:logs" {
		t.Fatalf("expected decision target_ids to preserve structured values, got %#v", decisionNode.Properties["target_ids"])
	}

	actionNode, ok := g.GetNode("action:evaluation:run-1:conv-1:call-1")
	if !ok || actionNode == nil {
		t.Fatalf("expected evaluation action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	if got := graphStringSlice(actionNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "bucket:logs" {
		t.Fatalf("expected action target_ids to preserve structured values, got %#v", actionNode.Properties["target_ids"])
	}

	observationNode, ok := g.GetNode("observation:evaluation_cost:run-1:conv-1:cost-1")
	if !ok || observationNode == nil {
		t.Fatalf("expected evaluation cost observation node, got %#v", observationNode)
	}
	if observationNode.Kind != graph.NodeKindObservation {
		t.Fatalf("expected observation node kind %q, got %q", graph.NodeKindObservation, observationNode.Kind)
	}
	if got := graphStringSlice(observationNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "bucket:logs" {
		t.Fatalf("expected observation target_ids to preserve structured values, got %#v", observationNode.Properties["target_ids"])
	}

	outcomeNode, ok := g.GetNode("outcome:evaluation:run-1:conv-1")
	if !ok || outcomeNode == nil {
		t.Fatalf("expected evaluation outcome node, got %#v", outcomeNode)
	}
	if outcomeNode.Kind != graph.NodeKindOutcome {
		t.Fatalf("expected outcome node kind %q, got %q", graph.NodeKindOutcome, outcomeNode.Kind)
	}
	if got := graphStringSlice(outcomeNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "bucket:logs" {
		t.Fatalf("expected outcome target_ids to preserve structured values, got %#v", outcomeNode.Properties["target_ids"])
	}

	if findEdge(g, "decision:evaluation:run-1:conv-1:turn-1", "thread:evaluation:run-1:conv-1", graph.EdgeKindTargets) == nil {
		t.Fatalf("expected decision to target conversation thread, got %#v", g.GetOutEdges("decision:evaluation:run-1:conv-1:turn-1"))
	}
	if findEdge(g, "action:evaluation:run-1:conv-1:call-1", "decision:evaluation:run-1:conv-1:turn-1", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected action to be based on decision, got %#v", g.GetOutEdges("action:evaluation:run-1:conv-1:call-1"))
	}
	if findEdge(g, "observation:evaluation_cost:run-1:conv-1:cost-1", "action:evaluation:run-1:conv-1:call-1", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected observation to be based on action, got %#v", g.GetOutEdges("observation:evaluation_cost:run-1:conv-1:cost-1"))
	}
	if findEdge(g, "outcome:evaluation:run-1:conv-1", "thread:evaluation:run-1:conv-1", graph.EdgeKindTargets) == nil {
		t.Fatalf("expected outcome to target conversation thread, got %#v", g.GetOutEdges("outcome:evaluation:run-1:conv-1"))
	}
}

func TestMapperApply_PlaybookLifecycleEvents(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:operator@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Operator",
		Properties: map[string]any{
			"email": "operator@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	runTime := time.Date(2026, 3, 23, 18, 0, 0, 0, time.UTC)
	stage1Time := runTime.Add(2 * time.Minute)
	stage2SkipTime := stage1Time.Add(3 * time.Minute)
	stage2RetryTime := stage2SkipTime.Add(2 * time.Minute)
	actionTime := stage2RetryTime.Add(20 * time.Second)
	outcomeTime := actionTime.Add(45 * time.Second)

	eventsToApply := []events.CloudEvent{
		{
			ID:     "evt-playbook-run-1",
			Type:   "platform.playbook.run.started",
			Time:   runTime,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id":  "run-1",
				"playbook_id":      "pb-42",
				"playbook_name":    "Contain Payment Incident",
				"playbook_version": "2026.03.23",
				"status":           "running",
				"trigger_id":       "trigger-123",
				"trigger_type":     "signal",
				"signal_id":        "signal-456",
				"operator_id":      "user-7",
				"operator_email":   "operator@example.com",
				"automation_id":    "automation-9",
				"automation_name":  "incident-conductor",
				"target_ids":       []any{"service:payments", "incident:inc-9"},
				"source_system":    "platform_playbook",
				"source_event_id":  "source-playbook-run-1",
				"observed_at":      runTime.Format(time.RFC3339),
				"valid_from":       runTime.Format(time.RFC3339),
				"tenant_id":        "tenant-a",
			},
		},
		{
			ID:     "evt-playbook-stage-1",
			Type:   "platform.playbook.stage.completed",
			Time:   stage1Time,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id":   "run-1",
				"playbook_id":       "pb-42",
				"playbook_name":     "Contain Payment Incident",
				"stage_id":          "stage-1",
				"stage_name":        "Request Approval",
				"stage_order":       1,
				"status":            "completed",
				"approval_required": true,
				"approval_status":   "approved",
				"approver_email":    "operator@example.com",
				"operator_email":    "operator@example.com",
				"automation_id":     "automation-9",
				"target_ids":        []any{"service:payments", "incident:inc-9"},
				"source_system":     "platform_playbook",
				"source_event_id":   "source-playbook-stage-1",
				"observed_at":       stage1Time.Format(time.RFC3339),
				"valid_from":        stage1Time.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-playbook-stage-2-skipped",
			Type:   "platform.playbook.stage.completed",
			Time:   stage2SkipTime,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id":   "run-1",
				"playbook_id":       "pb-42",
				"playbook_name":     "Contain Payment Incident",
				"stage_id":          "stage-2",
				"stage_name":        "Disable Writes",
				"stage_order":       2,
				"status":            "skipped",
				"previous_stage_id": "stage-1",
				"operator_email":    "operator@example.com",
				"automation_id":     "automation-9",
				"target_ids":        []any{"service:payments", "incident:inc-9"},
				"source_system":     "platform_playbook",
				"source_event_id":   "source-playbook-stage-2-skipped",
				"observed_at":       stage2SkipTime.Format(time.RFC3339),
				"valid_from":        stage2SkipTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-playbook-stage-2-retry",
			Type:   "platform.playbook.stage.completed",
			Time:   stage2RetryTime,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id":   "run-1",
				"playbook_id":       "pb-42",
				"playbook_name":     "Contain Payment Incident",
				"stage_id":          "stage-2-retry",
				"stage_name":        "Disable Writes Retry",
				"stage_order":       2,
				"status":            "completed",
				"previous_stage_id": "stage-1",
				"retry_of_stage_id": "stage-2",
				"operator_email":    "operator@example.com",
				"automation_id":     "automation-9",
				"target_ids":        []any{"service:payments", "incident:inc-9"},
				"source_system":     "platform_playbook",
				"source_event_id":   "source-playbook-stage-2-retry",
				"observed_at":       stage2RetryTime.Format(time.RFC3339),
				"valid_from":        stage2RetryTime.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-playbook-action-1",
			Type:   "platform.playbook.action.executed",
			Time:   actionTime,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id": "run-1",
				"playbook_id":     "pb-42",
				"playbook_name":   "Contain Payment Incident",
				"stage_id":        "stage-2-retry",
				"action_id":       "action-1",
				"action_type":     "disable_writes",
				"title":           "Disable writes on primary service",
				"summary":         "blocked new writes during containment",
				"status":          "completed",
				"operator_email":  "operator@example.com",
				"automation_id":   "automation-9",
				"target_ids":      []any{"service:payments", "incident:inc-9"},
				"source_system":   "platform_playbook",
				"source_event_id": "source-playbook-action-1",
				"observed_at":     actionTime.Format(time.RFC3339),
				"valid_from":      actionTime.Format(time.RFC3339),
				"tenant_id":       "tenant-a",
			},
		},
		{
			ID:     "evt-playbook-outcome-1",
			Type:   "platform.playbook.run.completed",
			Time:   outcomeTime,
			Source: "urn:platform:playbooks",
			Data: map[string]any{
				"playbook_run_id":       "run-1",
				"playbook_id":           "pb-42",
				"playbook_name":         "Contain Payment Incident",
				"final_stage_id":        "stage-2-retry",
				"verdict":               "mixed",
				"status":                "completed",
				"summary":               "writes disabled, rollback later restored normal traffic",
				"rollback_state":        "rolled_back",
				"completed_stage_count": 2,
				"skipped_stage_count":   1,
				"failed_stage_count":    0,
				"operator_email":        "operator@example.com",
				"automation_id":         "automation-9",
				"target_ids":            []any{"service:payments", "incident:inc-9"},
				"source_system":         "platform_playbook",
				"source_event_id":       "source-playbook-outcome-1",
				"observed_at":           outcomeTime.Format(time.RFC3339),
				"valid_from":            outcomeTime.Format(time.RFC3339),
				"tenant_id":             "tenant-a",
			},
		},
	}

	for _, event := range eventsToApply {
		result, err := mapper.Apply(g, event)
		if err != nil {
			t.Fatalf("mapper apply failed for %q: %v", event.Type, err)
		}
		if !result.Matched {
			t.Fatalf("expected mapping to match event %q, got %#v", event.Type, result)
		}
		if result.NodesRejected > 0 || result.EdgesRejected > 0 || result.EventsRejected > 0 {
			t.Fatalf("expected %q to be accepted, got %#v", event.Type, result)
		}
	}

	threadNode, ok := g.GetNode("thread:playbook:run-1")
	if !ok || threadNode == nil {
		t.Fatalf("expected playbook thread node, got %#v", threadNode)
	}
	if threadNode.Kind != graph.NodeKindThread {
		t.Fatalf("expected thread node kind %q, got %q", graph.NodeKindThread, threadNode.Kind)
	}
	if got := graphStringSlice(threadNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "incident:inc-9" {
		t.Fatalf("expected thread target_ids to preserve structured values, got %#v", threadNode.Properties["target_ids"])
	}
	if got := stringValue(threadNode.Properties["playbook_version"]); got != "2026.03.23" {
		t.Fatalf("expected playbook_version to persist across playbook updates, got %#v", threadNode.PropertyMap())
	}
	if got := stringValue(threadNode.Properties["trigger_id"]); got != "trigger-123" {
		t.Fatalf("expected trigger_id to persist across playbook updates, got %#v", threadNode.PropertyMap())
	}
	if got := stringValue(threadNode.Properties["trigger_type"]); got != "signal" {
		t.Fatalf("expected trigger_type to persist across playbook updates, got %#v", threadNode.PropertyMap())
	}
	if got := stringValue(threadNode.Properties["signal_id"]); got != "signal-456" {
		t.Fatalf("expected signal_id to persist across playbook updates, got %#v", threadNode.PropertyMap())
	}

	skippedStageNode, ok := g.GetNode("decision:playbook:run-1:stage-2")
	if !ok || skippedStageNode == nil {
		t.Fatalf("expected skipped stage decision node, got %#v", skippedStageNode)
	}
	if got := stringValue(skippedStageNode.Properties["status"]); got != "skipped" {
		t.Fatalf("expected skipped stage status, got %#v", skippedStageNode.PropertyMap())
	}
	if findEdge(g, "decision:playbook:run-1:stage-2", "decision:playbook:run-1:stage-1", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected skipped stage to sequence after stage-1, got %#v", g.GetOutEdges("decision:playbook:run-1:stage-2"))
	}

	retryStageNode, ok := g.GetNode("decision:playbook:run-1:stage-2-retry")
	if !ok || retryStageNode == nil {
		t.Fatalf("expected retry stage decision node, got %#v", retryStageNode)
	}
	if got := stringValue(retryStageNode.Properties["retry_of_stage_id"]); got != "stage-2" {
		t.Fatalf("expected retry_of_stage_id on retry stage, got %#v", retryStageNode.PropertyMap())
	}
	if findEdge(g, "decision:playbook:run-1:stage-2-retry", "decision:playbook:run-1:stage-2", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected retry stage to link to prior attempt, got %#v", g.GetOutEdges("decision:playbook:run-1:stage-2-retry"))
	}

	actionNode, ok := g.GetNode("action:playbook:run-1:action-1")
	if !ok || actionNode == nil {
		t.Fatalf("expected playbook action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	if got := graphStringSlice(actionNode.Properties["target_ids"]); len(got) != 2 || got[0] != "service:payments" || got[1] != "incident:inc-9" {
		t.Fatalf("expected action target_ids to preserve structured values, got %#v", actionNode.Properties["target_ids"])
	}
	if findEdge(g, "action:playbook:run-1:action-1", "decision:playbook:run-1:stage-2-retry", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected action to be based on retry stage, got %#v", g.GetOutEdges("action:playbook:run-1:action-1"))
	}

	outcomeNode, ok := g.GetNode("outcome:playbook:run-1")
	if !ok || outcomeNode == nil {
		t.Fatalf("expected playbook outcome node, got %#v", outcomeNode)
	}
	if outcomeNode.Kind != graph.NodeKindOutcome {
		t.Fatalf("expected outcome node kind %q, got %q", graph.NodeKindOutcome, outcomeNode.Kind)
	}
	if got := stringValue(outcomeNode.Properties["rollback_state"]); got != "rolled_back" {
		t.Fatalf("expected rollback_state to be preserved, got %#v", outcomeNode.PropertyMap())
	}
	if findEdge(g, "outcome:playbook:run-1", "decision:playbook:run-1:stage-2-retry", graph.EdgeKindEvaluates) == nil {
		t.Fatalf("expected outcome to evaluate final stage decision, got %#v", g.GetOutEdges("outcome:playbook:run-1"))
	}
}

func TestMapperApply_PlaybookRunStartedPartialRun(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:operator@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Operator",
		Properties: map[string]any{
			"email": "operator@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	startedAt := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-playbook-partial",
		Type:   "platform.playbook.run.started",
		Time:   startedAt,
		Source: "urn:platform:playbooks",
		Data: map[string]any{
			"playbook_run_id": "run-partial",
			"playbook_id":     "pb-99",
			"playbook_name":   "Partial Rollout",
			"status":          "running",
			"operator_email":  "operator@example.com",
			"target_ids":      []any{"service:api"},
			"source_system":   "platform_playbook",
			"source_event_id": "source-playbook-partial",
			"observed_at":     startedAt.Format(time.RFC3339),
			"valid_from":      startedAt.Format(time.RFC3339),
			"tenant_id":       "tenant-a",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected playbook run start to match, got %#v", result)
	}
	if _, ok := g.GetNode("thread:playbook:run-partial"); !ok {
		t.Fatalf("expected playbook thread node for partial run")
	}
	if _, ok := g.GetNode("decision:playbook:run-partial:stage-1"); ok {
		t.Fatal("did not expect stage decision node for partial run")
	}
	if _, ok := g.GetNode("action:playbook:run-partial:action-1"); ok {
		t.Fatal("did not expect action node for partial run")
	}
	if _, ok := g.GetNode("outcome:playbook:run-partial"); ok {
		t.Fatal("did not expect outcome node for partial run")
	}
}

func TestMapperApply_EvaluationStageClaimChains(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	base := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	eventsToApply := []events.CloudEvent{
		{
			ID:     "evt-stage-1",
			Type:   "evaluation.turn.completed",
			Time:   base,
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"turn_id":           "turn-1",
				"evaluation_run_id": "run-stage",
				"decision_type":     "initial_assessment",
				"status":            "completed",
				"rationale":         "stage one concluded the customer impact was limited",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"stage_id":          "stage-1",
				"stage_name":        "Initial assessment",
				"stage_order":       1,
				"target_ids":        []any{"service:payments"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-stage-1",
				"observed_at":       base.Format(time.RFC3339),
				"valid_from":        base.Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-stage-2",
			Type:   "evaluation.turn.completed",
			Time:   base.Add(2 * time.Minute),
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":      "conv-1",
				"turn_id":              "turn-2",
				"evaluation_run_id":    "run-stage",
				"decision_type":        "corrected_assessment",
				"status":               "completed",
				"rationale":            "stage two found contradicting deployment evidence",
				"agent_id":             "agent-1",
				"agent_email":          "agent@example.com",
				"stage_id":             "stage-2",
				"stage_name":           "Correction",
				"stage_order":          2,
				"previous_stage_id":    "stage-1",
				"supersedes_stage_id":  "stage-1",
				"contradicts_stage_id": "stage-1",
				"target_ids":           []any{"service:payments"},
				"source_system":        "platform_eval",
				"source_event_id":      "source-stage-2",
				"observed_at":          base.Add(2 * time.Minute).Format(time.RFC3339),
				"valid_from":           base.Add(2 * time.Minute).Format(time.RFC3339),
				"tenant_id":            "tenant-a",
			},
		},
		{
			ID:     "evt-stage-tool",
			Type:   "evaluation.agent.tool_call",
			Time:   base.Add(3 * time.Minute),
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"turn_id":           "turn-2",
				"tool_call_id":      "call-1",
				"tool_name":         "graph.lookup",
				"status":            "succeeded",
				"evaluation_run_id": "run-stage",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"stage_id":          "stage-2",
				"stage_name":        "Correction",
				"target_ids":        []any{"service:payments"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-stage-tool",
				"observed_at":       base.Add(3 * time.Minute).Format(time.RFC3339),
				"valid_from":        base.Add(3 * time.Minute).Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
		{
			ID:     "evt-stage-outcome",
			Type:   "evaluation.conversation.completed",
			Time:   base.Add(5 * time.Minute),
			Source: "urn:platform:eval",
			Data: map[string]any{
				"conversation_id":   "conv-1",
				"evaluation_run_id": "run-stage",
				"agent_id":          "agent-1",
				"agent_email":       "agent@example.com",
				"summary":           "the correction stage overturned the initial claim",
				"verdict":           "negative",
				"quality_score":     0.22,
				"final_stage_id":    "stage-2",
				"target_ids":        []any{"service:payments"},
				"source_system":     "platform_eval",
				"source_event_id":   "source-stage-outcome",
				"observed_at":       base.Add(5 * time.Minute).Format(time.RFC3339),
				"valid_from":        base.Add(5 * time.Minute).Format(time.RFC3339),
				"tenant_id":         "tenant-a",
			},
		},
	}

	for _, event := range eventsToApply {
		result, err := mapper.Apply(g, event)
		if err != nil {
			t.Fatalf("mapper apply failed for %q: %v", event.Type, err)
		}
		if !result.Matched {
			t.Fatalf("expected mapping to match event %q, got %#v", event.Type, result)
		}
		if result.NodesRejected > 0 || result.EdgesRejected > 0 || result.EventsRejected > 0 {
			t.Fatalf("expected %q to be accepted, got %#v", event.Type, result)
		}
	}

	stage1Claim, ok := g.GetNode("claim:evaluation:run-stage:conv-1:stage-1")
	if !ok || stage1Claim == nil {
		t.Fatalf("expected stage-1 claim node, got %#v", stage1Claim)
	}
	stage2Claim, ok := g.GetNode("claim:evaluation:run-stage:conv-1:stage-2")
	if !ok || stage2Claim == nil {
		t.Fatalf("expected stage-2 claim node, got %#v", stage2Claim)
	}
	if got := stringValue(stage2Claim.Properties["stage_id"]); got != "stage-2" {
		t.Fatalf("expected stage_id on stage-2 claim, got %#v", stage2Claim.PropertyMap())
	}
	if got := stringValue(stage2Claim.Properties["previous_stage_id"]); got != "stage-1" {
		t.Fatalf("expected previous_stage_id on stage-2 claim, got %#v", stage2Claim.PropertyMap())
	}

	stage1Evidence, ok := g.GetNode("evidence:evaluation:run-stage:conv-1:stage-1")
	if !ok || stage1Evidence == nil {
		t.Fatalf("expected stage-1 evidence node, got %#v", stage1Evidence)
	}
	if got := stringValue(stage1Evidence.Properties["detail"]); !strings.Contains(got, "limited") {
		t.Fatalf("expected rationale detail on stage-1 evidence, got %#v", stage1Evidence.PropertyMap())
	}

	stageSource, ok := g.GetNode("source:evaluation_agent:agent@example.com")
	if !ok || stageSource == nil {
		t.Fatalf("expected evaluation source node, got %#v", stageSource)
	}

	if findEdge(g, "claim:evaluation:run-stage:conv-1:stage-1", "source:evaluation_agent:agent@example.com", graph.EdgeKindAssertedBy) == nil {
		t.Fatalf("expected stage-1 claim to be asserted by agent source, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:stage-1"))
	}
	if findEdge(g, "claim:evaluation:run-stage:conv-1:stage-1", "evidence:evaluation:run-stage:conv-1:stage-1", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected stage-1 claim to be based on evidence, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:stage-1"))
	}
	if findEdge(g, "claim:evaluation:run-stage:conv-1:stage-2", "claim:evaluation:run-stage:conv-1:stage-1", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected stage-2 claim to chain off stage-1, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:stage-2"))
	}
	if findEdge(g, "claim:evaluation:run-stage:conv-1:stage-2", "claim:evaluation:run-stage:conv-1:stage-1", graph.EdgeKindSupersedes) == nil {
		t.Fatalf("expected stage-2 claim to supersede stage-1, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:stage-2"))
	}
	if findEdge(g, "claim:evaluation:run-stage:conv-1:stage-2", "claim:evaluation:run-stage:conv-1:stage-1", graph.EdgeKindContradicts) == nil {
		t.Fatalf("expected stage-2 claim to contradict stage-1, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:stage-2"))
	}
	if findEdge(g, "action:evaluation:run-stage:conv-1:call-1", "claim:evaluation:run-stage:conv-1:stage-2", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected action to be based on stage-2 claim, got %#v", g.GetOutEdges("action:evaluation:run-stage:conv-1:call-1"))
	}
	if findEdge(g, "outcome:evaluation:run-stage:conv-1", "claim:evaluation:run-stage:conv-1:stage-2", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected outcome to be based on final stage claim, got %#v", g.GetOutEdges("outcome:evaluation:run-stage:conv-1"))
	}
	if findEdge(g, "claim:evaluation:run-stage:conv-1:final", "claim:evaluation:run-stage:conv-1:stage-2", graph.EdgeKindBasedOn) == nil {
		t.Fatalf("expected outcome claim to be chained to final stage claim, got %#v", g.GetOutEdges("claim:evaluation:run-stage:conv-1:final"))
	}
}

func TestMapperApply_SupportTicketUpdated(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-support-1",
		Type:   "ensemble.tap.support.ticket.updated",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"ticket_id":   "12345",
			"subject":     "Payment failures",
			"status":      "open",
			"priority":    "high",
			"update_id":   "u-1",
			"update_type": "comment",
			"agent_email": "agent@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	ticketNode, ok := g.GetNode("ticket:support:12345")
	if !ok || ticketNode == nil || ticketNode.Kind != graph.NodeKindTicket {
		t.Fatalf("expected support ticket node, got %#v", ticketNode)
	}
	actionNode, ok := g.GetNode("action:support_update:12345:u-1")
	if !ok || actionNode == nil {
		t.Fatalf("expected support update action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected support action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	assignmentFound := false
	for _, edge := range g.GetOutEdges("person:agent@example.com") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindAssignedTo && edge.Target == "ticket:support:12345" {
			assignmentFound = true
			break
		}
	}
	if !assignmentFound {
		t.Fatalf("expected assigned_to edge to support ticket, got %#v", g.GetOutEdges("person:agent@example.com"))
	}
	if _, ok := g.GetNode("company:"); ok {
		t.Fatal("did not expect empty optional company node")
	}
}

func TestMapperApply_SupportTicketCreatesConditionalBusinessNodes(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	_, err = mapper.Apply(g, events.CloudEvent{
		ID:     "evt-support-conditional-1",
		Type:   "ensemble.tap.support.ticket.updated",
		Time:   time.Date(2026, 3, 9, 18, 5, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"ticket_id":         "12346",
			"subject":           "Renewal blocker",
			"status":            "open",
			"priority":          "high",
			"update_id":         "u-2",
			"update_type":       "escalation",
			"agent_email":       "agent@example.com",
			"customer_id":       "cust-42",
			"customer_name":     "Acme West",
			"company_id":        "comp-42",
			"company_name":      "Acme Corp",
			"subscription_id":   "sub-42",
			"subscription_name": "Enterprise Annual",
			"subscription_plan": "enterprise",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	for _, id := range []string{"customer:cust-42", "company:comp-42", "subscription:sub-42"} {
		if _, ok := g.GetNode(id); !ok {
			t.Fatalf("expected conditional node %q to exist", id)
		}
	}
	foundCustomerSubscription := false
	for _, edge := range g.GetOutEdges("customer:cust-42") {
		if edge != nil && edge.Kind == graph.EdgeKindSubscribedTo && edge.Target == "subscription:sub-42" {
			foundCustomerSubscription = true
			break
		}
	}
	if !foundCustomerSubscription {
		t.Fatalf("expected customer -> subscription edge, got %#v", g.GetOutEdges("customer:cust-42"))
	}
}

func TestMapperConditionMatches_TreatsScalarValuesAsPresent(t *testing.T) {
	mapper := &Mapper{}
	context := map[string]any{
		"data": map[string]any{
			"customer_zero":  "0",
			"customer_false": "false",
			"customer_null":  "null",
			"customer_empty": "",
		},
	}

	for _, tc := range []struct {
		name string
		when string
		want bool
	}{
		{name: "zero string", when: "{{data.customer_zero}}", want: true},
		{name: "false string", when: "{{data.customer_false}}", want: true},
		{name: "null string", when: "{{data.customer_null}}", want: true},
		{name: "empty string", when: "{{data.customer_empty}}", want: false},
	} {
		if got := mapper.conditionMatches(tc.when, context, events.CloudEvent{}); got != tc.want {
			t.Fatalf("%s: conditionMatches(%q) = %v, want %v", tc.name, tc.when, got, tc.want)
		}
	}
}

func TestMapperApply_CalendarMeetingUsesMeetingKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:organizer@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Organizer",
		Properties: map[string]any{
			"email": "organizer@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "payments",
		Properties: map[string]any{
			"service_id": "payments",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-meeting-1",
		Type:   "ensemble.tap.calendar.meeting.recorded",
		Time:   time.Date(2026, 3, 9, 18, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"meeting_id":      "mtg-1",
			"title":           "Payments Reliability Review",
			"organizer_email": "organizer@example.com",
			"starts_at":       "2026-03-09T18:30:00Z",
			"ends_at":         "2026-03-09T19:00:00Z",
			"service":         "payments",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	meeting, ok := g.GetNode("meeting:mtg-1")
	if !ok || meeting == nil {
		t.Fatalf("expected meeting node, got %#v", meeting)
	}
	if meeting.Kind != graph.NodeKindMeeting {
		t.Fatalf("expected meeting node kind %q, got %q", graph.NodeKindMeeting, meeting.Kind)
	}
}

func TestMapperApply_SlackThreadMessageUsesActionKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:author@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Author",
		Properties: map[string]any{
			"email": "author@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-slack-1",
		Type:   "ensemble.tap.slack.thread.message_posted",
		Time:   time.Date(2026, 3, 9, 19, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"channel_id":   "C123",
			"thread_ts":    "1700000000.000100",
			"message_ts":   "1700000000.000200",
			"channel_name": "payments-alerts",
			"text":         "Investigating elevated timeout rate",
			"author_email": "author@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	thread, ok := g.GetNode("thread:slack:C123:1700000000.000100")
	if !ok || thread == nil || thread.Kind != graph.NodeKindThread {
		t.Fatalf("expected thread node, got %#v", thread)
	}
	actionNode, ok := g.GetNode("action:slack_message:C123:1700000000.000200")
	if !ok || actionNode == nil {
		t.Fatalf("expected slack action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected slack action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}

	targetFound := false
	for _, edge := range g.GetOutEdges("action:slack_message:C123:1700000000.000200") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindTargets && edge.Target == "thread:slack:C123:1700000000.000100" {
			targetFound = true
			break
		}
	}
	if !targetFound {
		t.Fatalf("expected slack action to target thread, got %#v", g.GetOutEdges("action:slack_message:C123:1700000000.000200"))
	}
}

func TestMapperApply_GithubCheckRunCreatesRepositoryAndWorkflow(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:author@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Author",
		Properties: map[string]any{
			"email": "author@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-check-1",
		Type:   "ensemble.tap.github.check_run.completed",
		Time:   time.Date(2026, 3, 10, 15, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"repository":   "payments-api",
			"check_run_id": "123",
			"check_name":   "build-and-test",
			"status":       "completed",
			"conclusion":   "success",
			"actor_email":  "author@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	workflow, ok := g.GetNode("ci_workflow:github:payments-api:build-and-test")
	if !ok || workflow == nil || workflow.Kind != graph.NodeKindCIWorkflow {
		t.Fatalf("expected ci_workflow node, got %#v", workflow)
	}
	repositoryNode, ok := g.GetNode("repository:github:payments-api")
	if !ok || repositoryNode == nil || repositoryNode.Kind != graph.NodeKindRepository {
		t.Fatalf("expected repository node, got %#v", repositoryNode)
	}
	checkRun, ok := g.GetNode("check_run:payments-api:123")
	if !ok || checkRun == nil {
		t.Fatalf("expected check_run node, got %#v", checkRun)
	}
	foundWorkflowLink := false
	for _, edge := range g.GetOutEdges("check_run:payments-api:123") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "ci_workflow:github:payments-api:build-and-test" {
			foundWorkflowLink = true
			break
		}
	}
	if !foundWorkflowLink {
		t.Fatalf("expected check_run -> ci_workflow link, got %#v", g.GetOutEdges("check_run:payments-api:123"))
	}
}

func TestMapperApply_CIPipelineCreatesWorkflow(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()

	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-pipeline-1",
		Type:   "ensemble.tap.ci.pipeline.completed",
		Time:   time.Date(2026, 3, 10, 16, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"service":       "payments",
			"pipeline_id":   "pipe-1",
			"pipeline_name": "Deploy Payments",
			"run_id":        "run-9",
			"actor_email":   "build@example.com",
			"status":        "success",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	workflow, ok := g.GetNode("ci_workflow:ci:payments:pipe-1")
	if !ok || workflow == nil || workflow.Kind != graph.NodeKindCIWorkflow {
		t.Fatalf("expected ci_workflow node, got %#v", workflow)
	}
	pipelineRun, ok := g.GetNode("pipeline_run:payments:pipe-1:run-9")
	if !ok || pipelineRun == nil {
		t.Fatalf("expected pipeline_run node, got %#v", pipelineRun)
	}
	foundWorkflowLink := false
	for _, edge := range g.GetOutEdges("pipeline_run:payments:pipe-1:run-9") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "ci_workflow:ci:payments:pipe-1" {
			foundWorkflowLink = true
			break
		}
	}
	if !foundWorkflowLink {
		t.Fatalf("expected pipeline_run -> ci_workflow link, got %#v", g.GetOutEdges("pipeline_run:payments:pipe-1:run-9"))
	}
}

func TestMapperApply_SalesCallLoggedUsesActionKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:rep@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Rep",
		Properties: map[string]any{
			"email": "rep@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-sales-1",
		Type:   "ensemble.tap.sales.call.logged",
		Time:   time.Date(2026, 3, 9, 20, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"call_id":          "call-77",
			"contact_id":       "cont-123",
			"contact_name":     "Ari Lee",
			"contact_email":    "ari@example.com",
			"summary":          "Reviewed renewal and expansion timeline",
			"duration_minutes": 28,
			"rep_email":        "rep@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	contact, ok := g.GetNode("contact:cont-123")
	if !ok || contact == nil || contact.Kind != graph.NodeKindContact {
		t.Fatalf("expected contact node, got %#v", contact)
	}
	actionNode, ok := g.GetNode("action:sales_call:call-77")
	if !ok || actionNode == nil {
		t.Fatalf("expected sales action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected sales action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	if _, ok := g.GetNode("company:"); ok {
		t.Fatal("did not expect empty optional company node")
	}
}

func TestMapperApply_SalesCallLoggedCreatesConditionalBusinessNodes(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:rep@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Rep",
		Properties: map[string]any{
			"email": "rep@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	_, err = mapper.Apply(g, events.CloudEvent{
		ID:     "evt-sales-conditional-1",
		Type:   "ensemble.tap.sales.call.logged",
		Time:   time.Date(2026, 3, 9, 20, 10, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"call_id":            "call-78",
			"contact_id":         "cont-124",
			"contact_name":       "Ari Lee",
			"contact_email":      "ari@example.com",
			"summary":            "Qualified expansion and next procurement steps",
			"duration_minutes":   31,
			"rep_email":          "rep@example.com",
			"company_id":         "comp-7",
			"company_name":       "Northwind",
			"company_domain":     "northwind.example",
			"lead_id":            "lead-7",
			"lead_name":          "Northwind Expansion",
			"lead_source":        "conference",
			"opportunity_id":     "opp-7",
			"opportunity_name":   "Northwind Expansion FY26",
			"opportunity_stage":  "qualified",
			"opportunity_amount": 120000,
			"deal_id":            "deal-7",
			"deal_name":          "Northwind Annual",
			"deal_stage":         "proposal",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	for _, id := range []string{"company:comp-7", "lead:lead-7", "opportunity:opp-7", "deal:deal-7"} {
		if _, ok := g.GetNode(id); !ok {
			t.Fatalf("expected conditional node %q to exist", id)
		}
	}
	foundContactCompany := false
	for _, edge := range g.GetOutEdges("contact:cont-124") {
		if edge != nil && edge.Kind == graph.EdgeKindWorksAt && edge.Target == "company:comp-7" {
			foundContactCompany = true
			break
		}
	}
	if !foundContactCompany {
		t.Fatalf("expected contact -> company works_at edge, got %#v", g.GetOutEdges("contact:cont-124"))
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidWritesToDeadLetter(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}
	dlqPath := filepath.Join(t.TempDir(), "mapper.dlq.jsonl")
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-invalid-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 21, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}
	if result.NodesRejected != 1 || result.DeadLettered != 1 {
		t.Fatalf("expected one rejected/dead-lettered node, got %#v", result)
	}
	if _, ok := g.GetNode("test:entity:1"); ok {
		t.Fatal("expected invalid node to be rejected")
	}
	stats := mapper.Stats()
	if stats.NodesRejected != 1 || stats.DeadLettered != 1 {
		t.Fatalf("unexpected mapper stats: %#v", stats)
	}
	payload, err := os.ReadFile(dlqPath)
	if err != nil {
		t.Fatalf("read dead-letter file failed: %v", err)
	}
	if !strings.Contains(string(payload), "nonexistent_kind") {
		t.Fatalf("expected dead-letter payload to mention invalid kind, got %s", string(payload))
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidEventContract(t *testing.T) {
	config := MappingConfig{
		APIVersion: "cerebro.graphingest/v1alpha1",
		Mappings: []EventMapping{
			{
				Name:            "event_contract",
				Source:          "ensemble.tap.test.contract.updated",
				ContractVersion: "1.0.0",
				SchemaURL:       "https://schemas.example.com/event-contract.json",
				DataEnums: map[string][]string{
					"status": []string{"open", "closed"},
				},
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service}}",
						Kind:     "service",
						Name:     "{{data.service}}",
						Provider: "test",
						Properties: map[string]any{
							"service_id": "{{data.service}}",
						},
					},
				},
			},
		},
	}
	dlqPath := filepath.Join(t.TempDir(), "event-contract.dlq.jsonl")
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:            "evt-contract-bad-1",
		Type:          "ensemble.tap.test.contract.updated",
		Time:          time.Date(2026, 3, 9, 22, 10, 0, 0, time.UTC),
		Source:        "urn:ensemble:tap",
		SchemaVersion: "0.9.0",
		DataSchema:    "https://schemas.example.com/other.json",
		Data: map[string]any{
			"status": "invalid_status",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.EventsRejected != 1 || result.DeadLettered != 1 {
		t.Fatalf("expected one rejected/dead-lettered event, got %#v", result)
	}
	if result.Matched {
		t.Fatalf("expected Matched=false when contract validation rejects event, got %#v", result)
	}
	if len(result.NodesUpserted) > 0 || len(result.EdgesUpserted) > 0 {
		t.Fatalf("expected no writes after event-contract rejection, got %#v", result)
	}

	stats := mapper.Stats()
	if stats.EventsRejected != 1 {
		t.Fatalf("expected events_rejected=1, got %#v", stats)
	}
	if stats.EventRejectByCode[string(graph.SchemaIssueInvalidEventContract)] < 1 {
		t.Fatalf("expected invalid_event_contract reject code, got %#v", stats.EventRejectByCode)
	}
	payload, err := os.ReadFile(dlqPath)
	if err != nil {
		t.Fatalf("read dead-letter file failed: %v", err)
	}
	if !strings.Contains(string(payload), string(graph.SchemaIssueInvalidEventContract)) {
		t.Fatalf("expected dead-letter payload to include invalid_event_contract, got %s", string(payload))
	}
}

func TestMapperApply_EvaluationTurnCompletedStageWithoutAgentEmailSkipsAssertedByEdge(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	dlqPath := filepath.Join(t.TempDir(), "mapper-stage-no-agent.dlq.jsonl")
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}

	g := graph.New()
	event := events.CloudEvent{
		ID:     "evt-stage-no-agent",
		Type:   "evaluation.turn.completed",
		Time:   time.Date(2026, 3, 23, 19, 0, 0, 0, time.UTC),
		Source: "urn:platform:eval",
		Data: map[string]any{
			"conversation_id":   "conv-no-agent",
			"turn_id":           "turn-1",
			"evaluation_run_id": "run-no-agent",
			"decision_type":     "initial_assessment",
			"status":            "completed",
			"rationale":         "stage concluded without attributed agent identity",
			"stage_id":          "stage-1",
			"stage_name":        "Initial assessment",
			"stage_order":       1,
			"target_ids":        []any{"service:payments"},
			"source_system":     "platform_eval",
			"source_event_id":   "source-stage-no-agent",
			"observed_at":       "2026-03-23T19:00:00Z",
			"valid_from":        "2026-03-23T19:00:00Z",
			"tenant_id":         "tenant-a",
		},
	}

	result, err := mapper.Apply(g, event)
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping to match event, got %#v", result)
	}
	if result.EventsRejected != 0 || result.NodesRejected != 0 || result.EdgesRejected != 0 || result.DeadLettered != 0 {
		t.Fatalf("expected stage event without agent_email to be accepted, got %#v", result)
	}

	claimID := "claim:evaluation:run-no-agent:conv-no-agent:stage-1"
	if _, ok := g.GetNode(claimID); !ok {
		t.Fatalf("expected staged claim node %q to exist", claimID)
	}
	for _, edge := range g.GetOutEdges(claimID) {
		if edge.Kind == graph.EdgeKindAssertedBy {
			t.Fatalf("expected no asserted_by edge without agent_email, got %#v", edge)
		}
	}

	payload, err := os.ReadFile(dlqPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read dead-letter file failed: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("expected no dead-letter payload, got %s", string(payload))
	}
}

func TestMapperApply_EnrichesContractMetadataPointers(t *testing.T) {
	config := MappingConfig{
		APIVersion: "cerebro.graphingest/v1alpha1",
		Mappings: []EventMapping{
			{
				Name:            "metadata_pointers",
				Source:          "ensemble.tap.test.metadata.updated",
				ContractVersion: "2.1.0",
				SchemaURL:       "https://schemas.example.com/metadata.json",
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service}}",
						Kind:     "service",
						Name:     "{{data.service}}",
						Provider: "test",
						Properties: map[string]any{
							"service_id": "{{data.service}}",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:            "evt-metadata-1",
		Type:          "ensemble.tap.test.metadata.updated",
		Time:          time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source:        "urn:ensemble:tap",
		SchemaVersion: "2.1.0",
		DataSchema:    "https://schemas.example.com/metadata.json",
		Data: map[string]any{
			"service": "payments",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.EventsRejected != 0 || result.NodesRejected != 0 || result.EdgesRejected != 0 {
		t.Fatalf("expected no rejections, got %#v", result)
	}

	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatalf("expected node service:payments, got %#v", node)
	}
	for _, key := range []string{"source_schema_url", "producer_fingerprint", "contract_version", "contract_api_version", "mapping_name", "event_type", "recorded_at", "transaction_from"} {
		value, ok := node.PropertyValue(key)
		if !ok || strings.TrimSpace(valueToString(value)) == "" {
			t.Fatalf("expected metadata pointer %q on node, got %#v", key, node.PropertyMap())
		}
	}
}

func TestMapperApply_WarnValidationAllowsInvalidWrites(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "warn_invalid_kind",
				Source: "ensemble.tap.test.invalid.warn",
				Nodes: []NodeMapping{
					{
						ID:       "test:entity:warn",
						Kind:     "nonexistent_kind",
						Name:     "Invalid But Allowed",
						Provider: "test",
					},
				},
			},
		},
	}
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationWarn,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-invalid-warn-1",
		Type:   "ensemble.tap.test.invalid.warn",
		Time:   time.Date(2026, 3, 9, 21, 5, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.NodesRejected != 0 {
		t.Fatalf("expected warn mode not to reject writes, got %#v", result)
	}
	node, ok := g.GetNode("test:entity:warn")
	if !ok || node == nil {
		t.Fatalf("expected invalid node to be written in warn mode, got %#v", node)
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidProvenance(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "invalid_provenance",
				Source: "ensemble.tap.test.provenance",
				Nodes: []NodeMapping{
					{
						ID:       "service:payments",
						Kind:     "service",
						Name:     "Payments",
						Provider: "test",
						Properties: map[string]any{
							"service_id":  "payments",
							"observed_at": "{{data.observed_at}}",
							"valid_from":  "{{data.valid_from}}",
							"confidence":  "{{data.confidence}}",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(graph.New(), events.CloudEvent{
		ID:     "evt-provenance-1",
		Type:   "ensemble.tap.test.provenance",
		Time:   time.Date(2026, 3, 9, 21, 20, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"observed_at": "not-a-time",
			"valid_from":  "2026-03-09T21:00:00Z",
			"confidence":  "not-a-number",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.NodesRejected != 0 || len(result.NodesUpserted) != 1 {
		t.Fatalf("expected mapper to normalize weak provenance instead of rejecting, got %#v", result)
	}
	g := graph.New()
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-provenance-2",
		Type:   "ensemble.tap.test.provenance",
		Time:   time.Date(2026, 3, 9, 21, 20, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"observed_at": "not-a-time",
			"valid_from":  "2026-03-09T21:00:00Z",
			"confidence":  "not-a-number",
		},
	}); err != nil {
		t.Fatalf("second mapper apply failed: %v", err)
	}
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatalf("expected normalized node write, got %#v", node)
	}
	for _, key := range []string{"observed_at", "valid_from", "recorded_at", "transaction_from", "confidence"} {
		value, ok := node.PropertyValue(key)
		if !ok || strings.TrimSpace(valueToString(value)) == "" {
			t.Fatalf("expected normalized metadata key %q, got %#v", key, node.PropertyMap())
		}
	}
}

func TestMapperStatsIncludesPerSourceCounters(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "github_match",
				Source: "ensemble.tap.github.pull_request.opened",
				Nodes: []NodeMapping{
					{
						ID:       "service:payments",
						Kind:     "service",
						Name:     "Payments",
						Provider: "github",
						Properties: map[string]any{
							"service_id": "payments",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}
	g := graph.New()
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-github-1",
		Type:   "ensemble.tap.github.pull_request.opened",
		Time:   time.Date(2026, 3, 9, 21, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	}); err != nil {
		t.Fatalf("mapper apply github failed: %v", err)
	}
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-slack-1",
		Type:   "ensemble.tap.slack.unknown",
		Time:   time.Date(2026, 3, 9, 21, 31, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	}); err != nil {
		t.Fatalf("mapper apply slack failed: %v", err)
	}

	stats := mapper.Stats()
	github := stats.SourceStats["github"]
	if github.EventsProcessed != 1 || github.EventsMatched != 1 {
		t.Fatalf("unexpected github source stats: %#v", github)
	}
	slack := stats.SourceStats["slack"]
	if slack.EventsProcessed != 1 || slack.EventsUnmatched != 1 {
		t.Fatalf("unexpected slack source stats: %#v", slack)
	}
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}

func graphStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if rendered := strings.TrimSpace(stringValue(entry)); rendered != "" {
				out = append(out, rendered)
			}
		}
		return out
	default:
		return nil
	}
}
