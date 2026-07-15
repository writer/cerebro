package mcpoperations

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTaskToolSelectionFixtures(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "task_tools", "selection_cases.json"))
	if err != nil {
		t.Fatalf("read selection fixtures: %v", err)
	}
	var cases []TaskSelectionCase
	if err := json.Unmarshal(body, &cases); err != nil {
		t.Fatalf("decode selection fixtures: %v", err)
	}
	if len(cases) < 6 {
		t.Fatalf("selection fixtures = %d, want at least 6", len(cases))
	}
	for _, evalCase := range cases {
		if evalCase.ID == "" || evalCase.UserRequest == "" || evalCase.ExpectedTool == "" {
			t.Fatalf("fixture is incomplete: %#v", evalCase)
		}
		if evalCase.MaximumCallCount < 1 {
			t.Fatalf("fixture %q maximum_call_count = %d", evalCase.ID, evalCase.MaximumCallCount)
		}
		if !IsTaskTool(evalCase.ExpectedTool) {
			t.Fatalf("fixture %q expects non-task tool %q", evalCase.ID, evalCase.ExpectedTool)
		}
		for _, forbidden := range evalCase.ForbiddenTools {
			if IsTaskTool(forbidden) {
				t.Fatalf("fixture %q forbids task tool %q", evalCase.ID, forbidden)
			}
		}
	}
	for _, result := range EvaluateTaskSelection(cases) {
		if !result.Passed {
			t.Fatalf("fixture %q selected %q, want %q", result.ID, result.SelectedTool, result.ExpectedTool)
		}
	}
}

func TestEvidencePacketRequestRejectsExecution(t *testing.T) {
	if _, err := EvidencePacketRequest(StructuredContent{"question": "apply it", "action_stage": "execute"}); !errors.Is(err, ErrInvalidTaskRequest) {
		t.Fatalf("EvidencePacketRequest() error = %v, want ErrInvalidTaskRequest", err)
	}
	request, err := EvidencePacketRequest(StructuredContent{"question": "collect evidence", "action_stage": "dry_run", "target_urns": []any{"urn:b", "urn:a"}})
	if err != nil {
		t.Fatalf("EvidencePacketRequest() error = %v", err)
	}
	if request.Action.HumanApproved || request.Action.Stage != "dry_run" || len(request.Action.TargetURNs) != 2 {
		t.Fatalf("EvidencePacketRequest() = %#v", request)
	}
}

func TestEvidencePacketRequestTreatsNumericZeroAsFalse(t *testing.T) {
	t.Parallel()

	for _, value := range []json.Number{"0", "0.0", "0.00", "0e0", "-0"} {
		request, err := EvidencePacketRequest(StructuredContent{"question": "collect evidence", "allow_preview": value})
		if err != nil {
			t.Fatalf("EvidencePacketRequest(%q) error = %v", value, err)
		}
		if request.AllowPreview {
			t.Fatalf("EvidencePacketRequest(%q).AllowPreview = true, want false", value)
		}
	}

	for _, value := range []json.Number{"1", "1.5", "-2"} {
		request, err := EvidencePacketRequest(StructuredContent{"question": "collect evidence", "allow_preview": value})
		if err != nil {
			t.Fatalf("EvidencePacketRequest(%q) error = %v", value, err)
		}
		if !request.AllowPreview {
			t.Fatalf("EvidencePacketRequest(%q).AllowPreview = false, want true", value)
		}
	}
}

func TestTaskResponsesPreserveStructuredContentPartialErrors(t *testing.T) {
	t.Parallel()

	data := StructuredContent{
		"metadata": map[string]any{
			"partial_errors": []any{"graph lookup failed"},
		},
	}
	risk, err := RiskExplanation(data, false)
	if err != nil {
		t.Fatalf("RiskExplanation() error = %v", err)
	}
	if risk.State != TaskStatePartial || len(risk.PartialReasons) != 1 || risk.PartialReasons[0] != "graph lookup failed" {
		t.Fatalf("RiskExplanation() = %#v, want partial state with graph error", risk)
	}
	graphDependencyFound := false
	for _, dependency := range risk.Dependencies {
		if dependency.Name == "graph_projection" && dependency.State != DependencyUnavailable {
			t.Fatalf("RiskExplanation() graph dependency = %#v, want unavailable", dependency)
		}
		if dependency.Name == "graph_projection" {
			graphDependencyFound = true
		}
	}
	if !graphDependencyFound {
		t.Fatal("RiskExplanation() omitted graph_projection dependency")
	}

	plan, err := ActionPlan(data, true)
	if err != nil {
		t.Fatalf("ActionPlan() error = %v", err)
	}
	if plan.State != TaskStatePartial || len(plan.PartialReasons) != 1 || plan.PartialReasons[0] != "graph lookup failed" {
		t.Fatalf("ActionPlan() = %#v, want partial state with graph error", plan)
	}
}
