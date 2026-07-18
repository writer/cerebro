package mcpoperations

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTaskToolSelectionFixturesAreComplete(t *testing.T) {
	cases := readTaskSelectionCases(t)
	if len(cases) < 30 {
		t.Fatalf("selection fixtures = %d, want at least 30", len(cases))
	}
	seenIDs := map[string]bool{}
	for _, evalCase := range cases {
		if evalCase.ID == "" || evalCase.UserRequest == "" || evalCase.ExpectedTool == "" {
			t.Fatalf("fixture is incomplete: %#v", evalCase)
		}
		if seenIDs[evalCase.ID] {
			t.Fatalf("fixture ID %q is duplicated", evalCase.ID)
		}
		seenIDs[evalCase.ID] = true
		if evalCase.MaximumCallCount < 1 {
			t.Fatalf("fixture %q maximum_call_count = %d", evalCase.ID, evalCase.MaximumCallCount)
		}
		if !IsTaskTool(evalCase.ExpectedTool) {
			t.Fatalf("fixture %q expects non-task tool %q", evalCase.ID, evalCase.ExpectedTool)
		}
		for _, followup := range evalCase.AllowedFollowupTools {
			if !IsKnownTool(followup) {
				t.Fatalf("fixture %q allows unknown follow-up tool %q", evalCase.ID, followup)
			}
		}
		for _, forbidden := range evalCase.ForbiddenTools {
			if !IsKnownTool(forbidden) {
				t.Fatalf("fixture %q forbids unknown tool %q", evalCase.ID, forbidden)
			}
			if IsTaskTool(forbidden) {
				t.Fatalf("fixture %q forbids task tool %q", evalCase.ID, forbidden)
			}
		}
	}
}

func TestScoreTaskSelectionUsesAdvertisedMetadata(t *testing.T) {
	descriptors := []TaskToolDescriptor{
		{Name: "cerebro.findings.search", Title: "Search Findings", Description: "Find open findings by severity."},
		{Name: "cerebro.assets.search", Title: "Search Assets", Description: "Find inventory assets by type."},
	}
	report := ScoreTaskSelection([]TaskSelectionCase{{ID: "finding", UserRequest: "Find open critical findings", ExpectedTool: "cerebro.findings.search"}}, descriptors)
	if report.Correct != 1 || report.AccuracyBP != 10000 || report.Results[0].SelectedTool != "cerebro.findings.search" || report.Results[0].Margin <= 0 {
		t.Fatalf("report = %#v", report)
	}
}

func TestValidateTaskSelectionBaselineRejectsRegression(t *testing.T) {
	report := TaskSelectionReport{
		Contract:             TaskSelectionReportContract,
		AccuracyBP:           9000,
		ToolCoverageBP:       10000,
		MinimumCorrectMargin: 3,
		Incorrect:            1,
		PerTool:              []TaskSelectionToolScore{{Tool: "cerebro.health", Cases: 2, Correct: 2}},
	}
	baseline := TaskSelectionBaseline{
		Contract:                   TaskSelectionReportContract,
		MinimumAccuracyBP:          10000,
		MinimumToolCoverageBP:      10000,
		MinimumCasesPerTool:        3,
		MinimumCorrectMargin:       4,
		MaximumIncorrect:           0,
		MaximumUnselected:          0,
		MaximumAmbiguousSelections: 0,
	}
	err := ValidateTaskSelectionBaseline(report, baseline)
	if !errors.Is(err, ErrTaskSelectionRegression) {
		t.Fatalf("ValidateTaskSelectionBaseline() error = %v, want ErrTaskSelectionRegression", err)
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

func TestTaskResponseStateAllowsKnownStatesOnly(t *testing.T) {
	tests := []struct {
		name     string
		response TaskResponse
		want     string
	}{
		{name: "value response", response: TaskResponse{State: TaskStateComplete}, want: TaskStateComplete},
		{name: "partial response", response: TaskResponse{State: TaskStatePartial}, want: TaskStatePartial},
		{name: "blocked response", response: TaskResponse{State: TaskStateBlocked}, want: TaskStateBlocked},
		{name: "unknown state", response: TaskResponse{State: "running"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := TaskResponseState(test.response); got != test.want {
				t.Fatalf("TaskResponseState() = %q, want %q", got, test.want)
			}
		})
	}
}

func readTaskSelectionCases(t *testing.T) []TaskSelectionCase {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "task_tools", "selection_cases.json"))
	if err != nil {
		t.Fatalf("read selection fixtures: %v", err)
	}
	var cases []TaskSelectionCase
	if err := json.Unmarshal(body, &cases); err != nil {
		t.Fatalf("decode selection fixtures: %v", err)
	}
	return cases
}
