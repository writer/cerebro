package executions

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/autonomous"
	"github.com/writer/cerebro/internal/executionstore"
)

func TestSummarizeAutonomousWorkflowRun(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(autonomous.RunRecord{
		ID:           "run-1",
		WorkflowID:   autonomous.WorkflowCredentialExposureResponse,
		RequestedBy:  "alice",
		SecretNodeID: "secret:demo",
		Provider:     "aws",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	summary, ok, err := summarizeAutonomousWorkflowRun(executionstore.RunEnvelope{
		Namespace:   executionstore.NamespaceAutonomousWorkflow,
		RunID:       "run-1",
		Kind:        string(autonomous.WorkflowCredentialExposureResponse),
		Status:      string(autonomous.RunStatusAwaitingApproval),
		Stage:       string(autonomous.RunStageAwaitingApproval),
		SubmittedAt: now,
		UpdatedAt:   now,
		Payload:     payload,
	})
	if err != nil {
		t.Fatalf("summarizeAutonomousWorkflowRun() error = %v", err)
	}
	if !ok {
		t.Fatal("expected autonomous workflow summary to be included")
	}
	if summary.DisplayName != "workflow:credential_exposure_response:secret:demo" {
		t.Fatalf("DisplayName = %q", summary.DisplayName)
	}
	if summary.ScopeID != "secret:demo" || summary.RequestedBy != "alice" || summary.Provider != "aws" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}
