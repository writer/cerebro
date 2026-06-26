package grc

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestReadVantaControlTestEmitsControlReferences(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyControlTest)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(control_test) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(control_test).Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["control_id"]; got != "control-1" {
		t.Fatalf("control_id = %q, want first linked control", got)
	}
	if got := attrs["control_ids"]; got != "control-1,control-2" {
		t.Fatalf("control_ids = %q, want linked controls", got)
	}
	if got := attrs["control_external_ids"]; got != "CC6.2,CC7.1" {
		t.Fatalf("control_external_ids = %q, want linked control external ids", got)
	}
}

func TestAttributesForControlTestPreservesControlReferencePairs(t *testing.T) {
	attrs := attributesFor(settings{provider: "vanta", tenantID: "writer"}, familyControlTest, grcRecord{
		Values: map[string]any{
			"id": "test-1",
			"controls": []any{
				map[string]any{"id": "control-1"},
				map[string]any{"id": "control-2", "externalId": "CC7.1"},
				map[string]any{"id": "control-3", "externalId": "CC7.1"},
			},
		},
	})

	if got := attrs["control_references"]; got != "control-1=;control-2=CC7.1;control-3=CC7.1" {
		t.Fatalf("control_references = %q, want stable id/external pairs", got)
	}
}
