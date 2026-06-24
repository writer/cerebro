package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectAIUsageMetricNormalizesCredentialRuntimeUsage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 18, 12, 45, 0, 0, time.UTC)

	event := &cerebrov1.EventEnvelope{
		Id:         "openai-usage-runtime-credential",
		TenantId:   "writer",
		SourceId:   "openai",
		Kind:       "openai.usage_completion",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"api_key_id":         "usage_runtime_key",
			"end_time":           "2026-06-18T13:00:00Z",
			"family":             "usage_completion",
			"id":                 "usage_runtime_1",
			"input_tokens":       "1200",
			"model":              "gpt-4o",
			"num_model_requests": "5",
			"project_id":         "proj_runtime",
			"start_time":         "2026-06-18T12:00:00Z",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(%q) error = %v", event.GetId(), err)
	}

	credentialURN := "urn:cerebro:writer:openai_credential:usage_runtime_key" // #nosec G101 -- test credential identifier, not credential material.
	credential := state.entities[credentialURN]
	if credential == nil {
		t.Fatalf("credential entity %q missing", credentialURN)
	}
	for key, want := range map[string]string{ // #nosec G101 -- test credential identifier, not credential material.
		"api_key_id":      "usage_runtime_key",
		"credential_id":   "usage_runtime_key",
		"credential_type": "credential",
		"credential_use":  "true",
		"last_used_at":    "2026-06-18T13:00:00Z",
		"project_id":      "proj_runtime",
	} {
		if got := credential.Attributes[key]; got != want {
			t.Fatalf("credential attribute %q = %q, want %q", key, got, want)
		}
	}
}
