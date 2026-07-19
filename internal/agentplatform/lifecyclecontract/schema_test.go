package lifecyclecontract

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestLifecycleEventSchemaAcceptsNeutralServiceTransition(t *testing.T) {
	schema := compileLifecycleEventSchema(t)
	event := validServiceTransitionEvent()
	if err := schema.Validate(event); err != nil {
		t.Fatalf("valid lifecycle event rejected: %v", err)
	}
}

func TestLifecycleEventSchemaRejectsEventKindTransitionAxisMismatch(t *testing.T) {
	schema := compileLifecycleEventSchema(t)
	event := validServiceTransitionEvent()
	event["event_kind"] = "work.transition"
	if err := schema.Validate(event); err == nil {
		t.Fatal("lifecycle event accepted a work event with a service transition")
	}
}

func TestGeneratedLifecycleEventRoundTrips(t *testing.T) {
	transition, err := json.Marshal(ServiceTransition{Axis: "service", To: ServiceStateReady})
	if err != nil {
		t.Fatalf("marshal transition: %v", err)
	}
	event := LifecycleEventV1{
		SchemaVersion:  "cerebro.agent-service-lifecycle/v1",
		EventID:        "event.service.ready.1",
		EventKind:      "service.transition",
		Sequence:       1,
		OccurredAt:     "2026-07-16T16:00:00Z",
		ObservedAt:     "2026-07-16T16:00:00Z",
		Scope:          Scope{TenantID: "tenant-example", ServiceID: "agent-service", SubjectID: "service-1"},
		Producer:       Producer{Component: "continuity-controller", Version: "1.0.0"},
		Transition:     transition,
		Reason:         Reason{Code: "readiness.verified", Summary: "Required readiness checks passed."},
		IdempotencyKey: "service-1:ready:1",
		Deployment: &DeploymentIdentity{
			DeploymentID:   "agent-service",
			Generation:     1,
			Version:        "1.0.0",
			ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal lifecycle event: %v", err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode lifecycle event: %v", err)
	}
	if err := compileLifecycleEventSchema(t).Validate(instance); err != nil {
		t.Fatalf("generated lifecycle event rejected by source schema: %v", err)
	}
}

func compileLifecycleEventSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	payload, err := os.ReadFile("../../../schemas/agent-service-lifecycle.schema.json")
	if err != nil {
		t.Fatalf("read lifecycle event schema: %v", err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode lifecycle event schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("agent-service-lifecycle.schema.json", document); err != nil {
		t.Fatalf("add lifecycle event schema: %v", err)
	}
	compiled, err := compiler.Compile("agent-service-lifecycle.schema.json")
	if err != nil {
		t.Fatalf("compile lifecycle event schema: %v", err)
	}
	return compiled
}

func validServiceTransitionEvent() map[string]any {
	return map[string]any{
		"schema_version": "cerebro.agent-service-lifecycle/v1",
		"event_id":       "event.service.ready.1",
		"event_kind":     "service.transition",
		"sequence":       1,
		"occurred_at":    "2026-07-16T16:00:00Z",
		"observed_at":    "2026-07-16T16:00:00Z",
		"scope": map[string]any{
			"tenant_id":    "tenant-example",
			"service_id":   "agent-service",
			"subject_type": "service",
			"subject_id":   "service-1",
		},
		"producer": map[string]any{
			"component": "continuity-controller",
			"version":   "1.0.0",
		},
		"transition": map[string]any{
			"axis": "service",
			"from": "warming",
			"to":   "ready",
		},
		"reason": map[string]any{
			"code":    "readiness.verified",
			"summary": "Required readiness checks passed.",
		},
		"idempotency_key": "service-1:ready:1",
		"deployment": map[string]any{
			"deployment_id":   "agent-service",
			"generation":      1,
			"version":         "1.0.0",
			"artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
}
