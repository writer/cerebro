package k8saudit

import (
	"context"
	"testing"
)

func TestAdapterNormalizeExecEvent(t *testing.T) {
	raw := []byte(`{
		"auditID": "audit-1",
		"stage": "ResponseComplete",
		"verb": "create",
		"requestURI": "/api/v1/namespaces/prod/pods/web-7f9f/exec",
		"userAgent": "kubectl/v1.31.0",
		"sourceIPs": ["203.0.113.5"],
		"requestReceivedTimestamp": "2026-03-15T18:25:00Z",
		"user": {"username": "alice@example.com", "groups": ["system:authenticated"]},
		"objectRef": {
			"resource": "pods",
			"namespace": "prod",
			"name": "web-7f9f",
			"subresource": "exec",
			"apiVersion": "v1"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	observation := observations[0]
	if observation.Kind != "k8s_audit" {
		t.Fatalf("kind = %s, want k8s_audit", observation.Kind)
	}
	if observation.PrincipalID != "alice@example.com" {
		t.Fatalf("principal_id = %q, want %q", observation.PrincipalID, "alice@example.com")
	}
	if observation.ResourceID != "pods:prod:web-7f9f:exec" {
		t.Fatalf("resource_id = %q, want %q", observation.ResourceID, "pods:prod:web-7f9f:exec")
	}
	if len(observation.Tags) != 1 || observation.Tags[0] != "kubectl_exec" {
		t.Fatalf("tags = %#v, want [kubectl_exec]", observation.Tags)
	}
	if observation.ControlPlane == nil || observation.ControlPlane.RequestURI == "" {
		t.Fatalf("control plane context missing: %#v", observation.ControlPlane)
	}
}

func TestAdapterNormalizeListPayload(t *testing.T) {
	raw := []byte(`{
		"items": [
			{
				"auditID": "audit-1",
				"verb": "get",
				"stage": "ResponseComplete",
				"requestReceivedTimestamp": "2026-03-15T18:25:00Z",
				"user": {"username": "alice@example.com"},
				"objectRef": {"resource": "pods", "namespace": "prod", "name": "web-1"}
			},
			{
				"auditID": "audit-2",
				"verb": "delete",
				"stage": "ResponseComplete",
				"requestReceivedTimestamp": "2026-03-15T18:26:00Z",
				"user": {"username": "bob@example.com"},
				"objectRef": {"resource": "deployments", "namespace": "prod", "name": "api"}
			}
		]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("len(observations) = %d, want 2", len(observations))
	}
	if observations[1].ResourceID != "deployments:prod:api" {
		t.Fatalf("second resource_id = %q, want %q", observations[1].ResourceID, "deployments:prod:api")
	}
}

func TestAdapterNormalizeEmptyListPayload(t *testing.T) {
	observations, err := (Adapter{}).Normalize(context.Background(), []byte(`{"items":[]}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("len(observations) = %d, want 0", len(observations))
	}
}

func TestAdapterNormalizeNullListPayload(t *testing.T) {
	observations, err := (Adapter{}).Normalize(context.Background(), []byte(`{"items":null}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("len(observations) = %d, want 0", len(observations))
	}
}

func TestAdapterNormalizeRejectsMalformedPayload(t *testing.T) {
	if _, err := (Adapter{}).Normalize(context.Background(), []byte(`{`)); err == nil {
		t.Fatal("expected error for malformed payload")
	}
}
