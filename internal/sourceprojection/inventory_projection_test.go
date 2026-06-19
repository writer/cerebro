package sourceprojection

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGenericInventoryProjectionUsesSpecificTrivyIdentity(t *testing.T) {
	base := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "writer",
		SourceId: "trivy",
		Kind:     "trivy.image_vulnerability",
		Attributes: map[string]string{
			"family":            "image_vulnerability",
			"image_digest":      "sha256:img",
			"package":           "openssl",
			"installed_version": "1.0.0",
		},
	}
	first := cloneEvent(base)
	first.Attributes["vulnerability_id"] = "CVE-2026-0001"
	second := cloneEvent(base)
	second.Id = "event-2"
	second.Attributes["vulnerability_id"] = "CVE-2026-0002"

	firstEntities, _, err := genericInventoryProjections(first)
	if err != nil {
		t.Fatalf("genericInventoryProjections(first) error = %v", err)
	}
	secondEntities, _, err := genericInventoryProjections(second)
	if err != nil {
		t.Fatalf("genericInventoryProjections(second) error = %v", err)
	}
	if firstEntities[0].URN == secondEntities[0].URN {
		t.Fatalf("URNs both = %q, want vulnerability-specific identities", firstEntities[0].URN)
	}
	if !strings.Contains(firstEntities[0].URN, "CVE-2026-0001") {
		t.Fatalf("first URN = %q, want CVE identity", firstEntities[0].URN)
	}
}

func TestGenericInventoryProjectionIgnoresKubernetesClusterExternalIDForPods(t *testing.T) {
	base := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.pod",
		Attributes: map[string]string{
			"family":      "pod",
			"external_id": "cluster-external",
			"cluster_id":  "cluster-1",
			"namespace":   "default",
		},
	}
	first := cloneEvent(base)
	first.Attributes["resource_id"] = "pod-uid-1"
	first.Attributes["name"] = "api-1"
	second := cloneEvent(base)
	second.Id = "event-2"
	second.Attributes["resource_id"] = "pod-uid-2"
	second.Attributes["name"] = "api-2"

	firstEntities, _, err := genericInventoryProjections(first)
	if err != nil {
		t.Fatalf("genericInventoryProjections(first) error = %v", err)
	}
	secondEntities, _, err := genericInventoryProjections(second)
	if err != nil {
		t.Fatalf("genericInventoryProjections(second) error = %v", err)
	}
	if firstEntities[0].URN == secondEntities[0].URN {
		t.Fatalf("URNs both = %q, want pod-specific identities", firstEntities[0].URN)
	}
	if strings.Contains(firstEntities[0].URN, "cluster-external") {
		t.Fatalf("first URN = %q, should not use cluster external_id", firstEntities[0].URN)
	}
}

func TestGenericInventoryProjectionScopesCloudflareWorkerScriptsByAccount(t *testing.T) {
	base := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "writer",
		SourceId: "cloudflare",
		Kind:     "cloudflare.worker_script",
		Attributes: map[string]string{
			"script_id": "edge-router",
		},
	}
	first := cloneEvent(base)
	first.Attributes["account_id"] = "acct-1"
	second := cloneEvent(base)
	second.Id = "event-2"
	second.Attributes["account_id"] = "acct-2"

	firstEntities, _, err := genericInventoryProjections(first)
	if err != nil {
		t.Fatalf("genericInventoryProjections(first) error = %v", err)
	}
	secondEntities, _, err := genericInventoryProjections(second)
	if err != nil {
		t.Fatalf("genericInventoryProjections(second) error = %v", err)
	}
	if firstEntities[0].URN == secondEntities[0].URN {
		t.Fatalf("URNs both = %q, want account-scoped worker script identities", firstEntities[0].URN)
	}
}

func cloneEvent(event *cerebrov1.EventEnvelope) *cerebrov1.EventEnvelope {
	clone := &cerebrov1.EventEnvelope{
		Id:         event.GetId(),
		TenantId:   event.GetTenantId(),
		SourceId:   event.GetSourceId(),
		Kind:       event.GetKind(),
		SchemaRef:  event.GetSchemaRef(),
		Payload:    append([]byte(nil), event.GetPayload()...),
		Attributes: map[string]string{},
		OccurredAt: event.GetOccurredAt(),
	}
	for key, value := range event.Attributes {
		clone.Attributes[key] = value
	}
	return clone
}
