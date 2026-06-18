package trustedendpoint

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/endpointtelemetry"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func sampleTelemetryBody() []byte {
	return []byte(`{
		"posture": {"observation_table": "secheck.heartbeat", "status": "ok"},
		"events": [
			{"type": "remediation.remediated", "package": "openssl", "result": "success"},
			{"type": "verification.vulnerable", "finding_id": "finding-1", "severity": "high"},
			{"type": "trust_gate.deny", "action": "git_push", "reason": "posture_failed", "severity": "high"},
			{"control_id": "AC-2", "status": "failing", "framework": "SOC2"}
		]
	}`)
}

func TestNormalizeEmitsSupportedTrustedEndpointKinds(t *testing.T) {
	principal := endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev_123", HardwareUUID: "hw-123", Hostname: "workstation"}
	events, err := endpointtelemetry.Normalize(sampleTelemetryBody(), principal, time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	gotKinds := map[string]int{}
	for _, event := range events {
		gotKinds[event.GetKind()]++
	}
	for _, kind := range []string{
		"trusted_endpoint.host_posture",
		"trusted_endpoint.action_outcome",
		"trusted_endpoint.security_finding",
		"trusted_endpoint.trust_gate_decision",
		"trusted_endpoint.grc_evidence",
	} {
		if gotKinds[kind] == 0 {
			t.Fatalf("Normalize() did not emit kind %q; got kinds %v", kind, gotKinds)
		}
	}

	contracts := loadTelemetryEventContracts(t)
	for _, event := range events {
		if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, contracts); err != nil {
			t.Fatalf("event kind %q failed contract validation: %v", event.GetKind(), err)
		}
	}
}

func TestNormalizeTrustGateDecisionAttributes(t *testing.T) {
	principal := endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev_123"}
	body := []byte(`{"events":[{"type":"trust_gate.deny","action":"git_push","reason":"posture_failed","severity":"high"}]}`)
	events, err := endpointtelemetry.Normalize(body, principal, time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.GetKind() != "trusted_endpoint.trust_gate_decision" {
		t.Fatalf("Kind = %q, want trust_gate_decision", event.GetKind())
	}
	for key, want := range map[string]string{
		"agent_id": "dev_123",
		"action":   "git_push",
		"decision": "deny",
		"severity": "high",
	} {
		if got := event.GetAttributes()[key]; got != want {
			t.Fatalf("attribute %q = %q, want %q", key, got, want)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["decision"] != "deny" || payload["action"] != "git_push" {
		t.Fatalf("payload action/decision = %v/%v, want git_push/deny", payload["action"], payload["decision"])
	}
}

func TestNormalizeGRCEvidenceAttributes(t *testing.T) {
	principal := endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev_123"}
	body := []byte(`{"events":[{"control_id":"AC-2","status":"failing","framework":"SOC2"}]}`)
	events, err := endpointtelemetry.Normalize(body, principal, time.Now())
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.GetKind() != "trusted_endpoint.grc_evidence" {
		t.Fatalf("Kind = %q, want grc_evidence", event.GetKind())
	}
	if event.GetAttributes()["control_id"] != "AC-2" {
		t.Fatalf("control_id attr = %q, want AC-2", event.GetAttributes()["control_id"])
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["status"] != "failing" {
		t.Fatalf("payload status = %v, want failing", payload["status"])
	}
}

func TestNormalizeProducesStableEventIdentities(t *testing.T) {
	principal := endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev_123", HardwareUUID: "hw-123"}
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	first, err := endpointtelemetry.Normalize(sampleTelemetryBody(), principal, at)
	if err != nil {
		t.Fatalf("Normalize() first error = %v", err)
	}
	second, err := endpointtelemetry.Normalize(sampleTelemetryBody(), principal, at)
	if err != nil {
		t.Fatalf("Normalize() second error = %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("event count drift: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i].GetId() != second[i].GetId() {
			t.Fatalf("event[%d] id drift: %q != %q", i, first[i].GetId(), second[i].GetId())
		}
		if first[i].GetId() == "" {
			t.Fatalf("event[%d] id is empty", i)
		}
	}
}

func TestNormalizeRejectsMalformedTelemetry(t *testing.T) {
	cases := []struct {
		name      string
		body      []byte
		principal endpointtelemetry.Principal
	}{
		{"missing tenant", []byte(`{"events":[]}`), endpointtelemetry.Principal{DeviceID: "dev"}},
		{"missing device", []byte(`{"events":[]}`), endpointtelemetry.Principal{TenantID: "writer"}},
		{"invalid json", []byte(`{not-json`), endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev"}},
		{"trust gate without decision", []byte(`{"events":[{"type":"trust_gate"}]}`), endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev"}},
		{"grc evidence without status", []byte(`{"events":[{"control_id":"AC-2"}]}`), endpointtelemetry.Principal{TenantID: "writer", DeviceID: "dev"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := endpointtelemetry.Normalize(tc.body, tc.principal, time.Now()); err == nil {
				t.Fatalf("Normalize() error = nil, want rejection for %s", tc.name)
			}
		})
	}
}

func loadTelemetryEventContracts(t *testing.T) []sourcecdk.EventContract {
	t.Helper()
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog.yaml error = %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(specBytes)
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	return catalog.EventContracts
}
