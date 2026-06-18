package endpointtelemetry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeBuildsPostureAndActionOutcomeEvents(t *testing.T) {
	body := []byte(`{
		"posture": {"observation_table": "secheck.heartbeat", "status": "ok"},
		"events": [
			{"type": "remediation.remediated", "package": "openssl", "result": "success"}
		]
	}`)
	events, err := Normalize(body, Principal{
		TenantID:     "writer",
		DeviceID:     "dev_123",
		HardwareUUID: "hw-123",
		Hostname:     "workstation",
	}, time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetKind() != "trusted_endpoint.host_posture" {
		t.Fatalf("events[0].Kind = %q, want host_posture", events[0].GetKind())
	}
	if events[0].GetAttributes()["observation_table"] != "secheck.heartbeat" {
		t.Fatalf("observation_table attr = %q", events[0].GetAttributes()["observation_table"])
	}
	if events[1].GetKind() != "trusted_endpoint.action_outcome" {
		t.Fatalf("events[1].Kind = %q, want action_outcome", events[1].GetKind())
	}
	if events[1].GetAttributes()["action"] != "remediation" {
		t.Fatalf("action attr = %q, want remediation", events[1].GetAttributes()["action"])
	}
	var payload map[string]any
	if err := json.Unmarshal(events[1].GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["outcome"] != "success" {
		t.Fatalf("payload outcome = %v, want success", payload["outcome"])
	}
}

func TestNormalizeBuildsSecurityFindingEvent(t *testing.T) {
	body := []byte(`{"events":[{"type":"verification.vulnerable","finding_id":"finding-1","severity":"high"}]}`)
	events, err := Normalize(body, Principal{TenantID: "writer", DeviceID: "dev_123"}, time.Now())
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.GetKind() != "trusted_endpoint.security_finding" {
		t.Fatalf("Kind = %q, want security_finding", event.GetKind())
	}
	if event.GetAttributes()["finding_id"] != "finding-1" {
		t.Fatalf("finding_id attr = %q", event.GetAttributes()["finding_id"])
	}
	if event.GetAttributes()["severity"] != "high" {
		t.Fatalf("severity attr = %q", event.GetAttributes()["severity"])
	}
}

func TestNormalizeTrustGateDecisionSuffixDoesNotBecomeAction(t *testing.T) {
	body := []byte(`{"events":[
		{"type":"trust_gate.deny","reason":"posture_failed"},
		{"type":"trust_gate.allow","reason":"posture_remediated"}
	]}`)
	events, err := Normalize(body, Principal{TenantID: "writer", DeviceID: "dev_123"}, time.Now())
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	for i, event := range events {
		if got := event.GetAttributes()["action"]; got != "trust_gate" {
			t.Fatalf("event[%d] action = %q, want stable trust_gate action", i, got)
		}
	}
	if got := events[0].GetAttributes()["decision"]; got != "deny" {
		t.Fatalf("deny event decision = %q, want deny", got)
	}
	if got := events[1].GetAttributes()["decision"]; got != "allow" {
		t.Fatalf("allow event decision = %q, want allow", got)
	}
}

func TestNormalizeRequiresTenantAndDeviceIdentity(t *testing.T) {
	if _, err := Normalize([]byte(`{"events":[]}`), Principal{DeviceID: "dev"}, time.Now()); err == nil {
		t.Fatal("Normalize() without tenant error = nil, want error")
	}
	if _, err := Normalize([]byte(`{"events":[]}`), Principal{TenantID: "writer"}, time.Now()); err == nil {
		t.Fatal("Normalize() without device identity error = nil, want error")
	}
}
