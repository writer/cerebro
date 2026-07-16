package endpointtelemetry

import (
	"encoding/json"
	"fmt"
	"strings"
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

func TestNormalizeBuildsBoundedAgentExecutionReceipt(t *testing.T) {
	body := []byte(`{"events":[{
		"type":"agent_execution_receipt",
		"receipt_id":"receipt-1",
		"receipt_digest":"sha256:receipt",
		"sequence":7,
		"previous_receipt_digest":"sha256:previous",
		"captured_at":"2026-07-16T12:00:00Z",
		"phase":"completed",
		"agent_product":"Codex",
		"model":"gpt-test",
		"session_id":"session-1",
		"turn_id":"turn-1",
		"tool_call_id":"call-1",
		"tool_name":"Bash",
		"action_summary":"aws ecs register-task-definition",
		"permission_mode":"never",
		"local_user_claim":"jonathan",
		"local_user_claim_source":"process_user",
		"evidence_integrity":"signature_valid",
		"provider_binding":"provider_bound",
		"provider_event_id":"cloudtrail-1"
	}]}`)
	events, err := Normalize(body, Principal{TenantID: "writer", DeviceID: "dev_123"}, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.GetKind() != "trusted_endpoint.agent_execution_receipt" {
		t.Fatalf("Kind = %q, want agent_execution_receipt", event.GetKind())
	}
	for key, want := range map[string]string{
		"device_id":                  "dev_123",
		"receipt_id":                 "receipt-1",
		"captured_at":                "2026-07-16T12:00:00Z",
		"sequence":                   "7",
		"agent_product":              "Codex",
		"session_id":                 "session-1",
		"tool_name":                  "Bash",
		"action":                     "aws ecs register-task-definition",
		"local_user_claim":           "jonathan",
		"evidence_integrity":         "authenticated_device_claim",
		"claimed_evidence_integrity": "signature_valid",
		"provider_binding":           "unverified",
		"claimed_provider_binding":   "provider_bound",
	} {
		if got := event.GetAttributes()[key]; got != want {
			t.Fatalf("attribute %q = %q, want %q", key, got, want)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := payload["raw"]; ok {
		t.Fatal("agent execution receipt payload retained raw input")
	}
}

func TestNormalizeAgentExecutionReceiptMinimizesActionAndStabilizesIdentity(t *testing.T) {
	principal := Principal{TenantID: "writer", DeviceID: "dev_123"}
	receipt := `{"type":"agent_execution_receipt","receipt_id":"receipt-1","receipt_digest":"sha256:receipt","sequence":1,"captured_at":"2026-07-16T12:00:00Z","phase":"completed","agent_product":"Codex","session_id":"session-1","action_summary":"aws ecs register-task-definition --token super-secret","evidence_integrity":"signature_valid"}`
	first, err := Normalize([]byte(`{"events":[`+receipt+`]}`), principal, time.Now())
	if err != nil {
		t.Fatalf("Normalize(first) error = %v", err)
	}
	second, err := Normalize([]byte(`{"events":[{"type":"login"},`+receipt+`]}`), principal, time.Now())
	if err != nil {
		t.Fatalf("Normalize(second) error = %v", err)
	}
	if first[0].GetId() != second[1].GetId() {
		t.Fatalf("receipt event id changed with batch position: %q != %q", first[0].GetId(), second[1].GetId())
	}
	if got := first[0].GetAttributes()["action"]; got != "aws ecs register-task-definition" {
		t.Fatalf("minimized action = %q, want aws ecs register-task-definition", got)
	}
	if strings.Contains(string(first[0].GetPayload()), "super-secret") {
		t.Fatal("normalized receipt retained command argument")
	}
}

func TestNormalizeAgentExecutionReceiptDoesNotRetainUnknownActionTokens(t *testing.T) {
	receipt := `{"type":"agent_execution_receipt","receipt_id":"receipt-unknown","receipt_digest":"sha256:receipt","sequence":1,"captured_at":"2026-07-16T12:00:00Z","phase":"completed","agent_product":"Codex","session_id":"session-1","action_summary":"--token super-secret","evidence_integrity":"signature_valid"}`
	events, err := Normalize([]byte(`{"events":[`+receipt+`]}`), Principal{TenantID: "tenant-1", DeviceID: "device-1"}, time.Now())
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got := events[0].GetAttributes()["action"]; got != "agent_tool_execution" {
		t.Fatalf("minimized action = %q, want agent_tool_execution", got)
	}
	if strings.Contains(string(events[0].GetPayload()), "super-secret") {
		t.Fatal("normalized payload retained an unknown action token")
	}
}

func TestNormalizeAgentExecutionReceiptDoesNotRetainKnownCommandFlagValues(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{action: "git -C /Users/alice/private status", want: "git status"},
		{action: "aws --profile sensitive-profile s3 put-bucket-policy", want: "aws s3 put-bucket-policy"},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			receipt := fmt.Sprintf(`{"type":"agent_execution_receipt","receipt_id":"receipt-flags","receipt_digest":"sha256:receipt","sequence":1,"captured_at":"2026-07-16T12:00:00Z","phase":"completed","agent_product":"Codex","session_id":"session-1","action_summary":%q,"evidence_integrity":"signature_valid"}`, test.action)
			events, err := Normalize([]byte(`{"events":[`+receipt+`]}`), Principal{TenantID: "tenant-1", DeviceID: "device-1"}, time.Now())
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if got := events[0].GetAttributes()["action"]; got != test.want {
				t.Fatalf("minimized action = %q, want %q", got, test.want)
			}
			payload := string(events[0].GetPayload())
			if strings.Contains(payload, "alice") || strings.Contains(payload, "sensitive-profile") {
				t.Fatalf("normalized payload retained a flag value: %s", payload)
			}
		})
	}
}

func TestNormalizeRejectsIncompleteAgentExecutionReceipt(t *testing.T) {
	body := []byte(`{"events":[{"type":"agent_execution_receipt","receipt_id":"receipt-1","session_id":"session-1"}]}`)
	if _, err := Normalize(body, Principal{TenantID: "writer", DeviceID: "dev_123"}, time.Now()); err == nil {
		t.Fatal("Normalize() error = nil, want incomplete receipt rejection")
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
