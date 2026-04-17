package secheck

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/runtime"
)

func TestAdapterSource(t *testing.T) {
	t.Parallel()
	a := Adapter{}
	if got := a.Source(); got != SourceName {
		t.Fatalf("Source() = %q, want %q", got, SourceName)
	}
}

func TestAdapterNormalizeVerificationEvent(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{
		DeviceID:     "device-001",
		Hostname:     "bens-macbook",
		OSType:       "darwin",
		AgentVersion: "0.1.0",
		OrgID:        "org-123",
		EventType:    "batch",
		Timestamp:    time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Events: []agentEvent{
			{
				Type:      "verification.confirmed",
				FindingID: "f-001",
				CVEID:     "CVE-2026-1234",
				Package:   "openssl",
				Severity:  "critical",
				Manager:   "homebrew",
				Ecosystem: "brew",
				Status:    "confirmed",
			},
		},
	}
	raw, _ := json.Marshal(payload)
	observations, err := Adapter{}.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	obs := observations[0]
	if obs.Source != SourceName {
		t.Errorf("Source = %q, want %q", obs.Source, SourceName)
	}
	if obs.Kind != runtime.ObservationKindRuntimeAlert {
		t.Errorf("Kind = %q, want %q", obs.Kind, runtime.ObservationKindRuntimeAlert)
	}
	if obs.ResourceType != "endpoint_device" {
		t.Errorf("ResourceType = %q, want endpoint_device", obs.ResourceType)
	}
	if obs.NodeName != "bens-macbook" {
		t.Errorf("NodeName = %q, want bens-macbook", obs.NodeName)
	}
}

func TestAdapterNormalizeRemediationEvent(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{
		DeviceID:  "device-002",
		Hostname:  "win-desktop",
		OSType:    "windows",
		Timestamp: time.Date(2026, 4, 16, 13, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Events: []agentEvent{
			{
				Type:      "remediation.completed",
				FindingID: "f-002",
				CVEID:     "CVE-2026-5678",
				Package:   "lodash",
				Manager:   "npm",
				Ecosystem: "npm",
				Status:    "fixed",
				Data:      map[string]any{"old_version": "4.17.20", "new_version": "4.17.21"},
			},
		},
	}
	raw, _ := json.Marshal(payload)
	observations, err := Adapter{}.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	obs := observations[0]
	if obs.Kind != runtime.ObservationKindResponseOutcome {
		t.Errorf("Kind = %q, want %q", obs.Kind, runtime.ObservationKindResponseOutcome)
	}
}

func TestAdapterNormalizePostureHeartbeat(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{
		DeviceID:  "device-003",
		Hostname:  "dev-laptop",
		OSType:    "darwin",
		Timestamp: time.Date(2026, 4, 16, 14, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Posture: &postureReport{
			FindingsConfirmed:  3,
			FindingsDisputed:   1,
			FindingsRemediated: 5,
			FindingsSnoozed:    0,
			NetworkType:        "corporate",
		},
	}
	raw, _ := json.Marshal(payload)
	observations, err := Adapter{}.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	obs := observations[0]
	if obs.Kind != runtime.ObservationKindRuntimeAlert {
		t.Errorf("Kind = %q, want %q", obs.Kind, runtime.ObservationKindRuntimeAlert)
	}
}

func TestAdapterNormalizeMixedEventsAndPosture(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{
		DeviceID:  "device-004",
		Hostname:  "mixed-host",
		OSType:    "darwin",
		Timestamp: time.Date(2026, 4, 16, 15, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Events: []agentEvent{
			{Type: "verification.confirmed", FindingID: "f-010", CVEID: "CVE-2026-9999", Package: "curl", Manager: "homebrew", Ecosystem: "brew", Status: "confirmed"},
			{Type: "remediation.completed", FindingID: "f-011", CVEID: "CVE-2026-8888", Package: "pip", Manager: "pip", Ecosystem: "pip", Status: "fixed"},
		},
		Posture: &postureReport{FindingsConfirmed: 1, FindingsRemediated: 1, NetworkType: "public"},
	}
	raw, _ := json.Marshal(payload)
	observations, err := Adapter{}.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 3 {
		t.Fatalf("len(observations) = %d, want 3 (2 events + 1 posture)", len(observations))
	}
}

func TestAdapterNormalizeMissingDeviceID(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{Hostname: "no-device-id"}
	raw, _ := json.Marshal(payload)
	_, err := Adapter{}.Normalize(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing device_id")
	}
}

func TestAdapterNormalizeInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := Adapter{}.Normalize(context.Background(), []byte("{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestAdapterNormalizeEmptyEvents(t *testing.T) {
	t.Parallel()
	payload := endpointPayload{
		DeviceID:  "device-005",
		Hostname:  "empty-host",
		OSType:    "darwin",
		Timestamp: time.Date(2026, 4, 16, 16, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	raw, _ := json.Marshal(payload)
	observations, err := Adapter{}.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("len(observations) = %d, want 0", len(observations))
	}
}

func TestObservationKindMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eventType string
		wantKind  runtime.RuntimeObservationKind
	}{
		{"verification.confirmed", runtime.ObservationKindRuntimeAlert},
		{"verification.disputed", runtime.ObservationKindRuntimeAlert},
		{"verification.pending", runtime.ObservationKindRuntimeAlert},
		{"remediation.completed", runtime.ObservationKindResponseOutcome},
		{"remediation.failed", runtime.ObservationKindResponseOutcome},
		{"remediation.snoozed", runtime.ObservationKindResponseOutcome},
		{"unknown_type", runtime.ObservationKindRuntimeAlert},
	}
	for _, tt := range tests {
		if got := observationKind(tt.eventType); got != tt.wantKind {
			t.Errorf("observationKind(%q) = %q, want %q", tt.eventType, got, tt.wantKind)
		}
	}
}

func TestEventTags(t *testing.T) {
	t.Parallel()
	event := agentEvent{
		Type:      "verification.confirmed",
		Severity:  "critical",
		CVEID:     "CVE-2026-1234",
		Ecosystem: "brew",
	}
	tags := eventTags(event)
	expected := []string{"secheck", "secheck:verification.confirmed", "severity:critical", "cve:CVE-2026-1234", "ecosystem:brew"}
	if len(tags) != len(expected) {
		t.Fatalf("len(tags) = %d, want %d", len(tags), len(expected))
	}
	for i, tag := range tags {
		if tag != expected[i] {
			t.Errorf("tags[%d] = %q, want %q", i, tag, expected[i])
		}
	}
}
