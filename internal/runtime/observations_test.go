package runtime

import (
	"context"
	"testing"
	"time"
)

func TestObservationRoundTripPreservesDetectionFields(t *testing.T) {
	event := &RuntimeEvent{
		ID:           "event-1",
		Timestamp:    time.Date(2026, 3, 15, 20, 0, 0, 0, time.UTC),
		Source:       "agent-1",
		ResourceID:   "pod:prod/web",
		ResourceType: "pod",
		EventType:    "process",
		Process: &ProcessEvent{
			Name:       "xmrig",
			Cmdline:    "xmrig --url pool.example.com",
			ParentName: "bash",
		},
		Container: &ContainerEvent{
			ContainerID: "ctr-1",
			Namespace:   "prod",
			Image:       "ghcr.io/acme/web:1.2.3",
			ImageID:     "sha256:abc",
		},
		Metadata: map[string]any{
			"cluster":      "prod-west",
			"principal_id": "system:serviceaccount:prod:web",
			"trace_id":     "trace-1",
		},
	}

	observation := ObservationFromEvent(event)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if observation.Kind != ObservationKindProcessExec {
		t.Fatalf("kind = %s, want %s", observation.Kind, ObservationKindProcessExec)
	}
	if observation.PrincipalID != "system:serviceaccount:prod:web" {
		t.Fatalf("principal_id = %q, want %q", observation.PrincipalID, "system:serviceaccount:prod:web")
	}

	roundTrip := observation.AsRuntimeEvent()
	if roundTrip == nil {
		t.Fatal("expected round-trip event")
	}
	if roundTrip.Process == nil || roundTrip.Process.Name != "xmrig" {
		t.Fatalf("round-trip process = %#v", roundTrip.Process)
	}
	if roundTrip.Metadata["cluster"] != "prod-west" {
		t.Fatalf("cluster metadata = %#v, want %q", roundTrip.Metadata["cluster"], "prod-west")
	}
}

func TestObservationRoundTripPreservesCustomEventType(t *testing.T) {
	event := &RuntimeEvent{
		ID:           "event-custom-1",
		Timestamp:    time.Date(2026, 3, 15, 20, 1, 0, 0, time.UTC),
		Source:       "custom-agent",
		ResourceID:   "pod:prod/web",
		ResourceType: "pod",
		EventType:    "tracepoint",
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --url pool.example.com",
		},
	}

	observation := ObservationFromEvent(event)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if got := stringMapValue(observation.Metadata, runtimeObservationLegacyEventTypeKey); got != "tracepoint" {
		t.Fatalf("legacy event type metadata = %q, want %q", got, "tracepoint")
	}

	roundTrip := observation.AsRuntimeEvent()
	if roundTrip == nil {
		t.Fatal("expected round-trip event")
	}
	if roundTrip.EventType != "tracepoint" {
		t.Fatalf("round-trip event_type = %q, want %q", roundTrip.EventType, "tracepoint")
	}

	findings := NewDetectionEngine().ProcessObservation(context.Background(), observation)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Event == nil {
		t.Fatal("expected finding event")
	}
	if findings[0].Event.EventType != "tracepoint" {
		t.Fatalf("finding event_type = %q, want %q", findings[0].Event.EventType, "tracepoint")
	}
}

func TestLegacyEventTypeFromObservationNil(t *testing.T) {
	if got := legacyEventTypeFromObservation(nil); got != "" {
		t.Fatalf("legacyEventTypeFromObservation(nil) = %q, want empty string", got)
	}
}

func TestObservationRoundTripDoesNotAliasMutableFields(t *testing.T) {
	event := &RuntimeEvent{
		ID:           "event-1",
		Timestamp:    time.Date(2026, 3, 15, 20, 0, 0, 0, time.UTC),
		Source:       "agent-1",
		ResourceID:   "pod:prod/web",
		ResourceType: "pod",
		EventType:    "process",
		Process: &ProcessEvent{
			Name:      "xmrig",
			Ancestors: []string{"containerd", "bash"},
		},
		Network: &NetworkEvent{
			DstIP:   "203.0.113.10",
			DstPort: 443,
		},
		File: &FileEvent{
			Operation: "write",
			Path:      "/tmp/miner",
		},
		Container: &ContainerEvent{
			ContainerID:  "ctr-1",
			Namespace:    "prod",
			Capabilities: []string{"CAP_NET_RAW"},
		},
		Metadata: map[string]any{
			"cluster": "prod-west",
		},
	}

	observation := ObservationFromEvent(event)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if observation.Process == event.Process || observation.Network == event.Network || observation.File == event.File || observation.Container == event.Container {
		t.Fatal("expected observation conversion to clone mutable event sub-structs")
	}

	event.Process.Name = "bash"
	event.Process.Ancestors[0] = "mutated"
	event.Network.DstIP = "198.51.100.10"
	event.File.Path = "/tmp/other"
	event.Container.Namespace = "other"
	event.Container.Capabilities[0] = "CAP_SYS_ADMIN"
	if observation.Process.Name != "xmrig" || observation.Process.Ancestors[0] != "containerd" {
		t.Fatalf("observation process mutated with event: %#v", observation.Process)
	}
	if observation.Network.DstIP != "203.0.113.10" {
		t.Fatalf("observation network mutated with event: %#v", observation.Network)
	}
	if observation.File.Path != "/tmp/miner" {
		t.Fatalf("observation file mutated with event: %#v", observation.File)
	}
	if observation.Container.Namespace != "prod" || observation.Container.Capabilities[0] != "CAP_NET_RAW" {
		t.Fatalf("observation container mutated with event: %#v", observation.Container)
	}

	roundTrip := observation.AsRuntimeEvent()
	if roundTrip == nil {
		t.Fatal("expected round-trip event")
	}
	if roundTrip.Process == observation.Process || roundTrip.Network == observation.Network || roundTrip.File == observation.File || roundTrip.Container == observation.Container {
		t.Fatal("expected runtime event conversion to clone mutable observation sub-structs")
	}

	observation.Process.Name = "curl"
	observation.Process.Ancestors[0] = "changed"
	observation.Network.DstIP = "192.0.2.1"
	observation.File.Path = "/tmp/final"
	observation.Container.Namespace = "staging"
	observation.Container.Capabilities[0] = "CAP_CHOWN"
	if roundTrip.Process.Name != "xmrig" || roundTrip.Process.Ancestors[0] != "containerd" {
		t.Fatalf("round-trip process mutated with observation: %#v", roundTrip.Process)
	}
	if roundTrip.Network.DstIP != "203.0.113.10" {
		t.Fatalf("round-trip network mutated with observation: %#v", roundTrip.Network)
	}
	if roundTrip.File.Path != "/tmp/miner" {
		t.Fatalf("round-trip file mutated with observation: %#v", roundTrip.File)
	}
	if roundTrip.Container.Namespace != "prod" || roundTrip.Container.Capabilities[0] != "CAP_NET_RAW" {
		t.Fatalf("round-trip container mutated with observation: %#v", roundTrip.Container)
	}
}

func TestDetectionEngineProcessObservation(t *testing.T) {
	engine := NewDetectionEngine()
	observation := &RuntimeObservation{
		ID:         "obs-1",
		Kind:       ObservationKindProcessExec,
		Source:     "tetragon",
		ObservedAt: time.Now(),
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
		Container: &ContainerEvent{
			ContainerID: "ctr-1",
		},
	}

	findings := engine.ProcessObservation(context.Background(), observation)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Observation == nil {
		t.Fatal("expected finding observation to be populated")
	}
	if findings[0].Event == nil || findings[0].Event.Process == nil {
		t.Fatalf("expected legacy event compatibility on finding, got %#v", findings[0].Event)
	}
	if findings[0].Event.Process == findings[0].Observation.Process {
		t.Fatal("expected finding event and observation to keep independent process structs")
	}
}

func TestObservationFromResponseExecution(t *testing.T) {
	endTime := time.Date(2026, 3, 15, 21, 0, 0, 0, time.UTC)
	execution := &ResponseExecution{
		ID:           "exec-1",
		PolicyID:     "policy-1",
		PolicyName:   "Block suspicious egress",
		TriggerEvent: "finding-1",
		Status:       StatusCompleted,
		ResourceID:   "deployment:prod/web",
		ResourceType: "deployment",
		ApprovedBy:   "alice",
		EndTime:      &endTime,
	}
	action := &ActionExecution{
		Type:      ActionBlockIP,
		Status:    StatusCompleted,
		StartTime: endTime.Add(-5 * time.Second),
		EndTime:   &endTime,
		Output:    "blocked 203.0.113.10",
	}

	observation := observationFromResponseExecution(execution, action)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if observation.Kind != ObservationKindResponseOutcome {
		t.Fatalf("kind = %s, want %s", observation.Kind, ObservationKindResponseOutcome)
	}
	if observation.Metadata["action_type"] != ActionBlockIP {
		t.Fatalf("action_type = %#v, want %s", observation.Metadata["action_type"], ActionBlockIP)
	}
	if observation.ResourceID != "deployment:prod/web" {
		t.Fatalf("resource_id = %q, want %q", observation.ResourceID, "deployment:prod/web")
	}
}
