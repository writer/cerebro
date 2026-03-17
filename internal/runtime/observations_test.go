package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func mustObservationFromEvent(t *testing.T, event *RuntimeEvent) *RuntimeObservation {
	t.Helper()
	observation, err := ObservationFromEvent(event)
	if err != nil {
		t.Fatalf("ObservationFromEvent: %v", err)
	}
	if observation == nil {
		t.Fatal("expected observation")
	}
	return observation
}

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

	observation := mustObservationFromEvent(t, event)
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

	observation := mustObservationFromEvent(t, event)
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

func TestObservationRoundTripPreservesExplicitKindWithoutDomain(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		ID:         "obs-dns-1",
		Kind:       ObservationKindDNSQuery,
		Source:     "tetragon",
		ObservedAt: time.Date(2026, 3, 15, 20, 2, 0, 0, time.UTC),
		Network: &NetworkEvent{
			Direction: "outbound",
			Protocol:  "dns",
			SrcIP:     "10.0.0.5",
			SrcPort:   41522,
			DstIP:     "10.96.0.10",
			DstPort:   53,
			BytesSent: 88,
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}

	roundTrip := observation.AsRuntimeEvent()
	if roundTrip == nil {
		t.Fatal("expected round-trip event")
	}

	reconstructed := mustObservationFromEvent(t, roundTrip)
	if reconstructed.Kind != ObservationKindDNSQuery {
		t.Fatalf("kind = %s, want %s", reconstructed.Kind, ObservationKindDNSQuery)
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

	observation := mustObservationFromEvent(t, event)
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

func TestNormalizeObservationInfersKindAndGeneratedID(t *testing.T) {
	recordedAt := time.Date(2026, 3, 15, 21, 5, 0, 0, time.UTC)
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     " tetragon ",
		RecordedAt: recordedAt,
		Network: &NetworkEvent{
			Protocol: " UDP ",
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			DstPort:  53,
			Domain:   " api.github.com. ",
		},
		Container: &ContainerEvent{
			ContainerID: " ctr-1 ",
			Namespace:   " prod ",
			Image:       " ghcr.io/acme/web:1.2.3 ",
		},
		Metadata: map[string]any{
			"cluster":      "prod-west",
			"node_name":    "node-7",
			"principal_id": "system:serviceaccount:prod:web",
		},
		Tags: []string{" dns ", "dns", ""},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.Kind != ObservationKindDNSQuery {
		t.Fatalf("kind = %s, want %s", observation.Kind, ObservationKindDNSQuery)
	}
	if observation.ObservedAt != recordedAt {
		t.Fatalf("observed_at = %s, want %s", observation.ObservedAt, recordedAt)
	}
	if observation.ID == "" || !strings.HasPrefix(observation.ID, "runtime:dns_query:") {
		t.Fatalf("id = %q, want generated dns_query id", observation.ID)
	}
	if observation.Namespace != "prod" {
		t.Fatalf("namespace = %q, want prod", observation.Namespace)
	}
	if observation.ContainerID != "ctr-1" {
		t.Fatalf("container_id = %q, want ctr-1", observation.ContainerID)
	}
	if observation.ImageRef != "ghcr.io/acme/web:1.2.3" {
		t.Fatalf("image_ref = %q, want ghcr.io/acme/web:1.2.3", observation.ImageRef)
	}
	if observation.Cluster != "prod-west" || observation.NodeName != "node-7" {
		t.Fatalf("cluster/node = %q/%q, want prod-west/node-7", observation.Cluster, observation.NodeName)
	}
	if observation.PrincipalID != "system:serviceaccount:prod:web" {
		t.Fatalf("principal_id = %q, want system:serviceaccount:prod:web", observation.PrincipalID)
	}
	if got := observation.Tags; len(got) != 1 || got[0] != "dns" {
		t.Fatalf("tags = %#v, want [dns]", got)
	}
	if observation.ResourceType != "container" {
		t.Fatalf("resource_type = %q, want container", observation.ResourceType)
	}
	if observation.ResourceID != "container:ctr-1" {
		t.Fatalf("resource_id = %q, want container:ctr-1", observation.ResourceID)
	}
}

func TestNormalizeObservationRejectsInvalidStructure(t *testing.T) {
	_, err := NormalizeObservation(&RuntimeObservation{
		Kind:       ObservationKindNetworkFlow,
		Source:     "hubble",
		ObservedAt: time.Date(2026, 3, 15, 21, 10, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("error = %v, want ErrInvalidObservation", err)
	}
}

func TestObservationFromEventRejectsInvalidObservation(t *testing.T) {
	observation, err := ObservationFromEvent(&RuntimeEvent{
		ID:        "evt-invalid",
		Timestamp: time.Date(2026, 3, 15, 21, 11, 0, 0, time.UTC),
		Source:    "hubble",
		EventType: "network",
	})
	if observation != nil {
		t.Fatalf("observation = %#v, want nil", observation)
	}
	if !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("error = %v, want ErrInvalidObservation", err)
	}
}

func TestNormalizeObservationBoundsRawAndProvenancePayloads(t *testing.T) {
	raw := make(map[string]any, maxObservationPayloadEntries+5)
	for i := 0; i < maxObservationPayloadEntries+5; i++ {
		raw[fmt.Sprintf("raw_%02d", i)] = strings.Repeat("x", maxObservationStringValueBytes+100)
	}
	raw["nested"] = map[string]any{
		"deep": map[string]any{
			"drop": "value",
		},
	}
	raw["list"] = make([]any, 0, maxObservationListEntries+5)
	for i := 0; i < maxObservationListEntries+5; i++ {
		raw["list"] = append(raw["list"].([]any), fmt.Sprintf(" item-%02d ", i))
	}

	observation, err := NormalizeObservation(&RuntimeObservation{
		Kind:       ObservationKindRuntimeAlert,
		Source:     "falco",
		ObservedAt: time.Date(2026, 3, 15, 21, 12, 0, 0, time.UTC),
		Metadata: map[string]any{
			"execution_id": "exec-1",
		},
		Raw: raw,
		Provenance: map[string]any{
			"collector": strings.Repeat("p", maxObservationStringValueBytes+50),
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if len(observation.Raw) != maxObservationPayloadEntries {
		t.Fatalf("len(raw) = %d, want %d", len(observation.Raw), maxObservationPayloadEntries)
	}
	if got := observation.Raw["raw_00"].(string); len(got) != maxObservationStringValueBytes {
		t.Fatalf("len(raw_00) = %d, want %d", len(got), maxObservationStringValueBytes)
	}
	list, ok := observation.Raw["list"].([]any)
	if !ok {
		t.Fatalf("list = %#v, want []any", observation.Raw["list"])
	}
	if len(list) != maxObservationListEntries {
		t.Fatalf("len(list) = %d, want %d", len(list), maxObservationListEntries)
	}
	nested, ok := observation.Raw["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %#v, want map", observation.Raw["nested"])
	}
	if _, exists := nested["deep"]; exists {
		t.Fatalf("nested deep payload should be trimmed, got %#v", nested)
	}
	if got := observation.Provenance["collector"].(string); len(got) != maxObservationStringValueBytes {
		t.Fatalf("len(provenance.collector) = %d, want %d", len(got), maxObservationStringValueBytes)
	}
}

func TestNormalizeObservationAnyMapSelectsTrimmedKeysDeterministically(t *testing.T) {
	normalized := normalizeObservationAnyMap(map[string]any{
		"  alpha  ": "from-spaced",
		"alpha":     "from-plain",
	}, 0)
	if got := normalized["alpha"]; got != "from-spaced" {
		t.Fatalf("normalized[alpha] = %#v, want %#v", got, "from-spaced")
	}
}

func TestNormalizeObservationPreservesUTF8WhenTruncatingStrings(t *testing.T) {
	trimmed := strings.Repeat("界", maxObservationStringValueBytes/3+4)
	observation, err := NormalizeObservation(&RuntimeObservation{
		Kind:       ObservationKindRuntimeAlert,
		Source:     "falco",
		ObservedAt: time.Date(2026, 3, 15, 21, 12, 30, 0, time.UTC),
		Metadata: map[string]any{
			"execution_id": "exec-1",
		},
		Raw: map[string]any{
			"message": trimmed,
		},
		Provenance: map[string]any{
			"collector": trimmed,
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	message := observation.Raw["message"].(string)
	if !utf8.ValidString(message) {
		t.Fatalf("message is not valid UTF-8: %q", message)
	}
	if len(message) > maxObservationStringValueBytes {
		t.Fatalf("len(message) = %d, want <= %d", len(message), maxObservationStringValueBytes)
	}
	collector := observation.Provenance["collector"].(string)
	if !utf8.ValidString(collector) {
		t.Fatalf("collector is not valid UTF-8: %q", collector)
	}
	if len(collector) > maxObservationStringValueBytes {
		t.Fatalf("len(collector) = %d, want <= %d", len(collector), maxObservationStringValueBytes)
	}
}

func TestObservationFromEventStillNormalizesMetadataContext(t *testing.T) {
	observation := mustObservationFromEvent(t, &RuntimeEvent{
		ID:        "evt-1",
		Timestamp: time.Date(2026, 3, 15, 21, 12, 0, 0, time.UTC),
		Source:    "tetragon",
		EventType: "process_exec",
		Process:   &ProcessEvent{Name: "bash", Path: "/bin/bash"},
		Metadata: map[string]any{
			"cluster":              "prod-west",
			"node_name":            "worker-1",
			"workload_ref":         "deployment:prod/api",
			"workload_uid":         "uid-123",
			"kubernetes_namespace": "prod",
			"principal_id":         "alice",
		},
	})
	if observation.Cluster != "prod-west" || observation.NodeName != "worker-1" {
		t.Fatalf("cluster/node = %q/%q, want prod-west/worker-1", observation.Cluster, observation.NodeName)
	}
	if observation.WorkloadRef != "deployment:prod/api" || observation.WorkloadUID != "uid-123" {
		t.Fatalf("workload = %q/%q, want deployment:prod/api/uid-123", observation.WorkloadRef, observation.WorkloadUID)
	}
	if observation.Namespace != "prod" || observation.PrincipalID != "alice" {
		t.Fatalf("namespace/principal = %q/%q, want prod/alice", observation.Namespace, observation.PrincipalID)
	}
}

func TestNormalizeObservationBindsIdentityFromMetadataAndResourceRefs(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Kind:       ObservationKindRuntimeAlert,
		Source:     "falco",
		ObservedAt: time.Date(2026, 3, 16, 16, 0, 0, 0, time.UTC),
		ResourceID: "deployment:prod/api",
		Metadata: map[string]any{
			"cluster_name": "prod-west",
			"container_id": "ctr-42",
			"image_ref":    "ghcr.io/acme/api:1.2.3",
			"image_id":     "sha256:api42",
		},
		Process: &ProcessEvent{
			Name: "bash",
			User: "root",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.Cluster != "prod-west" {
		t.Fatalf("cluster = %q, want prod-west", observation.Cluster)
	}
	if observation.Namespace != "prod" {
		t.Fatalf("namespace = %q, want prod", observation.Namespace)
	}
	if observation.WorkloadRef != "deployment:prod/api" {
		t.Fatalf("workload_ref = %q, want deployment:prod/api", observation.WorkloadRef)
	}
	if observation.ContainerID != "ctr-42" {
		t.Fatalf("container_id = %q, want ctr-42", observation.ContainerID)
	}
	if observation.ImageRef != "ghcr.io/acme/api:1.2.3" {
		t.Fatalf("image_ref = %q, want ghcr.io/acme/api:1.2.3", observation.ImageRef)
	}
	if observation.ImageID != "sha256:api42" {
		t.Fatalf("image_id = %q, want sha256:api42", observation.ImageID)
	}
	if observation.PrincipalID != "root" {
		t.Fatalf("principal_id = %q, want root", observation.PrincipalID)
	}
}

func TestNormalizeObservationBindsContainerIdentityFromResourceID(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Kind:         ObservationKindRuntimeAlert,
		Source:       "falco",
		ObservedAt:   time.Date(2026, 3, 16, 16, 1, 0, 0, time.UTC),
		ResourceID:   "container:ctr-99",
		ResourceType: "container",
		File: &FileEvent{
			Operation: "modify",
			Path:      "/tmp/dropper",
			User:      "alice",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ContainerID != "ctr-99" {
		t.Fatalf("container_id = %q, want ctr-99", observation.ContainerID)
	}
	if observation.PrincipalID != "alice" {
		t.Fatalf("principal_id = %q, want alice", observation.PrincipalID)
	}
}

func TestNormalizeObservationBindsNamespaceFromWorkloadRef(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  time.Date(2026, 3, 16, 16, 2, 0, 0, time.UTC),
		WorkloadRef: "statefulset:data/postgres",
		Process: &ProcessEvent{
			Name: "postgres",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.Namespace != "data" {
		t.Fatalf("namespace = %q, want data", observation.Namespace)
	}
}

func TestNormalizeObservationBindsServiceIdentityFromTraceContext(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 30, 0, 0, time.UTC),
		Trace: &TraceContext{
			TraceID:     "abc123",
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
			"cluster_name":      "prod-west",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ResourceType != "service" {
		t.Fatalf("ResourceType = %q, want service", observation.ResourceType)
	}
	if observation.ResourceID != "service:backend/payments-api" {
		t.Fatalf("ResourceID = %q, want service:backend/payments-api", observation.ResourceID)
	}
	if observation.WorkloadRef != "" {
		t.Fatalf("WorkloadRef = %q, want empty", observation.WorkloadRef)
	}
	if observation.Namespace != "backend" {
		t.Fatalf("Namespace = %q, want backend", observation.Namespace)
	}
	if observation.Cluster != "prod-west" {
		t.Fatalf("Cluster = %q, want prod-west", observation.Cluster)
	}
}

func TestObservationFromEventReconstructsServiceIdentityFromMetadata(t *testing.T) {
	observation := mustObservationFromEvent(t, &RuntimeEvent{
		ID:        "evt-service-1",
		Timestamp: time.Date(2026, 3, 16, 9, 31, 0, 0, time.UTC),
		Source:    "otel",
		EventType: "span",
		Metadata: map[string]any{
			"trace_id":          " abc123 ",
			"span_id":           " def456 ",
			"service_name":      "checkout",
			"service_namespace": "storefront",
			"cluster_name":      "prod-east",
		},
	})
	if observation.Trace == nil {
		t.Fatal("expected trace context")
	}
	if observation.Trace.ServiceName != "checkout" {
		t.Fatalf("Trace.ServiceName = %q, want checkout", observation.Trace.ServiceName)
	}
	if observation.Trace.TraceID != "abc123" || observation.Trace.SpanID != "def456" {
		t.Fatalf("Trace IDs = %q/%q, want abc123/def456", observation.Trace.TraceID, observation.Trace.SpanID)
	}
	if observation.ResourceType != "service" {
		t.Fatalf("ResourceType = %q, want service", observation.ResourceType)
	}
	if observation.ResourceID != "service:storefront/checkout" {
		t.Fatalf("ResourceID = %q, want service:storefront/checkout", observation.ResourceID)
	}
	if observation.WorkloadRef != "" {
		t.Fatalf("WorkloadRef = %q, want empty", observation.WorkloadRef)
	}
	if observation.Namespace != "storefront" {
		t.Fatalf("Namespace = %q, want storefront", observation.Namespace)
	}
	if observation.Cluster != "prod-east" {
		t.Fatalf("Cluster = %q, want prod-east", observation.Cluster)
	}
}

func TestObservationFromEventRejectsWhitespaceOnlyTraceMetadata(t *testing.T) {
	observation, err := ObservationFromEvent(&RuntimeEvent{
		ID:        "evt-trace-whitespace-1",
		Timestamp: time.Date(2026, 3, 16, 9, 31, 30, 0, time.UTC),
		Source:    "otel",
		EventType: "span",
		Metadata: map[string]any{
			"trace_id":     " ",
			"span_id":      "\t",
			"service_name": "\n",
		},
	})
	if err == nil {
		t.Fatalf("ObservationFromEvent() error = nil, want invalid observation")
	}
	if observation != nil {
		t.Fatalf("ObservationFromEvent() observation = %#v, want nil", observation)
	}
}

func TestNormalizeObservationPrefersWorkloadIdentityOverServiceIdentity(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:      "otel",
		ObservedAt:  time.Date(2026, 3, 16, 9, 32, 0, 0, time.UTC),
		WorkloadRef: "deployment:payments/api",
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.WorkloadRef != "deployment:payments/api" {
		t.Fatalf("WorkloadRef = %q, want deployment:payments/api", observation.WorkloadRef)
	}
	if observation.ResourceID != "deployment:payments/api" {
		t.Fatalf("ResourceID = %q, want workload identity preserved", observation.ResourceID)
	}
	if observation.ResourceType != "workload" {
		t.Fatalf("ResourceType = %q, want workload", observation.ResourceType)
	}
}

func TestNormalizeObservationPrefersContainerIdentityOverServiceIdentity(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:      "otel",
		ObservedAt:  time.Date(2026, 3, 16, 9, 33, 0, 0, time.UTC),
		ContainerID: "containerd://abc123",
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ContainerID != "containerd://abc123" {
		t.Fatalf("ContainerID = %q, want containerd://abc123", observation.ContainerID)
	}
	if observation.ResourceID != "container:containerd://abc123" {
		t.Fatalf("ResourceID = %q, want container identity preserved", observation.ResourceID)
	}
	if observation.ResourceType != "container" {
		t.Fatalf("ResourceType = %q, want container", observation.ResourceType)
	}
}

func TestNormalizeObservationBindsServiceIdentityOverAdapterResourceID(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:       "hubble",
		ObservedAt:   time.Date(2026, 3, 16, 9, 34, 0, 0, time.UTC),
		ResourceID:   "pods:backend/payments-api-7f9d:exec",
		ResourceType: "pods",
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ResourceID != "service:backend/payments-api" {
		t.Fatalf("ResourceID = %q, want service:backend/payments-api", observation.ResourceID)
	}
	if observation.ResourceType != "service" {
		t.Fatalf("ResourceType = %q, want service", observation.ResourceType)
	}
	if observation.WorkloadRef != "" {
		t.Fatalf("WorkloadRef = %q, want empty", observation.WorkloadRef)
	}
}

func TestNormalizeObservationPrefersResourceIDBackfilledWorkloadOverServiceIdentity(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 34, 30, 0, time.UTC),
		ResourceID: "deployment:backend/payments-api",
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.WorkloadRef != "deployment:backend/payments-api" {
		t.Fatalf("WorkloadRef = %q, want deployment:backend/payments-api", observation.WorkloadRef)
	}
	if observation.ResourceID != "deployment:backend/payments-api" {
		t.Fatalf("ResourceID = %q, want deployment:backend/payments-api", observation.ResourceID)
	}
	if observation.ResourceType != "workload" {
		t.Fatalf("ResourceType = %q, want workload", observation.ResourceType)
	}
}

func TestNormalizeObservationPrefersResourceIDBackfilledContainerOverServiceIdentity(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 34, 45, 0, time.UTC),
		ResourceID: "container:containerd://svc-123",
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ContainerID != "containerd://svc-123" {
		t.Fatalf("ContainerID = %q, want containerd://svc-123", observation.ContainerID)
	}
	if observation.ResourceID != "container:containerd://svc-123" {
		t.Fatalf("ResourceID = %q, want container:containerd://svc-123", observation.ResourceID)
	}
	if observation.ResourceType != "container" {
		t.Fatalf("ResourceType = %q, want container", observation.ResourceType)
	}
}

func TestNormalizeObservationPrefersControlPlaneIdentityOverServiceIdentity(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "k8s_audit",
		ObservedAt: time.Date(2026, 3, 16, 9, 35, 0, 0, time.UTC),
		ControlPlane: &ControlPlaneContext{
			Resource:  "pods",
			Namespace: "backend",
			Name:      "payments-api-7f9d",
		},
		Trace: &TraceContext{
			ServiceName: "payments-api",
		},
		Metadata: map[string]any{
			"service_namespace": "backend",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ResourceID != "pods:backend/payments-api-7f9d" {
		t.Fatalf("ResourceID = %q, want pods:backend/payments-api-7f9d", observation.ResourceID)
	}
	if observation.ResourceType != "pods" {
		t.Fatalf("ResourceType = %q, want pods", observation.ResourceType)
	}
}

func TestNormalizeObservationSkipsWhitespaceMetadataBeforePrincipalFallback(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "falco",
		ObservedAt: time.Date(2026, 3, 16, 9, 35, 15, 0, time.UTC),
		Process: &ProcessEvent{
			Name: "sh",
			User: "root",
		},
		Metadata: map[string]any{
			"principal_id": " ",
			"user":         "\t",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.PrincipalID != "root" {
		t.Fatalf("PrincipalID = %q, want root", observation.PrincipalID)
	}
}

func TestNormalizeObservationSkipsWhitespaceMetadataBeforeWorkloadNamespaceBackfill(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 35, 45, 0, time.UTC),
		ResourceID: "deployment:backend/payments-api",
		Process: &ProcessEvent{
			Name: "payments-api",
		},
		Metadata: map[string]any{
			"namespace": " ",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.WorkloadRef != "deployment:backend/payments-api" {
		t.Fatalf("WorkloadRef = %q, want deployment:backend/payments-api", observation.WorkloadRef)
	}
	if observation.Namespace != "backend" {
		t.Fatalf("Namespace = %q, want backend", observation.Namespace)
	}
}

func TestNormalizeObservationSkipsWhitespaceMetadataBeforeContainerBackfill(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 36, 0, 0, time.UTC),
		ResourceID: "container:containerd://svc-123",
		Process: &ProcessEvent{
			Name: "payments-api",
		},
		Metadata: map[string]any{
			"container_id": "\n",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if observation.ContainerID != "containerd://svc-123" {
		t.Fatalf("ContainerID = %q, want containerd://svc-123", observation.ContainerID)
	}
	if observation.ResourceType != "container" {
		t.Fatalf("ResourceType = %q, want container", observation.ResourceType)
	}
}

func TestNormalizeObservationRejectsWhitespaceOnlyTraceContext(t *testing.T) {
	observation, err := NormalizeObservation(&RuntimeObservation{
		Source:     "otel",
		ObservedAt: time.Date(2026, 3, 16, 9, 35, 30, 0, time.UTC),
		Trace: &TraceContext{
			TraceID:     " ",
			SpanID:      "\t",
			ServiceName: "\n",
		},
	})
	if err == nil {
		t.Fatalf("NormalizeObservation() error = nil, want invalid observation")
	}
	if observation != nil {
		t.Fatalf("NormalizeObservation() observation = %#v, want nil", observation)
	}
}

func TestDetectionEngineProcessObservationRejectsInvalidObservation(t *testing.T) {
	engine := NewDetectionEngine()
	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		Kind:       ObservationKindNetworkFlow,
		ObservedAt: time.Now(),
	})
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
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
		TriggerData: map[string]any{
			"finding_id": "finding-1",
		},
		EndTime: &endTime,
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
	if got := observation.Metadata["finding_id"]; got != "finding-1" {
		t.Fatalf("finding_id = %#v, want finding-1", got)
	}
}
