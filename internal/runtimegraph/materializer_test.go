package runtimegraph

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/runtime"
)

func TestBuildObservationWriteRequestPrefersWorkloadSubject(t *testing.T) {
	observedAt := time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC)
	recordedAt := observedAt.Add(2 * time.Second)

	req, err := BuildObservationWriteRequest(&runtime.RuntimeObservation{
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  observedAt,
		RecordedAt:  recordedAt,
		WorkloadRef: "deployment:prod/api",
		ContainerID: "containerd://abc123",
		Namespace:   "prod",
		Cluster:     "prod-cluster",
		PrincipalID: "root",
		Process: &runtime.ProcessEvent{
			Name:    "sh",
			Path:    "/bin/sh",
			Cmdline: "sh -c id",
			User:    "root",
		},
	})
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest returned error: %v", err)
	}

	if req.SubjectID != "deployment:prod/api" {
		t.Fatalf("SubjectID = %q, want deployment:prod/api", req.SubjectID)
	}
	if req.ObservationType != string(runtime.ObservationKindProcessExec) {
		t.Fatalf("ObservationType = %q, want %q", req.ObservationType, runtime.ObservationKindProcessExec)
	}
	if req.SourceSystem != "tetragon" {
		t.Fatalf("SourceSystem = %q, want tetragon", req.SourceSystem)
	}
	if req.Confidence != runtimeObservationBaseConfidence {
		t.Fatalf("Confidence = %f, want %f", req.Confidence, runtimeObservationBaseConfidence)
	}
	if req.SourceEventID == "" {
		t.Fatal("SourceEventID should not be empty")
	}
	if !strings.HasPrefix(req.ID, "observation:runtime:process_exec:") {
		t.Fatalf("ID = %q, want observation:runtime:process_exec:*", req.ID)
	}
	if req.Summary != "process exec /bin/sh" {
		t.Fatalf("Summary = %q, want process exec /bin/sh", req.Summary)
	}
	if got := testMetadataString(req.Metadata, "workload_ref"); got != "deployment:prod/api" {
		t.Fatalf("metadata.workload_ref = %q, want deployment:prod/api", got)
	}
	if got := testMetadataString(req.Metadata, "container_id"); got != "containerd://abc123" {
		t.Fatalf("metadata.container_id = %q, want containerd://abc123", got)
	}
	if got := testMetadataString(req.Metadata, "principal_id"); got != "root" {
		t.Fatalf("metadata.principal_id = %q, want root", got)
	}
	if got := testMetadataString(req.Metadata, "process_path"); got != "/bin/sh" {
		t.Fatalf("metadata.process_path = %q, want /bin/sh", got)
	}
	if got := testMetadataString(req.Metadata, "correlation_key"); got != runtime.ObservationCorrelationKey(&runtime.RuntimeObservation{
		Source:      "tetragon",
		Kind:        runtime.ObservationKindProcessExec,
		ObservedAt:  observedAt,
		RecordedAt:  recordedAt,
		WorkloadRef: "deployment:prod/api",
		ContainerID: "containerd://abc123",
		Namespace:   "prod",
		Cluster:     "prod-cluster",
		PrincipalID: "root",
		Process: &runtime.ProcessEvent{
			Name:    "sh",
			Path:    "/bin/sh",
			Cmdline: "sh -c id",
			User:    "root",
		},
	}, "deployment:prod/api") {
		t.Fatalf("metadata.correlation_key = %q, want semantic correlation key", got)
	}
	if !req.ObservedAt.Equal(observedAt) {
		t.Fatalf("ObservedAt = %s, want %s", req.ObservedAt, observedAt)
	}
	if !req.RecordedAt.Equal(recordedAt) {
		t.Fatalf("RecordedAt = %s, want %s", req.RecordedAt, recordedAt)
	}
}

func TestBuildObservationWriteRequestFallsBackToServiceResourceID(t *testing.T) {
	observedAt := time.Date(2026, 3, 16, 18, 5, 0, 0, time.UTC)

	req, err := BuildObservationWriteRequest(&runtime.RuntimeObservation{
		Source:     "otel",
		Kind:       runtime.ObservationKindTraceLink,
		ObservedAt: observedAt,
		Metadata: map[string]any{
			"service_namespace":             "storefront",
			"trace_id":                      "abc123",
			"span_id":                       "def456",
			"parent_span_id":                "pqr999",
			"span_kind":                     "client",
			"span_status_code":              "ok",
			"service_name":                  "checkout",
			"destination_service_name":      "payments",
			"destination_service_namespace": "storefront",
			"call_protocol":                 "grpc",
		},
		Trace: &runtime.TraceContext{
			TraceID:     "abc123",
			SpanID:      "def456",
			ServiceName: "checkout",
		},
	})
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest returned error: %v", err)
	}

	if req.SubjectID != "service:storefront/checkout" {
		t.Fatalf("SubjectID = %q, want service:storefront/checkout", req.SubjectID)
	}
	if req.Summary != "trace link checkout" {
		t.Fatalf("Summary = %q, want trace link checkout", req.Summary)
	}
	if got := testMetadataString(req.Metadata, "trace_id"); got != "abc123" {
		t.Fatalf("metadata.trace_id = %q, want abc123", got)
	}
	if got := testMetadataString(req.Metadata, "service_name"); got != "checkout" {
		t.Fatalf("metadata.service_name = %q, want checkout", got)
	}
	if got := testMetadataString(req.Metadata, "parent_span_id"); got != "pqr999" {
		t.Fatalf("metadata.parent_span_id = %q, want pqr999", got)
	}
	if got := testMetadataString(req.Metadata, "span_kind"); got != "client" {
		t.Fatalf("metadata.span_kind = %q, want client", got)
	}
	if got := testMetadataString(req.Metadata, "destination_service_name"); got != "payments" {
		t.Fatalf("metadata.destination_service_name = %q, want payments", got)
	}
	if got := testMetadataString(req.Metadata, "destination_service_namespace"); got != "storefront" {
		t.Fatalf("metadata.destination_service_namespace = %q, want storefront", got)
	}
	if got := testMetadataString(req.Metadata, "call_protocol"); got != "grpc" {
		t.Fatalf("metadata.call_protocol = %q, want grpc", got)
	}
}

func TestBuildObservationWriteRequestUsesConcreteControlPlaneResourceID(t *testing.T) {
	observedAt := time.Date(2026, 3, 16, 18, 10, 0, 0, time.UTC)

	req, err := BuildObservationWriteRequest(&runtime.RuntimeObservation{
		Source:     "k8s_audit",
		Kind:       runtime.ObservationKindKubernetesAudit,
		ObservedAt: observedAt,
		ControlPlane: &runtime.ControlPlaneContext{
			Verb:      "delete",
			Resource:  "pods",
			Namespace: "prod",
			Name:      "api-7f9d",
			User:      "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("BuildObservationWriteRequest returned error: %v", err)
	}

	if req.SubjectID != "pods:prod/api-7f9d" {
		t.Fatalf("SubjectID = %q, want pods:prod/api-7f9d", req.SubjectID)
	}
	if req.Summary != "k8s audit delete pods prod/api-7f9d" {
		t.Fatalf("Summary = %q, want k8s audit delete pods prod/api-7f9d", req.Summary)
	}
}

func TestBuildObservationWriteRequestRejectsMissingConcreteSubject(t *testing.T) {
	_, err := BuildObservationWriteRequest(&runtime.RuntimeObservation{
		Source:     "falco",
		Kind:       runtime.ObservationKindRuntimeAlert,
		ObservedAt: time.Date(2026, 3, 16, 18, 15, 0, 0, time.UTC),
		Metadata: map[string]any{
			"signal_name": "suspicious binary execution",
		},
	})
	if !errors.Is(err, ErrMissingObservationSubject) {
		t.Fatalf("error = %v, want ErrMissingObservationSubject", err)
	}
}

func testMetadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[key].(string)
	return value
}
