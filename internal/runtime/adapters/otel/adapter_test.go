package otel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/runtime"
)

func TestAdapterSource(t *testing.T) {
	if got := (Adapter{}).Source(); got != sourceName {
		t.Fatalf("Source() = %q, want %q", got, sourceName)
	}
}

func TestAdapterNormalizeLogRecord(t *testing.T) {
	raw := []byte(`{
		"resourceLogs": [{
			"resource": {
				"attributes": [
					{"key":"service.name","value":{"stringValue":"payments-api"}},
					{"key":"service.namespace","value":{"stringValue":"backend"}},
					{"key":"service.instance.id","value":{"stringValue":"payments-api-7f5c9d"}},
					{"key":"k8s.cluster.name","value":{"stringValue":"prod-west"}},
					{"key":"k8s.namespace.name","value":{"stringValue":"payments"}},
					{"key":"k8s.deployment.name","value":{"stringValue":"payments-api"}},
					{"key":"container.id","value":{"stringValue":"containerd://abc123"}},
					{"key":"container.image.name","value":{"stringValue":"ghcr.io/evalops/payments:1.2.3"}},
					{"key":"container.image.id","value":{"stringValue":"sha256:deadbeef"}},
					{"key":"k8s.node.name","value":{"stringValue":"worker-a"}}
				]
			},
			"scopeLogs": [{
				"scope": {
					"name": "github.com/acme/payments",
					"version": "1.4.2",
					"attributes": [
						{"key":"scope.team","value":{"stringValue":"payments"}}
					]
				},
				"logRecords": [{
					"timeUnixNano": "1773600000000000000",
					"observedTimeUnixNano": "1773600001000000000",
					"severityNumber": 17,
					"severityText": "ERROR",
					"traceId": "ABCDEF0123456789ABCDEF0123456789",
					"spanId": "0123456789ABCDEF",
					"body": {"stringValue":"database connection reset"},
					"attributes": [
						{"key":"enduser.id","value":{"stringValue":"user-123"}},
						{"key":"http.request.method","value":{"stringValue":"POST"}}
					]
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindTraceLink {
		t.Fatalf("Kind = %q, want %q", observation.Kind, runtime.ObservationKindTraceLink)
	}
	if observation.Source != sourceName {
		t.Fatalf("Source = %q, want %q", observation.Source, sourceName)
	}
	if observation.Trace == nil {
		t.Fatal("expected trace context")
	}
	if observation.Trace.TraceID != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("TraceID = %q, want lowercase normalized value", observation.Trace.TraceID)
	}
	if observation.Trace.SpanID != "0123456789abcdef" {
		t.Fatalf("SpanID = %q, want lowercase normalized value", observation.Trace.SpanID)
	}
	if observation.Trace.ServiceName != "payments-api" {
		t.Fatalf("ServiceName = %q, want payments-api", observation.Trace.ServiceName)
	}
	if observation.Cluster != "prod-west" {
		t.Fatalf("Cluster = %q, want prod-west", observation.Cluster)
	}
	if observation.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", observation.Namespace)
	}
	if observation.NodeName != "worker-a" {
		t.Fatalf("NodeName = %q, want worker-a", observation.NodeName)
	}
	if observation.WorkloadRef != "deployment:payments/payments-api" {
		t.Fatalf("WorkloadRef = %q, want deployment:payments/payments-api", observation.WorkloadRef)
	}
	if observation.ContainerID != "containerd://abc123" {
		t.Fatalf("ContainerID = %q, want containerd://abc123", observation.ContainerID)
	}
	if observation.ImageRef != "ghcr.io/evalops/payments:1.2.3" {
		t.Fatalf("ImageRef = %q, want image ref", observation.ImageRef)
	}
	if observation.ImageID != "sha256:deadbeef" {
		t.Fatalf("ImageID = %q, want image id", observation.ImageID)
	}
	if observation.PrincipalID != "user-123" {
		t.Fatalf("PrincipalID = %q, want user-123", observation.PrincipalID)
	}
	if observation.RecordedAt.IsZero() || !observation.RecordedAt.After(observation.ObservedAt) {
		t.Fatalf("RecordedAt = %s, want later than ObservedAt %s", observation.RecordedAt, observation.ObservedAt)
	}
	if got := observation.Metadata["severity_text"]; got != "ERROR" {
		t.Fatalf("severity_text = %#v, want ERROR", got)
	}
	if got := observation.Metadata["service_namespace"]; got != "backend" {
		t.Fatalf("service_namespace = %#v, want backend", got)
	}
	if got := observation.Metadata["otel_scope_name"]; got != "github.com/acme/payments" {
		t.Fatalf("otel_scope_name = %#v, want github.com/acme/payments", got)
	}
	if got := observation.Metadata["otel_scope_version"]; got != "1.4.2" {
		t.Fatalf("otel_scope_version = %#v, want 1.4.2", got)
	}
	if got := observation.Metadata["log_body"]; got != "database connection reset" {
		t.Fatalf("log_body = %#v, want database connection reset", got)
	}
	if attrs, ok := observation.Metadata["otel_log_attributes"].(map[string]any); !ok || attrs["http.request.method"] != "POST" {
		t.Fatalf("otel_log_attributes = %#v, want request method preserved", observation.Metadata["otel_log_attributes"])
	}
	if observation.Raw == nil || observation.Provenance == nil {
		t.Fatalf("expected raw and provenance payloads, got raw=%#v provenance=%#v", observation.Raw, observation.Provenance)
	}
}

func TestAdapterNormalizeSpanRecord(t *testing.T) {
	raw := []byte(`{
		"resourceSpans": [{
			"resource": {
				"attributes": [
					{"key":"service.name","value":{"stringValue":"checkout"}},
					{"key":"service.namespace","value":{"stringValue":"storefront"}},
					{"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
					{"key":"k8s.statefulset.name","value":{"stringValue":"checkout-api"}},
					{"key":"host.name","value":{"stringValue":"worker-b"}}
				]
			},
			"scopeSpans": [{
				"scope": {
					"name": "checkout-tracer",
					"version": "2.0.0"
				},
				"spans": [{
					"traceId": "11111111111111111111111111111111",
					"spanId": "2222222222222222",
					"parentSpanId": "3333333333333333",
					"name": "POST /checkout",
					"kind": 3,
					"startTimeUnixNano": "1773601000000000000",
					"endTimeUnixNano": "1773601005000000000",
					"attributes": [
						{"key":"enduser.id","value":{"stringValue":"shopper-7"}},
						{"key":"http.request.method","value":{"stringValue":"POST"}},
						{"key":"http.response.status_code","value":{"intValue":"500"}}
					],
					"events": [{
						"name": "db.timeout",
						"timeUnixNano": "1773601003000000000"
					}],
					"status": {
						"code": 2,
						"message": "deadline exceeded"
					}
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindTraceLink {
		t.Fatalf("Kind = %q, want %q", observation.Kind, runtime.ObservationKindTraceLink)
	}
	if observation.Trace == nil {
		t.Fatal("expected trace context")
	}
	if observation.Trace.ServiceName != "checkout" {
		t.Fatalf("ServiceName = %q, want checkout", observation.Trace.ServiceName)
	}
	if observation.WorkloadRef != "statefulset:shop/checkout-api" {
		t.Fatalf("WorkloadRef = %q, want statefulset:shop/checkout-api", observation.WorkloadRef)
	}
	if observation.NodeName != "worker-b" {
		t.Fatalf("NodeName = %q, want worker-b", observation.NodeName)
	}
	if observation.PrincipalID != "shopper-7" {
		t.Fatalf("PrincipalID = %q, want shopper-7", observation.PrincipalID)
	}
	if observation.RecordedAt.Sub(observation.ObservedAt) != 5*time.Second {
		t.Fatalf("RecordedAt-ObservedAt = %s, want 5s", observation.RecordedAt.Sub(observation.ObservedAt))
	}
	if got := observation.Metadata["span_name"]; got != "POST /checkout" {
		t.Fatalf("span_name = %#v, want POST /checkout", got)
	}
	if got := observation.Metadata["span_kind"]; got != "client" {
		t.Fatalf("span_kind = %#v, want client", got)
	}
	if got := observation.Metadata["span_status_code"]; got != "error" {
		t.Fatalf("span_status_code = %#v, want error", got)
	}
	if got := observation.Metadata["span_status_message"]; got != "deadline exceeded" {
		t.Fatalf("span_status_message = %#v, want deadline exceeded", got)
	}
	if attrs, ok := observation.Metadata["otel_span_attributes"].(map[string]any); !ok || attrs["http.response.status_code"] != int64(500) {
		t.Fatalf("otel_span_attributes = %#v, want numeric response code", observation.Metadata["otel_span_attributes"])
	}
}

func TestAdapterNormalizeLogWithoutTraceFallsBackToRuntimeAlert(t *testing.T) {
	raw := []byte(`{
		"resourceLogs": [{
			"resource": {
				"attributes": [
					{"key":"host.name","value":{"stringValue":"worker-c"}}
				]
			},
			"scopeLogs": [{
				"logRecords": [{
					"timeUnixNano": "1773602000000000000",
					"severityText": "WARN",
					"body": {"stringValue":"filesystem usage exceeded threshold"}
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].Kind != runtime.ObservationKindRuntimeAlert {
		t.Fatalf("Kind = %q, want %q", observations[0].Kind, runtime.ObservationKindRuntimeAlert)
	}
	if observations[0].Trace != nil {
		t.Fatalf("Trace = %#v, want nil for runtime_alert", observations[0].Trace)
	}
	if observations[0].NodeName != "worker-c" {
		t.Fatalf("NodeName = %q, want worker-c", observations[0].NodeName)
	}
}

func TestAdapterNormalizeAcceptsEmptyKnownEnvelope(t *testing.T) {
	observations, err := (Adapter{}).Normalize(context.Background(), []byte(`{"resourceLogs":[]}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("len(observations) = %d, want 0", len(observations))
	}
}

func TestAdapterNormalizeLogWithServiceContextCreatesServiceResource(t *testing.T) {
	raw := []byte(`{
		"resourceLogs": [{
			"resource": {
				"attributes": [
					{"key":"service.name","value":{"stringValue":"billing-api"}},
					{"key":"service.namespace","value":{"stringValue":"shared-services"}},
					{"key":"service.instance.id","value":{"stringValue":"billing-api-01"}}
				]
			},
			"scopeLogs": [{
				"logRecords": [{
					"timeUnixNano": "1773603000000000000",
					"severityText": "INFO",
					"body": {"stringValue":"service startup complete"}
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindTraceLink {
		t.Fatalf("Kind = %q, want %q", observation.Kind, runtime.ObservationKindTraceLink)
	}
	if observation.ResourceType != "service" {
		t.Fatalf("ResourceType = %q, want service", observation.ResourceType)
	}
	if observation.ResourceID != "service:shared-services/billing-api" {
		t.Fatalf("ResourceID = %q, want service:shared-services/billing-api", observation.ResourceID)
	}
	if observation.Namespace != "shared-services" {
		t.Fatalf("Namespace = %q, want shared-services", observation.Namespace)
	}
	if observation.Trace == nil || observation.Trace.ServiceName != "billing-api" {
		t.Fatalf("Trace = %#v, want service-backed trace context", observation.Trace)
	}
	if got := observation.Metadata["service_instance_id"]; got != "billing-api-01" {
		t.Fatalf("service_instance_id = %#v, want billing-api-01", got)
	}
}

func TestAdapterNormalizeWorkloadRefDoesNotBorrowServiceNamespace(t *testing.T) {
	raw := []byte(`{
		"resourceLogs": [{
			"resource": {
				"attributes": [
					{"key":"service.name","value":{"stringValue":"inventory-api"}},
					{"key":"service.namespace","value":{"stringValue":"shared-services"}},
					{"key":"k8s.deployment.name","value":{"stringValue":"inventory-api"}}
				]
			},
			"scopeLogs": [{
				"logRecords": [{
					"timeUnixNano": "1773603500000000000",
					"severityText": "INFO",
					"body": {"stringValue":"deployment-scoped startup log"}
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Namespace != "shared-services" {
		t.Fatalf("Namespace = %q, want shared-services from service namespace fallback", observation.Namespace)
	}
	if observation.WorkloadRef != "deployment:inventory-api" {
		t.Fatalf("WorkloadRef = %q, want deployment:inventory-api without borrowed service namespace", observation.WorkloadRef)
	}
}

func TestAdapterNormalizeLogFallsBackToObservedTimestamp(t *testing.T) {
	raw := []byte(`{
		"resourceLogs": [{
			"scopeLogs": [{
				"logRecords": [{
					"observedTimeUnixNano": "1773604000000000000",
					"severityText": "WARN",
					"body": {"stringValue":"collector buffered delayed event"}
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	wantTime := time.Unix(0, 1773604000000000000).UTC()
	if !observation.ObservedAt.Equal(wantTime) {
		t.Fatalf("ObservedAt = %s, want %s", observation.ObservedAt, wantTime)
	}
	if !observation.RecordedAt.Equal(wantTime) {
		t.Fatalf("RecordedAt = %s, want %s", observation.RecordedAt, wantTime)
	}
}

func TestAdapterNormalizeSpanFallsBackToStartTimestamp(t *testing.T) {
	raw := []byte(`{
		"resourceSpans": [{
			"resource": {
				"attributes": [
					{"key":"service.name","value":{"stringValue":"orders"}}
				]
			},
			"scopeSpans": [{
				"spans": [{
					"traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"spanId": "bbbbbbbbbbbbbbbb",
					"name": "GET /orders",
					"startTimeUnixNano": "1773605000000000000"
				}]
			}]
		}]
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	wantTime := time.Unix(0, 1773605000000000000).UTC()
	if !observation.ObservedAt.Equal(wantTime) {
		t.Fatalf("ObservedAt = %s, want %s", observation.ObservedAt, wantTime)
	}
	if !observation.RecordedAt.Equal(wantTime) {
		t.Fatalf("RecordedAt = %s, want %s", observation.RecordedAt, wantTime)
	}
}

func TestAdapterNormalizeRejectsUnsupportedPayload(t *testing.T) {
	_, err := (Adapter{}).Normalize(context.Background(), []byte(`{"resourceMetrics":[]}`))
	if err == nil {
		t.Fatal("expected unsupported payload error")
	}
	if !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("error = %v, want unsupported event", err)
	}
}
