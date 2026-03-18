package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestDetectionEngineProcessObservationEmitsEvaluateSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		_ = tp.Shutdown(t.Context())
	})

	engine := NewDetectionEngine()
	observation := &RuntimeObservation{
		ID:           "obs-trace-1",
		Kind:         ObservationKindProcessExec,
		Source:       "tetragon",
		ObservedAt:   time.Now().UTC(),
		ResourceID:   "pod:payments",
		ResourceType: "pod",
		Namespace:    "prod",
		WorkloadRef:  "deployment/payments",
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
	}

	ctx := telemetry.ContextWithAttributes(context.Background(),
		attribute.String("cerebro.tenant_id", "tenant-a"),
	)
	ctx, parentSpan := otel.Tracer("cerebro.test").Start(ctx, "cerebro.event.handle")
	findings := engine.ProcessObservation(ctx, observation)
	parentSpan.End()
	if len(findings) == 0 {
		t.Fatal("expected detection findings")
	}

	evaluateSpan := runtimeTestSpanByName(t, exporter.GetSpans(), "cerebro.detection.evaluate")
	if evaluateSpan.Parent.SpanID() != parentSpan.SpanContext().SpanID() {
		t.Fatalf("evaluate span parent = %s, want %s", evaluateSpan.Parent.SpanID().String(), parentSpan.SpanContext().SpanID().String())
	}
	for key, want := range map[string]string{
		"cerebro.tenant_id":       "tenant-a",
		"cerebro.resource.id":     "pod:payments",
		"cerebro.resource.type":   "pod",
		"cerebro.detection.scope": "process_exec",
	} {
		if got, ok := runtimeTestSpanStringAttribute(evaluateSpan, key); !ok || got != want {
			t.Fatalf("evaluate span attribute %s = %q, ok=%t, want %q", key, got, ok, want)
		}
	}
	if got, ok := runtimeTestSpanIntAttribute(evaluateSpan, "cerebro.detection.findings_count"); !ok || got != 1 {
		t.Fatalf("findings_count = %d, ok=%t, want 1", got, ok)
	}
}

func runtimeTestSpanByName(t *testing.T, spans []tracetest.SpanStub, name string) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if span.Name == name {
			return span
		}
	}
	t.Fatalf("span %q not found", name)
	return tracetest.SpanStub{}
}

func runtimeTestSpanStringAttribute(span tracetest.SpanStub, key string) (string, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

func runtimeTestSpanIntAttribute(span tracetest.SpanStub, key string) (int64, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsInt64(), true
		}
	}
	return 0, false
}
