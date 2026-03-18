package runtime

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestDetectionEngineProcessEventEmitsTracingSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer func() {
		otel.SetTracerProvider(prevProvider)
		_ = tp.Shutdown(context.Background())
	}()

	engine := NewDetectionEngine()
	ctx, rootSpan := otel.Tracer("test").Start(context.Background(), "cerebro.event.handle")
	findings := engine.ProcessEvent(ctx, &RuntimeEvent{
		ID:           "evt-1",
		Timestamp:    time.Now().UTC(),
		EventType:    "process",
		ResourceID:   "pod:checkout",
		ResourceType: "pod",
		Metadata: map[string]any{
			"tenant_id": "tenant-a",
		},
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
	})
	rootSpan.End()

	if len(findings) == 0 {
		t.Fatal("expected detection findings")
	}

	spans := exporter.GetSpans()
	root := testTracingSpanByName(t, spans, "cerebro.event.handle")
	detection := testTracingSpanByName(t, spans, "cerebro.detection.evaluate")
	if detection.Parent.SpanID() != root.SpanContext.SpanID() {
		t.Fatalf("detection parent = %s, want %s", detection.Parent.SpanID().String(), root.SpanContext.SpanID().String())
	}
	if got, ok := testTracingSpanStringAttribute(detection, "cerebro.event.id"); !ok || got != "evt-1" {
		t.Fatalf("event id = %q, ok=%t, want evt-1", got, ok)
	}
	if got, ok := testTracingSpanStringAttribute(detection, "cerebro.tenant_id"); !ok || got != "tenant-a" {
		t.Fatalf("tenant id = %q, ok=%t, want tenant-a", got, ok)
	}
	if got, ok := testTracingSpanIntAttribute(detection, "cerebro.detection.findings_count"); !ok || got != len(findings) {
		t.Fatalf("findings_count = %d, ok=%t, want %d", got, ok, len(findings))
	}
}

func testTracingSpanByName(t *testing.T, spans []tracetest.SpanStub, name string) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if span.Name == name {
			return span
		}
	}
	t.Fatalf("span %q not found", name)
	return tracetest.SpanStub{}
}

func testTracingSpanStringAttribute(span tracetest.SpanStub, key string) (string, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

func testTracingSpanIntAttribute(span tracetest.SpanStub, key string) (int, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			switch attr.Value.Type() {
			case attribute.INT64:
				return int(attr.Value.AsInt64()), true
			}
		}
	}
	return 0, false
}
