package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMutateSecurityGraphEmitsMutationAndIndexSpans(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		_ = tp.Shutdown(t.Context())
	})

	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	application := &App{
		Config:        &Config{},
		SecurityGraph: liveGraph,
	}

	ctx := telemetry.ContextWithAttributes(context.Background(),
		attribute.String("cerebro.event.id", "evt-graph-1"),
		attribute.String("cerebro.tenant_id", "tenant-a"),
	)
	ctx, parentSpan := otel.Tracer("cerebro.test").Start(ctx, "cerebro.event.handle")
	_, err := application.MutateSecurityGraph(ctx, func(candidate *graph.Graph) error {
		candidate.AddNode(&graph.Node{ID: "service:billing", Kind: graph.NodeKindService, Name: "billing"})
		return nil
	})
	parentSpan.End()
	if err != nil {
		t.Fatalf("MutateSecurityGraph failed: %v", err)
	}

	spans := exporter.GetSpans()
	mutateSpan := appTestSpanByName(t, spans, "cerebro.graph.mutate")
	if mutateSpan.Parent.SpanID() != parentSpan.SpanContext().SpanID() {
		t.Fatalf("mutate span parent = %s, want %s", mutateSpan.Parent.SpanID().String(), parentSpan.SpanContext().SpanID().String())
	}
	indexSpan := appTestSpanByName(t, spans, "cerebro.graph.index_update")
	if indexSpan.Parent.SpanID() != mutateSpan.SpanContext.SpanID() {
		t.Fatalf("index span parent = %s, want %s", indexSpan.Parent.SpanID().String(), mutateSpan.SpanContext.SpanID().String())
	}

	for key, want := range map[string]string{
		"cerebro.event.id":  "evt-graph-1",
		"cerebro.tenant_id": "tenant-a",
	} {
		if got, ok := appTestSpanStringAttribute(mutateSpan, key); !ok || got != want {
			t.Fatalf("mutate span attribute %s = %q, ok=%t, want %q", key, got, ok, want)
		}
	}
	if got, ok := appTestSpanIntAttribute(mutateSpan, "cerebro.graph.before_node_count"); !ok || got != 1 {
		t.Fatalf("before_node_count = %d, ok=%t, want 1", got, ok)
	}
	if got, ok := appTestSpanIntAttribute(mutateSpan, "cerebro.graph.after_node_count"); !ok || got != 2 {
		t.Fatalf("after_node_count = %d, ok=%t, want 2", got, ok)
	}
	if got, ok := appTestSpanIntAttribute(mutateSpan, "cerebro.graph.mutation_count"); !ok || got != 1 {
		t.Fatalf("mutation_count = %d, ok=%t, want 1", got, ok)
	}
}

func appTestSpanByName(t *testing.T, spans []tracetest.SpanStub, name string) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if span.Name == name {
			return span
		}
	}
	t.Fatalf("span %q not found", name)
	return tracetest.SpanStub{}
}

func appTestSpanStringAttribute(span tracetest.SpanStub, key string) (string, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

func appTestSpanIntAttribute(span tracetest.SpanStub, key string) (int64, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsInt64(), true
		}
	}
	return 0, false
}
