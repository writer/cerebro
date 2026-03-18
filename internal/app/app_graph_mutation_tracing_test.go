package app

import (
	"context"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMutateSecurityGraphEmitsTracingSpans(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer func() {
		otel.SetTracerProvider(prevProvider)
		_ = tp.Shutdown(context.Background())
	}()

	application := &App{}
	application.setSecurityGraph(graph.New())

	ctx, rootSpan := otel.Tracer("test").Start(context.Background(), "cerebro.event.handle")
	if _, err := application.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		g.AddNode(&graph.Node{ID: "service:checkout", Kind: graph.NodeKindService})
		return nil
	}); err != nil {
		t.Fatalf("MutateSecurityGraph() error = %v", err)
	}
	rootSpan.End()

	spans := exporter.GetSpans()
	root := testTracingSpanByName(t, spans, "cerebro.event.handle")
	mutate := testTracingSpanByName(t, spans, "cerebro.graph.mutate")
	index := testTracingSpanByName(t, spans, "cerebro.graph.index_update")

	if mutate.Parent.SpanID() != root.SpanContext.SpanID() {
		t.Fatalf("graph mutate parent = %s, want %s", mutate.Parent.SpanID().String(), root.SpanContext.SpanID().String())
	}
	if index.Parent.SpanID() != mutate.SpanContext.SpanID() {
		t.Fatalf("index update parent = %s, want %s", index.Parent.SpanID().String(), mutate.SpanContext.SpanID().String())
	}
	if got, ok := testTracingSpanIntAttribute(mutate, "cerebro.graph.after_node_count"); !ok || got != 1 {
		t.Fatalf("after_node_count = %d, ok=%t, want 1", got, ok)
	}
	if got, ok := testTracingSpanIntAttribute(mutate, "cerebro.graph.mutation_count"); !ok || got != 1 {
		t.Fatalf("mutation_count = %d, ok=%t, want 1", got, ok)
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

func testTracingSpanIntAttribute(span tracetest.SpanStub, key string) (int, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key && attr.Value.Type() == attribute.INT64 {
			return int(attr.Value.AsInt64()), true
		}
	}
	return 0, false
}
