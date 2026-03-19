package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type spanAttributesContextKey struct{}

func ContextWithAttributes(ctx context.Context, attrs ...attribute.KeyValue) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(attrs) == 0 {
		return ctx
	}

	existing := ContextAttributes(ctx)
	combined := make([]attribute.KeyValue, 0, len(existing)+len(attrs))
	combined = append(combined, existing...)
	combined = append(combined, attrs...)
	return context.WithValue(ctx, spanAttributesContextKey{}, combined)
}

func ContextAttributes(ctx context.Context) []attribute.KeyValue {
	if ctx == nil {
		return nil
	}
	attrs, ok := ctx.Value(spanAttributesContextKey{}).([]attribute.KeyValue)
	if !ok || len(attrs) == 0 {
		return nil
	}
	cloned := make([]attribute.KeyValue, len(attrs))
	copy(cloned, attrs)
	return cloned
}

func StartSpan(ctx context.Context, instrumentationName, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	combined := ContextAttributes(ctx)
	if len(attrs) > 0 {
		merged := make([]attribute.KeyValue, 0, len(combined)+len(attrs))
		merged = append(merged, combined...)
		merged = append(merged, attrs...)
		combined = merged
	}
	if len(combined) == 0 {
		return Tracer(instrumentationName).Start(ctx, spanName)
	}
	return Tracer(instrumentationName).Start(ctx, spanName, trace.WithAttributes(combined...))
}
