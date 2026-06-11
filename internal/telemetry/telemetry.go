package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type spanContextKey struct{}

type spanContext struct {
	TraceID string
	SpanID  string
}

type Span struct {
	name     string
	traceID  string
	spanID   string
	parentID string
	started  time.Time
	otelSpan oteltrace.Span
}

type Attributes struct {
	values map[string]any
}

type Field struct {
	Key   string
	Value any
}

func Attrs(fields ...Field) Attributes {
	attributes := Attributes{values: map[string]any{}}
	for _, field := range fields {
		if field.Key == "" {
			continue
		}
		attributes.values[field.Key] = field.Value
	}
	return attributes
}

func (a Attributes) WithField(field Field) Attributes {
	return a.with(field.Key, field.Value)
}

func (a Attributes) with(key string, value any) Attributes {
	if a.values == nil {
		a.values = map[string]any{}
	}
	if key != "" {
		a.values[key] = value
	}
	return a
}

func Start(ctx context.Context, name string, attributes Attributes) (context.Context, *Span) {
	parent, _ := ctx.Value(spanContextKey{}).(spanContext)
	traceID := parent.TraceID
	if traceID == "" {
		traceID = randomHex(16)
	}
	otelCtx, otelSpan := otel.Tracer("github.com/writer/cerebro/internal/telemetry").Start(ctx, name, oteltrace.WithAttributes(attributes.OTELAttributes()...))
	if spanContext := otelSpan.SpanContext(); spanContext.IsValid() {
		traceID = spanContext.TraceID().String()
	}
	span := &Span{
		name:     name,
		traceID:  traceID,
		spanID:   randomHex(8),
		parentID: parent.SpanID,
		started:  time.Now().UTC(),
		otelSpan: otelSpan,
	}
	if spanContext := otelSpan.SpanContext(); spanContext.IsValid() {
		span.spanID = spanContext.SpanID().String()
	}
	next := context.WithValue(otelCtx, spanContextKey{}, spanContext{TraceID: span.traceID, SpanID: span.spanID})
	emit("span_start", span, attributes)
	return next, span
}

// WithTraceParent seeds telemetry context from a W3C traceparent header.
func WithTraceParent(ctx context.Context, header string) context.Context {
	traceID, spanID, ok := ParseTraceParent(header)
	if !ok {
		return ctx
	}
	ctx = propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": strings.TrimSpace(header)})
	return context.WithValue(ctx, spanContextKey{}, spanContext{TraceID: traceID, SpanID: spanID})
}

// TraceParent returns a W3C traceparent header for the current telemetry span.
func TraceParent(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	if value := carrier.Get("traceparent"); value != "" {
		return value
	}
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
	if current.TraceID == "" || current.SpanID == "" {
		return ""
	}
	return "00-" + current.TraceID + "-" + current.SpanID + "-01"
}

func ParseTraceParent(header string) (string, string, bool) {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return "", "", false
	}
	traceID := strings.ToLower(parts[1])
	spanID := strings.ToLower(parts[2])
	flags := strings.ToLower(parts[3])
	if len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 || allZero(traceID) || allZero(spanID) || !isLowerHex(traceID) || !isLowerHex(spanID) || !isLowerHex(flags) {
		return "", "", false
	}
	return traceID, spanID, true
}

func Event(ctx context.Context, name string, attributes Attributes) {
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
	if span := oteltrace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		span.AddEvent(name, oteltrace.WithAttributes(attributes.OTELAttributes()...))
	}
	emit("event", &Span{name: name, traceID: current.TraceID, spanID: current.SpanID}, attributes)
}

func End(span *Span, status string, attributes Attributes) {
	if span == nil {
		return
	}
	if status != "" {
		attributes = attributes.with("status", status)
	}
	attributes = attributes.with("duration_ms", time.Since(span.started).Milliseconds())
	if span.otelSpan != nil && span.otelSpan.SpanContext().IsValid() {
		span.otelSpan.SetAttributes(attributes.OTELAttributes()...)
		switch status {
		case "failed":
			span.otelSpan.SetStatus(codes.Error, status)
		case "":
		default:
			span.otelSpan.SetStatus(codes.Ok, status)
		}
		span.otelSpan.End()
	}
	emit("span_end", span, attributes)
}

func InjectEventAttributes(ctx context.Context, attributes map[string]string) {
	if attributes == nil {
		return
	}
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
	if current.TraceID == "" || current.SpanID == "" {
		if spanContext := oteltrace.SpanContextFromContext(ctx); spanContext.IsValid() {
			current.TraceID = spanContext.TraceID().String()
			current.SpanID = spanContext.SpanID().String()
		}
	}
	if current.TraceID != "" {
		attributes["trace_id"] = current.TraceID
	}
	if current.SpanID != "" {
		attributes["span_id"] = current.SpanID
	}
}

func (a Attributes) OTELAttributes() []attribute.KeyValue {
	if len(a.values) == 0 {
		return nil
	}
	attrs := make([]attribute.KeyValue, 0, len(a.values))
	for key, value := range a.values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		attrs = append(attrs, otelAttribute(key, value))
	}
	return attrs
}

func otelAttribute(key string, value any) attribute.KeyValue {
	switch v := value.(type) {
	case bool:
		return attribute.Bool(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case uint32:
		return attribute.Int64(key, int64(v))
	case uint64:
		if v <= uint64(^uint(0)>>1) {
			return attribute.Int64(key, int64(v))
		}
		return attribute.String(key, strconv.FormatUint(v, 10))
	case float64:
		return attribute.Float64(key, v)
	case string:
		return attribute.String(key, v)
	default:
		return attribute.String(key, strings.TrimSpace(fmt.Sprint(v)))
	}
}

func emit(kind string, span *Span, attributes Attributes) {
	payload := map[string]any{
		"kind": kind,
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if span != nil {
		if span.name != "" {
			payload["name"] = span.name
		}
		if span.traceID != "" {
			payload["trace_id"] = span.traceID
		}
		if span.spanID != "" {
			payload["span_id"] = span.spanID
		}
		if span.parentID != "" {
			payload["parent_span_id"] = span.parentID
		}
	}
	for key, value := range attributes.values {
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("telemetry encode: %v", err)
		return
	}
	encoded = append(encoded, '\n')
	if _, err := os.Stderr.Write(encoded); err != nil {
		log.Printf("telemetry write: %v", err)
	}
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}

func isLowerHex(value string) bool {
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func allZero(value string) bool {
	for _, ch := range value {
		if ch != '0' {
			return false
		}
	}
	return value != ""
}
