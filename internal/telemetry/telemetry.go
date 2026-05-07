package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"time"
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
	span := &Span{
		name:     name,
		traceID:  traceID,
		spanID:   randomHex(8),
		parentID: parent.SpanID,
		started:  time.Now().UTC(),
	}
	next := context.WithValue(ctx, spanContextKey{}, spanContext{TraceID: span.traceID, SpanID: span.spanID})
	emit("span_start", span, attributes)
	return next, span
}

func Event(ctx context.Context, name string, attributes Attributes) {
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
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
	emit("span_end", span, attributes)
}

func InjectEventAttributes(ctx context.Context, attributes map[string]string) {
	if attributes == nil {
		return
	}
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
	if current.TraceID != "" {
		attributes["trace_id"] = current.TraceID
	}
	if current.SpanID != "" {
		attributes["span_id"] = current.SpanID
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
