package telemetry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/writer/cerebro/internal/buildinfo"
)

type spanContextKey struct{}
type mainSpanContextKey struct{}

type spanContext struct {
	TraceID string
	SpanID  string
}

type Span struct {
	mu          sync.Mutex
	name        string
	traceID     string
	spanID      string
	parentID    string
	started     time.Time
	otelSpan    oteltrace.Span
	main        bool
	annotations map[string]any
}

type Attributes struct {
	values map[string]any
}

type Field struct {
	Key   string
	Value any
}

const maxAttributeStringLength = 1024

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

func (a Attributes) With(other Attributes) Attributes {
	for key, value := range other.values {
		a = a.with(key, value)
	}
	return a
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

func RuntimeAttributes() Attributes {
	hostname, _ := os.Hostname()
	return Attrs(
		Field{Key: "service.name", Value: buildinfo.ServiceName},
		Field{Key: "service.version", Value: buildinfo.Version},
		Field{Key: "service.commit", Value: buildinfo.Commit},
		Field{Key: "service.build_date", Value: buildinfo.BuildDate},
		Field{Key: "deployment.environment", Value: "unknown"},
		Field{Key: "host.name", Value: hostname},
		Field{Key: "os.type", Value: runtime.GOOS},
		Field{Key: "os.arch", Value: runtime.GOARCH},
		Field{Key: "process.pid", Value: os.Getpid()},
		Field{Key: "process.runtime.name", Value: "go"},
		Field{Key: "process.runtime.version", Value: runtime.Version()},
		Field{Key: "process.cpu.count", Value: runtime.NumCPU()},
		Field{Key: "go.goroutine.count", Value: runtime.NumGoroutine()},
		Field{Key: "cloud.provider", Value: "unknown"},
		Field{Key: "cloud.region", Value: ""},
		Field{Key: "container.id", Value: hostname},
	)
}

func Start(ctx context.Context, name string, attributes Attributes) (context.Context, *Span) {
	return StartWithOptions(ctx, name, attributes)
}

func StartMain(ctx context.Context, name string, attributes Attributes, options ...oteltrace.SpanStartOption) (context.Context, *Span) {
	attributes = RuntimeAttributes().With(attributes).
		WithField(Field{Key: "main", Value: true}).
		WithField(Field{Key: "wide_event", Value: true})
	ctx, span := StartWithOptions(ctx, name, attributes, options...)
	span.main = true
	span.annotate(attributes)
	ctx = context.WithValue(ctx, mainSpanContextKey{}, span)
	return ctx, span
}

func StartWithOptions(ctx context.Context, name string, attributes Attributes, options ...oteltrace.SpanStartOption) (context.Context, *Span) {
	parent, _ := ctx.Value(spanContextKey{}).(spanContext)
	traceID := parent.TraceID
	if traceID == "" {
		traceID = randomHex(16)
	}
	spanOptions := append([]oteltrace.SpanStartOption{oteltrace.WithAttributes(attributes.OTELAttributes()...)}, options...)
	otelCtx, otelSpan := otel.Tracer("github.com/writer/cerebro/internal/telemetry").Start(ctx, name, spanOptions...)
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

// EnsureTraceContext makes TraceParent available even when no OTEL provider is
// installed. It is intentionally quiet: it does not emit span_start/span_end.
func EnsureTraceContext(ctx context.Context) context.Context {
	current, _ := ctx.Value(spanContextKey{}).(spanContext)
	if current.TraceID != "" && current.SpanID != "" {
		return ctx
	}
	if sc := oteltrace.SpanContextFromContext(ctx); sc.IsValid() {
		return context.WithValue(ctx, spanContextKey{}, spanContext{
			TraceID: sc.TraceID().String(),
			SpanID:  sc.SpanID().String(),
		})
	}
	return context.WithValue(ctx, spanContextKey{}, spanContext{TraceID: randomHex(16), SpanID: randomHex(8)})
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

func AnnotateMain(ctx context.Context, attributes Attributes) {
	if span, ok := ctx.Value(mainSpanContextKey{}).(*Span); ok && span != nil {
		span.annotate(attributes)
	}
}

func IncrementMain(ctx context.Context, key string, delta int64) {
	if strings.TrimSpace(key) == "" || delta == 0 {
		return
	}
	span, ok := ctx.Value(mainSpanContextKey{}).(*Span)
	if !ok || span == nil {
		return
	}
	span.increment(key, delta)
}

// CaptureError records a Sentry-style handled error event without serializing
// the raw error message. Raw messages often contain DSNs, URLs, or token-shaped
// values, so errors are grouped with a stable kind and fingerprint instead.
func CaptureError(ctx context.Context, name string, err error, attributes Attributes) {
	if err == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "error.capture"
	}
	kind := ErrorKind(err)
	attributes = attributes.with("error_kind", kind).
		with("error_fingerprint", ErrorFingerprint(name, err, attributes)).
		with("handled", true)
	if span := oteltrace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		span.SetStatus(codes.Error, kind)
	}
	Event(ctx, name, attributes)
}

func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline_exceeded"
	}
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", err), "*")
	switch typeName {
	case "errors.errorString":
		return "error"
	case "fmt.wrapError", "fmt.wrapErrors":
		if unwrapped := unwrapOne(err); unwrapped != nil {
			return ErrorKind(unwrapped)
		}
		return "wrapped_error"
	}
	return compactErrorKind(typeName)
}

func ErrorFingerprint(name string, err error, attributes Attributes) string {
	component := fingerprintAttribute(attributes, "component")
	operation := fingerprintAttribute(attributes, "operation")
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(name),
		ErrorKind(err),
		component,
		operation,
	}, "|")))
	return hex.EncodeToString(sum[:8])
}

func fingerprintAttribute(attributes Attributes, key string) string {
	value, ok := attributes.values[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func End(span *Span, status string, attributes Attributes) {
	if span == nil {
		return
	}
	for key, value := range span.snapshotAnnotations() {
		if _, exists := attributes.values[key]; !exists {
			attributes = attributes.with(key, value)
		}
	}
	if status != "" {
		attributes = attributes.with("status", status)
	}
	attributes = attributes.with("duration_ms", time.Since(span.started).Milliseconds())
	if span.otelSpan != nil && span.otelSpan.SpanContext().IsValid() {
		span.otelSpan.SetAttributes(attributes.OTELAttributes()...)
		switch telemetryStatus(strings.TrimSpace(status)) {
		case codes.Error:
			span.otelSpan.SetStatus(codes.Error, status)
		case codes.Unset:
		default:
			span.otelSpan.SetStatus(codes.Ok, status)
		}
		span.otelSpan.End()
	}
	emit("span_end", span, attributes)
}

func (s *Span) annotate(attributes Attributes) {
	if s == nil || len(attributes.values) == 0 {
		return
	}
	s.mu.Lock()
	if s.annotations == nil {
		s.annotations = map[string]any{}
	}
	for key, value := range attributes.values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		s.annotations[key] = value
	}
	s.mu.Unlock()
	if s.otelSpan != nil && s.otelSpan.SpanContext().IsValid() {
		s.otelSpan.SetAttributes(attributes.OTELAttributes()...)
	}
}

func (s *Span) increment(key string, delta int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.annotations == nil {
		s.annotations = map[string]any{}
	}
	current := int64(0)
	switch value := s.annotations[key].(type) {
	case int:
		current = int64(value)
	case int64:
		current = value
	case uint32:
		current = int64(value)
	case uint64:
		if value <= uint64(^uint(0)>>1) {
			current = int64(value)
		}
	case float64:
		current = int64(value)
	}
	next := current + delta
	s.annotations[key] = next
	s.mu.Unlock()
	if s.otelSpan != nil && s.otelSpan.SpanContext().IsValid() {
		s.otelSpan.SetAttributes(attribute.Int64(key, next))
	}
}

func (s *Span) snapshotAnnotations() map[string]any {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.annotations) == 0 {
		return nil
	}
	copied := make(map[string]any, len(s.annotations))
	for key, value := range s.annotations {
		copied[key] = value
	}
	return copied
}

func telemetryStatus(status string) codes.Code {
	switch strings.ToLower(status) {
	case "", "canceled", "cancelled":
		return codes.Unset
	case "failed", "error":
		return codes.Error
	default:
		return codes.Ok
	}
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
		attrs = append(attrs, otelAttribute(key, safeAttributeValue(key, value)))
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

func unwrapOne(err error) error {
	type single interface {
		Unwrap() error
	}
	type multi interface {
		Unwrap() []error
	}
	if wrapper, ok := err.(single); ok {
		return wrapper.Unwrap()
	}
	if wrapper, ok := err.(multi); ok {
		for _, child := range wrapper.Unwrap() {
			if child != nil {
				return child
			}
		}
	}
	return nil
}

func compactErrorKind(typeName string) string {
	typeName = strings.TrimSpace(typeName)
	if typeName == "" {
		return "error"
	}
	typeName = strings.TrimPrefix(typeName, "github.com/writer/cerebro/")
	typeName = strings.ReplaceAll(typeName, "/", ".")
	typeName = strings.ReplaceAll(typeName, "*", "")
	var out strings.Builder
	out.Grow(len(typeName))
	for _, ch := range typeName {
		switch {
		case ch >= 'a' && ch <= 'z':
			out.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			if out.Len() > 0 {
				out.WriteByte('_')
			}
			out.WriteRune(ch + ('a' - 'A'))
		case ch >= '0' && ch <= '9':
			out.WriteRune(ch)
		case ch == '.' || ch == '_' || ch == '-':
			out.WriteByte('_')
		default:
			out.WriteByte('_')
		}
	}
	kind := strings.Trim(out.String(), "_")
	if kind == "" {
		return "error"
	}
	for strings.Contains(kind, "__") {
		kind = strings.ReplaceAll(kind, "__", "_")
	}
	return kind
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
		payload[key] = safeAttributeValue(key, value)
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

func safeAttributeValue(key string, value any) any {
	if secretLikeKey(key) {
		return "[redacted]"
	}
	switch v := value.(type) {
	case string:
		return boundString(v, maxAttributeStringLength)
	case fmt.Stringer:
		return boundString(v.String(), maxAttributeStringLength)
	default:
		return value
	}
}

func secretLikeKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range []string{
		"authorization",
		"api_key",
		"apikey",
		"access_token",
		"refresh_token",
		"id_token",
		"token_secret",
		"secret",
		"password",
		"cookie",
		"credential_id",
		"credential_secret",
		"credential_value",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func boundString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
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
