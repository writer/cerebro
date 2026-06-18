package observability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/writer/cerebro/internal/telemetry"
)

func TestNormalizeRouteLabelBoundsUnknownPaths(t *testing.T) {
	if got := normalizeRouteLabel("/platform/jobs/job-123/events"); got != "/platform/jobs/{jobID}/events" {
		t.Fatalf("job route label = %q", got)
	}
	if got := normalizeRouteLabel("/totally/random/path"); got != "/{unmatched}" {
		t.Fatalf("unknown route label = %q", got)
	}
	if got := normalizeRouteLabel("/platform/random-attacker-path"); got != "/platform/{unmatched}" {
		t.Fatalf("unknown platform route label = %q", got)
	}
	if got := normalizeRouteLabel("/source-runtimes/runtime-123/" + strings.Repeat("x", 128)); got != "/source-runtimes/{runtimeID}/{subresource}" {
		t.Fatalf("unknown source-runtime subresource label = %q", got)
	}
	if got := normalizeRouteLabel("/source-runtimes/health"); got != "/source-runtimes/health" {
		t.Fatalf("source-runtime health route label = %q", got)
	}
	if got := normalizeRouteLabel("/platform/runtime-freshness"); got != "/platform/runtime-freshness" {
		t.Fatalf("runtime freshness route label = %q", got)
	}
}

func TestNormalizeMethodLabelBoundsUnknownMethods(t *testing.T) {
	if got := normalizeMethodLabel("post"); got != http.MethodPost {
		t.Fatalf("method label = %q, want %q", got, http.MethodPost)
	}
	if got := normalizeMethodLabel("BREW-COFFEE-" + strings.Repeat("x", 128)); got != "OTHER" {
		t.Fatalf("unknown method label = %q, want OTHER", got)
	}
}

func TestMiddlewareDoesNotTrustInboundTraceParentBeforeAuth(t *testing.T) {
	attackerTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	var propagated string
	handler := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		propagated = telemetry.TraceParent(r.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set("Traceparent", "00-"+attackerTraceID+"-00f067aa0ba902b7-01")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if strings.Contains(propagated, attackerTraceID) {
		t.Fatalf("inbound traceparent was trusted before auth: %q", propagated)
	}
}

func TestMiddlewareReturnsTraceIDHeader(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))

	if got := recorder.Header().Get("X-Cerebro-Trace-Id"); len(got) != 32 {
		t.Fatalf("X-Cerebro-Trace-Id = %q, want 32 hex chars", got)
	}
}

func TestMiddlewareEmitsHTTPWideEventFields(t *testing.T) {
	_, stderr := captureObservabilityOutput(t, func() {
		handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			telemetry.AnnotateMain(r.Context(), telemetry.Attrs(
				telemetry.Field{Key: "tenant_id", Value: "tenant-a"},
				telemetry.Field{Key: "cache.redis.hit.count", Value: 1},
			))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		request := httptest.NewRequest(http.MethodPost, "/platform/jobs/job-123/events?cursor=abc&limit=10", strings.NewReader("body"))
		request.Host = "api.example.test:8443"
		request.RemoteAddr = "203.0.113.9:5678"
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Accept-Encoding", "gzip")
		request.Header.Set("Authorization", "Bearer definitely-not-emitted")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		request.Header.Set("User-Agent", "curl/8.0")

		handler.ServeHTTP(httptest.NewRecorder(), request)
	})

	payload := observabilityTelemetryPayload(t, stderr, "span_end", "http.server")
	expected := map[string]any{
		"main":                     true,
		"wide_event":               true,
		"tenant_id":                "tenant-a",
		"http.request.method":      http.MethodPost,
		"http.route":               "/platform/jobs/{jobID}/events",
		"url.path_depth":           float64(4),
		"url.query.param_count":    float64(2),
		"url.query.keys":           "cursor,limit",
		"url.scheme":               "http",
		"server.address":           "api.example.test",
		"server.port":              float64(8443),
		"network.protocol.version": "1.1",
		"http.request.body.size":   float64(4),
		"http.request.header.traceparent.present": true,
		"http.request.header.accept":              "application/json",
		"http.request.header.accept_encoding":     "gzip",
		"http.request.header.content_type":        "application/json",
		"http.request.header.user_agent.present":  true,
		"http.request.auth_header.present":        true,
		"user_agent.family":                       "curl",
		"cache.redis.hit.count":                   float64(1),
		"http.response.status_code":               float64(http.StatusOK),
		"http.response.body.size":                 float64(len(`{"ok":true}`)),
		"http.response.header.content_type":       "application/json",
	}
	for key, want := range expected {
		if got := payload[key]; got != want {
			t.Fatalf("payload[%q] = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if strings.Contains(stderr, "definitely-not-emitted") {
		t.Fatalf("authorization header leaked into telemetry: %s", stderr)
	}
	if strings.Contains(stderr, "curl/8.0") {
		t.Fatalf("raw user-agent leaked into telemetry: %s", stderr)
	}
}

func TestMiddlewareMarksServerErrorsOnOpenTelemetrySpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	})
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}
	if ended[0].Status().Code != codes.Error {
		t.Fatalf("span status = %v, want error", ended[0].Status())
	}
	events := ended[0].Events()
	if len(events) != 1 || events[0].Name != "http.server.error" {
		t.Fatalf("span events = %#v, want http.server.error", events)
	}
}

func TestStatusRecorderPreservesFlushAndUnwrap(t *testing.T) {
	inner := &flushResponseWriter{headers: http.Header{}}
	recorder := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	flusher, ok := any(recorder).(http.Flusher)
	if !ok {
		t.Fatal("statusRecorder does not implement http.Flusher")
	}
	flusher.Flush()
	if !inner.flushed {
		t.Fatal("inner writer was not flushed")
	}
	if inner.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", inner.status, http.StatusOK)
	}
	if recorder.Unwrap() != inner {
		t.Fatal("Unwrap did not return inner writer")
	}
}

type flushResponseWriter struct {
	headers http.Header
	status  int
	flushed bool
}

func (w *flushResponseWriter) Header() http.Header {
	return w.headers
}

func (w *flushResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return len(data), nil
}

func (w *flushResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *flushResponseWriter) Flush() {
	w.flushed = true
}

func captureObservabilityOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	fn()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr)
}

func observabilityTelemetryPayload(t *testing.T, stderr string, kind string, name string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", line, err)
		}
		if payload["kind"] == kind && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry payload kind=%q name=%q not found in stderr: %s", kind, name, stderr)
	return nil
}
