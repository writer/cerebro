package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
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
