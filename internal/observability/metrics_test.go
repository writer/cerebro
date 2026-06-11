package observability

import (
	"net/http"
	"strings"
	"testing"
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
}

func TestNormalizeMethodLabelBoundsUnknownMethods(t *testing.T) {
	if got := normalizeMethodLabel("post"); got != http.MethodPost {
		t.Fatalf("method label = %q, want %q", got, http.MethodPost)
	}
	if got := normalizeMethodLabel("BREW-COFFEE-" + strings.Repeat("x", 128)); got != "OTHER" {
		t.Fatalf("unknown method label = %q, want OTHER", got)
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
