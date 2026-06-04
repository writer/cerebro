package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/telemetry"
)

var Default = NewRegistry()

type Registry struct {
	mu       sync.Mutex
	counters map[string]float64
}

func NewRegistry() *Registry {
	return &Registry{counters: map[string]float64{}}
}

func (r *Registry) Inc(name string, labels map[string]string) {
	r.Add(name, labels, 1)
}

func (r *Registry) Add(name string, labels map[string]string, value float64) {
	if r == nil || strings.TrimSpace(name) == "" {
		return
	}
	key := metricKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[key] += value
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})
}

func (r *Registry) Render() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]string, 0, len(r.counters))
	for key := range r.counters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteByte(' ')
		out.WriteString(strconv.FormatFloat(r.counters[key], 'f', -1, 64))
		out.WriteByte('\n')
	}
	return out.String()
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := telemetry.WithTraceParent(r.Context(), r.Header.Get("Traceparent"))
		r = r.WithContext(ctx)
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		labels := map[string]string{
			"method":      r.Method,
			"route":       normalizeRouteLabel(r.URL.Path),
			"status_code": strconv.Itoa(recorder.status),
		}
		Default.Inc("cerebro_http_requests_total", labels)
		Default.Add("cerebro_http_request_duration_seconds_sum", labels, time.Since(started).Seconds())
		Default.Inc("cerebro_http_request_duration_seconds_count", labels)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func normalizeRouteLabel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if looksVariable(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func looksVariable(part string) bool {
	if len(part) >= 12 && strings.HasPrefix(part, "job-") {
		return true
	}
	if len(part) >= 8 && strings.ContainsAny(part, "0123456789") {
		return true
	}
	return false
}

func metricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf(`%s=%q`, sanitizeLabelName(key), labels[key]))
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func sanitizeLabelName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "label"
	}
	replacer := strings.NewReplacer("-", "_", ".", "_", "/", "_")
	return replacer.Replace(value)
}
