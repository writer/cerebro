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
			"method":      normalizeMethodLabel(r.Method),
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
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if r == nil {
		return
	}
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	if r == nil {
		return nil
	}
	return r.ResponseWriter
}

func normalizeMethodLabel(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodConnect:
		return http.MethodConnect
	case http.MethodDelete:
		return http.MethodDelete
	case http.MethodGet:
		return http.MethodGet
	case http.MethodHead:
		return http.MethodHead
	case http.MethodOptions:
		return http.MethodOptions
	case http.MethodPatch:
		return http.MethodPatch
	case http.MethodPost:
		return http.MethodPost
	case http.MethodPut:
		return http.MethodPut
	case http.MethodTrace:
		return http.MethodTrace
	default:
		return "OTHER"
	}
}

func normalizeRouteLabel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if _, ok := exactRouteLabels[path]; ok {
		return path
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if label, ok := dynamicRouteLabel(parts); ok {
		return label
	}
	return unmatchedRouteLabel(parts)
}

var exactRouteLabels = map[string]struct{}{
	"/":                                     {},
	"/health":                               {},
	"/healthz":                              {},
	"/livez":                                {},
	"/metrics":                              {},
	"/openapi.yaml":                         {},
	"/.well-known/oauth-protected-resource": {},
	"/.well-known/oauth-protected-resource/api/v1/mcp":                    {},
	"/.well-known/oauth-authorization-server":                             {},
	"/.well-known/device-jwks.json":                                       {},
	"/oauth/authorize":                                                    {},
	"/oauth/callback":                                                     {},
	"/oauth/token":                                                        {},
	"/oauth/revoke":                                                       {},
	"/oauth/register":                                                     {},
	"/reports":                                                            {},
	"/grc/dashboard":                                                      {},
	"/grc/ask":                                                            {},
	"/grc/findings":                                                       {},
	"/grc/controls":                                                       {},
	"/grc/evidence":                                                       {},
	"/finding-rules":                                                      {},
	"/endpoint-vulnerability-findings":                                    {},
	"/sources":                                                            {},
	"/platform/knowledge/decisions":                                       {},
	"/platform/knowledge/actions":                                         {},
	"/platform/knowledge/actions/recommendation":                          {},
	"/platform/knowledge/outcomes":                                        {},
	"/platform/workflow/replay":                                           {},
	"/platform/graph/neighborhood":                                        {},
	"/platform/graph/impact/package":                                      {},
	"/platform/graph/impact/asset":                                        {},
	"/platform/graph/attack-paths":                                        {},
	"/platform/graph/crown-jewel-rankings":                                {},
	"/platform/graph/aws-public-endpoint-insights":                        {},
	"/platform/graph/ingest-health":                                       {},
	"/platform/graph/ingest-runs":                                         {},
	"/platform/jobs":                                                      {},
	"/platform/runtime-response/capabilities":                             {},
	"/platform/runtime-response/actions":                                  {},
	"/platform/runtime-response/blocklist":                                {},
	"/platform/devices/enroll":                                            {},
	"/platform/devices/token":                                             {},
	"/platform/devices/bootstrap-tokens":                                  {},
	"/platform/telemetry/ingest":                                          {},
	"/source-runtimes":                                                    {},
	"/api/v1/mcp":                                                         {},
	"/cerebro.v1.BootstrapService/Health":                                 {},
	"/cerebro.v1.BootstrapService/Ingest":                                 {},
	"/cerebro.v1.BootstrapService/ListEvents":                             {},
	"/cerebro.v1.BootstrapService/ListStreams":                            {},
	"/cerebro.v1.BootstrapService/ListViews":                              {},
	"/cerebro.v1.BootstrapService/ListRules":                              {},
	"/cerebro.v1.BootstrapService/ListActions":                            {},
	"/cerebro.v1.BootstrapService/ListAgents":                             {},
	"/cerebro.v1.BootstrapService/ListSourceRuntimes":                     {},
	"/cerebro.v1.BootstrapService/CheckSourceRuntime":                     {},
	"/cerebro.v1.BootstrapService/DiscoverSourceRuntime":                  {},
	"/cerebro.v1.BootstrapService/ReadSourceRuntime":                      {},
	"/cerebro.v1.BootstrapService/PutSourceRuntime":                       {},
	"/cerebro.v1.BootstrapService/GetSourceRuntime":                       {},
	"/cerebro.v1.BootstrapService/SyncSourceRuntime":                      {},
	"/cerebro.v1.BootstrapService/ListClaims":                             {},
	"/cerebro.v1.BootstrapService/WriteClaims":                            {},
	"/cerebro.v1.BootstrapService/ListFindings":                           {},
	"/cerebro.v1.BootstrapService/ListFindingCandidates":                  {},
	"/cerebro.v1.BootstrapService/ListFindingEvidence":                    {},
	"/cerebro.v1.BootstrapService/ListFindingEvaluationRuns":              {},
	"/cerebro.v1.BootstrapService/EvaluateSourceRuntimeFindingCandidates": {},
	"/cerebro.v1.BootstrapService/EvaluateSourceRuntimeFindingRules":      {},
	"/cerebro.v1.BootstrapService/EvaluateSourceRuntimeFindings":          {},
}

func dynamicRouteLabel(parts []string) (string, bool) {
	switch {
	case match(parts, "reports", "*", "runs"):
		return "/reports/{reportID}/runs", true
	case match(parts, "report-runs", "*"):
		return "/report-runs/{runID}", true
	case match(parts, "grc", "entities", "*", "impact"):
		return "/grc/entities/{entityID}/impact", true
	case match(parts, "grc", "audit-packets", "*"):
		return "/grc/audit-packets/{packetID}", true
	case match(parts, "findings", "*"):
		return "/findings/{findingID}", true
	case match(parts, "findings", "*", "resolve"):
		return "/findings/{findingID}/resolve", true
	case match(parts, "findings", "*", "suppress"):
		return "/findings/{findingID}/suppress", true
	case match(parts, "findings", "*", "assign"):
		return "/findings/{findingID}/assign", true
	case match(parts, "findings", "*", "due"):
		return "/findings/{findingID}/due", true
	case match(parts, "findings", "*", "notes"):
		return "/findings/{findingID}/notes", true
	case match(parts, "findings", "*", "tickets"):
		return "/findings/{findingID}/tickets", true
	case match(parts, "finding-candidates", "*"):
		return "/finding-candidates/{candidateID}", true
	case match(parts, "finding-candidates", "*", "promote"):
		return "/finding-candidates/{candidateID}/promote", true
	case match(parts, "finding-candidates", "*", "reject"):
		return "/finding-candidates/{candidateID}/reject", true
	case match(parts, "finding-evaluation-runs", "*"):
		return "/finding-evaluation-runs/{runID}", true
	case match(parts, "finding-evidence", "*"):
		return "/finding-evidence/{evidenceID}", true
	case match(parts, "sources", "*", "check"):
		return "/sources/{sourceID}/check", true
	case match(parts, "sources", "*", "discover"):
		return "/sources/{sourceID}/discover", true
	case match(parts, "sources", "*", "read"):
		return "/sources/{sourceID}/read", true
	case match(parts, "source-runtimes", "health"):
		return "/source-runtimes/health", true
	case match(parts, "platform", "graph", "impact", "vulnerability", "*"):
		return "/platform/graph/impact/vulnerability/{id}", true
	case match(parts, "platform", "graph", "ingest-runs", "*"):
		return "/platform/graph/ingest-runs/{runID}", true
	case match(parts, "platform", "jobs", "*"):
		return "/platform/jobs/{jobID}", true
	case match(parts, "platform", "jobs", "*", "events"):
		return "/platform/jobs/{jobID}/events", true
	case match(parts, "platform", "jobs", "*", "cancel"):
		return "/platform/jobs/{jobID}/cancel", true
	case match(parts, "platform", "runtime-response", "blocklist", "*", "revoke"):
		return "/platform/runtime-response/blocklist/{entryID}/revoke", true
	case match(parts, "platform", "endpoints", "*", "vulnerability-findings"):
		return "/platform/endpoints/{deviceKey}/vulnerability-findings", true
	case match(parts, "platform", "devices", "*", "revoke"):
		return "/platform/devices/{deviceID}/revoke", true
	case match(parts, "source-runtimes", "*"):
		return "/source-runtimes/{runtimeID}", true
	case len(parts) == 3 && parts[0] == "source-runtimes":
		return sourceRuntimeSubresourceRouteLabel(parts[2]), true
	case len(parts) == 4 && parts[0] == "source-runtimes" && parts[2] == "finding-candidates" && parts[3] == "evaluate":
		return "/source-runtimes/{runtimeID}/finding-candidates/evaluate", true
	case len(parts) == 4 && parts[0] == "source-runtimes" && parts[2] == "finding-rules" && parts[3] == "evaluate":
		return "/source-runtimes/{runtimeID}/finding-rules/evaluate", true
	case len(parts) == 4 && parts[0] == "source-runtimes" && parts[2] == "findings" && parts[3] == "evaluate":
		return "/source-runtimes/{runtimeID}/findings/evaluate", true
	default:
		return "", false
	}
}

func sourceRuntimeSubresourceRouteLabel(subresource string) string {
	switch subresource {
	case "sync", "graph-ingest-runs", "claims", "findings", "finding-candidates", "finding-evidence", "finding-evaluation-runs":
		return "/source-runtimes/{runtimeID}/" + subresource
	default:
		return "/source-runtimes/{runtimeID}/{subresource}"
	}
}

func match(parts []string, pattern ...string) bool {
	if len(parts) != len(pattern) {
		return false
	}
	for i, want := range pattern {
		if want == "*" {
			if strings.TrimSpace(parts[i]) == "" {
				return false
			}
			continue
		}
		if parts[i] != want {
			return false
		}
	}
	return true
}

func unmatchedRouteLabel(parts []string) string {
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "/{unmatched}"
	}
	switch parts[0] {
	case ".well-known", "api", "cerebro.v1.BootstrapService", "finding-candidates", "finding-evaluation-runs", "finding-evidence", "finding-rules", "findings", "grc", "health", "healthz", "livez", "metrics", "oauth", "openapi.yaml", "platform", "report-runs", "reports", "source-runtimes", "sources":
		return "/" + parts[0] + "/{unmatched}"
	default:
		return "/{unmatched}"
	}
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
