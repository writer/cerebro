package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_api_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_api_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	httpRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		},
	)

	scanAssetsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_scan_assets_total",
			Help: "Total number of assets scanned",
		},
		[]string{"table"},
	)

	scanFindingsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_scan_findings_total",
			Help: "Total number of findings from scans",
		},
		[]string{"severity", "policy"},
	)

	scanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_api_scan_duration_seconds",
			Help:    "Scan duration in seconds",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120},
		},
		[]string{"table"},
	)

	policyEvaluationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_api_policy_evaluations_total",
			Help: "Total number of policy evaluations",
		},
		[]string{"policy", "result"},
	)

	snowflakeQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_api_snowflake_queries_total",
			Help: "Total number of Snowflake queries",
		},
		[]string{"status"},
	)

	snowflakeQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerebro_api_snowflake_query_duration_seconds",
			Help:    "Snowflake query duration in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)

	findingsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_findings_current",
			Help: "Current number of findings by status and severity",
		},
		[]string{"status", "severity"},
	)

	webhookDeliveriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_api_webhook_deliveries_total",
			Help: "Total number of webhook deliveries",
		},
		[]string{"event_type", "success"},
	)

	agentSessionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_agent_sessions_active",
			Help: "Number of active agent sessions",
		},
	)
)

// MetricsMiddleware records HTTP request metrics
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip metrics endpoint itself
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()

		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		path := metricPath(r)

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(wrapped.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

func metricPath(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pattern := rctx.RoutePattern(); pattern != "" {
			return pattern
		}
		if len(rctx.RoutePatterns) > 0 {
			return rctx.RoutePatterns[len(rctx.RoutePatterns)-1]
		}
	}
	return normalizePath(r.URL.Path)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// normalizePath removes variable parts from paths for cardinality control
func normalizePath(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/v1/assets/"):
		return "/api/v1/assets/{table}"
	case strings.HasPrefix(path, "/api/v1/policies/"):
		return "/api/v1/policies/{id}"
	case strings.HasPrefix(path, "/api/v1/findings/"):
		return "/api/v1/findings/{id}"
	default:
		return path
	}
}

// MetricsHandler returns the Prometheus metrics handler
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// RecordScan records metrics for a scan operation
func RecordScan(table string, assetsScanned int64, findingsBySeverity map[string]int64, duration time.Duration) {
	scanAssetsTotal.WithLabelValues(table).Add(float64(assetsScanned))
	scanDuration.WithLabelValues(table).Observe(duration.Seconds())

	for severity, count := range findingsBySeverity {
		scanFindingsTotal.WithLabelValues(severity, "").Add(float64(count))
	}
}

// RecordPolicyEvaluation records a policy evaluation
func RecordPolicyEvaluation(policyID string, violated bool) {
	result := "pass"
	if violated {
		result = "fail"
	}
	policyEvaluationsTotal.WithLabelValues(policyID, result).Inc()
}

// RecordSnowflakeQuery records a Snowflake query
func RecordSnowflakeQuery(success bool, duration time.Duration) {
	status := "success"
	if !success {
		status = "error"
	}
	snowflakeQueriesTotal.WithLabelValues(status).Inc()
	snowflakeQueryDuration.Observe(duration.Seconds())
}

// RecordWebhookDelivery records a webhook delivery
func RecordWebhookDelivery(eventType string, success bool) {
	webhookDeliveriesTotal.WithLabelValues(eventType, strconv.FormatBool(success)).Inc()
}

// UpdateFindingsGauge updates the findings gauge with current counts
func UpdateFindingsGauge(bySeverityAndStatus map[string]map[string]int) {
	for status, severities := range bySeverityAndStatus {
		for severity, count := range severities {
			findingsGauge.WithLabelValues(status, severity).Set(float64(count))
		}
	}
}

// SetActiveAgentSessions sets the number of active agent sessions
func SetActiveAgentSessions(count int) {
	agentSessionsGauge.Set(float64(count))
}
