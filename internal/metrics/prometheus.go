package metrics

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Findings metrics
	FindingsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_findings_total",
			Help: "Total number of findings",
		},
		[]string{"severity", "status"},
	)

	FindingsByPolicy = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_findings_by_policy",
			Help: "Number of findings per policy",
		},
		[]string{"policy_id", "severity"},
	)

	// Scan metrics
	ScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_scans_total",
			Help: "Total number of policy scans",
		},
		[]string{"status"},
	)

	// Sync metrics
	SyncsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_syncs_total",
			Help: "Total number of sync operations",
		},
		[]string{"provider", "status"},
	)

	SyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_sync_duration_seconds",
			Help:    "Duration of sync operations",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"provider"},
	)

	SyncRows = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_sync_rows_total",
			Help: "Total number of rows synced",
		},
		[]string{"provider"},
	)

	SyncErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_sync_errors_total",
			Help: "Total number of sync errors",
		},
		[]string{"provider"},
	)

	ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_scan_duration_seconds",
			Help:    "Duration of policy scans",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"table"},
	)

	AssetsScanned = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_assets_scanned_total",
			Help: "Total number of assets scanned",
		},
		[]string{"table"},
	)

	// API metrics
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_http_request_duration_seconds",
			Help:    "Duration of HTTP requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Cache metrics
	CacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cerebro_cache_hits_total",
			Help: "Total number of cache hits",
		},
	)

	CacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cerebro_cache_misses_total",
			Help: "Total number of cache misses",
		},
	)

	CacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_cache_size",
			Help: "Current number of items in cache",
		},
	)

	// Snowflake metrics
	SnowflakeQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_snowflake_queries_total",
			Help: "Total number of Snowflake queries",
		},
		[]string{"status"},
	)

	SnowflakeQueryDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerebro_snowflake_query_duration_seconds",
			Help:    "Duration of Snowflake queries",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 12),
		},
	)

	// Policy metrics
	PoliciesLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_policies_loaded",
			Help: "Number of policies loaded",
		},
	)

	PoliciesLoadedByType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_policies_loaded_by_type",
			Help: "Number of policies loaded by type",
		},
		[]string{"type"},
	)

	QueryOnlyPoliciesLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_query_only_policies_loaded",
			Help: "Number of query-only policies loaded",
		},
	)

	PolicyEvaluationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_policy_evaluations_total",
			Help: "Total number of policy evaluations",
		},
		[]string{"policy_id", "result"},
	)

	PolicyQueryTruncatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_policy_query_truncated_total",
			Help: "Total number of query policy scans where row limit truncation was detected",
		},
		[]string{"policy_id"},
	)

	// Webhook metrics
	WebhookDeliveriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_webhook_deliveries_total",
			Help: "Total number of webhook deliveries",
		},
		[]string{"status"},
	)

	WebhookDeliveryDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerebro_webhook_delivery_duration_seconds",
			Help:    "Duration of webhook deliveries",
			Buckets: prometheus.DefBuckets,
		},
	)

	JetStreamPublishTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_jetstream_publish_total",
			Help: "Total number of JetStream publish attempts",
		},
		[]string{"stream", "result"},
	)

	JetStreamOutboxFlushTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_jetstream_outbox_flush_total",
			Help: "Total number of JetStream outbox flush operations",
		},
		[]string{"stream", "result"},
	)

	JetStreamOutboxDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_jetstream_outbox_depth",
			Help: "Current number of queued records in the JetStream outbox",
		},
		[]string{"stream"},
	)

	JetStreamOutboxOldestAge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_jetstream_outbox_oldest_age_seconds",
			Help: "Age in seconds of the oldest queued outbox record",
		},
		[]string{"stream"},
	)

	JetStreamPublisherReady = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_jetstream_publisher_ready",
			Help: "JetStream publisher readiness (1 ready, 0 not ready)",
		},
		[]string{"stream"},
	)

	JetStreamOutboxBackpressureLevel = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_jetstream_outbox_backpressure_level",
			Help: "JetStream outbox backpressure level (0 normal, 1 warning, 2 critical, 3 unknown)",
		},
		[]string{"stream"},
	)

	JetStreamBackpressureAlertsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_jetstream_backpressure_alerts_total",
			Help: "Number of JetStream outbox backpressure alert transitions",
		},
		[]string{"stream", "level"},
	)

	NATSConsumerDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_nats_consumer_dropped_total",
			Help: "Total number of NATS consumer messages dropped after successful dead-letter quarantine",
		},
		[]string{"stream", "durable", "reason"},
	)

	// Notification metrics
	NotificationsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_notifications_sent_total",
			Help: "Total number of notifications sent",
		},
		[]string{"provider", "status"},
	)

	// Scheduler metrics
	SchedulerJobRuns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_scheduler_job_runs_total",
			Help: "Total number of scheduler job runs",
		},
		[]string{"job", "status"},
	)

	SchedulerJobDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_scheduler_job_duration_seconds",
			Help:    "Duration of scheduler job runs",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		},
		[]string{"job"},
	)

	ScheduledAuthPreflightTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_scheduled_auth_preflight_total",
			Help: "Total number of scheduled sync auth preflight checks",
		},
		[]string{"provider", "auth_method", "status"},
	)

	ProviderCounts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_provider_count",
			Help: "Provider counts by state",
		},
		[]string{"state"},
	)

	ComplianceExportsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_compliance_exports_total",
			Help: "Total number of compliance export attempts",
		},
		[]string{"status"},
	)

	// Identity metrics
	StaleAccessFindings = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_stale_access_findings",
			Help: "Number of stale access findings",
		},
		[]string{"type"},
	)

	GraphOutcomeEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_outcome_events_total",
			Help: "Total number of graph outcome events by status",
		},
		[]string{"status"},
	)

	GraphRuleDiscoveryCandidatesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_rule_discovery_candidates_total",
			Help: "Total number of graph rule discovery candidates by type and status",
		},
		[]string{"type", "status"},
	)

	GraphRuleDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_rule_decisions_total",
			Help: "Total number of graph rule review decisions by type and resulting status",
		},
		[]string{"type", "status"},
	)

	GraphCrossTenantIngestRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_cross_tenant_ingest_requests_total",
			Help: "Total number of cross-tenant ingest requests by result",
		},
		[]string{"result"},
	)

	GraphCrossTenantIngestSamplesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_cross_tenant_ingest_samples_total",
			Help: "Total number of cross-tenant ingest samples by result",
		},
		[]string{"result"},
	)

	GraphCrossTenantPatterns = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_cross_tenant_patterns",
			Help: "Current number of cross-tenant aggregate patterns returned by API",
		},
	)

	GraphCrossTenantMatches = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_cross_tenant_matches",
			Help: "Current number of cross-tenant matches returned by API",
		},
	)

	GraphStatePersistenceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_state_persistence_total",
			Help: "Total number of risk-engine state persistence operations by result",
		},
		[]string{"result"},
	)

	// Build info
	BuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_build_info",
			Help: "Build information",
		},
		[]string{"version", "commit", "go_version"},
	)
)

var (
	registerOnce sync.Once
)

// Register registers all metrics with Prometheus
func Register() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			// Findings
			FindingsTotal,
			FindingsByPolicy,
			// Scans
			ScansTotal,
			ScanDuration,
			AssetsScanned,
			// Syncs
			SyncsTotal,
			SyncDuration,
			SyncRows,
			SyncErrors,
			// HTTP
			HTTPRequestsTotal,
			HTTPRequestDuration,
			// Cache
			CacheHits,
			CacheMisses,
			CacheSize,
			// Snowflake
			SnowflakeQueriesTotal,
			SnowflakeQueryDuration,
			// Policies
			PoliciesLoaded,
			PoliciesLoadedByType,
			QueryOnlyPoliciesLoaded,
			PolicyEvaluationsTotal,
			PolicyQueryTruncatedTotal,
			// Webhooks
			WebhookDeliveriesTotal,
			WebhookDeliveryDuration,
			JetStreamPublishTotal,
			JetStreamOutboxFlushTotal,
			JetStreamOutboxDepth,
			JetStreamOutboxOldestAge,
			JetStreamPublisherReady,
			JetStreamOutboxBackpressureLevel,
			JetStreamBackpressureAlertsTotal,
			NATSConsumerDroppedTotal,
			// Notifications
			NotificationsSent,
			// Scheduler
			SchedulerJobRuns,
			SchedulerJobDuration,
			ScheduledAuthPreflightTotal,
			ProviderCounts,
			ComplianceExportsTotal,
			// Identity
			StaleAccessFindings,
			// Graph intelligence
			GraphOutcomeEventsTotal,
			GraphRuleDiscoveryCandidatesTotal,
			GraphRuleDecisionsTotal,
			GraphCrossTenantIngestRequestsTotal,
			GraphCrossTenantIngestSamplesTotal,
			GraphCrossTenantPatterns,
			GraphCrossTenantMatches,
			GraphStatePersistenceTotal,
			// Build
			BuildInfo,
		)
	})
}

// Handler returns the Prometheus HTTP handler
func Handler() http.Handler {
	Register()
	return promhttp.Handler()
}

// RecordScanMetrics records metrics for a completed scan
func RecordScanMetrics(table string, duration time.Duration, assetsCount int64, success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	ScansTotal.WithLabelValues(status).Inc()
	ScanDuration.WithLabelValues(table).Observe(duration.Seconds())
	AssetsScanned.WithLabelValues(table).Add(float64(assetsCount))
}

// RecordSyncMetrics records metrics for a completed sync operation
func RecordSyncMetrics(provider, table, region string, duration time.Duration, rows, errorCount int) {
	status := "success"
	if errorCount > 0 {
		status = "error"
	}
	_ = table
	_ = region
	providerLabel := normalizeProvider(provider)
	SyncsTotal.WithLabelValues(providerLabel, status).Inc()
	SyncDuration.WithLabelValues(providerLabel).Observe(duration.Seconds())
	SyncRows.WithLabelValues(providerLabel).Add(float64(rows))
	if errorCount > 0 {
		SyncErrors.WithLabelValues(providerLabel).Add(float64(errorCount))
	}
}

// RecordHTTPRequest records metrics for an HTTP request
func RecordHTTPRequest(method, path string, status int, duration time.Duration) {
	path = normalizeMetricPath(path)
	HTTPRequestsTotal.WithLabelValues(method, path, statusBucket(status)).Inc()
	HTTPRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordSnowflakeQuery records metrics for a Snowflake query
func RecordSnowflakeQuery(duration time.Duration, success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	SnowflakeQueriesTotal.WithLabelValues(status).Inc()
	SnowflakeQueryDuration.Observe(duration.Seconds())
}

// SetPolicyLoadMetrics sets policy load gauges for total and type-specific counts.
func SetPolicyLoadMetrics(totalPolicies, queryOnlyPolicies int) {
	if queryOnlyPolicies > totalPolicies {
		queryOnlyPolicies = totalPolicies
	}

	conditionPolicies := totalPolicies - queryOnlyPolicies
	PoliciesLoaded.Set(float64(totalPolicies))
	PoliciesLoadedByType.WithLabelValues("condition_resource").Set(float64(conditionPolicies))
	PoliciesLoadedByType.WithLabelValues("query_only").Set(float64(queryOnlyPolicies))
	QueryOnlyPoliciesLoaded.Set(float64(queryOnlyPolicies))
}

func RecordPolicyQueryTruncation(policyID string) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		policyID = "unknown"
	}
	PolicyQueryTruncatedTotal.WithLabelValues(policyID).Inc()
}

// SetProviderCountMetrics sets provider inventory gauges.
func SetProviderCountMetrics(registeredProviders, implementedProviders int) {
	ProviderCounts.WithLabelValues("registered").Set(float64(registeredProviders))
	ProviderCounts.WithLabelValues("implemented").Set(float64(implementedProviders))
}

// RecordComplianceExport records an attempted compliance export.
func RecordComplianceExport(success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	ComplianceExportsTotal.WithLabelValues(status).Inc()
}

// RecordScheduledAuthPreflight records scheduled sync auth preflight status by provider and auth mode.
func RecordScheduledAuthPreflight(provider, authMethod string, success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	if strings.TrimSpace(provider) == "" {
		provider = "unknown"
	}
	if strings.TrimSpace(authMethod) == "" {
		authMethod = "unknown"
	}
	ScheduledAuthPreflightTotal.WithLabelValues(provider, authMethod, status).Inc()
}

func RecordGraphOutcome(status string) {
	status = strings.TrimSpace(status)
	if status == "" {
		status = "unknown"
	}
	GraphOutcomeEventsTotal.WithLabelValues(status).Inc()
}

func RecordGraphRuleDiscoveryCandidate(ruleType, status string) {
	ruleType = strings.TrimSpace(strings.ToLower(ruleType))
	if ruleType == "" {
		ruleType = "unknown"
	}
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		status = "unknown"
	}
	GraphRuleDiscoveryCandidatesTotal.WithLabelValues(ruleType, status).Inc()
}

func RecordGraphRuleDecision(ruleType, status string) {
	ruleType = strings.TrimSpace(strings.ToLower(ruleType))
	if ruleType == "" {
		ruleType = "unknown"
	}
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		status = "unknown"
	}
	GraphRuleDecisionsTotal.WithLabelValues(ruleType, status).Inc()
}

func RecordGraphCrossTenantIngest(result string, samples int) {
	result = strings.TrimSpace(strings.ToLower(result))
	if result == "" {
		result = "unknown"
	}
	GraphCrossTenantIngestRequestsTotal.WithLabelValues(result).Inc()
	if samples > 0 {
		GraphCrossTenantIngestSamplesTotal.WithLabelValues(result).Add(float64(samples))
	}
}

func RecordGraphCrossTenantPatterns(count int) {
	if count < 0 {
		count = 0
	}
	GraphCrossTenantPatterns.Set(float64(count))
}

func RecordGraphCrossTenantMatches(count int) {
	if count < 0 {
		count = 0
	}
	GraphCrossTenantMatches.Set(float64(count))
}

func RecordGraphStatePersistence(result string) {
	result = strings.TrimSpace(strings.ToLower(result))
	if result == "" {
		result = "unknown"
	}
	GraphStatePersistenceTotal.WithLabelValues(result).Inc()
}

func RecordJetStreamPublish(stream, result string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(result) == "" {
		result = "unknown"
	}
	JetStreamPublishTotal.WithLabelValues(stream, result).Inc()
}

func RecordJetStreamOutboxFlush(stream, result string, count int) {
	if count <= 0 {
		return
	}
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(result) == "" {
		result = "unknown"
	}
	JetStreamOutboxFlushTotal.WithLabelValues(stream, result).Add(float64(count))
}

func SetJetStreamOutboxDepth(stream string, depth int) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if depth < 0 {
		depth = 0
	}
	JetStreamOutboxDepth.WithLabelValues(stream).Set(float64(depth))
}

func SetJetStreamOutboxOldestAge(stream string, age time.Duration) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if age < 0 {
		age = 0
	}
	JetStreamOutboxOldestAge.WithLabelValues(stream).Set(age.Seconds())
}

func SetJetStreamPublisherReady(stream string, ready bool) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if ready {
		JetStreamPublisherReady.WithLabelValues(stream).Set(1)
		return
	}
	JetStreamPublisherReady.WithLabelValues(stream).Set(0)
}

func SetJetStreamOutboxBackpressureLevel(stream, level string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}

	value := 0.0
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "normal":
		value = 0
	case "warning":
		value = 1
	case "critical":
		value = 2
	case "unknown":
		value = 3
	default:
		value = 3
	}

	JetStreamOutboxBackpressureLevel.WithLabelValues(stream).Set(value)
}

func RecordJetStreamBackpressureAlert(stream, level string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "" {
		level = "unknown"
	}
	JetStreamBackpressureAlertsTotal.WithLabelValues(stream, level).Inc()
}

// UpdateFindingsMetrics updates findings gauge metrics
func UpdateFindingsMetrics(bySeverity, byStatus map[string]int) {
	// Reset all values
	FindingsTotal.Reset()

	for severity, count := range bySeverity {
		for status, statusCount := range byStatus {
			// This is a simplification - ideally we'd have the cross-product
			FindingsTotal.WithLabelValues(severity, status).Set(float64(statusCount))
			_ = count // Use severity count elsewhere
		}
	}
}

// SetBuildInfo sets the build info metric
func SetBuildInfo(version, commit, goVersion string) {
	BuildInfo.WithLabelValues(version, commit, goVersion).Set(1)
}

func statusBucket(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func normalizeProvider(provider string) string {
	if strings.TrimSpace(provider) == "" {
		return "unknown"
	}
	return provider
}

func normalizeMetricPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}

	switch {
	case strings.HasPrefix(path, "/api/v1/assets/"):
		return "/api/v1/assets/{table}"
	case strings.HasPrefix(path, "/api/v1/policies/"):
		return "/api/v1/policies/{id}"
	case strings.HasPrefix(path, "/api/v1/findings/"):
		return "/api/v1/findings/{id}"
	case strings.HasPrefix(path, "/api/v1/"):
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) >= 4 {
			return "/" + strings.Join(parts[:3], "/") + "/{subpath}"
		}
		return path
	default:
		return path
	}
}
