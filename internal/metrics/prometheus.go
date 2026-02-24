package metrics

import (
	"net/http"
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
		[]string{"provider", "table", "region", "status"},
	)

	SyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_sync_duration_seconds",
			Help:    "Duration of sync operations",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"provider", "table", "region"},
	)

	SyncRows = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_sync_rows_total",
			Help: "Total number of rows synced",
		},
		[]string{"provider", "table", "region"},
	)

	SyncErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_sync_errors_total",
			Help: "Total number of sync errors",
		},
		[]string{"provider", "table", "region"},
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
			// Webhooks
			WebhookDeliveriesTotal,
			WebhookDeliveryDuration,
			// Notifications
			NotificationsSent,
			// Scheduler
			SchedulerJobRuns,
			SchedulerJobDuration,
			ProviderCounts,
			ComplianceExportsTotal,
			// Identity
			StaleAccessFindings,
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
	regionLabel := normalizeRegion(region)
	SyncsTotal.WithLabelValues(provider, table, regionLabel, status).Inc()
	SyncDuration.WithLabelValues(provider, table, regionLabel).Observe(duration.Seconds())
	SyncRows.WithLabelValues(provider, table, regionLabel).Add(float64(rows))
	if errorCount > 0 {
		SyncErrors.WithLabelValues(provider, table, regionLabel).Add(float64(errorCount))
	}
}

// RecordHTTPRequest records metrics for an HTTP request
func RecordHTTPRequest(method, path string, status int, duration time.Duration) {
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

func normalizeRegion(region string) string {
	if region == "" {
		return "global"
	}
	return region
}
