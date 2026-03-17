package metrics

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	graphLastUpdateMu       sync.Mutex
	graphLastUpdateUnixNano atomic.Int64

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

	FindingsStoreSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_findings_store_size",
			Help: "Current number of findings retained in the active in-memory findings store",
		},
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

	NATSConsumerRedeliveriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_nats_consumer_redeliveries_total",
			Help: "Total number of NATS consumer redeliveries observed",
		},
		[]string{"stream", "durable"},
	)

	NATSConsumerProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_nats_consumer_processed_total",
			Help: "Total number of NATS consumer messages processed successfully",
		},
		[]string{"stream", "durable"},
	)

	NATSConsumerDeduplicatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_nats_consumer_deduplicated_total",
			Help: "Total number of NATS consumer messages skipped because the CloudEvent was already processed",
		},
		[]string{"stream", "durable"},
	)

	NATSConsumerLag = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_nats_consumer_lag",
			Help: "Current NATS consumer lag measured as pending plus ack-pending messages",
		},
		[]string{"stream", "durable"},
	)

	NATSConsumerLagSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_nats_consumer_lag_seconds",
			Help: "Estimated NATS consumer lag in seconds between the stream head and the last processed event time",
		},
		[]string{"stream", "durable"},
	)

	GraphBuildStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_build_status",
			Help: "Graph build status (0 not_started, 1 building, 2 success, 3 failed)",
		},
	)

	GraphLastUpdateTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_last_update_timestamp",
			Help: "Unix timestamp of the most recent successful graph update",
		},
	)

	GraphStalenessSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_staleness_seconds",
			Help: "Age in seconds of the most recent successful graph update",
		},
	)

	GraphPropertyHistoryDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_property_history_depth",
			Help: "Configured maximum number of property-history snapshots retained per node property",
		},
	)

	GraphFreshnessByProvider = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_freshness_by_provider",
			Help: "Freshness percent by provider based on observed_at coverage",
		},
		[]string{"provider"},
	)

	GraphOldestNodeAgeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_oldest_node_age_seconds",
			Help: "Age in seconds of the oldest observed active node by provider",
		},
		[]string{"provider"},
	)

	GraphProviderLastSyncTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_last_sync_timestamp",
			Help: "Unix timestamp of the most recent observed active node by provider",
		},
		[]string{"provider"},
	)

	GraphIndexBuildDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_graph_index_build_duration_seconds",
			Help:    "Duration of graph secondary-index builds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"trigger"},
	)

	GraphMutationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_graph_mutation_latency_seconds",
			Help:    "Duration of graph mutation operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"op"},
	)

	GraphSearchLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_graph_search_latency_seconds",
			Help:    "Duration of graph search operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"query_type"},
	)

	GraphSnapshotDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_graph_snapshot_duration_seconds",
			Help:    "Duration of graph snapshot operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"op"},
	)

	GraphSnapshotSizeBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_snapshot_size_bytes",
			Help: "Size in bytes of the most recently persisted graph snapshot artifact",
		},
	)

	GraphNodesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_nodes_total",
			Help: "Node count of the current live security graph",
		},
	)

	GraphEdgesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_graph_edges_total",
			Help: "Edge count of the current live security graph",
		},
	)

	GraphCloneDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerebro_graph_clone_duration_seconds",
			Help:    "Duration of full graph clone operations",
			Buckets: prometheus.DefBuckets,
		},
	)

	EventProcessingDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerebro_event_processing_duration_seconds",
			Help:    "End-to-end duration from event timestamp to successful graph processing",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
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

	SchedulerQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_scheduler_queue_depth",
			Help: "Number of due scheduler jobs awaiting execution",
		},
	)

	SchedulerRunningJobs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerebro_scheduler_running_jobs",
			Help: "Number of scheduler jobs currently executing",
		},
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

	ProviderCircuitState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_provider_circuit_state",
			Help: "Circuit breaker state per provider (0=closed, 0.5=half_open, 1=open)",
		},
		[]string{"provider"},
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

	WorkloadScanRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_workload_scan_runs_total",
			Help: "Total number of workload scan runs by provider, status, and dry-run mode",
		},
		[]string{"provider", "status", "dry_run"},
	)

	WorkloadScanRunDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_workload_scan_run_duration_seconds",
			Help:    "Duration of workload scan runs by provider, status, and dry-run mode",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		},
		[]string{"provider", "status", "dry_run"},
	)

	WorkloadScanStageDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_workload_scan_stage_duration_seconds",
			Help:    "Duration of workload scan stages by provider, stage, and status",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
		},
		[]string{"provider", "stage", "status"},
	)

	WorkloadScanActiveRuns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_workload_scan_active_runs",
			Help: "Number of workload scan runs currently executing",
		},
		[]string{"provider"},
	)

	WorkloadScanActiveVolumeOps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerebro_workload_scan_active_volume_ops",
			Help: "Number of workload scan volume operations currently executing by provider and stage",
		},
		[]string{"provider", "stage"},
	)

	WorkloadScanMountFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_workload_scan_mount_failures_total",
			Help: "Total number of workload scan mount failures by provider",
		},
		[]string{"provider"},
	)

	AttackPathQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_attack_path_queries_total",
			Help: "Total number of attack path queries by operation and status",
		},
		[]string{"operation", "status"},
	)

	AttackPathQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_attack_path_query_duration_seconds",
			Help:    "Duration of attack path queries by operation and status",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		},
		[]string{"operation", "status"},
	)

	AttackPathResultCount = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerebro_attack_path_result_count",
			Help:    "Number of attack paths returned per attack path operation",
			Buckets: []float64{0, 1, 2, 5, 10, 25, 50, 100},
		},
		[]string{"operation"},
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

	GraphCrossTenantReadsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerebro_graph_cross_tenant_reads_total",
			Help: "Total number of allowed cross-tenant graph reads by operation and bounded access scope",
		},
		[]string{"operation", "request_scope", "target_scope", "outcome"},
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
			FindingsStoreSize,
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
			NATSConsumerRedeliveriesTotal,
			NATSConsumerProcessedTotal,
			NATSConsumerDeduplicatedTotal,
			NATSConsumerLag,
			NATSConsumerLagSeconds,
			GraphBuildStatus,
			GraphLastUpdateTimestamp,
			GraphStalenessSeconds,
			GraphPropertyHistoryDepth,
			GraphFreshnessByProvider,
			GraphOldestNodeAgeSeconds,
			GraphProviderLastSyncTimestamp,
			GraphIndexBuildDuration,
			GraphMutationLatency,
			GraphSearchLatency,
			GraphSnapshotDuration,
			GraphSnapshotSizeBytes,
			GraphNodesTotal,
			GraphEdgesTotal,
			GraphCloneDuration,
			EventProcessingDuration,
			// Notifications
			NotificationsSent,
			// Scheduler
			SchedulerJobRuns,
			SchedulerJobDuration,
			SchedulerQueueDepth,
			SchedulerRunningJobs,
			ScheduledAuthPreflightTotal,
			ProviderCounts,
			ProviderCircuitState,
			ComplianceExportsTotal,
			// Identity
			StaleAccessFindings,
			WorkloadScanRunsTotal,
			WorkloadScanRunDuration,
			WorkloadScanStageDuration,
			WorkloadScanActiveRuns,
			WorkloadScanActiveVolumeOps,
			WorkloadScanMountFailuresTotal,
			AttackPathQueriesTotal,
			AttackPathQueryDuration,
			AttackPathResultCount,
			// Graph intelligence
			GraphOutcomeEventsTotal,
			GraphRuleDiscoveryCandidatesTotal,
			GraphRuleDecisionsTotal,
			GraphCrossTenantIngestRequestsTotal,
			GraphCrossTenantIngestSamplesTotal,
			GraphCrossTenantPatterns,
			GraphCrossTenantMatches,
			GraphCrossTenantReadsTotal,
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

func RecordSchedulerJobRun(job, status string, duration time.Duration) {
	job = strings.TrimSpace(job)
	if job == "" {
		job = "unknown"
	}
	status = normalizeResult(status)
	SchedulerJobRuns.WithLabelValues(job, status).Inc()
	SchedulerJobDuration.WithLabelValues(job).Observe(duration.Seconds())
}

func SetSchedulerQueueDepth(depth int) {
	if depth < 0 {
		depth = 0
	}
	SchedulerQueueDepth.Set(float64(depth))
}

func SetSchedulerRunningJobs(count int) {
	if count < 0 {
		count = 0
	}
	SchedulerRunningJobs.Set(float64(count))
}

func RecordWorkloadScanRun(provider, status string, dryRun bool, duration time.Duration) {
	provider = normalizeProvider(provider)
	status = normalizeResult(status)
	dryRunLabel := "false"
	if dryRun {
		dryRunLabel = "true"
	}
	WorkloadScanRunsTotal.WithLabelValues(provider, status, dryRunLabel).Inc()
	WorkloadScanRunDuration.WithLabelValues(provider, status, dryRunLabel).Observe(duration.Seconds())
}

func RecordWorkloadScanStage(provider, stage, status string, duration time.Duration) {
	provider = normalizeProvider(provider)
	stage = normalizeStage(stage)
	status = normalizeResult(status)
	WorkloadScanStageDuration.WithLabelValues(provider, stage, status).Observe(duration.Seconds())
}

func AddWorkloadScanActiveRun(provider string, delta int) {
	provider = normalizeProvider(provider)
	WorkloadScanActiveRuns.WithLabelValues(provider).Add(float64(delta))
}

func AddWorkloadScanActiveVolumeOp(provider, stage string, delta int) {
	provider = normalizeProvider(provider)
	stage = normalizeStage(stage)
	WorkloadScanActiveVolumeOps.WithLabelValues(provider, stage).Add(float64(delta))
}

func RecordWorkloadScanMountFailure(provider string) {
	provider = normalizeProvider(provider)
	WorkloadScanMountFailuresTotal.WithLabelValues(provider).Inc()
}

func RecordAttackPathQuery(operation, status string, duration time.Duration, resultCount int) {
	operation = normalizeOperation(operation)
	status = normalizeResult(status)
	if resultCount < 0 {
		resultCount = 0
	}
	AttackPathQueriesTotal.WithLabelValues(operation, status).Inc()
	AttackPathQueryDuration.WithLabelValues(operation, status).Observe(duration.Seconds())
	AttackPathResultCount.WithLabelValues(operation).Observe(float64(resultCount))
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

func RecordGraphCrossTenantRead(operation, requestScope, targetScope, outcome string) {
	operation = strings.TrimSpace(strings.ToLower(operation))
	if operation == "" {
		operation = "unknown"
	}
	requestScope = strings.TrimSpace(strings.ToLower(requestScope))
	if requestScope == "" {
		requestScope = "unknown"
	}
	targetScope = strings.TrimSpace(strings.ToLower(targetScope))
	if targetScope == "" {
		targetScope = "unknown"
	}
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome == "" {
		outcome = "unknown"
	}
	GraphCrossTenantReadsTotal.WithLabelValues(operation, requestScope, targetScope, outcome).Inc()
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

func RecordNATSConsumerRedelivery(stream, durable string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(durable) == "" {
		durable = "unknown"
	}
	NATSConsumerRedeliveriesTotal.WithLabelValues(stream, durable).Inc()
}

func RecordNATSConsumerProcessed(stream, durable string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(durable) == "" {
		durable = "unknown"
	}
	NATSConsumerProcessedTotal.WithLabelValues(stream, durable).Inc()
}

func RecordNATSConsumerDeduplicated(stream, durable string) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(durable) == "" {
		durable = "unknown"
	}
	NATSConsumerDeduplicatedTotal.WithLabelValues(stream, durable).Inc()
}

func SetNATSConsumerLag(stream, durable string, lag int) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(durable) == "" {
		durable = "unknown"
	}
	if lag < 0 {
		lag = 0
	}
	NATSConsumerLag.WithLabelValues(stream, durable).Set(float64(lag))
}

func SetNATSConsumerLagSeconds(stream, durable string, lag time.Duration) {
	if strings.TrimSpace(stream) == "" {
		stream = "unknown"
	}
	if strings.TrimSpace(durable) == "" {
		durable = "unknown"
	}
	if lag < 0 {
		lag = 0
	}
	NATSConsumerLagSeconds.WithLabelValues(stream, durable).Set(lag.Seconds())
}

func SetProviderCircuitState(provider, state string) {
	provider = normalizeProvider(provider)
	value := 0.0
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "open":
		value = 1
	case "half_open":
		value = 0.5
	default:
		value = 0
	}
	ProviderCircuitState.WithLabelValues(provider).Set(value)
}

func SetGraphBuildStatus(status string) {
	value := 0.0
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "building":
		value = 1
	case "success", "succeeded", "healthy":
		value = 2
	case "failed", "error":
		value = 3
	default:
		value = 0
	}
	GraphBuildStatus.Set(value)
}

func SetGraphLastUpdate(at time.Time) {
	graphLastUpdateMu.Lock()
	defer graphLastUpdateMu.Unlock()

	if at.IsZero() {
		graphLastUpdateUnixNano.Store(0)
		GraphLastUpdateTimestamp.Set(0)
		GraphStalenessSeconds.Set(0)
		return
	}
	at = at.UTC()
	targetUnixNano := at.UnixNano()
	for {
		current := graphLastUpdateUnixNano.Load()
		if current >= targetUnixNano {
			targetUnixNano = current
			break
		}
		if graphLastUpdateUnixNano.CompareAndSwap(current, targetUnixNano) {
			break
		}
	}
	effectiveAt := time.Unix(0, targetUnixNano).UTC()
	GraphLastUpdateTimestamp.Set(float64(effectiveAt.Unix()))
	SetGraphStaleness(time.Since(effectiveAt))
}

func SetGraphStaleness(age time.Duration) {
	if age < 0 {
		age = 0
	}
	GraphStalenessSeconds.Set(age.Seconds())
}

func SetGraphPropertyHistoryDepth(depth int) {
	if depth < 0 {
		depth = 0
	}
	GraphPropertyHistoryDepth.Set(float64(depth))
}

func ObserveGraphIndexBuild(trigger string, duration time.Duration) {
	if duration < 0 {
		return
	}
	trigger = strings.ToLower(strings.TrimSpace(trigger))
	if trigger == "" {
		trigger = "manual"
	}
	GraphIndexBuildDuration.WithLabelValues(trigger).Observe(duration.Seconds())
}

func ObserveGraphMutation(op string, duration time.Duration) {
	if duration < 0 {
		return
	}
	op = strings.ToLower(strings.TrimSpace(op))
	if op == "" {
		op = "unknown"
	}
	GraphMutationLatency.WithLabelValues(op).Observe(duration.Seconds())
}

func ObserveGraphSearch(queryType string, duration time.Duration) {
	if duration < 0 {
		return
	}
	queryType = strings.ToLower(strings.TrimSpace(queryType))
	if queryType == "" {
		queryType = "unknown"
	}
	GraphSearchLatency.WithLabelValues(queryType).Observe(duration.Seconds())
}

func ObserveGraphSnapshot(op string, duration time.Duration) {
	if duration < 0 {
		return
	}
	op = strings.ToLower(strings.TrimSpace(op))
	if op == "" {
		op = "unknown"
	}
	GraphSnapshotDuration.WithLabelValues(op).Observe(duration.Seconds())
}

func SetGraphSnapshotSizeBytes(size int64) {
	if size < 0 {
		size = 0
	}
	GraphSnapshotSizeBytes.Set(float64(size))
}

func SetGraphCounts(nodes, edges int) {
	if nodes < 0 {
		nodes = 0
	}
	if edges < 0 {
		edges = 0
	}
	GraphNodesTotal.Set(float64(nodes))
	GraphEdgesTotal.Set(float64(edges))
}

func ObserveGraphCloneDuration(duration time.Duration) {
	if duration < 0 {
		return
	}
	GraphCloneDuration.Observe(duration.Seconds())
}

func ResetGraphFreshnessProviderMetrics() {
	GraphFreshnessByProvider.Reset()
	GraphOldestNodeAgeSeconds.Reset()
	GraphProviderLastSyncTimestamp.Reset()
}

func SetGraphFreshnessProvider(provider string, freshnessPercent, oldestAgeSeconds float64, lastSync time.Time) {
	provider = normalizeProvider(provider)
	GraphFreshnessByProvider.WithLabelValues(provider).Set(freshnessPercent)
	if oldestAgeSeconds < 0 {
		oldestAgeSeconds = 0
	}
	GraphOldestNodeAgeSeconds.WithLabelValues(provider).Set(oldestAgeSeconds)
	if lastSync.IsZero() {
		GraphProviderLastSyncTimestamp.WithLabelValues(provider).Set(0)
		return
	}
	GraphProviderLastSyncTimestamp.WithLabelValues(provider).Set(float64(lastSync.UTC().Unix()))
}

func ObserveEventProcessingDuration(duration time.Duration) {
	if duration < 0 {
		return
	}
	EventProcessingDuration.Observe(duration.Seconds())
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

func SetFindingsStoreSize(size int) {
	if size < 0 {
		size = 0
	}
	FindingsStoreSize.Set(float64(size))
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
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "unknown"
	}
	return provider
}

func normalizeOperation(operation string) string {
	operation = strings.TrimSpace(strings.ToLower(operation))
	if operation == "" {
		return "unknown"
	}
	return operation
}

func normalizeResult(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return "unknown"
	}
	return status
}

func normalizeStage(stage string) string {
	stage = strings.TrimSpace(strings.ToLower(stage))
	if stage == "" {
		return "unknown"
	}
	return stage
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
