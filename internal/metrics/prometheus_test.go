package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRegister(t *testing.T) {
	// Should not panic
	Register()

	// Can be called multiple times safely
	Register()
}

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatal("Handler returned nil")
	}

	// Should return metrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "cerebro_") {
		t.Error("expected metrics to contain cerebro_ prefix")
	}
}

func TestRecordScanMetrics(t *testing.T) {
	Register()

	// Record successful scan
	RecordScanMetrics("aws_ec2_instances", 5*time.Second, 100, true)

	// Record failed scan
	RecordScanMetrics("aws_s3_buckets", 2*time.Second, 0, false)
}

func TestRecordSyncMetrics(t *testing.T) {
	Register()

	RecordSyncMetrics("aws", "aws_iam_accounts", "us-east-1", 3*time.Second, 5, 0)
	RecordSyncMetrics("gcp", "gcp_compute_instances", "", 2*time.Second, 0, 1)
}

func TestRecordHTTPRequest(t *testing.T) {
	Register()

	// Record various requests
	RecordHTTPRequest("GET", "/api/v1/findings", 200, 50*time.Millisecond)
	RecordHTTPRequest("POST", "/api/v1/scans", 201, 100*time.Millisecond)
	RecordHTTPRequest("GET", "/api/v1/findings/123", 404, 10*time.Millisecond)
	RecordHTTPRequest("POST", "/api/v1/policies", 500, 200*time.Millisecond)
}

func TestRecordSnowflakeQuery(t *testing.T) {
	Register()

	// Successful query
	RecordSnowflakeQuery(100*time.Millisecond, true)

	// Failed query
	RecordSnowflakeQuery(50*time.Millisecond, false)
}

func TestUpdateFindingsMetrics(t *testing.T) {
	Register()

	bySeverity := map[string]int{
		"critical": 5,
		"high":     10,
		"medium":   20,
		"low":      30,
	}

	byStatus := map[string]int{
		"open":     50,
		"resolved": 15,
	}

	// Should not panic
	UpdateFindingsMetrics(bySeverity, byStatus)
}

func TestSetBuildInfo(t *testing.T) {
	Register()

	SetBuildInfo("1.0.0", "abc123", "go1.21")
}

func TestStatusBucket(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{100, "1xx"},
		{199, "1xx"},
		{200, "2xx"},
		{201, "2xx"},
		{299, "2xx"},
		{301, "3xx"},
		{400, "4xx"},
		{404, "4xx"},
		{500, "5xx"},
		{503, "5xx"},
	}

	for _, tt := range tests {
		got := statusBucket(tt.status)
		if got != tt.want {
			t.Errorf("statusBucket(%d) = %s, want %s", tt.status, got, tt.want)
		}
	}
}

func TestNormalizeProvider(t *testing.T) {
	if got := normalizeProvider(""); got != "unknown" {
		t.Fatalf("expected unknown provider label, got %q", got)
	}
	if got := normalizeProvider("aws"); got != "aws" {
		t.Fatalf("expected provider label aws, got %q", got)
	}
}

func TestNormalizeMetricPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "/"},
		{input: "health", want: "/health"},
		{input: "/api/v1/findings/abc123", want: "/api/v1/findings/{id}"},
		{input: "/api/v1/assets/aws_s3_buckets", want: "/api/v1/assets/{table}"},
		{input: "/api/v1/webhooks/test/path", want: "/api/v1/webhooks/{subpath}"},
		{input: "/metrics", want: "/metrics"},
	}

	for _, tt := range tests {
		if got := normalizeMetricPath(tt.input); got != tt.want {
			t.Fatalf("normalizeMetricPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCacheMetrics(t *testing.T) {
	Register()

	// Record cache operations
	CacheHits.Inc()
	CacheHits.Inc()
	CacheMisses.Inc()
	CacheSize.Set(100)
}

func TestPolicyMetrics(t *testing.T) {
	Register()

	PoliciesLoaded.Set(150)
	PoliciesLoadedByType.WithLabelValues("condition_resource").Set(120)
	PoliciesLoadedByType.WithLabelValues("query_only").Set(30)
	QueryOnlyPoliciesLoaded.Set(30)
	PolicyEvaluationsTotal.WithLabelValues("s3-public-bucket", "fail").Inc()
	PolicyEvaluationsTotal.WithLabelValues("s3-public-bucket", "pass").Add(10)
}

func TestSetPolicyLoadMetrics(t *testing.T) {
	Register()
	SetPolicyLoadMetrics(20, 5)
}

func TestRecordPolicyQueryTruncation(t *testing.T) {
	Register()
	policyID := "query-policy-truncation-test"

	before := counterValue(t, PolicyQueryTruncatedTotal, policyID)
	RecordPolicyQueryTruncation(policyID)
	after := counterValue(t, PolicyQueryTruncatedTotal, policyID)

	if after != before+1 {
		t.Fatalf("expected truncation counter to increase by 1, got before=%v after=%v", before, after)
	}
}

func TestWebhookMetrics(t *testing.T) {
	Register()

	WebhookDeliveriesTotal.WithLabelValues("success").Inc()
	WebhookDeliveriesTotal.WithLabelValues("error").Inc()
	WebhookDeliveryDuration.Observe(0.5)
}

func TestNotificationMetrics(t *testing.T) {
	Register()

	NotificationsSent.WithLabelValues("slack", "success").Inc()
	NotificationsSent.WithLabelValues("pagerduty", "error").Inc()
}

func TestSchedulerMetrics(t *testing.T) {
	Register()

	SchedulerJobRuns.WithLabelValues("sync-feeds", "success").Inc()
	SchedulerJobRuns.WithLabelValues("cleanup", "error").Inc()
	SchedulerJobDuration.WithLabelValues("sync-feeds").Observe(30.0)
}

func TestSchedulerObservationHelpers(t *testing.T) {
	Register()

	beforeRuns := counterValue(t, SchedulerJobRuns, "sync-feeds", "success")
	beforeDurations := histogramCountVec(t, SchedulerJobDuration, "sync-feeds")

	RecordSchedulerJobRun("sync-feeds", "success", 2*time.Second)
	SetSchedulerQueueDepth(3)
	SetSchedulerRunningJobs(2)

	if got := counterValue(t, SchedulerJobRuns, "sync-feeds", "success"); got != beforeRuns+1 {
		t.Fatalf("expected scheduler run counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
	if got := histogramCountVec(t, SchedulerJobDuration, "sync-feeds"); got != beforeDurations+1 {
		t.Fatalf("expected scheduler duration histogram count to increase by 1, got before=%v after=%v", beforeDurations, got)
	}
	if got := gaugeValue(t, SchedulerQueueDepth); got != 3 {
		t.Fatalf("expected scheduler queue depth 3, got %v", got)
	}
	if got := gaugeValue(t, SchedulerRunningJobs); got != 2 {
		t.Fatalf("expected scheduler running jobs 2, got %v", got)
	}
}

func TestRecordScheduledAuthPreflight(t *testing.T) {
	Register()

	RecordScheduledAuthPreflight("aws", "assume_role", true)
	RecordScheduledAuthPreflight("gcp", "service_account_impersonation", false)
	RecordScheduledAuthPreflight("", "", true)
}

func TestSetProviderCountMetrics(t *testing.T) {
	Register()
	SetProviderCountMetrics(11, 22)
}

func TestRecordComplianceExport(t *testing.T) {
	Register()
	RecordComplianceExport(true)
	RecordComplianceExport(false)
}

func TestIdentityMetrics(t *testing.T) {
	Register()

	StaleAccessFindings.WithLabelValues("ssh_keys").Set(15)
	StaleAccessFindings.WithLabelValues("iam_users").Set(3)
}

func TestWorkloadAndAttackPathMetricsHelpers(t *testing.T) {
	Register()

	beforeRuns := counterValue(t, WorkloadScanRunsTotal, "aws", "succeeded", "false")
	beforeMountFailures := counterValue(t, WorkloadScanMountFailuresTotal, "aws")
	beforeStageDurations := histogramCountVec(t, WorkloadScanStageDuration, "aws", "mount", "failed")
	beforeAttackQueries := counterValue(t, AttackPathQueriesTotal, "get", "not_found")
	beforeAttackResults := histogramCountVec(t, AttackPathResultCount, "get")

	AddWorkloadScanActiveRun("aws", 1)
	AddWorkloadScanActiveRun("aws", -1)
	AddWorkloadScanActiveVolumeOp("aws", "mount", 1)
	AddWorkloadScanActiveVolumeOp("aws", "mount", -1)
	RecordWorkloadScanRun("aws", "succeeded", false, time.Second)
	RecordWorkloadScanStage("aws", "mount", "failed", 500*time.Millisecond)
	RecordWorkloadScanMountFailure("aws")
	RecordAttackPathQuery("get", "not_found", 25*time.Millisecond, 0)

	if got := counterValue(t, WorkloadScanRunsTotal, "aws", "succeeded", "false"); got != beforeRuns+1 {
		t.Fatalf("expected workload scan run counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
	if got := counterValue(t, WorkloadScanMountFailuresTotal, "aws"); got != beforeMountFailures+1 {
		t.Fatalf("expected workload mount failure counter to increase by 1, got before=%v after=%v", beforeMountFailures, got)
	}
	if got := histogramCountVec(t, WorkloadScanStageDuration, "aws", "mount", "failed"); got != beforeStageDurations+1 {
		t.Fatalf("expected workload stage histogram count to increase by 1, got before=%v after=%v", beforeStageDurations, got)
	}
	if got := gaugeVecValue(t, WorkloadScanActiveRuns, "aws"); got != 0 {
		t.Fatalf("expected workload active runs gauge to return to 0, got %v", got)
	}
	if got := gaugeVecValue(t, WorkloadScanActiveVolumeOps, "aws", "mount"); got != 0 {
		t.Fatalf("expected workload active volume ops gauge to return to 0, got %v", got)
	}
	if got := counterValue(t, AttackPathQueriesTotal, "get", "not_found"); got != beforeAttackQueries+1 {
		t.Fatalf("expected attack path query counter to increase by 1, got before=%v after=%v", beforeAttackQueries, got)
	}
	if got := histogramCountVec(t, AttackPathResultCount, "get"); got != beforeAttackResults+1 {
		t.Fatalf("expected attack path result histogram count to increase by 1, got before=%v after=%v", beforeAttackResults, got)
	}
}

func TestFindingsMetrics(t *testing.T) {
	Register()

	FindingsTotal.WithLabelValues("critical", "open").Set(5)
	FindingsTotal.WithLabelValues("high", "open").Set(10)
	FindingsByPolicy.WithLabelValues("s3-public-bucket", "high").Set(3)
}

func TestScanMetrics(t *testing.T) {
	Register()

	ScansTotal.WithLabelValues("success").Inc()
	ScansTotal.WithLabelValues("error").Inc()
	ScanDuration.WithLabelValues("aws_s3_buckets").Observe(5.5)
	AssetsScanned.WithLabelValues("aws_ec2_instances").Add(50)
}

func TestJetStreamMetrics(t *testing.T) {
	Register()

	RecordJetStreamPublish("CEREBRO_EVENTS", "published")
	RecordJetStreamPublish("CEREBRO_EVENTS", "queued")
	RecordJetStreamOutboxFlush("CEREBRO_EVENTS", "published", 2)
	RecordJetStreamOutboxFlush("CEREBRO_EVENTS", "quarantined", 1)
	SetJetStreamOutboxDepth("CEREBRO_EVENTS", 3)
	SetJetStreamOutboxOldestAge("CEREBRO_EVENTS", 2*time.Second)
	SetJetStreamPublisherReady("CEREBRO_EVENTS", true)
	SetJetStreamPublisherReady("CEREBRO_EVENTS", false)
	SetJetStreamOutboxBackpressureLevel("CEREBRO_EVENTS", "warning")
	SetJetStreamOutboxBackpressureLevel("CEREBRO_EVENTS", "critical")
	SetJetStreamOutboxBackpressureLevel("CEREBRO_EVENTS", "unknown")
	RecordJetStreamBackpressureAlert("CEREBRO_EVENTS", "warning")
	RecordJetStreamBackpressureAlert("CEREBRO_EVENTS", "critical")
	RecordJetStreamBackpressureAlert("CEREBRO_EVENTS", "recovered")
	RecordNATSConsumerProcessed("ENSEMBLE_TAP", "cerebro_graph_builder")
	RecordNATSConsumerDeduplicated("ENSEMBLE_TAP", "cerebro_graph_builder")
}

func TestSetGraphLastUpdateDoesNotRegress(t *testing.T) {
	Register()
	graphLastUpdateUnixNano.Store(0)
	t.Cleanup(func() {
		graphLastUpdateUnixNano.Store(0)
	})

	newer := time.Now().UTC()
	older := newer.Add(-time.Minute)
	SetGraphLastUpdate(newer)
	SetGraphLastUpdate(older)

	if got := gaugeValue(t, GraphLastUpdateTimestamp); got != float64(newer.Unix()) {
		t.Fatalf("expected graph last update timestamp to remain at %d, got %v", newer.Unix(), got)
	}
}

func TestSetGraphLastUpdatePublishesStoredTimestamp(t *testing.T) {
	Register()
	graphLastUpdateUnixNano.Store(0)
	t.Cleanup(func() {
		graphLastUpdateUnixNano.Store(0)
	})

	newer := time.Now().UTC()
	older := newer.Add(-time.Minute)
	graphLastUpdateUnixNano.Store(newer.UnixNano())

	SetGraphLastUpdate(older)

	if got := gaugeValue(t, GraphLastUpdateTimestamp); got != float64(newer.Unix()) {
		t.Fatalf("expected graph last update timestamp to publish stored timestamp %d, got %v", newer.Unix(), got)
	}
}

func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	counter, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get metric with labels %v: %v", labels, err)
	}
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return metric.GetGauge().GetValue()
}

func gaugeVecValue(t *testing.T, gauge *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	metric, err := gauge.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get gauge metric with labels %v: %v", labels, err)
	}
	var dtoMetric dto.Metric
	if err := metric.Write(&dtoMetric); err != nil {
		t.Fatalf("write gauge vec metric: %v", err)
	}
	return dtoMetric.GetGauge().GetValue()
}

func histogramCountVec(t *testing.T, histogram *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	collector, err := histogram.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get histogram metric with labels %v: %v", labels, err)
	}
	metricCollector, ok := collector.(prometheus.Metric)
	if !ok {
		t.Fatalf("histogram collector does not implement prometheus.Metric")
	}
	var metric dto.Metric
	if err := metricCollector.Write(&metric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	return metric.GetHistogram().GetSampleCount()
}
