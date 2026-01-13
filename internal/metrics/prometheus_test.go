package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	PolicyEvaluationsTotal.WithLabelValues("s3-public-bucket", "fail").Inc()
	PolicyEvaluationsTotal.WithLabelValues("s3-public-bucket", "pass").Add(10)
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

func TestIdentityMetrics(t *testing.T) {
	Register()

	StaleAccessFindings.WithLabelValues("ssh_keys").Set(15)
	StaleAccessFindings.WithLabelValues("iam_users").Set(3)
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
