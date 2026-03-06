package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

// newTestApp creates a minimal in-memory App suitable for API integration tests.
func newTestApp(t *testing.T) *app.App {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	pe := policy.NewEngine()
	fs := findings.NewStore()
	sc := scanner.NewScanner(pe, scanner.ScanConfig{Workers: 2}, logger)

	return &app.App{
		Config: &app.Config{
			LogLevel: "error",
			Port:     0,
		},
		Logger:         logger,
		Policy:         pe,
		Findings:       fs,
		Scanner:        sc,
		Cache:          cache.NewPolicyCache(1000, 5*time.Minute),
		Agents:         agents.NewAgentRegistry(),
		RBAC:           auth.NewRBAC(),
		Webhooks:       webhooks.NewServiceForTesting(),
		Notifications:  notifications.NewManager(),
		Scheduler:      scheduler.NewScheduler(logger),
		Ticketing:      ticketing.NewService(),
		Identity:       identity.NewService(),
		AttackPath:     attackpath.NewGraph(),
		Providers:      providers.NewRegistry(),
		Health:         health.NewRegistry(),
		Lineage:        lineage.NewLineageMapper(),
		Remediation:    remediation.NewEngine(logger),
		RuntimeDetect:  runtime.NewDetectionEngine(),
		RuntimeRespond: runtime.NewResponseEngine(),
		SecurityGraph:  graph.New(),
		ScanWatermarks: scanner.NewWatermarkStore(nil),
		ThreatIntel:    threatintel.NewThreatIntelService(),
	}
}

// newTestServer creates a Server backed by the in-memory test app.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(newTestApp(t))
}

// do is a helper that sends a request to the test server and returns the response.
func do(t *testing.T, s *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// decodeJSON decodes the response body into a generic map.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode json: %v (body=%s)", err, w.Body.String())
	}
	return out
}

type scriptedAgentProvider struct {
	responses []*agents.Response
	index     int
}

func (p *scriptedAgentProvider) Complete(_ context.Context, _ []agents.Message, _ []agents.Tool) (*agents.Response, error) {
	if p.index >= len(p.responses) {
		return &agents.Response{Message: agents.Message{Role: "assistant", Content: "done"}}, nil
	}
	resp := p.responses[p.index]
	p.index++
	return resp, nil
}

func (p *scriptedAgentProvider) Stream(context.Context, []agents.Message, []agents.Tool) (<-chan agents.StreamEvent, error) {
	return nil, nil
}

type captureAuditLogger struct {
	entries []*snowflake.AuditEntry
}

func (l *captureAuditLogger) Log(_ context.Context, entry *snowflake.AuditEntry) error {
	l.entries = append(l.entries, entry)
	return nil
}

type staticProvider struct {
	name     string
	provider providers.ProviderType
}

func (p *staticProvider) Name() string { return p.name }

func (p *staticProvider) Type() providers.ProviderType { return p.provider }

func (p *staticProvider) Configure(context.Context, map[string]interface{}) error { return nil }

func (p *staticProvider) Sync(context.Context, providers.SyncOptions) (*providers.SyncResult, error) {
	return &providers.SyncResult{Provider: p.name}, nil
}

func (p *staticProvider) Test(context.Context) error { return nil }

func (p *staticProvider) Schema() []providers.TableSchema {
	return []providers.TableSchema{{
		Name:       "table",
		Columns:    []providers.ColumnSchema{{Name: "id", Type: "string", Required: true}},
		PrimaryKey: []string{"id"},
	}}
}

// --- Health / Readiness ---

func TestHealth(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "healthy" {
		t.Fatalf("expected healthy, got %v", body["status"])
	}
}

func TestReady(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/ready", nil)
	// Ready may return 503 when Snowflake is nil; that's expected in unit tests
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 200 or 503, got %d", w.Code)
	}
}

func TestSetupMiddleware_RateLimitBeforeAuth(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	a.Config.RateLimitEnabled = true
	a.Config.RateLimitRequests = 1
	a.Config.RateLimitWindow = time.Minute

	s := NewServer(a)

	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req1.RemoteAddr = "198.51.100.42:1234"
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("first request expected 401, got %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req2.RemoteAddr = "198.51.100.42:1234"
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", w2.Code)
	}
}

func TestRateLimitSpoofedXFF_UntrustedRemote(t *testing.T) {
	// An untrusted client sends spoofed X-Forwarded-For to appear as
	// different IPs per request. Without the ordering fix (RealIP before
	// rate limiting) each request would get a different bucket and never
	// be throttled. After the fix the limiter keys on RemoteAddr so the
	// same socket peer is correctly rate-limited.
	a := newTestApp(t)
	a.Config.RateLimitEnabled = true
	a.Config.RateLimitRequests = 1
	a.Config.RateLimitWindow = time.Minute
	// No trusted proxies configured -- forwarded headers must be ignored.

	s := NewServer(a)

	// First request: spoofed XFF, should consume the one allowed request.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req1.RemoteAddr = "203.0.113.50:9999"
	req1.Header.Set("X-Forwarded-For", "10.10.10.1")
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	// Expect 200 (policies list, not rate limited yet).
	if w1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request should not be rate limited, got %d", w1.Code)
	}

	// Second request: same RemoteAddr, different spoofed XFF.
	// Must be rejected because the limiter keys on RemoteAddr, not XFF.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req2.RemoteAddr = "203.0.113.50:9999"
	req2.Header.Set("X-Forwarded-For", "10.10.10.2")
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429 (rate limited), got %d", w2.Code)
	}
}

func TestRateLimitTrustedProxy_HonoursXFF(t *testing.T) {
	// When the direct peer IS a trusted proxy, the limiter should honour
	// X-Forwarded-For and rate-limit by the real client IP.
	a := newTestApp(t)
	a.Config.RateLimitEnabled = true
	a.Config.RateLimitRequests = 1
	a.Config.RateLimitWindow = time.Minute
	a.Config.RateLimitTrustedProxies = []string{"10.0.0.0/8"}

	s := NewServer(a)

	// Request 1 from client A through the trusted proxy.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req1.RemoteAddr = "10.0.0.1:8080" // trusted proxy
	req1.Header.Set("X-Forwarded-For", "198.51.100.1")
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	if w1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request should not be rate limited, got %d", w1.Code)
	}

	// Request 2 from client A (same XFF) through same trusted proxy => rate limited.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req2.RemoteAddr = "10.0.0.1:8080"
	req2.Header.Set("X-Forwarded-For", "198.51.100.1")
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same XFF client expected 429, got %d", w2.Code)
	}

	// Request 3 from client B (different XFF) through same trusted proxy => allowed.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req3.RemoteAddr = "10.0.0.1:8080"
	req3.Header.Set("X-Forwarded-For", "198.51.100.2")
	w3 := httptest.NewRecorder()
	s.ServeHTTP(w3, req3)
	if w3.Code == http.StatusTooManyRequests {
		t.Fatalf("request from different XFF client should not be rate limited, got %d", w3.Code)
	}
}

func TestServer_ConfiguredCORSMiddleware(t *testing.T) {
	a := newTestApp(t)
	a.Config.CORSAllowedOrigins = []string{"https://app.example.com"}
	s := NewServer(a)

	allowedReq := httptest.NewRequest(http.MethodOptions, "/health", nil)
	allowedReq.Header.Set("Origin", "https://app.example.com")
	allowedResp := httptest.NewRecorder()
	s.ServeHTTP(allowedResp, allowedReq)
	if allowedResp.Code != http.StatusNoContent {
		t.Fatalf("allowed origin expected 204, got %d", allowedResp.Code)
	}

	blockedReq := httptest.NewRequest(http.MethodOptions, "/health", nil)
	blockedReq.Header.Set("Origin", "https://blocked.example.com")
	blockedResp := httptest.NewRecorder()
	s.ServeHTTP(blockedResp, blockedReq)
	if blockedResp.Code != http.StatusForbidden {
		t.Fatalf("blocked origin expected 403, got %d", blockedResp.Code)
	}
}

func TestError_SanitizesInternalServerError(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()

	s.error(w, http.StatusInternalServerError, "sensitive backend details")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error != "internal server error" {
		t.Fatalf("expected sanitized error, got %q", body.Error)
	}
	if body.Code != "internal_error" {
		t.Fatalf("expected internal_error code, got %q", body.Code)
	}
}

// --- Policies CRUD ---

func TestListPolicies_Empty(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/policies/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 0 {
		t.Fatalf("expected 0, got %v", body["count"])
	}
}

func TestCreateAndGetPolicy(t *testing.T) {
	s := newTestServer(t)

	p := policy.Policy{
		ID:         "test-001",
		Name:       "No public buckets",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true"},
		Severity:   "high",
	}

	w := do(t, s, "POST", "/api/v1/policies/", p)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// GET by ID
	w = do(t, s, "GET", "/api/v1/policies/test-001", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["id"] != "test-001" {
		t.Fatalf("expected id test-001, got %v", body["id"])
	}

	// List should show 1
	w = do(t, s, "GET", "/api/v1/policies/", nil)
	body = decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1, got %v", body["count"])
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/policies/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Findings ---

func TestListFindings_Empty(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 0 {
		t.Fatalf("expected 0, got %v", body["count"])
	}
}

func TestFindingsStats(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGetFinding_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCreatePolicyThenScanFindings(t *testing.T) {
	s := newTestServer(t)

	// Create a policy
	p := policy.Policy{
		ID:         "pub-check",
		Name:       "Public check",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == true"},
		Severity:   "high",
	}
	w := do(t, s, "POST", "/api/v1/policies/", p)
	if w.Code != http.StatusCreated {
		t.Fatalf("create policy: %d %s", w.Code, w.Body.String())
	}

	// Upsert a finding directly so we can test retrieval
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:         "f-1",
		PolicyID:   "pub-check",
		PolicyName: "Public check",
		ResourceID: "arn:aws:s3:::my-bucket",
		Resource:   map[string]interface{}{"type": "aws::s3::bucket"},
		Severity:   "high",
	})

	// List should have 1
	w = do(t, s, "GET", "/api/v1/findings/", nil)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1 finding, got %v", body["count"])
	}

	// Get by ID
	w = do(t, s, "GET", "/api/v1/findings/f-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Resolve
	w = do(t, s, "POST", "/api/v1/findings/f-1/resolve", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Findings filter ---

func TestListFindings_SeverityFilter(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-high", PolicyID: "p1", Severity: "high",
	})
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-low", PolicyID: "p2", Severity: "low",
	})

	w := do(t, s, "GET", "/api/v1/findings/?severity=high", nil)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1 high finding, got %v", body["count"])
	}
}

func TestExportFindings_InvalidFormat(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/findings/export?format=xml", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Compliance exports ---

func TestComplianceExportAuditPackage_ReturnsZip(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:         "f-export-1",
		PolicyID:   "aws-iam-root-no-access-keys",
		PolicyName: "Root access key found",
		ResourceID: "aws-account-123",
		Severity:   "critical",
	})

	w := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/zip") {
		t.Fatalf("expected zip content-type, got %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment;") || !strings.Contains(got, "cerebro-audit-cis-aws-1.5-") {
		t.Fatalf("unexpected content-disposition: %q", got)
	}

	body := w.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("invalid zip payload: %v", err)
	}

	entries := map[string]*zip.File{}
	for _, file := range zr.File {
		entries[file.Name] = file
	}
	for _, required := range []string{"manifest.json", "summary.json", "controls.json"} {
		if _, ok := entries[required]; !ok {
			t.Fatalf("missing zip entry %q", required)
		}
	}

	summaryRC, err := entries["summary.json"].Open()
	if err != nil {
		t.Fatalf("open summary entry: %v", err)
	}
	defer summaryRC.Close()

	var summary struct {
		FailingControls int `json:"failing_controls"`
	}
	if err := json.NewDecoder(summaryRC).Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary.FailingControls == 0 {
		t.Fatalf("expected at least one failing control, got %+v", summary)
	}
}

func TestComplianceExportAuditPackage_FrameworkNotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/compliance/frameworks/does-not-exist/export", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCompliancePreAuditToExport_Smoke(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:         "f-smoke-1",
		PolicyID:   "aws-iam-root-no-access-keys",
		PolicyName: "Root access key found",
		ResourceID: "aws-account-999",
		Severity:   "critical",
	})

	preAudit := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/pre-audit", nil)
	if preAudit.Code != http.StatusOK {
		t.Fatalf("pre-audit expected 200, got %d: %s", preAudit.Code, preAudit.Body.String())
	}
	preAuditBody := decodeJSON(t, preAudit)
	if preAuditBody["framework_id"] != "cis-aws-1.5" {
		t.Fatalf("unexpected framework_id: %v", preAuditBody["framework_id"])
	}
	if preAuditBody["estimated_outcome"] == nil {
		t.Fatalf("expected estimated_outcome in pre-audit response")
	}

	export := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/export", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d: %s", export.Code, export.Body.String())
	}

	body := export.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("invalid zip payload: %v", err)
	}

	entries := map[string]bool{}
	for _, file := range zr.File {
		entries[file.Name] = true
	}
	for _, required := range []string{"manifest.json", "summary.json", "controls.json"} {
		if !entries[required] {
			t.Fatalf("missing export entry %q", required)
		}
	}
}

func TestComplianceReportAndExport_IgnoreResolvedFindings(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:         "f-resolved-1",
		PolicyID:   "aws-iam-root-no-access-keys",
		PolicyName: "Root access key found",
		ResourceID: "aws-account-111",
		Severity:   "critical",
	})
	if !s.app.Findings.Resolve("f-resolved-1") {
		t.Fatal("expected finding resolve to succeed")
	}

	preAudit := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/pre-audit", nil)
	if preAudit.Code != http.StatusOK {
		t.Fatalf("pre-audit expected 200, got %d: %s", preAudit.Code, preAudit.Body.String())
	}
	preAuditBody := decodeJSON(t, preAudit)
	if preAuditBody["estimated_outcome"] != "PASS" {
		t.Fatalf("expected PASS outcome, got %v", preAuditBody["estimated_outcome"])
	}
	summary, ok := preAuditBody["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary map, got %T", preAuditBody["summary"])
	}
	if failing, ok := summary["failing"].(float64); !ok || failing != 0 {
		t.Fatalf("expected failing=0, got %v", summary["failing"])
	}

	report := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/report", nil)
	if report.Code != http.StatusOK {
		t.Fatalf("report expected 200, got %d: %s", report.Code, report.Body.String())
	}
	reportBody := decodeJSON(t, report)
	if got, ok := reportBody["total_findings"].(float64); !ok || got != 0 {
		t.Fatalf("expected total_findings=0, got %v", reportBody["total_findings"])
	}

	export := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/export", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d: %s", export.Code, export.Body.String())
	}

	body := export.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("invalid zip payload: %v", err)
	}

	entries := map[string]*zip.File{}
	for _, file := range zr.File {
		entries[file.Name] = file
	}
	summaryFile, ok := entries["summary.json"]
	if !ok {
		t.Fatalf("missing summary.json entry")
	}
	summaryRC, err := summaryFile.Open()
	if err != nil {
		t.Fatalf("open summary entry: %v", err)
	}
	defer summaryRC.Close()

	var exportSummary struct {
		FailingControls int `json:"failing_controls"`
	}
	if err := json.NewDecoder(summaryRC).Decode(&exportSummary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if exportSummary.FailingControls != 0 {
		t.Fatalf("expected no failing controls, got %+v", exportSummary)
	}
}

func TestSyncScanFindingsPreAuditExport_Smoke(t *testing.T) {
	s := newTestServer(t)
	s.app.Providers.Register(&staticProvider{name: "github", provider: providers.ProviderTypeSaaS})

	syncResp := do(t, s, "POST", "/api/v1/providers/github/sync", map[string]interface{}{})
	if syncResp.Code != http.StatusOK {
		t.Fatalf("provider sync expected 200, got %d: %s", syncResp.Code, syncResp.Body.String())
	}

	s.app.Policy.AddPolicy(&policy.Policy{
		ID:          "aws-iam-root-no-access-keys",
		Name:        "Root access key found",
		Description: "root access key should not exist",
		Severity:    "critical",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"_cq_id exists"},
	})

	result := s.app.Scanner.ScanAssets(context.Background(), []map[string]interface{}{{
		"_cq_id":    "asset-1",
		"_cq_table": "aws_s3_buckets",
		"name":      "bucket-1",
	}})
	if result.Violations == 0 || len(result.Findings) == 0 {
		t.Fatalf("expected scan to produce findings, got violations=%d findings=%d", result.Violations, len(result.Findings))
	}

	for _, finding := range result.Findings {
		s.app.Findings.Upsert(context.Background(), finding)
	}

	listResp := do(t, s, "GET", "/api/v1/findings/", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("findings list expected 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeJSON(t, listResp)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected findings count >= 1, got %v", listBody["count"])
	}

	preAudit := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/pre-audit", nil)
	if preAudit.Code != http.StatusOK {
		t.Fatalf("pre-audit expected 200, got %d: %s", preAudit.Code, preAudit.Body.String())
	}

	export := do(t, s, "GET", "/api/v1/compliance/frameworks/cis-aws-1.5/export", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d: %s", export.Code, export.Body.String())
	}

	body := export.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("invalid zip payload: %v", err)
	}

	entries := map[string]bool{}
	for _, file := range zr.File {
		entries[file.Name] = true
	}
	for _, required := range []string{"manifest.json", "summary.json", "controls.json"} {
		if !entries[required] {
			t.Fatalf("missing export entry %q", required)
		}
	}
}

func TestGenerateAuditRecommendations_ZeroTotal(t *testing.T) {
	s := newTestServer(t)
	recs := s.generateAuditRecommendations(1, 0, 0)
	if len(recs) == 0 {
		t.Fatal("expected recommendations")
	}
}

// --- Attack path ---

func TestGetAttackPath_ReturnsPath(t *testing.T) {
	s := newTestServer(t)

	s.app.AttackPath.AddNode(&attackpath.Node{ID: "external", Type: attackpath.NodeTypeExternal, Name: "Internet", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "role", Type: attackpath.NodeTypeRole, Name: "Compromised Role", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "db", Type: attackpath.NodeTypeDatabase, Name: "Prod DB", Risk: attackpath.RiskCritical})

	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-1", Source: "external", Target: "role", Type: attackpath.EdgeTypeExposedTo, Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-2", Source: "role", Target: "db", Type: attackpath.EdgeTypeHasAccess, Risk: attackpath.RiskCritical})

	w := do(t, s, "GET", "/api/v1/attack-paths/external-db", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["id"] != "external-db" {
		t.Fatalf("expected path id external-db, got %v", body["id"])
	}
	steps, ok := body["steps"].([]interface{})
	if !ok || len(steps) == 0 {
		t.Fatalf("expected non-empty steps, got %v", body["steps"])
	}
}

func TestGetAttackPath_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/attack-paths/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetAttackPath_RespectsTargetsFilter(t *testing.T) {
	s := newTestServer(t)

	s.app.AttackPath.AddNode(&attackpath.Node{ID: "external", Type: attackpath.NodeTypeExternal, Name: "Internet", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "role", Type: attackpath.NodeTypeRole, Name: "Compromised Role", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "db", Type: attackpath.NodeTypeDatabase, Name: "Prod DB", Risk: attackpath.RiskCritical})

	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-1", Source: "external", Target: "role", Type: attackpath.EdgeTypeExposedTo, Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-2", Source: "role", Target: "db", Type: attackpath.EdgeTypeHasAccess, Risk: attackpath.RiskCritical})

	w := do(t, s, "GET", "/api/v1/attack-paths/external-db?targets=role", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when target is excluded, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, "GET", "/api/v1/attack-paths/external-db?targets=db", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when target is included, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetAttackPath_RespectsMaxDepth(t *testing.T) {
	s := newTestServer(t)

	s.app.AttackPath.AddNode(&attackpath.Node{ID: "external", Type: attackpath.NodeTypeExternal, Name: "Internet", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "role", Type: attackpath.NodeTypeRole, Name: "Compromised Role", Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddNode(&attackpath.Node{ID: "db", Type: attackpath.NodeTypeDatabase, Name: "Prod DB", Risk: attackpath.RiskCritical})

	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-1", Source: "external", Target: "role", Type: attackpath.EdgeTypeExposedTo, Risk: attackpath.RiskHigh})
	s.app.AttackPath.AddEdge(&attackpath.Edge{ID: "edge-2", Source: "role", Target: "db", Type: attackpath.EdgeTypeHasAccess, Risk: attackpath.RiskCritical})

	w := do(t, s, "GET", "/api/v1/attack-paths/external-db?max_depth=1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 with insufficient max_depth, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, "GET", "/api/v1/attack-paths/external-db?max_depth=2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with sufficient max_depth, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Webhooks CRUD ---

func TestWebhookCRUD(t *testing.T) {
	s := newTestServer(t)

	// Create
	w := do(t, s, "POST", "/api/v1/webhooks/", map[string]interface{}{
		"url":    "https://example.com/hook",
		"events": []string{"finding.created"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeJSON(t, w)
	id := created["id"].(string)

	// List
	w = do(t, s, "GET", "/api/v1/webhooks/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Get
	w = do(t, s, "GET", "/api/v1/webhooks/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Delete
	w = do(t, s, "DELETE", "/api/v1/webhooks/"+id, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Tickets ---

func TestTicketList(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/tickets/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTicketCreate_NoProvider(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "POST", "/api/v1/tickets/", map[string]interface{}{
		"title":    "Fix bucket",
		"severity": "high",
	})
	// Expect 503 because no ticketing provider is configured
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without provider, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Remediation ---

func TestRemediationRuleCRUD(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "GET", "/api/v1/remediation/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Scheduler ---

func TestSchedulerStatus(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scheduler/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSchedulerListJobs(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scheduler/jobs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Runtime Detection ---

func TestListDetectionRules(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/detections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListRuntimeFindings(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListResponsePolicies(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/runtime/responses", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Providers ---

func TestListProviders(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/providers/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListProviders_IncludesOracleIDCSByDefault(t *testing.T) {
	a := newTestApp(t)
	a.Providers.Register(&staticProvider{name: "okta", provider: providers.ProviderTypeSaaS})
	a.Providers.Register(&staticProvider{name: "oracle_idcs", provider: providers.ProviderTypeIdentity})

	s := NewServer(a)
	w := do(t, s, "GET", "/api/v1/providers/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected 2 visible providers, got %v", body["count"])
	}
	items := body["providers"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("expected 2 provider entries, got %d", len(items))
	}

	foundOKTA := false
	foundOracleIDCS := false
	for _, item := range items {
		provider := item.(map[string]interface{})
		switch provider["name"] {
		case "okta":
			foundOKTA = true
		case "oracle_idcs":
			foundOracleIDCS = true
		}
	}

	if !foundOKTA {
		t.Fatal("expected okta in provider list")
	}
	if !foundOracleIDCS {
		t.Fatal("expected oracle_idcs in provider list")
	}
}

func TestListProviders_IncludeIncomplete(t *testing.T) {
	a := newTestApp(t)
	a.Providers.Register(&staticProvider{name: "okta", provider: providers.ProviderTypeSaaS})
	a.Providers.Register(&staticProvider{name: "oracle_idcs", provider: providers.ProviderTypeIdentity})

	s := NewServer(a)
	w := do(t, s, "GET", "/api/v1/providers/?include_incomplete=true", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected 2 providers, got %v", body["count"])
	}

	items := body["providers"].([]interface{})
	foundOracleIDCS := false
	for _, item := range items {
		provider := item.(map[string]interface{})
		if provider["name"] == "oracle_idcs" {
			foundOracleIDCS = true
			if provider["maturity"] != string(providers.ProviderMaturityProductionReady) {
				t.Fatalf("expected oracle_idcs maturity %q, got %v", providers.ProviderMaturityProductionReady, provider["maturity"])
			}
		}
	}
	if !foundOracleIDCS {
		t.Fatal("expected oracle_idcs in provider list when include_incomplete=true")
	}
}

func TestGetProvider_OracleIDCSVisibleByDefault(t *testing.T) {
	a := newTestApp(t)
	a.Providers.Register(&staticProvider{name: "oracle_idcs", provider: providers.ProviderTypeIdentity})
	s := NewServer(a)

	w := do(t, s, "GET", "/api/v1/providers/oracle_idcs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["maturity"] != string(providers.ProviderMaturityProductionReady) {
		t.Fatalf("expected maturity %q, got %v", providers.ProviderMaturityProductionReady, body["maturity"])
	}

	w = do(t, s, "GET", "/api/v1/providers/oracle_idcs?include_incomplete=true", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with include_incomplete, got %d", w.Code)
	}
	body = decodeJSON(t, w)
	if body["maturity"] != string(providers.ProviderMaturityProductionReady) {
		t.Fatalf("expected maturity %q, got %v", providers.ProviderMaturityProductionReady, body["maturity"])
	}
}

func TestConfigureProvider_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "POST", "/api/v1/providers/missing/configure", map[string]interface{}{"token": "x"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- RBAC ---

func TestListRoles(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/rbac/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListPermissions(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/rbac/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var perms []string
	if err := json.Unmarshal(w.Body.Bytes(), &perms); err != nil {
		t.Fatalf("decode permissions: %v", err)
	}

	permSet := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		permSet[p] = struct{}{}
	}

	expected := []string{"agents:read", "agents:write", "tickets:read", "runtime:read", "graph:write"}
	for _, perm := range expected {
		if _, ok := permSet[perm]; !ok {
			t.Fatalf("expected permission %s in response", perm)
		}
	}
}

// --- Threat Intel ---

func TestListThreatFeeds(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/threatintel/feeds", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestThreatIntelStats(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/threatintel/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Identity ---

func TestListReviews(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/identity/reviews", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Reports ---

func TestExecutiveSummary(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/reports/executive-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRiskSummary(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/reports/risk-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Notifications ---

func TestListNotifiers(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/notifications/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Scan watermarks ---

func TestScanWatermarks(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/scan/watermarks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Auth middleware integration ---

func TestAuthMiddleware_BlocksUnauthenticated(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	s := NewServer(a)

	w := do(t, s, "GET", "/api/v1/policies/", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_AllowsAuthenticated(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	// Disable RBAC so we only test auth layer
	a.RBAC = nil
	s := NewServer(a)

	req := httptest.NewRequest("GET", "/api/v1/policies/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_HealthBypassesAuth(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	s := NewServer(a)

	w := do(t, s, "GET", "/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /health even without auth, got %d", w.Code)
	}
}

func TestAuthMiddleware_RBACProtectsAgentRoutes(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"test-key": "user-1"}
	s := NewServer(a)

	req := httptest.NewRequest("GET", "/api/v1/agents/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for user without RBAC role, got %d", w.Code)
	}
}

func TestAuthMiddleware_RBACAgentReadWriteByRole(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"viewer-key": "viewer-1", "analyst-key": "analyst-1"}

	if err := a.RBAC.CreateUser(&auth.User{ID: "viewer-1", Email: "viewer@example.com", RoleIDs: []string{"viewer"}}); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{ID: "analyst-1", Email: "analyst@example.com", RoleIDs: []string{"analyst"}}); err != nil {
		t.Fatalf("create analyst: %v", err)
	}

	s := NewServer(a)

	// Viewer can read agents.
	readReq := httptest.NewRequest("GET", "/api/v1/agents/", nil)
	readReq.Header.Set("Authorization", "Bearer viewer-key")
	readW := httptest.NewRecorder()
	s.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected viewer read to succeed, got %d", readW.Code)
	}

	// Viewer cannot perform write operation on agent session endpoint.
	viewerWriteReq := httptest.NewRequest("POST", "/api/v1/agents/sessions", strings.NewReader(`{"agent_id":"agent-1"}`))
	viewerWriteReq.Header.Set("Authorization", "Bearer viewer-key")
	viewerWriteReq.Header.Set("Content-Type", "application/json")
	viewerWriteW := httptest.NewRecorder()
	s.ServeHTTP(viewerWriteW, viewerWriteReq)
	if viewerWriteW.Code != http.StatusForbidden {
		t.Fatalf("expected viewer write to be forbidden, got %d", viewerWriteW.Code)
	}

	// Analyst has agents:write so request reaches handler (agent missing => 404).
	analystWriteReq := httptest.NewRequest("POST", "/api/v1/agents/sessions", strings.NewReader(`{"agent_id":"agent-1"}`))
	analystWriteReq.Header.Set("Authorization", "Bearer analyst-key")
	analystWriteReq.Header.Set("Content-Type", "application/json")
	analystWriteW := httptest.NewRecorder()
	s.ServeHTTP(analystWriteW, analystWriteReq)
	if analystWriteW.Code == http.StatusForbidden {
		t.Fatalf("expected analyst write to pass RBAC, got %d", analystWriteW.Code)
	}
}

func TestAuthMiddleware_RBACRouteMatrix(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"viewer-key": "viewer-1", "analyst-key": "analyst-1", "admin-key": "admin-1"}

	if err := a.RBAC.CreateUser(&auth.User{ID: "viewer-1", Email: "viewer@example.com", RoleIDs: []string{"viewer"}}); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{ID: "analyst-1", Email: "analyst@example.com", RoleIDs: []string{"analyst"}}); err != nil {
		t.Fatalf("create analyst: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{ID: "admin-1", Email: "admin@example.com", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	s := NewServer(a)

	type routeCase struct {
		name             string
		method           string
		path             string
		body             interface{}
		viewerForbidden  bool
		analystForbidden bool
		adminForbidden   bool
	}

	cases := []routeCase{
		{name: "agents read", method: http.MethodGet, path: "/api/v1/agents/", viewerForbidden: false, analystForbidden: false, adminForbidden: false},
		{name: "agents write", method: http.MethodPost, path: "/api/v1/agents/sessions", body: map[string]string{"agent_id": "missing-agent"}, viewerForbidden: true, analystForbidden: false, adminForbidden: false},
		{name: "tickets read", method: http.MethodGet, path: "/api/v1/tickets/", viewerForbidden: false, analystForbidden: false, adminForbidden: false},
		{name: "tickets write", method: http.MethodPost, path: "/api/v1/tickets/", body: map[string]string{"title": "x", "description": "y"}, viewerForbidden: true, analystForbidden: false, adminForbidden: false},
		{name: "runtime read", method: http.MethodGet, path: "/api/v1/runtime/detections", viewerForbidden: false, analystForbidden: false, adminForbidden: false},
		{name: "runtime write", method: http.MethodPost, path: "/api/v1/runtime/events", body: map[string]interface{}{}, viewerForbidden: true, analystForbidden: false, adminForbidden: false},
		{name: "graph read", method: http.MethodGet, path: "/api/v1/graph/stats", viewerForbidden: false, analystForbidden: false, adminForbidden: false},
		{name: "graph write", method: http.MethodPost, path: "/api/v1/graph/rebuild", viewerForbidden: true, analystForbidden: false, adminForbidden: false},
		{name: "audit admin only", method: http.MethodGet, path: "/api/v1/audit", viewerForbidden: true, analystForbidden: true, adminForbidden: false},
		{name: "providers admin only", method: http.MethodGet, path: "/api/v1/providers/", viewerForbidden: true, analystForbidden: true, adminForbidden: false},
		{name: "scheduler admin only", method: http.MethodPost, path: "/api/v1/scheduler/jobs/test/run", viewerForbidden: true, analystForbidden: true, adminForbidden: false},
		{name: "fallback read", method: http.MethodGet, path: "/api/v1/nonexistent", viewerForbidden: false, analystForbidden: false, adminForbidden: false},
		{name: "fallback write", method: http.MethodPost, path: "/api/v1/nonexistent", body: map[string]interface{}{}, viewerForbidden: true, analystForbidden: true, adminForbidden: false},
	}

	doAuth := func(method, path, apiKey string, body interface{}) *httptest.ResponseRecorder {
		var reader io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			reader = bytes.NewReader(b)
		}

		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	assertForbidden := func(tc routeCase, actor string, got int, wantForbidden bool) {
		if wantForbidden && got != http.StatusForbidden {
			t.Fatalf("%s (%s): expected 403, got %d", tc.name, actor, got)
		}
		if !wantForbidden && got == http.StatusForbidden {
			t.Fatalf("%s (%s): expected non-403, got %d", tc.name, actor, got)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viewer := doAuth(tc.method, tc.path, "viewer-key", tc.body)
			assertForbidden(tc, "viewer", viewer.Code, tc.viewerForbidden)

			analyst := doAuth(tc.method, tc.path, "analyst-key", tc.body)
			assertForbidden(tc, "analyst", analyst.Code, tc.analystForbidden)

			admin := doAuth(tc.method, tc.path, "admin-key", tc.body)
			assertForbidden(tc, "admin", admin.Code, tc.adminForbidden)
		})
	}
}

func TestAgentSessionOwnershipEnforcedWhenAuthenticated(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{"alice-key": "alice-1", "bob-key": "bob-1"}

	if err := a.RBAC.CreateUser(&auth.User{ID: "alice-1", Email: "alice@example.com", RoleIDs: []string{"analyst"}}); err != nil {
		t.Fatalf("create alice user: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{ID: "bob-1", Email: "bob@example.com", RoleIDs: []string{"analyst"}}); err != nil {
		t.Fatalf("create bob user: %v", err)
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:   "agent-ownership",
		Name: "Ownership Agent",
	})

	s := NewServer(a)

	doAuth := func(method, path, apiKey string, body interface{}) *httptest.ResponseRecorder {
		var reader io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			reader = bytes.NewReader(b)
		}

		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	// Cannot spoof another user's identity when creating sessions.
	spoofedCreate := doAuth(http.MethodPost, "/api/v1/agents/sessions", "alice-key", map[string]string{
		"agent_id": "agent-ownership",
		"user_id":  "bob-1",
	})
	if spoofedCreate.Code != http.StatusForbidden {
		t.Fatalf("expected spoofed create to be forbidden, got %d", spoofedCreate.Code)
	}

	create := doAuth(http.MethodPost, "/api/v1/agents/sessions", "alice-key", map[string]string{
		"agent_id": "agent-ownership",
		"user_id":  "alice-1",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected session create to succeed, got %d: %s", create.Code, create.Body.String())
	}

	var session agents.Session
	if err := json.Unmarshal(create.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if session.UserID != "alice-1" {
		t.Fatalf("expected session user alice-1, got %s", session.UserID)
	}

	bobRead := doAuth(http.MethodGet, "/api/v1/agents/sessions/"+session.ID, "bob-key", nil)
	if bobRead.Code != http.StatusForbidden {
		t.Fatalf("expected bob read to be forbidden, got %d", bobRead.Code)
	}

	bobMessages := doAuth(http.MethodGet, "/api/v1/agents/sessions/"+session.ID+"/messages", "bob-key", nil)
	if bobMessages.Code != http.StatusForbidden {
		t.Fatalf("expected bob message read to be forbidden, got %d", bobMessages.Code)
	}

	bobSend := doAuth(http.MethodPost, "/api/v1/agents/sessions/"+session.ID+"/messages", "bob-key", map[string]string{
		"content": "hi",
	})
	if bobSend.Code != http.StatusForbidden {
		t.Fatalf("expected bob send to be forbidden, got %d", bobSend.Code)
	}
}

func TestListAuditLogsRejectsNonPositiveLimit(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/audit?limit=-1", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid limit, got %d", w.Code)
	}
}

// --- 404 for unknown routes ---

func TestUnknownRoute(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/nonexistent", nil)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 404/405, got %d", w.Code)
	}
}

// --- MaxBodySize ---

func TestMaxBodySize_RejectsLargeBody(t *testing.T) {
	s := newTestServer(t)
	largeBody := strings.Repeat("x", 11*1024*1024) // 11MB
	req := httptest.NewRequest("POST", "/api/v1/policies/", bytes.NewReader([]byte(largeBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code == http.StatusOK || w.Code == http.StatusCreated {
		t.Fatalf("expected rejection of 11MB body, got %d", w.Code)
	}
}

func TestAgentSendMessageExecutesToolCalls(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "safe_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
			{Message: agents.Message{Role: "assistant", Content: "final response"}},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-1",
		Name:     "Test Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name: "safe_tool",
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-1", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "investigate"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Content != "final response" {
		t.Fatalf("expected final response, got %q", msg.Content)
	}
	if !called {
		t.Fatal("expected tool handler to be called")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if len(updated.Messages) < 4 {
		t.Fatalf("expected at least 4 messages in session, got %d", len(updated.Messages))
	}
}

func TestAgentSendMessage_NoProviderConfiguredReturnsGuidance(t *testing.T) {
	a := newTestApp(t)
	a.Agents.RegisterAgent(&agents.Agent{
		ID:   "agent-no-provider",
		Name: "No Provider Agent",
	})

	session, err := a.Agents.CreateSession("agent-no-provider", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "help me triage"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(msg.Content, "no LLM provider is configured") {
		t.Fatalf("expected guidance about missing provider, got %q", msg.Content)
	}
}

func TestNoPlaceholderMarkersInAPIServer(t *testing.T) {
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("resolve test file path: runtime caller unavailable")
	}

	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	content, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}

	lower := strings.ToLower(string(content))
	for _, marker := range []string{"placeholder response", "not implemented"} {
		if strings.Contains(lower, marker) {
			t.Fatalf("server.go contains placeholder marker %q", marker)
		}
	}
}

func TestAgentSendMessageBlocksRequiresApprovalTool(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-2",
		Name:     "Approval Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-2", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Metadata["status"] != "pending_approval" {
		t.Fatalf("expected pending_approval status, got %#v", msg.Metadata["status"])
	}
	if called {
		t.Fatal("expected tool handler not to be called before approval")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if updated.Status != "pending_approval" {
		t.Fatalf("expected session status pending_approval, got %s", updated.Status)
	}
}

func TestApproveSessionToolCallExecutesPendingTool(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
			{Message: agents.Message{Role: "assistant", Content: "tool approved and completed"}},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-3",
		Name:     "Approval Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-3", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	auditLogs := &captureAuditLogger{}
	s.auditLogger = auditLogs

	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/approve", map[string]bool{"approve": true})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on approval, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Content != "tool approved and completed" {
		t.Fatalf("expected final assistant message after approval, got %q", msg.Content)
	}
	if !called {
		t.Fatal("expected pending tool to be executed after approval")
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if updated.Status != "active" {
		t.Fatalf("expected session status active after approval, got %s", updated.Status)
	}
	if updated.Context.Metadata != nil {
		if _, exists := updated.Context.Metadata["pending_tool_call"]; exists {
			t.Fatal("expected pending tool call metadata to be cleared")
		}
	}

	if len(auditLogs.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditLogs.entries))
	}
	entry := auditLogs.entries[0]
	if entry.Action != "agent.tool_approval" {
		t.Fatalf("expected action agent.tool_approval, got %s", entry.Action)
	}
	if entry.ActorID != "user-1" {
		t.Fatalf("expected actor user-1, got %s", entry.ActorID)
	}
	if entry.Details["decision"] != "approved" {
		t.Fatalf("expected approved decision in details, got %#v", entry.Details["decision"])
	}
	if entry.Details["tool_call_id"] != "tool-1" {
		t.Fatalf("expected tool_call_id tool-1, got %#v", entry.Details["tool_call_id"])
	}
}

func TestApproveSessionToolCallDeniedRecordsAudit(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-deny",
		Name:     "Approval Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-deny", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	auditLogs := &captureAuditLogger{}
	s.auditLogger = auditLogs

	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/approve", map[string]bool{"approve": false})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when denying approval, got %d: %s", w.Code, w.Body.String())
	}

	if called {
		t.Fatal("expected tool not to execute when approval is denied")
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Metadata["status"] != "approval_denied" {
		t.Fatalf("expected approval_denied status, got %#v", msg.Metadata["status"])
	}

	if len(auditLogs.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditLogs.entries))
	}
	if auditLogs.entries[0].Details["decision"] != "denied" {
		t.Fatalf("expected denied decision, got %#v", auditLogs.entries[0].Details["decision"])
	}
}

func TestApproveSessionToolCallExpiredPendingRequest(t *testing.T) {
	a := newTestApp(t)
	called := false

	provider := &scriptedAgentProvider{
		responses: []*agents.Response{
			{
				Message: agents.Message{
					Role: "assistant",
					ToolCalls: []agents.ToolCall{{
						ID:        "tool-1",
						Name:      "dangerous_tool",
						Arguments: json.RawMessage(`{"target":"asset-1"}`),
					}},
				},
			},
		},
	}

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-expiry",
		Name:     "Expiry Agent",
		Provider: provider,
		Tools: []agents.Tool{{
			Name:             "dangerous_tool",
			RequiresApproval: true,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-expiry", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	s := NewServer(a)
	auditLogs := &captureAuditLogger{}
	s.auditLogger = auditLogs

	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/messages", map[string]string{"content": "run dangerous tool"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, ok := a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	pending, ok := updated.Context.Metadata["pending_tool_call"].(map[string]interface{})
	if !ok {
		t.Fatal("expected pending_tool_call metadata")
	}
	pending["created_at"] = time.Now().Add(-2 * pendingToolApprovalTTL).UTC().Format(time.RFC3339Nano)

	w = do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/approve", map[string]bool{"approve": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on expired approval, got %d: %s", w.Code, w.Body.String())
	}

	var msg agents.Message
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Metadata["status"] != "approval_expired" {
		t.Fatalf("expected approval_expired status, got %#v", msg.Metadata["status"])
	}
	if called {
		t.Fatal("expected tool not to run when approval is expired")
	}

	updated, ok = a.Agents.GetSession(session.ID)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if updated.Status != "active" {
		t.Fatalf("expected active status after expiry handling, got %s", updated.Status)
	}
	if updated.Context.Metadata != nil {
		if _, exists := updated.Context.Metadata["pending_tool_call"]; exists {
			t.Fatal("expected pending tool metadata to be cleared after expiry")
		}
	}

	if len(auditLogs.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditLogs.entries))
	}
	if auditLogs.entries[0].Details["decision"] != "expired" {
		t.Fatalf("expected expired decision, got %#v", auditLogs.entries[0].Details["decision"])
	}
}

func TestApproveSessionToolCallRejectsNonApprovalTool(t *testing.T) {
	a := newTestApp(t)
	called := false

	a.Agents.RegisterAgent(&agents.Agent{
		ID:       "agent-non-approval",
		Name:     "Non Approval Agent",
		Provider: &scriptedAgentProvider{},
		Tools: []agents.Tool{{
			Name:             "safe_tool",
			RequiresApproval: false,
			Handler: func(context.Context, json.RawMessage) (string, error) {
				called = true
				return `{"ok":true}`, nil
			},
		}},
	})

	session, err := a.Agents.CreateSession("agent-non-approval", "user-1", agents.SessionContext{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	session.Status = "pending_approval"
	session.Context.Metadata = map[string]interface{}{
		"pending_tool_call": map[string]interface{}{
			"id":         "tool-1",
			"name":       "safe_tool",
			"arguments":  map[string]interface{}{},
			"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
	if err := a.Agents.UpdateSession(session); err != nil {
		t.Fatalf("update session: %v", err)
	}

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/agents/sessions/"+session.ID+"/approve", map[string]bool{"approve": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-approval tool, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("expected handler not to execute for non-approval tool in approval endpoint")
	}
}

// suppress unused import warnings
var _ = os.DevNull
