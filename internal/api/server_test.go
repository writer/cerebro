package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"

	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/apptest"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/snowflake"
)

// newTestApp creates a minimal in-memory App suitable for API integration tests.
func newTestApp(t *testing.T) *app.App {
	t.Helper()
	return apptest.NewApp(t)
}

// newTestServer creates a Server backed by the in-memory test app.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := NewServer(newTestApp(t))
	t.Cleanup(func() {
		s.Close()
	})
	return s
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

func decodePagination(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, ok := body["pagination"]
	if !ok {
		t.Fatalf("expected pagination object in response: %v", body)
	}
	pagination, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("expected pagination map, got %T", raw)
	}
	return pagination
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

type captureSyncProvider struct {
	name     string
	provider providers.ProviderType
	calls    int
	lastOpts providers.SyncOptions
}

func (p *captureSyncProvider) Name() string { return p.name }

func (p *captureSyncProvider) Type() providers.ProviderType { return p.provider }

func (p *captureSyncProvider) Configure(context.Context, map[string]interface{}) error { return nil }

func (p *captureSyncProvider) Sync(_ context.Context, opts providers.SyncOptions) (*providers.SyncResult, error) {
	p.calls++
	p.lastOpts = opts
	return &providers.SyncResult{Provider: p.name}, nil
}

func (p *captureSyncProvider) Test(context.Context) error { return nil }

func (p *captureSyncProvider) Schema() []providers.TableSchema {
	return []providers.TableSchema{{
		Name:       "table",
		Columns:    []providers.ColumnSchema{{Name: "id", Type: "string", Required: true}},
		PrimaryKey: []string{"id"},
	}}
}

type stubNotifier struct {
	name string
}

func (n stubNotifier) Send(context.Context, notifications.Event) error { return nil }
func (n stubNotifier) Name() string                                    { return n.name }
func (n stubNotifier) Test(context.Context) error                      { return nil }

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

func TestHealth_DegradedReturns503(t *testing.T) {
	prev := runtimeNumGoroutine
	runtimeNumGoroutine = func() int { return 15000 }
	defer func() { runtimeNumGoroutine = prev }()

	s := newTestServer(t)
	w := do(t, s, "GET", "/health", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "degraded" {
		t.Fatalf("expected degraded status, got %v", body["status"])
	}
}

func TestReady(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/ready", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "healthy" {
		t.Fatalf("expected healthy status, got %v", body["status"])
	}
}

func TestReady_UnhealthyReturns503(t *testing.T) {
	a := newTestApp(t)
	a.Health.Register("dependency", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "dependency",
			Status:  health.StatusUnhealthy,
			Message: "dependency unavailable",
		}
	})

	s := NewServer(a)
	w := do(t, s, "GET", "/ready", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["status"] != "unhealthy" {
		t.Fatalf("expected unhealthy status, got %v", body["status"])
	}
	if body["ready"] != false {
		t.Fatalf("expected ready=false, got %v", body["ready"])
	}
}

func TestStatus(t *testing.T) {
	s := newTestServer(t)
	base := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Provider: "github",
		Properties: map[string]any{
			"observed_at": base.Add(-30 * time.Minute).Format(time.RFC3339),
		},
	})
	w := do(t, s, "GET", "/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if _, ok := body["graph_build"]; !ok {
		t.Fatalf("expected graph_build in status response, got %v", body)
	}
	if _, ok := body["retention"]; !ok {
		t.Fatalf("expected retention in status response, got %v", body)
	}
	if freshness, ok := body["freshness"].(map[string]any); !ok || freshness["healthy"] == nil {
		t.Fatalf("expected freshness in status response, got %v", body["freshness"])
	}

	freshness := do(t, s, "GET", "/api/v1/status/freshness", nil)
	if freshness.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/v1/status/freshness, got %d: %s", freshness.Code, freshness.Body.String())
	}
	freshnessBody := decodeJSON(t, freshness)
	breakdown := freshnessBody["breakdown"].(map[string]any)
	providers, ok := breakdown["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("expected one provider freshness scope, got %#v", breakdown["providers"])
	}
}

func TestGraphBuildWarningHeadersSkipHealthAndStatus(t *testing.T) {
	for _, path := range []string{"/health", "/ready", "/status", "/metrics", "/api/v1/status/freshness"} {
		if !skipGraphBuildWarningHeaders(path) {
			t.Fatalf("expected graph build warning headers to be skipped for %s", path)
		}
	}
}

func TestGraphBuildWarningHeadersApplyToNonHealthRoutes(t *testing.T) {
	for _, path := range []string{"/api/v1/policies/", "/api/v1/admin/providers", "/docs"} {
		if skipGraphBuildWarningHeaders(path) {
			t.Fatalf("expected graph build warning headers to apply to %s", path)
		}
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

func TestListPolicies_Pagination(t *testing.T) {
	s := newTestServer(t)
	s.app.Policy.AddPolicy(&policy.Policy{ID: "policy-1", Name: "Policy 1", Effect: "forbid", Resource: "aws::s3::bucket", Conditions: []string{"public == true"}, Severity: "high"})
	s.app.Policy.AddPolicy(&policy.Policy{ID: "policy-2", Name: "Policy 2", Effect: "forbid", Resource: "aws::s3::bucket", Conditions: []string{"public == true"}, Severity: "high"})
	s.app.Policy.AddPolicy(&policy.Policy{ID: "policy-3", Name: "Policy 3", Effect: "forbid", Resource: "aws::s3::bucket", Conditions: []string{"public == true"}, Severity: "high"})

	w := do(t, s, "GET", "/api/v1/policies/?limit=2&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected paged count 2, got %v", body["count"])
	}
	if body["total_count"].(float64) != 3 {
		t.Fatalf("expected total_count 3, got %v", body["total_count"])
	}

	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 2 {
		t.Fatalf("expected pagination.limit 2, got %v", pagination["limit"])
	}
	if pagination["offset"].(float64) != 1 {
		t.Fatalf("expected pagination.offset 1, got %v", pagination["offset"])
	}
	if pagination["has_more"].(bool) {
		t.Fatal("expected has_more false for final page")
	}
}

func TestCreateAndGetPolicy(t *testing.T) {
	s := newTestServer(t)

	p := policy.Policy{
		ID:          "test-001",
		Name:        "No public buckets",
		Description: "test policy",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
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

func TestPolicyUpdateAndDelete(t *testing.T) {
	s := newTestServer(t)
	create := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:          "policy-update",
		Name:        "Original",
		Description: "original policy",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", create.Code, create.Body.String())
	}

	update := do(t, s, "PUT", "/api/v1/policies/policy-update", policy.Policy{
		Name:        "Updated",
		Description: "updated policy",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == false"},
		Severity:    "critical",
	})
	if update.Code != http.StatusOK {
		t.Fatalf("expected 200 on update, got %d: %s", update.Code, update.Body.String())
	}

	get := do(t, s, "GET", "/api/v1/policies/policy-update", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d", get.Code)
	}
	body := decodeJSON(t, get)
	if body["name"] != "Updated" {
		t.Fatalf("expected updated name, got %v", body["name"])
	}

	del := do(t, s, "DELETE", "/api/v1/policies/policy-update", nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d: %s", del.Code, del.Body.String())
	}

	missing := do(t, s, "GET", "/api/v1/policies/policy-update", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", missing.Code)
	}
}

func TestCreatePolicy_RejectsInvalidCELCondition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:              "invalid-cel",
		Name:            "Invalid CEL",
		Description:     "test",
		Effect:          "forbid",
		Resource:        "aws::s3::bucket",
		ConditionFormat: policy.ConditionFormatCEL,
		Conditions:      []string{"resource.public =="},
		Severity:        "high",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid CEL condition") {
		t.Fatalf("expected CEL validation error, got %s", w.Body.String())
	}
}

func TestCreatePolicy_InfersCELConditionFormatWhenOmitted(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:          "implicit-cel",
		Name:        "Implicit CEL",
		Description: "test",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == true"},
		Severity:    "high",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["condition_format"] != policy.ConditionFormatCEL {
		t.Fatalf("expected inferred CEL condition format, got %#v", body["condition_format"])
	}
}

func TestCreatePolicy_RejectsInvalidImplicitCELCondition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:          "invalid-implicit-cel",
		Name:        "Invalid implicit CEL",
		Description: "test",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public =="},
		Severity:    "high",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid CEL condition") {
		t.Fatalf("expected implicit CEL validation error, got %s", w.Body.String())
	}
}

func TestPolicyVersionsAndRollback(t *testing.T) {
	s := newTestServer(t)

	create := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:          "policy-history",
		Name:        "V1",
		Description: "version 1",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", create.Code, create.Body.String())
	}

	update := do(t, s, "PUT", "/api/v1/policies/policy-history", policy.Policy{
		Name:        "V2",
		Description: "version 2",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == false"},
		Severity:    "critical",
	})
	if update.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", update.Code, update.Body.String())
	}

	versionsResp := do(t, s, "GET", "/api/v1/policies/policy-history/versions", nil)
	if versionsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for versions, got %d: %s", versionsResp.Code, versionsResp.Body.String())
	}
	versionsBody := decodeJSON(t, versionsResp)
	versions, ok := versionsBody["versions"].([]interface{})
	if !ok {
		t.Fatalf("expected versions array, got %T", versionsBody["versions"])
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}

	rollback := do(t, s, "POST", "/api/v1/policies/policy-history/rollback", map[string]interface{}{"version": 1})
	if rollback.Code != http.StatusOK {
		t.Fatalf("expected 200 on rollback, got %d: %s", rollback.Code, rollback.Body.String())
	}
	rollbackBody := decodeJSON(t, rollback)
	if rollbackBody["version"].(float64) != 3 {
		t.Fatalf("expected rollback to create version 3, got %v", rollbackBody["version"])
	}
	if rollbackBody["pinned_version"].(float64) != 1 {
		t.Fatalf("expected pinned_version 1, got %v", rollbackBody["pinned_version"])
	}
	if rollbackBody["name"] != "V1" {
		t.Fatalf("expected rollback content from version 1, got %v", rollbackBody["name"])
	}
}

func TestPolicyDryRun_DoesNotPersistChanges(t *testing.T) {
	s := newTestServer(t)

	create := do(t, s, "POST", "/api/v1/policies/", policy.Policy{
		ID:          "policy-dry-run-api",
		Name:        "Current",
		Description: "current",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", create.Code, create.Body.String())
	}

	dryRun := do(t, s, "POST", "/api/v1/policies/policy-dry-run-api/dry-run", map[string]interface{}{
		"policy": map[string]interface{}{
			"name":        "Candidate",
			"description": "candidate",
			"effect":      "forbid",
			"resource":    "aws::s3::bucket",
			"conditions":  []string{"public == false"},
			"severity":    "high",
		},
		"assets": []map[string]interface{}{
			{"_cq_id": "bucket-a", "_cq_table": "aws_s3_buckets", "public": "true"},
			{"_cq_id": "bucket-b", "_cq_table": "aws_s3_buckets", "public": "false"},
		},
	})
	if dryRun.Code != http.StatusOK {
		t.Fatalf("expected 200 for dry-run, got %d: %s", dryRun.Code, dryRun.Body.String())
	}
	dryRunBody := decodeJSON(t, dryRun)
	if dryRunBody["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", dryRunBody["dry_run"])
	}
	impact, ok := dryRunBody["impact"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected impact object, got %T", dryRunBody["impact"])
	}
	if impact["before_matches"].(float64) != 1 {
		t.Fatalf("expected before_matches=1, got %v", impact["before_matches"])
	}
	if impact["after_matches"].(float64) != 1 {
		t.Fatalf("expected after_matches=1, got %v", impact["after_matches"])
	}

	get := do(t, s, "GET", "/api/v1/policies/policy-dry-run-api", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 on policy get, got %d", get.Code)
	}
	body := decodeJSON(t, get)
	if body["name"] != "Current" {
		t.Fatalf("expected persisted policy name to remain Current, got %v", body["name"])
	}
	conditions, ok := body["conditions"].([]interface{})
	if !ok || len(conditions) != 1 || conditions[0] != "public == true" {
		t.Fatalf("expected original conditions to remain, got %v", body["conditions"])
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

func TestDeleteFinding_SoftDelete(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID:           "finding-delete",
		PolicyID:     "policy-1",
		PolicyName:   "Policy 1",
		Description:  "test finding",
		Severity:     "high",
		Resource:     map[string]interface{}{"_cq_id": "res-1"},
		ResourceID:   "res-1",
		ResourceType: "aws::s3::bucket",
	})

	w := do(t, s, "DELETE", "/api/v1/findings/finding-delete", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	get := do(t, s, "GET", "/api/v1/findings/finding-delete", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 when retrieving soft-deleted finding, got %d", get.Code)
	}
	body := decodeJSON(t, get)
	if body["status"] != "DELETED" {
		t.Fatalf("expected finding status DELETED, got %v", body["status"])
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
		ID:          "pub-check",
		Name:        "Public check",
		Description: "findings scan test policy",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"public == true"},
		Severity:    "high",
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

func TestListFindings_SignalTypeAndDomainFilter(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-1", PolicyID: "p1", Severity: "high",
	})
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-2", PolicyID: "stripe-large-refund", Severity: "high",
	})

	if err := s.app.Findings.Update("f-1", func(f *findings.Finding) error {
		f.SignalType = findings.SignalTypeBusiness
		f.Domain = findings.DomainPipeline
		return nil
	}); err != nil {
		t.Fatalf("update f-1: %v", err)
	}

	w := do(t, s, "GET", "/api/v1/findings/?signal_type=business&domain=pipeline", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected 1 filtered finding, got %v", body["count"])
	}
}

func TestSignalsDashboard(t *testing.T) {
	s := newTestServer(t)
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-1", PolicyID: "hubspot-stale-deal", Severity: "high",
	})
	s.app.Findings.Upsert(context.Background(), policy.Finding{
		ID: "f-2", PolicyID: "stripe-large-refund", Severity: "critical",
	})

	if err := s.app.Findings.Update("f-1", func(f *findings.Finding) error {
		f.SignalType = findings.SignalTypeBusiness
		f.Domain = findings.DomainPipeline
		return nil
	}); err != nil {
		t.Fatalf("update f-1: %v", err)
	}
	if err := s.app.Findings.Update("f-2", func(f *findings.Finding) error {
		f.SignalType = findings.SignalTypeCompliance
		f.Domain = findings.DomainFinancial
		f.Status = "SNOOZED"
		return nil
	}); err != nil {
		t.Fatalf("update f-2: %v", err)
	}

	w := do(t, s, "GET", "/api/v1/signals/dashboard", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing summary payload: %#v", body)
	}
	if summary["total_signals"].(float64) != 2 {
		t.Fatalf("expected total_signals=2, got %v", summary["total_signals"])
	}
	if summary["snoozed_signals"].(float64) != 1 {
		t.Fatalf("expected snoozed_signals=1, got %v", summary["snoozed_signals"])
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
	defer func() {
		_ = summaryRC.Close()
	}()

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
	defer func() {
		_ = summaryRC.Close()
	}()

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

func TestListToxicCombinations_PaginationMetadata(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/graph/toxic-combinations?limit=1&offset=0", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 1 || pagination["offset"].(float64) != 0 {
		t.Fatalf("unexpected pagination: %v", pagination)
	}
}

func TestAnalyzePeerGroups_PaginationMetadata(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/graph/peer-groups?limit=1&offset=0", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 1 || pagination["offset"].(float64) != 0 {
		t.Fatalf("unexpected pagination: %v", pagination)
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

func TestListWebhooks_Pagination(t *testing.T) {
	s := newTestServer(t)

	for i := 1; i <= 3; i++ {
		w := do(t, s, "POST", "/api/v1/webhooks/", map[string]interface{}{
			"url":    "https://example.com/hook-" + strconv.Itoa(i),
			"events": []string{"finding.created"},
		})
		if w.Code != http.StatusCreated {
			t.Fatalf("create webhook %d: expected 201, got %d", i, w.Code)
		}
	}

	w := do(t, s, "GET", "/api/v1/webhooks/?limit=2&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected count 2, got %v", body["count"])
	}
	if body["total_count"].(float64) != 3 {
		t.Fatalf("expected total_count 3, got %v", body["total_count"])
	}
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 2 || pagination["offset"].(float64) != 1 {
		t.Fatalf("unexpected pagination: %v", pagination)
	}
	if pagination["has_more"].(bool) {
		t.Fatal("expected has_more false on final page")
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

func TestRemediationRuleUpdateAndDelete(t *testing.T) {
	s := newTestServer(t)

	create := do(t, s, "POST", "/api/v1/remediation/rules", map[string]interface{}{
		"id":          "rule-update",
		"name":        "Original Rule",
		"description": "original description",
		"enabled":     true,
		"trigger": map[string]interface{}{
			"type":     "finding.created",
			"severity": "high",
		},
		"actions": []map[string]interface{}{
			{"type": "create_ticket", "config": map[string]string{"priority": "high"}},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", create.Code, create.Body.String())
	}

	update := do(t, s, "PUT", "/api/v1/remediation/rules/rule-update", map[string]interface{}{
		"name":        "Updated Rule",
		"description": "updated description",
		"enabled":     false,
		"trigger": map[string]interface{}{
			"type":     "finding.created",
			"severity": "critical",
		},
		"actions": []map[string]interface{}{
			{"type": "notify_slack", "config": map[string]string{"channel": "#security"}},
		},
	})
	if update.Code != http.StatusOK {
		t.Fatalf("expected 200 on update, got %d: %s", update.Code, update.Body.String())
	}

	get := do(t, s, "GET", "/api/v1/remediation/rules/rule-update", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d", get.Code)
	}
	body := decodeJSON(t, get)
	if body["name"] != "Updated Rule" {
		t.Fatalf("expected updated name, got %v", body["name"])
	}
	if body["enabled"] != false {
		t.Fatalf("expected updated enabled=false, got %v", body["enabled"])
	}

	del := do(t, s, "DELETE", "/api/v1/remediation/rules/rule-update", nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d: %s", del.Code, del.Body.String())
	}

	missing := do(t, s, "GET", "/api/v1/remediation/rules/rule-update", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", missing.Code)
	}
}

func TestListRemediationRules_Pagination(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, "GET", "/api/v1/remediation/rules?limit=2&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected count 2, got %v", body["count"])
	}
	if body["total_count"].(float64) < 2 {
		t.Fatalf("expected total_count >= 2, got %v", body["total_count"])
	}
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 2 || pagination["offset"].(float64) != 1 {
		t.Fatalf("unexpected pagination: %v", pagination)
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

func TestSchedulerListJobs_Pagination(t *testing.T) {
	s := newTestServer(t)
	s.app.Scheduler.AddJob("job-a", time.Hour, func(ctx context.Context) error { return nil })
	s.app.Scheduler.AddJob("job-b", time.Hour, func(ctx context.Context) error { return nil })
	s.app.Scheduler.AddJob("job-c", time.Hour, func(ctx context.Context) error { return nil })

	w := do(t, s, "GET", "/api/v1/scheduler/jobs?limit=1&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected count 1, got %v", body["count"])
	}
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 1 || pagination["offset"].(float64) != 1 {
		t.Fatalf("unexpected pagination: %v", pagination)
	}
	if !pagination["has_more"].(bool) {
		t.Fatal("expected has_more true when more jobs remain")
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

func TestSyncProvider_UsesRequestOptions(t *testing.T) {
	a := newTestApp(t)
	provider := &captureSyncProvider{name: "okta", provider: providers.ProviderTypeIdentity}
	a.Providers.Register(provider)

	s := NewServer(a)
	w := do(t, s, "POST", "/api/v1/providers/okta/sync", map[string]interface{}{
		"full_sync": false,
		"tables":    []string{"okta_users", "okta_groups"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if provider.calls != 1 {
		t.Fatalf("expected exactly one provider sync call, got %d", provider.calls)
	}
	if provider.lastOpts.FullSync {
		t.Fatalf("expected full_sync=false, got %+v", provider.lastOpts)
	}
	if len(provider.lastOpts.Tables) != 2 || provider.lastOpts.Tables[0] != "okta_users" || provider.lastOpts.Tables[1] != "okta_groups" {
		t.Fatalf("expected table filter to be forwarded, got %+v", provider.lastOpts.Tables)
	}
}

func TestSyncProvider_EmptyBodyDefaultsToFullSync(t *testing.T) {
	a := newTestApp(t)
	provider := &captureSyncProvider{name: "okta", provider: providers.ProviderTypeIdentity}
	a.Providers.Register(provider)

	s := NewServer(a)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/providers/okta/sync", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("expected exactly one provider sync call, got %d", provider.calls)
	}
	if !provider.lastOpts.FullSync {
		t.Fatalf("expected default full sync behavior, got %+v", provider.lastOpts)
	}
	if len(provider.lastOpts.Tables) != 0 {
		t.Fatalf("expected no table filter by default, got %+v", provider.lastOpts.Tables)
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

func TestCollectStaleAccessFindings_SkipsOrphanedWithoutHRData(t *testing.T) {
	detector := identity.NewStaleAccessDetector(identity.DefaultThresholds())

	users := []map[string]interface{}{
		{
			"arn":                "arn:aws:iam::123456789012:user/alice",
			"user_name":          "alice",
			"password_last_used": "2000-01-01T00:00:00Z",
			"provider":           "aws",
			"account_id":         "123456789012",
		},
	}

	findings := collectStaleAccessFindings(context.Background(), detector, users, nil, nil, nil, nil)
	if len(findings) == 0 {
		t.Fatal("expected stale access findings")
	}

	for _, finding := range findings {
		if finding.Type == identity.StaleAccessOrphanedAccount {
			t.Fatal("expected orphaned account detection to be skipped without HR data")
		}
	}
}

func TestPersistStaleAccessFindings_PersistsAndRunsRemediation(t *testing.T) {
	s := newTestServer(t)
	s.app.RemediationExecutor = remediation.NewExecutor(
		s.app.Remediation,
		s.app.Ticketing,
		s.app.Notifications,
		s.app.Findings,
		s.app.Webhooks,
	)

	err := s.app.Remediation.AddRule(remediation.Rule{
		ID:          "test-identity-stale-resolve",
		Name:        "Resolve stale identity finding",
		Description: "Test-only rule",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: "identity-stale-inactive-user",
		},
		Actions: []remediation.Action{
			{Type: remediation.ActionResolveFinding},
		},
	})
	if err != nil {
		t.Fatalf("failed to add remediation rule: %v", err)
	}

	now := time.Now().Add(-120 * 24 * time.Hour)
	stale := identity.StaleAccessFinding{
		ID:       "stale-user-arn:aws:iam::123456789012:user/alice",
		Type:     identity.StaleAccessInactiveUser,
		Severity: "high",
		Principal: identity.Principal{
			ID:    "arn:aws:iam::123456789012:user/alice",
			Type:  "user",
			Name:  "alice",
			Email: "alice@example.com",
		},
		Provider:     "aws",
		Account:      "123456789012",
		LastActivity: &now,
		DaysSince:    120,
		Details:      "stale user",
		Remediation:  "disable user",
	}

	persisted, remediated := s.persistStaleAccessFindings(context.Background(), []identity.StaleAccessFinding{stale})
	if persisted != 1 {
		t.Fatalf("expected persisted=1, got %d", persisted)
	}
	if remediated == 0 {
		t.Fatalf("expected remediation executions, got %d", remediated)
	}

	findingID := "identity-" + stale.ID
	record, ok := s.app.Findings.Get(findingID)
	if !ok {
		t.Fatalf("expected finding %s in store", findingID)
	}
	if strings.ToUpper(record.Status) != "RESOLVED" {
		t.Fatalf("expected finding to be resolved by remediation rule, got status=%s", record.Status)
	}

	_, remediatedAgain := s.persistStaleAccessFindings(context.Background(), []identity.StaleAccessFinding{stale})
	if remediatedAgain != 0 {
		t.Fatalf("expected no remediation run on re-observation, got %d", remediatedAgain)
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

func TestListNotifiers_Pagination(t *testing.T) {
	s := newTestServer(t)
	s.app.Notifications.AddNotifier(stubNotifier{name: "zeta"})
	s.app.Notifications.AddNotifier(stubNotifier{name: "alpha"})
	s.app.Notifications.AddNotifier(stubNotifier{name: "bravo"})

	w := do(t, s, "GET", "/api/v1/notifications/?limit=2&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected count 2, got %v", body["count"])
	}
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 2 || pagination["offset"].(float64) != 1 {
		t.Fatalf("unexpected pagination: %v", pagination)
	}
}

func TestListAgents_Pagination(t *testing.T) {
	s := newTestServer(t)
	s.app.Agents.RegisterAgent(&agents.Agent{ID: "agent-a", Name: "A"})
	s.app.Agents.RegisterAgent(&agents.Agent{ID: "agent-b", Name: "B"})
	s.app.Agents.RegisterAgent(&agents.Agent{ID: "agent-c", Name: "C"})

	w := do(t, s, "GET", "/api/v1/agents/?limit=2&offset=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("expected count 2, got %v", body["count"])
	}
	if body["total_count"].(float64) != 3 {
		t.Fatalf("expected total_count 3, got %v", body["total_count"])
	}
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 2 || pagination["offset"].(float64) != 1 {
		t.Fatalf("unexpected pagination: %v", pagination)
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

func TestAuthMiddleware_TenantIsolationForFindings(t *testing.T) {
	a := newTestApp(t)
	a.Config.APIAuthEnabled = true
	a.Config.APIKeys = map[string]string{
		"alice-key": "alice-tenant-a",
		"bob-key":   "bob-tenant-b",
	}

	if err := a.RBAC.CreateUser(&auth.User{
		ID:       "alice-tenant-a",
		Email:    "alice@example.com",
		TenantID: "tenant-a",
		RoleIDs:  []string{"analyst"},
	}); err != nil {
		t.Fatalf("create alice user: %v", err)
	}
	if err := a.RBAC.CreateUser(&auth.User{
		ID:       "bob-tenant-b",
		Email:    "bob@example.com",
		TenantID: "tenant-b",
		RoleIDs:  []string{"analyst"},
	}); err != nil {
		t.Fatalf("create bob user: %v", err)
	}

	a.Findings.Upsert(context.Background(), policy.Finding{
		ID:          "finding-tenant-a",
		PolicyID:    "policy-a",
		PolicyName:  "Policy A",
		Severity:    "high",
		Description: "tenant a finding",
		Resource: map[string]interface{}{
			"_cq_id":    "asset-a",
			"_cq_table": "aws_s3_buckets",
			"tenant_id": "tenant-a",
		},
	})
	a.Findings.Upsert(context.Background(), policy.Finding{
		ID:          "finding-tenant-b",
		PolicyID:    "policy-b",
		PolicyName:  "Policy B",
		Severity:    "critical",
		Description: "tenant b finding",
		Resource: map[string]interface{}{
			"_cq_id":    "asset-b",
			"_cq_table": "aws_s3_buckets",
			"tenant_id": "tenant-b",
		},
	})

	s := NewServer(a)

	doAuth := func(method, path, apiKey string, body interface{}) *httptest.ResponseRecorder {
		var reader io.Reader
		if body != nil {
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			reader = bytes.NewReader(payload)
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

	aliceList := doAuth(http.MethodGet, "/api/v1/findings", "alice-key", nil)
	if aliceList.Code != http.StatusOK {
		t.Fatalf("expected alice list status 200, got %d", aliceList.Code)
	}
	aliceBody := decodeJSON(t, aliceList)
	if aliceBody["count"].(float64) != 1 {
		t.Fatalf("expected alice to see 1 finding, got %v", aliceBody["count"])
	}
	aliceFindings, ok := aliceBody["findings"].([]interface{})
	if !ok || len(aliceFindings) != 1 {
		t.Fatalf("expected alice findings list with one entry, got %#v", aliceBody["findings"])
	}
	aliceFinding, ok := aliceFindings[0].(map[string]interface{})
	if !ok || aliceFinding["id"] != "finding-tenant-a" {
		t.Fatalf("expected alice to see finding-tenant-a, got %#v", aliceFindings[0])
	}

	aliceCrossTenantGet := doAuth(http.MethodGet, "/api/v1/findings/finding-tenant-b", "alice-key", nil)
	if aliceCrossTenantGet.Code != http.StatusNotFound {
		t.Fatalf("expected alice cross-tenant get to return 404, got %d", aliceCrossTenantGet.Code)
	}

	aliceCrossTenantResolve := doAuth(http.MethodPost, "/api/v1/findings/finding-tenant-b/resolve", "alice-key", nil)
	if aliceCrossTenantResolve.Code != http.StatusNotFound {
		t.Fatalf("expected alice cross-tenant resolve to return 404, got %d", aliceCrossTenantResolve.Code)
	}

	bobGet := doAuth(http.MethodGet, "/api/v1/findings/finding-tenant-b", "bob-key", nil)
	if bobGet.Code != http.StatusOK {
		t.Fatalf("expected bob to access own finding, got %d", bobGet.Code)
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

func TestListAuditLogsRejectsNegativeOffset(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/audit?offset=-1", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid offset, got %d", w.Code)
	}
}

func TestListAuditLogsDegradedResponseIncludesPagination(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, "GET", "/api/v1/audit?limit=5&offset=2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	pagination := decodePagination(t, body)
	if pagination["limit"].(float64) != 5 || pagination["offset"].(float64) != 2 {
		t.Fatalf("unexpected pagination: %v", pagination)
	}
	if pagination["has_more"].(bool) {
		t.Fatal("expected has_more false for degraded empty response")
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
