package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLineageEndpoints_Return503WhenServiceMissing(t *testing.T) {
	a := newTestApp(t)
	a.Lineage = nil
	s := NewServer(a)

	cases := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/lineage/asset-123"},
		{method: http.MethodGet, path: "/api/v1/lineage/by-commit/abc123"},
		{method: http.MethodGet, path: "/api/v1/lineage/by-image/sha256:abc"},
		{method: http.MethodPost, path: "/api/v1/lineage/drift/asset-123"},
	}

	for _, tc := range cases {
		w := do(t, s, tc.method, tc.path, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: expected 503, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestTicketDetailEndpoints_Return503WithoutProvider(t *testing.T) {
	s := newTestServer(t)

	cases := []struct {
		method string
		path   string
		body   interface{}
	}{
		{method: http.MethodGet, path: "/api/v1/tickets/example-id", body: nil},
		{method: http.MethodPut, path: "/api/v1/tickets/example-id", body: map[string]interface{}{"status": "in_progress"}},
		{method: http.MethodPost, path: "/api/v1/tickets/example-id/comments", body: map[string]interface{}{"body": "test"}},
		{method: http.MethodPost, path: "/api/v1/tickets/example-id/close", body: map[string]interface{}{"resolution": "done"}},
	}

	for _, tc := range cases {
		w := do(t, s, tc.method, tc.path, tc.body)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: expected 503, got %d", tc.method, tc.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "no ticketing provider configured") {
			t.Fatalf("%s %s: expected provider missing message, got %s", tc.method, tc.path, w.Body.String())
		}
	}
}

func TestAuditEndpoint_ReturnsDegradedResponseWithoutAuditRepo(t *testing.T) {
	a := newTestApp(t)
	a.AuditRepo = nil
	s := NewServer(a)

	w := do(t, s, http.MethodGet, "/api/v1/audit/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "snowflake not configured") {
		t.Fatalf("expected degraded audit response, got %s", w.Body.String())
	}
}

func TestWebhookAndRemediationEndpoints_RejectMalformedJSON(t *testing.T) {
	s := newTestServer(t)

	cases := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/webhooks/test"},
		{method: http.MethodPost, path: "/api/v1/remediation/executions/ex-1/approve"},
		{method: http.MethodPost, path: "/api/v1/remediation/executions/ex-1/reject"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: expected 400, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestCreateIncident_ReturnsBadRequestWhenTitleMissing(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/incidents/", map[string]interface{}{
		"severity": "high",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "title is required") {
		t.Fatalf("expected validation error message, got %s", w.Body.String())
	}
}
