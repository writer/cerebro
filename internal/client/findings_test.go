package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/findings"
)

func TestListFindings_SendsFiltersAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("severity"); got != "high" {
			t.Fatalf("expected severity filter, got %q", got)
		}
		if got := r.URL.Query().Get("status"); got != "OPEN" {
			t.Fatalf("expected status filter, got %q", got)
		}
		if got := r.URL.Query().Get("policy_id"); got != "policy-1" {
			t.Fatalf("expected policy_id filter, got %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "25" {
			t.Fatalf("expected limit filter, got %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("expected bearer auth header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != defaultUserAgent {
			t.Fatalf("expected default user-agent %q, got %q", defaultUserAgent, got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": []map[string]interface{}{
				{
					"id":          "finding-1",
					"policy_id":   "policy-1",
					"resource_id": "resource-1",
					"severity":    "high",
					"status":      "OPEN",
				},
			},
			"count": 1,
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	list, err := c.ListFindings(context.Background(), findings.FindingFilter{
		Severity: "high",
		Status:   "OPEN",
		PolicyID: "policy-1",
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one finding, got %d", len(list))
	}
	if list[0].ID != "finding-1" {
		t.Fatalf("unexpected finding id: %s", list[0].ID)
	}
}

func TestResolveFinding_NotFoundReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/missing/resolve" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "finding not found",
			"code":  "not_found",
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = c.ResolveFinding(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !IsAPIErrorStatus(err, http.StatusNotFound) {
		t.Fatalf("expected 404 API error, got %v", err)
	}
}

func TestExportFindings_ReturnsDataAndContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/export" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("format"); got != "json" {
			t.Fatalf("expected json format query, got %q", got)
		}
		if got := r.URL.Query().Get("pretty"); got != "true" {
			t.Fatalf("expected pretty query flag, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"findings\":[]}"))
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	data, contentType, err := c.ExportFindings(context.Background(), findings.FindingFilter{Severity: "critical"}, "json", true)
	if err != nil {
		t.Fatalf("export findings: %v", err)
	}
	if !strings.Contains(contentType, "application/json") {
		t.Fatalf("unexpected content type: %s", contentType)
	}
	if string(data) != "{\"findings\":[]}" {
		t.Fatalf("unexpected payload: %s", string(data))
	}
}
