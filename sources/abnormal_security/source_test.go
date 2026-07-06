package abnormal_security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requested := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		requested[r.URL.Path]++
		if r.URL.Path == "/users" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/resources":
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]string{{"resourceId": "resource-1", "name": "Mailbox Resource", "description": "Protected mailbox resource", "updated_at": "2026-06-01T00:00:00Z"}}})
		case "/threats":
			_ = json.NewEncoder(w).Encode(map[string]any{"threats": []map[string]string{{"threatId": "threat-1", "severity": "high", "status": "active", "title": "Credential phishing campaign"}}})
		case "/cases":
			_ = json.NewEncoder(w).Encode(map[string]any{"cases": []map[string]any{{"caseId": 1234, "description": "Account takeover case", "severity_level": "LOW", "confidence": "HIGH", "created": "2026-06-01T00:00:00Z", "first_observed": "2026-06-01T00:00:00Z", "last_modified": "2026-06-02T00:00:00Z"}}})
		case "/spm-v2/posture-catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "posture-1", "name": "Mailbox forwarding posture", "risk_level": "medium", "description": "Posture catalog item"}}})
		case "/auditlogs":
			_ = json.NewEncoder(w).Encode(map[string]any{"auditLogs": []map[string]any{{"action": "update_remediation_status", "category": "search-and-respond-notifications", "sourceIp": "192.0.2.10", "status": "SUCCESS", "timestamp": "2026-06-01T00:00:00Z", "user": map[string]string{"email": "analyst@example.com"}}}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": "resources", "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	cases := []struct {
		family string
		kind   string
		path   string
	}{
		{family: "resources", kind: "abnormal_security.resources", path: "/resources"},
		{family: "threats", kind: "abnormal_security.threats", path: "/threats"},
		{family: "cases", kind: "abnormal_security.cases", path: "/cases"},
		{family: "posture_catalog", kind: "abnormal_security.posture_catalog", path: "/spm-v2/posture-catalog"},
		{family: "audit_events", kind: "abnormal_security.audit_events", path: "/auditlogs"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tc.family, "token": "test-token"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q", event.Kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if requested[tc.path] == 0 {
				t.Fatalf("provider path %s was not requested", tc.path)
			}
		})
	}
}
