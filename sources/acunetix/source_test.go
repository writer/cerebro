package acunetix

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
	responses := map[string]map[string]any{
		"/targets": {
			"targets": []map[string]any{{
				"target_id":   "target-1",
				"address":     "https://app.example.test",
				"description": "Primary application",
				"type":        "default",
				"criticality": 30,
			}},
			"pagination": map[string]any{"count": 1},
		},
		"/scans": {
			"scans": []map[string]any{{
				"scan_id":      "scan-1",
				"profile_name": "Full Scan",
				"target_id":    "target-1",
				"target":       map[string]any{"address": "https://app.example.test"},
				"current_session": map[string]any{
					"status": "completed",
				},
				"start_date": "2026-06-01T00:00:00Z",
			}},
			"pagination": map[string]any{"count": 1},
		},
		"/vulnerabilities": {
			"vulnerabilities": []map[string]any{{
				"vuln_id":     "vuln-1",
				"vt_name":     "Cross-site scripting",
				"severity":    3,
				"status":      "open",
				"target_id":   "target-1",
				"affects_url": "https://app.example.test/search",
			}},
			"pagination": map[string]any{"count": 1},
		},
		"/scanning_profiles": {
			"scanning_profiles": []map[string]any{{
				"profile_id": "11111111-1111-1111-1111-111111111111",
				"name":       "Full Scan",
				"sort_order": 1,
			}},
		},
		"/reports": {
			"reports": []map[string]any{{
				"report_id":       "report-1",
				"template_name":   "Developer Report",
				"generation_date": "2026-06-01T00:00:00Z",
				"status":          "completed",
			}},
			"pagination": map[string]any{"count": 1},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "test-token" {
			t.Fatalf("X-Auth = %q", r.Header.Get("X-Auth"))
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	for _, tc := range []struct {
		family string
		kind   string
	}{
		{family: familyTargets, kind: "acunetix.targets"},
		{family: familyScans, kind: "acunetix.scans"},
		{family: familyVulnerabilities, kind: "acunetix.vulnerabilities"},
		{family: familyScanningProfiles, kind: "acunetix.scanning_profiles"},
		{family: familyReports, kind: "acunetix.reports"},
	} {
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
		})
	}
}
