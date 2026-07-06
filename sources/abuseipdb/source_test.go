package abuseipdb

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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-token" {
			t.Fatalf("Key header = %q", r.Header.Get("Key"))
		}
		if r.URL.Path != "/blacklist" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("confidenceMinimum"); got != "" && got != "90" {
			t.Fatalf("confidenceMinimum = %q, want empty health query or 90", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]string{"generatedAt": "2026-06-01T00:00:00Z"},
			"data": []map[string]any{{
				"ipAddress":            "192.0.2.10",
				"countryCode":          "US",
				"abuseConfidenceScore": 100,
				"lastReportedAt":       "2026-06-01T00:00:00Z",
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_key": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "abuseipdb.ip_addresses" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadReportsUsesDocumentedQuery(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-token" {
			t.Fatalf("Key header = %q", r.Header.Get("Key"))
		}
		if r.URL.Path != "/reports" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("ipAddress"); got != "192.0.2.10" {
			t.Fatalf("ipAddress = %q, want 192.0.2.10", got)
		}
		if got := r.URL.Query().Get("perPage"); got != "25" {
			t.Fatalf("perPage = %q, want 25", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"total":   1,
				"page":    1,
				"count":   1,
				"perPage": 25,
				"results": []map[string]any{{
					"reportedAt":          "2026-06-01T00:00:00Z",
					"comment":             "SSH login attempts",
					"categories":          []int{18, 22},
					"reporterId":          43121,
					"reporterCountryCode": "US",
				}},
			},
		})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "tenant",
		"base_url":   server.URL,
		"family":     familyReports,
		"api_key":    "test-token",
		"ip_address": "192.0.2.10",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "abuseipdb.reports" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["resource_id"]; got != "192.0.2.10" {
		t.Fatalf("resource_id = %q, want configured IP", got)
	}
}
