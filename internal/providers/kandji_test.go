package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKandjiProviderSync_TableParityAndMaterialization(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/devices":
			if r.URL.Query().Get("offset") != "0" {
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"device_id":     "device-1",
					"device_name":   "macbook-1",
					"serial_number": "SERIAL-1",
					"platform":      "macos",
					"user": map[string]interface{}{
						"name":  "Alice",
						"email": "alice@example.com",
					},
					"applications": []map[string]interface{}{
						{"name": "Slack", "bundle_id": "com.slack.Slack", "version": "4.0.0", "path": "/Applications/Slack.app"},
						{"name": "Chrome", "bundle_id": "com.google.Chrome", "version": "125.0", "path": "/Applications/Chrome.app"},
					},
					"profiles": []map[string]interface{}{
						{"id": "profile-1", "name": "Baseline", "uuid": "uuid-1", "installed": true},
					},
				},
			})
		case "/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "user-1", "email": "alice@example.com", "name": "Alice", "role": "admin", "is_active": true},
			})
		case "/vulnerability-management/detections":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{
					{
						"cve_id": "CVE-2026-0001",
						"device": map[string]interface{}{
							"id":            "device-1",
							"name":          "macbook-1",
							"serial_number": "SERIAL-1",
						},
						"software": map[string]interface{}{
							"name":    "OpenSSL",
							"version": "1.0.2",
						},
						"cvss_score":            9.1,
						"cvss_severity":         "critical",
						"first_detection_date":  "2026-02-01T00:00:00Z",
						"latest_detection_date": "2026-02-03T00:00:00Z",
						"cve_link":              "https://example.com/CVE-2026-0001",
					},
				},
			})
		case "/audit/events":
			if r.URL.Query().Get("cursor") == "cursor-2" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"results": []map[string]interface{}{
						{"id": "evt-2", "action": "device.remediated", "actor_id": "user-1", "target_id": "device-1", "occurred_at": "2026-02-04T00:00:00Z"},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": []map[string]interface{}{
					{"id": "evt-1", "action": "device.enrolled", "actor_id": "user-1", "target_id": "device-1", "occurred_at": "2026-02-02T00:00:00Z"},
				},
				"next_cursor": "cursor-2",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewKandjiProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":   server.URL,
		"api_token": "token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	expected := map[string]int64{
		"kandji_devices":         1,
		"kandji_device_apps":     2,
		"kandji_device_profiles": 1,
		"kandji_users":           1,
		"kandji_vulnerabilities": 1,
		"kandji_audit_events":    2,
	}

	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestKandjiProviderSync_IgnoresVulnerabilityPermissionErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vulnerability-management/detections":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewKandjiProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_url":   server.URL,
		"api_token": "token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	table, err := provider.syncVulnerabilities(context.Background())
	if err != nil {
		t.Fatalf("syncVulnerabilities failed: %v", err)
	}
	if table.Rows != 0 {
		t.Fatalf("syncVulnerabilities rows = %d, want 0", table.Rows)
	}
	if table.Inserted != 0 {
		t.Fatalf("syncVulnerabilities inserted = %d, want 0", table.Inserted)
	}
}

func TestKandjiResolveNextPathRejectsForeignHost(t *testing.T) {
	t.Parallel()

	provider := NewKandjiProvider()
	provider.apiURL = "https://tenant.kandji.io/api/v1"

	if _, err := provider.resolveKandjiNextPath("/audit/events?limit=500", "https://evil.example.com/audit/events?cursor=abc"); err == nil {
		t.Fatal("expected foreign host pagination path to be rejected")
	}
}
