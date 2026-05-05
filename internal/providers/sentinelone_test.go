package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSentinelOneProviderSync_IncludesApplicationsAndVulnerabilities(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/web/api/v2.1/sites":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"sites": []map[string]interface{}{
						{"id": "site-1", "name": "Default"},
					},
				},
			})
		case "/web/api/v2.1/agents":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "agent-1", "computerName": "host-1", "siteId": "site-1"},
				},
			})
		case "/web/api/v2.1/threats":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "threat-1", "agentId": "agent-1", "threatName": "Malware"},
				},
			})
		case "/web/api/v2.1/activities":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "activity-1", "agentId": "agent-1", "activityType": 1001},
				},
			})
		case "/web/api/v2.1/installed-applications":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"agentId": "agent-1", "name": "Chrome", "version": "1.2.3", "publisher": "Google"},
				},
			})
		case "/web/api/v2.1/application-management/risks":
			if got := r.URL.Query().Get("siteIds"); got != "site-1" {
				t.Fatalf("risk siteIds = %q, want site-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"endpointId":         "agent-1",
						"endpointName":       "host-1",
						"cveId":              "CVE-2026-0001",
						"applicationName":    "Chrome",
						"applicationVersion": "1.2.3",
						"severity":           "Medium",
						"status":             "open",
						"baseScore":          "6.5",
						"daysDetected":       31,
						"detectionDate":      "2026-01-01T00:00:00Z",
						"lastScanResult":     "patch available",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSentinelOneProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"base_url":  server.URL,
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

	for _, table := range []string{
		"sentinelone_sites",
		"sentinelone_agents",
		"sentinelone_threats",
		"sentinelone_activities",
		"sentinelone_applications",
		"sentinelone_vulnerabilities",
	} {
		if got := rowsByTable[table]; got != 1 {
			t.Fatalf("%s rows = %d, want 1", table, got)
		}
	}
}

func TestSentinelOneProviderSyncAgents_PaginationLoopStops(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/web/api/v2.1/agents" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		requestCount++

		switch r.URL.Query().Get("cursor") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{"id": "agent-1"}},
				"pagination": map[string]interface{}{
					"nextCursor": "cursor-1",
				},
			})
		case "cursor-1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{"id": "agent-2"}},
				"pagination": map[string]interface{}{
					"nextCursor": "cursor-1",
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{}})
		}
	}))
	defer server.Close()

	provider := NewSentinelOneProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"base_url":  server.URL,
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	table, err := provider.syncAgents(context.Background())
	if err != nil {
		t.Fatalf("syncAgents failed: %v", err)
	}
	if table.Rows != 2 {
		t.Fatalf("syncAgents rows = %d, want 2", table.Rows)
	}
	if requestCount != 2 {
		t.Fatalf("syncAgents request count = %d, want 2", requestCount)
	}
}

func TestSentinelOneProviderConfigure_ValidatesRequiredConfig(t *testing.T) {
	t.Parallel()

	provider := NewSentinelOneProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"base_url": "https://example.sentinelone.net",
	}); err == nil || !strings.Contains(err.Error(), "api_token") {
		t.Fatalf("configure missing token error = %v, want api_token error", err)
	}

	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"base_url":  "not-a-url",
	}); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("configure invalid base_url error = %v, want base_url error", err)
	}
}

func TestSentinelOneProviderSync_HonorsTableFilter(t *testing.T) {
	t.Parallel()

	requestedPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/web/api/v2.1/agents":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{"id": "agent-1"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSentinelOneProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"api_token": "token",
		"base_url":  server.URL + "/",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{Tables: []string{"sentinelone_agents"}})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}
	if len(result.Tables) != 1 || result.Tables[0].Name != "sentinelone_agents" {
		t.Fatalf("synced tables = %+v, want only sentinelone_agents", result.Tables)
	}
	if len(requestedPaths) != 1 || requestedPaths[0] != "/web/api/v2.1/agents" {
		t.Fatalf("requested paths = %v, want only agents", requestedPaths)
	}

	_, err = provider.Sync(context.Background(), SyncOptions{Tables: []string{"sentinelone_unknown"}})
	if err == nil || !strings.Contains(err.Error(), "no matching SentinelOne tables") {
		t.Fatalf("unknown table sync error = %v, want no matching tables error", err)
	}
}

func TestNormalizeSentinelOneThreat_LiveNestedShape(t *testing.T) {
	t.Parallel()

	row := normalizeSentinelOneThreat(map[string]interface{}{
		"threatInfo": map[string]interface{}{
			"threatId":             "threat-1",
			"threatName":           "EICAR",
			"classification":       "Malware",
			"classificationSource": "Cloud",
			"analystVerdict":       "true_positive",
			"mitigationStatus":     "not_mitigated",
			"sha256":               "abc123",
			"createdAt":            "2026-01-01T00:00:00Z",
		},
		"agentRealtimeInfo": map[string]interface{}{
			"agentId":           "agent-1",
			"agentComputerName": "host-1",
		},
		"indicators": map[string]interface{}{
			"mitreTactics": []interface{}{"TA0011"},
			"categories":   []interface{}{"Ransomware"},
		},
	})

	if got := row["id"]; got != "threat-1" {
		t.Fatalf("id = %v, want threat-1", got)
	}
	if got := row["agent_id"]; got != "agent-1" {
		t.Fatalf("agent_id = %v, want agent-1", got)
	}
	if got := row["agent_computer_name"]; got != "host-1" {
		t.Fatalf("agent_computer_name = %v, want host-1", got)
	}
	if got := row["threat_name"]; got != "EICAR" {
		t.Fatalf("threat_name = %v, want EICAR", got)
	}
	if _, ok := row["threat_info"].(map[string]interface{}); !ok {
		t.Fatalf("threat_info missing or wrong type: %T", row["threat_info"])
	}
	if _, ok := row["indicators"].(map[string]interface{}); !ok {
		t.Fatalf("indicators missing or wrong type: %T", row["indicators"])
	}
}

func TestNormalizeSentinelOneVulnerability_ApplicationRiskShape(t *testing.T) {
	t.Parallel()

	row := normalizeSentinelOneVulnerability(map[string]interface{}{
		"endpointId":         "agent-1",
		"endpointName":       "host-1",
		"cveId":              "CVE-2026-0001",
		"applicationName":    "Chrome",
		"applicationVersion": "1.2.3",
		"severity":           "Medium",
		"status":             "open",
		"baseScore":          "6.5",
		"daysDetected":       31,
		"detectionDate":      "2026-01-01T00:00:00Z",
		"lastScanResult":     "patch available",
	}, "site-1")

	want := map[string]interface{}{
		"agent_id":             "agent-1",
		"site_id":              "site-1",
		"cve_id":               "CVE-2026-0001",
		"application_name":     "Chrome",
		"application_version":  "1.2.3",
		"severity":             "Medium",
		"status":               "open",
		"cvss_score":           "6.5",
		"days_since_detection": 31,
		"detected_at":          "2026-01-01T00:00:00Z",
		"remediation_action":   "patch available",
	}

	for key, wantValue := range want {
		if got := row[key]; got != wantValue {
			t.Fatalf("%s = %v, want %v", key, got, wantValue)
		}
	}
}
