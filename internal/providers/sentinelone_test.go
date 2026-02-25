package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		case "/web/api/v2.1/vulnerabilities":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"agentId": "agent-1", "cveId": "CVE-2026-0001", "applicationName": "Chrome", "applicationVersion": "1.2.3", "severity": "high"},
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
