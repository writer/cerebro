package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSplunkProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Splunk splunk-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/services/authentication/users":
			offset, _ := strconv.Atoi(req.URL.Query().Get("offset"))
			count := 200
			if c := req.URL.Query().Get("count"); c != "" {
				if parsed, err := strconv.Atoi(c); err == nil {
					count = parsed
				}
			}

			entries := []map[string]interface{}{}
			switch offset {
			case 0:
				entries = splunkTestUserEntries(count, 1)
			case 200:
				entries = splunkTestUserEntries(1, 201)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": entries,
			})
			return
		case "/services/authorization/roles":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": []map[string]interface{}{{
					"id":      "role-admin",
					"name":    "admin",
					"updated": "2026-02-25T13:00:00Z",
					"content": map[string]interface{}{
						"imported_roles":             []string{"power"},
						"srch_filter":                "index=*",
						"srch_indexes_allowed":       []string{"main", "security"},
						"srch_indexes_default":       []string{"main"},
						"cumulative_srch_jobs_quota": 6,
					},
				}},
			})
			return
		case "/services/data/indexes":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": []map[string]interface{}{{
					"id":      "idx-main",
					"name":    "main",
					"updated": "2026-02-25T13:10:00Z",
					"content": map[string]interface{}{
						"datatype":                   "event",
						"max_total_data_size_mb":     512000,
						"home_path":                  "/opt/splunk/var/lib/splunk/main/db",
						"cold_path":                  "/opt/splunk/var/lib/splunk/main/colddb",
						"thawed_path":                "/opt/splunk/var/lib/splunk/main/thaweddb",
						"frozen_time_period_in_secs": 188697600,
						"is_internal":                false,
						"disabled":                   false,
					},
				}},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSplunkProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "splunk-token",
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

	if rowsByTable["splunk_users"] != 201 {
		t.Fatalf("splunk_users rows = %d, want 201", rowsByTable["splunk_users"])
	}
	if rowsByTable["splunk_roles"] != 1 {
		t.Fatalf("splunk_roles rows = %d, want 1", rowsByTable["splunk_roles"])
	}
	if rowsByTable["splunk_indexes"] != 1 {
		t.Fatalf("splunk_indexes rows = %d, want 1", rowsByTable["splunk_indexes"])
	}
}

func TestSplunkProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Splunk splunk-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/services/authentication/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": []map[string]interface{}{{
					"id":   "user-1",
					"name": "alice",
					"content": map[string]interface{}{
						"email": "alice@example.com",
					},
				}},
			})
			return
		case "/services/authorization/roles":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		case "/services/data/indexes":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewSplunkProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL,
		"token": "splunk-token",
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

	if rowsByTable["splunk_users"] != 1 {
		t.Fatalf("splunk_users rows = %d, want 1", rowsByTable["splunk_users"])
	}
	if rowsByTable["splunk_roles"] != 0 {
		t.Fatalf("splunk_roles rows = %d, want 0", rowsByTable["splunk_roles"])
	}
	if rowsByTable["splunk_indexes"] != 0 {
		t.Fatalf("splunk_indexes rows = %d, want 0", rowsByTable["splunk_indexes"])
	}
}

func TestSplunkProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewSplunkProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   "https://splunk.example.com",
		"token": "splunk-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/services/server/info?output_mode=json")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func splunkTestUserEntries(count int, start int) []map[string]interface{} {
	entries := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		entries = append(entries, map[string]interface{}{
			"id":        "user-" + strconv.Itoa(id),
			"name":      "user-" + strconv.Itoa(id),
			"published": "2026-02-25T12:00:00Z",
			"updated":   "2026-02-25T13:00:00Z",
			"content": map[string]interface{}{
				"realname":    "User " + strconv.Itoa(id),
				"email":       "user" + strconv.Itoa(id) + "@example.com",
				"roles":       []string{"user"},
				"default_app": "search",
				"tz":          "UTC",
				"status":      "active",
			},
		})
	}
	return entries
}
