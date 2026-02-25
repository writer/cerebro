package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRampProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	var tokenCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/oauth/token":
			if req.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if err := req.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.PostForm.Get("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			atomic.AddInt32(&tokenCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "ramp-access-token",
				"expires_in":   3600,
			})
			return
		}

		if req.Header.Get("Authorization") != "Bearer ramp-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"missing bearer token"}`))
			return
		}

		switch req.URL.Path {
		case "/v1/users":
			nextToken := req.URL.Query().Get("next_page_token")
			if nextToken == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":         "user-1",
							"email":      "alice@example.com",
							"first_name": "Alice",
							"last_name":  "Admin",
							"status":     "active",
							"role":       "admin",
							"department": map[string]interface{}{"name": "Security"},
						},
					},
					"next_page_token": "users-page-2",
				})
				return
			}
			if nextToken == "users-page-2" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"users": []map[string]interface{}{
						{
							"id":         "user-2",
							"email":      "bob@example.com",
							"first_name": "Bob",
							"last_name":  "Builder",
							"status":     "active",
							"role":       "user",
							"department": map[string]interface{}{"name": "Engineering"},
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		case "/v1/cards":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"cards": []map[string]interface{}{
					{
						"id":     "card-1",
						"status": "active",
						"user": map[string]interface{}{
							"id":    "user-1",
							"email": "alice@example.com",
						},
						"spend_limit": map[string]interface{}{
							"amount":   1000,
							"currency": "USD",
						},
						"last4": "1234",
					},
				},
			})
			return
		case "/v1/transactions":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"transactions": []map[string]interface{}{
					{
						"id":      "txn-1",
						"user_id": "user-1",
						"card_id": "card-1",
						"merchant": map[string]interface{}{
							"name": "ACME Corp",
						},
						"amount": map[string]interface{}{
							"amount":   2450,
							"currency": "USD",
						},
						"state":            "posted",
						"transaction_time": "2026-02-25T10:00:00Z",
					},
				},
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewRampProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "ramp-client-id",
		"client_secret": "ramp-client-secret",
		"base_url":      server.URL + "/v1",
		"token_url":     server.URL + "/oauth/token",
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
	if got := atomic.LoadInt32(&tokenCalls); got != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", got)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	expected := map[string]int64{
		"ramp_users":        2,
		"ramp_cards":        1,
		"ramp_transactions": 1,
	}
	for table, want := range expected {
		if got := rowsByTable[table]; got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestRampProviderSync_IgnoresPermissionDeniedChildTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "ramp-access-token",
				"expires_in":   3600,
			})
			return
		case "/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{{"id": "user-1", "email": "alice@example.com"}},
			})
			return
		case "/v1/cards", "/v1/transactions":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewRampProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "ramp-client-id",
		"client_secret": "ramp-client-secret",
		"base_url":      server.URL + "/v1",
		"token_url":     server.URL + "/oauth/token",
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

	if rowsByTable["ramp_users"] != 1 {
		t.Fatalf("ramp_users rows = %d, want 1", rowsByTable["ramp_users"])
	}
	if rowsByTable["ramp_cards"] != 0 {
		t.Fatalf("ramp_cards rows = %d, want 0", rowsByTable["ramp_cards"])
	}
	if rowsByTable["ramp_transactions"] != 0 {
		t.Fatalf("ramp_transactions rows = %d, want 0", rowsByTable["ramp_transactions"])
	}
}

func TestRampProviderListCollection_DetectsPaginationLoop(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "ramp-access-token",
				"expires_in":   3600,
			})
			return
		case "/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users":           []map[string]interface{}{{"id": "user-1"}},
				"next_page_token": "repeat-token",
			})
			return
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewRampProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "ramp-client-id",
		"client_secret": "ramp-client-secret",
		"base_url":      server.URL + "/v1",
		"token_url":     server.URL + "/oauth/token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.listUsers(context.Background())
	if err == nil {
		t.Fatal("expected pagination loop error")
	}
	if !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}
