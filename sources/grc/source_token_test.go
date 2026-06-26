package grc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenCacheScopesRuntimeSecretsAndBaseURL(t *testing.T) {
	tokenRequests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			secret := payload["client_secret"]
			tokenRequests[secret]++
			writeJSON(t, w, map[string]any{
				"access_token": "token-for-" + secret,
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/tenant-a/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer token-for-secret-a" {
				t.Fatalf("tenant-a Authorization = %q, want token for secret-a", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-a", "name": "Tenant A"}})
		case "/tenant-b/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer token-for-secret-b" {
				t.Fatalf("tenant-b Authorization = %q, want token for secret-b", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-b", "name": "Tenant B"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfgA := tokenCacheTestConfig(server.URL, "/tenant-a", "secret-a")
	cfgB := tokenCacheTestConfig(server.URL, "/tenant-b", "secret-b")
	if _, err := source.Read(context.Background(), cfgA, nil); err != nil {
		t.Fatalf("Read(tenant-a) error = %v", err)
	}
	if _, err := source.Read(context.Background(), cfgB, nil); err != nil {
		t.Fatalf("Read(tenant-b) error = %v", err)
	}
	if got := tokenRequests["secret-a"]; got != 1 {
		t.Fatalf("secret-a token requests = %d, want 1", got)
	}
	if got := tokenRequests["secret-b"]; got != 1 {
		t.Fatalf("secret-b token requests = %d, want 1", got)
	}
}

func TestTokenCacheReusesTokenAcrossFamilies(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			writeJSON(t, w, map[string]any{
				"access_token": "shared-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/controls", "/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer shared-token" {
				t.Fatalf("Authorization = %q, want shared token", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "record-1", "name": "Record"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfgControl := testConfig(server.URL, familyControl)
	cfgVendor := testConfig(server.URL, familyVendor)
	if _, err := source.Read(context.Background(), cfgControl, nil); err != nil {
		t.Fatalf("Read(control) error = %v", err)
	}
	if _, err := source.Read(context.Background(), cfgVendor, nil); err != nil {
		t.Fatalf("Read(vendor) error = %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
}

func TestReadRefreshesTokenAfterUnauthorizedPage(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			token := "token-1"
			if tokenRequests == 2 {
				token = "token-2"
			}
			writeJSON(t, w, map[string]any{
				"access_token": token,
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			cursor := r.URL.Query().Get("pageCursor")
			switch cursor {
			case "":
				if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
					t.Fatalf("first page Authorization = %q, want token-1", got)
				}
				writePage(t, w, true, "cursor-2", []map[string]any{{"id": "vendor-1", "name": "Acme SaaS"}})
			case "cursor-2":
				switch got := r.Header.Get("Authorization"); got {
				case "Bearer token-1":
					http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				case "Bearer token-2":
					writePage(t, w, false, "", []map[string]any{{"id": "vendor-2", "name": "Beta SaaS"}})
				default:
					t.Fatalf("second page Authorization = %q, want token-1 retry then token-2", got)
				}
			default:
				t.Fatalf("unexpected pageCursor = %q", cursor)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVendor)
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first page) error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatalf("Read(first page).NextCursor is nil")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(second page).Events) = %d, want 1", len(second.Events))
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want 2", tokenRequests)
	}
}

func TestTokenRequestRetriesRateLimit(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			if tokenRequests < 3 {
				http.Error(w, `{"error":"Too Many Requests"}`, http.StatusTooManyRequests)
				return
			}
			writeJSON(t, w, map[string]any{
				"access_token": "retry-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer retry-token" {
				t.Fatalf("Authorization = %q, want retry-token", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-1", "name": "Acme SaaS"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	source.tokenRetryBackoffs = []time.Duration{0, 0}
	pull, err := source.Read(context.Background(), testConfig(server.URL, familyVendor), nil)
	if err != nil {
		t.Fatalf("Read(vendor) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(vendor).Events) = %d, want 1", len(pull.Events))
	}
	if tokenRequests != 3 {
		t.Fatalf("token requests = %d, want 3", tokenRequests)
	}
}
