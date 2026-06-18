package sourcehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestClientCredentialsCacheSeparatesResolvedOAuthRequest(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/tenant-a/token":
			if r.Form.Get("client_id") != "client-a" || r.Form.Get("client_secret") != "secret-a" {
				http.Error(w, "unexpected tenant-a credentials", http.StatusBadRequest)
				return
			}
			writeOAuthToken(t, w, "token-a")
		case "/tenant-b/token":
			if r.Form.Get("client_id") != "client-b" || r.Form.Get("client_secret") != "secret-b" {
				http.Error(w, "unexpected tenant-b credentials", http.StatusBadRequest)
				return
			}
			writeOAuthToken(t, w, "token-b")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var cache ClientCredentialsCache
	options := ClientCredentialsOptions{SourceID: "test", AllowLoopback: true}
	tokenA, err := cache.Token(context.Background(), sourcecdk.NewConfig(map[string]string{
		"token_url":     server.URL + "/tenant-a/token",
		"client_id":     "client-a",
		"client_secret": "secret-a",
	}), options)
	if err != nil {
		t.Fatalf("tenant-a token: %v", err)
	}
	if tokenA != "token-a" {
		t.Fatalf("tenant-a token = %q, want token-a", tokenA)
	}

	tokenB, err := cache.Token(context.Background(), sourcecdk.NewConfig(map[string]string{
		"token_url":     server.URL + "/tenant-b/token",
		"client_id":     "client-b",
		"client_secret": "secret-b",
	}), options)
	if err != nil {
		t.Fatalf("tenant-b token: %v", err)
	}
	if tokenB != "token-b" {
		t.Fatalf("tenant-b token = %q, want token-b", tokenB)
	}

	tokenAAgain, err := cache.Token(context.Background(), sourcecdk.NewConfig(map[string]string{
		"token_url":     server.URL + "/tenant-a/token",
		"client_id":     "client-a",
		"client_secret": "secret-a",
	}), options)
	if err != nil {
		t.Fatalf("tenant-a cached token: %v", err)
	}
	if tokenAAgain != "token-a" {
		t.Fatalf("tenant-a cached token = %q, want token-a", tokenAAgain)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["/tenant-a/token"] != 1 {
		t.Fatalf("tenant-a token endpoint calls = %d, want 1", calls["/tenant-a/token"])
	}
	if calls["/tenant-b/token"] != 1 {
		t.Fatalf("tenant-b token endpoint calls = %d, want 1", calls["/tenant-b/token"])
	}
}

func TestClientCredentialsCacheSeparatesRenderedTokenParams(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audience := r.Form.Get("audience")
		if audience == "" {
			http.Error(w, "missing audience", http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls[audience]++
		mu.Unlock()
		writeOAuthToken(t, w, "token-"+audience)
	}))
	defer server.Close()

	var cache ClientCredentialsCache
	options := ClientCredentialsOptions{
		SourceID:      "test",
		TokenParams:   map[string]string{"audience": "${config.audience}"},
		TemplateKeys:  []string{"audience"},
		AllowLoopback: true,
	}
	cfg := func(audience string) sourcecdk.Config {
		return sourcecdk.NewConfig(map[string]string{
			"token_url":     server.URL + "/oauth/token",
			"client_id":     "client",
			"client_secret": "secret",
			"audience":      audience,
		})
	}

	tokenOne, err := cache.Token(context.Background(), cfg("audience-one"), options)
	if err != nil {
		t.Fatalf("audience-one token: %v", err)
	}
	if tokenOne != "token-audience-one" {
		t.Fatalf("audience-one token = %q, want token-audience-one", tokenOne)
	}
	tokenTwo, err := cache.Token(context.Background(), cfg("audience-two"), options)
	if err != nil {
		t.Fatalf("audience-two token: %v", err)
	}
	if tokenTwo != "token-audience-two" {
		t.Fatalf("audience-two token = %q, want token-audience-two", tokenTwo)
	}
	tokenOneAgain, err := cache.Token(context.Background(), cfg("audience-one"), options)
	if err != nil {
		t.Fatalf("audience-one cached token: %v", err)
	}
	if tokenOneAgain != "token-audience-one" {
		t.Fatalf("audience-one cached token = %q, want token-audience-one", tokenOneAgain)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["audience-one"] != 1 {
		t.Fatalf("audience-one token endpoint calls = %d, want 1", calls["audience-one"])
	}
	if calls["audience-two"] != 1 {
		t.Fatalf("audience-two token endpoint calls = %d, want 1", calls["audience-two"])
	}
}

func writeOAuthToken(t *testing.T, w http.ResponseWriter, token string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"expires_in":   3600,
	}); err != nil {
		t.Fatalf("encode token response: %v", err)
	}
}
