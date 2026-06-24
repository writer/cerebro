package googleworkspaceauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"golang.org/x/oauth2/google"
)

func TestBearerTokenCachedSourceIsNotRequestScoped(t *testing.T) {
	tokenSources = sync.Map{}
	t.Cleanup(func() { tokenSources = sync.Map{} })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("token request method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	previousEndpoint := google.Endpoint
	google.Endpoint.TokenURL = server.URL
	t.Cleanup(func() { google.Endpoint = previousEndpoint })

	token, err := BearerToken(Settings{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RefreshToken: "refresh-token-" + t.Name(),
	})
	if err != nil {
		t.Fatalf("BearerToken() error = %v", err)
	}
	if token != "fresh-token" {
		t.Fatalf("BearerToken() = %q, want fresh-token", token)
	}
}

func TestBearerTokenCacheKeyChangesWhenOAuthClientSecretRotates(t *testing.T) {
	tokenSources = sync.Map{}
	t.Cleanup(func() { tokenSources = sync.Map{} })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token request form: %v", err)
		}
		secret := r.Form.Get("client_secret")
		if secret == "" {
			_, secret, _ = r.BasicAuth()
		}
		if secret == "" {
			t.Fatal("token request missing client_secret")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-for-" + secret,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	previousEndpoint := google.Endpoint
	google.Endpoint.TokenURL = server.URL
	t.Cleanup(func() { google.Endpoint = previousEndpoint })

	settings := Settings{ClientID: "client-id", ClientSecret: "secret-a", RefreshToken: "refresh-token"}
	token, err := BearerToken(settings)
	if err != nil {
		t.Fatalf("BearerToken(secret-a) error = %v", err)
	}
	if token != "token-for-secret-a" {
		t.Fatalf("BearerToken(secret-a) = %q, want token-for-secret-a", token)
	}

	settings.ClientSecret = "secret-b"
	token, err = BearerToken(settings)
	if err != nil {
		t.Fatalf("BearerToken(secret-b) error = %v", err)
	}
	if token != "token-for-secret-b" {
		t.Fatalf("BearerToken(secret-b) = %q, want token-for-secret-b", token)
	}
}
