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
