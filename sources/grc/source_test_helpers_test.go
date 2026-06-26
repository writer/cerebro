package grc

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

func testConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":      baseURL,
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        family,
		"per_page":      "1",
		"provider":      "vanta",
		"tenant_id":     "writer",
	})
}

func tokenCacheTestConfig(baseURL string, basePath string, clientSecret string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":      baseURL + basePath,
		"client_id":     testClientID,
		"client_secret": clientSecret,
		"family":        familyVendor,
		"per_page":      "1",
		"provider":      "vanta",
		"tenant_id":     "writer",
		"token_url":     baseURL + "/oauth/token",
	})
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", got)
	}
}

func writePage(t *testing.T, w http.ResponseWriter, hasNext bool, endCursor string, data []map[string]any) {
	t.Helper()
	writeJSON(t, w, map[string]any{
		"results": map[string]any{
			"pageInfo": map[string]any{
				"endCursor":   endCursor,
				"hasNextPage": hasNext,
			},
			"data": data,
		},
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
