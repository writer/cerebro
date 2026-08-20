package sourcehttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateReplayRequestBindsMethodPathAndCanonicalQuery(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/items?offset=0&limit=1", nil)
	if err := ValidateReplayRequest(request, http.MethodGet, "/v1/items", "limit=1&offset=0"); err != nil {
		t.Fatalf("ValidateReplayRequest() error = %v", err)
	}
	for _, test := range []struct {
		name     string
		method   string
		path     string
		rawQuery string
	}{
		{name: "method", method: http.MethodPost, path: "/v1/items", rawQuery: "limit=1&offset=0"},
		{name: "path", method: http.MethodGet, path: "/v1/other", rawQuery: "limit=1&offset=0"},
		{name: "query", method: http.MethodGet, path: "/v1/items", rawQuery: "limit=2&offset=0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReplayRequest(request, test.method, test.path, test.rawQuery); err == nil {
				t.Fatal("ValidateReplayRequest() error = nil, want mismatch rejection")
			}
		})
	}
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "semicolon", rawQuery: "kept=1;discarded=2"},
		{name: "percent_escape", rawQuery: "kept=%zz"},
	} {
		t.Run("actual_"+test.name, func(t *testing.T) {
			request.URL.RawQuery = test.rawQuery
			if err := ValidateReplayRequest(request, http.MethodGet, "/v1/items", "kept=1"); err == nil || !strings.Contains(err.Error(), "replay HTTP query is invalid") {
				t.Fatalf("ValidateReplayRequest(actual malformed query) error = %v", err)
			}
		})
	}
	request.URL.RawQuery = "kept=1"
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "semicolon", rawQuery: "kept=1;discarded=2"},
		{name: "percent_escape", rawQuery: "kept=%zz"},
	} {
		t.Run("expected_"+test.name, func(t *testing.T) {
			if err := ValidateReplayRequest(request, http.MethodGet, "/v1/items", test.rawQuery); err == nil || !strings.Contains(err.Error(), "expected replay HTTP query is invalid") {
				t.Fatalf("ValidateReplayRequest(expected malformed query) error = %v", err)
			}
		})
	}
}
