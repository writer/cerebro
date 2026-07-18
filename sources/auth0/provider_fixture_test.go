package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/sources/internal/auth0api"
)

func TestSourceReplaysCapturedAuth0Families(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		configKey   string
		idSegment   int
		captureTime bool
	}{
		{family: auth0api.FamilyUsers, fixtureCase: "list_users"},
		{family: auth0api.FamilyRoles, fixtureCase: "list_roles", captureTime: true},
		{family: auth0api.FamilyOrganizationMembers, fixtureCase: "list_organization_members", configKey: "organization_ids", idSegment: 3, captureTime: true},
		{family: auth0api.FamilyClients, fixtureCase: "list_clients", captureTime: true},
		{family: auth0api.FamilyClientGrants, fixtureCase: "list_client_grants", captureTime: true},
		{family: auth0api.FamilyUserRoles, fixtureCase: "list_user_roles", configKey: "user_ids", idSegment: 3, captureTime: true},
		{family: auth0api.FamilyGuardianFactors, fixtureCase: "list_guardian_factors", captureTime: true},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedAuth0Bundle(t, test.family, test.fixtureCase)
			requestPath := capturedAuth0RequestPath(t, bundle)
			server := capturedAuth0Server(t, requestPath, bundle)
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			values := map[string]string{
				"base_url":      server.URL + "/api/v2",
				"client_id":     "replay-client",
				"client_secret": "replay-secret",
				"domain":        "tenant.auth0.com",
				"family":        test.family,
				"per_page":      "1",
				"tenant_id":     "tenant",
				"token_url":     server.URL + "/oauth/token",
			}
			if test.configKey != "" {
				values[test.configKey] = capturedAuth0PathSegment(t, requestPath, test.idSegment)
			}
			cfg := sourcecdk.NewConfig(values)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) == 0 || pull.Events[0].Kind != "auth0."+test.family {
				t.Fatalf("Read() events = %#v, want kind auth0.%s", pull.Events, test.family)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.captureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedAuth0Fixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceUsesCapturedOrganizationMemberCheckpointAsFrom(t *testing.T) {
	bundle := capturedAuth0Bundle(t, auth0api.FamilyOrganizationMembers, "list_organization_members")
	requestPath := capturedAuth0RequestPath(t, bundle)
	var capturedPage struct {
		Next string `json:"next"`
	}
	if err := json.Unmarshal(bundle.Payload, &capturedPage); err != nil {
		t.Fatalf("decode captured organization members response: %v", err)
	}
	if capturedPage.Next == "" {
		t.Fatal("captured organization members response has no next checkpoint")
	}

	requests := make([]url.Values, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "replay-token", "expires_in": 600})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("unexpected Auth0 replay request %s %s", r.Method, r.URL.RequestURI())
		}
		query := r.URL.Query()
		requests = append(requests, query)
		if got := query.Get("page"); got != "" {
			t.Fatalf("page = %q, want checkpoint pagination without page", got)
		}
		if got := query.Get("take"); got != "1" {
			t.Fatalf("take = %q, want 1", got)
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		if from := query.Get("from"); from != "" {
			if from != capturedPage.Next {
				t.Fatalf("from = %q, want captured checkpoint %q", from, capturedPage.Next)
			}
			_, _ = w.Write([]byte(`{"members":[]}`))
			return
		}
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":                   server.URL + "/api/v2",
		"client_id":                  "replay-client",
		"client_secret":              "replay-secret",
		"domain":                     "tenant.auth0.com",
		"family":                     auth0api.FamilyOrganizationMembers,
		"organization_ids":           capturedAuth0PathSegment(t, requestPath, 3),
		"organization_member_fields": "user_id",
		"per_page":                   "1",
		"tenant_id":                  "tenant",
		"token_url":                  server.URL + "/oauth/token",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() first error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor is nil, want captured Auth0 checkpoint")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read() second error = %v", err)
	}
	if len(second.Events) != 0 || second.NextCursor != nil {
		t.Fatalf("second pull = %#v, want terminal empty page", second)
	}
	if len(requests) != 2 || requests[0].Get("from") != "" || requests[1].Get("from") != capturedPage.Next {
		t.Fatalf("requests = %#v, want initial request then from=%q", requests, capturedPage.Next)
	}
}

func capturedAuth0Bundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", auth0api.SourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedAuth0RequestPath(t *testing.T, bundle sourcefixture.Bundle) string {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed.EscapedPath()
}

func capturedAuth0PathSegment(t *testing.T, requestPath string, index int) string {
	t.Helper()
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	if index < 0 || index >= len(segments) {
		t.Fatalf("request path %q has no segment %d", requestPath, index)
	}
	value, err := url.PathUnescape(segments[index])
	if err != nil {
		t.Fatalf("unescape captured path segment: %v", err)
	}
	return value
}

func capturedAuth0Server(t *testing.T, requestPath string, bundle sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "replay-token", "expires_in": 600})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("unexpected Auth0 replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
}

func updateCapturedAuth0Fixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
