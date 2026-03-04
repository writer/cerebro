package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractOktaAdminID(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected string
	}{
		{
			name:     "user.id",
			input:    map[string]interface{}{"user": map[string]interface{}{"id": "user-1"}},
			expected: "user-1",
		},
		{
			name:     "assignee.id",
			input:    map[string]interface{}{"assignee": map[string]interface{}{"id": "user-2"}},
			expected: "user-2",
		},
		{
			name:     "user_id",
			input:    map[string]interface{}{"user_id": "user-3"},
			expected: "user-3",
		},
		{
			name:     "id",
			input:    map[string]interface{}{"id": "user-4"},
			expected: "user-4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOktaAdminID(tc.input); got != tc.expected {
				t.Errorf("extractOktaAdminID() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestExtractOktaPolicyAppIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected []string
	}{
		{
			name: "conditions.apps.include strings",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"apps": map[string]interface{}{
						"include": []interface{}{"app-1", "app-2"},
					},
				},
			},
			expected: []string{"app-1", "app-2"},
		},
		{
			name: "conditions.app.include objects",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"app": map[string]interface{}{
						"include": []interface{}{map[string]interface{}{"id": "app-3"}},
					},
				},
			},
			expected: []string{"app-3"},
		},
		{
			name: "conditions.apps.include string slice",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"apps": map[string]interface{}{
						"include": []string{"app-4", "app-5"},
					},
				},
			},
			expected: []string{"app-4", "app-5"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractOktaPolicyAppIDs(tc.input)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("extractOktaPolicyAppIDs() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestExtractOktaAppTarget(t *testing.T) {
	tests := []struct {
		name          string
		input         interface{}
		expectedID    string
		expectedLabel string
	}{
		{
			name: "target list with appinstance",
			input: []interface{}{
				map[string]interface{}{"type": "User", "id": "user-1"},
				map[string]interface{}{"type": "AppInstance", "id": "app-1", "display_name": "Salesforce"},
			},
			expectedID:    "app-1",
			expectedLabel: "Salesforce",
		},
		{
			name:          "single app object",
			input:         map[string]interface{}{"type": "application", "id": "app-2", "alternate_id": "jira"},
			expectedID:    "app-2",
			expectedLabel: "jira",
		},
		{
			name:          "unsupported target type",
			input:         []interface{}{map[string]interface{}{"type": "User", "id": "user-1"}},
			expectedID:    "",
			expectedLabel: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, label := extractOktaAppTarget(tc.input)
			if id != tc.expectedID || label != tc.expectedLabel {
				t.Fatalf("extractOktaAppTarget() = (%q, %q), want (%q, %q)", id, label, tc.expectedID, tc.expectedLabel)
			}
		})
	}
}

func TestNormalizeOktaLogExtractsTargetApp(t *testing.T) {
	log := map[string]interface{}{
		"uuid":      "evt-1",
		"eventType": "user.authentication.sso",
		"actor": map[string]interface{}{
			"id":   "user-1",
			"type": "User",
		},
		"target": []interface{}{
			map[string]interface{}{"type": "User", "id": "user-1"},
			map[string]interface{}{"type": "AppInstance", "id": "app-1", "displayName": "Salesforce"},
		},
	}

	normalized := normalizeOktaLog(log)
	if got := asString(normalized["target_app_id"]); got != "app-1" {
		t.Fatalf("target_app_id = %q, want app-1", got)
	}
	if got := asString(normalized["target_app_label"]); got != "Salesforce" {
		t.Fatalf("target_app_label = %q, want Salesforce", got)
	}
}

func TestOktaRequestWithResponse_RetryOn429(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	okta := &OktaProvider{
		apiToken: "token",
		client:   server.Client(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	body, _, err := okta.requestWithResponse(ctx, server.URL)
	if err != nil {
		t.Fatalf("requestWithResponse() error = %v", err)
	}
	if string(body) != "[]" {
		t.Fatalf("requestWithResponse() body = %q, want []", string(body))
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("requestWithResponse() calls = %d, want 2", got)
	}
}

func TestOktaSyncGroupMemberships(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/groups":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"id": "group-1"}})
		case "/api/v1/groups/group-1/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id": "user-1",
				"profile": map[string]interface{}{
					"login": "alice@example.com",
					"email": "alice@example.com",
				},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newTLSTestOktaProvider(t, server)
	table, err := provider.syncGroupMemberships(context.Background())
	if err != nil {
		t.Fatalf("syncGroupMemberships failed: %v", err)
	}
	if table.Rows != 1 {
		t.Fatalf("syncGroupMemberships rows = %d, want 1", table.Rows)
	}
	if table.Inserted != 1 {
		t.Fatalf("syncGroupMemberships inserted = %d, want 1", table.Inserted)
	}
}

func TestOktaSyncAppAssignments(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/apps":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":    "app-1",
				"label": "Admin Console",
			}})
		case "/api/v1/apps/app-1/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":      "user-1",
				"status":  "ACTIVE",
				"created": "2026-02-01T00:00:00Z",
			}})
		case "/api/v1/apps/app-1/groups":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":          "group-1",
				"status":      "ASSIGNED",
				"lastUpdated": "2026-02-02T00:00:00Z",
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newTLSTestOktaProvider(t, server)
	table, err := provider.syncAppAssignments(context.Background())
	if err != nil {
		t.Fatalf("syncAppAssignments failed: %v", err)
	}
	if table.Rows != 2 {
		t.Fatalf("syncAppAssignments rows = %d, want 2", table.Rows)
	}
	if table.Inserted != 2 {
		t.Fatalf("syncAppAssignments inserted = %d, want 2", table.Inserted)
	}
}

func TestOktaSyncAdminRoles(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/iam/assignees/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"user": map[string]interface{}{"id": "user-1"},
			}})
		case "/api/v1/users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id": "user-1",
				"profile": map[string]interface{}{
					"login": "alice@example.com",
				},
			}})
		case "/api/v1/users/user-1/roles":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"type":    "SUPER_ADMIN",
				"label":   "Super Admin",
				"status":  "ACTIVE",
				"created": "2026-02-03T00:00:00Z",
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newTLSTestOktaProvider(t, server)
	table, err := provider.syncAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("syncAdminRoles failed: %v", err)
	}
	if table.Rows != 1 {
		t.Fatalf("syncAdminRoles rows = %d, want 1", table.Rows)
	}
	if table.Inserted != 1 {
		t.Fatalf("syncAdminRoles inserted = %d, want 1", table.Inserted)
	}
}

func newTLSTestOktaProvider(t *testing.T, server *httptest.Server) *OktaProvider {
	t.Helper()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	provider := NewOktaProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"domain":    parsed.Host,
		"api_token": "token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	provider.client = server.Client()

	return provider
}
