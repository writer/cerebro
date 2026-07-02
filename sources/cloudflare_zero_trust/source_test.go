package cloudflare_zero_trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			http.Error(w, "bad authorization", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/accounts/test-account_id/access/users" {
			t.Errorf("path = %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":         "user-1",
				"email":      "alice@example.com",
				"name":       "Alice Example",
				"last_seen":  "2026-06-01T00:00:00Z",
				"created_at": "2026-05-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "account_id": "test-account_id", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "cloudflare_zero_trust.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["tenant_id"]; got != "tenant" {
		t.Fatalf("tenant_id = %q, want tenant", got)
	}
}

func TestReadUsesCloudflareV4Pagination(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/account-1/access/users" {
			t.Errorf("path = %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("per_page"); got != "1" {
			t.Errorf("per_page = %q, want 1", got)
			http.Error(w, "bad per_page", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("limit"); got != "" {
			t.Errorf("limit = %q, want empty", got)
			http.Error(w, "bad limit", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("cursor"); got != "" {
			t.Errorf("cursor = %q, want empty", got)
			http.Error(w, "bad cursor", http.StatusBadRequest)
			return
		}
		requests = append(requests, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{{
					"id":    "user-1",
					"email": "alice@example.com",
					"name":  "Alice Example",
				}},
				"result_info": map[string]any{"page": 1, "total_pages": 2},
				"success":     true,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{{
					"id":    "user-2",
					"email": "bob@example.com",
					"name":  "Bob Example",
				}},
				"result_info": map[string]any{"page": 2, "total_pages": 2},
				"success":     true,
			})
		default:
			t.Errorf("page = %q, want empty or 2", r.URL.Query().Get("page"))
			http.Error(w, "bad page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	cfg := sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     familyUsers,
		"per_page":   "1",
		"tenant_id":  "writer",
		"token":      "token-1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("page") != "2" {
		t.Fatalf("requests = %#v, want second request with page=2", requests)
	}
}

func TestReadApplicationsDerivesRequiredAttributes(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/account-1/access/apps" {
			t.Errorf("path = %q, want /accounts/account-1/access/apps", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":               "access-app-1",
				"name":             "Admin Console",
				"domain":           "admin.example.com",
				"type":             "self_hosted",
				"aud":              "aud-access-app-1",
				"session_duration": "24h",
				"created_at":       "2026-05-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     familyApplications,
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for attr, want := range map[string]string{
		"resource_id":     "access-app-1",
		"resource_name":   "Admin Console",
		"resource_type":   "application",
		"resource_urn":    "urn:cerebro:tenant:cloudflare_zero_trust_applications:access-app-1",
		"source_event_id": "access-app-1",
	} {
		if got := attrs[attr]; got != want {
			t.Fatalf("%s = %q, want %q", attr, got, want)
		}
	}
	if got := attrs["observed_at"]; got != "" {
		t.Fatalf("observed_at = %q, want empty without provider observed/updated timestamp", got)
	}
}

func TestReadAccessFamiliesDeriveResourceAttributes(t *testing.T) {
	cases := []struct {
		name     string
		family   string
		path     string
		record   map[string]any
		wantType string
		wantID   string
		wantName string
		wantURN  string
	}{
		{
			name:   "users",
			family: familyUsers,
			path:   "/accounts/account-1/access/users",
			record: map[string]any{
				"id":         "access-user-1",
				"name":       "Alice Example",
				"email":      "alice@example.com",
				"type":       "person",
				"created_at": "2026-05-01T00:00:00Z",
			},
			wantType: "user",
			wantID:   "access-user-1",
			wantName: "Alice Example",
			wantURN:  "urn:cerebro:tenant:cloudflare_zero_trust_users:access-user-1",
		},
		{
			name:   "groups",
			family: familyGroups,
			path:   "/accounts/account-1/access/groups",
			record: map[string]any{
				"id":          "access-group-1",
				"name":        "Employees",
				"description": "Employees allowed through Access",
				"type":        "email_domain",
			},
			wantType: "group",
			wantID:   "access-group-1",
			wantName: "Employees",
			wantURN:  "urn:cerebro:tenant:cloudflare_zero_trust_groups:access-group-1",
		},
		{
			name:   "roles",
			family: familyRoles,
			path:   "/accounts/account-1/access/policies",
			record: map[string]any{
				"id":          "access-policy-1",
				"name":        "Require MFA",
				"type":        "allow",
				"decision":    "allow",
				"description": "Access policy requiring MFA group membership",
			},
			wantType: "access_policy",
			wantID:   "access-policy-1",
			wantName: "Require MFA",
			wantURN:  "urn:cerebro:tenant:cloudflare_zero_trust_roles:access-policy-1",
		},
		{
			name:   "audit_events",
			family: familyAuditEvents,
			path:   "/accounts/account-1/access/logs/access_requests",
			record: map[string]any{
				"id":         "access-request-1",
				"action":     "login",
				"status":     "approved",
				"user_id":    "access-user-1",
				"user_email": "alice@example.com",
				"app_id":     "access-app-1",
				"app_domain": "admin.example.com",
				"created_at": "2026-06-01T00:00:00Z",
			},
			wantType: "application",
			wantID:   "access-request-1",
			wantName: "admin.example.com",
			wantURN:  "urn:cerebro:tenant:cloudflare_zero_trust_audit_events:access-request-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Path; got != tc.path {
					t.Errorf("path = %q, want %q", got, tc.path)
					http.Error(w, "unexpected path", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"result":  []map[string]any{tc.record},
					"success": true,
				})
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"account_id": "account-1",
				"base_url":   server.URL,
				"family":     tc.family,
				"tenant_id":  "tenant",
				"token":      "test-token",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			attrs := pull.Events[0].Attributes
			for attr, want := range map[string]string{
				"resource_id":   tc.wantID,
				"resource_name": tc.wantName,
				"resource_type": tc.wantType,
				"resource_urn":  tc.wantURN,
				"tenant_id":     "tenant",
			} {
				if got := attrs[attr]; got != want {
					t.Fatalf("%s = %q, want %q", attr, got, want)
				}
			}
			if tc.family == familyAuditEvents {
				if got := attrs["event_type"]; got != "login" {
					t.Fatalf("event_type = %q, want action value", got)
				}
				if got := attrs["observed_at"]; got != "" {
					t.Fatalf("observed_at = %q, want empty without provider observed/updated timestamp", got)
				}
			}
		})
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyApplications, familyAuditEvents, familyGroups, familyRoles, familyUsers} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"account_id": "account-1",
			"family":     family,
			"tenant_id":  "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"message":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     familyUsers,
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "cloudflare_zero_trust API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}
