package onelogin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/oneloginapi"
)

func TestSourceCheckAndReadUsesOneLoginV2API(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	tokenRequests := 0
	userRequests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth2/v2/token" {
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s", r.Method)
			}
			clientID, clientSecret, ok := r.BasicAuth()
			if !ok || clientID != "client-id" || clientSecret != "client-secret" {
				t.Fatalf("BasicAuth = %q/%q/%t, want configured client credentials", clientID, clientSecret, ok)
			}
			var body struct {
				GrantType string `json:"grant_type"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
				t.Fatalf("decode token body: %v", err)
			}
			if body.GrantType != "client_credentials" {
				t.Fatalf("grant_type = %q", body.GrantType)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "bearer:test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/2/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		userRequests = append(userRequests, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cursor") {
		case "":
			if r.URL.Query().Get("limit") == "2" {
				w.Header().Set("After-Cursor", "cursor-2")
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":         "user-1",
				"email":      "user@example.test",
				"username":   "user@example.test",
				"name":       "User One",
				"updated_at": "2026-06-01T00:00:00Z",
			}})
		case "cursor-2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":         "user-2",
				"email":      "user-two@example.test",
				"username":   "user-two@example.test",
				"name":       "User Two",
				"updated_at": "2026-06-02T00:00:00Z",
			}})
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        defaultFamily,
		"token_url":     server.URL + "/auth/oauth2/v2/token",
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"per_page":      "2",
	})
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
	if pull.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("NextCursor = %q, want cursor-2", pull.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, pull.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["user_id"] != "user-2" {
		t.Fatalf("second Events = %#v, want user-2", second.Events)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1 cached token", tokenRequests)
	}
	event := pull.Events[0]
	if event.Kind != "onelogin.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if !containsRawQuery(userRequests, "limit=2") {
		t.Fatalf("user requests = %#v, want runtime read with limit=2", userRequests)
	}
	if !containsRawQuery(userRequests, "cursor=cursor-2") {
		t.Fatalf("user requests = %#v, want runtime read with cursor=cursor-2", userRequests)
	}
}

func TestSourceReadFansOutRoleUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	tokenRequests := 0
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth2/v2/token" {
			tokenRequests++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
			return
		}
		if r.Header.Get("Authorization") != "bearer:test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		requests = append(requests, r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.EscapedPath() {
		case "/api/2/roles/role-1/users":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "user-1", "email": "user@example.test", "name": "User One"}})
		case "/api/2/roles/role-2/users":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "user-2", "email": "user-two@example.test", "name": "User Two"}})
		default:
			t.Fatalf("unexpected path %q", r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        "role_users",
		"token_url":     server.URL + "/auth/oauth2/v2/token",
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"role_ids":      "role-1, role-2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.Events[0].Attributes["role_id"] != "role-1" {
		t.Fatalf("first Events = %#v, want role-1 membership", first.Events)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want fanout cursor for role-2")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["role_id"] != "role-2" {
		t.Fatalf("second Events = %#v, want role-2 membership", second.Events)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	wantRequests := []string{"/api/2/roles/role-1/users", "/api/2/roles/role-2/users"}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1 cached token", tokenRequests)
	}
}

func TestSourceProviderUnavailable(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth2/v2/token" {
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
			return
		}
		t.Fatalf("unexpected resource request %s", r.URL.Path)
	}))
	defer server.Close()

	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        defaultFamily,
		"token_url":     server.URL + "/auth/oauth2/v2/token",
		"client_id":     "client-id",
		"client_secret": "client-secret",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable error")
	}
	if !sourcecdk.IsHTTPStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("Check() error = %v, want HTTP 503", err)
	}
}

func TestPathParamValuesCoversScopedFamilies(t *testing.T) {
	cases := []struct {
		family    string
		configKey string
		wantParam string
	}{
		{family: oneloginapi.FamilyUserApps, configKey: "user_ids", wantParam: "user_id"},
		{family: oneloginapi.FamilyUserPrivileges, configKey: "user_ids", wantParam: "user_id"},
		{family: oneloginapi.FamilyDelegatedPrivileges, configKey: "user_ids", wantParam: "user_id"},
		{family: oneloginapi.FamilyMFADevices, configKey: "user_ids", wantParam: "user_id"},
		{family: oneloginapi.FamilyRoleUsers, configKey: "role_ids", wantParam: "role_id"},
		{family: oneloginapi.FamilyRoleAdmins, configKey: "role_ids", wantParam: "role_id"},
		{family: oneloginapi.FamilyRoleApps, configKey: "role_ids", wantParam: "role_id"},
		{family: oneloginapi.FamilyAppUsers, configKey: "app_ids", wantParam: "app_id"},
		{family: oneloginapi.FamilyAppRules, configKey: "app_ids", wantParam: "app_id"},
		{family: oneloginapi.FamilyPrivilegeUsers, configKey: "privilege_ids", wantParam: "privilege_id"},
		{family: oneloginapi.FamilyPrivilegeRoles, configKey: "privilege_ids", wantParam: "privilege_id"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{
				"family":     tc.family,
				tc.configKey: "first, second",
			})
			param, values := oneloginapi.PathParamValues(cfg)
			if param != tc.wantParam {
				t.Fatalf("param = %q, want %q", param, tc.wantParam)
			}
			if strings.Join(values, ",") != "first,second" {
				t.Fatalf("values = %#v, want first and second", values)
			}
		})
	}
	param, values := oneloginapi.PathParamValues(sourcecdk.NewConfig(map[string]string{"family": oneloginapi.FamilyUsers}))
	if param != "" || len(values) != 0 {
		t.Fatalf("users param/values = %q/%#v, want no scoped fanout", param, values)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range oneloginapi.FamilyNames() {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":        family,
			"tenant_id":     "tenant",
			"user_ids":      "user-1",
			"role_ids":      "role-1",
			"app_ids":       "app-1",
			"privilege_ids": "privilege-1",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func containsRawQuery(queries []string, want string) bool {
	for _, query := range queries {
		if strings.Contains(query, want) {
			return true
		}
	}
	return false
}
