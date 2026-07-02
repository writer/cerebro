package sailpoint_identitynow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/sailpointapi"
)

func TestSourceCheckAndReadUsesOAuthAndOffsetPaging(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	var tokenRequests int
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenRequests++
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Fatalf("grant_type = %q", got)
			}
			if got := r.Form.Get("client_id"); got != "client-1" {
				t.Fatalf("client_id = %q", got)
			}
			if got := r.Form.Get("client_secret"); got != "secret-1" {
				t.Fatalf("client_secret = %q", got)
			}
			if got := r.Form.Get("scope"); got != "sp:scopes:all" {
				t.Fatalf("scope = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.URL.Path != "/v2025/identities" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		offsets = append(offsets, r.URL.Query().Get("offset"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("offset") == "1" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":             "2c91808568c529c60168cca6f90c1001",
			"name":           "Morgan Alvarez",
			"emailAddress":   "morgan.alvarez@example.com",
			"identityStatus": "ACTIVE",
			"created":        "2026-05-01T10:00:00Z",
			"modified":       "2026-06-15T16:20:00Z",
			"attributes": map[string]any{
				"department": "Engineering",
				"title":      "Platform Engineer",
			},
		}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"tenant":        "acme",
		"base_url":      server.URL + "/v2025",
		"token_url":     server.URL + "/oauth/token",
		"client_id":     "client-1",
		"client_secret": "secret-1",
		"family":        sailpointapi.FamilyIdentities,
		"per_page":      "1",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(first.Events))
	}
	if first.Events[0].Kind != "sailpoint_identitynow.identities" {
		t.Fatalf("kind = %q", first.Events[0].Kind)
	}
	if got := first.Events[0].Attributes["email"]; got != "morgan.alvarez@example.com" {
		t.Fatalf("email attribute = %q", got)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "1" {
		t.Fatalf("NextCursor = %#v, want offset 1", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 0 || second.NextCursor != nil {
		t.Fatalf("second page events/cursor = %d/%#v, want empty terminal page", len(second.Events), second.NextCursor)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want cached single exchange", tokenRequests)
	}
	if !containsString(offsets, "1") {
		t.Fatalf("offsets = %v, want offset 1 request", offsets)
	}
}

func TestSourceAccessRequestStatusEmitsAuditProjectionAttributes(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.URL.Path != "/v2025/access-request-status" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":              "request-item-1",
			"accessRequestId": "access-request-1",
			"name":            "Payroll access",
			"requestType":     "GRANT_ACCESS",
			"state":           "EXECUTED",
			"requester": map[string]string{
				"id":   "requester-1",
				"name": "Request Owner",
			},
			"requestedFor": map[string]string{
				"id":   "identity-1",
				"name": "Jane Access",
			},
			"modified": "2026-06-20T12:00:00Z",
		}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyAccessRequestStatus,
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for key, want := range map[string]string{
		"actor_id":      "requester-1",
		"actor_name":    "Request Owner",
		"resource_id":   "identity-1",
		"resource_name": "Jane Access",
		"resource_type": "user",
		"event_type":    "EXECUTED",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("%s = %q, want %q in %#v", key, got, want, attrs)
		}
	}
}

func TestSourceFanoutReadsRoleAssignedIdentities(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v2025/roles/role-a/assigned-identities":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "identity-a", "name": "Morgan Alvarez", "email": "morgan.alvarez@example.com"}})
		case "/v2025/roles/role-b/assigned-identities":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "identity-b", "name": "Riley Chen", "email": "riley.chen@example.com"}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"tenant":        "acme",
		"base_url":      server.URL + "/v2025",
		"token_url":     server.URL + "/oauth/token",
		"client_id":     "client-1",
		"client_secret": "secret-1",
		"family":        sailpointapi.FamilyRoleAssignedIdentities,
		"role_ids":      "role-a,role-b",
		"per_page":      "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(first.Events))
	}
	if got := first.Events[0].Attributes["role_id"]; got != "role-a" {
		t.Fatalf("role_id = %q, want role-a", got)
	}
	if got := first.Events[0].Attributes["subject_type"]; got != "user" {
		t.Fatalf("subject_type = %q, want user", got)
	}
	if got := first.Events[0].Attributes["role_name"]; got != "" {
		t.Fatalf("role_name = %q, want empty because scoped endpoint does not return the parent role name", got)
	}
	if first.NextCursor == nil {
		t.Fatal("expected fanout cursor for second role")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["role_id"]; got != "role-b" {
		t.Fatalf("second role_id = %q, want role-b", got)
	}
	if got := second.Events[0].Attributes["role_name"]; got != "" {
		t.Fatalf("second role_name = %q, want empty because scoped endpoint does not return the parent role name", got)
	}
}

func TestSourceCheckFanoutFamilyUsesHealthProbeBeforeScopedCheck(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v2025/identities", "/v2025/roles/role-a/assigned-identities":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoleAssignedIdentities,
		"role_ids":  "role-a,role-b",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := sourcecdk.ConfigValue(cfg, "family"); got != sailpointapi.FamilyRoleAssignedIdentities {
		t.Fatalf("original family = %q, want scoped family unchanged", got)
	}
	if len(paths) != 2 || paths[0] != "/v2025/identities" || paths[1] != "/v2025/roles/role-a/assigned-identities" {
		t.Fatalf("paths = %v, want health probe followed by scoped family check", paths)
	}
}

func TestSourceFanoutDiscoversSourceSchedulesPerSource(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v2025/sources/source-a/schedules", "/v2025/sources/source-b/schedules":
			_ = json.NewEncoder(w).Encode([]map[string]string{{
				"type":           "ACCOUNT_AGGREGATION",
				"cronExpression": "0 0 2 * * ?",
			}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "tenant",
		"base_url":   server.URL + "/v2025",
		"token":      "test-token",
		"family":     sailpointapi.FamilySourceSchedules,
		"source_ids": "source-a,source-b",
	})
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 2 {
		t.Fatalf("URNs = %#v, want one schedule per source", urns)
	}
	if urns[0] == urns[1] {
		t.Fatalf("URNs collapsed schedules across sources: %#v", urns)
	}
}

func TestSourceRejectsMissingFanoutIDsBeforeProviderCalls(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  "https://acme.api.identitynow.com/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoleAssignedIdentities,
	})
	if err := source.Check(context.Background(), cfg); !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
	if _, err := source.Discover(context.Background(), cfg); !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Discover() error = %v, want ErrInvalidConfig", err)
	}
	if _, err := source.Read(context.Background(), cfg, nil); !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Read() error = %v, want ErrInvalidConfig", err)
	}
	if _, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil); !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("ReadWithCheckpoint() error = %v, want ErrInvalidConfig", err)
	}
}

func TestSourceRejectsTokenFallbackTenantHostInjection(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"tenant":    "evil.com/",
		"token":     "test-token",
		"family":    sailpointapi.FamilyIdentities,
	})
	if err := source.Check(context.Background(), cfg); !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
}

func TestSourceAcceptsManagedFedRAMPBaseURLHost(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  "https://acme.api.identitynow-fed.com/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyIdentities,
	})
	if _, err := source.runtimeConfig(context.Background(), cfg); err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	tokenURL, err := managedOAuthTokenURLForBaseURL(sourcecdk.ConfigValue(cfg, "base_url"))
	if err != nil {
		t.Fatalf("managedOAuthTokenURLForBaseURL() error = %v", err)
	}
	if want := "https://acme.api.identitynow-fed.com/oauth/token"; tokenURL != want {
		t.Fatalf("token URL = %q, want %q", tokenURL, want)
	}
}

func TestSourceUsesFamilyDefaultPageSizeAndHonorsOverride(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	var limits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.URL.Path != "/v2025/roles" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		limits = append(limits, r.URL.Query().Get("limit"))
		if got := r.URL.Query().Get("offset"); got != "0" {
			t.Fatalf("offset = %q, want 0", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoles,
	})
	if _, err := source.Read(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Read(default) error = %v", err)
	}
	override := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoles,
		"per_page":  "7",
	})
	if _, err := source.Read(context.Background(), override, nil); err != nil {
		t.Fatalf("Read(override) error = %v", err)
	}
	if len(limits) != 2 || limits[0] != "50" || limits[1] != "7" {
		t.Fatalf("limits = %v, want [50 7]", limits)
	}
}

func TestSourceCheckKeepsSmallProbeForDefaultPageSizeFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	var roleLimits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v2025/identities":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/v2025/roles":
			roleLimits = append(roleLimits, r.URL.Query().Get("limit"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoles,
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(roleLimits) != 1 || roleLimits[0] != "1" {
		t.Fatalf("role limits = %v, want [1]", roleLimits)
	}
}

func TestSourceRolesEmitStaticPolicyAttributes(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.URL.Path != "/v2025/roles" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":      "role-1",
			"name":    "Access Reviewer",
			"enabled": true,
		}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyRoles,
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["policy_type"]; got != "role" {
		t.Fatalf("policy_type = %q, want role", got)
	}
	if got := pull.Events[0].Attributes["role_type"]; got != "role" {
		t.Fatalf("role_type = %q, want role", got)
	}
}

func TestSourcePersonalAccessTokensUsesOffsetPagination(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	var offsets []string
	var limits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.URL.Path != "/v2025/personal-access-tokens" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		offsets = append(offsets, r.URL.Query().Get("offset"))
		limits = append(limits, r.URL.Query().Get("limit"))
		records := make([]map[string]any, 50)
		for i := range records {
			records[i] = map[string]any{
				"id":   fmt.Sprintf("pat-%02d", i),
				"name": fmt.Sprintf("Token %02d", i),
				"owner": map[string]string{
					"id":   "identity-1",
					"name": "Jane Access",
				},
			}
		}
		_ = json.NewEncoder(w).Encode(records)
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL + "/v2025",
		"token":     "test-token",
		"family":    sailpointapi.FamilyPersonalAccessTokens,
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(first.Events) != 50 {
		t.Fatalf("events = %d, want 50", len(first.Events))
	}
	if got := first.Events[0].Attributes["credential_type"]; got != "personal_access_token" {
		t.Fatalf("credential_type = %q, want personal_access_token", got)
	}
	if got := first.Events[0].Attributes["subject_type"]; got != "user" {
		t.Fatalf("subject_type = %q, want user", got)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "50" {
		t.Fatalf("NextCursor = %#v, want offset 50", first.NextCursor)
	}
	if len(offsets) != 1 || offsets[0] != "0" || len(limits) != 1 || limits[0] != "50" {
		t.Fatalf("offsets/limits = %v/%v, want [0]/[50]", offsets, limits)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	fixture, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range sailpointapi.FamilyNames() {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"tenant_id": "tenant",
			"family":    family,
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          fixture,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
		MaxPages:        2,
	})
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
