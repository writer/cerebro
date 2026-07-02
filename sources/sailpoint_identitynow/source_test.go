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
