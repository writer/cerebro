package tailscale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "tailscale" {
		t.Fatalf("Spec().Id = %q, want tailscale", got)
	}
}

func TestCatalogDeclaresVerifiedTailscaleProviderAPI(t *testing.T) {
	payload, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog struct {
		Description     string   `yaml:"description"`
		RuntimeFamilies []string `yaml:"runtime_families"`
		ProviderAPI     struct {
			Status     string   `yaml:"status"`
			Transport  string   `yaml:"transport"`
			Auth       string   `yaml:"auth"`
			BaseURL    string   `yaml:"base_url"`
			References []string `yaml:"references"`
			Families   []struct {
				ID     string `yaml:"id"`
				Method string `yaml:"method"`
				Path   string `yaml:"path"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	for _, text := range []string{"tailnet settings", "user inventory", "device inventory", "ACL groups", "tag ownership", "Services inventory", "policy grants"} {
		if !strings.Contains(catalog.Description, text) {
			t.Fatalf("description = %q, want source-specific text %q", catalog.Description, text)
		}
	}
	assertStringSet(t, catalog.RuntimeFamilies, []string{"device", "grant", "group", "service", "tag", "tailnet", "user"})
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "bearer_token" || catalog.ProviderAPI.BaseURL != "https://api.tailscale.com/api/v2" {
		t.Fatalf("provider_api = %#v, want verified REST bearer-token API", catalog.ProviderAPI)
	}
	for _, ref := range []string{
		"https://tailscale.com/docs/reference/tailscale-api",
		"https://tailscale.com/docs/reference/trust-credentials",
		"https://tailscale.com/docs/features/tailscale-services",
		"https://github.com/tailscale/tailscale/blob/b727675a8be8eb307420eb5e6cb8d7b902eb751b/internal/client/tailscale/vip_service.go",
	} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	wantPaths := map[string]string{
		"device":  "/tailnet/{tailnet}/devices",
		"grant":   "/tailnet/{tailnet}/acl",
		"group":   "/tailnet/{tailnet}/acl",
		"service": "/tailnet/{tailnet}/vip-services",
		"tag":     "/tailnet/{tailnet}/acl",
		"tailnet": "/tailnet/{tailnet}/settings",
		"user":    "/tailnet/{tailnet}/users",
	}
	gotPaths := map[string]string{}
	for _, family := range catalog.ProviderAPI.Families {
		if family.Method != http.MethodGet {
			t.Fatalf("provider family %s method = %q, want GET", family.ID, family.Method)
		}
		gotPaths[family.ID] = family.Path
	}
	for family, want := range wantPaths {
		if got := gotPaths[family]; got != want {
			t.Fatalf("provider path for %s = %q, want %q", family, got, want)
		}
	}
}

func TestReadTailscaleCoreInventoryKinds(t *testing.T) {
	aclResponse := map[string]any{
		"groups":    map[string]any{"group:eng": []string{"alice@writer.com", "bob@writer.com"}},
		"tagOwners": map[string]any{"tag:prod": []string{"group:eng"}},
		"grants":    []map[string]any{{"id": "grant-1", "src": []string{"group:eng"}, "dst": []string{"tag:prod:443"}, "disabled": false}},
	}
	for _, tt := range []struct {
		name     string
		family   string
		kind     string
		path     string
		response map[string]any
		want     map[string]string
	}{
		{
			name:     "tailnet",
			family:   "tailnet",
			kind:     "tailscale.tailnet",
			path:     "/tailnet/-/settings",
			response: map[string]any{"devicesApprovalOn": false, "usersApprovalOn": true, "networkFlowLoggingOn": true, "regionalRoutingOn": false, "maxKeyDurationDays": 90},
			want:     map[string]string{"tailnet": "writer.com", "devices_approval_on": "false", "users_approval_on": "true", "regional_routing_on": "false", "max_key_duration_days": "90"},
		},
		{
			name:     "user",
			family:   "user",
			kind:     "tailscale.user",
			path:     "/tailnet/-/users",
			response: map[string]any{"users": []map[string]any{{"id": "user-1", "loginName": "alice@writer.com", "role": "admin", "status": "active", "type": "member"}}},
			want:     map[string]string{"user_id": "user-1", "login_name": "alice@writer.com", "role": "admin", "type": "member"},
		},
		{
			name:     "device",
			family:   "device",
			kind:     "tailscale.device",
			path:     "/tailnet/-/devices",
			response: map[string]any{"devices": []map[string]any{{"id": "device-1", "nodeId": "node-1", "name": "laptop", "os": "macOS", "user": "alice@writer.com", "authorized": true, "keyExpiryDisabled": false, "tags": []string{"tag:prod"}}}},
			want:     map[string]string{"device_id": "device-1", "node_id": "node-1", "user_id": "alice@writer.com", "authorized": "true", "key_expiry_disabled": "false", "tags": "tag:prod"},
		},
		{
			name:     "service",
			family:   "service",
			kind:     "tailscale.service",
			path:     "/tailnet/-/vip-services",
			response: map[string]any{"vipServices": []map[string]any{{"name": "svc:api", "addrs": []string{"192.0.2.10", "fd7a:115c:a1e0::10"}, "ports": []string{"443"}, "tags": []string{"tag:prod"}, "comment": "Production API"}}},
			want:     map[string]string{"service_id": "svc:api", "name": "svc:api", "addresses": "192.0.2.10,fd7a:115c:a1e0::10", "ports": "443", "tags": "tag:prod", "comment": "Production API"},
		},
		{
			name:     "group",
			family:   "group",
			kind:     "tailscale.group",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"group_id": "group:eng", "members": "alice@writer.com,bob@writer.com"},
		},
		{
			name:     "tag",
			family:   "tag",
			kind:     "tailscale.tag",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"tag_id": "tag:prod", "owners": "group:eng"},
		},
		{
			name:     "grant",
			family:   "grant",
			kind:     "tailscale.grant",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"grant_id": "grant-1", "sources": "group:eng", "destinations": "tag:prod:443"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "tailnet": "writer.com", "token": "token-1"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    "user",
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "tailscale API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestNewFixtureReplaysTailscaleFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{"device", "grant", "group", "service", "tag", "tailnet", "user"} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestFixtureDiscoverURNsMatchReadResourceURNs(t *testing.T) {
	for _, family := range []string{"device", "grant", "group", "service", "tag", "tailnet", "user"} {
		t.Run(family, func(t *testing.T) {
			discoverPayload, err := fixtureFS.ReadFile("testdata/discover_" + family + ".json")
			if err != nil {
				t.Fatalf("read discover fixture: %v", err)
			}
			var discoverURNs []string
			if err := json.Unmarshal(discoverPayload, &discoverURNs); err != nil {
				t.Fatalf("unmarshal discover fixture: %v", err)
			}

			readPayload, err := fixtureFS.ReadFile("testdata/read_" + family + ".json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var readEvents []struct {
				Attributes map[string]string `json:"attributes"`
			}
			if err := json.Unmarshal(readPayload, &readEvents); err != nil {
				t.Fatalf("unmarshal read fixture: %v", err)
			}
			readURNs := make([]string, 0, len(readEvents))
			for _, event := range readEvents {
				urn := event.Attributes["resource_urn"]
				if urn == "" {
					t.Fatalf("read fixture event missing resource_urn: %#v", event.Attributes)
				}
				readURNs = append(readURNs, urn)
			}
			assertStringSet(t, discoverURNs, readURNs)
		})
	}
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("strings = %v, want %v", got, want)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestReadTailscaleTailnetSettingsFallsBackToTenantID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/tailnet/-/settings" {
			t.Fatalf("request path = %q, want /tailnet/-/settings", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"devicesApprovalOn": true,
			"usersApprovalOn":   false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	config := map[string]string{"base_url": server.URL, "family": "tailnet", "tenant_id": "writer", "token": "token-1"}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["tailnet"]; got != "writer" {
		t.Fatalf("tailnet = %q, want tenant_id fallback writer", got)
	}
	if got := pull.Events[0].Attributes["external_id"]; got != "writer" {
		t.Fatalf("external_id = %q, want tenant_id fallback writer", got)
	}
}
