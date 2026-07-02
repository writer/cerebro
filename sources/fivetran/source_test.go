package fivetran

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/fivetranapi"
)

func TestSourceCheckAndReadUsers(t *testing.T) {
	source := newTestSource(t)
	requests := []*http.Request{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		requireFivetranHeaders(t, r, "application/json")
		switch r.URL.Path {
		case "/v1/account/info":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/users":
			if got := r.URL.Query().Get("limit"); got != "1" && got != "2" {
				t.Fatalf("limit = %q, want 1 for check or 2 for read", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    "Success",
				"message": "Users retrieved successfully",
				"data": map[string]any{
					"items": []map[string]any{{
						"id":         "user-1",
						"email":      "user@example.test",
						"name":       "User One",
						"created_at": "2026-06-01T00:00:00Z",
					}},
					"next_cursor": "cursor-2",
				},
			})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := fivetranConfig(server.URL, map[string]string{"family": fivetranapi.FamilyUsers, "per_page": "2"})
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
	if event.Kind != "fivetran.users" {
		t.Fatalf("kind = %q, want fivetran.users", event.Kind)
	}
	if event.Attributes["user_id"] != "user-1" || event.Attributes["email"] != "user@example.test" || event.Attributes["tenant_id"] != "tenant" {
		t.Fatalf("attributes = %#v, want user identity attributes", event.Attributes)
	}
	if pull.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("NextCursor = %q, want cursor-2", pull.NextCursor.GetOpaque())
	}
	if len(requests) < 3 {
		t.Fatalf("requests = %d, want health, check, and read", len(requests))
	}
}

func TestSourceReadsProviderFamilies(t *testing.T) {
	tests := []struct {
		name       string
		family     string
		path       string
		accept     string
		item       map[string]any
		kind       string
		attrKey    string
		attrValue  string
		config     map[string]string
		queryKey   string
		queryValue string
	}{
		{
			name:      "users",
			family:    fivetranapi.FamilyUsers,
			path:      "/v1/users",
			accept:    "application/json",
			item:      map[string]any{"id": "user-1", "email": "user@example.test", "name": "User One"},
			kind:      "fivetran.users",
			attrKey:   "user_id",
			attrValue: "user-1",
		},
		{
			name:      "roles",
			family:    fivetranapi.FamilyRoles,
			path:      "/v1/roles",
			accept:    "application/json",
			item:      map[string]any{"id": "role-1", "name": "Account Reviewer", "scope": "account"},
			kind:      "fivetran.roles",
			attrKey:   "role_id",
			attrValue: "role-1",
		},
		{
			name:      "teams",
			family:    fivetranapi.FamilyTeams,
			path:      "/v1/teams",
			accept:    "application/json",
			item:      map[string]any{"id": "team-1", "name": "Analytics"},
			kind:      "fivetran.teams",
			attrKey:   "team_id",
			attrValue: "team-1",
		},
		{
			name:      "groups",
			family:    fivetranapi.FamilyGroups,
			path:      "/v1/groups",
			accept:    "application/json",
			item:      map[string]any{"id": "group-1", "name": "Warehouse"},
			kind:      "fivetran.groups",
			attrKey:   "group_id",
			attrValue: "group-1",
		},
		{
			name:      "destinations",
			family:    fivetranapi.FamilyDestinations,
			path:      "/v1/destinations",
			accept:    "application/json;version=2",
			item:      map[string]any{"id": "destination-1", "service": "snowflake", "region": "AWS_US_EAST_1"},
			kind:      "fivetran.destinations",
			attrKey:   "resource_id",
			attrValue: "destination-1",
		},
		{
			name:      "connections",
			family:    fivetranapi.FamilyConnections,
			path:      "/v1/connections",
			accept:    "application/json;version=2",
			item:      map[string]any{"id": "connection-1", "service": "postgres", "schema": "prod", "group_id": "group-1"},
			kind:      "fivetran.connections",
			attrKey:   "resource_id",
			attrValue: "connection-1",
		},
		{
			name:      "log services",
			family:    fivetranapi.FamilyLogServices,
			path:      "/v1/external-logging",
			accept:    "application/json",
			item:      map[string]any{"id": "log-1", "service": "splunk", "enabled": true},
			kind:      "fivetran.log_services",
			attrKey:   "resource_id",
			attrValue: "log-1",
		},
		{
			name:      "webhooks",
			family:    fivetranapi.FamilyWebhooks,
			path:      "/v1/webhooks",
			accept:    "application/json",
			item:      map[string]any{"id": "webhook-1", "url": "https://hooks.example.test/fivetran", "active": true},
			kind:      "fivetran.webhooks",
			attrKey:   "resource_id",
			attrValue: "webhook-1",
		},
		{
			name:      "private links",
			family:    fivetranapi.FamilyPrivateLinks,
			path:      "/v1/private-links",
			accept:    "application/json",
			item:      map[string]any{"id": "plink-1", "name": "warehouse-link", "state": "CONNECTED"},
			kind:      "fivetran.private_links",
			attrKey:   "resource_id",
			attrValue: "plink-1",
		},
		{
			name:      "proxy agents",
			family:    fivetranapi.FamilyProxyAgents,
			path:      "/v1/proxy",
			accept:    "application/json",
			item:      map[string]any{"id": "proxy-1", "name": "proxy-east", "status": "active"},
			kind:      "fivetran.proxy_agents",
			attrKey:   "resource_id",
			attrValue: "proxy-1",
		},
		{
			name:      "hybrid deployment agents",
			family:    fivetranapi.FamilyHybridAgents,
			path:      "/v1/hybrid-deployment-agents",
			accept:    "application/json",
			item:      map[string]any{"id": "hybrid-1", "name": "agent-east", "status": "active"},
			kind:      "fivetran.hybrid_deployment_agents",
			attrKey:   "resource_id",
			attrValue: "hybrid-1",
		},
		{
			name:      "connector metadata",
			family:    fivetranapi.FamilyConnectorMetadata,
			path:      "/v1/metadata/connector-types",
			accept:    "application/json",
			item:      map[string]any{"id": "postgres", "service": "postgres", "name": "PostgreSQL"},
			kind:      "fivetran.connector_metadata",
			attrKey:   "resource_id",
			attrValue: "postgres",
		},
		{
			name:      "system keys",
			family:    fivetranapi.FamilySystemKeys,
			path:      "/v1/system-keys",
			accept:    "application/json",
			item:      map[string]any{"id": "system-key-1", "name": "automation-key", "key": "public-material", "secret": "secret-material", "created_at": "2026-06-01T00:00:00Z"},
			kind:      "fivetran.system_keys",
			attrKey:   "resource_id",
			attrValue: "system-key-1",
		},
		{
			name:      "transformations",
			family:    fivetranapi.FamilyTransformations,
			path:      "/v1/transformations",
			accept:    "application/json",
			item:      map[string]any{"id": "transformation-1", "name": "dbt hourly", "status": "enabled"},
			kind:      "fivetran.transformations",
			attrKey:   "resource_id",
			attrValue: "transformation-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newTestSource(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireFivetranHeaders(t, r, tt.accept)
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %s", r.URL.Path, tt.path)
				}
				if got := r.URL.Query().Get("limit"); got != "2" {
					t.Fatalf("limit = %q, want 2", got)
				}
				if tt.queryKey != "" && r.URL.Query().Get(tt.queryKey) != tt.queryValue {
					t.Fatalf("%s query = %q, want %q", tt.queryKey, r.URL.Query().Get(tt.queryKey), tt.queryValue)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(fivetranList(tt.item, ""))
			}))
			defer server.Close()

			cfgValues := map[string]string{"family": tt.family, "per_page": "2"}
			for key, value := range tt.config {
				cfgValues[key] = value
			}
			pull, err := source.Read(context.Background(), fivetranConfig(server.URL, cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %s", event.Kind, tt.kind)
			}
			if event.Attributes[tt.attrKey] != tt.attrValue {
				t.Fatalf("%s = %q, want %q in %#v", tt.attrKey, event.Attributes[tt.attrKey], tt.attrValue, event.Attributes)
			}
			if event.Attributes["tenant_id"] != "tenant" {
				t.Fatalf("tenant_id = %q, want tenant", event.Attributes["tenant_id"])
			}
			if tt.family == fivetranapi.FamilySystemKeys {
				var payload map[string]any
				if err := json.Unmarshal(event.Payload, &payload); err != nil {
					t.Fatalf("decode system key payload: %v", err)
				}
				if _, ok := payload["key"]; ok {
					t.Fatalf("system key payload retained key: %#v", payload)
				}
				if _, ok := payload["secret"]; ok {
					t.Fatalf("system key payload retained secret: %#v", payload)
				}
			}
		})
	}
}

func TestSourceReadsScopedMembershipsWithFanout(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		if r.URL.Path != "/v1/groups/group-1/users" {
			t.Fatalf("path = %q, want /v1/groups/group-1/users", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
			"id":    "user-1",
			"email": "user@example.test",
			"role":  "Destination Reviewer",
		}, ""))
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), fivetranConfig(server.URL, map[string]string{
		"family":    fivetranapi.FamilyGroupUsers,
		"group_ids": "group-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["group_id"] != "group-1" || attrs["member_id"] != "user-1" || attrs["member_type"] != "user" || attrs["role"] != "Destination Reviewer" || attrs["email"] != "user@example.test" {
		t.Fatalf("attributes = %#v, want scoped membership", attrs)
	}
}

func TestSourceDiscoverScopedMembershipsRequiresIDs(t *testing.T) {
	source := newTestSource(t)
	_, err := source.Discover(context.Background(), fivetranConfig("https://api.fivetran.com", map[string]string{
		"family": fivetranapi.FamilyGroupUsers,
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Discover() error = %v, want invalid config", err)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		http.Error(w, `{"code":"ServiceUnavailable","message":"provider unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := source.Read(context.Background(), fivetranConfig(server.URL, map[string]string{
		"family": fivetranapi.FamilyUsers,
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "fivetran API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		fivetranapi.FamilyUsers,
		fivetranapi.FamilyUserConnections,
		fivetranapi.FamilyUserGroups,
		fivetranapi.FamilyRoles,
		fivetranapi.FamilyTeams,
		fivetranapi.FamilyTeamUsers,
		fivetranapi.FamilyTeamConnections,
		fivetranapi.FamilyTeamGroups,
		fivetranapi.FamilyGroups,
		fivetranapi.FamilyGroupUsers,
		fivetranapi.FamilyGroupConnections,
		fivetranapi.FamilyDestinations,
		fivetranapi.FamilyConnections,
		fivetranapi.FamilyConnectionCertificates,
		fivetranapi.FamilyConnectionFingerprints,
		fivetranapi.FamilyLogServices,
		fivetranapi.FamilyWebhooks,
		fivetranapi.FamilyPrivateLinks,
		fivetranapi.FamilyProxyAgents,
		fivetranapi.FamilyHybridAgents,
		fivetranapi.FamilyConnectorMetadata,
		fivetranapi.FamilySystemKeys,
		fivetranapi.FamilyTransformations,
	} {
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

func newTestSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func fivetranConfig(baseURL string, values map[string]string) sourcecdk.Config {
	cfg := map[string]string{
		"tenant_id": "tenant",
		"base_url":  baseURL,
		"username":  "api-key",
		"password":  "api-secret",
	}
	for key, value := range values {
		cfg[key] = value
	}
	return sourcecdk.NewConfig(cfg)
}

func requireFivetranHeaders(t *testing.T, r *http.Request, accept string) {
	t.Helper()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("api-key:api-secret"))
	if got := r.Header.Get("Authorization"); got != wantAuth {
		t.Fatalf("Authorization = %q, want %q", got, wantAuth)
	}
	if got := r.Header.Get("Accept"); got != accept {
		t.Fatalf("Accept = %q, want %q", got, accept)
	}
}

func fivetranList(item map[string]any, nextCursor string) map[string]any {
	data := map[string]any{"items": []map[string]any{item}}
	if strings.TrimSpace(nextCursor) != "" {
		data["next_cursor"] = nextCursor
	}
	return map[string]any{"code": "Success", "data": data}
}
