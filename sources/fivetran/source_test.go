package fivetran

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
				"id":         "user-1",
				"email":      "user@example.test",
				"name":       "User One",
				"created_at": "2026-06-01T00:00:00Z",
			}, "cursor-2"))
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
		name                 string
		family               string
		path                 string
		accept               string
		item                 map[string]any
		kind                 string
		attrKey              string
		attrValue            string
		config               map[string]string
		queryKey             string
		queryValue           string
		singleton            bool
		wantLimit            string
		wantScopedResourceID bool
	}{
		{
			name:      "account info",
			family:    fivetranapi.FamilyAccountInfo,
			path:      "/v1/account/info",
			accept:    "application/json",
			item:      map[string]any{"account_id": "account-1", "account_name": "Primary account"},
			kind:      "fivetran.account_info",
			attrKey:   "resource_id",
			attrValue: "account-1",
			singleton: true,
			wantLimit: "none",
		},
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
			name:      "group public keys",
			family:    fivetranapi.FamilyGroupPublicKeys,
			path:      "/v1/groups/group-1/public-key",
			accept:    "application/json",
			item:      map[string]any{"public_key": "ssh-rsa-test"},
			kind:      "fivetran.group_public_keys",
			attrKey:   "credential_id",
			attrValue: "ssh-rsa-test",
			config:    map[string]string{"group_ids": "group-1"},
			singleton: true,
			wantLimit: "none",
		},
		{
			name:      "group service accounts",
			family:    fivetranapi.FamilyGroupServiceAccounts,
			path:      "/v1/groups/group-1/service-account",
			accept:    "application/json",
			item:      map[string]any{"service_account": "svc-account"},
			kind:      "fivetran.group_service_accounts",
			attrKey:   "credential_id",
			attrValue: "group-1",
			config:    map[string]string{"group_ids": "group-1"},
			singleton: true,
			wantLimit: "none",
		},
		{
			name:      "destinations",
			family:    fivetranapi.FamilyDestinations,
			path:      "/v1/destinations",
			accept:    "application/json;version=2",
			item:      map[string]any{"id": "destination-1", "service": "snowflake", "region": "AWS_US_EAST_1", "config": map[string]any{"host": "warehouse.example"}},
			kind:      "fivetran.destinations",
			attrKey:   "resource_id",
			attrValue: "destination-1",
		},
		{
			name:      "connections",
			family:    fivetranapi.FamilyConnections,
			path:      "/v1/connections",
			accept:    "application/json;version=2",
			item:      map[string]any{"id": "connection-1", "service": "postgres", "schema": "prod", "group_id": "group-1", "config": map[string]any{"host": "source.example"}},
			kind:      "fivetran.connections",
			attrKey:   "resource_id",
			attrValue: "connection-1",
		},
		{
			name:      "connection certificates",
			family:    fivetranapi.FamilyConnectionCertificates,
			path:      "/v1/connections/connection-1/certificates",
			accept:    "application/json",
			item:      map[string]any{"id": "cert-1", "name": "Warehouse TLS certificate", "hash": "sha256:8f7f3d2c"},
			kind:      "fivetran.connection_certificates",
			attrKey:   "credential_id",
			attrValue: "cert-1",
			config:    map[string]string{"connection_ids": "connection-1"},
		},
		{
			name:      "connection fingerprints",
			family:    fivetranapi.FamilyConnectionFingerprints,
			path:      "/v1/connections/connection-1/fingerprints",
			accept:    "application/json",
			item:      map[string]any{"id": "fingerprint-1", "hash": "sha256:78a9"},
			kind:      "fivetran.connection_fingerprints",
			attrKey:   "credential_id",
			attrValue: "fingerprint-1",
			config:    map[string]string{"connection_ids": "connection-1"},
		},
		{
			name:      "connection schemas",
			family:    fivetranapi.FamilyConnectionSchemas,
			path:      "/v1/connections/connection-1/schemas",
			accept:    "application/json",
			item:      map[string]any{"schema_change_handling": "ALLOW_ALL"},
			kind:      "fivetran.connection_schemas",
			attrKey:   "connection_id",
			attrValue: "connection-1",
			config:    map[string]string{"connection_ids": "connection-1"},
			singleton: true,
			wantLimit: "none",
		},
		{
			name:      "connection state",
			family:    fivetranapi.FamilyConnectionState,
			path:      "/v1/connections/connection-1/state",
			accept:    "application/json",
			item:      map[string]any{"status": "connected"},
			kind:      "fivetran.connection_state",
			attrKey:   "connection_id",
			attrValue: "connection-1",
			config:    map[string]string{"connection_ids": "connection-1"},
			singleton: true,
			wantLimit: "none",
		},
		{
			name:      "connector sdk packages",
			family:    fivetranapi.FamilyConnectorSDKPackages,
			path:      "/v1/connector-sdk/packages",
			accept:    "application/json",
			item:      map[string]any{"id": "package-1", "name": "custom connector package", "status": "ready"},
			kind:      "fivetran.connector_sdk_packages",
			attrKey:   "resource_id",
			attrValue: "package-1",
		},
		{
			name:      "destination certificates",
			family:    fivetranapi.FamilyDestinationCertificates,
			path:      "/v1/destinations/destination-1/certificates",
			accept:    "application/json",
			item:      map[string]any{"id": "dest-cert-1", "name": "Destination TLS certificate", "hash": "sha256:1234"},
			kind:      "fivetran.destination_certificates",
			attrKey:   "credential_id",
			attrValue: "dest-cert-1",
			config:    map[string]string{"destination_ids": "destination-1"},
		},
		{
			name:      "destination fingerprints",
			family:    fivetranapi.FamilyDestinationFingerprints,
			path:      "/v1/destinations/destination-1/fingerprints",
			accept:    "application/json",
			item:      map[string]any{"id": "dest-fingerprint-1", "hash": "sha256:5678"},
			kind:      "fivetran.destination_fingerprints",
			attrKey:   "credential_id",
			attrValue: "dest-fingerprint-1",
			config:    map[string]string{"destination_ids": "destination-1"},
		},
		{
			name:      "account log service",
			family:    fivetranapi.FamilyAccountLogService,
			path:      "/v1/external-logging/account",
			accept:    "application/json",
			item:      map[string]any{"id": "log-1", "service": "datadog_log", "enabled": true, "config": map[string]any{"api_key": "datadog-secret"}},
			kind:      "fivetran.account_log_service",
			attrKey:   "resource_id",
			attrValue: "log-1",
			singleton: true,
			wantLimit: "none",
		},
		{
			name:      "log services",
			family:    fivetranapi.FamilyLogServices,
			path:      "/v1/external-logging",
			accept:    "application/json",
			item:      map[string]any{"id": "log-1", "service": "splunk", "enabled": true, "config": map[string]any{"hec_token": "splunk-secret"}},
			kind:      "fivetran.log_services",
			attrKey:   "resource_id",
			attrValue: "log-1",
		},
		{
			name:      "webhooks",
			family:    fivetranapi.FamilyWebhooks,
			path:      "/v1/webhooks",
			accept:    "application/json",
			item:      map[string]any{"id": "webhook-1", "url": "https://hooks.example.test/fivetran", "active": true, "signing_key": "webhook-signing-material"},
			kind:      "fivetran.webhooks",
			attrKey:   "resource_id",
			attrValue: "webhook-1",
		},
		{
			name:      "external secret managers",
			family:    fivetranapi.FamilyExternalSecretManagers,
			path:      "/v1/external-secrets-managers",
			accept:    "application/json",
			item:      map[string]any{"id": "esm-1", "name": "Vault production", "status": "connected"},
			kind:      "fivetran.external_secret_managers",
			attrKey:   "resource_id",
			attrValue: "esm-1",
		},
		{
			name:      "external secret manager entities",
			family:    fivetranapi.FamilyExternalSecretManagerEntities,
			path:      "/v1/external-secrets-managers-entities",
			accept:    "application/json",
			item:      map[string]any{"id": "esm-entity-1", "name": "Salesforce connection", "secret_manager_id": "esm-1"},
			kind:      "fivetran.external_secret_manager_entities",
			attrKey:   "resource_id",
			attrValue: "esm-entity-1",
		},
		{
			name:      "external secret manager assignments",
			family:    fivetranapi.FamilyExternalSecretManagerAssignments,
			path:      "/v1/external-secrets-managers/esm-1/entities",
			accept:    "application/json",
			item:      map[string]any{"id": "connection-1", "name": "Salesforce connection"},
			kind:      "fivetran.external_secret_manager_assignments",
			attrKey:   "external_secret_manager_id",
			attrValue: "esm-1",
			config:    map[string]string{"external_secret_manager_ids": "esm-1"},
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
			name:      "proxy agent connections",
			family:    fivetranapi.FamilyProxyAgentConnections,
			path:      "/v1/proxy/proxy-1/connections",
			accept:    "application/json",
			item:      map[string]any{"id": "connection-1", "name": "Salesforce connection"},
			kind:      "fivetran.proxy_agent_connections",
			attrKey:   "proxy_agent_id",
			attrValue: "proxy-1",
			config:    map[string]string{"proxy_agent_ids": "proxy-1"},
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
			name:      "public connector types",
			family:    fivetranapi.FamilyPublicConnectorTypes,
			path:      "/public/connector-types",
			accept:    "application/json",
			item:      map[string]any{"id": "postgres", "service": "postgres", "name": "PostgreSQL"},
			kind:      "fivetran.public_connector_types",
			attrKey:   "resource_id",
			attrValue: "postgres",
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
			name:                 "connector metadata details",
			family:               fivetranapi.FamilyConnectorMetadataDetails,
			path:                 "/v1/metadata/connector-types/postgres",
			accept:               "application/json",
			item:                 map[string]any{"id": "postgres", "name": "PostgreSQL", "service_status": "general_availability"},
			kind:                 "fivetran.connector_metadata_details",
			attrKey:              "resource_id",
			attrValue:            "postgres",
			config:               map[string]string{"services": "postgres"},
			singleton:            true,
			wantLimit:            "none",
			wantScopedResourceID: true,
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
		{
			name:      "transformation projects",
			family:    fivetranapi.FamilyTransformationProjects,
			path:      "/v1/transformation-projects",
			accept:    "application/json",
			item:      map[string]any{"id": "project-1", "name": "dbt production"},
			kind:      "fivetran.transformation_projects",
			attrKey:   "resource_id",
			attrValue: "project-1",
		},
		{
			name:      "transformation package metadata",
			family:    fivetranapi.FamilyTransformationPackageMetadata,
			path:      "/v1/transformations/package-metadata",
			accept:    "application/json",
			item:      map[string]any{"package_definition_id": "package-definition-1", "name": "Quickstart package"},
			kind:      "fivetran.transformation_package_metadata",
			attrKey:   "resource_id",
			attrValue: "package-definition-1",
		},
		{
			name:                 "transformation package details",
			family:               fivetranapi.FamilyTransformationPackageDetails,
			path:                 "/v1/transformations/package-metadata/package-definition-1",
			accept:               "application/json",
			item:                 map[string]any{"id": "package-definition-1", "name": "Quickstart package", "version": "1.0.0"},
			kind:                 "fivetran.transformation_package_details",
			attrKey:              "resource_id",
			attrValue:            "package-definition-1",
			config:               map[string]string{"package_definition_ids": "package-definition-1"},
			singleton:            true,
			wantLimit:            "none",
			wantScopedResourceID: true,
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
				wantLimit := tt.wantLimit
				if wantLimit == "" {
					wantLimit = "2"
				}
				if got := r.URL.Query().Get("limit"); wantLimit == "none" {
					if got != "" {
						t.Fatalf("limit = %q, want no limit", got)
					}
				} else if got != wantLimit {
					t.Fatalf("limit = %q, want %s", got, wantLimit)
				}
				if tt.queryKey != "" && r.URL.Query().Get(tt.queryKey) != tt.queryValue {
					t.Fatalf("%s query = %q, want %q", tt.queryKey, r.URL.Query().Get(tt.queryKey), tt.queryValue)
				}
				w.Header().Set("Content-Type", "application/json")
				if tt.singleton {
					_ = json.NewEncoder(w).Encode(map[string]any{"code": "Success", "data": tt.item})
					return
				}
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
			if tt.wantScopedResourceID {
				got := event.Attributes[tt.attrKey]
				if got == "" || got == tt.attrValue || !strings.HasPrefix(got, tt.attrValue+"-") {
					t.Fatalf("%s = %q, want scoped %q identity in %#v", tt.attrKey, got, tt.attrValue, event.Attributes)
				}
				if event.Attributes["source_event_id"] != got {
					t.Fatalf("source_event_id should match scoped resource_id, got %#v", event.Attributes)
				}
			} else if event.Attributes[tt.attrKey] != tt.attrValue {
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
			if tt.family == fivetranapi.FamilyGroupServiceAccounts {
				var payload map[string]any
				if err := json.Unmarshal(event.Payload, &payload); err != nil {
					t.Fatalf("decode service account payload: %v", err)
				}
				if _, ok := payload["service_account"]; ok {
					t.Fatalf("service account payload retained API key: %#v", payload)
				}
				if got := event.Attributes["service_account"]; got != "" {
					t.Fatalf("service_account attribute = %q, want redacted", got)
				}
				if got := event.Attributes["resource_id"]; got == "group-1" || got == "" {
					t.Fatalf("resource_id = %q, want scoped group service account identity", got)
				}
				if event.Attributes["source_event_id"] != event.Attributes["resource_id"] {
					t.Fatalf("source_event_id should match scoped resource_id, got %#v", event.Attributes)
				}
			}
			if tt.family == fivetranapi.FamilyDestinations || tt.family == fivetranapi.FamilyConnections || tt.family == fivetranapi.FamilyAccountLogService || tt.family == fivetranapi.FamilyLogServices {
				var payload map[string]any
				if err := json.Unmarshal(event.Payload, &payload); err != nil {
					t.Fatalf("decode config-bearing payload: %v", err)
				}
				if _, ok := payload["config"]; ok {
					t.Fatalf("%s payload retained config: %#v", tt.family, payload)
				}
			}
			if tt.family == fivetranapi.FamilyWebhooks {
				var payload map[string]any
				if err := json.Unmarshal(event.Payload, &payload); err != nil {
					t.Fatalf("decode webhook payload: %v", err)
				}
				if _, ok := payload["signing_key"]; ok {
					t.Fatalf("webhook payload retained signing key: %#v", payload)
				}
			}
		})
	}
}

func TestSourceReadsConnectionTableColumns(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		if r.URL.Path != "/v1/connections/connection-1/schemas/public/tables/users/columns" {
			t.Fatalf("path = %q, want table columns path", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "" {
			t.Fatalf("limit = %q, want no limit", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": "Success",
			"data": map[string]any{
				"columns": map[string]any{
					"EMAIL": map[string]any{"enabled": true, "hashed": false},
				},
			},
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), fivetranConfig(server.URL, map[string]string{
		"connection_id": "connection-1",
		"family":        fivetranapi.FamilyConnectionTableColumns,
		"schema_name":   "public",
		"table_name":    "users",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "fivetran.connection_table_columns" {
		t.Fatalf("kind = %q, want fivetran.connection_table_columns", event.Kind)
	}
	attrs := event.Attributes
	if attrs["connection_id"] != "connection-1" || attrs["schema_name"] != "public" || attrs["table_name"] != "users" || attrs["column_name"] != "EMAIL" || attrs["enabled"] != "true" {
		t.Fatalf("attributes = %#v, want table column attributes", attrs)
	}
	if got := attrs["resource_id"]; got == "" || got == "EMAIL" || !strings.HasPrefix(got, "EMAIL-") {
		t.Fatalf("resource_id = %q, want scoped table column identity in %#v", got, attrs)
	}
	if attrs["source_event_id"] != attrs["resource_id"] {
		t.Fatalf("source_event_id should match scoped table column resource_id, got %#v", attrs)
	}
	if got := attrs["resource_urn"]; got == "urn:cerebro:tenant:fivetran_connection_table_columns:EMAIL" || !strings.Contains(got, attrs["resource_id"]) {
		t.Fatalf("resource_urn = %q, want scoped table column URN for %#v", got, attrs)
	}
}

func TestSourceReadsScopedMembershipsWithFanout(t *testing.T) {
	source := newTestSource(t)
	requestedPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		requestedPaths = append(requestedPaths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/groups/group-1/users", "/v1/groups/group-2/users":
		default:
			t.Fatalf("path = %q, want scoped group users path", r.URL.Path)
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
		"group_ids": "group-1,group-2",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.NextCursor == nil {
		t.Fatalf("first pull events=%d cursor=%v, want one event and cursor", len(pull.Events), pull.NextCursor)
	}
	next, err := source.Read(context.Background(), fivetranConfig(server.URL, map[string]string{
		"family":    fivetranapi.FamilyGroupUsers,
		"group_ids": "group-1,group-2",
		"per_page":  "2",
	}), pull.NextCursor)
	if err != nil {
		t.Fatalf("Read(next) error = %v", err)
	}
	if len(next.Events) != 1 || next.NextCursor != nil {
		t.Fatalf("next pull events=%d cursor=%v, want one event and no cursor", len(next.Events), next.NextCursor)
	}
	byGroup := map[string]map[string]string{}
	for _, event := range pull.Events {
		byGroup[event.Attributes["group_id"]] = event.Attributes
	}
	for _, event := range next.Events {
		byGroup[event.Attributes["group_id"]] = event.Attributes
	}
	attrs := byGroup["group-1"]
	if attrs["group_id"] != "group-1" || attrs["member_id"] != "user-1" || attrs["member_type"] != "user" || attrs["role"] != "Destination Reviewer" || attrs["email"] != "user@example.test" {
		t.Fatalf("attributes = %#v, want scoped membership", attrs)
	}
	otherAttrs := byGroup["group-2"]
	if otherAttrs["group_id"] != "group-2" || otherAttrs["member_id"] != "user-1" {
		t.Fatalf("second attributes = %#v, want second scoped membership", otherAttrs)
	}
	if attrs["resource_id"] == "user-1" || otherAttrs["resource_id"] == "user-1" || attrs["resource_id"] == otherAttrs["resource_id"] {
		t.Fatalf("resource_id values should include scope identity, got %q and %q", attrs["resource_id"], otherAttrs["resource_id"])
	}
	if attrs["source_event_id"] != attrs["resource_id"] || otherAttrs["source_event_id"] != otherAttrs["resource_id"] {
		t.Fatalf("source_event_id should match scoped resource_id, got %#v and %#v", attrs, otherAttrs)
	}
	if attrs["resource_urn"] == "urn:cerebro:tenant:fivetran_group_users:user-1" || attrs["resource_urn"] == otherAttrs["resource_urn"] {
		t.Fatalf("resource_urn values should be scoped, got %q and %q", attrs["resource_urn"], otherAttrs["resource_urn"])
	}
	if strings.Join(requestedPaths, ",") != "/v1/groups/group-1/users,/v1/groups/group-2/users" {
		t.Fatalf("requested paths = %#v, want both scoped reads", requestedPaths)
	}
}

func TestSourceReadsScopedAssetsWithScopedResourceIdentity(t *testing.T) {
	tests := []struct {
		name       string
		family     string
		configKey  string
		scopeKey   string
		scopeA     string
		scopeB     string
		pathA      string
		pathB      string
		resourceID string
	}{
		{
			name:       "external secret manager assignments",
			family:     fivetranapi.FamilyExternalSecretManagerAssignments,
			configKey:  "external_secret_manager_ids",
			scopeKey:   "external_secret_manager_id",
			scopeA:     "esm-1",
			scopeB:     "esm-2",
			pathA:      "/v1/external-secrets-managers/esm-1/entities",
			pathB:      "/v1/external-secrets-managers/esm-2/entities",
			resourceID: "connection-1",
		},
		{
			name:       "proxy agent connections",
			family:     fivetranapi.FamilyProxyAgentConnections,
			configKey:  "proxy_agent_ids",
			scopeKey:   "proxy_agent_id",
			scopeA:     "proxy-1",
			scopeB:     "proxy-2",
			pathA:      "/v1/proxy/proxy-1/connections",
			pathB:      "/v1/proxy/proxy-2/connections",
			resourceID: "connection-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newTestSource(t)
			requestedPaths := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireFivetranHeaders(t, r, "application/json")
				requestedPaths = append(requestedPaths, r.URL.Path)
				switch r.URL.Path {
				case tt.pathA, tt.pathB:
				default:
					t.Fatalf("path = %q, want scoped asset path", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
					"id":   tt.resourceID,
					"name": "Salesforce connection",
				}, ""))
			}))
			defer server.Close()

			cfg := fivetranConfig(server.URL, map[string]string{
				"family":     tt.family,
				tt.configKey: tt.scopeA + "," + tt.scopeB,
				"per_page":   "2",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 || pull.NextCursor == nil {
				t.Fatalf("first pull events=%d cursor=%v, want one event and cursor", len(pull.Events), pull.NextCursor)
			}
			next, err := source.Read(context.Background(), cfg, pull.NextCursor)
			if err != nil {
				t.Fatalf("Read(next) error = %v", err)
			}
			if len(next.Events) != 1 || next.NextCursor != nil {
				t.Fatalf("next pull events=%d cursor=%v, want one event and no cursor", len(next.Events), next.NextCursor)
			}

			byScope := map[string]map[string]string{}
			for _, event := range pull.Events {
				byScope[event.Attributes[tt.scopeKey]] = event.Attributes
			}
			for _, event := range next.Events {
				byScope[event.Attributes[tt.scopeKey]] = event.Attributes
			}
			attrs := byScope[tt.scopeA]
			otherAttrs := byScope[tt.scopeB]
			if attrs[tt.scopeKey] != tt.scopeA || otherAttrs[tt.scopeKey] != tt.scopeB {
				t.Fatalf("scoped attributes = %#v / %#v, want both scopes", attrs, otherAttrs)
			}
			if attrs["resource_id"] == tt.resourceID || otherAttrs["resource_id"] == tt.resourceID || attrs["resource_id"] == otherAttrs["resource_id"] {
				t.Fatalf("resource_id values should include scope identity, got %q and %q", attrs["resource_id"], otherAttrs["resource_id"])
			}
			if attrs["source_event_id"] != attrs["resource_id"] || otherAttrs["source_event_id"] != otherAttrs["resource_id"] {
				t.Fatalf("source_event_id should match scoped resource_id, got %#v and %#v", attrs, otherAttrs)
			}
			if attrs["resource_urn"] == otherAttrs["resource_urn"] {
				t.Fatalf("resource_urn values should be scoped, got %q and %q", attrs["resource_urn"], otherAttrs["resource_urn"])
			}
			if strings.Join(requestedPaths, ",") != tt.pathA+","+tt.pathB {
				t.Fatalf("requested paths = %#v, want both scoped reads", requestedPaths)
			}
		})
	}
}

func TestSourceAutoFansOutScopedFamiliesFromParentInventory(t *testing.T) {
	source := newTestSource(t)
	requestedPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/groups":
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
				"id":   "group-1",
				"name": "Warehouse",
			}, ""))
		case "/v1/groups/group-1/users":
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
				"id":    "user-1",
				"email": "user@example.test",
				"role":  "Destination Reviewer",
			}, ""))
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), fivetranConfig(server.URL, map[string]string{
		"family":   fivetranapi.FamilyGroupUsers,
		"per_page": "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["group_id"] != "group-1" || attrs["member_id"] != "user-1" {
		t.Fatalf("attributes = %#v, want discovered group membership", attrs)
	}
	if strings.Join(requestedPaths, ",") != "/v1/groups,/v1/groups/group-1/users" {
		t.Fatalf("requested paths = %#v, want parent inventory then scoped read", requestedPaths)
	}
}

func TestSourceAutoFanoutCursorPinsParentInventoryAcrossPages(t *testing.T) {
	source := newTestSource(t)
	parentReads := 0
	scopedReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/groups":
			parentReads++
			if parentReads > 1 {
				t.Fatalf("parent inventory was re-read after cursor resume")
			}
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
				"id":   "group-1",
				"name": "Warehouse",
			}, ""))
		case "/v1/groups/group-1/users":
			scopedReads++
			switch scopedReads {
			case 1:
				if got := r.URL.Query().Get("cursor"); got != "" {
					t.Fatalf("first scoped cursor = %q, want empty", got)
				}
				_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
					"id":    "user-1",
					"email": "first@example.test",
				}, "scope-page-2"))
			case 2:
				if got := r.URL.Query().Get("cursor"); got != "scope-page-2" {
					t.Fatalf("second scoped cursor = %q, want scope-page-2", got)
				}
				_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{
					"id":    "user-2",
					"email": "second@example.test",
				}, ""))
			default:
				t.Fatalf("scoped reads = %d, want at most 2", scopedReads)
			}
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := fivetranConfig(server.URL, map[string]string{
		"family":   fivetranapi.FamilyGroupUsers,
		"per_page": "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.NextCursor == nil {
		t.Fatalf("first pull events=%d cursor=%v, want one event and cursor", len(first.Events), first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second pull events = %d, want 1", len(second.Events))
	}
	if parentReads != 1 || scopedReads != 2 {
		t.Fatalf("parentReads=%d scopedReads=%d, want 1 and 2", parentReads, scopedReads)
	}
}

func TestSourceEmptyAutoFanoutParentInventoryNoOps(t *testing.T) {
	source := newTestSource(t)
	requestedPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "Success", "data": map[string]any{"items": []any{}}})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := fivetranConfig(server.URL, map[string]string{
		"family":   fivetranapi.FamilyGroupUsers,
		"per_page": "2",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v, want nil for empty auto-discovered parent inventory", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v, want nil for empty auto-discovered parent inventory", err)
	}
	if len(pull.Events) != 0 || pull.NextCursor != nil {
		t.Fatalf("pull events=%d cursor=%v, want empty no-op", len(pull.Events), pull.NextCursor)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil for empty auto-discovered parent inventory", err)
	}
	if len(urns) != 0 {
		t.Fatalf("URNs = %#v, want none", urns)
	}
	if strings.Join(requestedPaths, ",") != "/v1/groups,/v1/groups,/v1/groups" {
		t.Fatalf("requested paths = %#v, want parent inventory for check/read/discover only", requestedPaths)
	}
}

func TestSourceDiscoverAutoFansOutScopedFamilies(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFivetranHeaders(t, r, "application/json")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/groups":
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{"id": "group-1", "name": "Warehouse"}, ""))
		case "/v1/groups/group-1/users":
			_ = json.NewEncoder(w).Encode(fivetranList(map[string]any{"id": "user-1", "email": "user@example.test"}, ""))
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	urns, err := source.Discover(context.Background(), fivetranConfig(server.URL, map[string]string{
		"family":   fivetranapi.FamilyGroupUsers,
		"per_page": "2",
	}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || !strings.Contains(urns[0].String(), "user-1") {
		t.Fatalf("URNs = %#v, want discovered scoped user", urns)
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
		fivetranapi.FamilyAccountInfo,
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
		fivetranapi.FamilyGroupPublicKeys,
		fivetranapi.FamilyGroupServiceAccounts,
		fivetranapi.FamilyDestinations,
		fivetranapi.FamilyConnections,
		fivetranapi.FamilyConnectionCertificates,
		fivetranapi.FamilyConnectionFingerprints,
		fivetranapi.FamilyConnectionSchemas,
		fivetranapi.FamilyConnectionState,
		fivetranapi.FamilyConnectionTableColumns,
		fivetranapi.FamilyConnectorSDKPackages,
		fivetranapi.FamilyDestinationCertificates,
		fivetranapi.FamilyDestinationFingerprints,
		fivetranapi.FamilyAccountLogService,
		fivetranapi.FamilyLogServices,
		fivetranapi.FamilyWebhooks,
		fivetranapi.FamilyExternalSecretManagers,
		fivetranapi.FamilyExternalSecretManagerEntities,
		fivetranapi.FamilyExternalSecretManagerAssignments,
		fivetranapi.FamilyPrivateLinks,
		fivetranapi.FamilyProxyAgents,
		fivetranapi.FamilyProxyAgentConnections,
		fivetranapi.FamilyHybridAgents,
		fivetranapi.FamilyPublicConnectorTypes,
		fivetranapi.FamilyConnectorMetadata,
		fivetranapi.FamilyConnectorMetadataDetails,
		fivetranapi.FamilySystemKeys,
		fivetranapi.FamilyTransformations,
		fivetranapi.FamilyTransformationProjects,
		fivetranapi.FamilyTransformationPackageMetadata,
		fivetranapi.FamilyTransformationPackageDetails,
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
