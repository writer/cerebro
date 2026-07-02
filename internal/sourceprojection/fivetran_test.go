package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestFivetranProviderFamiliesProjectToGraph(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		project   ProjectFunc
		attrs     map[string]string
		wantLinks bool
	}{
		{name: "users", kind: "fivetran.users", project: fivetranUsersProjections, attrs: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}},
		{name: "user_connections", kind: "fivetran.user_connections", project: fivetranScopedMembershipProjections, attrs: map[string]string{"user_id": "user-1", "member_id": "connection-1", "member_type": "connection", "resource_name": "Customer warehouse", "role": "owner"}, wantLinks: true},
		{name: "user_groups", kind: "fivetran.user_groups", project: fivetranScopedMembershipProjections, attrs: map[string]string{"user_id": "user-1", "member_id": "group-1", "member_type": "group", "resource_name": "Finance"}, wantLinks: true},
		{name: "roles", kind: "fivetran.roles", project: fivetranRolesProjections, attrs: map[string]string{"role_id": "role-1", "role_name": "Account Reviewer", "resource_id": "role-1", "resource_type": "role"}},
		{name: "teams", kind: "fivetran.teams", project: fivetranTeamsProjections, attrs: map[string]string{"team_id": "team-1", "group_id": "team-1", "group_name": "Data Platform"}},
		{name: "team_users", kind: "fivetran.team_users", project: fivetranScopedMembershipProjections, attrs: map[string]string{"team_id": "team-1", "member_id": "user-1", "member_type": "user", "email": "user@example.test"}, wantLinks: true},
		{name: "team_connections", kind: "fivetran.team_connections", project: fivetranScopedMembershipProjections, attrs: map[string]string{"team_id": "team-1", "member_id": "connection-1", "member_type": "connection"}, wantLinks: true},
		{name: "team_groups", kind: "fivetran.team_groups", project: fivetranScopedMembershipProjections, attrs: map[string]string{"team_id": "team-1", "member_id": "group-1", "member_type": "group"}, wantLinks: true},
		{name: "groups", kind: "fivetran.groups", project: fivetranGroupsProjections, attrs: map[string]string{"group_id": "group-1", "group_name": "Finance"}},
		{name: "group_users", kind: "fivetran.group_users", project: fivetranScopedMembershipProjections, attrs: map[string]string{"group_id": "group-1", "member_id": "user-1", "member_type": "user", "email": "user@example.test"}, wantLinks: true},
		{name: "group_connections", kind: "fivetran.group_connections", project: fivetranScopedMembershipProjections, attrs: map[string]string{"group_id": "group-1", "member_id": "connection-1", "member_type": "connection"}, wantLinks: true},
		{name: "destinations", kind: "fivetran.destinations", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "dest-1", "resource_type": "destination", "resource_name": "Warehouse"}},
		{name: "connections", kind: "fivetran.connections", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "connection-1", "resource_type": "connection", "resource_name": "Salesforce"}},
		{name: "connection_certificates", kind: "fivetran.connection_certificates", project: fivetranCredentialProjections, attrs: map[string]string{"connection_id": "connection-1", "credential_id": "cert-1", "resource_id": "cert-1", "resource_type": "certificate"}, wantLinks: true},
		{name: "connection_fingerprints", kind: "fivetran.connection_fingerprints", project: fivetranCredentialProjections, attrs: map[string]string{"connection_id": "connection-1", "credential_id": "fingerprint-1", "resource_id": "fingerprint-1", "resource_type": "fingerprint"}, wantLinks: true},
		{name: "log_services", kind: "fivetran.log_services", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "log-1", "resource_type": "log_service", "resource_name": "Datadog"}},
		{name: "webhooks", kind: "fivetran.webhooks", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "webhook-1", "resource_type": "webhook", "resource_name": "Sync alerts"}},
		{name: "private_links", kind: "fivetran.private_links", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "plink-1", "resource_type": "private_link", "resource_name": "AWS PrivateLink"}},
		{name: "proxy_agents", kind: "fivetran.proxy_agents", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "proxy-1", "resource_type": "proxy_agent", "resource_name": "Proxy Agent"}},
		{name: "hybrid_deployment_agents", kind: "fivetran.hybrid_deployment_agents", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "hybrid-1", "resource_type": "hybrid_deployment_agent", "resource_name": "Hybrid Agent"}},
		{name: "connector_metadata", kind: "fivetran.connector_metadata", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "postgres", "resource_type": "connector_metadata", "service": "postgres"}},
		{name: "system_keys", kind: "fivetran.system_keys", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "key-1", "resource_type": "system_key", "resource_name": "Automation key"}},
		{name: "transformations", kind: "fivetran.transformations", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "transformation-1", "resource_type": "transformation", "resource_name": "Normalize accounts"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: tt.kind, Attributes: tt.attrs}
			entities, links, err := tt.project(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if len(entities) == 0 {
				t.Fatalf("%s projected no entities", tt.kind)
			}
			if tt.wantLinks && len(links) == 0 {
				t.Fatalf("%s projected no links", tt.kind)
			}
		})
	}
}

func TestFivetranRegistryContainsProviderFamilies(t *testing.T) {
	registry := BuiltinRegistry()
	for _, kind := range []string{
		"fivetran.users",
		"fivetran.user_connections",
		"fivetran.user_groups",
		"fivetran.roles",
		"fivetran.teams",
		"fivetran.team_users",
		"fivetran.team_connections",
		"fivetran.team_groups",
		"fivetran.groups",
		"fivetran.group_users",
		"fivetran.group_connections",
		"fivetran.destinations",
		"fivetran.connections",
		"fivetran.connection_certificates",
		"fivetran.connection_fingerprints",
		"fivetran.log_services",
		"fivetran.webhooks",
		"fivetran.private_links",
		"fivetran.proxy_agents",
		"fivetran.hybrid_deployment_agents",
		"fivetran.connector_metadata",
		"fivetran.system_keys",
		"fivetran.transformations",
	} {
		if registry.projectors[kind] == nil {
			t.Fatalf("missing projector for %s", kind)
		}
	}
	for _, stale := range []string{"fivetran.accounts", "fivetran.records", "fivetran.policies", "fivetran.audit_events"} {
		if registry.projectors[stale] != nil {
			t.Fatalf("stale projector registered for %s", stale)
		}
	}
}
