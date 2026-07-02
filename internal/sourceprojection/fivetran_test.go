package sourceprojection

import (
	"context"
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
		{name: "account_info", kind: "fivetran.account_info", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"account_id": "account-1", "resource_id": "account-1", "resource_type": "account", "resource_name": "Primary account"}},
		{name: "legacy_accounts", kind: "fivetran.accounts", project: fivetranAccountsProjections, attrs: map[string]string{"resource_id": "account-1", "resource_type": "account", "resource_name": "Primary account"}},
		{name: "legacy_records", kind: "fivetran.records", project: fivetranRecordsProjections, attrs: map[string]string{"resource_id": "record-1", "resource_type": "record", "resource_name": "Runtime record"}},
		{name: "legacy_policies", kind: "fivetran.policies", project: fivetranPoliciesProjections, attrs: map[string]string{"policy_id": "policy-1", "policy_name": "Access policy"}},
		{name: "legacy_audit_events", kind: "fivetran.audit_events", project: fivetranAuditEventsProjections, attrs: map[string]string{"audit_event_id": "audit-1", "actor_id": "user-1", "action": "connection.updated"}},
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
		{name: "group_public_keys", kind: "fivetran.group_public_keys", project: fivetranCredentialProjections, attrs: map[string]string{"credential_id": "ssh-rsa-test", "group_id": "group-1", "resource_id": "ssh-rsa-test", "resource_type": "public_key"}, wantLinks: true},
		{name: "group_service_accounts", kind: "fivetran.group_service_accounts", project: fivetranCredentialProjections, attrs: map[string]string{"credential_id": "svc-account", "group_id": "group-1", "resource_id": "svc-account", "resource_type": "service_account"}, wantLinks: true},
		{name: "destinations", kind: "fivetran.destinations", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "dest-1", "resource_type": "destination", "resource_name": "Warehouse"}},
		{name: "connections", kind: "fivetran.connections", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "connection-1", "resource_type": "connection", "resource_name": "Salesforce"}},
		{name: "connection_certificates", kind: "fivetran.connection_certificates", project: fivetranCredentialProjections, attrs: map[string]string{"connection_id": "connection-1", "credential_id": "cert-1", "resource_id": "cert-1", "resource_type": "certificate"}, wantLinks: true},
		{name: "connection_fingerprints", kind: "fivetran.connection_fingerprints", project: fivetranCredentialProjections, attrs: map[string]string{"connection_id": "connection-1", "credential_id": "fingerprint-1", "resource_id": "fingerprint-1", "resource_type": "fingerprint"}, wantLinks: true},
		{name: "connection_schemas", kind: "fivetran.connection_schemas", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"connection_id": "connection-1", "resource_id": "connection-1", "resource_type": "connection_schema"}},
		{name: "connection_state", kind: "fivetran.connection_state", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"connection_id": "connection-1", "resource_id": "connection-1", "resource_type": "connection_state", "status": "connected"}},
		{name: "connection_table_columns", kind: "fivetran.connection_table_columns", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"column_name": "EMAIL", "connection_id": "connection-1", "resource_id": "EMAIL", "resource_type": "connection_table_column", "schema_name": "public", "table_name": "users"}, wantLinks: true},
		{name: "connector_sdk_packages", kind: "fivetran.connector_sdk_packages", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "package-1", "resource_type": "connector_sdk_package", "resource_name": "Custom package"}},
		{name: "destination_certificates", kind: "fivetran.destination_certificates", project: fivetranCredentialProjections, attrs: map[string]string{"destination_id": "destination-1", "credential_id": "dest-cert-1", "resource_id": "dest-cert-1", "resource_type": "certificate"}, wantLinks: true},
		{name: "destination_fingerprints", kind: "fivetran.destination_fingerprints", project: fivetranCredentialProjections, attrs: map[string]string{"destination_id": "destination-1", "credential_id": "dest-fingerprint-1", "resource_id": "dest-fingerprint-1", "resource_type": "fingerprint"}, wantLinks: true},
		{name: "account_log_service", kind: "fivetran.account_log_service", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "log-1", "resource_type": "log_service", "resource_name": "Datadog", "status": "true"}},
		{name: "log_services", kind: "fivetran.log_services", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "log-1", "resource_type": "log_service", "resource_name": "Datadog"}},
		{name: "webhooks", kind: "fivetran.webhooks", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "webhook-1", "resource_type": "webhook", "resource_name": "Sync alerts"}},
		{name: "external_secret_managers", kind: "fivetran.external_secret_managers", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "esm-1", "resource_type": "external_secret_manager", "resource_name": "Vault production"}},
		{name: "external_secret_manager_entities", kind: "fivetran.external_secret_manager_entities", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "esm-entity-1", "resource_type": "external_secret_manager_entity", "resource_name": "Salesforce connection"}},
		{name: "external_secret_manager_assignments", kind: "fivetran.external_secret_manager_assignments", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"external_secret_manager_id": "esm-1", "resource_id": "connection-1", "resource_type": "external_secret_manager_assignment", "resource_name": "Salesforce connection"}},
		{name: "private_links", kind: "fivetran.private_links", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "plink-1", "resource_type": "private_link", "resource_name": "AWS PrivateLink"}},
		{name: "proxy_agents", kind: "fivetran.proxy_agents", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "proxy-1", "resource_type": "proxy_agent", "resource_name": "Proxy Agent"}},
		{name: "proxy_agent_connections", kind: "fivetran.proxy_agent_connections", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"proxy_agent_id": "proxy-1", "resource_id": "connection-1", "resource_type": "proxy_agent_connection", "resource_name": "Salesforce connection"}},
		{name: "hybrid_deployment_agents", kind: "fivetran.hybrid_deployment_agents", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "hybrid-1", "resource_type": "hybrid_deployment_agent", "resource_name": "Hybrid Agent"}},
		{name: "public_connector_types", kind: "fivetran.public_connector_types", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "postgres", "resource_type": "public_connector_type", "service": "postgres"}},
		{name: "connector_metadata", kind: "fivetran.connector_metadata", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "postgres", "resource_type": "connector_metadata", "service": "postgres"}},
		{name: "connector_metadata_details", kind: "fivetran.connector_metadata_details", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "postgres", "resource_type": "connector_metadata_detail", "service": "postgres", "status": "general_availability"}},
		{name: "system_keys", kind: "fivetran.system_keys", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "key-1", "resource_type": "system_key", "resource_name": "Automation key"}},
		{name: "transformations", kind: "fivetran.transformations", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "transformation-1", "resource_type": "transformation", "resource_name": "Normalize accounts"}},
		{name: "transformation_projects", kind: "fivetran.transformation_projects", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "project-1", "resource_type": "transformation_project", "resource_name": "dbt production"}},
		{name: "transformation_package_metadata", kind: "fivetran.transformation_package_metadata", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"resource_id": "package-definition-1", "resource_type": "transformation_package_metadata", "resource_name": "Quickstart package"}},
		{name: "transformation_package_details", kind: "fivetran.transformation_package_details", project: fivetranRuntimeAssetProjections, attrs: map[string]string{"package_definition_id": "package-definition-1", "resource_id": "package-definition-1", "resource_type": "transformation_package_detail", "resource_name": "Quickstart package"}},
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
		"fivetran.account_info",
		"fivetran.accounts",
		"fivetran.audit_events",
		"fivetran.policies",
		"fivetran.records",
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
		"fivetran.group_public_keys",
		"fivetran.group_service_accounts",
		"fivetran.destinations",
		"fivetran.connections",
		"fivetran.connection_certificates",
		"fivetran.connection_fingerprints",
		"fivetran.connection_schemas",
		"fivetran.connection_state",
		"fivetran.connection_table_columns",
		"fivetran.connector_sdk_packages",
		"fivetran.destination_certificates",
		"fivetran.destination_fingerprints",
		"fivetran.account_log_service",
		"fivetran.log_services",
		"fivetran.webhooks",
		"fivetran.external_secret_managers",
		"fivetran.external_secret_manager_entities",
		"fivetran.external_secret_manager_assignments",
		"fivetran.private_links",
		"fivetran.proxy_agents",
		"fivetran.proxy_agent_connections",
		"fivetran.hybrid_deployment_agents",
		"fivetran.public_connector_types",
		"fivetran.connector_metadata",
		"fivetran.connector_metadata_details",
		"fivetran.system_keys",
		"fivetran.transformations",
		"fivetran.transformation_projects",
		"fivetran.transformation_package_metadata",
		"fivetran.transformation_package_details",
	} {
		if registry.projectors[kind] == nil {
			t.Fatalf("missing projector for %s", kind)
		}
	}
}

func TestFivetranLegacyAssetsKeepGenericRuntimeURNs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "account-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.accounts",
			Attributes: map[string]string{
				"resource_id":   "account-1",
				"resource_name": "Primary account",
				"resource_type": "account",
			},
		},
		{
			Id:       "record-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.records",
			Attributes: map[string]string{
				"resource_id":   "record-1",
				"resource_name": "Runtime record",
				"resource_type": "record",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	assertProjectedEntityType(t, state, "urn:cerebro:writer:runtime_account:account-1", "runtime.account")
	assertProjectedEntityType(t, state, "urn:cerebro:writer:runtime_record:record-1", "runtime.record")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:runtime_fivetran_account:account-1")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:runtime_fivetran_record:record-1")
}

func TestFivetranMembershipEdgesUseStandaloneEntityURNs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "team-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.teams",
			Attributes: map[string]string{
				"group_id":   "team-1",
				"group_name": "Data Platform",
				"team_id":    "team-1",
			},
		},
		{
			Id:       "connection-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.connections",
			Attributes: map[string]string{
				"resource_id":   "connection-1",
				"resource_name": "Salesforce production sync",
				"resource_type": "connection",
			},
		},
		{
			Id:       "membership-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.team_connections",
			Attributes: map[string]string{
				"member_id":     "connection-1",
				"member_type":   "connection",
				"resource_name": "Salesforce production sync",
				"role":          "owner",
				"team_id":       "team-1",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	teamURN := "urn:cerebro:writer:fivetran_group:team-1"
	connectionURN := "urn:cerebro:writer:runtime_fivetran_connection:connection-1"
	assertProjectedEntityType(t, state, teamURN, "fivetran.group")
	assertProjectedEntityType(t, state, connectionURN, "runtime.fivetran.connection")
	assertProjectedLink(t, state, connectionURN, relationMemberOf, teamURN)
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:fivetran_user:team-1")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:fivetran_user:connection-1")
}

func TestFivetranRoleTargetsUseRuntimeAssetURNs(t *testing.T) {
	if got, want := fivetranPrincipalOrAssetURN("writer", "role", "role-1"), "urn:cerebro:writer:runtime_fivetran_role:role-1"; got != want {
		t.Fatalf("role URN = %q, want %q", got, want)
	}
	if got, want := fivetranEntityType("role"), "runtime.fivetran.role"; got != want {
		t.Fatalf("role entity type = %q, want %q", got, want)
	}
}

func TestFivetranDestinationCredentialsLinkToDestination(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "destination-certificate-event",
		TenantId: "writer",
		SourceId: "fivetran",
		Kind:     "fivetran.destination_certificates",
		Attributes: map[string]string{
			"credential_id":  "dest-cert-1",
			"destination_id": "destination-1",
			"resource_id":    "dest-cert-1",
			"resource_type":  "certificate",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	certificateURN := "urn:cerebro:writer:runtime_fivetran_certificate:dest-cert-1"
	destinationURN := "urn:cerebro:writer:runtime_fivetran_destination:destination-1"
	assertProjectedEntityType(t, state, certificateURN, "runtime.fivetran.certificate")
	assertProjectedEntityType(t, state, destinationURN, "runtime.fivetran.destination")
	assertProjectedLink(t, state, certificateURN, relationAssignedTo, destinationURN)
}

func TestFivetranGroupCredentialsLinkToGroup(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "group-public-key-event",
		TenantId: "writer",
		SourceId: "fivetran",
		Kind:     "fivetran.group_public_keys",
		Attributes: map[string]string{
			"credential_id": "ssh-rsa-test",
			"group_id":      "group-1",
			"resource_id":   "ssh-rsa-test",
			"resource_type": "public_key",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	publicKeyURN := "urn:cerebro:writer:runtime_fivetran_public_key:ssh-rsa-test"
	groupURN := "urn:cerebro:writer:fivetran_group:group-1"
	assertProjectedEntityType(t, state, publicKeyURN, "runtime.fivetran.public.key")
	assertProjectedEntityType(t, state, groupURN, "fivetran.group")
	assertProjectedLink(t, state, publicKeyURN, relationAssignedTo, groupURN)
}

func TestFivetranTableColumnUsesCompositeRuntimeURN(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "column-event",
		TenantId: "writer",
		SourceId: "fivetran",
		Kind:     "fivetran.connection_table_columns",
		Attributes: map[string]string{
			"column_name":   "EMAIL",
			"connection_id": "connection-1",
			"resource_id":   "EMAIL",
			"resource_type": "connection_table_column",
			"resource_urn":  "urn:cerebro:writer:fivetran_connection_table_columns:EMAIL",
			"schema_name":   "public",
			"table_name":    "users",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	columnURN := "urn:cerebro:writer:runtime_fivetran_connection_table_column:connection-1/public/users/EMAIL"
	connectionURN := "urn:cerebro:writer:runtime_fivetran_connection:connection-1"
	assertProjectedEntityType(t, state, columnURN, "runtime.fivetran.connection.table.column")
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:fivetran_connection_table_columns:EMAIL")
	assertProjectedLink(t, state, columnURN, relationBelongsTo, connectionURN)
}

func TestFivetranConnectionGroupDoesNotCreateDestination(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "connection-event",
		TenantId: "writer",
		SourceId: "fivetran",
		Kind:     "fivetran.connections",
		Attributes: map[string]string{
			"group_id":      "group-1",
			"resource_id":   "connection-1",
			"resource_name": "Salesforce production sync",
			"resource_type": "connection",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	connectionURN := "urn:cerebro:writer:runtime_fivetran_connection:connection-1"
	groupURN := "urn:cerebro:writer:fivetran_group:group-1"
	assertProjectedEntityType(t, state, connectionURN, "runtime.fivetran.connection")
	assertProjectedEntityType(t, state, groupURN, "fivetran.group")
	assertProjectedLink(t, state, connectionURN, relationBelongsTo, groupURN)
	assertProjectedEntityMissing(t, state, "urn:cerebro:writer:runtime_fivetran_destination:group-1")
	assertProjectedLinkMissing(t, state, connectionURN, relationBelongsTo, "urn:cerebro:writer:runtime_fivetran_destination:group-1")
}

func TestFivetranAssetRelationshipsProjectToGraph(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "connection-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.connections",
			Attributes: map[string]string{
				"destination_id": "destination-1",
				"group_id":       "group-1",
				"resource_id":    "connection-1",
				"resource_name":  "Salesforce production sync",
				"resource_type":  "connection",
			},
		},
		{
			Id:       "proxy-attachment-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.proxy_agent_connections",
			Attributes: map[string]string{
				"proxy_agent_id": "proxy-1",
				"resource_id":    "connection-1",
				"resource_name":  "Salesforce production sync",
				"resource_type":  "proxy_agent_connection",
			},
		},
		{
			Id:       "transformation-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.transformations",
			Attributes: map[string]string{
				"connection_id": "connection-1",
				"group_id":      "group-1",
				"project_id":    "project-1",
				"resource_id":   "transformation-1",
				"resource_name": "Normalize accounts",
				"resource_type": "transformation",
			},
		},
		{
			Id:       "esm-assignment-event",
			TenantId: "writer",
			SourceId: "fivetran",
			Kind:     "fivetran.external_secret_manager_assignments",
			Attributes: map[string]string{
				"entity_type":                "connection",
				"external_secret_manager_id": "esm-1",
				"resource_id":                "connection-1",
				"resource_name":              "Salesforce production sync",
				"resource_type":              "external_secret_manager_assignment",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	connectionURN := "urn:cerebro:writer:runtime_fivetran_connection:connection-1"
	destinationURN := "urn:cerebro:writer:runtime_fivetran_destination:destination-1"
	groupURN := "urn:cerebro:writer:fivetran_group:group-1"
	proxyURN := "urn:cerebro:writer:runtime_fivetran_proxy_agent:proxy-1"
	transformationURN := "urn:cerebro:writer:runtime_fivetran_transformation:transformation-1"
	projectURN := "urn:cerebro:writer:runtime_fivetran_transformation_project:project-1"
	esmURN := "urn:cerebro:writer:runtime_fivetran_external_secret_manager:esm-1"
	assertProjectedLink(t, state, connectionURN, relationBelongsTo, groupURN)
	assertProjectedLink(t, state, connectionURN, relationBelongsTo, destinationURN)
	assertProjectedLink(t, state, connectionURN, relationAttachedTo, proxyURN)
	assertProjectedLink(t, state, transformationURN, relationBelongsTo, projectURN)
	assertProjectedLink(t, state, transformationURN, relationBelongsTo, connectionURN)
	assertProjectedLink(t, state, transformationURN, relationBelongsTo, groupURN)
	assertProjectedLink(t, state, connectionURN, relationDependsOn, esmURN)
}
