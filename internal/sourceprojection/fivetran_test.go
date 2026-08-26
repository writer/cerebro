package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestFivetranGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"fivetran.accounts",
		"fivetran.account_info",
		"fivetran.account_log_service",
		"fivetran.audit_events",
		"fivetran.connection_certificates",
		"fivetran.connection_fingerprints",
		"fivetran.connection_schemas",
		"fivetran.connection_state",
		"fivetran.connection_table_columns",
		"fivetran.connections",
		"fivetran.connector_metadata",
		"fivetran.connector_metadata_details",
		"fivetran.connector_sdk_packages",
		"fivetran.destinations",
		"fivetran.destination_certificates",
		"fivetran.destination_fingerprints",
		"fivetran.external_secret_manager_assignments",
		"fivetran.external_secret_manager_entities",
		"fivetran.external_secret_managers",
		"fivetran.group_connections",
		"fivetran.group_public_keys",
		"fivetran.group_service_accounts",
		"fivetran.group_users",
		"fivetran.groups",
		"fivetran.hybrid_deployment_agents",
		"fivetran.log_services",
		"fivetran.private_links",
		"fivetran.policies",
		"fivetran.proxy_agent_connections",
		"fivetran.proxy_agents",
		"fivetran.public_connector_types",
		"fivetran.records",
		"fivetran.roles",
		"fivetran.system_keys",
		"fivetran.team_connections",
		"fivetran.team_groups",
		"fivetran.team_users",
		"fivetran.teams",
		"fivetran.transformation_package_details",
		"fivetran.transformation_package_metadata",
		"fivetran.transformation_projects",
		"fivetran.transformations",
		"fivetran.user_connections",
		"fivetran.user_groups",
		"fivetran.users",
		"fivetran.webhooks",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "fivetran",
				Kind:     kind,
			})
			if !errors.Is(err, errFivetranRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
