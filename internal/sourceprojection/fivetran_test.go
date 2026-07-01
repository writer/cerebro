package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestFivetranIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := fivetranUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestFivetranConnectionProjectionLinksGroup(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.connections", Attributes: map[string]string{"resource_id": "conn-1", "resource_name": "warehouse_sync", "resource_type": "connection", "group_id": "group-1"}}
	entities, links, err := fivetranAssetsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 {
		t.Fatalf("entities = %d, want connection and group", len(entities))
	}
	if len(links) == 0 {
		t.Fatal("expected connection-to-group link")
	}
}

func TestFivetranChildAssetProjectionLinksConnection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.connection_certificates", Attributes: map[string]string{"resource_id": "cert-1", "resource_name": "db.example.test", "resource_type": "certificate", "connection_id": "conn-1"}}
	entities, links, err := fivetranAssetsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 {
		t.Fatalf("entities = %d, want certificate and connection", len(entities))
	}
	if len(links) == 0 {
		t.Fatal("expected certificate-to-connection link")
	}
}

func TestFivetranGroupUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.group_users", Attributes: map[string]string{"group_id": "group-1", "user_id": "user-1", "email": "user@example.test"}}
	entities, links, err := fivetranGroupUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want group membership", len(entities), len(links))
	}
}

func TestFivetranTeamConnectionProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.team_connections", Attributes: map[string]string{"team_id": "team-1", "member_id": "conn-1", "role": "Destination Reviewer"}}
	entities, links, err := fivetranTeamConnectionsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want team assignment", len(entities), len(links))
	}
}

func TestFivetranRoleProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "fivetran", Kind: "fivetran.roles", Attributes: map[string]string{"role_id": "Account Administrator", "role_name": "Account Administrator", "role_scope": "account", "is_custom": "false"}}
	entities, links, err := fivetranRolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) != 1 || len(links) != 0 {
		t.Fatalf("entities/links = %d/%d, want standalone role", len(entities), len(links))
	}
}
