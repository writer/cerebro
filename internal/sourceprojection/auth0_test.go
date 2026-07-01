package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAuth0IdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := auth0UsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	assertAuth0Entity(t, entities, identityUserURN("tenant", "auth0", "user-1", "user@example.test"), "auth0.user")
}

func TestAuth0RoleProjectionAddsRoleAndEntitlement(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.roles", Attributes: map[string]string{"role_id": "role-1", "role_name": "Security Administrators", "description": "Manage identity security settings"}}
	entities, links, err := auth0RolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	roleURN := projectionURN("tenant", "auth0_role", "role-1")
	groupURN := identityGroupURN("tenant", "auth0", "role-1", "")
	assertAuth0Entity(t, entities, roleURN, "auth0.role")
	assertAuth0Entity(t, entities, groupURN, "auth0.group")
	assertAuth0Link(t, links, groupURN, relationRepresents, roleURN)
	assertAuth0LinkFrom(t, links, roleURN, relationGrantsEntitlement)
}

func TestAuth0AuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := auth0AuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func TestAuth0ClientProjectionAddsApplication(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.clients", Attributes: map[string]string{"client_id": "client-1", "app_id": "client-1", "app_name": "Workforce Portal"}}
	entities, _, err := auth0ClientsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	assertAuth0Entity(t, entities, identityApplicationURN("tenant", "auth0", "client-1"), "auth0.application")
}

func TestAuth0ConnectionProjectionLinksEnabledClients(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.connections", Attributes: map[string]string{"connection_id": "conn-1", "connection_name": "Username-Password-Authentication", "enabled_clients": "client-1", "strategy": "auth0"}}
	entities, links, err := auth0ConnectionsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	connectionURN := projectionURN("tenant", "auth0_connection", "conn-1")
	appURN := identityApplicationURN("tenant", "auth0", "client-1")
	assertAuth0Entity(t, entities, connectionURN, "auth0.connection")
	assertAuth0Entity(t, entities, appURN, "auth0.application")
	assertAuth0Link(t, links, connectionURN, relationSupports, appURN)
}

func TestAuth0OrganizationProjectionAddsOrganization(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organizations", Attributes: map[string]string{"organization_id": "org_1", "organization_name": "acme", "display_name": "Acme"}}
	entities, _, err := auth0OrganizationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	assertAuth0Entity(t, entities, auth0OrganizationURN("tenant", "org_1"), "auth0.organization")
}

func TestAuth0OrganizationMemberProjectionLinksUserToOrganization(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organization_members", Attributes: map[string]string{"organization_id": "org_1", "user_id": "user-1", "email": "user@example.test", "member_name": "User One"}}
	entities, links, err := auth0OrganizationMembersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	userURN := identityUserURN("tenant", "auth0", "user-1", "user@example.test")
	orgURN := auth0OrganizationURN("tenant", "org_1")
	assertAuth0Entity(t, entities, userURN, "auth0.user")
	assertAuth0Entity(t, entities, orgURN, "auth0.organization")
	assertAuth0Link(t, links, userURN, relationMemberOf, orgURN)
}

func TestAuth0RoleUsersProjectionLinksUserToRole(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.role_users", Attributes: map[string]string{"role_id": "role-1", "subject_id": "user-1", "subject_type": "user", "email": "user@example.test", "subject_name": "User One"}}
	entities, links, err := auth0RoleUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	userURN := identityUserURN("tenant", "auth0", "user-1", "user@example.test")
	roleURN := projectionURN("tenant", "auth0_role", "role-1")
	assertAuth0Entity(t, entities, userURN, "auth0.user")
	assertAuth0Entity(t, entities, roleURN, "auth0.role")
	assertAuth0Link(t, links, userURN, relationAssignedTo, roleURN)
}

func TestAuth0OrganizationMemberRoleProjectionLinksUserRoleAndOrganization(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organization_member_roles", Attributes: map[string]string{"organization_id": "org_1", "role_id": "role-1", "role_name": "Member Administrator", "subject_id": "user-1", "subject_type": "user", "email": "user@example.test"}}
	entities, links, err := auth0OrganizationMemberRolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	userURN := identityUserURN("tenant", "auth0", "user-1", "user@example.test")
	roleURN := projectionURN("tenant", "auth0_role", "role-1")
	orgURN := auth0OrganizationURN("tenant", "org_1")
	assertAuth0Entity(t, entities, userURN, "auth0.user")
	assertAuth0Entity(t, entities, roleURN, "auth0.role")
	assertAuth0Entity(t, entities, orgURN, "auth0.organization")
	assertAuth0Link(t, links, userURN, relationAssignedTo, roleURN)
	assertAuth0Link(t, links, roleURN, relationBelongsTo, orgURN)
}

func assertAuth0Entity(t *testing.T, entities []*ports.ProjectedEntity, urn string, entityType string) {
	t.Helper()
	for _, entity := range entities {
		if entity.URN == urn && entity.EntityType == entityType {
			return
		}
	}
	t.Fatalf("missing entity %s type %s in %#v", urn, entityType, entities)
}

func assertAuth0Link(t *testing.T, links []*ports.ProjectedLink, fromURN string, relation string, toURN string) {
	t.Helper()
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return
		}
	}
	t.Fatalf("missing link %s -[%s]-> %s in %#v", fromURN, relation, toURN, links)
}

func assertAuth0LinkFrom(t *testing.T, links []*ports.ProjectedLink, fromURN string, relation string) {
	t.Helper()
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation {
			return
		}
	}
	t.Fatalf("missing link from %s relation %s in %#v", fromURN, relation, links)
}
