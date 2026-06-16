package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAuth0IdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := auth0UsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAuth0IdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.roles", Attributes: map[string]string{"group_id": "group-1", "group_email": "group@example.test", "group_name": "Group One"}}
	entities, _, err := auth0RolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
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
