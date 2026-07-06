package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestActivtrakAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activtrak", Kind: "activtrak.groups", Attributes: map[string]string{"resource_id": "group-1", "resource_type": "activtrak_group", "resource_name": "Engineering", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := activtrakGroupsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestActivtrakClientProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activtrak", Kind: "activtrak.clients", Attributes: map[string]string{"resource_id": "client-1", "resource_type": "activtrak_client", "resource_name": "Client One", "evidence_id": "evidence-1"}}
	entities, links, err := activtrakClientsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected client asset")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestActivtrakIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activtrak", Kind: "activtrak.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := activtrakUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestActivtrakConsumerProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activtrak", Kind: "activtrak.consumers", Attributes: map[string]string{"user_id": "consumer-1", "email": "consumer@example.test", "display_name": "Consumer One"}}
	entities, _, err := activtrakConsumersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected consumer identity")
	}
}

func TestActivtrakAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activtrak", Kind: "activtrak.activity_log", Attributes: map[string]string{"event_type": "application.use", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := activtrakActivityLogProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
