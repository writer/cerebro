package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSendgridSecretProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sendgrid", Kind: "sendgrid.api_key", Attributes: map[string]string{"secret_id": "secret-1", "secret_name": "DB Password", "secret_type": "password", "secret_status": "active", "evidence_id": "evidence-1"}}
	entities, links, err := sendgridApiKeyProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected secret")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestSendgridIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sendgrid", Kind: "sendgrid.invalid_email", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := sendgridInvalidEmailProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestSendgridIdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sendgrid", Kind: "sendgrid.group", Attributes: map[string]string{"group_id": "group-1", "group_email": "group@example.test", "group_name": "Group One"}}
	entities, _, err := sendgridGroupProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}

func TestSendgridAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sendgrid", Kind: "sendgrid.activity", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := sendgridActivityProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
