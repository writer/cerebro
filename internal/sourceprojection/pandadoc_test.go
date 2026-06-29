package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestPandadocAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "pandadoc", Kind: "pandadoc.accounts", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := pandadocAccountsProjections(event)
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

func TestPandadocPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "pandadoc", Kind: "pandadoc.policies", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := pandadocPoliciesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected policy")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestPandadocIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "pandadoc", Kind: "pandadoc.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := pandadocUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestPandadocAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "pandadoc", Kind: "pandadoc.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := pandadocAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
