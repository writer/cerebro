package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAkeylessAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "akeyless", Kind: "akeyless.auth_methods", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := akeylessAuthMethodsProjections(event)
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

func TestAkeylessSecretProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "akeyless", Kind: "akeyless.items", Attributes: map[string]string{"secret_id": "secret-1", "secret_name": "DB Password", "secret_type": "password", "secret_status": "active", "evidence_id": "evidence-1"}}
	entities, links, err := akeylessItemsProjections(event)
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

func TestAkeylessIdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "akeyless", Kind: "akeyless.roles", Attributes: map[string]string{"group_id": "group-1", "group_email": "group@example.test", "group_name": "Group One"}}
	entities, _, err := akeylessRolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}

func TestAkeylessAnalyticsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "akeyless", Kind: "akeyless.analytics", Attributes: map[string]string{"resource_id": "analytics-1", "resource_type": "akeyless_analytics", "resource_name": "Analytics Report", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := akeylessAnalyticsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want analytics asset projection", len(entities), len(links))
	}
}
