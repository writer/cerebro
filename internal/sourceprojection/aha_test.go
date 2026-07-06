package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAhaIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "aha", Kind: "aha.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := ahaUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAhaAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "aha", Kind: "aha.products", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := ahaProductsProjections(event)
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

func TestAhaFeaturesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "aha", Kind: "aha.features", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := ahaFeaturesProjections(event)
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

func TestAhaReleasesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "aha", Kind: "aha.releases", Attributes: map[string]string{"resource_id": "release-1", "resource_type": "release", "resource_name": "Q3 Launch", "evidence_id": "evidence-1"}}
	entities, links, err := ahaReleasesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected release")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestAhaAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "aha", Kind: "aha.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := ahaAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
