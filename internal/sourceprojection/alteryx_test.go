package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAlteryxWorkflowProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alteryx", Kind: "alteryx.workflows", Attributes: map[string]string{"resource_id": "workflow-1", "resource_type": "workflow", "resource_name": "Workflow One", "owner_id": "user-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := alteryxWorkflowsProjections(event)
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

func TestAlteryxCollectionProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alteryx", Kind: "alteryx.collections", Attributes: map[string]string{"resource_id": "collection-1", "resource_type": "collection", "resource_name": "Security", "evidence_id": "evidence-1"}}
	entities, _, err := alteryxCollectionsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected collection")
	}
}

func TestAlteryxUserGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alteryx", Kind: "alteryx.usergroups", Attributes: map[string]string{"group_id": "group-1", "group_name": "Curators"}}
	entities, _, err := alteryxUserGroupsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}

func TestAlteryxIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alteryx", Kind: "alteryx.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := alteryxUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAlteryxAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alteryx", Kind: "alteryx.audit_events", Attributes: map[string]string{"event_type": "Update", "actor_id": "user-1", "resource_id": "app-1", "resource_type": "User"}}
	entities, links, err := alteryxAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
