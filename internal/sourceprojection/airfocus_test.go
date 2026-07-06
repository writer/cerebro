package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAirfocusIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := airfocusUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAirfocusWorkspaceProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.workspaces", Attributes: airfocusAssetAttributes("workspace-1", "workspace")}
	entities, links, err := airfocusWorkspacesProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusWorkspaceGroupsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.workspace_groups", Attributes: airfocusAssetAttributes("group-1", "workspace_group")}
	entities, links, err := airfocusWorkspaceGroupsProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusLinkTypesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.link_types", Attributes: airfocusAssetAttributes("link-type-1", "link_type")}
	entities, links, err := airfocusLinkTypesProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusAPIKeysProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.api_keys", Attributes: airfocusAssetAttributes("api-key-1", "api_key")}
	entities, links, err := airfocusAPIKeysProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func airfocusAssetAttributes(resourceID, resourceType string) map[string]string {
	return map[string]string{"resource_id": resourceID, "resource_type": resourceType, "resource_name": resourceID, "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}
}

func assertAirfocusAssetProjection(t *testing.T, entities []*ports.ProjectedEntity, links []*ports.ProjectedLink, err error) {
	t.Helper()
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
