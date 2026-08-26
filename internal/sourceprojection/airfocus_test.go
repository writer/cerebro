package sourceprojection

import (
	"errors"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAirfocusIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := airfocusOracleUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAirfocusWorkspaceProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.workspaces", Attributes: airfocusAssetAttributes("workspace-1", "workspace")}
	entities, links, err := airfocusOracleWorkspacesProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusWorkspaceGroupsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.workspace_groups", Attributes: airfocusAssetAttributes("group-1", "workspace_group")}
	entities, links, err := airfocusOracleWorkspaceGroupsProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusLinkTypesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.link_types", Attributes: airfocusAssetAttributes("link-type-1", "link_type")}
	entities, links, err := airfocusOracleLinkTypesProjections(event)
	assertAirfocusAssetProjection(t, entities, links, err)
}

func TestAirfocusAPIKeysProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airfocus", Kind: "airfocus.api_keys", Attributes: airfocusAssetAttributes("api-key-1", "api_key")}
	entities, links, err := airfocusOracleAPIKeysProjections(event)
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

func TestAirfocusGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"airfocus.api_keys",
		"airfocus.link_types",
		"airfocus.users",
		"airfocus.workspace_groups",
		"airfocus.workspaces",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "airfocus",
				Kind:     kind,
			})
			if !errors.Is(err, errAirfocusRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}

// The oracle functions preserve the retired Go writer's semantic output for
// fixture parity without leaving that writer reachable from production.
func airfocusOracleUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "airfocus"})
}

func airfocusOracleWorkspacesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return airfocusOracleGenericAssetProjections(event)
}

func airfocusOracleWorkspaceGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return airfocusOracleGenericAssetProjections(event)
}

func airfocusOracleLinkTypesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return airfocusOracleGenericAssetProjections(event)
}

func airfocusOracleAPIKeysProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return airfocusOracleGenericAssetProjections(event)
}

func airfocusOracleGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: firstNonEmpty(attributes["resource_name"], resourceID), Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
