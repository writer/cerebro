package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectBackstageComponent(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-1",
		TenantId:   "writer",
		SourceId:   "backstage",
		Kind:       "backstage.component",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"name":       "cerebro",
			"namespace":  "default",
			"kind":       "Component",
			"type":       "service",
			"lifecycle":  "production",
			"owner":      "group:platform/security",
			"system":     "security",
			"repository": "WriterInternal/cerebro",
		},
		Payload: mustJSON(t, map[string]any{
			"kind": "Component",
			"metadata": map[string]any{
				"name":      "cerebro",
				"namespace": "default",
			},
		}),
	}

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 4 {
		t.Fatalf("EntitiesProjected = %d, want 4", result.EntitiesProjected)
	}
	serviceURN := "urn:cerebro:writer:service:component/default/cerebro"
	ownerURN := "urn:cerebro:writer:owner:platform/security"
	systemURN := "urn:cerebro:writer:system:security"
	repoURN := "urn:cerebro:writer:github_repo:WriterInternal/cerebro"
	entity := state.entities[serviceURN]
	if entity == nil || entity.EntityType != "service" || entity.Attributes["lifecycle"] != "production" {
		t.Fatalf("service entity = %#v, want production service", entity)
	}
	assertProjectedLink(t, state, serviceURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, serviceURN, relationBelongsTo, systemURN)
	assertProjectedLink(t, state, serviceURN, relationBelongsTo, repoURN)
}

func TestProjectSecurityToolingMapTool(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-2",
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.tool",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"tool_id":         "agent-gateway",
			"name":            "agent-gateway",
			"org":             "WriterInternal",
			"repo":            "agent-gateway",
			"status":          "beta",
			"lifecycle_owner": "Security",
			"categories":      "ai_security,dlp",
			"depends_on":      "security",
			"overlaps_with":   "cosmo",
		},
		Payload: mustJSON(t, map[string]any{"id": "agent-gateway", "name": "agent-gateway"}),
	}

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 7 {
		t.Fatalf("EntitiesProjected = %d, want 7", result.EntitiesProjected)
	}
	toolURN := "urn:cerebro:writer:security_tool:agent-gateway"
	ownerURN := "urn:cerebro:writer:owner:security"
	repoURN := "urn:cerebro:writer:github_repo:WriterInternal/agent-gateway"
	assertProjectedLink(t, state, toolURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, toolURN, relationBelongsTo, repoURN)
	assertProjectedLink(t, state, toolURN, relationHasClassification, "urn:cerebro:writer:security_category:ai_security")
	assertProjectedLink(t, state, toolURN, relationHasClassification, "urn:cerebro:writer:security_category:dlp")
	assertProjectedLink(t, state, toolURN, relationDependsOn, "urn:cerebro:writer:security_tool:security")
	assertProjectedLink(t, state, toolURN, relationAffects, "urn:cerebro:writer:security_tool:cosmo")
}

func TestProjectSecurityToolingMapControlMapping(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-3",
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.control_mapping",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"tool_id":      "agent-gateway",
			"control_id":   "CC6.1",
			"control_name": "Logical access",
			"framework":    "SOC2",
			"coverage":     "partial",
		},
		Payload: mustJSON(t, map[string]any{"tool_id": "agent-gateway", "control_id": "CC6.1"}),
	}

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 2 || result.LinksProjected != 1 {
		t.Fatalf("Project() = entities %d links %d, want 2/1", result.EntitiesProjected, result.LinksProjected)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:security_tool:agent-gateway", relationSupports, "urn:cerebro:writer:control:SOC2:CC6.1")
}
