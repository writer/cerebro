package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func sdkIntegrationPostureEvent() *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "evt-sdk-posture-1",
		TenantId:   "writer",
		SourceId:   "sdk",
		Kind:       "sdk.integration_posture",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"integration":    "jira",
			"resource_urn":   "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer",
			"resource_type":  "workspace",
			"resource_label": "Writer Jira",
			"control":        "sso_enforced",
			"posture_status": "at_risk",
			"risk_reason":    "workspace allows password-only sign-in",
		},
	}
}

func TestRegistryRoutesSDKIntegrationPosture(t *testing.T) {
	registry := BuiltinRegistry()
	entities, links, err := registry.Project(sdkIntegrationPostureEvent())
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("registry did not route sdk.integration_posture: entities=%d links=%d", len(entities), len(links))
	}
}

func TestProjectSDKIntegrationPosture(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), sdkIntegrationPostureEvent())
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 3 || result.LinksProjected != 3 {
		t.Fatalf("Project() = entities %d links %d, want 3/3", result.EntitiesProjected, result.LinksProjected)
	}

	resourceURN := "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer"
	integrationURN := "urn:cerebro:writer:sdk_integration:jira"
	postureURN := "urn:cerebro:writer:sdk_integration_posture:jira:sso_enforced:resource-5035f700434eea4e6f45818655dcdc65"

	resource := state.entities[resourceURN]
	if resource == nil || resource.EntityType != "workspace" {
		t.Fatalf("resource entity = %#v, want workspace", resource)
	}
	if resource.Attributes["control"] != "" || resource.Attributes["posture_status"] != "" {
		t.Fatalf("resource attributes carry per-control posture fields: %#v", resource.Attributes)
	}
	integration := state.entities[integrationURN]
	if integration == nil || integration.EntityType != "sdk.integration" || integration.Label != "jira" {
		t.Fatalf("integration entity = %#v, want sdk.integration jira", integration)
	}
	posture := state.entities[postureURN]
	if posture == nil || posture.EntityType != "sdk.integration_posture" {
		t.Fatalf("posture entity = %#v, want sdk.integration_posture", posture)
	}
	if posture.Attributes["posture_status"] != "at_risk" || posture.Attributes["control"] != "sso_enforced" {
		t.Fatalf("posture attributes = %#v", posture.Attributes)
	}

	assertProjectedLink(t, state, resourceURN, relationHasEvidence, postureURN)
	assertProjectedLink(t, state, postureURN, relationObservedOn, resourceURN)
	assertProjectedLink(t, state, postureURN, relationBelongsTo, integrationURN)
}

func TestProjectSDKIntegrationPostureRejectsReservedTokenDelimiter(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := sdkIntegrationPostureEvent()
	event.Attributes["integration"] = "jira:prod"

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 0 || result.LinksProjected != 0 {
		t.Fatalf("Project() with colon token = entities %d links %d, want 0/0", result.EntitiesProjected, result.LinksProjected)
	}
}

func TestProjectSDKIntegrationPostureRejectsCrossTenantResourceURN(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := sdkIntegrationPostureEvent()
	event.Attributes["resource_urn"] = "urn:cerebro:acme:runtime:acme-sdk-jira-posture:workspace:acme"

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 0 || result.LinksProjected != 0 {
		t.Fatalf("Project() with cross-tenant resource = entities %d links %d, want 0/0", result.EntitiesProjected, result.LinksProjected)
	}
}

func TestSDKPostureResourceKeyKeepsUnscopedResourceDistinct(t *testing.T) {
	scoped := sdkPostureResourceKey("urn:cerebro:writer:foo:bar")
	unscoped := sdkPostureResourceKey("urn:cerebro:foo:bar")
	if scoped == unscoped {
		t.Fatalf("tenant-scoped and unscoped resource keys collided at %q", scoped)
	}
}

func TestSDKPostureResourceKeyAvoidsSlashColonCollision(t *testing.T) {
	slashSegment := sdkPostureResourceKey("urn:cerebro:writer:github_code_repository:writer/cerebro")
	colonSegment := sdkPostureResourceKey("urn:cerebro:writer:github_code_repository:writer:cerebro")
	if slashSegment == colonSegment {
		t.Fatalf("slash and colon resource keys collided at %q", slashSegment)
	}
}

func TestProjectSDKIntegrationPostureIsIdempotent(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	first, err := service.Project(context.Background(), sdkIntegrationPostureEvent())
	if err != nil {
		t.Fatalf("first Project() error = %v", err)
	}
	entitiesAfterFirst := len(state.entities)
	linksAfterFirst := len(state.links)

	second, err := service.Project(context.Background(), sdkIntegrationPostureEvent())
	if err != nil {
		t.Fatalf("second Project() error = %v", err)
	}
	if len(state.entities) != entitiesAfterFirst || len(state.links) != linksAfterFirst {
		t.Fatalf("duplicate projection changed graph: entities %d->%d links %d->%d", entitiesAfterFirst, len(state.entities), linksAfterFirst, len(state.links))
	}
	if first.EntitiesProjected != second.EntitiesProjected || first.LinksProjected != second.LinksProjected {
		t.Fatalf("duplicate projection counts differ: %+v vs %+v", first, second)
	}
}

func TestProjectSDKIntegrationPostureRequiresIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := sdkIntegrationPostureEvent()
	delete(event.Attributes, "resource_urn")

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 0 || result.LinksProjected != 0 {
		t.Fatalf("Project() without resource_urn = entities %d links %d, want 0/0", result.EntitiesProjected, result.LinksProjected)
	}
}
