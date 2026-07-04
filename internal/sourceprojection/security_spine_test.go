package sourceprojection

import (
	"context"
	"strings"
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
	if result.EntitiesProjected != 7 {
		t.Fatalf("EntitiesProjected = %d, want 7", result.EntitiesProjected)
	}
	serviceURN := "urn:cerebro:writer:service:component/default/cerebro"
	ownerURN := "urn:cerebro:writer:owner:platform/security"
	ownerIdentifierURN := "urn:cerebro:writer:identifier:login:security"
	systemURN := "urn:cerebro:writer:system:security"
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/cerebro"
	orgURN := "urn:cerebro:writer:github_org:WriterInternal"
	entity := state.entities[serviceURN]
	if entity == nil || entity.EntityType != "service" || entity.Attributes["lifecycle"] != "production" {
		t.Fatalf("service entity = %#v, want production service", entity)
	}
	assertProjectedLink(t, state, serviceURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, serviceURN, relationBelongsTo, systemURN)
	assertProjectedLink(t, state, serviceURN, relationBelongsTo, repoURN)
	assertProjectedLink(t, state, repoURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, ownerURN, relationHasIdentifier, ownerIdentifierURN)
	assertProjectedLink(t, state, ownerURN, relationHasIdentifier, "urn:cerebro:writer:identifier:login:platform/security")
	assertProjectedLinkMissing(t, state, ownerURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:login:security")
}

func TestProjectBackstageComponentCanonicalizesEntityRef(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "evt-backstage-canonical",
		TenantId: "writer",
		SourceId: "backstage",
		Kind:     "backstage.component",
		Attributes: map[string]string{
			"name":       "payments",
			"namespace":  "default",
			"kind":       "Component",
			"entity_ref": "component:default/payments",
			"type":       "service",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	serviceURN := "urn:cerebro:writer:service:component/default/payments"
	entity := state.entities[serviceURN]
	if entity == nil {
		t.Fatalf("service entity %q missing from %#v", serviceURN, state.entities)
	}
	if got := entity.Attributes["backstage_entity_ref"]; got != "component/default/payments" {
		t.Fatalf("backstage_entity_ref = %q, want canonical component/default/payments", got)
	}
}

func TestProjectBackstageComponentLinksClassificationAndCriticality(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-backstage-classification",
		TenantId:   "writer",
		SourceId:   "backstage",
		Kind:       "backstage.component",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"name":        "payments",
			"namespace":   "default",
			"kind":        "Component",
			"type":        "service",
			"data_class":  "restricted",
			"criticality": "tier0",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceURN := "urn:cerebro:writer:service:component/default/payments"
	assertProjectedLink(t, state, serviceURN, relationHasClassification, "urn:cerebro:writer:data_classification:restricted")
	assertProjectedLink(t, state, serviceURN, relationTaggedAs, "urn:cerebro:writer:asset_tag:criticality:tier0")
	assertProjectedLink(t, state, serviceURN, relationTaggedAs, "urn:cerebro:writer:asset_tag:crown_jewel")
}

func TestProjectBackstageComponentLinksKubernetesRuntime(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-k8s",
		TenantId:   "writer",
		SourceId:   "backstage",
		Kind:       "backstage.component",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"name":      "cerebro",
			"namespace": "default",
			"type":      "service",
		},
		Payload: mustJSON(t, map[string]any{
			"kind": "Component",
			"metadata": map[string]any{
				"name":      "cerebro",
				"namespace": "default",
				"annotations": map[string]any{
					"backstage.io/kubernetes-id":            "cerebro",
					"backstage.io/kubernetes-namespace":     "security",
					"cerebro.io/aws-account-id":             "123456789012",
					"cerebro.io/cloud-provider":             "aws",
					"cerebro.io/kubernetes-cluster-id":      "prod-us1",
					"cerebro.io/kubernetes-service-account": "cerebro-sa",
					"cerebro.io/kubernetes-workload-kind":   "Deployment",
				},
			},
		}),
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceURN := "urn:cerebro:writer:service:component/default/cerebro"
	workloadURN := "urn:cerebro:writer:kubernetes_workload:prod-us1:security:Deployment/cerebro"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-us1:security"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-us1"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-us1:security:cerebro-sa"
	assertProjectedLink(t, state, serviceURN, relationRepresents, workloadURN)
	assertProjectedLink(t, state, workloadURN, relationRepresents, serviceURN)
	assertProjectedLink(t, state, workloadURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, namespaceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, workloadURN, relationRunsAs, serviceAccountURN)
}

func TestRegistryRoutesBackstageDeclaredKinds(t *testing.T) {
	declared := []string{
		"backstage.component",
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, kind := range declared {
		if _, ok := registered[kind]; !ok {
			t.Fatalf("declared Backstage kind %q is not routed in the projection registry", kind)
		}
	}
}

func TestProjectBackstageComponentWithoutOwnerOmitsOwnerLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-backstage-unowned",
		TenantId:   "writer",
		SourceId:   "backstage",
		Kind:       "backstage.component",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"name":        "ledger",
			"namespace":   "default",
			"kind":        "Component",
			"type":        "service",
			"criticality": "tier0",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceURN := "urn:cerebro:writer:service:component/default/ledger"
	if state.entities[serviceURN] == nil {
		t.Fatalf("component entity %q was not projected", serviceURN)
	}
	for key := range state.links {
		if strings.Contains(key, "|"+relationOwnedBy+"|") {
			t.Fatalf("unexpected ownership link %q for component without an owner", key)
		}
	}
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
			"consumed_by":     "cosmo,iris",
			"overlaps_with":   "cosmo",
		},
		Payload: mustJSON(t, map[string]any{"id": "agent-gateway", "name": "agent-gateway"}),
	}

	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 10 {
		t.Fatalf("EntitiesProjected = %d, want 10", result.EntitiesProjected)
	}
	toolURN := "urn:cerebro:writer:security_tool:agent-gateway"
	ownerURN := "urn:cerebro:writer:owner:security"
	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/agent-gateway"
	orgURN := "urn:cerebro:writer:github_org:WriterInternal"
	assertProjectedLink(t, state, toolURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, ownerURN, relationHasIdentifier, "urn:cerebro:writer:identifier:login:security")
	assertProjectedLink(t, state, toolURN, relationBelongsTo, repoURN)
	assertProjectedLink(t, state, repoURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, toolURN, relationHasClassification, "urn:cerebro:writer:security_category:ai_security")
	assertProjectedLink(t, state, toolURN, relationHasClassification, "urn:cerebro:writer:security_category:dlp")
	assertProjectedLink(t, state, toolURN, relationDependsOn, "urn:cerebro:writer:security_tool:security")
	assertProjectedLink(t, state, "urn:cerebro:writer:security_tool:cosmo", relationDependsOn, toolURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:security_tool:iris", relationDependsOn, toolURN)
	assertProjectedLink(t, state, toolURN, relationAffects, "urn:cerebro:writer:security_tool:cosmo")
	consumerLink := state.links["urn:cerebro:writer:security_tool:cosmo|"+relationDependsOn+"|"+toolURN]
	if got := consumerLink.Attributes["relationship"]; got != "consumed_by" {
		t.Fatalf("consumer link relationship = %q, want consumed_by", got)
	}
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

func TestProjectSecurityToolingMapControlMappingLinksMITRECoverage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-mitre-coverage",
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.control_mapping",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"mapping_id":       "agent-gateway-t1190-token-binding",
			"tool_id":          "agent-gateway",
			"control_id":       "CC6.1",
			"control_name":     "Logical access",
			"framework":        "SOC2",
			"coverage":         "partial",
			"coverage_status":  "gap",
			"attack_tactic":    "Initial Access",
			"attack_technique": "T1190",
			"d3fend_technique": "TokenBinding",
			"d3fend_artifact":  "AuthorizationToken",
			"evidence_surface": "endpoint",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	toolURN := "urn:cerebro:writer:security_tool:agent-gateway"
	controlURN := "urn:cerebro:writer:control:SOC2:CC6.1"
	attackTacticURN := "urn:cerebro:writer:mitre_attack_tactic:TA0001"
	attackTechniqueURN := "urn:cerebro:writer:mitre_attack_technique:T1190"
	defendTechniqueURN := "urn:cerebro:writer:mitre_defend_technique:TokenBinding"
	defendArtifactURN := "urn:cerebro:writer:mitre_defend_artifact:AuthorizationToken"
	assertProjectedLink(t, state, controlURN, relationHasContext, attackTacticURN)
	assertProjectedLink(t, state, controlURN, relationHasContext, attackTechniqueURN)
	assertProjectedLink(t, state, controlURN, relationHasContext, defendTechniqueURN)
	assertProjectedLink(t, state, controlURN, relationHasContext, defendArtifactURN)
	assertProjectedLink(t, state, toolURN, relationSupports, attackTacticURN)
	assertProjectedLink(t, state, toolURN, relationSupports, attackTechniqueURN)
	assertProjectedLink(t, state, toolURN, relationSupports, defendTechniqueURN)
	assertProjectedLink(t, state, toolURN, relationSupports, defendArtifactURN)
	assertProjectedLink(t, state, defendTechniqueURN, relationSupports, attackTechniqueURN)
	if got := state.links[toolURN+"|"+relationSupports+"|"+attackTechniqueURN].Attributes["coverage_status"]; got != "gap" {
		t.Fatalf("tool attack coverage_status = %q, want gap", got)
	}
	if got := state.links[defendTechniqueURN+"|"+relationSupports+"|"+attackTechniqueURN].Attributes["relationship"]; got != "defends_against" {
		t.Fatalf("defend attack relationship = %q, want defends_against", got)
	}
}

func TestRegistryRoutesSecurityToolingMapDeclaredKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"security_tooling_map.tool", map[string]string{"tool_id": "agent-gateway", "name": "agent-gateway"}, "security.tool"},
		{"security_tooling_map.control_mapping", map[string]string{"tool_id": "agent-gateway", "control_id": "CC6.1", "framework": "SOC2", "coverage": "partial"}, "control"},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if _, ok := registered[tc.kind]; !ok {
				t.Fatalf("declared security tooling map kind %q is not routed in the projection registry", tc.kind)
			}
			event := &cerebrov1.EventEnvelope{
				Id:         "evt-" + tc.kind,
				TenantId:   "writer",
				SourceId:   "security_tooling_map",
				Kind:       tc.kind,
				OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
				Attributes: tc.attrs,
			}
			entities, _, err := BuiltinRegistry().Project(event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}

func TestProjectSecurityToolingMapControlMappingAnnotatesCoverageGap(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-coverage-gap",
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.control_mapping",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"tool_id":         "agent-gateway",
			"control_id":      "CC6.1",
			"control_name":    "Logical access",
			"framework":       "SOC2",
			"coverage":        "partial",
			"coverage_status": "gap",
		},
		Payload: mustJSON(t, map[string]any{"tool_id": "agent-gateway", "control_id": "CC6.1"}),
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	toolURN := "urn:cerebro:writer:security_tool:agent-gateway"
	controlURN := "urn:cerebro:writer:control:SOC2:CC6.1"
	control := state.entities[controlURN]
	if control == nil || control.Attributes["coverage_status"] != "gap" {
		t.Fatalf("control entity = %#v, want coverage_status gap", control)
	}
	supportLink := state.links[toolURN+"|"+relationSupports+"|"+controlURN]
	if supportLink == nil || supportLink.Attributes["coverage_status"] != "gap" {
		t.Fatalf("support link = %#v, want coverage_status gap", supportLink)
	}
}

func TestProjectSecurityToolingMapControlMappingDerivesCoverageStatus(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-coverage-derived",
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.control_mapping",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"tool_id":    "agent-gateway",
			"control_id": "CC7.2",
			"framework":  "SOC2",
			"coverage":   "full",
		},
		Payload: mustJSON(t, map[string]any{"tool_id": "agent-gateway", "control_id": "CC7.2"}),
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	controlURN := "urn:cerebro:writer:control:SOC2:CC7.2"
	control := state.entities[controlURN]
	if control == nil || control.Attributes["coverage_status"] != "covered" {
		t.Fatalf("control entity = %#v, want derived coverage_status covered", control)
	}
}
