package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/mitre"
)

// The backstage.component projection tests that used to live here
// (TestProjectBackstageComponent and its canonicalization/classification/
// Kubernetes-runtime/no-owner variants) were removed along with the real
// backstageComponentProjections implementation once Backstage's Go
// projection writer was retired to Rust authority (see backstage.go,
// backstage_test.go). TestRegistryRoutesBackstageDeclaredKinds below still
// confirms backstage.component stays routed (to the fail-closed stub).

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
	coverageURN := mitre.AttackCoverageURN("writer", toolURN, attackTechniqueURN)
	coverage := state.entities[coverageURN]
	if coverage == nil || coverage.EntityType != mitre.AttackCoverageEntityType {
		t.Fatalf("coverage entity = %#v, want MITRE ATT&CK coverage node", coverage)
	}
	if got := coverage.Attributes["coverage_state"]; got != "gap" {
		t.Fatalf("coverage_state = %q, want gap", got)
	}
	if got := coverage.Attributes["evidence_surface"]; got != "endpoint" {
		t.Fatalf("evidence_surface = %q, want endpoint", got)
	}
	assertProjectedLink(t, state, toolURN, relationHasContext, coverageURN)
	assertProjectedLink(t, state, coverageURN, relationSupports, attackTechniqueURN)
	componentURN := securitySpineEntityURNByAttribute(state, mitre.AttackDataComponentEntityType, "data_component_name", "Application Log Content")
	if componentURN == "" {
		t.Fatalf("MITRE ATT&CK data component Application Log Content missing: %#v", state.entities)
	}
	sourceURN := securitySpineEntityURNByAttribute(state, mitre.AttackDataSourceEntityType, "data_source_id", "DS0015")
	if sourceURN == "" {
		t.Fatalf("MITRE ATT&CK data source DS0015 missing: %#v", state.entities)
	}
	assertProjectedLink(t, state, coverageURN, relationHasEvidence, componentURN)
	assertProjectedLink(t, state, componentURN, relationSupports, attackTechniqueURN)
	assertProjectedLink(t, state, componentURN, relationBelongsTo, sourceURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:mitre_defend_technique:InboundTrafficFiltering", relationSupports, attackTechniqueURN)
}

func securitySpineEntityURNByAttribute(recorder *projectionRecorder, entityType string, key string, value string) string {
	if recorder == nil {
		return ""
	}
	for _, entity := range recorder.entities {
		if entity == nil || entity.EntityType != entityType {
			continue
		}
		if entity.Attributes[key] == value {
			return entity.URN
		}
	}
	return ""
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
