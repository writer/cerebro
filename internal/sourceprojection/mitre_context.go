package sourceprojection

import (
	"context"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/mitre"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitytooling"
)

func mitreContextInput(attrs map[string]string) (mitre.ContextInput, bool) {
	attackTagValues := mitreAttributeValues(attrs, mitreAttackTagAttributeKeys...)
	input := mitre.ContextInput{
		AttackTacticValues: append(
			mitreAttributeValues(attrs, mitreAttackTacticAttributeKeys...),
			attackTagValues...,
		),
		AttackTechniqueValues:   mitreAttributeValues(attrs, mitreAttackTechniqueAttributeKeys...),
		AttackTechniqueIDValues: attackTagValues,
		DefendTacticValues:      mitreAttributeValues(attrs, mitreDefendTacticAttributeKeys...),
		DefendTechniqueValues:   mitreAttributeValues(attrs, mitreDefendTechniqueAttributeKeys...),
		DefendArtifactValues:    mitreAttributeValues(attrs, mitreDefendArtifactAttributeKeys...),
	}
	if len(input.AttackTacticValues) == 0 &&
		len(input.AttackTechniqueValues) == 0 &&
		len(input.AttackTechniqueIDValues) == 0 &&
		len(input.DefendTacticValues) == 0 &&
		len(input.DefendTechniqueValues) == 0 &&
		len(input.DefendArtifactValues) == 0 {
		return mitre.ContextInput{}, false
	}
	return input, true
}

type mitreProjectionTargets struct {
	contextURNs       []string
	attackContextURNs []string
	supportToolURN    string
}

func addMITREProjectionContext(ctx context.Context, event *cerebrov1.EventEnvelope, projectedEntities []*ports.ProjectedEntity, projectedLinks []*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	input, present := mitreContextInput(event.GetAttributes())
	if !present {
		return projectedEntities, projectedLinks, nil
	}
	entities, links := projectionMaps(projectedEntities, projectedLinks)
	targets := findMITREProjectionTargets(event, entities)
	if len(targets.contextURNs) == 0 && len(targets.attackContextURNs) == 0 && targets.supportToolURN == "" {
		return projectedEntities, projectedLinks, nil
	}
	mitreContext, err := mitre.EvaluateContext(ctx, input)
	if err != nil {
		return nil, nil, err
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	for _, urn := range targets.contextURNs {
		addMITREContextLinks(entities, links, tenantID, event, urn, mitreContext)
	}
	for _, urn := range targets.attackContextURNs {
		addMITREAttackContextLinks(entities, links, tenantID, event, urn, mitreContext)
	}
	if targets.supportToolURN != "" {
		addSecurityToolingMITRESupportLinks(entities, links, tenantID, event, targets.supportToolURN, mitreContext)
	}
	entitiesOut, linksOut := entitiesAndLinks(entities, links)
	return entitiesOut, linksOut, nil
}

func findMITREProjectionTargets(event *cerebrov1.EventEnvelope, entities map[string]*ports.ProjectedEntity) mitreProjectionTargets {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	targets := mitreProjectionTargets{}
	addContextURN := func(urn string) {
		if urn = strings.TrimSpace(urn); urn != "" && entities[urn] != nil {
			targets.contextURNs = append(targets.contextURNs, urn)
		}
	}
	addAttackContextURN := func(urn string) {
		if urn = strings.TrimSpace(urn); urn != "" && entities[urn] != nil {
			targets.attackContextURNs = append(targets.attackContextURNs, urn)
		}
	}

	primaryResourceID := cloudResourceProjectionID(attrs)
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		provider := normalizeCloudProvider(entity.Attributes["resource_provider"])
		resourceType := strings.TrimSpace(entity.Attributes["resource_type"])
		resourceID := strings.TrimSpace(entity.Attributes["resource_id"])
		primaryResourceType := cloudResourceProjectionType(event, provider, attrs)
		primaryResourceURN := firstNonEmpty(attrs["resource_urn"], projectionURN(tenantID, provider+"_"+primaryResourceType, primaryResourceID))
		if provider == "" || resourceType == "" || resourceID == "" || resourceID != primaryResourceID || resourceType != primaryResourceType || entity.URN != primaryResourceURN || entity.EntityType != provider+"."+strings.ReplaceAll(resourceType, "_", ".") {
			continue
		}
		addContextURN(entity.URN)
		if family := cloudFindingFamily(event, provider, attrs); family != "" {
			addContextURN(projectionURN(tenantID, "security_finding", provider, cloudFindingID(event, attrs)))
		}
		break
	}

	switch strings.TrimSpace(event.GetKind()) {
	case "grc.policy_rule":
		addContextURN(grcPolicyRuleURN(tenantID, grcProvider(attrs), firstAttribute(attrs, "policy_rule_id", "rule_id", "external_id")))
	case "grc.evidence_requirement":
		addContextURN(grcEvidenceRequirementURN(tenantID, grcProvider(attrs), grcEvidenceRequirementID(attrs)))
	case "grc.coverage_gap":
		addContextURN(grcCoverageGapURN(tenantID, grcProvider(attrs), grcCoverageGapID(attrs)))
	case "sentinelone.threat":
		addAttackContextURN(sentinelOneThreatURN(tenantID, strings.TrimSpace(attrs["threat_id"])))
	case "security_tooling_map.control_mapping":
		toolID := firstNonEmpty(attrs["tool_id"], attrs["tool_name"])
		controlURN := projectionURN(tenantID, "control", firstNonEmpty(attrs["framework"], "security"), attrs["control_id"])
		toolURN := projectionURN(tenantID, "security_tool", toolID)
		addContextURN(controlURN)
		if entities[toolURN] != nil {
			targets.supportToolURN = toolURN
		}
	}
	return targets
}

func addSecurityToolingMITRESupportLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, toolURN string, mitreContext mitre.Context) {
	attrs := event.GetAttributes()
	coverageStatus := firstNonEmpty(attrs["coverage_status"], securitytooling.CoverageStatus(attrs["coverage"]))
	coverageAttrs := compactAttributes(map[string]string{
		"event_id":         event.GetId(),
		"coverage":         attrs["coverage"],
		"coverage_status":  coverageStatus,
		"evidence_surface": attrs["evidence_surface"],
		"framework":        attrs["framework"],
		"control_id":       attrs["control_id"],
		"mapping_id":       attrs["mapping_id"],
		"relationship":     "security_tooling_coverage",
	})
	attackTechniqueURNs := addMITREAttackTechniqueLinks(entities, links, tenantID, event, toolURN, relationSupports, mitreContext.AttackTechniques, coverageAttrs)
	addMITREAttackTacticLinks(entities, links, tenantID, event, toolURN, relationSupports, mitreContext.AttackTactics, coverageAttrs)
	defendTechniqueURNs := addMITREDefendTechniqueLinks(entities, links, tenantID, event, toolURN, relationSupports, mitreContext.DefendTechniques, coverageAttrs)
	addMITREDefendTacticLinks(entities, links, tenantID, event, toolURN, relationSupports, mitreContext.DefendTactics, coverageAttrs)
	addMITREDefendArtifactLinks(entities, links, tenantID, event, toolURN, relationSupports, mitreContext.DefendArtifacts, coverageAttrs)
	for _, defendTechniqueURN := range defendTechniqueURNs {
		for _, attackTechniqueURN := range attackTechniqueURNs {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), defendTechniqueURN, attackTechniqueURN, relationSupports, compactAttributes(map[string]string{
				"event_id":         event.GetId(),
				"coverage":         attrs["coverage"],
				"coverage_status":  coverageStatus,
				"evidence_surface": attrs["evidence_surface"],
				"framework":        attrs["framework"],
				"control_id":       attrs["control_id"],
				"mapping_id":       attrs["mapping_id"],
				"relationship":     "defends_against",
			})))
		}
	}
}
