package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcPolicyRuleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	ruleID := firstAttribute(ctx.attrs, "policy_rule_id", "rule_id", "external_id")
	if ruleID == "" {
		return nil, nil, nil
	}
	ruleURN := grcPolicyRuleURN(ctx.tenantID, ctx.provider, ruleID)
	ctx.addResourceEntity(
		ruleURN,
		"policy.rule",
		firstAttribute(ctx.attrs, "name", "title", "policy_rule_name", "rule_name", "policy_rule_id", "rule_id"),
		map[string]string{
			"claim_strength":   firstAttribute(ctx.attrs, "claim_strength"),
			"coverage_claim":   firstAttribute(ctx.attrs, "coverage_claim"),
			"entity_type":      firstAttribute(ctx.attrs, "entity_type", "required_entity_type"),
			"policy_rule_id":   ruleID,
			"profile_id":       firstAttribute(ctx.attrs, "profile_id", "control_profile_id"),
			"rule_id":          ruleID,
			"source_system":    ctx.provider,
			"status":           firstAttribute(ctx.attrs, "status", "rule_status", "lifecycle_state"),
			"sufficiency_rule": firstAttribute(ctx.attrs, "sufficiency_rule"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, ruleURN, firstAttribute(ctx.attrs, "policy_id"), firstAttribute(ctx.attrs, "policy_version_id", "version_id"))
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider)
	addMITREAttackContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, ruleURN, ctx.attrs)
	addMITREDefendContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, ruleURN, ctx.attrs)
	addGRCEvidenceRequirementReferenceLinks(ctx, ruleURN)
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider, ctx.attrs, relationTargeted, "grc_policy_rule")
	addGRCIntegrationLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider, firstAttribute(ctx.attrs, "integration_id", "integration_ids", "required_source_id", "evidence_source_id"), "grc_policy_rule")
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "control_owner_user_id", "policy_owner_user_id"))
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, "policy_rule_profile", firstAttribute(ctx.attrs, "profile_id", "control_profile_id"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, "policy_rule_source", firstAttribute(ctx.attrs, "required_source_id", "evidence_source_id", "source_id"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ruleURN, "policy_rule_status", firstAttribute(ctx.attrs, "status", "rule_status", "lifecycle_state"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcEvidenceRequirementProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	requirementID := grcEvidenceRequirementID(ctx.attrs)
	if requirementID == "" {
		return nil, nil, nil
	}
	requirementURN := grcEvidenceRequirementURN(ctx.tenantID, ctx.provider, requirementID)
	ctx.addResourceEntity(
		requirementURN,
		"evidence.requirement",
		firstAttribute(ctx.attrs, "name", "title", "requirement_name", "profile_name", "evidence_requirement_id", "requirement_id"),
		map[string]string{
			"assessment_methods":      firstAttribute(ctx.attrs, "assessment_methods"),
			"claim_strength":          firstAttribute(ctx.attrs, "claim_strength"),
			"coverage_claim":          firstAttribute(ctx.attrs, "coverage_claim"),
			"entity_type":             firstAttribute(ctx.attrs, "entity_type", "required_entity_type"),
			"evidence_requirement_id": requirementID,
			"freshness_window":        firstAttribute(ctx.attrs, "freshness_window", "freshness_sla"),
			"profile_id":              firstAttribute(ctx.attrs, "profile_id", "control_profile_id"),
			"required_fields":         firstAttribute(ctx.attrs, "required_fields"),
			"required_source_id":      firstAttribute(ctx.attrs, "required_source_id", "evidence_source_id", "source_id"),
			"requirement_id":          requirementID,
			"source_system":           ctx.provider,
			"status":                  firstAttribute(ctx.attrs, "status", "requirement_status", "lifecycle_state"),
			"sufficiency_rule":        firstAttribute(ctx.attrs, "sufficiency_rule"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, requirementURN, firstAttribute(ctx.attrs, "policy_id"), firstAttribute(ctx.attrs, "policy_version_id", "version_id"))
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, ctx.provider)
	addMITREAttackContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, requirementURN, ctx.attrs)
	addMITREDefendContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, requirementURN, ctx.attrs)
	addGRCPolicyRuleReferenceLinks(ctx, requirementURN)
	addGRCIntegrationLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, ctx.provider, firstAttribute(ctx.attrs, "integration_id", "integration_ids", "required_source_id", "evidence_source_id"), "grc_evidence_requirement")
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "control_owner_user_id", "policy_owner_user_id"))
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, "evidence_requirement_profile", firstAttribute(ctx.attrs, "profile_id", "control_profile_id"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, "evidence_requirement_source", firstAttribute(ctx.attrs, "required_source_id", "evidence_source_id", "source_id"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, requirementURN, "evidence_requirement_status", firstAttribute(ctx.attrs, "status", "requirement_status", "lifecycle_state"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcCoverageGapProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	gapID := grcCoverageGapID(ctx.attrs)
	if gapID == "" {
		return nil, nil, nil
	}
	gapURN := grcCoverageGapURN(ctx.tenantID, ctx.provider, gapID)
	ctx.addResourceEntity(
		gapURN,
		"coverage.gap",
		firstAttribute(ctx.attrs, "name", "title", "gap_title", "coverage_gap_id", "gap_id"),
		map[string]string{
			"coverage_gap_id": gapID,
			"gap_id":          gapID,
			"gap_state":       firstAttribute(ctx.attrs, "gap_state", "status"),
			"gap_type":        firstAttribute(ctx.attrs, "gap_type", "coverage_gap_type"),
			"owner_id":        firstAttribute(ctx.attrs, "owner_id", "control_owner_user_id", "policy_owner_user_id"),
			"severity":        firstAttribute(ctx.attrs, "severity", "risk_level"),
			"source_system":   ctx.provider,
			"status":          firstAttribute(ctx.attrs, "status", "gap_state", "lifecycle_state"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, gapURN, firstAttribute(ctx.attrs, "policy_id"), firstAttribute(ctx.attrs, "policy_version_id", "version_id"))
	addGRCCoverageGapControlLinks(ctx, gapURN)
	addMITREAttackContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, gapURN, ctx.attrs)
	addMITREDefendContextLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.event, gapURN, ctx.attrs)
	addGRCPolicyRuleReferenceLinks(ctx, gapURN)
	addGRCEvidenceRequirementReferenceLinks(ctx, gapURN)
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, ctx.provider, ctx.attrs, relationTargeted, "grc_coverage_gap")
	addGRCIntegrationLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, ctx.provider, firstAttribute(ctx.attrs, "integration_id", "integration_ids", "required_source_id", "evidence_source_id"), "grc_coverage_gap")
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "control_owner_user_id", "policy_owner_user_id"))
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, "coverage_gap_status", firstAttribute(ctx.attrs, "status", "gap_state", "lifecycle_state"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, "coverage_gap_severity", firstAttribute(ctx.attrs, "severity", "risk_level"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, gapURN, "coverage_gap_type", firstAttribute(ctx.attrs, "gap_type", "coverage_gap_type"))
	entities, links := ctx.done()
	return entities, links, nil
}

func addGRCPolicyRuleReferenceLinks(ctx *grcProjectionContext, fromURN string) {
	if fromURN == "" {
		return
	}
	for _, ruleID := range grcPolicyRuleRefs(ctx.attrs) {
		ruleURN := grcPolicyRuleURN(ctx.tenantID, ctx.provider, ruleID)
		if ruleURN == "" || ruleURN == fromURN {
			continue
		}
		ctx.addReferenceEntity(
			ruleURN,
			"policy.rule",
			firstAttribute(ctx.attrs, "policy_rule_name", "rule_name", "policy_rule_id"),
			map[string]string{"policy_rule_id": ruleID, "rule_id": ruleID, "source_system": ctx.provider},
		)
		addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, fromURN, ruleURN, relationAssociatedWith, map[string]string{
			"event_id":         ctx.event.GetId(),
			"match_type":       "grc_policy_rule_reference",
			"policy_rule_id":   ruleID,
			"source_reference": "policy_rule",
		}))
	}
}

func addGRCEvidenceRequirementReferenceLinks(ctx *grcProjectionContext, fromURN string) {
	if fromURN == "" {
		return
	}
	for _, requirementID := range grcEvidenceRequirementRefs(ctx.attrs) {
		requirementURN := grcEvidenceRequirementURN(ctx.tenantID, ctx.provider, requirementID)
		if requirementURN == "" || requirementURN == fromURN {
			continue
		}
		ctx.addReferenceEntity(
			requirementURN,
			"evidence.requirement",
			firstAttribute(ctx.attrs, "requirement_name", "profile_name", "evidence_requirement_id", "requirement_id"),
			map[string]string{"evidence_requirement_id": requirementID, "requirement_id": requirementID, "source_system": ctx.provider},
		)
		addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, fromURN, requirementURN, relationAssociatedWith, map[string]string{
			"event_id":                ctx.event.GetId(),
			"evidence_requirement_id": requirementID,
			"match_type":              "grc_evidence_requirement_reference",
			"source_reference":        "evidence_requirement",
		}))
	}
}

func addGRCCoverageGapControlLinks(ctx *grcProjectionContext, fromURN string) {
	if fromURN == "" {
		return
	}
	for _, controlRef := range grcControlReferences(ctx.attrs) {
		controlURN := projectionURN(ctx.tenantID, "policy", ctx.provider, "control", controlRef.id)
		if controlURN == "" {
			continue
		}
		if controlRef.externalID != "" || !controlRef.paired {
			controlAttrs := map[string]string{"control_id": controlRef.id, "policy_id": controlRef.id, "policy_type": "control", "source_system": ctx.provider}
			if controlRef.externalID != "" {
				controlAttrs["control_external_id"] = controlRef.externalID
			}
			ctx.addReferenceEntity(controlURN, "policy", firstNonEmptyString(controlRef.externalID, controlRef.id), controlAttrs)
		}
		linkAttrs := map[string]string{
			"control_id":      controlRef.id,
			"coverage_status": "gap",
			"event_id":        ctx.event.GetId(),
			"match_type":      "grc_coverage_gap_control",
			"relationship":    relationSupports,
		}
		if controlRef.externalID != "" {
			linkAttrs["control_external_id"] = controlRef.externalID
		}
		addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, fromURN, controlURN, relationSupports, linkAttrs))
	}
}

func grcPolicyRuleRefs(attrs map[string]string) []string {
	return grcPolicyCatalogRefs(
		attrs["policy_rule_id"],
		attrs["policy_rule_ids"],
		attrs["policy_rule_ref"],
		attrs["policy_rule_refs"],
	)
}

func grcEvidenceRequirementRefs(attrs map[string]string) []string {
	return grcPolicyCatalogRefs(
		attrs["evidence_requirement_id"],
		attrs["evidence_requirement_ids"],
		attrs["evidence_requirement_ref"],
		attrs["evidence_requirement_refs"],
		attrs["policy_evidence_requirement_ref"],
		attrs["policy_evidence_requirement_refs"],
		attrs["requirement_id"],
		attrs["requirement_ids"],
		attrs["requirement_ref"],
		attrs["requirement_refs"],
	)
}

func grcPolicyCatalogRefs(rawValues ...string) []string {
	refs := []string{}
	seen := map[string]struct{}{}
	for _, ref := range grcAttributeSequence(strings.Join(rawValues, ",")) {
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func grcEvidenceRequirementID(attrs map[string]string) string {
	if id := firstAttribute(attrs, "evidence_requirement_id", "requirement_id", "external_id"); id != "" {
		return id
	}
	return grcDerivedID(
		firstAttribute(attrs, "profile_id", "control_profile_id"),
		firstAttribute(attrs, "required_source_id", "evidence_source_id", "source_id"),
		firstAttribute(attrs, "entity_type", "required_entity_type"),
		firstAttribute(attrs, "control_id", "control_ids", "control_external_id", "control_external_ids"),
	)
}

func grcCoverageGapID(attrs map[string]string) string {
	if id := firstAttribute(attrs, "coverage_gap_id", "gap_id", "external_id"); id != "" {
		return id
	}
	return grcDerivedID(
		firstAttribute(attrs, "gap_type", "coverage_gap_type"),
		firstAttribute(attrs, "control_id", "control_ids", "control_external_id", "control_external_ids"),
		firstAttribute(attrs, "policy_rule_id", "policy_rule_ids"),
		firstAttribute(attrs, "evidence_requirement_id", "evidence_requirement_ids", "requirement_id", "requirement_ids"),
		firstAttribute(attrs, "target_id", "resource_id", "asset_id"),
	)
}

func grcPolicyRuleURN(tenantID string, provider string, ruleID string) string {
	return projectionURN(tenantID, "policy_rule", provider, ruleID)
}

func grcEvidenceRequirementURN(tenantID string, provider string, requirementID string) string {
	return projectionURN(tenantID, "evidence_requirement", provider, requirementID)
}

func grcCoverageGapURN(tenantID string, provider string, gapID string) string {
	return projectionURN(tenantID, "coverage_gap", provider, gapID)
}
