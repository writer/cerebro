package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcRiskScenarioProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	riskID := firstAttribute(ctx.attrs, "risk_id", "risk_register_id", "external_id")
	if riskID == "" {
		return nil, nil, nil
	}
	riskURN := projectionURN(ctx.tenantID, "claim", ctx.provider, "risk_scenario", riskID)
	ctx.addResourceEntity(
		riskURN,
		"claim",
		firstAttribute(ctx.attrs, "title", "description", "risk_statement", "risk_id"),
		map[string]string{
			"claim_type":          "risk_scenario",
			"impact":              firstAttribute(ctx.attrs, "impact", "impact_level"),
			"inherent_risk_level": firstAttribute(ctx.attrs, "inherent_risk_level", "inherent_risk", "risk_level"),
			"likelihood":          firstAttribute(ctx.attrs, "likelihood", "likelihood_level"),
			"predicate":           firstAttribute(ctx.attrs, "risk_statement", "description"),
			"residual_risk_level": firstAttribute(ctx.attrs, "residual_risk_level", "residual_risk"),
			"review_due_at":       firstAttribute(ctx.attrs, "review_due_at", "next_review_due_at", "due_at"),
			"risk_category":       firstAttribute(ctx.attrs, "risk_category", "category", "domain"),
			"risk_id":             riskID,
			"source_system":       ctx.provider,
			"status":              firstAttribute(ctx.attrs, "status", "risk_status", "review_status"),
			"treatment":           firstAttribute(ctx.attrs, "treatment", "treatment_plan", "response", "mitigation"),
			"treatment_due_at":    firstAttribute(ctx.attrs, "treatment_due_at", "mitigation_due_at", "target_due_at"),
		},
	)
	if owner := firstAttribute(ctx.attrs, "owner", "risk_owner", "owner_email"); owner != "" {
		ownerURN := projectionURN(ctx.tenantID, "contact", ctx.provider, "owner", owner)
		ctx.addReferenceEntity(ownerURN, "contact", owner, map[string]string{"source_system": ctx.provider, "owner": owner})
		ctx.addEventLink(riskURN, ownerURN, relationAssignedTo)
		addGRCRiskOwnerEmailLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ownerURN, owner)
	}
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "risk_owner_user_id"))
	addGRCPolicyLifecycleSubjectLinks(ctx, riskURN, firstAttribute(ctx.attrs, "policy_id"), firstAttribute(ctx.attrs, "policy_version_id", "version_id"))
	addGRCControlAssociationLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, ctx.provider, relationAssociatedWith, "grc_risk_scenario")
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, ctx.provider, ctx.attrs)
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, ctx.provider, ctx.attrs, relationTargeted, "grc_risk_scenario")
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, "grc_risk_category", firstAttribute(ctx.attrs, "risk_category", "category", "domain"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, riskURN, "grc_risk_level", firstAttribute(ctx.attrs, "residual_risk_level", "residual_risk", "inherent_risk_level", "inherent_risk", "risk_level"))
	entities, links := ctx.done()
	return entities, links, nil
}

func addGRCRiskOwnerEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, contactURN string, owner string) {
	addSecurityContactEmailLink(entities, links, tenantID, sourceID, event, contactURN, owner, "owner")
}
