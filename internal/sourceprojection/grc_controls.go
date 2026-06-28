package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcFrameworkProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "framework", "framework_id", []string{"display_name", "name", "framework_id"})
}

func grcControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "control", "control_id", []string{"control_external_id", "name", "control_id"})
}

func grcPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id", "external_id")
	if policyID == "" {
		return nil, nil, nil
	}
	policyURN := grcPolicyURN(ctx.tenantID, ctx.provider, policyID)
	ctx.addResourceEntity(
		policyURN,
		"policy",
		firstAttribute(ctx.attrs, "name", "title", "policy_name", "policy_id"),
		map[string]string{
			"policy_id":     policyID,
			"policy_type":   "policy",
			"source_system": ctx.provider,
			"status":        firstAttribute(ctx.attrs, "status", "policy_status", "lifecycle_state"),
		},
	)
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "policy_owner_user_id"))
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, ctx.provider)
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, ctx.provider, ctx.attrs)
	addGRCPolicyAssignmentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, "policy_framework", firstAttribute(ctx.attrs, "frameworks", "framework"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, policyURN, "policy_status", firstAttribute(ctx.attrs, "status", "policy_status", "lifecycle_state"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcControlTestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	testID := firstAttribute(attrs, "test_id", "external_id")
	if testID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	testURN := projectionURN(tenantID, "evidence", provider, "control_test", testID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        testURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "evidence",
		Label:      firstAttribute(attrs, "name", "test_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"evidence_type": "grc_control_test",
			"source_system": provider,
			"status":        firstAttribute(attrs, "status"),
		}),
	})
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider)
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCIntegrationLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, firstAttribute(attrs, "integrations"), "grc_control_test")
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, "grc_category", firstAttribute(attrs, "category"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGRCControlSupportLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string) {
	if fromURN == "" {
		return
	}
	for _, controlRef := range grcControlReferences(event.GetAttributes()) {
		controlURN := projectionURN(tenantID, "policy", provider, "control", controlRef.id)
		if controlURN == "" {
			continue
		}
		if controlRef.externalID != "" || !controlRef.paired {
			controlAttrs := map[string]string{"control_id": controlRef.id, "policy_id": controlRef.id, "policy_type": "control", "source_system": provider}
			if controlRef.externalID != "" {
				controlAttrs["control_external_id"] = controlRef.externalID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        controlURN,
				TenantID:   tenantID,
				SourceID:   sourceID,
				EntityType: "policy",
				Label:      firstNonEmpty(controlRef.externalID, controlRef.id),
				Attributes: controlAttrs,
			})
		}
		addLink(links, projectedLink(tenantID, sourceID, fromURN, controlURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
}

type grcControlReference struct {
	id         string
	externalID string
	paired     bool
}

func grcControlReferences(attrs map[string]string) []grcControlReference {
	if refs := grcPairedControlReferences(attrs["control_references"]); len(refs) > 0 {
		return refs
	}
	ids := grcAttributeList(attrs["control_id"] + "," + attrs["control_ids"])
	externalIDs := grcAttributeList(attrs["control_external_id"] + "," + attrs["control_external_ids"])
	if len(ids) == 0 {
		ids = externalIDs
	}
	refs := make([]grcControlReference, 0, len(ids))
	for index, id := range ids {
		ref := grcControlReference{id: id}
		if index < len(externalIDs) {
			ref.externalID = externalIDs[index]
		}
		refs = append(refs, ref)
	}
	return refs
}

func grcPairedControlReferences(raw string) []grcControlReference {
	refs := []grcControlReference{}
	seen := map[string]struct{}{}
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, externalID, _ := strings.Cut(item, "=")
		ref := grcControlReference{id: strings.TrimSpace(id), externalID: strings.TrimSpace(externalID), paired: true}
		if ref.id == "" {
			ref.id = ref.externalID
		}
		if ref.id == "" {
			continue
		}
		key := ref.id + "\x00" + ref.externalID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func grcPolicyLikeProjections(event *cerebrov1.EventEnvelope, policyType string, idKey string, labelKeys []string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	id := firstAttribute(attrs, idKey, "external_id")
	if id == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	label := firstAttribute(attrs, labelKeys...)
	policyURN := projectionURN(tenantID, "policy", provider, policyType, id)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        policyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "policy",
		Label:      label,
		Attributes: grcAttributes(attrs, map[string]string{
			"policy_id":     id,
			"policy_type":   policyType,
			"source_system": provider,
		}),
	})
	links := map[string]*ports.ProjectedLink{}
	if policyType == "control" {
		addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, policyURN, provider, firstAttribute(attrs, "owner_id"))
		addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, policyURN, "grc_domain", firstAttribute(attrs, "domains"))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}
