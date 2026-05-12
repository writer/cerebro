package sourceprojection

import (
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func grcFrameworkProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "framework", "framework_id", []string{"display_name", "name", "framework_id"})
}

func grcControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "control", "control_id", []string{"control_external_id", "name", "control_id"})
}

func grcPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "policy", "policy_id", []string{"name", "policy_id"})
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
	for _, controlRef := range grcControlReferences(attrs) {
		controlURN := projectionURN(tenantID, "policy", provider, "control", controlRef.id)
		if controlRef.externalID != "" || !controlRef.paired {
			controlAttrs := map[string]string{"control_id": controlRef.id, "policy_id": controlRef.id, "policy_type": "control", "source_system": provider}
			if controlRef.externalID != "" {
				controlAttrs["control_external_id"] = controlRef.externalID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        controlURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "policy",
				Label:      firstNonEmpty(controlRef.externalID, controlRef.id),
				Attributes: controlAttrs,
			})
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), testURN, controlURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
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

func grcAttributeList(value string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		values = append(values, trimmed)
		seen[trimmed] = struct{}{}
	}
	return values
}

func grcDocumentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	documentID := firstAttribute(attrs, "document_id", "external_id")
	if documentID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	documentURN := projectionURN(tenantID, "document", provider, documentID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        documentURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "document",
		Label:      firstAttribute(attrs, "title", "document_id"),
		Attributes: grcAttributes(attrs, map[string]string{"document_id": documentID, "source_system": provider}),
	})
	if ownerID := firstAttribute(attrs, "owner_id"); ownerID != "" {
		ownerURN := grcUserURN(tenantID, provider, ownerID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), documentURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	vendorID := firstAttribute(attrs, "vendor_id", "external_id")
	if vendorID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vendorURN := projectionURN(tenantID, "vendor", provider, vendorID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vendorURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor",
		Label:      firstAttribute(attrs, "name", "vendor_id"),
		Attributes: grcAttributes(attrs, map[string]string{"vendor_id": vendorID, "source_system": provider}),
	})
	for _, ownerID := range []string{firstAttribute(attrs, "security_owner_user_id"), firstAttribute(attrs, "business_owner_user_id")} {
		if ownerID == "" {
			continue
		}
		ownerURN := grcUserURN(tenantID, provider, ownerID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), vendorURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerabilityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)
	if vulnerabilityURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        vulnerabilityURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "vulnerability",
			Label:      firstAttribute(attrs, "name", "vulnerability_id"),
			Attributes: map[string]string{"source_system": provider},
		})
	}
	integrationID := firstAttribute(attrs, "integration_id")
	integrationURN := grcIntegrationURN(tenantID, provider, integrationID)
	if integrationURN != "" {
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, event.GetSourceId(), integrationURN, integrationID, provider))
	}
	targetID := firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if targetURN != "" {
		addEntity(entities, grcTargetEntity(tenantID, event.GetSourceId(), targetURN, targetID, attrs, provider))
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
		}
		if integrationURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
		}
	}
	packageURN := vulnerabilityPackageURN(tenantID, attrs, "grc")
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attrs, "grc")
	if packageURN != "" {
		addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, attrs, "grc")
		if targetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, attrs)))
		}
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attrs, "grc")))
	}
	if canonicalPackageURN != "" && vulnerabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcTargetURN(tenantID string, provider string, targetID string) string {
	if strings.TrimSpace(targetID) == "" {
		return ""
	}
	return projectionURN(tenantID, "grc_target", provider, targetID)
}

func grcTargetEntity(tenantID string, sourceID string, urn string, targetID string, attrs map[string]string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "grc.target",
		Label:      firstAttribute(attrs, "target_name", "resource_name", "hostname", "target_id", "resource_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"integration_id": firstAttribute(attrs, "integration_id"),
			"source_system":  provider,
			"target_id":      targetID,
			"target_type":    firstAttribute(attrs, "target_type", "resource_type", "asset_type"),
		}),
	}
}

func grcIntegrationURN(tenantID string, provider string, integrationID string) string {
	if strings.TrimSpace(integrationID) == "" {
		return ""
	}
	return projectionURN(tenantID, "source", provider, "integration", integrationID)
}

func grcIntegrationEntity(tenantID string, sourceID string, urn string, integrationID string, attrs map[string]string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "source",
		Label:      firstAttribute(attrs, "display_name", "integration_name", "integration_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"canonical_name": integrationID,
			"source_system":  provider,
			"source_type":    "grc_integration",
		}),
	}
}

func grcIntegrationReferenceEntity(tenantID string, sourceID string, urn string, integrationID string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "source",
		Label:      integrationID,
		Attributes: grcAttributes(nil, map[string]string{
			"canonical_name": integrationID,
			"source_system":  provider,
			"source_type":    "grc_integration",
		}),
	}
}

func grcIntegrationLinkAttributes(event *cerebrov1.EventEnvelope, integrationID string) map[string]string {
	return map[string]string{
		"event_id":        event.GetId(),
		"integration_id":  integrationID,
		"relationship":    relationBelongsTo,
		"relationship_by": "grc_vulnerability",
	}
}

func grcPackageTargetAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string) map[string]string {
	return map[string]string{
		"event_id":      event.GetId(),
		"package":       vulnerablePackageName(attrs),
		"target_id":     firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id"),
		"version":       firstAttribute(attrs, "version", "package_version", "application_version", "installed_version"),
		"source_system": firstAttribute(attrs, "source_system", "provider", "source_provider"),
	}
}

func grcRiskScenarioProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	riskID := firstAttribute(attrs, "risk_id", "external_id")
	if riskID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	riskURN := projectionURN(tenantID, "claim", provider, "risk_scenario", riskID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        riskURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "claim",
		Label:      firstAttribute(attrs, "description", "risk_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"claim_type":    "risk_scenario",
			"predicate":     firstAttribute(attrs, "description"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "review_status"),
		}),
	})
	if owner := firstAttribute(attrs, "owner"); owner != "" {
		ownerURN := projectionURN(tenantID, "contact", provider, "owner", owner)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ownerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "contact",
			Label:      owner,
			Attributes: map[string]string{"source_system": provider, "owner": owner},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), riskURN, ownerURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPersonProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	personID := firstAttribute(attrs, "person_id", "user_id", "email", "external_id")
	if personID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	personURN := projectionURN(tenantID, "person", provider, personID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        personURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "person",
		Label:      firstAttribute(attrs, "email", "job_title", "person_id"),
		Attributes: grcAttributes(attrs, map[string]string{"person_id": personID, "source_system": provider}),
	})
	observedAt := timestamppb.New(time.Now().UTC())
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), personURN, firstAttribute(attrs, "email"), observedAt)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	userID := firstAttribute(attrs, "user_id", "email", "external_id")
	if userID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	userURN := grcUserURN(tenantID, provider, userID)
	addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), userURN, firstAttribute(attrs, "display_name", "email", "user_id"), grcAttributes(attrs, map[string]string{"user_id": userID, "source_system": provider})))
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, firstAttribute(attrs, "email"), event.GetOccurredAt())
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcIntegrationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	integrationID := firstAttribute(attrs, "integration_id", "external_id")
	if integrationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	sourceURN := grcIntegrationURN(tenantID, provider, integrationID)
	addEntity(entities, grcIntegrationEntity(tenantID, event.GetSourceId(), sourceURN, integrationID, attrs, provider))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
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
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func grcAttributes(attrs map[string]string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(attrs)+len(extra))
	for key, value := range attrs {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range extra {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	return merged
}

func grcProvider(attrs map[string]string) string {
	return firstNonEmpty(attrs["provider"], attrs["source_provider"], "grc")
}

func grcUserURN(tenantID string, provider string, userID string) string {
	return projectionURN(tenantID, "user", provider, userID)
}

func grcUserEntity(tenantID string, sourceID string, urn string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "user",
		Label:      label,
		Attributes: attrs,
	}
}
