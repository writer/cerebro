package sourceprojection

import (
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
	email := firstAttribute(attrs, "email")
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), personURN, email, observedAt)
	addSameActorEmailLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), personURN, email, observedAt)
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
	email := firstAttribute(attrs, "email")
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
	addSameActorEmailLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
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
	links := map[string]*ports.ProjectedLink{}
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, sourceURN, "grc_resource_kind", firstAttribute(attrs, "resource_kinds"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
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
		Attributes: grcAttributes(nil, map[string]string{
			"canonical_name": integrationID,
			"source_system":  provider,
			"source_type":    "grc_integration",
		}),
	}
}

func addGRCUserActionLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, provider string, userID string, toURN string, action string) {
	userID = strings.TrimSpace(userID)
	if userID == "" || strings.TrimSpace(toURN) == "" {
		return
	}
	userURN := grcUserURN(tenantID, provider, userID)
	addEntity(entities, grcUserEntity(tenantID, sourceID, userURN, userID, map[string]string{"source_system": provider, "user_id": userID}))
	addLink(links, projectedLink(tenantID, sourceID, userURN, toURN, relationActedOn, map[string]string{
		"action":   strings.TrimSpace(action),
		"event_id": event.GetId(),
		"user_id":  userID,
	}))
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

func addGRCUserOwnerLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, ownerID string) {
	ownerID = strings.TrimSpace(ownerID)
	if fromURN == "" || ownerID == "" {
		return
	}
	ownerURN := grcUserURN(tenantID, provider, ownerID)
	addEntity(entities, grcUserEntity(tenantID, sourceID, ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
	addLink(links, projectedLink(tenantID, sourceID, fromURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
}

func addSecurityContactEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, email string, contactType string) {
	normalizedEmail := normalizeIdentifier(extractEmailIdentifier(email))
	fromURN = strings.TrimSpace(fromURN)
	if fromURN == "" || normalizedEmail == "" {
		return
	}
	identityURN := projectionURN(tenantID, "identity", "email", normalizedEmail)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "identity.email",
		Label:      normalizedEmail,
		Attributes: map[string]string{"value": normalizedEmail},
	})
	linkAttrs := map[string]string{
		"confidence":   "0.90",
		"contact_type": strings.TrimSpace(contactType),
		"event_id":     event.GetId(),
		"match_type":   "contact_email",
	}
	addProjectedAttribute(linkAttrs, "at", eventObservedAt(event))
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identityURN, relationAssociatedWith, linkAttrs))
}

func addGRCIntegrationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, rawIntegrations string, relationshipBy string) {
	if fromURN == "" {
		return
	}
	for _, integrationID := range grcAttributeSequence(rawIntegrations) {
		integrationURN := grcIntegrationURN(tenantID, provider, integrationID)
		if integrationURN == "" {
			continue
		}
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, sourceID, integrationURN, integrationID, provider))
		addLink(links, projectedLink(tenantID, sourceID, fromURN, integrationURN, relationBelongsTo, map[string]string{
			"event_id":         event.GetId(),
			"integration_id":   integrationID,
			"relationship":     relationBelongsTo,
			"relationship_by":  relationshipBy,
			"source_reference": "integrations",
		}))
	}
}
