package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func cloudflareAccountURN(tenantID string, accountID string) string {
	return projectionURN(tenantID, "cloudflare_account", strings.TrimSpace(accountID))
}

func cloudflareMemberURN(tenantID string, memberID string) string {
	return projectionURN(tenantID, "cloudflare_member", strings.TrimSpace(memberID))
}

func cloudflareRoleURN(tenantID string, roleID string) string {
	return projectionURN(tenantID, "cloudflare_role", strings.TrimSpace(roleID))
}

func cloudflareZoneURN(tenantID string, zoneID string) string {
	return projectionURN(tenantID, "cloudflare_zone", strings.TrimSpace(zoneID))
}

func cloudflareDNSRecordURN(tenantID string, recordID string) string {
	return projectionURN(tenantID, "cloudflare_dns_record", strings.TrimSpace(recordID))
}

func cloudflareEntity(event *cerebrov1.EventEnvelope, urn string, entityType string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   event.GetTenantId(),
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: attrs,
	}
}

func cloudflareAttributes(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		addProjectedAttribute(out, key, value)
	}
	return out
}

func cloudflareAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	accountID := strings.TrimSpace(attrs["account_id"])
	if accountID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, cloudflareEntity(event, cloudflareAccountURN(tenantID, accountID), "cloudflare.account", firstNonEmpty(attrs["name"], accountID), cloudflareAttributes(map[string]string{
		"account_id": accountID,
		"name":       attrs["name"],
		"type":       attrs["type"],
	})))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func cloudflareMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	memberID := strings.TrimSpace(attrs["member_id"])
	if memberID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	memberURN := cloudflareMemberURN(tenantID, memberID)
	addEntity(entities, cloudflareEntity(event, memberURN, "cloudflare.member", firstNonEmpty(attrs["email"], memberID), cloudflareAttributes(map[string]string{
		"member_id":  memberID,
		"account_id": attrs["account_id"],
		"email":      attrs["email"],
		"status":     attrs["status"],
	})))
	if accountID := strings.TrimSpace(attrs["account_id"]); accountID != "" {
		accountURN := cloudflareAccountURN(tenantID, accountID)
		addEntity(entities, cloudflareEntity(event, accountURN, "cloudflare.account", "", map[string]string{"account_id": accountID}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, accountURN, relationBelongsTo, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "cloudflare_member_account",
		}))
	}
	for _, role := range cloudflareMemberRoleRefs(event) {
		roleURN := cloudflareRoleURN(tenantID, role.id)
		if roleURN == "" {
			continue
		}
		addEntity(entities, cloudflareEntity(event, roleURN, "cloudflare.role", firstNonEmpty(role.name, role.id), map[string]string{
			"role_id": role.id,
			"name":    role.name,
		}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, roleURN, relationAssignedTo, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "cloudflare_member_role",
			"role_id":    role.id,
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cloudflareRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	roleID := strings.TrimSpace(attrs["role_id"])
	if roleID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	roleURN := cloudflareRoleURN(tenantID, roleID)
	addEntity(entities, cloudflareEntity(event, roleURN, "cloudflare.role", firstNonEmpty(attrs["name"], roleID), cloudflareAttributes(map[string]string{
		"role_id":     roleID,
		"account_id":  attrs["account_id"],
		"name":        attrs["name"],
		"description": attrs["description"],
		"permissions": attrs["permissions"],
	})))
	if accountID := strings.TrimSpace(attrs["account_id"]); accountID != "" {
		accountURN := cloudflareAccountURN(tenantID, accountID)
		addEntity(entities, cloudflareEntity(event, accountURN, "cloudflare.account", "", map[string]string{"account_id": accountID}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, accountURN, relationBelongsTo, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "cloudflare_role_account",
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cloudflareZoneProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	zoneID := strings.TrimSpace(attrs["zone_id"])
	if zoneID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	zoneURN := cloudflareZoneURN(tenantID, zoneID)
	addEntity(entities, cloudflareEntity(event, zoneURN, "cloudflare.zone", firstNonEmpty(attrs["name"], zoneID), cloudflareAttributes(map[string]string{
		"zone_id":    zoneID,
		"account_id": attrs["account_id"],
		"name":       attrs["name"],
		"status":     attrs["status"],
		"type":       attrs["type"],
		"paused":     attrs["paused"],
	})))
	if accountID := strings.TrimSpace(attrs["account_id"]); accountID != "" {
		accountURN := cloudflareAccountURN(tenantID, accountID)
		addEntity(entities, cloudflareEntity(event, accountURN, "cloudflare.account", "", map[string]string{"account_id": accountID}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), zoneURN, accountURN, relationBelongsTo, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "cloudflare_zone_account",
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cloudflareDNSRecordProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	recordID := strings.TrimSpace(attrs["record_id"])
	zoneID := strings.TrimSpace(attrs["zone_id"])
	if recordID == "" || zoneID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	recordURN := cloudflareDNSRecordURN(tenantID, recordID)
	addEntity(entities, cloudflareEntity(event, recordURN, "cloudflare.dns_record", firstNonEmpty(attrs["name"], recordID), cloudflareAttributes(map[string]string{
		"record_id": recordID,
		"zone_id":   zoneID,
		"name":      attrs["name"],
		"type":      attrs["type"],
		"content":   attrs["content"],
		"proxied":   attrs["proxied"],
	})))
	zoneURN := cloudflareZoneURN(tenantID, zoneID)
	addEntity(entities, cloudflareEntity(event, zoneURN, "cloudflare.zone", "", map[string]string{"zone_id": zoneID}))
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "cloudflare_dns_record_zone",
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), recordURN, zoneURN, relationBelongsTo, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), zoneURN, recordURN, relationHasDNSRecord, linkAttrs))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// cloudflareDNSRecordRetractions removes obsolete dns_record-to-zone links when a
// DNS record is observed as reassigned to a different zone, so the record no
// longer appears under a zone where it is no longer present.
func cloudflareDNSRecordRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	if event.GetKind() != "cloudflare.dns_record" {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	attrs := event.GetAttributes()
	recordID := strings.TrimSpace(attrs["record_id"])
	previousZoneID := strings.TrimSpace(attrs["previous_zone_id"])
	currentZoneID := strings.TrimSpace(attrs["zone_id"])
	if recordID == "" || previousZoneID == "" || previousZoneID == currentZoneID {
		return nil, nil
	}
	recordURN := cloudflareDNSRecordURN(tenantID, recordID)
	previousZoneURN := cloudflareZoneURN(tenantID, previousZoneID)
	if recordURN == "" || previousZoneURN == "" {
		return nil, nil
	}
	links := map[string]*ports.ProjectedLink{}
	retractionAttrs := map[string]string{
		"event_id":   event.GetId(),
		"retraction": "cloudflare_dns_record_zone_reassigned",
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), recordURN, previousZoneURN, relationBelongsTo, retractionAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), previousZoneURN, recordURN, relationHasDNSRecord, retractionAttrs))
	_, projectedLinks := entitiesAndLinks(nil, links)
	return projectedLinks, nil
}

type cloudflareRoleRef struct {
	id   string
	name string
}

func cloudflareMemberRoleRefs(event *cerebrov1.EventEnvelope) []cloudflareRoleRef {
	payload := payloadMap(event)
	rawRoles, ok := payload["roles"].([]any)
	if !ok {
		return nil
	}
	refs := make([]cloudflareRoleRef, 0, len(rawRoles))
	seen := map[string]struct{}{}
	for _, raw := range rawRoles {
		ref := cloudflareRoleRef{}
		switch typed := raw.(type) {
		case map[string]any:
			ref.id = strings.TrimSpace(stringValue(typed, "id"))
			ref.name = strings.TrimSpace(stringValue(typed, "name"))
		case string:
			ref.id = strings.TrimSpace(typed)
		}
		if ref.id == "" {
			continue
		}
		if _, dup := seen[ref.id]; dup {
			continue
		}
		seen[ref.id] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}
