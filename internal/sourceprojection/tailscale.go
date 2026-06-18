package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func tailscaleTailnetURN(tenantID string, tailnet string) string {
	return projectionURN(tenantID, "tailscale_tailnet", strings.TrimSpace(tailnet))
}

func tailscaleUserURN(tenantID string, userID string) string {
	return projectionURN(tenantID, "tailscale_user", strings.TrimSpace(userID))
}

func tailscaleUserKey(attrs map[string]string) string {
	return firstNonEmpty(attrs["login_name"], attrs["email"], attrs["owner_email"], attrs["user_id"])
}

func tailscaleDeviceURN(tenantID string, deviceID string) string {
	return projectionURN(tenantID, "tailscale_device", strings.TrimSpace(deviceID))
}

func tailscaleGroupURN(tenantID string, groupID string) string {
	return projectionURN(tenantID, "tailscale_group", strings.TrimSpace(groupID))
}

func tailscaleTagURN(tenantID string, tagID string) string {
	return projectionURN(tenantID, "tailscale_tag", strings.TrimSpace(tagID))
}

func tailscaleServiceURN(tenantID string, serviceID string) string {
	return projectionURN(tenantID, "tailscale_service", strings.TrimSpace(serviceID))
}

func tailscaleGrantURN(tenantID string, grantID string) string {
	return projectionURN(tenantID, "tailscale_grant", strings.TrimSpace(grantID))
}

func tailscaleDestinationURN(tenantID string, destination string) string {
	return projectionURN(tenantID, "tailscale_destination", strings.TrimSpace(destination))
}

func tailscaleEntity(event *cerebrov1.EventEnvelope, urn string, entityType string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   event.GetTenantId(),
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: attrs,
	}
}

func tailscaleAttributes(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		addProjectedAttribute(out, key, value)
	}
	return out
}

func tailscaleSplitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, dup := seen[part]; dup {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func tailscalePrincipalRef(tenantID string, value string) (string, string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", ""
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "group:"):
		return tailscaleGroupURN(tenantID, value), "tailscale.group", value
	case strings.HasPrefix(lower, "tag:"):
		return tailscaleTagURN(tenantID, value), "tailscale.tag", value
	default:
		return tailscaleUserURN(tenantID, value), "tailscale.user", value
	}
}

func tailscaleBoolIsTrue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "true")
}

func tailscaleBoolIsFalse(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "false")
}

func tailscaleTailnetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	tailnet := strings.TrimSpace(attrs["tailnet"])
	if tailnet == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, tailscaleEntity(event, tailscaleTailnetURN(tenantID, tailnet), "tailscale.tailnet", tailnet, tailscaleAttributes(map[string]string{
		"tailnet":                 tailnet,
		"devices_approval_on":     attrs["devices_approval_on"],
		"users_approval_on":       attrs["users_approval_on"],
		"network_flow_logging_on": attrs["network_flow_logging_on"],
		"regional_routing_on":     attrs["regional_routing_on"],
		"max_key_duration_days":   attrs["max_key_duration_days"],
	})))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func tailscaleUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	userID := strings.TrimSpace(attrs["user_id"])
	if userID == "" {
		return nil, nil, nil
	}
	userKey := firstNonEmpty(tailscaleUserKey(attrs), userID)
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, tailscaleEntity(event, tailscaleUserURN(tenantID, userKey), "tailscale.user", firstNonEmpty(attrs["login_name"], attrs["email"], userID), tailscaleAttributes(map[string]string{
		"user_id":      userID,
		"login_name":   attrs["login_name"],
		"email":        attrs["email"],
		"display_name": attrs["display_name"],
		"role":         attrs["role"],
		"status":       attrs["status"],
		"type":         attrs["type"],
	})))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func tailscaleDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	deviceID := strings.TrimSpace(attrs["device_id"])
	if deviceID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	deviceURN := tailscaleDeviceURN(tenantID, deviceID)
	addEntity(entities, tailscaleEntity(event, deviceURN, "tailscale.device", firstNonEmpty(attrs["name"], attrs["hostname"], deviceID), tailscaleAttributes(map[string]string{
		"device_id":                   deviceID,
		"node_id":                     attrs["node_id"],
		"name":                        attrs["name"],
		"hostname":                    attrs["hostname"],
		"os":                          attrs["os"],
		"user_id":                     attrs["user_id"],
		"owner_email":                 attrs["owner_email"],
		"authorized":                  attrs["authorized"],
		"is_external":                 attrs["is_external"],
		"key_expiry_disabled":         attrs["key_expiry_disabled"],
		"update_available":            attrs["update_available"],
		"blocks_incoming_connections": attrs["blocks_incoming_connections"],
		"tags":                        attrs["tags"],
	})))
	if ownerID := tailscaleUserKey(attrs); strings.TrimSpace(ownerID) != "" {
		ownerURN := tailscaleUserURN(tenantID, ownerID)
		ownerAttrs := map[string]string{
			"user_id":    attrs["user_id"],
			"login_name": attrs["login_name"],
			"email":      firstNonEmpty(attrs["email"], attrs["owner_email"]),
		}
		addEntity(entities, tailscaleEntity(event, ownerURN, "tailscale.user", "", tailscaleAttributes(ownerAttrs)))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), deviceURN, ownerURN, relationOwnedBy, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "tailscale_device_owner",
		}))
		if tailscaleBoolIsTrue(attrs["authorized"]) && !tailscaleBoolIsTrue(attrs["blocks_incoming_connections"]) {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), ownerURN, deviceURN, relationCanReach, map[string]string{
				"event_id":   event.GetId(),
				"at":         eventObservedAt(event),
				"match_type": "tailscale_device_access",
			}))
		}
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func tailscaleGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	groupID := strings.TrimSpace(attrs["group_id"])
	if groupID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	groupURN := tailscaleGroupURN(tenantID, groupID)
	addEntity(entities, tailscaleEntity(event, groupURN, "tailscale.group", firstNonEmpty(attrs["name"], groupID), tailscaleAttributes(map[string]string{
		"group_id": groupID,
		"name":     attrs["name"],
		"members":  attrs["members"],
	})))
	for _, member := range tailscaleSplitList(attrs["members"]) {
		memberURN, memberType, memberLabel := tailscalePrincipalRef(tenantID, member)
		if memberURN == "" {
			continue
		}
		addEntity(entities, tailscaleEntity(event, memberURN, memberType, memberLabel, map[string]string{"login_name": memberLabel}))
		linkAttrs := map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "tailscale_group_member",
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, memberURN, relationContains, linkAttrs))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, groupURN, relationMemberOf, linkAttrs))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func tailscaleTagProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	tagID := strings.TrimSpace(attrs["tag_id"])
	if tagID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	tagURN := tailscaleTagURN(tenantID, tagID)
	addEntity(entities, tailscaleEntity(event, tagURN, "tailscale.tag", firstNonEmpty(attrs["name"], tagID), tailscaleAttributes(map[string]string{
		"tag_id": tagID,
		"name":   attrs["name"],
		"owners": attrs["owners"],
	})))
	for _, owner := range tailscaleSplitList(attrs["owners"]) {
		ownerURN, ownerType, ownerLabel := tailscalePrincipalRef(tenantID, owner)
		if ownerURN == "" {
			continue
		}
		addEntity(entities, tailscaleEntity(event, ownerURN, ownerType, ownerLabel, map[string]string{"login_name": ownerLabel}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), tagURN, ownerURN, relationOwnedBy, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "tailscale_tag_owner",
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func tailscaleServiceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	serviceID := strings.TrimSpace(attrs["service_id"])
	if serviceID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	serviceURN := tailscaleServiceURN(tenantID, serviceID)
	addEntity(entities, tailscaleEntity(event, serviceURN, "tailscale.service", firstNonEmpty(attrs["name"], serviceID), tailscaleAttributes(map[string]string{
		"service_id": serviceID,
		"name":       attrs["name"],
		"tags":       attrs["tags"],
	})))
	for _, tag := range tailscaleSplitList(attrs["tags"]) {
		tagURN := tailscaleTagURN(tenantID, tag)
		addEntity(entities, tailscaleEntity(event, tagURN, "tailscale.tag", tag, map[string]string{"tag_id": tag}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), serviceURN, tagURN, relationTaggedAs, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "tailscale_service_tag",
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func tailscaleGrantProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	grantID := strings.TrimSpace(attrs["grant_id"])
	if grantID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	grantURN := tailscaleGrantURN(tenantID, grantID)
	addEntity(entities, tailscaleEntity(event, grantURN, "tailscale.grant", grantID, tailscaleAttributes(map[string]string{
		"grant_id":     grantID,
		"sources":      attrs["sources"],
		"destinations": attrs["destinations"],
		"via":          attrs["via"],
		"ip":           attrs["ip"],
		"app":          attrs["app"],
		"disabled":     attrs["disabled"],
	})))
	disabled := tailscaleBoolIsTrue(attrs["disabled"])
	for _, source := range tailscaleSplitList(attrs["sources"]) {
		sourceURN, sourceType, sourceLabel := tailscalePrincipalRef(tenantID, source)
		if sourceURN == "" {
			continue
		}
		addEntity(entities, tailscaleEntity(event, sourceURN, sourceType, sourceLabel, map[string]string{"login_name": sourceLabel}))
		if !disabled {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), grantURN, sourceURN, relationGrantsEntitlement, map[string]string{
				"event_id":   event.GetId(),
				"at":         eventObservedAt(event),
				"match_type": "tailscale_grant_source",
			}))
		}
	}
	for _, destination := range tailscaleSplitList(attrs["destinations"]) {
		destinationURN := tailscaleDestinationURN(tenantID, destination)
		addEntity(entities, tailscaleEntity(event, destinationURN, "tailscale.destination", destination, map[string]string{"destination": destination}))
		if !disabled {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), grantURN, destinationURN, relationCanReach, map[string]string{
				"event_id":   event.GetId(),
				"at":         eventObservedAt(event),
				"match_type": "tailscale_grant_destination",
			}))
		}
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// tailscaleAccessRetractions clears obsolete access edges when Tailscale evidence
// shows that access has been revoked: a deauthorized device, or one that blocks
// incoming connections, must no longer be reachable by its owner, and a disabled
// ACL grant must no longer confer source entitlements or destination reachability.
func tailscaleAccessRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	switch event.GetKind() {
	case "tailscale.device":
		return tailscaleDeviceAccessRetractions(event)
	case "tailscale.grant":
		return tailscaleGrantAccessRetractions(event)
	default:
		return nil, nil
	}
}

func tailscaleDeviceAccessRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	attrs := event.GetAttributes()
	deauthorized := tailscaleBoolIsFalse(attrs["authorized"])
	blocksIncoming := tailscaleBoolIsTrue(attrs["blocks_incoming_connections"])
	if !deauthorized && !blocksIncoming {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	deviceID := strings.TrimSpace(attrs["device_id"])
	ownerID := tailscaleUserKey(attrs)
	if deviceID == "" || strings.TrimSpace(ownerID) == "" {
		return nil, nil
	}
	reason := "tailscale_device_blocks_incoming"
	if deauthorized {
		reason = "tailscale_device_deauthorized"
	}
	deviceURN := tailscaleDeviceURN(tenantID, deviceID)
	ownerURN := tailscaleUserURN(tenantID, ownerID)
	links := map[string]*ports.ProjectedLink{}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), ownerURN, deviceURN, relationCanReach, map[string]string{
		"event_id":   event.GetId(),
		"retraction": reason,
	}))
	_, projectedLinks := entitiesAndLinks(nil, links)
	return projectedLinks, nil
}

func tailscaleGrantAccessRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	attrs := event.GetAttributes()
	if !tailscaleBoolIsTrue(attrs["disabled"]) {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	grantID := strings.TrimSpace(attrs["grant_id"])
	if grantID == "" {
		return nil, nil
	}
	grantURN := tailscaleGrantURN(tenantID, grantID)
	links := map[string]*ports.ProjectedLink{}
	for _, source := range tailscaleSplitList(attrs["sources"]) {
		sourceURN, _, _ := tailscalePrincipalRef(tenantID, source)
		if sourceURN == "" {
			continue
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), grantURN, sourceURN, relationGrantsEntitlement, map[string]string{
			"event_id":   event.GetId(),
			"retraction": "tailscale_grant_disabled",
		}))
	}
	for _, destination := range tailscaleSplitList(attrs["destinations"]) {
		destinationURN := tailscaleDestinationURN(tenantID, destination)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), grantURN, destinationURN, relationCanReach, map[string]string{
			"event_id":   event.GetId(),
			"retraction": "tailscale_grant_disabled",
		}))
	}
	_, projectedLinks := entitiesAndLinks(nil, links)
	return projectedLinks, nil
}
