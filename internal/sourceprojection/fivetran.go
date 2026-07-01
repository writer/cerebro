package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const fivetranProvider = "fivetran"

func fivetranUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: fivetranProvider})
}

func fivetranGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: fivetranProvider})
}

func fivetranGroupUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: fivetranProvider})
}

func fivetranRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	roleID := firstNonEmpty(attributes["role_id"], attributes["role_name"], event.GetId())
	roleURN := fivetranURN(tenantID, "role", roleID)
	entities := map[string]*ports.ProjectedEntity{}
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "fivetran.role",
			Label:      firstNonEmpty(attributes["role_name"], roleID),
			Attributes: map[string]string{
				"description":           strings.TrimSpace(attributes["description"]),
				"is_custom":             strings.TrimSpace(attributes["is_custom"]),
				"is_deprecated":         strings.TrimSpace(attributes["is_deprecated"]),
				"replacement_role_name": strings.TrimSpace(attributes["replacement_role_name"]),
				"role_id":               roleID,
				"role_scope":            strings.TrimSpace(attributes["role_scope"]),
				"role_status":           strings.TrimSpace(attributes["role_status"]),
				"source_runtime_id":     strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			},
		})
	}
	return identityProjectionResult(entities, nil)
}

func fivetranTeamsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranScopedAssetProjections(event, "team")
}

func fivetranTeamUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	teamID := strings.TrimSpace(attributes["team_id"])
	userID := firstNonEmpty(attributes["user_id"], attributes["member_id"], attributes["email"])
	userURN := identityPrincipalURN(tenantID, fivetranProvider, "user", userID, attributes["email"])
	return fivetranMembershipProjection(event, tenantID, userURN, firstNonEmpty(attributes["email"], userID), "fivetran.user", fivetranURN(tenantID, "team", teamID), firstNonEmpty(attributes["team_name"], teamID), "fivetran.team", relationMemberOf)
}

func fivetranTeamGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	teamID := strings.TrimSpace(attributes["team_id"])
	groupID := firstNonEmpty(attributes["member_id"], attributes["group_id"], attributes["resource_id"])
	return fivetranMembershipProjection(event, tenantID, fivetranURN(tenantID, "team", teamID), firstNonEmpty(attributes["team_name"], teamID), "fivetran.team", identityGroupURN(tenantID, fivetranProvider, groupID, ""), firstNonEmpty(attributes["resource_name"], groupID), "fivetran.group", relationAssignedTo)
}

func fivetranTeamConnectionsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	teamID := strings.TrimSpace(attributes["team_id"])
	connectionID := firstNonEmpty(attributes["member_id"], attributes["connection_id"], attributes["resource_id"])
	return fivetranMembershipProjection(event, tenantID, fivetranURN(tenantID, "team", teamID), firstNonEmpty(attributes["team_name"], teamID), "fivetran.team", fivetranURN(tenantID, "connection", connectionID), firstNonEmpty(attributes["resource_name"], connectionID), "fivetran.connection", relationAssignedTo)
}

func fivetranUserGroupMembershipsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranUserScopedMembershipProjection(event, "group", relationMemberOf)
}

func fivetranUserConnectionMembershipsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranUserScopedMembershipProjection(event, "connection", relationAssignedTo)
}

func fivetranAssetsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranScopedAssetProjections(event, "")
}

func fivetranScopedAssetProjections(event *cerebrov1.EventEnvelope, fallbackType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], fallbackType, attributes["schema"], "resource"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["connection_id"], attributes["external_id"], event.GetId())
	resourceURN := firstNonEmpty(attributes["resource_urn"], fivetranURN(tenantID, resourceType, resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "fivetran." + strings.ReplaceAll(resourceType, "_", "."),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["display_name"], attributes["name"], resourceID),
			Attributes: map[string]string{
				"active":            strings.TrimSpace(attributes["active"]),
				"created_at":        strings.TrimSpace(attributes["created_at"]),
				"enabled":           strings.TrimSpace(attributes["enabled"]),
				"group_id":          strings.TrimSpace(attributes["group_id"]),
				"region":            strings.TrimSpace(attributes["region"]),
				"resource_id":       resourceID,
				"resource_status":   strings.TrimSpace(attributes["resource_status"]),
				"resource_type":     resourceType,
				"service":           strings.TrimSpace(attributes["service"]),
				"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
				"updated_at":        strings.TrimSpace(attributes["updated_at"]),
				"version":           strings.TrimSpace(attributes["version"]),
			},
		})
		addFivetranParentLinks(entities, links, tenantID, event, resourceURN, attributes, resourceType, resourceID)
	}
	return identityProjectionResult(entities, links)
}

func fivetranUserScopedMembershipProjection(event *cerebrov1.EventEnvelope, targetType string, relation string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	userID := firstNonEmpty(attributes["user_id"], attributes["email"])
	targetID := firstNonEmpty(attributes["member_id"], attributes["resource_id"])
	userURN := identityPrincipalURN(tenantID, fivetranProvider, "user", userID, attributes["email"])
	targetURN := fivetranURN(tenantID, targetType, targetID)
	targetEntityType := "fivetran." + strings.ReplaceAll(targetType, "_", ".")
	if targetType == "group" {
		targetURN = identityGroupURN(tenantID, fivetranProvider, targetID, "")
		targetEntityType = "fivetran.group"
	}
	return fivetranMembershipProjection(event, tenantID, userURN, firstNonEmpty(attributes["email"], userID), "fivetran.user", targetURN, firstNonEmpty(attributes["resource_name"], targetID), targetEntityType, relation)
}

func fivetranMembershipProjection(event *cerebrov1.EventEnvelope, tenantID string, fromURN string, fromLabel string, fromType string, toURN string, toLabel string, toType string, relation string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if fromURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        fromURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: fromType,
			Label:      fromLabel,
			Attributes: map[string]string{"role": strings.TrimSpace(attributes["role"])},
		})
	}
	if toURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        toURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: toType,
			Label:      toLabel,
			Attributes: map[string]string{"role": strings.TrimSpace(attributes["role"])},
		})
	}
	if fromURN != "" && toURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, toURN, relation, map[string]string{
			"event_id":    event.GetId(),
			"match_type":  "fivetran_membership",
			"role":        strings.TrimSpace(attributes["role"]),
			"source_kind": event.GetKind(),
		}))
	}
	return identityProjectionResult(entities, links)
}

func addFivetranParentLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, attributes map[string]string, resourceType string, resourceID string) {
	if groupID := strings.TrimSpace(attributes["group_id"]); groupID != "" && resourceType != "group" {
		groupURN := identityGroupURN(tenantID, fivetranProvider, groupID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: groupURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "fivetran.group", Label: groupID, Attributes: map[string]string{"group_id": groupID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, groupURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "fivetran_group_scope"}))
	}
	if teamID := strings.TrimSpace(attributes["team_id"]); teamID != "" && resourceType != "team" {
		teamURN := fivetranURN(tenantID, "team", teamID)
		addEntity(entities, &ports.ProjectedEntity{URN: teamURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "fivetran.team", Label: teamID, Attributes: map[string]string{"team_id": teamID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, teamURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "fivetran_team_scope"}))
	}
	if connectionID := strings.TrimSpace(attributes["connection_id"]); connectionID != "" && resourceType != "connection" && connectionID != resourceID {
		connectionURN := fivetranURN(tenantID, "connection", connectionID)
		addEntity(entities, &ports.ProjectedEntity{URN: connectionURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "fivetran.connection", Label: connectionID, Attributes: map[string]string{"connection_id": connectionID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, connectionURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "fivetran_connection_scope"}))
	}
	if destinationID := strings.TrimSpace(attributes["destination_id"]); destinationID != "" && resourceType != "destination" && destinationID != resourceID {
		destinationURN := fivetranURN(tenantID, "destination", destinationID)
		addEntity(entities, &ports.ProjectedEntity{URN: destinationURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "fivetran.destination", Label: destinationID, Attributes: map[string]string{"destination_id": destinationID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, destinationURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "fivetran_destination_scope"}))
	}
	if proxyAgentID := strings.TrimSpace(attributes["proxy_agent_id"]); proxyAgentID != "" && resourceType != "proxy_agent" && proxyAgentID != resourceID {
		proxyAgentURN := fivetranURN(tenantID, "proxy_agent", proxyAgentID)
		addEntity(entities, &ports.ProjectedEntity{URN: proxyAgentURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "fivetran.proxy.agent", Label: proxyAgentID, Attributes: map[string]string{"proxy_agent_id": proxyAgentID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, proxyAgentURN, relationAttachedTo, map[string]string{"event_id": event.GetId(), "match_type": "fivetran_proxy_agent_attachment"}))
	}
}

func fivetranURN(tenantID string, resourceType string, resourceID string) string {
	resourceType = normalizeCloudType(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if resourceType == "" || resourceID == "" {
		return ""
	}
	return projectionURN(tenantID, "fivetran_"+resourceType, resourceID)
}
