package sourceprojection

import (
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var auth0IdentityProfile = identityProjectionProfile{Provider: "auth0"}

func auth0UsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, auth0IdentityProfile)
}

func auth0RolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	roleID := firstNonEmpty(attributes["role_id"], attributes["group_id"], attributes["resource_id"], event.GetId())
	if roleID == "" {
		return nil, nil, nil
	}
	legacyEvent := &cerebrov1.EventEnvelope{
		Id:         event.GetId(),
		TenantId:   event.GetTenantId(),
		SourceId:   event.GetSourceId(),
		Kind:       event.GetKind(),
		OccurredAt: event.GetOccurredAt(),
		Attributes: auth0LegacyRoleGroupAttributes(attributes, roleID),
	}
	legacyEntities, legacyLinks, err := identityGroupProjections(legacyEvent, auth0IdentityProfile)
	if err != nil {
		return nil, nil, err
	}
	privileged := identityProjectionPrivileged(attributes)
	roleKind := "role"
	if privileged {
		roleKind = "admin_role"
	}
	roleURN := projectionURN(tenantID, "auth0_"+roleKind, roleID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, entity := range legacyEntities {
		addEntity(entities, entity)
	}
	for _, link := range legacyLinks {
		addLink(links, link)
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        roleURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "auth0." + roleKind,
		Label:      firstNonEmpty(attributes["role_name"], attributes["group_name"], attributes["resource_name"], roleID),
		Attributes: map[string]string{
			"description": strings.TrimSpace(attributes["description"]),
			"is_admin":    boolString(privileged),
			"role_id":     roleID,
			"role_name":   firstNonEmpty(attributes["role_name"], attributes["group_name"], attributes["resource_name"]),
			"role_type":   firstNonEmpty(attributes["role_type"], "tenant_role"),
		},
	})
	legacyGroupURN := identityGroupURN(tenantID, auth0IdentityProfile.Provider, legacyEvent.GetAttributes()["group_id"], legacyEvent.GetAttributes()["group_email"])
	if legacyGroupURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), legacyGroupURN, roleURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "auth0_role_legacy_group"}))
	}
	entitlementURN, capabilityURN := addIdentityRoleEntitlement(entities, tenantID, event, auth0IdentityProfile, roleURN, roleID, privileged, attributes)
	if entitlementURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	}
	if entitlementURN != "" && capabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func auth0LegacyRoleGroupAttributes(attributes map[string]string, roleID string) map[string]string {
	legacy := make(map[string]string, len(attributes)+2)
	for key, value := range attributes {
		legacy[key] = value
	}
	if strings.TrimSpace(legacy["group_id"]) == "" {
		legacy["group_id"] = strings.TrimSpace(roleID)
	}
	if strings.TrimSpace(legacy["group_name"]) == "" {
		legacy["group_name"] = firstNonEmpty(legacy["role_name"], legacy["resource_name"], roleID)
	}
	return legacy
}

func auth0AuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, auth0IdentityProfile)
}

func auth0ClientsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, auth0IdentityProfile)
}

func auth0ConnectionsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	connectionID := firstNonEmpty(attributes["connection_id"], attributes["resource_id"], event.GetId())
	if connectionID == "" {
		return nil, nil, nil
	}
	connectionURN := projectionURN(tenantID, "auth0_connection", connectionID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        connectionURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "auth0.connection",
		Label:      firstNonEmpty(attributes["connection_name"], attributes["resource_name"], connectionID),
		Attributes: map[string]string{
			"connection_id":   connectionID,
			"connection_name": firstNonEmpty(attributes["connection_name"], attributes["resource_name"]),
			"realms":          strings.TrimSpace(attributes["realms"]),
			"strategy":        strings.TrimSpace(attributes["strategy"]),
		},
	})
	for _, clientID := range auth0EnabledClientIDs(event, attributes) {
		appURN := identityApplicationURN(tenantID, auth0IdentityProfile.Provider, clientID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        appURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "auth0.application",
			Label:      clientID,
			Attributes: map[string]string{"app_id": clientID, "client_id": clientID},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), connectionURN, appURN, relationSupports, map[string]string{"event_id": event.GetId(), "match_type": "auth0_connection_enabled_client"}))
	}
	return identityProjectionResult(entities, links)
}

func auth0OrganizationsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	organizationID := firstNonEmpty(attributes["organization_id"], attributes["resource_id"], event.GetId())
	if organizationID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addAuth0OrganizationEntity(entities, tenantID, event.GetSourceId(), organizationID, firstNonEmpty(attributes["display_name"], attributes["organization_name"], attributes["resource_name"], organizationID), attributes)
	return identityProjectionResult(entities, links)
}

func auth0OrganizationMembersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	organizationID := strings.TrimSpace(attributes["organization_id"])
	userID := firstNonEmpty(attributes["user_id"], attributes["member_user_id"], attributes["subject_id"], attributes["email"])
	if organizationID == "" || userID == "" {
		return nil, nil, nil
	}
	orgURN := auth0OrganizationURN(tenantID, organizationID)
	userURN := identityUserURN(tenantID, auth0IdentityProfile.Provider, userID, attributes["email"])
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addAuth0OrganizationEntity(entities, tenantID, event.GetSourceId(), organizationID, organizationID, attributes)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        userURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "auth0.user",
		Label:      firstNonEmpty(attributes["member_name"], attributes["subject_name"], attributes["display_name"], attributes["email"], userID),
		Attributes: map[string]string{
			"email":       strings.TrimSpace(attributes["email"]),
			"member_id":   userID,
			"member_type": firstNonEmpty(attributes["member_type"], "user"),
			"user_id":     userID,
		},
	})
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, attributes["email"], event.GetOccurredAt())
	addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationMemberOf, map[string]string{"event_id": event.GetId(), "match_type": "auth0_organization_member"}))
	return identityProjectionResult(entities, links)
}

func auth0RoleUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, auth0IdentityProfile)
}

func auth0OrganizationMemberRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := identityRoleAssignmentProjections(event, auth0IdentityProfile)
	if err != nil {
		return nil, nil, err
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	organizationID := strings.TrimSpace(attributes["organization_id"])
	roleID := strings.TrimSpace(attributes["role_id"])
	if organizationID == "" || roleID == "" {
		return entities, links, nil
	}
	entityMap := map[string]*ports.ProjectedEntity{}
	linkMap := map[string]*ports.ProjectedLink{}
	for _, entity := range entities {
		addEntity(entityMap, entity)
	}
	for _, link := range links {
		addLink(linkMap, link)
	}
	addAuth0OrganizationEntity(entityMap, tenantID, event.GetSourceId(), organizationID, organizationID, attributes)
	roleKind := "role"
	if identityProjectionPrivileged(attributes) {
		roleKind = "admin_role"
	}
	roleURN := projectionURN(tenantID, "auth0_"+roleKind, roleID)
	orgURN := auth0OrganizationURN(tenantID, organizationID)
	addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), roleURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "auth0_organization_role_scope"}))
	return identityProjectionResult(entityMap, linkMap)
}

func auth0OrganizationURN(tenantID string, organizationID string) string {
	return projectionURN(tenantID, "auth0_organization", organizationID)
}

func addAuth0OrganizationEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, organizationID string, label string, attributes map[string]string) {
	if organizationID == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        auth0OrganizationURN(tenantID, organizationID),
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "auth0.organization",
		Label:      firstNonEmpty(label, organizationID),
		Attributes: map[string]string{
			"display_name":      strings.TrimSpace(attributes["display_name"]),
			"organization_id":   organizationID,
			"organization_name": strings.TrimSpace(attributes["organization_name"]),
		},
	})
}

func auth0EnabledClientIDs(event *cerebrov1.EventEnvelope, attributes map[string]string) []string {
	seen := map[string]struct{}{}
	clientIDs := []string{}
	add := func(value string) {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			clientIDs = append(clientIDs, part)
		}
	}
	add(attributes["enabled_clients"])
	payload := payloadMap(event)
	switch raw := payload["enabled_clients"].(type) {
	case []any:
		for _, item := range raw {
			add(fmt.Sprint(item))
		}
	case []string:
		for _, item := range raw {
			add(item)
		}
	case string:
		add(raw)
	}
	return clientIDs
}
