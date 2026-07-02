package sourceprojection

import (
	"encoding/json"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var auth0IdentityProfile = identityProjectionProfile{Provider: "auth0"}

func auth0UsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, auth0IdentityProfile)
}

func auth0RolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := identityGroupProjections(event, auth0IdentityProfile)
	if err != nil {
		return nil, nil, err
	}
	roleEntities, roleLinks, err := auth0RoleEntitlementProjections(event)
	if err != nil {
		return nil, nil, err
	}
	return mergeProjectionSlices(entities, roleEntities, links, roleLinks)
}

func auth0AuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, auth0IdentityProfile)
}

func auth0OrganizationsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	orgID := firstNonEmpty(attributes["organization_id"], attributes["group_id"], attributes["resource_id"])
	orgURN := projectionURN(tenantID, "auth0_org", orgID)
	if orgURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addAuth0OrgEntity(entities, tenantID, event.GetSourceId(), orgURN, attributes)
	return identityProjectionResult(entities, nil)
}

func auth0OrganizationMembersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	orgID := firstNonEmpty(attributes["organization_id"], attributes["group_id"])
	userID := firstNonEmpty(attributes["member_user_id"], attributes["user_id"], attributes["member_id"])
	email := firstNonEmpty(attributes["member_email"], attributes["email"])
	orgURN := projectionURN(tenantID, "auth0_org", orgID)
	userURN := identityUserURN(tenantID, auth0IdentityProfile.Provider, userID, email)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addAuth0OrgEntity(entities, tenantID, event.GetSourceId(), orgURN, attributes)
	if userURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: auth0IdentityProfile.entityType("user"),
			Label:      firstNonEmpty(attributes["member_name"], attributes["display_name"], email, userID),
			Attributes: map[string]string{"email": email, "user_id": userID},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationMemberOf, map[string]string{"event_id": event.GetId()}))
		}
	}
	for _, role := range auth0ScopeValues(attributes["role"]) {
		roleURN := identityGroupURN(tenantID, auth0IdentityProfile.Provider, role, "")
		if roleURN == "" || userURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{URN: roleURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: auth0IdentityProfile.entityType("group"), Label: role, Attributes: map[string]string{"group_id": role, "group_name": role}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, roleURN, relationMemberOf, map[string]string{"event_id": event.GetId(), "role_scope": "organization"}))
	}
	return identityProjectionResult(entities, links)
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
	connectionID := firstNonEmpty(attributes["connection_id"], attributes["resource_id"], attributes["app_id"])
	connectionURN := projectionURN(tenantID, "auth0_connection", connectionID)
	if connectionURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	connAttrs := map[string]string{
		"connection_id":    connectionID,
		"connection_name":  firstNonEmpty(attributes["connection_name"], attributes["resource_name"], attributes["app_name"]),
		"enabled_clients":  strings.TrimSpace(attributes["enabled_clients"]),
		"strategy":         strings.TrimSpace(attributes["strategy"]),
		"strategy_version": strings.TrimSpace(attributes["strategy_version"]),
	}
	trimEmptyProjectionAttributes(connAttrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        connectionURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "auth0.connection",
		Label:      firstNonEmpty(connAttrs["connection_name"], connectionID),
		Attributes: connAttrs,
	})
	for _, clientID := range auth0ScopeValues(attributes["enabled_clients"]) {
		clientURN := addIdentityOAuthClient(entities, tenantID, event.GetSourceId(), auth0IdentityProfile, clientID, clientID, map[string]string{"client_id": clientID})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), clientURN, connectionURN, relationDependsOn, map[string]string{"event_id": event.GetId(), "match_type": "auth0_connection_enabled_client"}))
	}
	return identityProjectionResult(entities, links)
}

func auth0ResourceServersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	apiURN := addAuth0APIEntity(entities, tenantID, event.GetSourceId(), attributes)
	apiIdentifier := firstNonEmpty(attributes["api_identifier"], attributes["audience"], attributes["api_id"], attributes["resource_id"])
	for _, scope := range auth0ScopeValues(firstNonEmpty(attributes["scopes"], attributes["scope"])) {
		entitlementURN := auth0APIEntitlementURN(tenantID, apiIdentifier, scope)
		if entitlementURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        entitlementURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: auth0IdentityProfile.entityType("entitlement"),
			Label:      scope,
			Attributes: map[string]string{"api_id": firstNonEmpty(attributes["api_id"], attributes["resource_id"]), "scope": scope},
		})
		if apiURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), apiURN, entitlementURN, relationGrantsEntitlement, map[string]string{"event_id": event.GetId(), "match_type": "auth0_api_scope"}))
		}
	}
	return identityProjectionResult(entities, links)
}

func auth0ClientGrantsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return auth0GrantProjections(event, "application")
}

func auth0GrantsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return auth0GrantProjections(event, "user")
}

func auth0UserRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, auth0IdentityProfile)
}

func auth0UserAuthenticationMethodsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, auth0IdentityProfile)
}

func auth0GuardianFactorsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, auth0IdentityProfile)
}

func auth0RoleEntitlementProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	roleID := firstNonEmpty(attributes["group_id"], attributes["id"], attributes["resource_id"])
	roleURN := identityGroupURN(tenantID, auth0IdentityProfile.Provider, roleID, attributes["group_email"])
	if roleURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	capability := "identity_role"
	if strings.Contains(strings.ToLower(firstNonEmpty(attributes["group_name"], attributes["name"], roleID)), "admin") {
		capability = "identity_admin"
	}
	entitlementURN, capabilityURN := addIdentityRoleEntitlement(entities, tenantID, event, auth0IdentityProfile, roleURN, roleID, capability == "identity_admin", map[string]string{
		"capability":       capability,
		"entitlement_id":   "role:" + roleID,
		"entitlement_name": firstNonEmpty(attributes["group_name"], attributes["name"], roleID),
		"role_name":        firstNonEmpty(attributes["group_name"], attributes["name"], roleID),
		"role_type":        "auth0_role",
	})
	if entitlementURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	}
	if entitlementURN != "" && capabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func auth0GrantProjections(event *cerebrov1.EventEnvelope, defaultSubjectType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	grantID := firstNonEmpty(attributes["client_grant_id"], attributes["grant_id"], attributes["resource_id"], attributes["entitlement_id"])
	clientID := strings.TrimSpace(firstNonEmpty(attributes["client_id"], attributes["app_id"]))
	audience := strings.TrimSpace(attributes["audience"])
	subjectType := firstNonEmpty(attributes["subject_type"], defaultSubjectType)
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["user_id"], clientID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	apiURN := addAuth0APIEntity(entities, tenantID, event.GetSourceId(), map[string]string{"api_identifier": audience, "api_name": audience, "resource_id": audience})
	clientURN := addIdentityOAuthClient(entities, tenantID, event.GetSourceId(), auth0IdentityProfile, clientID, clientID, map[string]string{"client_id": clientID})
	subjectURN := identityPrincipalURN(tenantID, auth0IdentityProfile.Provider, subjectType, subjectID, "")
	if subjectURN != "" && subjectType != "application" {
		addEntity(entities, &ports.ProjectedEntity{URN: subjectURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: auth0IdentityProfile.entityType(identityPrincipalType(subjectType)), Label: subjectID, Attributes: map[string]string{"subject_type": subjectType, "user_id": subjectID}})
	}
	if grantID != "" {
		grantURN := projectionURN(tenantID, "auth0_grant", grantID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        grantURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "auth0.grant",
			Label:      firstNonEmpty(attributes["resource_name"], audience, grantID),
			Attributes: map[string]string{"audience": audience, "client_id": clientID, "grant_id": grantID, "subject_id": subjectID, "subject_type": subjectType},
		})
		if apiURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), grantURN, apiURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "auth0_grant_api"}))
		}
	}
	for _, scope := range auth0ScopeValues(firstNonEmpty(attributes["scope"], attributes["entitlement"])) {
		entitlementURN := auth0APIEntitlementURN(tenantID, audience, scope)
		if entitlementURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        entitlementURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: auth0IdentityProfile.entityType("entitlement"),
			Label:      scope,
			Attributes: map[string]string{"audience": audience, "client_id": clientID, "scope": scope},
		})
		if apiURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), apiURN, entitlementURN, relationGrantsEntitlement, map[string]string{"event_id": event.GetId(), "match_type": "auth0_api_scope"}))
		}
		if clientURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), clientURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
		}
		if subjectURN != "" && subjectURN != clientURN && subjectType != "application" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, entitlementURN, relationAssignedTo, map[string]string{"event_id": event.GetId(), "match_type": "auth0_user_grant_scope"}))
		}
		capabilityURN := addIdentityCapability(entities, tenantID, event.GetSourceId(), "app_access", "Application access", map[string]string{"source": "auth0"})
		if capabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, identityEventLinkAttributes(event)))
		}
	}
	return identityProjectionResult(entities, links)
}

func addAuth0OrgEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, orgURN string, attributes map[string]string) {
	if orgURN == "" {
		return
	}
	orgID := firstNonEmpty(attributes["organization_id"], attributes["group_id"], attributes["resource_id"])
	orgAttrs := map[string]string{"display_name": strings.TrimSpace(attributes["display_name"]), "organization_id": orgID, "organization_name": strings.TrimSpace(attributes["organization_name"])}
	trimEmptyProjectionAttributes(orgAttrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        orgURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "auth0.org",
		Label:      firstNonEmpty(attributes["display_name"], attributes["organization_name"], orgID),
		Attributes: orgAttrs,
	})
}

func addAuth0APIEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attributes map[string]string) string {
	apiID := firstNonEmpty(attributes["api_identifier"], attributes["audience"], attributes["api_id"], attributes["resource_id"])
	apiURN := projectionURN(tenantID, "auth0_api", apiID)
	if apiURN == "" {
		return ""
	}
	apiAttrs := map[string]string{
		"api_id":         firstNonEmpty(attributes["api_id"], attributes["resource_id"]),
		"api_identifier": apiID,
		"api_name":       firstNonEmpty(attributes["api_name"], attributes["resource_name"], apiID),
		"signing_alg":    strings.TrimSpace(attributes["signing_alg"]),
	}
	trimEmptyProjectionAttributes(apiAttrs)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        apiURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "auth0.api",
		Label:      firstNonEmpty(apiAttrs["api_name"], apiID),
		Attributes: apiAttrs,
	})
	return apiURN
}

func auth0APIEntitlementURN(tenantID string, audience string, scope string) string {
	return projectionURN(tenantID, "auth0_entitlement", firstNonEmpty(audience, "api"), scope)
}

func auth0ScopeValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var objectScopes []auth0ScopeObject
	if err := json.Unmarshal([]byte(raw), &objectScopes); err == nil && len(objectScopes) > 0 {
		return auth0ScopeObjectValues(objectScopes)
	}
	if strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte("["+raw+"]"), &objectScopes); err == nil && len(objectScopes) > 0 {
			return auth0ScopeObjectValues(objectScopes)
		}
	}
	var stringScopes []string
	if err := json.Unmarshal([]byte(raw), &stringScopes); err == nil {
		return compactProjectionStrings(stringScopes)
	}
	return splitCSV(raw)
}

type auth0ScopeObject struct {
	Value string `json:"value"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

func auth0ScopeObjectValues(scopes []auth0ScopeObject) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if value := firstNonEmpty(scope.Value, scope.ID, scope.Name); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func compactProjectionStrings(values []string) []string {
	out := []string{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func mergeProjectionSlices(leftEntities []*ports.ProjectedEntity, rightEntities []*ports.ProjectedEntity, leftLinks []*ports.ProjectedLink, rightLinks []*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, entity := range append(leftEntities, rightEntities...) {
		addEntity(entities, entity)
	}
	for _, link := range append(leftLinks, rightLinks...) {
		addLink(links, link)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}
