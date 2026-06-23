package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func duoUserURN(tenantID string, userID string) string {
	return projectionURN(tenantID, "duo_user", strings.TrimSpace(userID))
}

func duoGroupURN(tenantID string, groupID string) string {
	return projectionURN(tenantID, "duo_group", strings.TrimSpace(groupID))
}

func duoEndpointURN(tenantID string, endpointID string) string {
	return projectionURN(tenantID, "duo_endpoint", strings.TrimSpace(endpointID))
}

func duoPhoneURN(tenantID string, phoneID string) string {
	return projectionURN(tenantID, "duo_phone", strings.TrimSpace(phoneID))
}

func duoTokenURN(tenantID string, tokenID string) string {
	return projectionURN(tenantID, "duo_token", strings.TrimSpace(tokenID))
}

func duoWebAuthnCredentialURN(tenantID string, credentialID string) string {
	return projectionURN(tenantID, "duo_web_authn_credential", strings.TrimSpace(credentialID))
}

func duoEntity(event *cerebrov1.EventEnvelope, urn string, entityType string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   event.GetTenantId(),
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: attrs,
	}
}

func duoAttributes(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		addProjectedAttribute(out, key, value)
	}
	return out
}

// duoUserProjections materializes the Duo identity slice: a duo_user entity
// enriched with current MFA posture (status and enrollment state) plus a
// represents_identity link to the canonical email identity so MFA posture
// findings and cross-source identity traversal anchor on the same identity.
func duoUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	userID := strings.TrimSpace(attrs["user_id"])
	if userID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	userURN := duoUserURN(tenantID, userID)
	userAttrs := duoAttributes(map[string]string{
		"user_id":             userID,
		"username":            attrs["username"],
		"email":               attrs["email"],
		"realname":            attrs["realname"],
		"status":              attrs["status"],
		"is_enrolled":         attrs["is_enrolled"],
		"last_login_at":       attrs["last_login_at"],
		"lockout_reason":      attrs["lockout_reason"],
		"last_directory_sync": attrs["last_directory_sync"],
	})
	enrichDuoUserPosture(userAttrs, attrs)
	addEntity(entities, duoEntity(event, userURN, "duo.user", firstNonEmpty(attrs["username"], attrs["email"], userID), userAttrs))
	if email := strings.TrimSpace(attrs["email"]); email != "" {
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// enrichDuoUserPosture derives normalized MFA and activity posture flags from
// Duo user snapshot attributes so identity findings and graph queries can
// reference a consistent vocabulary across sources.
func enrichDuoUserPosture(projected map[string]string, source map[string]string) {
	if enrolled := strings.TrimSpace(source["is_enrolled"]); enrolled != "" {
		projected["mfa_enrolled"] = boolString(projectionBool(enrolled))
	}
	if status := strings.ToLower(strings.TrimSpace(source["status"])); status != "" {
		projected["active"] = boolString(status == "active" || status == "bypass")
	}
}

func duoGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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
	addEntity(entities, duoEntity(event, duoGroupURN(tenantID, groupID), "duo.group", firstNonEmpty(attrs["name"], groupID), duoAttributes(map[string]string{
		"group_id":    groupID,
		"name":        attrs["name"],
		"description": attrs["description"],
		"status":      attrs["status"],
	})))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func duoEndpointProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	endpointID := strings.TrimSpace(attrs["endpoint_id"])
	if endpointID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, duoEntity(event, duoEndpointURN(tenantID, endpointID), "duo.endpoint", firstNonEmpty(attrs["hostname"], endpointID), duoAttributes(map[string]string{
		"endpoint_id":            endpointID,
		"hostname":               attrs["hostname"],
		"os":                     attrs["os"],
		"os_version":             attrs["os_version"],
		"browser":                attrs["browser"],
		"disk_encryption_status": attrs["disk_encryption_status"],
		"last_seen_at":           attrs["last_seen_at"],
	})))
	projectedEntities, _ := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return projectedEntities, nil, nil
}

func duoPhoneProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return duoFactorProjections(event, "phone_id", duoPhoneURN, "duo.phone", map[string]string{
		"name":         "name",
		"number":       "number",
		"platform":     "platform",
		"model":        "model",
		"activated":    "activated",
		"encrypted":    "encrypted",
		"screenlock":   "screenlock",
		"tampered":     "tampered",
		"capabilities": "capabilities",
		"last_seen_at": "last_seen_at",
		"factor_type":  "",
	})
}

func duoTokenProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return duoFactorProjections(event, "token_id", duoTokenURN, "duo.token", map[string]string{
		"serial":       "serial",
		"type":         "type",
		"totp_step":    "totp_step",
		"last_seen_at": "last_seen_at",
		"factor_type":  "",
	})
}

// duoWebAuthnCredentialProjections materializes a Duo WebAuthn MFA factor and,
// when the factor reports its owning user, links the factor to the duo_user
// identity so the MFA control relationship is represented in the graph.
func duoWebAuthnCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	credentialID := strings.TrimSpace(attrs["credential_id"])
	if credentialID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	credentialURN := duoWebAuthnCredentialURN(tenantID, credentialID)
	addEntity(entities, duoEntity(event, credentialURN, "duo.web_authn_credential", firstNonEmpty(attrs["label"], attrs["credential_name"], credentialID), duoAttributes(map[string]string{
		"credential_id":   credentialID,
		"label":           attrs["label"],
		"credential_name": attrs["credential_name"],
		"user_id":         attrs["user_id"],
		"last_used_at":    attrs["last_used_at"],
		"factor_type":     "webauthn",
	})))
	addDuoFactorOwnerLink(entities, links, event, tenantID, credentialURN, attrs["user_id"])
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func duoFactorProjections(event *cerebrov1.EventEnvelope, idKey string, urnFunc func(string, string) string, entityType string, attributeMap map[string]string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	factorID := strings.TrimSpace(attrs[idKey])
	if factorID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	factorURN := urnFunc(tenantID, factorID)
	factorAttrs := duoAttributes(map[string]string{idKey: factorID})
	for target, source := range attributeMap {
		if target == "factor_type" {
			addProjectedAttribute(factorAttrs, "factor_type", duoFactorType(entityType))
			continue
		}
		addProjectedAttribute(factorAttrs, target, attrs[source])
	}
	addEntity(entities, duoEntity(event, factorURN, entityType, firstNonEmpty(attrs["name"], factorID), factorAttrs))
	addDuoFactorOwnerLink(entities, links, event, tenantID, factorURN, attrs["user_id"])
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func duoFactorType(entityType string) string {
	switch entityType {
	case "duo.phone":
		return "phone"
	case "duo.token":
		return "hardware_token"
	default:
		return ""
	}
}

func addDuoFactorOwnerLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, factorURN string, userID string) {
	userID = strings.TrimSpace(userID)
	if factorURN == "" || userID == "" {
		return
	}
	userURN := duoUserURN(tenantID, userID)
	addEntity(entities, duoEntity(event, userURN, "duo.user", userID, map[string]string{"user_id": userID}))
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "duo_mfa_factor",
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), factorURN, userURN, relationAssignedTo, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, factorURN, relationContains, linkAttrs))
}
