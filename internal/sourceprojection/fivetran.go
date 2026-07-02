package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var fivetranIdentityProfile = identityProjectionProfile{Provider: "fivetran"}

func fivetranUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, fivetranIdentityProfile)
}

func fivetranRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranRuntimeAssetProjections(event)
}

func fivetranTeamsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, fivetranIdentityProfile)
}

func fivetranGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, fivetranIdentityProfile)
}

func fivetranScopedMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	scopeType, scopeID := fivetranMembershipScope(event, attributes)
	memberType := fivetranMembershipMemberType(event, attributes)
	memberID := firstNonEmpty(attributes["member_id"], attributes["resource_id"], attributes["id"], attributes["user_id"], attributes["group_id"], attributes["connection_id"])
	if scopeID == "" || memberID == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scopeURN := fivetranPrincipalOrAssetURN(tenantID, scopeType, scopeID)
	memberURN := fivetranPrincipalOrAssetURN(tenantID, memberType, memberID)
	addFivetranMembershipEntity(entities, tenantID, event.GetSourceId(), scopeURN, scopeType, scopeID, firstNonEmpty(attributes["scope_name"], attributes[scopeType+"_name"], scopeID), attributes)
	addFivetranMembershipEntity(entities, tenantID, event.GetSourceId(), memberURN, memberType, memberID, firstNonEmpty(attributes["member_name"], attributes["resource_name"], attributes["name"], attributes["email"], memberID), attributes)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, scopeURN, relationMemberOf, compactAttributes(map[string]string{
		"event_id":      event.GetId(),
		"match_type":    "fivetran_" + scopeType + "_" + memberType + "_membership",
		"member_id":     memberID,
		"member_type":   memberType,
		"role":          strings.TrimSpace(attributes["role"]),
		"scope_id":      scopeID,
		"scope_type":    scopeType,
		"source_kind":   strings.TrimSpace(event.GetKind()),
		"source_system": "fivetran",
	})))
	return identityProjectionResult(entities, links)
}

func fivetranCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := fivetranRuntimeAssetProjections(event)
	if err != nil {
		return nil, nil, err
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	connectionID := strings.TrimSpace(attributes["connection_id"])
	credentialID := firstNonEmpty(attributes["credential_id"], attributes["resource_id"], attributes["id"], attributes["hash"], attributes["public_key"])
	connectionURN := fivetranRuntimeAssetURN(tenantID, "connection", connectionID)
	credentialURN := fivetranRuntimeAssetURN(tenantID, firstNonEmpty(attributes["resource_type"], "credential"), credentialID)
	if connectionURN == "" || credentialURN == "" {
		return entities, links, nil
	}
	entityMap, linkMap := projectionMaps(entities, links)
	addEntity(entityMap, &ports.ProjectedEntity{
		URN:        connectionURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime.fivetran.connection",
		Label:      connectionID,
		Attributes: compactAttributes(map[string]string{
			"resource_id":       connectionID,
			"resource_type":     "connection",
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		}),
	})
	addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), credentialURN, connectionURN, relationAssignedTo, compactAttributes(map[string]string{
		"event_id":        event.GetId(),
		"match_type":      "fivetran_connection_credential",
		"connection_id":   connectionID,
		"credential_id":   credentialID,
		"credential_type": firstNonEmpty(attributes["resource_type"], "credential"),
	})))
	outEntities, outLinks := entitiesAndLinks(entityMap, linkMap)
	return outEntities, outLinks, nil
}

func fivetranRuntimeAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], fivetranKindFamily(event), "asset")
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], attributes["id"], attributes["name"], event.GetId())
	resourceURN := fivetranRuntimeAssetURN(tenantID, resourceType, resourceID)
	if explicitURN := strings.TrimSpace(attributes["resource_urn"]); explicitURN != "" {
		resourceURN = explicitURN
	}
	if resourceURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime.fivetran." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."),
		Label:      firstNonEmpty(attributes["resource_name"], attributes["role_name"], attributes["group_name"], attributes["name"], resourceID),
		Attributes: compactAttributes(map[string]string{
			"destination_id":    strings.TrimSpace(attributes["destination_id"]),
			"group_id":          strings.TrimSpace(attributes["group_id"]),
			"paused":            strings.TrimSpace(attributes["paused"]),
			"record_class":      strings.TrimSpace(attributes["record_class"]),
			"resource_id":       resourceID,
			"resource_name":     firstNonEmpty(attributes["resource_name"], attributes["role_name"], attributes["group_name"], attributes["name"]),
			"resource_type":     resourceType,
			"role_id":           strings.TrimSpace(attributes["role_id"]),
			"role_name":         strings.TrimSpace(attributes["role_name"]),
			"schedule_type":     strings.TrimSpace(attributes["schedule_type"]),
			"schema":            strings.TrimSpace(attributes["schema"]),
			"service":           strings.TrimSpace(attributes["service"]),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			"source_system":     "fivetran",
			"status":            strings.TrimSpace(attributes["status"]),
			"sync_frequency":    strings.TrimSpace(attributes["sync_frequency"]),
			"transformation_id": strings.TrimSpace(attributes["transformation_id"]),
		}),
	})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      firstNonEmpty(attributes["evidence_type"], evidenceID),
			Attributes: compactAttributes(map[string]string{
				"evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"]),
				"evidence_cas_uri":    strings.TrimSpace(attributes["evidence_cas_uri"]),
				"evidence_id":         evidenceID,
			}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, resourceURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func fivetranMembershipScope(event *cerebrov1.EventEnvelope, attributes map[string]string) (string, string) {
	kind := fivetranKindFamily(event)
	switch {
	case strings.HasPrefix(kind, "user_"):
		return "user", strings.TrimSpace(attributes["user_id"])
	case strings.HasPrefix(kind, "team_"):
		return "team", strings.TrimSpace(attributes["team_id"])
	case strings.HasPrefix(kind, "group_"):
		return "group", strings.TrimSpace(attributes["group_id"])
	default:
		return "scope", firstNonEmpty(attributes["scope_id"], attributes["user_id"], attributes["team_id"], attributes["group_id"])
	}
}

func fivetranMembershipMemberType(event *cerebrov1.EventEnvelope, attributes map[string]string) string {
	if memberType := strings.TrimSpace(attributes["member_type"]); memberType != "" && memberType != "membership" {
		return normalizeCloudType(memberType)
	}
	kind := fivetranKindFamily(event)
	switch {
	case strings.HasSuffix(kind, "_users"):
		return "user"
	case strings.HasSuffix(kind, "_groups"):
		return "group"
	case strings.HasSuffix(kind, "_connections"):
		return "connection"
	default:
		return "member"
	}
}

func addFivetranMembershipEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, entityType string, id string, label string, eventAttributes map[string]string) {
	if urn == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: fivetranEntityType(entityType),
		Label:      firstNonEmpty(label, id),
		Attributes: compactAttributes(map[string]string{
			"email":             strings.TrimSpace(eventAttributes["email"]),
			"entity_id":         id,
			"entity_type":       entityType,
			"resource_id":       id,
			"source_runtime_id": strings.TrimSpace(eventAttributes[ports.EventAttributeSourceRuntimeID]),
			"source_system":     "fivetran",
			"status":            strings.TrimSpace(eventAttributes["status"]),
		}),
	})
}

func fivetranPrincipalOrAssetURN(tenantID string, entityType string, id string) string {
	switch fivetranIdentityKind(entityType) {
	case "user":
		return identityUserURN(tenantID, fivetranIdentityProfile.Provider, id, "")
	case "group":
		return identityGroupURN(tenantID, fivetranIdentityProfile.Provider, id, "")
	default:
		return fivetranRuntimeAssetURN(tenantID, entityType, id)
	}
}

func fivetranRuntimeAssetURN(tenantID string, resourceType string, id string) string {
	if strings.TrimSpace(id) == "" {
		return ""
	}
	return projectionURN(tenantID, "runtime_fivetran_"+normalizeCloudType(resourceType), id)
}

func fivetranEntityType(entityType string) string {
	if identityKind := fivetranIdentityKind(entityType); identityKind != "" {
		return fivetranIdentityProfile.entityType(identityKind)
	}
	return "runtime.fivetran." + strings.ReplaceAll(normalizeCloudType(entityType), "_", ".")
}

func fivetranIdentityKind(entityType string) string {
	switch normalizeCloudType(entityType) {
	case "user", "users":
		return "user"
	case "group", "groups", "team", "teams":
		return "group"
	default:
		return ""
	}
}

func fivetranKindFamily(event *cerebrov1.EventEnvelope) string {
	kind := strings.TrimSpace(event.GetKind())
	if strings.HasPrefix(kind, "fivetran.") {
		return strings.TrimPrefix(kind, "fivetran.")
	}
	if _, family, ok := strings.Cut(kind, "."); ok {
		return family
	}
	return kind
}
