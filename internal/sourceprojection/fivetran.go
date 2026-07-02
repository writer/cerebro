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

func fivetranAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranGenericAssetProjections(event)
}

func fivetranRecordsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranGenericAssetProjections(event)
}

func fivetranPoliciesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return fivetranGenericPolicyProjections(event)
}

func fivetranAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, fivetranIdentityProfile)
}

func fivetranGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."),
		Label:      firstNonEmpty(attributes["resource_name"], resourceID),
		Attributes: map[string]string{
			"resource_id":       resourceID,
			"resource_type":     resourceType,
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		},
	})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      evidenceID,
			Attributes: map[string]string{
				"evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"]),
				"evidence_cas_uri":    strings.TrimSpace(attributes["evidence_cas_uri"]),
				"evidence_id":         evidenceID,
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
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
	linkMemberType, linkMemberID, linkMemberURN, linkScopeType, linkScopeID, linkScopeURN := fivetranMembershipLinkEndpoints(event, scopeType, scopeID, scopeURN, memberType, memberID, memberURN)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), linkMemberURN, linkScopeURN, relationMemberOf, compactAttributes(map[string]string{
		"event_id":      event.GetId(),
		"match_type":    "fivetran_" + linkScopeType + "_" + linkMemberType + "_membership",
		"member_id":     linkMemberID,
		"member_type":   linkMemberType,
		"role":          strings.TrimSpace(attributes["role"]),
		"scope_id":      linkScopeID,
		"scope_type":    linkScopeType,
		"source_kind":   strings.TrimSpace(event.GetKind()),
		"source_system": "fivetran",
	})))
	return identityProjectionResult(entities, links)
}

func fivetranMembershipLinkEndpoints(event *cerebrov1.EventEnvelope, scopeType string, scopeID string, scopeURN string, memberType string, memberID string, memberURN string) (string, string, string, string, string, string) {
	switch fivetranKindFamily(event) {
	case "user_groups", "team_groups":
		return scopeType, scopeID, scopeURN, memberType, memberID, memberURN
	default:
		return memberType, memberID, memberURN, scopeType, scopeID, scopeURN
	}
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
	destinationID := strings.TrimSpace(attributes["destination_id"])
	groupID := strings.TrimSpace(attributes["group_id"])
	credentialID := firstNonEmpty(attributes["credential_id"], attributes["resource_id"], attributes["id"], attributes["hash"], attributes["public_key"])
	targetType := "connection"
	targetID := connectionID
	if targetID == "" {
		targetType = "destination"
		targetID = destinationID
	}
	if targetID == "" {
		targetType = "group"
		targetID = groupID
	}
	targetURN := fivetranPrincipalOrAssetURN(tenantID, targetType, targetID)
	credentialURN := fivetranRuntimeAssetURN(tenantID, firstNonEmpty(attributes["resource_type"], "credential"), credentialID)
	if targetURN == "" || credentialURN == "" {
		return entities, links, nil
	}
	entityMap, linkMap := projectionMaps(entities, links)
	addEntity(entityMap, &ports.ProjectedEntity{
		URN:        targetURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: fivetranEntityType(targetType),
		Label:      targetID,
		Attributes: compactAttributes(map[string]string{
			"resource_id":       targetID,
			"resource_type":     targetType,
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			"source_system":     "fivetran",
		}),
	})
	addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), credentialURN, targetURN, relationAssignedTo, compactAttributes(map[string]string{
		"event_id":        event.GetId(),
		"match_type":      "fivetran_" + targetType + "_credential",
		"connection_id":   connectionID,
		"destination_id":  destinationID,
		"group_id":        groupID,
		"credential_id":   credentialID,
		"credential_type": firstNonEmpty(attributes["resource_type"], "credential"),
		"target_type":     targetType,
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
	resourceID := fivetranRuntimeResourceID(event, attributes, resourceType)
	resourceURN := fivetranRuntimeAssetURN(tenantID, resourceType, resourceID)
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
	fivetranRuntimeAssetRelationshipProjections(event, tenantID, resourceURN, resourceType, attributes, entities, links)
	return identityProjectionResult(entities, links)
}

func fivetranRuntimeResourceID(event *cerebrov1.EventEnvelope, attributes map[string]string, resourceType string) string {
	if fivetranUsesCompositeRuntimeID(resourceType) {
		parts := fivetranIDParts(
			attributes["connection_id"],
			attributes["schema_name"],
			attributes["table_name"],
			firstNonEmpty(attributes["column_name"], attributes["resource_id"], attributes["external_id"], attributes["id"], attributes["name"]),
		)
		if len(parts) > 0 {
			return strings.Join(parts, "/")
		}
	}
	return firstNonEmpty(attributes["resource_id"], attributes["external_id"], attributes["id"], attributes["name"], event.GetId())
}

func fivetranIDParts(values ...string) []string {
	parts := []string{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			parts = append(parts, value)
		}
	}
	return parts
}

func fivetranUsesCompositeRuntimeID(resourceType string) bool {
	return normalizeCloudType(resourceType) == "connection_table_column"
}

func fivetranGenericPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	policyID := firstNonEmpty(attributes["policy_id"], event.GetId())
	policyURN := projectionURN(tenantID, "policy", policyID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        policyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "policy",
		Label:      firstNonEmpty(attributes["policy_name"], policyID),
		Attributes: compactAttributes(map[string]string{
			"policy_id":         policyID,
			"policy_severity":   strings.TrimSpace(attributes["policy_severity"]),
			"policy_status":     strings.TrimSpace(attributes["policy_status"]),
			"policy_type":       strings.TrimSpace(attributes["policy_type"]),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		}),
	})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      evidenceID,
			Attributes: compactAttributes(map[string]string{
				"evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"]),
				"evidence_cas_uri":    strings.TrimSpace(attributes["evidence_cas_uri"]),
				"evidence_id":         evidenceID,
			}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func fivetranRuntimeAssetRelationshipProjections(event *cerebrov1.EventEnvelope, tenantID string, resourceURN string, resourceType string, attributes map[string]string, entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink) {
	groupID := strings.TrimSpace(attributes["group_id"])
	if groupID != "" && normalizeCloudType(resourceType) != "group" {
		groupURN := fivetranPrincipalOrAssetURN(tenantID, "group", groupID)
		addFivetranMembershipEntity(entities, tenantID, event.GetSourceId(), groupURN, "group", groupID, firstNonEmpty(attributes["group_name"], groupID), attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, groupURN, relationBelongsTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_asset_group")))
	}
	destinationID := strings.TrimSpace(attributes["destination_id"])
	if destinationID != "" && normalizeCloudType(resourceType) != "destination" {
		destinationURN := fivetranRuntimeAssetURN(tenantID, "destination", destinationID)
		addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), destinationURN, "destination", destinationID, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, destinationURN, relationBelongsTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_asset_destination")))
	}
	connectionID := strings.TrimSpace(attributes["connection_id"])
	if connectionID != "" && normalizeCloudType(resourceType) != "connection" {
		connectionURN := fivetranRuntimeAssetURN(tenantID, "connection", connectionID)
		addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), connectionURN, "connection", connectionID, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, connectionURN, relationBelongsTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_asset_connection")))
	}
	proxyAgentID := strings.TrimSpace(attributes["proxy_agent_id"])
	if proxyAgentID != "" && normalizeCloudType(resourceType) != "proxy_agent" {
		proxyURN := fivetranRuntimeAssetURN(tenantID, "proxy_agent", proxyAgentID)
		addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), proxyURN, "proxy_agent", proxyAgentID, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, proxyURN, relationBelongsTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_asset_proxy_agent")))
		if connectionID == "" {
			connectionID = firstNonEmpty(attributes["resource_id"], attributes["id"])
		}
		if connectionID != "" && normalizeCloudType(resourceType) == "proxy_agent_connection" {
			connectionURN := fivetranRuntimeAssetURN(tenantID, "connection", connectionID)
			addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), connectionURN, "connection", connectionID, attributes)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), connectionURN, proxyURN, relationAttachedTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_proxy_connection")))
		}
	}
	projectID := firstNonEmpty(attributes["project_id"], attributes["transformation_project_id"])
	if projectID != "" && normalizeCloudType(resourceType) != "transformation_project" {
		projectURN := fivetranRuntimeAssetURN(tenantID, "transformation_project", projectID)
		addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), projectURN, "transformation_project", projectID, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, projectURN, relationBelongsTo, fivetranAssetRelationAttributes(event, attributes, "fivetran_transformation_project")))
	}
	externalSecretManagerID := strings.TrimSpace(attributes["external_secret_manager_id"])
	if externalSecretManagerID != "" && normalizeCloudType(resourceType) != "external_secret_manager" {
		managerURN := fivetranRuntimeAssetURN(tenantID, "external_secret_manager", externalSecretManagerID)
		addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), managerURN, "external_secret_manager", externalSecretManagerID, attributes)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, managerURN, relationDependsOn, fivetranAssetRelationAttributes(event, attributes, "fivetran_external_secret_manager_usage")))
		usingType := normalizeCloudType(firstNonEmpty(attributes["entity_type"], attributes["entity_resource_type"]))
		usingID := firstNonEmpty(attributes["connection_id"], attributes["destination_id"], attributes["entity_id"], attributes["resource_id"])
		if (usingType == "connection" || usingType == "destination") && usingID != "" {
			usingURN := fivetranRuntimeAssetURN(tenantID, usingType, usingID)
			addFivetranRuntimeAssetReference(entities, tenantID, event.GetSourceId(), usingURN, usingType, usingID, attributes)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), usingURN, managerURN, relationDependsOn, fivetranAssetRelationAttributes(event, attributes, "fivetran_external_secret_manager_resource")))
		}
	}
}

func addFivetranRuntimeAssetReference(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, resourceType string, id string, eventAttributes map[string]string) {
	if urn == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: fivetranEntityType(resourceType),
		Label:      firstNonEmpty(eventAttributes[resourceType+"_name"], eventAttributes["resource_name"], id),
		Attributes: compactAttributes(map[string]string{
			"resource_id":       id,
			"resource_type":     resourceType,
			"source_runtime_id": strings.TrimSpace(eventAttributes[ports.EventAttributeSourceRuntimeID]),
			"source_system":     "fivetran",
		}),
	})
}

func fivetranAssetRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string, matchType string) map[string]string {
	return compactAttributes(map[string]string{
		"connection_id":              strings.TrimSpace(attributes["connection_id"]),
		"destination_id":             strings.TrimSpace(attributes["destination_id"]),
		"event_id":                   event.GetId(),
		"external_secret_manager_id": strings.TrimSpace(attributes["external_secret_manager_id"]),
		"group_id":                   strings.TrimSpace(attributes["group_id"]),
		"match_type":                 matchType,
		"project_id":                 firstNonEmpty(attributes["project_id"], attributes["transformation_project_id"]),
		"proxy_agent_id":             strings.TrimSpace(attributes["proxy_agent_id"]),
		"source_kind":                strings.TrimSpace(event.GetKind()),
		"source_system":              "fivetran",
	})
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
