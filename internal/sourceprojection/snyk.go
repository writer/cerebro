package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func snykAssetsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykGenericAssetProjections(event)
}

func snykFindingsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykGenericFindingProjections(event)
}

func snykVulnerabilitiesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykGenericFindingProjections(event)
}

func snykOrgMembershipsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykMembershipProjections(event, "snyk_orgs", "snyk.orgs")
}

func snykGroupMembershipsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykMembershipProjections(event, "snyk_groups", "snyk.groups")
}

func snykServiceAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykServiceAccountProjections(event)
}

func snykGroupServiceAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykServiceAccountProjections(event)
}

func snykAuditLogsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykAuditProjections(event)
}

func snykGroupAuditLogsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykAuditProjections(event)
}

func snykCloudResourcesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykGenericAssetProjections(event)
}

func snykAssetProjectRelationshipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykAssetRelationshipProjections(event, "project_id", "snyk_projects", "snyk.projects")
}

func snykAssetTargetRelationshipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykAssetRelationshipProjections(event, "target_id", "snyk_targets", "snyk.targets")
}

func snykGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	assetID := firstNonEmpty(attributes["asset_id"], attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceID := firstNonEmpty(attributes["resource_id"], assetID, attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	assetURN := projectionURN(tenantID, "snyk_assets", assetID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: firstNonEmpty(attributes["resource_name"], resourceID), Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if assetURN != "" && assetURN != resourceURN {
		addEntity(entities, &ports.ProjectedEntity{URN: assetURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "snyk.assets", Label: firstNonEmpty(attributes["resource_name"], assetID), Attributes: map[string]string{"asset_id": assetID, "resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, resourceURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "snyk_asset_runtime_resource"}))
	}
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func snykMembershipProjections(event *cerebrov1.EventEnvelope, groupURNKind string, groupEntityType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	groupID := strings.TrimSpace(attributes["group_id"])
	groupURN := projectionURN(tenantID, groupURNKind, groupID)
	memberEmail := firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"])
	memberID := firstNonEmpty(attributes["member_user_id"], attributes["user_id"], attributes["member_id"], memberEmail)
	memberType := strings.ToLower(firstNonEmpty(attributes["member_type"], attributes["type"], "user"))
	memberURN := identityPrincipalURN(tenantID, "snyk", memberType, memberID, memberEmail)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: groupEntityType,
			Label:      firstNonEmpty(attributes["group_name"], groupID),
			Attributes: map[string]string{
				"group_id": groupID,
			},
		})
	}
	if memberURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        memberURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk." + identityPrincipalType(memberType),
			Label:      firstNonEmpty(attributes["member_name"], memberEmail, memberID),
			Attributes: map[string]string{
				"email":       memberEmail,
				"member_id":   memberID,
				"member_type": memberType,
				"role":        strings.TrimSpace(attributes["role"]),
			},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), memberURN, memberEmail, event.GetOccurredAt())
		if groupURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, groupURN, relationMemberOf, map[string]string{
				"event_id": event.GetId(),
				"role":     strings.TrimSpace(attributes["role"]),
			}))
		}
	}
	return identityProjectionResult(entities, links)
}

func snykAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	actorEmail := firstNonEmpty(attributes["actor_email"], attributes["email"])
	actorID := firstNonEmpty(attributes["actor_id"], actorEmail)
	actorURN := identityUserURN(tenantID, "snyk", actorID, actorEmail)
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["target_id"], attributes["project_id"], attributes["group_id"])
	resourceType := normalizeIdentifier(firstNonEmpty(attributes["resource_type"], attributes["target_type"], "resource"))
	resourceURNKind := snykAuditResourceURNKind(event, resourceType)
	resourceURN := ""
	if resourceURNKind != "" {
		resourceURN = projectionURN(tenantID, resourceURNKind, resourceID)
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk.user",
			Label:      firstNonEmpty(attributes["actor_name"], actorEmail, actorID),
			Attributes: map[string]string{"actor_id": strings.TrimSpace(attributes["actor_id"]), "email": actorEmail},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorEmail, event.GetOccurredAt())
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk." + strings.TrimPrefix(resourceURNKind, "snyk_"),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["target_name"], resourceID),
			Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType},
		})
	}
	if actorURN != "" && resourceURN != "" {
		actedAttrs := map[string]string{
			"event_id":   event.GetId(),
			"event_type": firstNonEmpty(attributes["event_type"], attributes["event_name"]),
		}
		addProjectedAttribute(actedAttrs, "at", eventObservedAt(event))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, actedAttrs))
	}
	return identityProjectionResult(entities, links)
}

func snykAuditResourceURNKind(event *cerebrov1.EventEnvelope, resourceType string) string {
	if urnKind := snykInventoryURNKind(resourceType); urnKind != "" {
		return urnKind
	}
	switch normalizeIdentifier(resourceType) {
	case "membership", "group_membership", "org_membership":
		attributes := event.GetAttributes()
		if strings.TrimSpace(attributes["group_id"]) != "" || normalizeIdentifier(event.GetKind()) == "snyk_group_audit_logs" {
			return "snyk_groups"
		}
		if strings.TrimSpace(attributes["org_id"]) != "" {
			return "snyk_orgs"
		}
	}
	return ""
}

func snykInventoryURNKind(resourceType string) string {
	switch normalizeIdentifier(resourceType) {
	case "org", "organization":
		return "snyk_orgs"
	case "group":
		return "snyk_groups"
	case "project":
		return "snyk_projects"
	case "target":
		return "snyk_targets"
	case "asset", "resource":
		return "snyk_assets"
	case "collection":
		return "snyk_collections"
	case "cloud_environment", "environment":
		return "snyk_cloud_environments"
	case "cloud_resource":
		return "snyk_assets"
	case "cloud_scan", "scan":
		return "snyk_cloud_scans"
	default:
		return ""
	}
}

func snykServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	accountID := firstNonEmpty(attributes["service_account_id"], attributes["resource_id"], event.GetId())
	accountURN := identityPrincipalURN(tenantID, "snyk", "service_account", accountID, "")
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if accountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        accountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk.service_account",
			Label:      firstNonEmpty(attributes["name"], attributes["resource_name"], accountID),
			Attributes: map[string]string{
				"service_account_id": accountID,
				"level":              strings.TrimSpace(attributes["level"]),
				"auth_type":          strings.TrimSpace(attributes["auth_type"]),
				"client_id":          strings.TrimSpace(attributes["client_id"]),
				"source_runtime_id":  strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			},
		})
	}
	roleID := firstNonEmpty(attributes["role_id"], attributes["role"])
	if accountURN != "" && roleID != "" {
		privileged := identityProjectionPrivileged(attributes)
		roleKind := "role"
		relation := relationAssignedTo
		if privileged {
			roleKind = "admin_role"
			relation = relationCanAdmin
		}
		roleURN := projectionURN(tenantID, "snyk_"+roleKind, roleID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk." + strings.ReplaceAll(roleKind, "_", "."),
			Label:      firstNonEmpty(attributes["role_name"], attributes["role_type"], roleID),
			Attributes: map[string]string{
				"role_id":  roleID,
				"is_admin": boolString(privileged),
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), accountURN, roleURN, relation, map[string]string{"event_id": event.GetId(), "role_id": roleID}))
	}
	return identityProjectionResult(entities, links)
}

func snykAssetRelationshipProjections(event *cerebrov1.EventEnvelope, relatedIDKey string, relatedURNKind string, relatedType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	assetID := firstNonEmpty(attributes["asset_id"], attributes["source_asset_id"])
	relatedID := firstNonEmpty(attributes[relatedIDKey], attributes["resource_id"], event.GetId())
	assetURN := projectionURN(tenantID, "snyk_assets", assetID)
	relatedURN := projectionURN(tenantID, relatedURNKind, relatedID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if relatedID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        relatedURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: relatedType,
			Label:      firstNonEmpty(attributes["resource_name"], attributes[relatedIDKey], relatedID),
			Attributes: map[string]string{relatedIDKey: relatedID, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])},
		})
	}
	if assetID != "" && relatedID != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, relatedURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": event.GetKind()}))
	}
	return identityProjectionResult(entities, links)
}

func snykGenericFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	findingID := firstNonEmpty(attributes["finding_id"], event.GetId())
	findingURN := projectionURN(tenantID, "finding", findingID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "finding", Label: firstNonEmpty(attributes["title"], findingID), Attributes: map[string]string{"finding_id": findingID, "severity": strings.TrimSpace(attributes["severity"]), "status": strings.TrimSpace(attributes["status"]), "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if resourceURN := strings.TrimSpace(attributes["resource_urn"]); resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, resourceURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime_evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
