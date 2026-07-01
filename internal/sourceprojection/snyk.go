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
	return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: "snyk"})
}

func snykGroupMembershipsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: "snyk"})
}

func snykServiceAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykServiceAccountProjections(event)
}

func snykGroupServiceAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return snykServiceAccountProjections(event)
}

func snykAuditLogsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "snyk"})
}

func snykGroupAuditLogsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "snyk"})
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
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: firstNonEmpty(attributes["resource_name"], resourceID), Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
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
	if assetID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        assetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "snyk.assets",
			Label:      firstNonEmpty(attributes["asset_name"], assetID),
			Attributes: map[string]string{"asset_id": assetID},
		})
	}
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
