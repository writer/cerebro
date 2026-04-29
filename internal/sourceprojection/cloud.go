package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, awsIdentityProfile)
}

func azureResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, azureIdentityProfile)
}

func gcpResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, gcpIdentityProfile)
}

func awsIAMRoleTrustProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, awsIdentityProfile)
}

func azureAppRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, azureIdentityProfile)
}

func gcpServiceAccountImpersonationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, gcpIdentityProfile)
}

func awsEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, awsIdentityProfile)
}

func azureEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, azureIdentityProfile)
}

func gcpEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, gcpIdentityProfile)
}

func cloudResourceExposureProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["resource_name"], attributes["exposure_id"])
	resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	publicURN := identityPrincipalURN(tenantID, provider, "public", firstNonEmpty(attributes["exposed_to"], "public_internet"), "")

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if publicURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        publicURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("public_principal"),
			Label:      firstNonEmpty(attributes["exposed_to"], "public internet"),
			Attributes: map[string]string{"principal_type": "public"},
		})
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], resourceID),
			Attributes: map[string]string{
				"domain":            strings.TrimSpace(attributes["domain"]),
				"exposure_id":       strings.TrimSpace(attributes["exposure_id"]),
				"exposure_type":     strings.TrimSpace(attributes["exposure_type"]),
				"external_exposure": strings.TrimSpace(attributes["external_exposure"]),
				"internet_exposed":  strings.TrimSpace(attributes["internet_exposed"]),
				"public":            strings.TrimSpace(attributes["public"]),
				"resource_id":       resourceID,
				"resource_provider": strings.TrimSpace(attributes["resource_provider"]),
				"resource_type":     resourceType,
				"source_cidr":       strings.TrimSpace(attributes["source_cidr"]),
			},
		})
	}
	if publicURN != "" && resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), publicURN, resourceURN, relationCanReach, map[string]string{
			"action":        strings.TrimSpace(attributes["action"]),
			"direction":     strings.TrimSpace(attributes["direction"]),
			"event_id":      event.GetId(),
			"exposure_type": strings.TrimSpace(attributes["exposure_type"]),
			"port_range":    strings.TrimSpace(attributes["port_range"]),
			"protocol":      strings.TrimSpace(attributes["protocol"]),
			"source_cidr":   strings.TrimSpace(attributes["source_cidr"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func cloudPrivilegePathProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["principal_id"], attributes["assigned_to"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["principal_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	targetType := strings.ToLower(firstNonEmpty(attributes["target_type"], attributes["resource_type"], "resource"))
	targetID := firstNonEmpty(attributes["target_id"], attributes["resource_id"], attributes["target_email"], attributes["target_app_id"], attributes["role_id"])
	targetEmail := firstNonEmpty(attributes["target_email"], attributes["resource_email"])
	targetURN := cloudTargetURN(tenantID, provider, targetType, targetID, targetEmail)
	relation := cloudPrivilegeRelation(attributes)

	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), subjectURN, firstNonEmpty(subjectEmail, subjectID))
	}
	if targetURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(normalizeCloudType(targetType), "_", ".")),
			Label:      firstNonEmpty(attributes["target_name"], attributes["resource_name"], targetEmail, targetID),
			Attributes: map[string]string{"target_id": targetID, "target_type": targetType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), targetURN, targetEmail)
	}
	if subjectURN != "" && targetURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, targetURN, relation, map[string]string{
			"event_id":     event.GetId(),
			"path_type":    strings.TrimSpace(attributes["path_type"]),
			"relationship": strings.TrimSpace(attributes["relationship"]),
			"role_id":      strings.TrimSpace(attributes["role_id"]),
			"role_name":    strings.TrimSpace(attributes["role_name"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func cloudEffectivePermissionProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["principal_id"], attributes["assigned_to"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["principal_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], attributes["target_type"], "scope"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["target_id"], attributes["scope"], attributes["policy_id"])
	resourceURN := cloudTargetURN(tenantID, provider, resourceType, resourceID, firstNonEmpty(attributes["resource_email"], attributes["target_email"]))
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), subjectURN, firstNonEmpty(subjectEmail, subjectID))
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["target_name"], resourceID),
			Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "scope": strings.TrimSpace(attributes["scope"])},
		})
	}
	if subjectURN != "" && resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, resourceURN, relationCanPerform, map[string]string{
			"actions":         strings.TrimSpace(attributes["actions"]),
			"condition":       strings.TrimSpace(attributes["condition"]),
			"effect":          strings.TrimSpace(attributes["effect"]),
			"event_id":        event.GetId(),
			"permission":      firstNonEmpty(attributes["permission"], attributes["actions"]),
			"privilege_level": strings.TrimSpace(attributes["privilege_level"]),
			"role_id":         strings.TrimSpace(attributes["role_id"]),
			"role_name":       strings.TrimSpace(attributes["role_name"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func cloudTargetURN(tenantID string, provider string, targetType string, targetID string, targetEmail string) string {
	normalizedType := identityPrincipalType(targetType)
	switch normalizedType {
	case "application", "group", "public", "role", "service_account", "service_principal":
		return identityPrincipalURN(tenantID, provider, normalizedType, targetID, targetEmail)
	default:
		return projectionURN(tenantID, provider+"_"+normalizeCloudType(targetType), firstNonEmpty(targetID, targetEmail))
	}
}

func cloudPrivilegeRelation(attributes map[string]string) string {
	relationship := normalizeIdentifier(firstNonEmpty(attributes["relationship"], attributes["path_type"]))
	switch {
	case strings.Contains(relationship, "assume"):
		return relationCanAssume
	case strings.Contains(relationship, "impersonate"):
		return relationCanImpersonate
	case identityProjectionPrivileged(attributes):
		return relationCanAdmin
	default:
		return relationAssignedTo
	}
}

func normalizeCloudType(value string) string {
	normalized := strings.ReplaceAll(normalizeIdentifier(value), ".", "_")
	normalized = strings.ReplaceAll(normalized, "/", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return strings.Trim(normalized, "_")
}
