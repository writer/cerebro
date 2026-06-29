package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsAccountContactProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	accountID := firstNonEmpty(awsAccountID(attributes["account_id"]), awsAccountID(attributes["resource_id"]), awsAccountID(attributes["domain"]))
	accountURN := cloudAccountURN(tenantID, accountID)
	if accountURN == "" {
		return nil, nil, nil
	}
	accountAttributes := compactAttributes(cloneStringMap(attributes))
	accountAttributes["account_id"] = accountID
	accountAttributes["provider"] = "aws"
	accountAttributes["resource_provider"] = "aws"
	accountAttributes["resource_type"] = "aws_account"
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accountURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "cloud.account",
		Label:      accountID,
		Attributes: accountAttributes,
	})
	return identityProjectionResult(entities, nil)
}

func awsSSOAccountAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	principalType := identityPrincipalType(firstNonEmpty(attributes["principal_type"], attributes["subject_type"], "user"))
	principalID := firstNonEmpty(attributes["principal_id"], attributes["subject_id"])
	principalURN := identityPrincipalURN(tenantID, "aws", principalType, principalID, "")
	permissionSetARN := strings.TrimSpace(attributes["permission_set_arn"])
	permissionSetURN := projectionURN(tenantID, "aws_sso_permission_set", permissionSetARN)
	accountID := firstNonEmpty(awsAccountID(attributes["account_id"]), awsAccountID(attributes["resource_id"]))
	accountURN := cloudAccountURN(tenantID, accountID)

	if principalURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        principalURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: awsIdentityProfile.entityType(principalType),
			Label:      firstNonEmpty(attributes["principal_name"], attributes["subject_name"], principalID),
			Attributes: compactAttributes(map[string]string{
				"identity_store_id": strings.TrimSpace(attributes["identity_store_id"]),
				"principal_id":      principalID,
				"principal_type":    principalType,
			}),
		})
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, principalURN, awsIdentityProfile, attributes, principalType, principalID)
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, principalURN, awsIdentityProfile, attributes, principalType, principalID)
	}
	if permissionSetURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        permissionSetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.sso.permission.set",
			Label:      firstNonEmpty(attributes["permission_set_name"], permissionSetARN),
			Attributes: compactAttributes(map[string]string{
				"account_id":          accountID,
				"identity_store_id":   strings.TrimSpace(attributes["identity_store_id"]),
				"instance_arn":        strings.TrimSpace(attributes["instance_arn"]),
				"permission_set_arn":  permissionSetARN,
				"permission_set_name": strings.TrimSpace(attributes["permission_set_name"]),
				"resource_provider":   "aws",
				"resource_type":       "sso_permission_set",
			}),
		})
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, permissionSetURN, firstNonEmpty(accountID, attributes["domain"]), "aws")
	}
	if accountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        accountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "cloud.account",
			Label:      accountID,
			Attributes: map[string]string{"account_id": accountID, "provider": "aws"},
		})
	}
	if principalURN != "" && permissionSetURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, permissionSetURN, relationAssignedTo, map[string]string{
			"event_id":           event.GetId(),
			"identity_store_id":  strings.TrimSpace(attributes["identity_store_id"]),
			"permission_set_arn": permissionSetARN,
			"principal_id":       principalID,
			"principal_type":     principalType,
		}))
	}
	if permissionSetURN != "" && accountURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), permissionSetURN, accountURN, relationCanPerform, map[string]string{
			"account_id":          accountID,
			"event_id":            event.GetId(),
			"match_type":          "sso_permission_set_account_assignment",
			"permission_set_arn":  permissionSetARN,
			"permission_set_name": strings.TrimSpace(attributes["permission_set_name"]),
		}))
	}
	if principalURN != "" && accountURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), principalURN, accountURN, relationCanPerform, map[string]string{
			"account_id":          accountID,
			"event_id":            event.GetId(),
			"match_type":          "sso_account_assignment",
			"permission_set_arn":  permissionSetARN,
			"permission_set_name": strings.TrimSpace(attributes["permission_set_name"]),
		}))
	}
	return identityProjectionResult(entities, links)
}
