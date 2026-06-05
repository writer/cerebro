package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsOrganizationsAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	accountID := firstNonEmpty(attributes["account_id"], attributes["resource_id"])
	accountURN := awsOrganizationsAccountURN(tenantID, accountID)
	if accountURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accountURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "aws.organizations.account",
		Label:      firstNonEmpty(attributes["account_name"], attributes["resource_name"], accountID),
		Attributes: map[string]string{
			"account_arn":   strings.TrimSpace(attributes["account_arn"]),
			"account_email": strings.TrimSpace(attributes["account_email"]),
			"account_id":    accountID,
			"domain":        strings.TrimSpace(attributes["domain"]),
			"joined_method": strings.TrimSpace(attributes["joined_method"]),
			"state":         strings.TrimSpace(attributes["state"]),
			"status":        strings.TrimSpace(attributes["status"]),
		},
	})
	addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, accountURN, accountID, "aws")
	if parentURN := awsOrganizationsParentURN(tenantID, attributes["parent_id"], attributes["parent_type"]); parentURN != "" {
		addAWSOrganizationsParentEntity(entities, tenantID, event.GetSourceId(), attributes["parent_id"], attributes["parent_type"], "")
		addLink(links, projectedLink(tenantID, event.GetSourceId(), accountURN, parentURN, relationBelongsTo, map[string]string{
			"event_id":     event.GetId(),
			"match_type":   "aws_organizations_account_parent",
			"parent_id":    strings.TrimSpace(attributes["parent_id"]),
			"parent_type":  strings.TrimSpace(attributes["parent_type"]),
			"relationship": strings.TrimSpace(attributes["relationship"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func awsOrganizationsOrganizationalUnitProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	ouURN := awsOrganizationsOUURN(tenantID, firstNonEmpty(attributes["ou_id"], attributes["resource_id"]))
	if ouURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        ouURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "aws.organizations.organizational.unit",
		Label:      firstNonEmpty(attributes["ou_name"], attributes["resource_name"], attributes["ou_id"]),
		Attributes: map[string]string{
			"domain":  strings.TrimSpace(attributes["domain"]),
			"ou_arn":  strings.TrimSpace(attributes["ou_arn"]),
			"ou_id":   strings.TrimSpace(attributes["ou_id"]),
			"ou_name": strings.TrimSpace(attributes["ou_name"]),
		},
	})
	if parentURN := awsOrganizationsParentURN(tenantID, attributes["parent_id"], attributes["parent_type"]); parentURN != "" {
		addAWSOrganizationsParentEntity(entities, tenantID, event.GetSourceId(), attributes["parent_id"], attributes["parent_type"], "")
		addLink(links, projectedLink(tenantID, event.GetSourceId(), ouURN, parentURN, relationBelongsTo, map[string]string{
			"event_id":     event.GetId(),
			"match_type":   "aws_organizations_ou_parent",
			"parent_id":    strings.TrimSpace(attributes["parent_id"]),
			"parent_type":  strings.TrimSpace(attributes["parent_type"]),
			"relationship": strings.TrimSpace(attributes["relationship"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func awsOrganizationsRootProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	rootURN := awsOrganizationsRootURN(tenantID, firstNonEmpty(attributes["root_id"], attributes["resource_id"]))
	if rootURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        rootURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "aws.organizations.root",
			Label:      firstNonEmpty(attributes["root_name"], attributes["resource_name"], attributes["root_id"]),
			Attributes: map[string]string{
				"domain":       strings.TrimSpace(attributes["domain"]),
				"policy_types": strings.TrimSpace(attributes["policy_types"]),
				"root_arn":     strings.TrimSpace(attributes["root_arn"]),
				"root_id":      strings.TrimSpace(attributes["root_id"]),
				"root_name":    strings.TrimSpace(attributes["root_name"]),
			},
		})
	}
	return identityProjectionResult(entities, nil)
}

func awsOrganizationsPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	policyID := firstNonEmpty(attributes["policy_id"], attributes["resource_id"])
	policyURN := projectionURN(tenantID, "aws_organizations_policy", policyID)
	if policyURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        policyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "aws.organizations.policy",
		Label:      firstNonEmpty(attributes["policy_name"], attributes["resource_name"], policyID),
		Attributes: map[string]string{
			"aws_managed": strings.TrimSpace(attributes["aws_managed"]),
			"description": strings.TrimSpace(attributes["description"]),
			"domain":      strings.TrimSpace(attributes["domain"]),
			"policy_arn":  strings.TrimSpace(attributes["policy_arn"]),
			"policy_id":   policyID,
			"policy_name": strings.TrimSpace(attributes["policy_name"]),
			"policy_type": strings.TrimSpace(attributes["policy_type"]),
		},
	})
	for _, target := range awsOrganizationsPolicyTargets(attributes) {
		targetURN := addAWSOrganizationsTargetEntity(entities, tenantID, event.GetSourceId(), target)
		if targetURN == "" {
			continue
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, targetURN, relationAttachedTo, map[string]string{
			"event_id":     event.GetId(),
			"match_type":   "aws_organizations_policy_target",
			"policy_id":    policyID,
			"policy_type":  strings.TrimSpace(attributes["policy_type"]),
			"relationship": strings.TrimSpace(attributes["relationship"]),
			"target_id":    target.ID,
			"target_type":  target.Type,
			"target_arn":   target.ARN,
			"target_name":  target.Name,
		}))
	}
	return identityProjectionResult(entities, links)
}

type awsOrganizationsPolicyTarget struct {
	ID   string
	Type string
	Name string
	ARN  string
}

func awsOrganizationsPolicyTargets(attributes map[string]string) []awsOrganizationsPolicyTarget {
	ids := splitCloudAttributeListAligned(attributes["target_ids"])
	types := splitCloudAttributeListAligned(attributes["target_types"])
	names := splitCloudAttributeListAligned(attributes["target_names"])
	arns := splitCloudAttributeListAligned(attributes["target_arns"])
	targets := make([]awsOrganizationsPolicyTarget, 0, len(ids))
	for index, id := range ids {
		target := awsOrganizationsPolicyTarget{ID: id, Type: awsOrganizationsValueAt(types, index), Name: awsOrganizationsValueAt(names, index), ARN: awsOrganizationsValueAt(arns, index)}
		if target.Type == "" {
			target.Type = awsOrganizationsTargetTypeFromID(target.ID)
		}
		targets = append(targets, target)
	}
	return targets
}

func addAWSOrganizationsTargetEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, target awsOrganizationsPolicyTarget) string {
	switch strings.ToUpper(strings.TrimSpace(target.Type)) {
	case "ACCOUNT":
		urn := awsOrganizationsAccountURN(tenantID, target.ID)
		if urn == "" {
			return ""
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        urn,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "aws.organizations.account",
			Label:      firstNonEmpty(target.Name, target.ID),
			Attributes: map[string]string{"account_arn": target.ARN, "account_id": target.ID},
		})
		return urn
	case "ORGANIZATIONAL_UNIT":
		return addAWSOrganizationsOUEntity(entities, tenantID, sourceID, target.ID, target.Name, target.ARN)
	case "ROOT":
		return addAWSOrganizationsRootEntity(entities, tenantID, sourceID, target.ID, target.Name, target.ARN)
	default:
		return ""
	}
}

func addAWSOrganizationsParentEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, id string, parentType string, label string) string {
	switch strings.ToUpper(strings.TrimSpace(parentType)) {
	case "ROOT":
		return addAWSOrganizationsRootEntity(entities, tenantID, sourceID, id, label, "")
	case "ORGANIZATIONAL_UNIT":
		return addAWSOrganizationsOUEntity(entities, tenantID, sourceID, id, label, "")
	default:
		return ""
	}
}

func addAWSOrganizationsRootEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, id string, label string, arn string) string {
	urn := awsOrganizationsRootURN(tenantID, id)
	if urn == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.organizations.root",
		Label:      firstNonEmpty(label, id),
		Attributes: map[string]string{"root_arn": strings.TrimSpace(arn), "root_id": strings.TrimSpace(id)},
	})
	return urn
}

func addAWSOrganizationsOUEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, id string, label string, arn string) string {
	urn := awsOrganizationsOUURN(tenantID, id)
	if urn == "" {
		return ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.organizations.organizational.unit",
		Label:      firstNonEmpty(label, id),
		Attributes: map[string]string{"ou_arn": strings.TrimSpace(arn), "ou_id": strings.TrimSpace(id), "ou_name": strings.TrimSpace(label)},
	})
	return urn
}

func awsOrganizationsParentURN(tenantID string, id string, parentType string) string {
	switch strings.ToUpper(strings.TrimSpace(parentType)) {
	case "ROOT":
		return awsOrganizationsRootURN(tenantID, id)
	case "ORGANIZATIONAL_UNIT":
		return awsOrganizationsOUURN(tenantID, id)
	default:
		return ""
	}
}

func awsOrganizationsAccountURN(tenantID string, id string) string {
	return projectionURN(tenantID, "aws_organizations_account", strings.TrimSpace(id))
}

func awsOrganizationsOUURN(tenantID string, id string) string {
	return projectionURN(tenantID, "aws_organizations_organizational_unit", strings.TrimSpace(id))
}

func awsOrganizationsRootURN(tenantID string, id string) string {
	return projectionURN(tenantID, "aws_organizations_root", strings.TrimSpace(id))
}

func awsOrganizationsValueAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return strings.TrimSpace(values[index])
}

func splitCloudAttributeListAligned(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	normalized := strings.NewReplacer(";", ",", "\n", ",", "\t", ",").Replace(value)
	fields := strings.Split(normalized, ",")
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		result = append(result, strings.TrimSpace(field))
	}
	return result
}

func awsOrganizationsTargetTypeFromID(id string) string {
	switch {
	case strings.HasPrefix(id, "ou-"):
		return "ORGANIZATIONAL_UNIT"
	case strings.HasPrefix(id, "r-"):
		return "ROOT"
	case awsAccountID(id) != "":
		return "ACCOUNT"
	default:
		return ""
	}
}
