package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func awsBackupVaultProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return awsCloudResourceProjections(event)
}

func awsBackupPlanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntitiesMap(entities)
	linkMap := projectedLinksMap(links)
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	planURN := awsBackupPlanURN(tenantID, attributes)
	if planURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	for _, vaultName := range splitCloudAttributeList(attributes["target_backup_vault_names"]) {
		vaultURN := awsBackupVaultURN(tenantID, attributes, vaultName)
		if vaultURN == "" {
			continue
		}
		addAWSBackupVault(entityMap, linkMap, tenantID, event.GetSourceId(), event, vaultURN, vaultName, attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), planURN, vaultURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "backup_plan_target_vault"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsBackupProtectedResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntitiesMap(entities)
	linkMap := projectedLinksMap(links)
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	protectedURN := projectionURN(tenantID, "aws_backup_protected_resource", firstNonEmpty(attributes["protected_resource_arn"], attributes["resource_id"], attributes["resource_name"]))
	if protectedURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	sourceURN := awsBackupSourceResourceURN(tenantID, attributes)
	if sourceURN != "" {
		addAWSBackupSourceResource(entityMap, tenantID, event.GetSourceId(), attributes, sourceURN)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), protectedURN, sourceURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "backup_protected_source_resource"}))
	}
	if vaultURN := projectionURN(tenantID, "aws_backup_vault", attributes["last_backup_vault_arn"]); vaultURN != "" {
		addAWSBackupVault(entityMap, linkMap, tenantID, event.GetSourceId(), event, vaultURN, awsBackupVaultNameFromARN(attributes["last_backup_vault_arn"]), attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), protectedURN, vaultURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "backup_protected_last_vault"}))
	}
	if recoveryURN := projectionURN(tenantID, "aws_backup_recovery_point", attributes["last_recovery_point_arn"]); recoveryURN != "" {
		addEntity(entityMap, &ports.ProjectedEntity{URN: recoveryURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: awsBackupRecoveryPointEntityType(), Label: attributes["last_recovery_point_arn"], Attributes: map[string]string{"recovery_point_arn": strings.TrimSpace(attributes["last_recovery_point_arn"])}})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), protectedURN, recoveryURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "backup_protected_last_recovery_point"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func awsBackupRecoveryPointProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := awsCloudResourceProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := projectedEntitiesMap(entities)
	linkMap := projectedLinksMap(links)
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	recoveryURN := projectionURN(tenantID, "aws_backup_recovery_point", firstNonEmpty(attributes["recovery_point_arn"], attributes["resource_id"]))
	if recoveryURN == "" {
		return identityProjectionResult(entityMap, linkMap)
	}
	if vaultURN := projectionURN(tenantID, "aws_backup_vault", firstNonEmpty(attributes["backup_vault_arn"], awsBackupVaultARNFromName(attributes, attributes["backup_vault_name"]))); vaultURN != "" {
		addAWSBackupVault(entityMap, linkMap, tenantID, event.GetSourceId(), event, vaultURN, attributes["backup_vault_name"], attributes)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), recoveryURN, vaultURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "backup_recovery_point_vault"}))
	}
	planARN := firstNonEmpty(attributes["backup_plan_arn"], awsBackupPlanARNFromID(attributes, attributes["backup_plan_id"]))
	if planURN := projectionURN(tenantID, "aws_backup_plan", planARN); planURN != "" {
		addEntity(entityMap, &ports.ProjectedEntity{URN: planURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "aws.backup.plan", Label: firstNonEmpty(attributes["backup_plan_id"], planARN), Attributes: map[string]string{"backup_plan_arn": strings.TrimSpace(planARN), "backup_plan_id": strings.TrimSpace(attributes["backup_plan_id"])}})
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), recoveryURN, planURN, relationDependsOn, map[string]string{"backup_rule_id": strings.TrimSpace(attributes["backup_rule_id"]), "event_id": event.GetId(), "match_type": "backup_recovery_point_plan"}))
	}
	if sourceURN := awsBackupSourceResourceURN(tenantID, attributes); sourceURN != "" {
		addAWSBackupSourceResource(entityMap, tenantID, event.GetSourceId(), attributes, sourceURN)
		addLink(linkMap, projectedLink(tenantID, event.GetSourceId(), recoveryURN, sourceURN, relationAssociatedWith, map[string]string{"event_id": event.GetId(), "match_type": "backup_recovery_point_source_resource"}))
	}
	return identityProjectionResult(entityMap, linkMap)
}

func addAWSBackupVault(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, vaultURN string, vaultName string, attributes map[string]string) {
	if vaultURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vaultURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.backup.vault",
		Label:      firstNonEmpty(vaultName, attributes["backup_vault_name"], attributes["backup_vault_arn"]),
		Attributes: map[string]string{
			"backup_vault_arn":  strings.TrimSpace(firstNonEmpty(attributes["backup_vault_arn"], attributes["last_backup_vault_arn"])),
			"backup_vault_name": strings.TrimSpace(firstNonEmpty(vaultName, attributes["backup_vault_name"])),
			"domain":            strings.TrimSpace(attributes["domain"]),
			"region":            strings.TrimSpace(attributes["region"]),
		},
	})
	addCloudAccountLink(entities, links, tenantID, sourceID, event, vaultURN, attributes["domain"], "aws")
}

func addAWSBackupSourceResource(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attributes map[string]string, sourceURN string) {
	if sourceURN == "" {
		return
	}
	sourceType := awsBackupProjectedResourceFamily(firstNonEmpty(attributes["source_resource_type"], "resource"))
	addEntity(entities, &ports.ProjectedEntity{
		URN:        sourceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws." + strings.ReplaceAll(sourceType, "_", "."),
		Label:      firstNonEmpty(attributes["source_resource_name"], attributes["source_resource_arn"]),
		Attributes: compactAttributes(map[string]string{
			"domain":            strings.TrimSpace(attributes["domain"]),
			"resource_id":       strings.TrimSpace(attributes["source_resource_arn"]),
			"resource_name":     strings.TrimSpace(attributes["source_resource_name"]),
			"resource_provider": "aws",
			"resource_type":     sourceType,
		}),
	})
}

func awsBackupPlanURN(tenantID string, attributes map[string]string) string {
	return projectionURN(tenantID, "aws_backup_plan", firstNonEmpty(attributes["backup_plan_arn"], attributes["resource_id"], attributes["backup_plan_id"]))
}

func awsBackupVaultURN(tenantID string, attributes map[string]string, vaultName string) string {
	return projectionURN(tenantID, "aws_backup_vault", firstNonEmpty(awsBackupVaultARNFromName(attributes, vaultName), vaultName))
}

func awsBackupVaultARNFromName(attributes map[string]string, vaultName string) string {
	vaultName = strings.TrimSpace(vaultName)
	region := strings.TrimSpace(attributes["region"])
	accountID := strings.TrimSpace(attributes["domain"])
	if vaultName == "" || region == "" || accountID == "" {
		return ""
	}
	return "arn:aws:backup:" + region + ":" + accountID + ":backup-vault:" + vaultName
}

func awsBackupVaultNameFromARN(arn string) string {
	_, name, ok := strings.Cut(strings.TrimSpace(arn), ":backup-vault:")
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func awsBackupSourceResourceURN(tenantID string, attributes map[string]string) string {
	sourceARN := strings.TrimSpace(firstNonEmpty(attributes["source_resource_arn"], attributes["protected_resource_arn"]))
	if sourceARN == "" {
		return ""
	}
	resourceFamily := awsBackupProjectedResourceFamily(firstNonEmpty(attributes["source_resource_type"], attributes["protected_resource_type"]))
	return projectionURN(tenantID, "aws_"+resourceFamily, awsBackupSourceResourceID(resourceFamily, sourceARN))
}

func awsBackupPlanARNFromID(attributes map[string]string, planID string) string {
	planID = strings.TrimSpace(planID)
	region := strings.TrimSpace(attributes["region"])
	accountID := strings.TrimSpace(attributes["domain"])
	if planID == "" || region == "" || accountID == "" {
		return ""
	}
	return "arn:aws:backup:" + region + ":" + accountID + ":backup-plan:" + planID
}

func awsBackupSourceResourceID(resourceFamily string, sourceARN string) string {
	sourceARN = strings.TrimSpace(sourceARN)
	if resourceFamily == "ec2_instance" {
		if _, id, ok := strings.Cut(sourceARN, ":instance/"); ok {
			return strings.TrimSpace(id)
		}
	}
	return sourceARN
}

func awsBackupRecoveryPointEntityType() string {
	return "aws." + strings.ReplaceAll("backup_recovery_point", "_", ".")
}

func awsBackupProjectedResourceFamily(resourceType string) string {
	normalized := normalizeCloudType(resourceType)
	switch normalized {
	case "ebs":
		return "ebs_volume"
	case "rds":
		return "rds_instance"
	case "ec2":
		return "ec2_instance"
	case "s3":
		return "s3_bucket"
	default:
		return normalized
	}
}
