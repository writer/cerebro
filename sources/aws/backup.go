package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"

	"github.com/writer/cerebro/internal/primitives"
)

type backupRecoveryPointCursor struct {
	VaultIndex int    `json:"vault_index,omitempty"`
	NextToken  string `json:"next_token,omitempty"`
}

type awsBackupVault struct {
	backuptypes.BackupVaultListMember
	Name string
	ARN  string
	Tags map[string]string
}

type awsBackupPlan struct {
	Summary backuptypes.BackupPlansListMember
	Details *backup.GetBackupPlanOutput
	ID      string
	ARN     string
	Name    string
	Tags    map[string]string
}

type awsBackupProtectedResource struct {
	backuptypes.ProtectedResource
}

type awsBackupRecoveryPoint struct {
	backuptypes.RecoveryPointByBackupVault
}

func listBackupVaults(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBackupVault, string, error) {
	out, err := clients.backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 1000))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsBackupVault, 0, len(out.BackupVaultList))
	for _, vault := range out.BackupVaultList {
		record := awsBackupVault{BackupVaultListMember: vault, Name: awssdk.ToString(vault.BackupVaultName), ARN: awssdk.ToString(vault.BackupVaultArn)}
		if record.ARN != "" {
			tags, err := listBackupTags(ctx, clients, record.ARN)
			if err != nil {
				return nil, "", fmt.Errorf("list backup vault tags %q: %w", record.ARN, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listBackupPlans(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBackupPlan, string, error) {
	out, err := clients.backup.ListBackupPlans(ctx, &backup.ListBackupPlansInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 1000))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsBackupPlan, 0, len(out.BackupPlansList))
	for _, plan := range out.BackupPlansList {
		record := awsBackupPlan{Summary: plan, ID: awssdk.ToString(plan.BackupPlanId), ARN: awssdk.ToString(plan.BackupPlanArn), Name: awssdk.ToString(plan.BackupPlanName)}
		if record.ID != "" {
			details, err := clients.backup.GetBackupPlan(ctx, &backup.GetBackupPlanInput{BackupPlanId: awssdk.String(record.ID), VersionId: plan.VersionId})
			if err != nil {
				return nil, "", fmt.Errorf("get backup plan %q: %w", record.ID, err)
			}
			record.Details = details
			record.ARN = firstNonEmpty(record.ARN, awssdk.ToString(details.BackupPlanArn))
			record.ID = firstNonEmpty(record.ID, awssdk.ToString(details.BackupPlanId))
			if details.BackupPlan != nil {
				record.Name = firstNonEmpty(record.Name, awssdk.ToString(details.BackupPlan.BackupPlanName))
			}
		}
		if record.ARN != "" {
			tags, err := listBackupTags(ctx, clients, record.ARN)
			if err != nil {
				return nil, "", fmt.Errorf("list backup plan tags %q: %w", record.ARN, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listBackupProtectedResources(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBackupProtectedResource, string, error) {
	out, err := clients.backup.ListProtectedResources(ctx, &backup.ListProtectedResourcesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 1000))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsBackupProtectedResource, 0, len(out.Results))
	for _, resource := range out.Results {
		records = append(records, awsBackupProtectedResource{ProtectedResource: resource})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listBackupRecoveryPoints(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsBackupRecoveryPoint, string, error) {
	vaults, err := listAllBackupVaultNames(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeBackupRecoveryPointCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if state.VaultIndex < 0 || state.VaultIndex >= len(vaults) {
		state = backupRecoveryPointCursor{}
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsBackupRecoveryPoint, 0, remaining)
	for state.VaultIndex < len(vaults) && len(records) < remaining {
		vaultName := vaults[state.VaultIndex]
		out, err := clients.backup.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{
			BackupVaultName: awssdk.String(vaultName),
			MaxResults:      awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 1000))),
			NextToken:       stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list backup recovery points for vault %q: %w", vaultName, err)
		}
		for _, point := range out.RecoveryPoints {
			records = append(records, awsBackupRecoveryPoint{RecoveryPointByBackupVault: point})
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.NextToken = awssdk.ToString(out.NextToken)
			return records, encodeBackupRecoveryPointCursor(state), nil
		}
		state.VaultIndex++
		state.NextToken = ""
	}
	if state.VaultIndex < len(vaults) {
		return records, encodeBackupRecoveryPointCursor(state), nil
	}
	return records, "", nil
}

func backupVaultEvent(settings settings, record awsBackupVault) (*primitives.Event, error) {
	arn := firstNonEmpty(record.ARN, backupVaultARN(settings, record.Name), record.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBackupVault, arn, record.Name, "backup_vault", record.Tags)
	attributes["arn"] = arn
	attributes["backup_vault_arn"] = arn
	attributes["backup_vault_name"] = record.Name
	attributes["encryption"] = boolString(awssdk.ToString(record.EncryptionKeyArn) != "" || string(record.EncryptionKeyType) != "")
	attributes["encryption_key_arn"] = awssdk.ToString(record.EncryptionKeyArn)
	attributes["encryption_key_type"] = string(record.EncryptionKeyType)
	attributes["locked"] = boolString(awssdk.ToBool(record.Locked))
	attributes["state"] = string(record.VaultState)
	attributes["vault_type"] = string(record.VaultType)
	attributes["recovery_point_count"] = fmt.Sprint(record.NumberOfRecoveryPoints)
	attributes["min_retention_days"] = int64AttrString(record.MinRetentionDays)
	attributes["max_retention_days"] = int64AttrString(record.MaxRetentionDays)
	addTimeAttribute(attributes, "lock_at", record.LockDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "vault": record.BackupVaultListMember, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-backup-vault-"+arn, "aws.backup_vault", "aws/backup_vault/v1", payload, attributes, firstTime(record.CreationDate))
}

func backupPlanEvent(settings settings, record awsBackupPlan) (*primitives.Event, error) {
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBackupPlan, firstNonEmpty(record.ARN, record.ID), record.Name, "backup_plan", record.Tags)
	attributes["arn"] = record.ARN
	attributes["backup_plan_arn"] = record.ARN
	attributes["backup_plan_id"] = record.ID
	attributes["backup_plan_name"] = record.Name
	attributes["version_id"] = awssdk.ToString(record.Summary.VersionId)
	attributes["backup_rule_count"] = fmt.Sprint(len(backupPlanRules(record)))
	attributes["target_backup_vault_names"] = strings.Join(backupPlanTargetVaultNames(record), ",")
	attributes["backup_frequency"] = strings.Join(backupPlanSchedules(record), ",")
	attributes["retention_days"] = int64ValueString(maxBackupPlanRetentionDays(record))
	attributes["cold_storage_after_days"] = int64ValueString(minBackupPlanColdStorageDays(record))
	attributes["continuous_backup"] = boolString(backupPlanContinuous(record))
	attributes["air_gapped_vault_arns"] = strings.Join(backupPlanAirGappedVaultARNs(record), ",")
	addTimeAttribute(attributes, "last_executed_at", record.Summary.LastExecutionDate)
	addTimeAttribute(attributes, "deleted_at", record.Summary.DeletionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "plan": record.Summary, "details": record.Details, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-backup-plan-"+firstNonEmpty(record.ARN, record.ID, record.Name), "aws.backup_plan", "aws/backup_plan/v1", payload, attributes, firstTime(record.Summary.CreationDate))
}

func backupProtectedResourceEvent(settings settings, record awsBackupProtectedResource) (*primitives.Event, error) {
	resourceARN := awssdk.ToString(record.ResourceArn)
	resourceName := firstNonEmpty(awssdk.ToString(record.ResourceName), awsResourceName(resourceARN), resourceARN)
	resourceType := backupSourceResourceType(awssdk.ToString(record.ResourceType))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBackupProtected, resourceARN, resourceName, "backup_protected_resource", nil)
	attributes["protected_resource_arn"] = resourceARN
	attributes["protected_resource_name"] = resourceName
	attributes["protected_resource_type"] = awssdk.ToString(record.ResourceType)
	attributes["backups"] = boolString(awssdk.ToString(record.LastRecoveryPointArn) != "")
	attributes["last_backup_vault_arn"] = awssdk.ToString(record.LastBackupVaultArn)
	attributes["last_recovery_point_arn"] = awssdk.ToString(record.LastRecoveryPointArn)
	attributes["source_resource_arn"] = resourceARN
	attributes["source_resource_type"] = resourceType
	addTimeAttribute(attributes, "last_backup_at", record.LastBackupTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "protected_resource": record.ProtectedResource})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-backup-protected-resource-"+resourceARN, "aws.backup_protected_resource", "aws/backup_protected_resource/v1", payload, attributes, firstTime(record.LastBackupTime))
}

func backupRecoveryPointEvent(settings settings, record awsBackupRecoveryPoint) (*primitives.Event, error) {
	pointARN := awssdk.ToString(record.RecoveryPointArn)
	resourceARN := awssdk.ToString(record.ResourceArn)
	resourceName := firstNonEmpty(awssdk.ToString(record.ResourceName), awsResourceName(resourceARN), resourceARN)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyBackupRecoveryPoint, pointARN, firstNonEmpty(resourceName, pointARN), "backup_recovery_point", nil)
	attributes["arn"] = pointARN
	attributes["backup_plan_arn"] = backupRecoveryPointPlanARN(record)
	attributes["backup_plan_id"] = backupRecoveryPointPlanID(record)
	attributes["backup_rule_id"] = backupRecoveryPointRuleID(record)
	attributes["backup_size_bytes"] = int64AttrString(record.BackupSizeInBytes)
	attributes["backup_vault_arn"] = awssdk.ToString(record.BackupVaultArn)
	attributes["backup_vault_name"] = awssdk.ToString(record.BackupVaultName)
	attributes["encryption"] = boolString(record.IsEncrypted || awssdk.ToString(record.EncryptionKeyArn) != "" || string(record.EncryptionKeyType) != "")
	attributes["encryption_key_arn"] = awssdk.ToString(record.EncryptionKeyArn)
	attributes["encryption_key_type"] = string(record.EncryptionKeyType)
	attributes["iam_role_arn"] = awssdk.ToString(record.IamRoleArn)
	attributes["iam_role_name"] = roleNameFromARN(awssdk.ToString(record.IamRoleArn))
	attributes["role_arn"] = awssdk.ToString(record.IamRoleArn)
	attributes["role_name"] = roleNameFromARN(awssdk.ToString(record.IamRoleArn))
	attributes["recovery_point_arn"] = pointARN
	attributes["retention_days"] = int64AttrString(backupLifecycleDeleteAfterDays(record.Lifecycle))
	attributes["cold_storage_after_days"] = int64AttrString(backupLifecycleMoveToColdDays(record.Lifecycle))
	attributes["source_backup_vault_arn"] = awssdk.ToString(record.SourceBackupVaultArn)
	attributes["source_resource_arn"] = resourceARN
	attributes["source_resource_name"] = resourceName
	attributes["source_resource_type"] = backupSourceResourceType(awssdk.ToString(record.ResourceType))
	attributes["state"] = string(record.Status)
	attributes["vault_type"] = string(record.VaultType)
	addTimeAttribute(attributes, "completed_at", record.CompletionDate)
	addTimeAttribute(attributes, "created_at", record.CreationDate)
	addTimeAttribute(attributes, "initiated_at", record.InitiationDate)
	addTimeAttribute(attributes, "last_restored_at", record.LastRestoreTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "recovery_point": record.RecoveryPointByBackupVault})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-backup-recovery-point-"+pointARN, "aws.backup_recovery_point", "aws/backup_recovery_point/v1", payload, attributes, firstTime(record.CreationDate, record.CompletionDate))
}

func listBackupTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	out, err := clients.backup.ListTags(ctx, &backup.ListTagsInput{ResourceArn: awssdk.String(arn), MaxResults: awssdk.Int32(1000)})
	if err != nil {
		return nil, err
	}
	return out.Tags, nil
}

func listAllBackupVaultNames(ctx context.Context, clients awsClients) ([]string, error) {
	var names []string
	var next *string
	for {
		out, err := clients.backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{MaxResults: awssdk.Int32(1000), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, vault := range out.BackupVaultList {
			if name := awssdk.ToString(vault.BackupVaultName); name != "" {
				names = append(names, name)
			}
		}
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	return cleanStrings(names), nil
}

func backupVaultARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:backup:%s:%s:backup-vault:%s", settings.region, settings.accountID, name)
}

func backupPlanRules(record awsBackupPlan) []backuptypes.BackupRule {
	if record.Details == nil || record.Details.BackupPlan == nil {
		return nil
	}
	return record.Details.BackupPlan.Rules
}

func backupPlanTargetVaultNames(record awsBackupPlan) []string {
	values := make([]string, 0, len(backupPlanRules(record)))
	for _, rule := range backupPlanRules(record) {
		values = append(values, awssdk.ToString(rule.TargetBackupVaultName))
	}
	return cleanStrings(values)
}

func backupPlanSchedules(record awsBackupPlan) []string {
	values := make([]string, 0, len(backupPlanRules(record)))
	for _, rule := range backupPlanRules(record) {
		values = append(values, awssdk.ToString(rule.ScheduleExpression))
	}
	return cleanStrings(values)
}

func maxBackupPlanRetentionDays(record awsBackupPlan) *int64 {
	var max *int64
	for _, rule := range backupPlanRules(record) {
		if value := backupLifecycleDeleteAfterDays(rule.Lifecycle); value != nil && (max == nil || *value > *max) {
			max = value
		}
	}
	return max
}

func minBackupPlanColdStorageDays(record awsBackupPlan) *int64 {
	var min *int64
	for _, rule := range backupPlanRules(record) {
		if value := backupLifecycleMoveToColdDays(rule.Lifecycle); value != nil && (min == nil || *value < *min) {
			min = value
		}
	}
	return min
}

func backupPlanContinuous(record awsBackupPlan) bool {
	for _, rule := range backupPlanRules(record) {
		if awssdk.ToBool(rule.EnableContinuousBackup) {
			return true
		}
	}
	return false
}

func backupPlanAirGappedVaultARNs(record awsBackupPlan) []string {
	values := make([]string, 0, len(backupPlanRules(record)))
	for _, rule := range backupPlanRules(record) {
		values = append(values, awssdk.ToString(rule.TargetLogicallyAirGappedBackupVaultArn))
	}
	return cleanStrings(values)
}

func backupLifecycleDeleteAfterDays(lifecycle *backuptypes.Lifecycle) *int64 {
	if lifecycle == nil {
		return nil
	}
	return lifecycle.DeleteAfterDays
}

func backupLifecycleMoveToColdDays(lifecycle *backuptypes.Lifecycle) *int64 {
	if lifecycle == nil {
		return nil
	}
	return lifecycle.MoveToColdStorageAfterDays
}

func backupRecoveryPointPlanARN(record awsBackupRecoveryPoint) string {
	if record.CreatedBy == nil {
		return ""
	}
	return awssdk.ToString(record.CreatedBy.BackupPlanArn)
}

func backupRecoveryPointPlanID(record awsBackupRecoveryPoint) string {
	if record.CreatedBy == nil {
		return ""
	}
	return awssdk.ToString(record.CreatedBy.BackupPlanId)
}

func backupSourceResourceType(resourceType string) string {
	normalized := normalizeAWSResourceType(resourceType)
	switch normalized {
	case "rds":
		return "rds_instance"
	default:
		return normalized
	}
}

func backupRecoveryPointRuleID(record awsBackupRecoveryPoint) string {
	if record.CreatedBy == nil {
		return ""
	}
	return awssdk.ToString(record.CreatedBy.BackupRuleId)
}

func int64AttrString(value *int64) string {
	if value == nil {
		return ""
	}
	return int64ValueString(value)
}

func int64ValueString(value *int64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func decodeBackupRecoveryPointCursor(raw string) (backupRecoveryPointCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return backupRecoveryPointCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return backupRecoveryPointCursor{}, fmt.Errorf("decode backup recovery point cursor: %w", err)
	}
	var cursor backupRecoveryPointCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return backupRecoveryPointCursor{}, fmt.Errorf("parse backup recovery point cursor: %w", err)
	}
	return cursor, nil
}

func encodeBackupRecoveryPointCursor(cursor backupRecoveryPointCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
