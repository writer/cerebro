package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

// Backup Vaults table
func (e *SyncEngine) backupVaultTable() TableSpec {
	return TableSpec{
		Name: "aws_backup_vaults",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"creation_date", "creator_request_id", "encryption_key_arn",
			"lock_date", "locked", "max_retention_days", "min_retention_days",
			"number_of_recovery_points", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := backup.NewFromConfig(cfg, func(o *backup.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := backup.NewListBackupVaultsPaginator(client, &backup.ListBackupVaultsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, vault := range page.BackupVaultList {
					// Get tags
					tagsOut, _ := client.ListTags(ctx, &backup.ListTagsInput{
						ResourceArn: vault.BackupVaultArn,
					})
					tags := map[string]string{}
					if tagsOut != nil {
						tags = tagsOut.Tags
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                       aws.ToString(vault.BackupVaultArn),
						"name":                      aws.ToString(vault.BackupVaultName),
						"account_id":                accountID,
						"region":                    region,
						"creation_date":             timeToString(vault.CreationDate),
						"creator_request_id":        aws.ToString(vault.CreatorRequestId),
						"encryption_key_arn":        aws.ToString(vault.EncryptionKeyArn),
						"lock_date":                 timeToString(vault.LockDate),
						"locked":                    vault.Locked,
						"max_retention_days":        vault.MaxRetentionDays,
						"min_retention_days":        vault.MinRetentionDays,
						"number_of_recovery_points": vault.NumberOfRecoveryPoints,
						"tags":                      string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Backup Plans table
func (e *SyncEngine) backupPlanTable() TableSpec {
	return TableSpec{
		Name: "aws_backup_plans",
		Columns: []string{
			"_cq_hash", "arn", "backup_plan_id", "account_id", "region",
			"backup_plan_name", "creation_date", "creator_request_id",
			"deletion_date", "last_execution_date", "version_id",
			"advanced_backup_settings", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := backup.NewFromConfig(cfg, func(o *backup.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := backup.NewListBackupPlansPaginator(client, &backup.ListBackupPlansInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, plan := range page.BackupPlansList {
					advSettingsJSON, _ := json.Marshal(plan.AdvancedBackupSettings)

					// Get tags - need ARN
					arn := aws.ToString(plan.BackupPlanArn)
					tagsOut, _ := client.ListTags(ctx, &backup.ListTagsInput{
						ResourceArn: aws.String(arn),
					})
					tags := map[string]string{}
					if tagsOut != nil {
						tags = tagsOut.Tags
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                      arn,
						"backup_plan_id":           aws.ToString(plan.BackupPlanId),
						"account_id":               accountID,
						"region":                   region,
						"backup_plan_name":         aws.ToString(plan.BackupPlanName),
						"creation_date":            timeToString(plan.CreationDate),
						"creator_request_id":       aws.ToString(plan.CreatorRequestId),
						"deletion_date":            timeToString(plan.DeletionDate),
						"last_execution_date":      timeToString(plan.LastExecutionDate),
						"version_id":               aws.ToString(plan.VersionId),
						"advanced_backup_settings": string(advSettingsJSON),
						"tags":                     string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Backup Protected Resources table
func (e *SyncEngine) backupProtectedResourceTable() TableSpec {
	return TableSpec{
		Name: "aws_backup_protected_resources",
		Columns: []string{
			"_cq_hash", "resource_arn", "account_id", "region",
			"resource_type", "resource_name", "last_backup_time",
			"last_backup_vault_arn", "last_recovery_point_arn",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := backup.NewFromConfig(cfg, func(o *backup.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := backup.NewListProtectedResourcesPaginator(client, &backup.ListProtectedResourcesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, resource := range page.Results {
					row := map[string]interface{}{
						"resource_arn":            aws.ToString(resource.ResourceArn),
						"account_id":              accountID,
						"region":                  region,
						"resource_type":           aws.ToString(resource.ResourceType),
						"resource_name":           aws.ToString(resource.ResourceName),
						"last_backup_time":        timeToString(resource.LastBackupTime),
						"last_backup_vault_arn":   aws.ToString(resource.LastBackupVaultArn),
						"last_recovery_point_arn": aws.ToString(resource.LastRecoveryPointArn),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Backup Recovery Points table
func (e *SyncEngine) backupRecoveryPointTable() TableSpec {
	return TableSpec{
		Name: "aws_backup_recovery_points",
		Columns: []string{
			"_cq_hash", "arn", "backup_vault_name", "account_id", "region",
			"backup_size_in_bytes", "backup_vault_arn", "calculated_lifecycle",
			"completion_date", "composite_member_identifier", "creation_date",
			"encryption_key_arn", "iam_role_arn", "is_encrypted", "is_parent",
			"lifecycle", "parent_recovery_point_arn", "resource_arn", "resource_name",
			"resource_type", "source_backup_vault_arn", "status", "status_message",
			"vault_type",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := backup.NewFromConfig(cfg, func(o *backup.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all vaults
			vaultsPaginator := backup.NewListBackupVaultsPaginator(client, &backup.ListBackupVaultsInput{})
			for vaultsPaginator.HasMorePages() {
				vaultsPage, err := vaultsPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, vault := range vaultsPage.BackupVaultList {
					vaultName := aws.ToString(vault.BackupVaultName)

					// Get recovery points for this vault
					rpPaginator := backup.NewListRecoveryPointsByBackupVaultPaginator(client, &backup.ListRecoveryPointsByBackupVaultInput{
						BackupVaultName: aws.String(vaultName),
					})

					for rpPaginator.HasMorePages() {
						rpPage, err := rpPaginator.NextPage(ctx)
						if err != nil {
							break
						}

						for _, rp := range rpPage.RecoveryPoints {
							lifecycleJSON, _ := json.Marshal(rp.Lifecycle)
							calcLifecycleJSON, _ := json.Marshal(rp.CalculatedLifecycle)

							row := map[string]interface{}{
								"arn":                         aws.ToString(rp.RecoveryPointArn),
								"backup_vault_name":           vaultName,
								"account_id":                  accountID,
								"region":                      region,
								"backup_size_in_bytes":        rp.BackupSizeInBytes,
								"backup_vault_arn":            aws.ToString(rp.BackupVaultArn),
								"calculated_lifecycle":        string(calcLifecycleJSON),
								"completion_date":             timeToString(rp.CompletionDate),
								"composite_member_identifier": aws.ToString(rp.CompositeMemberIdentifier),
								"creation_date":               timeToString(rp.CreationDate),
								"encryption_key_arn":          aws.ToString(rp.EncryptionKeyArn),
								"iam_role_arn":                aws.ToString(rp.IamRoleArn),
								"is_encrypted":                rp.IsEncrypted,
								"is_parent":                   rp.IsParent,
								"lifecycle":                   string(lifecycleJSON),
								"parent_recovery_point_arn":   aws.ToString(rp.ParentRecoveryPointArn),
								"resource_arn":                aws.ToString(rp.ResourceArn),
								"resource_name":               aws.ToString(rp.ResourceName),
								"resource_type":               aws.ToString(rp.ResourceType),
								"source_backup_vault_arn":     aws.ToString(rp.SourceBackupVaultArn),
								"status":                      string(rp.Status),
								"status_message":              aws.ToString(rp.StatusMessage),
								"vault_type":                  string(rp.VaultType),
							}
							results = append(results, row)
						}
					}
				}
			}
			return results, nil
		},
	}
}
