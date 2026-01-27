package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
)

// FSx File Systems table
func (e *SyncEngine) fsxFileSystemTable() TableSpec {
	return TableSpec{
		Name: "aws_fsx_file_systems",
		Columns: []string{
			"_cq_hash", "arn", "file_system_id", "account_id", "region",
			"creation_time", "dns_name", "file_system_type", "file_system_type_version",
			"kms_key_id", "lifecycle", "lifecycle_transition_reason",
			"lustre_configuration", "network_interface_ids", "ontap_configuration",
			"open_zfs_configuration", "owner_id", "resource_arn",
			"storage_capacity", "storage_type", "subnet_ids", "vpc_id",
			"windows_configuration", "administrative_actions", "failure_details", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := fsx.NewFromConfig(cfg, func(o *fsx.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := fsx.NewDescribeFileSystemsPaginator(client, &fsx.DescribeFileSystemsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, fs := range page.FileSystems {
					lustreJSON, _ := json.Marshal(fs.LustreConfiguration)
					networkIDsJSON, _ := json.Marshal(fs.NetworkInterfaceIds)
					ontapJSON, _ := json.Marshal(fs.OntapConfiguration)
					openzfsJSON, _ := json.Marshal(fs.OpenZFSConfiguration)
					subnetIDsJSON, _ := json.Marshal(fs.SubnetIds)
					windowsJSON, _ := json.Marshal(fs.WindowsConfiguration)
					actionsJSON, _ := json.Marshal(fs.AdministrativeActions)
					failureJSON, _ := json.Marshal(fs.FailureDetails)

					tags := map[string]string{}
					for _, t := range fs.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                         aws.ToString(fs.ResourceARN),
						"file_system_id":              aws.ToString(fs.FileSystemId),
						"account_id":                  accountID,
						"region":                      region,
						"creation_time":               timeToString(fs.CreationTime),
						"dns_name":                    aws.ToString(fs.DNSName),
						"file_system_type":            string(fs.FileSystemType),
						"file_system_type_version":    aws.ToString(fs.FileSystemTypeVersion),
						"kms_key_id":                  aws.ToString(fs.KmsKeyId),
						"lifecycle":                   string(fs.Lifecycle),
						"lifecycle_transition_reason": "",
						"lustre_configuration":        string(lustreJSON),
						"network_interface_ids":       string(networkIDsJSON),
						"ontap_configuration":         string(ontapJSON),
						"open_zfs_configuration":      string(openzfsJSON),
						"owner_id":                    aws.ToString(fs.OwnerId),
						"resource_arn":                aws.ToString(fs.ResourceARN),
						"storage_capacity":            fs.StorageCapacity,
						"storage_type":                string(fs.StorageType),
						"subnet_ids":                  string(subnetIDsJSON),
						"vpc_id":                      aws.ToString(fs.VpcId),
						"windows_configuration":       string(windowsJSON),
						"administrative_actions":      string(actionsJSON),
						"failure_details":             string(failureJSON),
						"tags":                        string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// FSx Volumes table
func (e *SyncEngine) fsxVolumeTable() TableSpec {
	return TableSpec{
		Name: "aws_fsx_volumes",
		Columns: []string{
			"_cq_hash", "arn", "volume_id", "account_id", "region",
			"creation_time", "file_system_id", "lifecycle",
			"lifecycle_transition_reason", "name", "ontap_configuration",
			"open_zfs_configuration", "resource_arn", "volume_type",
			"administrative_actions", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := fsx.NewFromConfig(cfg, func(o *fsx.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := fsx.NewDescribeVolumesPaginator(client, &fsx.DescribeVolumesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, vol := range page.Volumes {
					lifecycleReasonJSON, _ := json.Marshal(vol.LifecycleTransitionReason)
					ontapJSON, _ := json.Marshal(vol.OntapConfiguration)
					openzfsJSON, _ := json.Marshal(vol.OpenZFSConfiguration)
					actionsJSON, _ := json.Marshal(vol.AdministrativeActions)

					tags := map[string]string{}
					for _, t := range vol.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                         aws.ToString(vol.ResourceARN),
						"volume_id":                   aws.ToString(vol.VolumeId),
						"account_id":                  accountID,
						"region":                      region,
						"creation_time":               timeToString(vol.CreationTime),
						"file_system_id":              aws.ToString(vol.FileSystemId),
						"lifecycle":                   string(vol.Lifecycle),
						"lifecycle_transition_reason": string(lifecycleReasonJSON),
						"name":                        aws.ToString(vol.Name),
						"ontap_configuration":         string(ontapJSON),
						"open_zfs_configuration":      string(openzfsJSON),
						"resource_arn":                aws.ToString(vol.ResourceARN),
						"volume_type":                 string(vol.VolumeType),
						"administrative_actions":      string(actionsJSON),
						"tags":                        string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// FSx Backups table
func (e *SyncEngine) fsxBackupTable() TableSpec {
	return TableSpec{
		Name: "aws_fsx_backups",
		Columns: []string{
			"_cq_hash", "arn", "backup_id", "account_id", "region",
			"creation_time", "directory_information", "failure_details",
			"file_system", "kms_key_id", "lifecycle", "owner_id",
			"progress_percent", "resource_arn", "resource_type",
			"source_backup_id", "source_backup_region", "type", "volume", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := fsx.NewFromConfig(cfg, func(o *fsx.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := fsx.NewDescribeBackupsPaginator(client, &fsx.DescribeBackupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, backup := range page.Backups {
					dirInfoJSON, _ := json.Marshal(backup.DirectoryInformation)
					failureJSON, _ := json.Marshal(backup.FailureDetails)
					fsJSON, _ := json.Marshal(backup.FileSystem)
					volumeJSON, _ := json.Marshal(backup.Volume)

					tags := map[string]string{}
					for _, t := range backup.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                   aws.ToString(backup.ResourceARN),
						"backup_id":             aws.ToString(backup.BackupId),
						"account_id":            accountID,
						"region":                region,
						"creation_time":         timeToString(backup.CreationTime),
						"directory_information": string(dirInfoJSON),
						"failure_details":       string(failureJSON),
						"file_system":           string(fsJSON),
						"kms_key_id":            aws.ToString(backup.KmsKeyId),
						"lifecycle":             string(backup.Lifecycle),
						"owner_id":              aws.ToString(backup.OwnerId),
						"progress_percent":      backup.ProgressPercent,
						"resource_arn":          aws.ToString(backup.ResourceARN),
						"resource_type":         string(backup.ResourceType),
						"source_backup_id":      aws.ToString(backup.SourceBackupId),
						"source_backup_region":  aws.ToString(backup.SourceBackupRegion),
						"type":                  string(backup.Type),
						"volume":                string(volumeJSON),
						"tags":                  string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
