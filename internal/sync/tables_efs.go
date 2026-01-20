package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func (e *SyncEngine) efsFileSystemTable() TableSpec {
	return TableSpec{
		Name:    "aws_efs_file_systems",
		Columns: []string{"arn", "account_id", "region", "file_system_id", "name", "creation_time", "life_cycle_state", "number_of_mount_targets", "size_in_bytes", "performance_mode", "encrypted", "kms_key_id", "throughput_mode", "provisioned_throughput_in_mibps", "tags"},
		Fetch:   e.fetchEFSFileSystems,
	}
}

func (e *SyncEngine) efsMountTargetTable() TableSpec {
	return TableSpec{
		Name:    "aws_efs_mount_targets",
		Columns: []string{"arn", "account_id", "region", "mount_target_id", "file_system_id", "subnet_id", "life_cycle_state", "ip_address", "network_interface_id", "availability_zone_id", "availability_zone_name", "vpc_id", "owner_id"},
		Fetch:   e.fetchEFSMountTargets,
	}
}

func (e *SyncEngine) fetchEFSFileSystems(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := efs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := efs.NewDescribeFileSystemsPaginator(client, &efs.DescribeFileSystemsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fs := range page.FileSystems {
			fsID := aws.ToString(fs.FileSystemId)
			arn := fmt.Sprintf("arn:aws:elasticfilesystem:%s:%s:file-system/%s", region, accountID, fsID)

			row := map[string]interface{}{
				"_cq_id":                  arn,
				"arn":                     arn,
				"account_id":              accountID,
				"region":                  region,
				"file_system_id":          fsID,
				"name":                    aws.ToString(fs.Name),
				"creation_time":           fs.CreationTime,
				"life_cycle_state":        string(fs.LifeCycleState),
				"number_of_mount_targets": fs.NumberOfMountTargets,
				"performance_mode":        string(fs.PerformanceMode),
				"encrypted":               aws.ToBool(fs.Encrypted),
				"kms_key_id":              aws.ToString(fs.KmsKeyId),
				"throughput_mode":         string(fs.ThroughputMode),
				"tags":                    fs.Tags,
			}

			if fs.SizeInBytes != nil {
				row["size_in_bytes"] = fs.SizeInBytes.Value
			}
			if fs.ProvisionedThroughputInMibps != nil {
				row["provisioned_throughput_in_mibps"] = *fs.ProvisionedThroughputInMibps
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchEFSMountTargets(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := efs.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// First get all file systems
	fsPaginator := efs.NewDescribeFileSystemsPaginator(client, &efs.DescribeFileSystemsInput{})

	var rows []map[string]interface{}
	for fsPaginator.HasMorePages() {
		fsPage, err := fsPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fs := range fsPage.FileSystems {
			// Get mount targets for each file system
			mtPaginator := efs.NewDescribeMountTargetsPaginator(client, &efs.DescribeMountTargetsInput{
				FileSystemId: fs.FileSystemId,
			})

			for mtPaginator.HasMorePages() {
				mtPage, err := mtPaginator.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, mt := range mtPage.MountTargets {
					mtID := aws.ToString(mt.MountTargetId)
					arn := fmt.Sprintf("arn:aws:elasticfilesystem:%s:%s:mount-target/%s", region, accountID, mtID)

					rows = append(rows, map[string]interface{}{
						"_cq_id":                 arn,
						"arn":                    arn,
						"account_id":             accountID,
						"region":                 region,
						"mount_target_id":        mtID,
						"file_system_id":         aws.ToString(mt.FileSystemId),
						"subnet_id":              aws.ToString(mt.SubnetId),
						"life_cycle_state":       string(mt.LifeCycleState),
						"ip_address":             aws.ToString(mt.IpAddress),
						"network_interface_id":   aws.ToString(mt.NetworkInterfaceId),
						"availability_zone_id":   aws.ToString(mt.AvailabilityZoneId),
						"availability_zone_name": aws.ToString(mt.AvailabilityZoneName),
						"vpc_id":                 aws.ToString(mt.VpcId),
						"owner_id":               aws.ToString(mt.OwnerId),
					})
				}
			}
		}
	}
	return rows, nil
}
