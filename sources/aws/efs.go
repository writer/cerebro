package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsEFSFileSystem struct {
	FileSystem   efstypes.FileSystemDescription
	Tags         map[string]string
	MountTargets []awsEFSMountTarget
}

type awsEFSMountTarget struct {
	MountTarget    efstypes.MountTargetDescription
	SecurityGroups []string
	FileSystem     *efstypes.FileSystemDescription `json:"file_system,omitempty"`
	Tags           map[string]string               `json:"tags,omitempty"`
}

type awsEFSAccessPoint struct {
	AccessPoint efstypes.AccessPointDescription
	Tags        map[string]string
}

func listEFSFileSystems(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEFSFileSystem, string, error) {
	out, err := clients.efs.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEFSFileSystem, 0, len(out.FileSystems))
	for _, fileSystem := range out.FileSystems {
		record := awsEFSFileSystem{FileSystem: fileSystem, Tags: efsTagMap(fileSystem.Tags)}
		mountTargets, err := listAllEFSMountTargets(ctx, clients, awssdk.ToString(fileSystem.FileSystemId))
		if err != nil {
			return nil, "", err
		}
		record.MountTargets = mountTargets
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextMarker), nil
}

func listEFSAccessPoints(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEFSAccessPoint, string, error) {
	out, err := clients.efs.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEFSAccessPoint, 0, len(out.AccessPoints))
	for _, accessPoint := range out.AccessPoints {
		records = append(records, awsEFSAccessPoint{AccessPoint: accessPoint, Tags: efsTagMap(accessPoint.Tags)})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEFSMountTargets(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEFSMountTarget, string, error) {
	out, err := clients.efs.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
	})
	if err != nil {
		return nil, "", err
	}
	var records []awsEFSMountTarget
	for _, fileSystem := range out.FileSystems {
		mountTargets, err := listAllEFSMountTargets(ctx, clients, awssdk.ToString(fileSystem.FileSystemId))
		if err != nil {
			return nil, "", err
		}
		tags := efsTagMap(fileSystem.Tags)
		fileSystemCopy := fileSystem
		for _, mountTarget := range mountTargets {
			mountTarget.FileSystem = &fileSystemCopy
			mountTarget.Tags = tags
			records = append(records, mountTarget)
		}
	}
	return records, awssdk.ToString(out.NextMarker), nil
}

func efsFileSystemEvent(settings settings, record awsEFSFileSystem) (*primitives.Event, error) {
	fileSystem := record.FileSystem
	arn := awssdk.ToString(fileSystem.FileSystemArn)
	id := awssdk.ToString(fileSystem.FileSystemId)
	name := firstNonEmpty(awssdk.ToString(fileSystem.Name), id)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEFSFileSystem, firstNonEmpty(arn, id), name, "efs_file_system", record.Tags)
	attributes["arn"] = arn
	attributes["file_system_arn"] = arn
	attributes["file_system_id"] = id
	attributes["file_system_name"] = name
	attributes["state"] = string(fileSystem.LifeCycleState)
	attributes["owner_id"] = awssdk.ToString(fileSystem.OwnerId)
	attributes["performance_mode"] = string(fileSystem.PerformanceMode)
	attributes["throughput_mode"] = string(fileSystem.ThroughputMode)
	attributes["encrypted"] = boolString(awssdk.ToBool(fileSystem.Encrypted))
	attributes["encryption"] = attributes["encrypted"]
	attributes["kms_key_id"] = awssdk.ToString(fileSystem.KmsKeyId)
	attributes["availability_zone_id"] = awssdk.ToString(fileSystem.AvailabilityZoneId)
	attributes["availability_zone_name"] = awssdk.ToString(fileSystem.AvailabilityZoneName)
	attributes["mount_target_count"] = strconv.Itoa(len(record.MountTargets))
	attributes["number_of_mount_targets"] = strconv.FormatInt(int64(fileSystem.NumberOfMountTargets), 10)
	attributes["mount_target_ids"] = strings.Join(efsMountTargetIDs(record.MountTargets), ",")
	attributes["subnet_ids"] = strings.Join(efsMountTargetSubnets(record.MountTargets), ",")
	attributes["vpc_ids"] = strings.Join(efsMountTargetVPCs(record.MountTargets), ",")
	attributes["security_group_ids"] = strings.Join(efsMountTargetSecurityGroups(record.MountTargets), ",")
	if fileSystem.SizeInBytes != nil {
		attributes["size_bytes"] = strconv.FormatInt(fileSystem.SizeInBytes.Value, 10)
		attributes["size_ia_bytes"] = int64AttrString(fileSystem.SizeInBytes.ValueInIA)
		attributes["size_archive_bytes"] = int64AttrString(fileSystem.SizeInBytes.ValueInArchive)
		attributes["size_standard_bytes"] = int64AttrString(fileSystem.SizeInBytes.ValueInStandard)
		addTimeAttribute(attributes, "size_recorded_at", fileSystem.SizeInBytes.Timestamp)
	}
	if fileSystem.ProvisionedThroughputInMibps != nil {
		attributes["provisioned_throughput_mibps"] = strconv.FormatFloat(awssdk.ToFloat64(fileSystem.ProvisionedThroughputInMibps), 'f', -1, 64)
	}
	if fileSystem.FileSystemProtection != nil {
		attributes["replication_overwrite_protection"] = string(fileSystem.FileSystemProtection.ReplicationOverwriteProtection)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "file_system": fileSystem, "mount_targets": record.MountTargets, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-efs-file-system-"+firstNonEmpty(arn, id), "aws.efs_file_system", "aws/efs_file_system/v1", payload, attributes, firstTime(fileSystem.CreationTime))
}

func efsAccessPointEvent(settings settings, record awsEFSAccessPoint) (*primitives.Event, error) {
	accessPoint := record.AccessPoint
	arn := awssdk.ToString(accessPoint.AccessPointArn)
	id := awssdk.ToString(accessPoint.AccessPointId)
	name := firstNonEmpty(awssdk.ToString(accessPoint.Name), id)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEFSAccessPoint, firstNonEmpty(arn, id), name, "efs_access_point", record.Tags)
	attributes["arn"] = arn
	attributes["access_point_arn"] = arn
	attributes["access_point_id"] = id
	attributes["access_point_name"] = name
	attributes["file_system_id"] = awssdk.ToString(accessPoint.FileSystemId)
	attributes["state"] = string(accessPoint.LifeCycleState)
	attributes["owner_id"] = awssdk.ToString(accessPoint.OwnerId)
	if accessPoint.PosixUser != nil {
		attributes["posix_uid"] = int64AttrString(accessPoint.PosixUser.Uid)
		attributes["posix_gid"] = int64AttrString(accessPoint.PosixUser.Gid)
		attributes["secondary_gids"] = strings.Join(int64SliceStrings(accessPoint.PosixUser.SecondaryGids), ",")
	}
	if accessPoint.RootDirectory != nil {
		attributes["root_directory_path"] = awssdk.ToString(accessPoint.RootDirectory.Path)
		if accessPoint.RootDirectory.CreationInfo != nil {
			attributes["root_owner_uid"] = int64AttrString(accessPoint.RootDirectory.CreationInfo.OwnerUid)
			attributes["root_owner_gid"] = int64AttrString(accessPoint.RootDirectory.CreationInfo.OwnerGid)
			attributes["root_permissions"] = awssdk.ToString(accessPoint.RootDirectory.CreationInfo.Permissions)
		}
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "access_point": accessPoint, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-efs-access-point-"+firstNonEmpty(arn, id), "aws.efs_access_point", "aws/efs_access_point/v1", payload, attributes, time.Now().UTC())
}

func efsMountTargetEvent(settings settings, record awsEFSMountTarget) (*primitives.Event, error) {
	mountTarget := record.MountTarget
	id := awssdk.ToString(mountTarget.MountTargetId)
	arn := efsMountTargetARN(settings, id)
	name := id
	fileSystemID := awssdk.ToString(mountTarget.FileSystemId)
	fileSystemARN := ""
	fileSystemName := ""
	encrypted := ""
	kmsKeyID := ""
	if record.FileSystem != nil {
		fileSystemARN = awssdk.ToString(record.FileSystem.FileSystemArn)
		fileSystemName = firstNonEmpty(awssdk.ToString(record.FileSystem.Name), fileSystemID)
		encrypted = boolString(awssdk.ToBool(record.FileSystem.Encrypted))
		kmsKeyID = awssdk.ToString(record.FileSystem.KmsKeyId)
	}
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEFSMountTarget, firstNonEmpty(arn, id), name, "efs_mount_target", record.Tags)
	attributes["arn"] = arn
	attributes["mount_target_arn"] = arn
	attributes["mount_target_id"] = id
	attributes["file_system_id"] = fileSystemID
	attributes["file_system_arn"] = fileSystemARN
	attributes["file_system_name"] = fileSystemName
	attributes["state"] = string(mountTarget.LifeCycleState)
	attributes["owner_id"] = awssdk.ToString(mountTarget.OwnerId)
	attributes["availability_zone_id"] = awssdk.ToString(mountTarget.AvailabilityZoneId)
	attributes["availability_zone_name"] = awssdk.ToString(mountTarget.AvailabilityZoneName)
	attributes["ip_address"] = awssdk.ToString(mountTarget.IpAddress)
	attributes["ipv6_address"] = awssdk.ToString(mountTarget.Ipv6Address)
	attributes["network_interface_id"] = awssdk.ToString(mountTarget.NetworkInterfaceId)
	attributes["network_interface_ids"] = awssdk.ToString(mountTarget.NetworkInterfaceId)
	attributes["security_group_ids"] = strings.Join(cleanStrings(record.SecurityGroups), ",")
	attributes["subnet_id"] = awssdk.ToString(mountTarget.SubnetId)
	attributes["subnet_ids"] = awssdk.ToString(mountTarget.SubnetId)
	attributes["vpc_id"] = awssdk.ToString(mountTarget.VpcId)
	attributes["encrypted"] = encrypted
	attributes["kms_key_id"] = kmsKeyID
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "file_system": record.FileSystem, "mount_target": mountTarget, "security_groups": record.SecurityGroups, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-efs-mount-target-"+firstNonEmpty(arn, id), "aws.efs_mount_target", "aws/efs_mount_target/v1", payload, attributes, time.Now().UTC())
}

func listAllEFSMountTargets(ctx context.Context, clients awsClients, fileSystemID string) ([]awsEFSMountTarget, error) {
	if strings.TrimSpace(fileSystemID) == "" {
		return nil, nil
	}
	var records []awsEFSMountTarget
	var cursor string
	for {
		out, err := clients.efs.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: awssdk.String(fileSystemID),
			Marker:       stringPtr(cursor),
			MaxItems:     awssdk.Int32(100),
		})
		if err != nil {
			if optionalAWSError(err, "FileSystemNotFound") {
				return records, nil
			}
			return nil, fmt.Errorf("describe efs mount targets %q: %w", fileSystemID, err)
		}
		for _, mountTarget := range out.MountTargets {
			record := awsEFSMountTarget{MountTarget: mountTarget}
			mountTargetID := awssdk.ToString(mountTarget.MountTargetId)
			if mountTargetID != "" {
				groups, err := clients.efs.DescribeMountTargetSecurityGroups(ctx, &efs.DescribeMountTargetSecurityGroupsInput{MountTargetId: awssdk.String(mountTargetID)})
				if err != nil {
					if !optionalAWSError(err, "MountTargetNotFound") {
						return nil, fmt.Errorf("describe efs mount target security groups %q: %w", mountTargetID, err)
					}
				} else {
					record.SecurityGroups = groups.SecurityGroups
				}
			}
			records = append(records, record)
		}
		cursor = awssdk.ToString(out.NextMarker)
		if cursor == "" {
			return records, nil
		}
	}
}

func efsMountTargetARN(settings settings, mountTargetID string) string {
	if mountTargetID == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:elasticfilesystem:%s:%s:mount-target/%s", settings.region, settings.accountID, mountTargetID)
}

func efsTagMap(tags []efstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func efsMountTargetIDs(targets []awsEFSMountTarget) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		if value := strings.TrimSpace(awssdk.ToString(target.MountTarget.MountTargetId)); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func efsMountTargetSubnets(targets []awsEFSMountTarget) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		if value := strings.TrimSpace(awssdk.ToString(target.MountTarget.SubnetId)); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func efsMountTargetVPCs(targets []awsEFSMountTarget) []string {
	return uniqueStringsFromTargets(targets, func(target awsEFSMountTarget) string {
		return awssdk.ToString(target.MountTarget.VpcId)
	})
}

func efsMountTargetSecurityGroups(targets []awsEFSMountTarget) []string {
	seen := map[string]struct{}{}
	var values []string
	for _, target := range targets {
		for _, group := range target.SecurityGroups {
			group = strings.TrimSpace(group)
			if group == "" {
				continue
			}
			if _, ok := seen[group]; ok {
				continue
			}
			seen[group] = struct{}{}
			values = append(values, group)
		}
	}
	return values
}

func uniqueStringsFromTargets(targets []awsEFSMountTarget, value func(awsEFSMountTarget) string) []string {
	seen := map[string]struct{}{}
	var values []string
	for _, target := range targets {
		item := strings.TrimSpace(value(target))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		values = append(values, item)
	}
	return values
}

func int64SliceStrings(values []int64) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strconv.FormatInt(value, 10))
	}
	return out
}
