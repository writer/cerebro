package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsS3AccessPoint struct {
	Summary      s3controltypes.AccessPoint
	Detail       *s3control.GetAccessPointOutput
	Tags         map[string]string
	PublicPolicy *bool
}

type awsS3MultiRegionAccessPoint struct {
	Report       s3controltypes.MultiRegionAccessPointReport
	Tags         map[string]string
	PublicPolicy *bool
}

type awsEBSSnapshot struct {
	Snapshot ec2types.Snapshot
	Public   bool
}

type awsEC2EBSEncryptionByDefault struct {
	ResourceID string
	Region     string
	Enabled    bool
	ObservedAt time.Time
}

type awsDataSyncTask struct {
	Task *datasync.DescribeTaskOutput
	Tags map[string]string
}

type awsDataSyncLocation struct {
	Entry                   datasynctypes.LocationListEntry
	Type                    string
	CreationTime            *time.Time
	AgentARNs               []string
	RoleARN                 string
	KMSKeyID                string
	SecretARN               string
	StorageClass            string
	Protocol                string
	AuthenticationType      string
	Domain                  string
	User                    string
	SubnetARN               string
	SecurityGroupARNs       []string
	AccessPointARN          string
	FileSystemAccessRoleARN string
	InTransitEncryption     string
	Tags                    map[string]string
}

func listS3AccessPoints(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsS3AccessPoint, string, error) {
	out, err := clients.s3control.ListAccessPoints(ctx, &s3control.ListAccessPointsInput{
		AccountId:      awssdk.String(settings.accountID),
		DataSourceType: awssdk.String("ALL"),
		MaxResults:     boundedAWSPageSizeInt32(limit, 1, 1000),
		NextToken:      stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsS3AccessPoint, 0, len(out.AccessPointList))
	for _, summary := range out.AccessPointList {
		name := awssdk.ToString(summary.Name)
		if name == "" {
			continue
		}
		record := awsS3AccessPoint{Summary: summary}
		if detail, err := clients.s3control.GetAccessPoint(ctx, &s3control.GetAccessPointInput{AccountId: awssdk.String(settings.accountID), Name: awssdk.String(name)}); err == nil {
			record.Detail = detail
		} else if !optionalAWSError(err, "NoSuchAccessPoint", "NoSuchAccessPointPolicy", "NotFound") {
			return nil, "", fmt.Errorf("get s3 access point %q: %w", name, err)
		}
		arn := s3AccessPointARN(settings, firstNonEmpty(awssdk.ToString(summary.AccessPointArn), s3AccessPointDetailARN(record.Detail)), name)
		if tags, err := clients.s3control.ListTagsForResource(ctx, &s3control.ListTagsForResourceInput{AccountId: awssdk.String(settings.accountID), ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = s3ControlTagMap(tags.Tags)
		} else if !optionalAWSError(err, "NoSuchTagSet", "NoSuchAccessPoint", "NoSuchAccessPointPolicy", "NotFound") {
			return nil, "", fmt.Errorf("list s3 access point tags %q: %w", name, err)
		}
		if status, err := clients.s3control.GetAccessPointPolicyStatus(ctx, &s3control.GetAccessPointPolicyStatusInput{AccountId: awssdk.String(settings.accountID), Name: awssdk.String(name)}); err == nil && status.PolicyStatus != nil {
			public := status.PolicyStatus.IsPublic
			record.PublicPolicy = &public
		} else if !optionalAWSError(err, "NoSuchAccessPoint", "NoSuchAccessPointPolicy", "NotFound") {
			return nil, "", fmt.Errorf("get s3 access point policy status %q: %w", name, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listS3MultiRegionAccessPoints(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsS3MultiRegionAccessPoint, string, error) {
	out, err := clients.s3control.ListMultiRegionAccessPoints(ctx, &s3control.ListMultiRegionAccessPointsInput{
		AccountId:  awssdk.String(settings.accountID),
		MaxResults: boundedAWSPageSizeInt32(limit, 1, 100),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsS3MultiRegionAccessPoint, 0, len(out.AccessPoints))
	for _, report := range out.AccessPoints {
		name := awssdk.ToString(report.Name)
		if name == "" {
			continue
		}
		record := awsS3MultiRegionAccessPoint{Report: report}
		if detail, err := clients.s3control.GetMultiRegionAccessPoint(ctx, &s3control.GetMultiRegionAccessPointInput{AccountId: awssdk.String(settings.accountID), Name: awssdk.String(name)}); err == nil && detail.AccessPoint != nil {
			record.Report = *detail.AccessPoint
		} else if !optionalAWSError(err, "NoSuchMultiRegionAccessPoint", "NoSuchAccessPoint", "NotFound") {
			return nil, "", fmt.Errorf("get s3 multi-region access point %q: %w", name, err)
		}
		arn := s3MultiRegionAccessPointARN(settings, awssdk.ToString(record.Report.Alias), name)
		if tags, err := clients.s3control.ListTagsForResource(ctx, &s3control.ListTagsForResourceInput{AccountId: awssdk.String(settings.accountID), ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = s3ControlTagMap(tags.Tags)
		} else if !optionalAWSError(err, "NoSuchMultiRegionAccessPoint", "NoSuchAccessPoint", "NoSuchTagSet", "NotFound") {
			return nil, "", fmt.Errorf("list s3 multi-region access point tags %q: %w", name, err)
		}
		if status, err := clients.s3control.GetMultiRegionAccessPointPolicyStatus(ctx, &s3control.GetMultiRegionAccessPointPolicyStatusInput{AccountId: awssdk.String(settings.accountID), Name: awssdk.String(name)}); err == nil && status.Established != nil {
			public := status.Established.IsPublic
			record.PublicPolicy = &public
		} else if !optionalAWSError(err, "NoSuchMultiRegionAccessPoint", "NoSuchAccessPointPolicy", "NotFound") {
			return nil, "", fmt.Errorf("get s3 multi-region access point policy status %q: %w", name, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEBSVolumes(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.Volume, string, error) {
	out, err := clients.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 500)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Volumes, awssdk.ToString(out.NextToken), nil
}

func listEBSSnapshots(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsEBSSnapshot, string, error) {
	out, err := clients.ec2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
		OwnerIds:   []string{"self"},
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEBSSnapshot, 0, len(out.Snapshots))
	for _, snapshot := range out.Snapshots {
		record := awsEBSSnapshot{Snapshot: snapshot}
		snapshotID := awssdk.ToString(snapshot.SnapshotId)
		if snapshotID != "" {
			attr, err := clients.ec2.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
				SnapshotId: awssdk.String(snapshotID),
			})
			if err != nil && !optionalAWSError(err, "InvalidSnapshot.NotFound", "AuthFailure", "UnauthorizedOperation") {
				return nil, "", fmt.Errorf("describe ebs snapshot permissions %q for %s: %w", snapshotID, settings.accountID, err)
			}
			record.Public = ebsSnapshotPublic(attr)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEC2EBSEncryptionByDefault(ctx context.Context, clients awsClients, settings settings, cursor string, _ int) ([]awsEC2EBSEncryptionByDefault, string, error) {
	if strings.TrimSpace(cursor) != "" {
		return nil, "", nil
	}
	out, err := clients.ec2.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return nil, "", err
	}
	return []awsEC2EBSEncryptionByDefault{{
		ResourceID: ec2EBSEncryptionByDefaultResourceID(settings),
		Region:     settings.region,
		Enabled:    awssdk.ToBool(out.EbsEncryptionByDefault),
		ObservedAt: time.Now().UTC(),
	}}, "", nil
}

func listDataSyncTasks(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsDataSyncTask, string, error) {
	out, err := clients.datasync.ListTasks(ctx, &datasync.ListTasksInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDataSyncTask, 0, len(out.Tasks))
	for _, summary := range out.Tasks {
		arn := awssdk.ToString(summary.TaskArn)
		if arn == "" {
			continue
		}
		task, err := clients.datasync.DescribeTask(ctx, &datasync.DescribeTaskInput{TaskArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe datasync task %q: %w", arn, err)
		}
		record := awsDataSyncTask{Task: task}
		tags, err := datasyncTags(ctx, clients, arn)
		if err != nil {
			return nil, "", fmt.Errorf("list datasync task tags %q for %s: %w", arn, settings.accountID, err)
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listDataSyncLocations(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsDataSyncLocation, string, error) {
	out, err := clients.datasync.ListLocations(ctx, &datasync.ListLocationsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDataSyncLocation, 0, len(out.Locations))
	for _, entry := range out.Locations {
		location, err := describeDataSyncLocation(ctx, clients, entry)
		if err != nil {
			return nil, "", fmt.Errorf("describe datasync location %q for %s: %w", awssdk.ToString(entry.LocationArn), settings.accountID, err)
		}
		tags, err := datasyncTags(ctx, clients, awssdk.ToString(entry.LocationArn))
		if err != nil {
			return nil, "", fmt.Errorf("list datasync location tags %q for %s: %w", awssdk.ToString(entry.LocationArn), settings.accountID, err)
		}
		location.Tags = tags
		records = append(records, location)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func s3AccessPointEvent(settings settings, record awsS3AccessPoint) (*primitives.Event, error) {
	name := firstNonEmpty(s3AccessPointDetailName(record.Detail), awssdk.ToString(record.Summary.Name))
	arn := s3AccessPointARN(settings, firstNonEmpty(s3AccessPointDetailARN(record.Detail), awssdk.ToString(record.Summary.AccessPointArn)), name)
	region := settings.region
	publicBlock := s3AccessPointPublicBlock(record.Detail)
	networkOrigin := firstNonEmpty(s3AccessPointNetworkOrigin(record.Detail), string(record.Summary.NetworkOrigin))
	public := s3AccessPointPublic(networkOrigin, publicBlock, record.PublicPolicy)
	attributes := commonCloudAssetAttributes(settings, region, familyS3AccessPoint, firstNonEmpty(arn, name), name, "s3_access_point", record.Tags)
	attributes["arn"] = arn
	attributes["access_point_name"] = name
	attributes["alias"] = firstNonEmpty(s3AccessPointDetailAlias(record.Detail), awssdk.ToString(record.Summary.Alias))
	attributes["bucket_name"] = firstNonEmpty(s3AccessPointDetailBucket(record.Detail), awssdk.ToString(record.Summary.Bucket))
	attributes["bucket_account_id"] = firstNonEmpty(s3AccessPointDetailBucketAccount(record.Detail), awssdk.ToString(record.Summary.BucketAccountId))
	attributes["data_source_id"] = firstNonEmpty(s3AccessPointDetailDataSourceID(record.Detail), awssdk.ToString(record.Summary.DataSourceId))
	attributes["data_source_type"] = firstNonEmpty(s3AccessPointDetailDataSourceType(record.Detail), awssdk.ToString(record.Summary.DataSourceType))
	attributes["network_origin"] = networkOrigin
	attributes["vpc_id"] = s3AccessPointVPCID(record)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = boolString(public)
	attributes["public_policy"] = boolString(record.PublicPolicy != nil && *record.PublicPolicy)
	attributes["encryption"] = "bucket_default"
	attributes["backups"] = ""
	attributes["block_public_acls"] = boolString(s3ControlPublicBlockBool(publicBlock, "block_public_acls"))
	attributes["block_public_policy"] = boolString(s3ControlPublicBlockBool(publicBlock, "block_public_policy"))
	attributes["ignore_public_acls"] = boolString(s3ControlPublicBlockBool(publicBlock, "ignore_public_acls"))
	attributes["restrict_public_buckets"] = boolString(s3ControlPublicBlockBool(publicBlock, "restrict_public_buckets"))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "access_point": record.Detail, "summary": record.Summary, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-s3-access-point-"+firstNonEmpty(arn, name), "aws.s3_access_point", "aws/s3_access_point/v1", payload, attributes, firstTime(s3AccessPointCreationDate(record.Detail)))
}

func s3MultiRegionAccessPointEvent(settings settings, record awsS3MultiRegionAccessPoint) (*primitives.Event, error) {
	name := awssdk.ToString(record.Report.Name)
	arn := s3MultiRegionAccessPointARN(settings, awssdk.ToString(record.Report.Alias), name)
	public := s3MultiRegionAccessPointPublic(record.Report.PublicAccessBlock, record.PublicPolicy)
	attributes := commonCloudAssetAttributes(settings, "global", familyS3MultiRegionAccessPoint, firstNonEmpty(arn, name), name, "s3_multi_region_access_point", record.Tags)
	attributes["arn"] = arn
	attributes["access_point_name"] = name
	attributes["alias"] = awssdk.ToString(record.Report.Alias)
	attributes["regions"] = strings.Join(s3MultiRegionAccessPointRegions(record.Report.Regions), ",")
	attributes["bucket_names"] = strings.Join(s3MultiRegionAccessPointBuckets(record.Report.Regions), ",")
	attributes["status"] = string(record.Report.Status)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = boolString(public)
	attributes["public_policy"] = boolString(record.PublicPolicy != nil && *record.PublicPolicy)
	attributes["encryption"] = "bucket_default"
	attributes["backups"] = boolString(len(record.Report.Regions) > 1)
	attributes["multi_region"] = boolString(true)
	attributes["block_public_acls"] = boolString(s3ControlPublicBlockBool(record.Report.PublicAccessBlock, "block_public_acls"))
	attributes["block_public_policy"] = boolString(s3ControlPublicBlockBool(record.Report.PublicAccessBlock, "block_public_policy"))
	attributes["ignore_public_acls"] = boolString(s3ControlPublicBlockBool(record.Report.PublicAccessBlock, "ignore_public_acls"))
	attributes["restrict_public_buckets"] = boolString(s3ControlPublicBlockBool(record.Report.PublicAccessBlock, "restrict_public_buckets"))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "access_point": record.Report, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-s3-multi-region-access-point-"+firstNonEmpty(arn, name), "aws.s3_multi_region_access_point", "aws/s3_multi_region_access_point/v1", payload, attributes, firstTime(record.Report.CreatedAt))
}

func ebsVolumeEvent(settings settings, volume ec2types.Volume) (*primitives.Event, error) {
	volumeID := awssdk.ToString(volume.VolumeId)
	arn := ebsVolumeARN(settings, volumeID)
	tags := ec2Tags(volume.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEBSVolume, firstNonEmpty(arn, volumeID), firstNonEmpty(ec2NameTag(volume.Tags), volumeID), "ebs_volume", tags)
	attributes["arn"] = arn
	attributes["availability_zone"] = awssdk.ToString(volume.AvailabilityZone)
	attributes["availability_zone_id"] = awssdk.ToString(volume.AvailabilityZoneId)
	attributes["backups"] = boolString(awssdk.ToString(volume.SnapshotId) != "")
	attributes["encryption"] = boolString(awssdk.ToBool(volume.Encrypted))
	attributes["iops"] = int32AttrString(volume.Iops)
	attributes["kms_key_id"] = awssdk.ToString(volume.KmsKeyId)
	attributes["multi_attach_enabled"] = boolString(awssdk.ToBool(volume.MultiAttachEnabled))
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = boolString(false)
	attributes["size_gib"] = int32AttrString(volume.Size)
	attributes["snapshot_id"] = awssdk.ToString(volume.SnapshotId)
	attributes["state"] = string(volume.State)
	attributes["throughput_mibps"] = int32AttrString(volume.Throughput)
	attributes["volume_id"] = volumeID
	attributes["volume_type"] = string(volume.VolumeType)
	attributes["attached_instance_ids"] = strings.Join(ebsVolumeAttachmentInstanceIDs(volume.Attachments), ",")
	attributes["attachment_states"] = strings.Join(ebsVolumeAttachmentStates(volume.Attachments), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "volume": volume, "tags": tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ebs-volume-"+firstNonEmpty(volumeID, arn), "aws.ebs_volume", "aws/ebs_volume/v1", payload, attributes, firstTime(volume.CreateTime))
}

func ebsSnapshotEvent(settings settings, record awsEBSSnapshot) (*primitives.Event, error) {
	snapshot := record.Snapshot
	snapshotID := awssdk.ToString(snapshot.SnapshotId)
	tags := ec2Tags(snapshot.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEBSSnapshot, snapshotID, firstNonEmpty(ec2NameTag(snapshot.Tags), snapshotID), "ebs_snapshot", tags)
	attributes["availability_zone"] = awssdk.ToString(snapshot.AvailabilityZone)
	attributes["backups"] = boolString(true)
	attributes["description"] = awssdk.ToString(snapshot.Description)
	attributes["encryption"] = boolString(awssdk.ToBool(snapshot.Encrypted))
	attributes["kms_key_id"] = awssdk.ToString(snapshot.KmsKeyId)
	attributes["owner_id"] = awssdk.ToString(snapshot.OwnerId)
	attributes["progress"] = awssdk.ToString(snapshot.Progress)
	attributes["public"] = boolString(record.Public)
	attributes["internet_exposed"] = boolString(record.Public)
	attributes["snapshot_id"] = snapshotID
	attributes["state"] = string(snapshot.State)
	attributes["storage_tier"] = string(snapshot.StorageTier)
	attributes["volume_id"] = awssdk.ToString(snapshot.VolumeId)
	attributes["volume_size_gib"] = int32AttrString(snapshot.VolumeSize)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "snapshot": snapshot, "public": record.Public})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ebs-snapshot-"+snapshotID, "aws.ebs_snapshot", "aws/ebs_snapshot/v1", payload, attributes, firstTime(snapshot.StartTime))
}

func ec2EBSEncryptionByDefaultEvent(settings settings, record awsEC2EBSEncryptionByDefault) (*primitives.Event, error) {
	region := firstNonEmpty(record.Region, settings.region)
	resourceID := firstNonEmpty(record.ResourceID, ec2EBSEncryptionByDefaultResourceID(settings))
	attributes := commonCloudAssetAttributes(settings, region, familyEC2EBSEncryptionByDefault, resourceID, "EBS encryption by default "+region, "ec2_ebs_encryption_by_default", nil)
	attributes["account_id"] = settings.accountID
	attributes["arn"] = resourceID
	attributes["ebs_encryption_enabled"] = boolString(record.Enabled)
	attributes["enabled"] = boolString(record.Enabled)
	attributes["encryption"] = boolString(record.Enabled)
	attributes["internet_exposed"] = boolString(false)
	attributes["policy_resource_type"] = "aws::ec2::ebs_encryption_by_default"
	attributes["public"] = boolString(false)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": region, "resource_id": resourceID, "ebs_encryption_enabled": record.Enabled})
	if err != nil {
		return nil, err
	}
	observedAt := record.ObservedAt
	return sourceEvent(settings, "aws-ec2-ebs-encryption-by-default-"+region, "aws.ec2_ebs_encryption_by_default", "aws/ec2_ebs_encryption_by_default/v1", payload, attributes, firstTime(&observedAt))
}

func dataSyncTaskEvent(settings settings, record awsDataSyncTask) (*primitives.Event, error) {
	task := record.Task
	taskARN := awssdk.ToString(task.TaskArn)
	name := firstNonEmpty(awssdk.ToString(task.Name), awsResourceName(taskARN))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDataSyncTask, taskARN, name, "datasync_task", record.Tags)
	attributes["task_arn"] = taskARN
	attributes["task_name"] = name
	attributes["task_mode"] = string(task.TaskMode)
	attributes["state"] = string(task.Status)
	attributes["status"] = string(task.Status)
	attributes["source_location_arn"] = awssdk.ToString(task.SourceLocationArn)
	attributes["destination_location_arn"] = awssdk.ToString(task.DestinationLocationArn)
	attributes["source_network_interface_arns"] = strings.Join(cleanStrings(task.SourceNetworkInterfaceArns), ",")
	attributes["destination_network_interface_arns"] = strings.Join(cleanStrings(task.DestinationNetworkInterfaceArns), ",")
	attributes["cloudwatch_log_group_arn"] = awssdk.ToString(task.CloudWatchLogGroupArn)
	attributes["current_task_execution_arn"] = awssdk.ToString(task.CurrentTaskExecutionArn)
	attributes["error_code"] = awssdk.ToString(task.ErrorCode)
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = boolString(false)
	attributes["encryption"] = "service_managed"
	attributes["backups"] = boolString(task.Schedule != nil)
	if task.Schedule != nil {
		attributes["schedule_expression"] = awssdk.ToString(task.Schedule.ScheduleExpression)
		attributes["schedule_status"] = string(task.Schedule.Status)
	}
	if task.Options != nil {
		attributes["bytes_per_second"] = dataSyncInt64AttrString(task.Options.BytesPerSecond)
		attributes["log_level"] = string(task.Options.LogLevel)
		attributes["transfer_mode"] = string(task.Options.TransferMode)
		attributes["verify_mode"] = string(task.Options.VerifyMode)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "task": task, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-datasync-task-"+firstNonEmpty(taskARN, name), "aws.datasync_task", "aws/datasync_task/v1", payload, attributes, firstTime(task.CreationTime))
}

func dataSyncLocationEvent(settings settings, location awsDataSyncLocation) (*primitives.Event, error) {
	arn := awssdk.ToString(location.Entry.LocationArn)
	uri := awssdk.ToString(location.Entry.LocationUri)
	name := firstNonEmpty(path.Base(strings.TrimRight(uri, "/")), awsResourceName(arn), arn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDataSyncLocation, firstNonEmpty(arn, uri), name, "datasync_location", location.Tags)
	attributes["location_arn"] = arn
	attributes["location_uri"] = uri
	attributes["location_type"] = location.Type
	attributes["agent_arns"] = strings.Join(cleanStrings(location.AgentARNs), ",")
	attributes["role_arn"] = location.RoleARN
	attributes["kms_key_id"] = location.KMSKeyID
	attributes["secret_arn"] = location.SecretARN
	attributes["storage_class"] = location.StorageClass
	attributes["protocol"] = location.Protocol
	attributes["authentication_type"] = location.AuthenticationType
	attributes["domain_name"] = location.Domain
	attributes["user_name"] = location.User
	attributes["subnet_arn"] = location.SubnetARN
	attributes["security_group_arns"] = strings.Join(cleanStrings(location.SecurityGroupARNs), ",")
	attributes["access_point_arn"] = location.AccessPointARN
	attributes["file_system_access_role_arn"] = location.FileSystemAccessRoleARN
	attributes["in_transit_encryption"] = location.InTransitEncryption
	attributes["public"] = boolString(dataSyncLocationPublic(location))
	attributes["internet_exposed"] = attributes["public"]
	attributes["encryption"] = dataSyncLocationEncryption(location)
	attributes["backups"] = boolString(false)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "location": location})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-datasync-location-"+firstNonEmpty(arn, uri), "aws.datasync_location", "aws/datasync_location/v1", payload, attributes, firstTime(location.CreationTime))
}

func describeDataSyncLocation(ctx context.Context, clients awsClients, entry datasynctypes.LocationListEntry) (awsDataSyncLocation, error) {
	location := awsDataSyncLocation{Entry: entry, Type: dataSyncLocationType(awssdk.ToString(entry.LocationUri))}
	arn := awssdk.ToString(entry.LocationArn)
	if arn == "" {
		return location, nil
	}
	switch location.Type {
	case "s3":
		out, err := clients.datasync.DescribeLocationS3(ctx, &datasync.DescribeLocationS3Input{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AgentARNs, location.StorageClass = out.CreationTime, out.AgentArns, string(out.S3StorageClass)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
		if out.S3Config != nil {
			location.RoleARN = awssdk.ToString(out.S3Config.BucketAccessRoleArn)
		}
	case "efs":
		out, err := clients.datasync.DescribeLocationEfs(ctx, &datasync.DescribeLocationEfsInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AccessPointARN, location.FileSystemAccessRoleARN = out.CreationTime, awssdk.ToString(out.AccessPointArn), awssdk.ToString(out.FileSystemAccessRoleArn)
		location.InTransitEncryption = string(out.InTransitEncryption)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
		if out.Ec2Config != nil {
			location.SubnetARN = awssdk.ToString(out.Ec2Config.SubnetArn)
			location.SecurityGroupARNs = out.Ec2Config.SecurityGroupArns
		}
	case "fsx_lustre":
		out, err := clients.datasync.DescribeLocationFsxLustre(ctx, &datasync.DescribeLocationFsxLustreInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.SecurityGroupARNs = out.CreationTime, out.SecurityGroupArns
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "fsx_ontap":
		out, err := clients.datasync.DescribeLocationFsxOntap(ctx, &datasync.DescribeLocationFsxOntapInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.SecurityGroupARNs = out.CreationTime, out.SecurityGroupArns
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "fsx_openzfs":
		out, err := clients.datasync.DescribeLocationFsxOpenZfs(ctx, &datasync.DescribeLocationFsxOpenZfsInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.SecurityGroupARNs = out.CreationTime, out.SecurityGroupArns
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "fsx_windows":
		out, err := clients.datasync.DescribeLocationFsxWindows(ctx, &datasync.DescribeLocationFsxWindowsInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.SecurityGroupARNs = out.CreationTime, out.SecurityGroupArns
		location.Domain, location.User = awssdk.ToString(out.Domain), awssdk.ToString(out.User)
		location.KMSKeyID, location.SecretARN, location.RoleARN = dataSyncSecretAttributes(out.CmkSecretConfig, out.CustomSecretConfig, out.ManagedSecretConfig)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "nfs":
		out, err := clients.datasync.DescribeLocationNfs(ctx, &datasync.DescribeLocationNfsInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime = out.CreationTime
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
		if out.OnPremConfig != nil {
			location.AgentARNs = out.OnPremConfig.AgentArns
		}
	case "smb":
		out, err := clients.datasync.DescribeLocationSmb(ctx, &datasync.DescribeLocationSmbInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AgentARNs = out.CreationTime, out.AgentArns
		location.AuthenticationType, location.Domain, location.User = string(out.AuthenticationType), awssdk.ToString(out.Domain), awssdk.ToString(out.User)
		location.KMSKeyID, location.SecretARN, location.RoleARN = dataSyncSecretAttributes(out.CmkSecretConfig, out.CustomSecretConfig, out.ManagedSecretConfig)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "object_storage":
		out, err := clients.datasync.DescribeLocationObjectStorage(ctx, &datasync.DescribeLocationObjectStorageInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AgentARNs = out.CreationTime, out.AgentArns
		location.Protocol = string(out.ServerProtocol)
		location.KMSKeyID, location.SecretARN, location.RoleARN = dataSyncSecretAttributes(out.CmkSecretConfig, out.CustomSecretConfig, out.ManagedSecretConfig)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "hdfs":
		out, err := clients.datasync.DescribeLocationHdfs(ctx, &datasync.DescribeLocationHdfsInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AgentARNs = out.CreationTime, out.AgentArns
		location.AuthenticationType = string(out.AuthenticationType)
		location.KMSKeyID, location.SecretARN, location.RoleARN = dataSyncSecretAttributes(out.CmkSecretConfig, out.CustomSecretConfig, out.ManagedSecretConfig)
		if location.KMSKeyID == "" {
			location.KMSKeyID = awssdk.ToString(out.KmsKeyProviderUri)
		}
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	case "azure_blob":
		out, err := clients.datasync.DescribeLocationAzureBlob(ctx, &datasync.DescribeLocationAzureBlobInput{LocationArn: awssdk.String(arn)})
		if err != nil {
			return location, err
		}
		location.CreationTime, location.AgentARNs = out.CreationTime, out.AgentArns
		location.AuthenticationType = string(out.AuthenticationType)
		location.KMSKeyID, location.SecretARN, location.RoleARN = dataSyncSecretAttributes(out.CmkSecretConfig, out.CustomSecretConfig, out.ManagedSecretConfig)
		location.Entry.LocationArn, location.Entry.LocationUri = out.LocationArn, out.LocationUri
	}
	return location, nil
}

func datasyncTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	if strings.TrimSpace(arn) == "" {
		return nil, nil
	}
	out, err := clients.datasync.ListTagsForResource(ctx, &datasync.ListTagsForResourceInput{ResourceArn: awssdk.String(arn), MaxResults: awssdk.Int32(100)})
	if err != nil {
		return nil, err
	}
	return dataSyncTagMap(out.Tags), nil
}

func dataSyncSecretAttributes(cmk *datasynctypes.CmkSecretConfig, custom *datasynctypes.CustomSecretConfig, managed *datasynctypes.ManagedSecretConfig) (string, string, string) {
	if cmk != nil {
		return awssdk.ToString(cmk.KmsKeyArn), awssdk.ToString(cmk.SecretArn), ""
	}
	if custom != nil {
		return "", awssdk.ToString(custom.SecretArn), awssdk.ToString(custom.SecretAccessRoleArn)
	}
	if managed != nil {
		return "", awssdk.ToString(managed.SecretArn), ""
	}
	return "", "", ""
}

func dataSyncLocationType(uri string) string {
	prefix, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(uri)), "://")
	if !ok {
		return "unknown"
	}
	switch strings.ReplaceAll(prefix, "-", "_") {
	case "fsxl":
		return "fsx_lustre"
	case "fsxw":
		return "fsx_windows"
	case "fsxz":
		return "fsx_openzfs"
	case "fsxn", "fsxontap":
		return "fsx_ontap"
	default:
		return strings.ReplaceAll(prefix, "-", "_")
	}
}

func dataSyncLocationEncryption(location awsDataSyncLocation) string {
	switch {
	case location.KMSKeyID != "":
		return "customer_managed_kms"
	case strings.EqualFold(location.InTransitEncryption, "TLS1_2"):
		return "tls"
	case location.SecretARN != "":
		return "service_managed_secret"
	default:
		return ""
	}
}

func dataSyncLocationPublic(location awsDataSyncLocation) bool {
	switch location.Type {
	case "object_storage", "azure_blob":
		return true
	default:
		return false
	}
}

func ebsSnapshotPublic(output *ec2.DescribeSnapshotAttributeOutput) bool {
	if output == nil {
		return false
	}
	for _, permission := range output.CreateVolumePermissions {
		if permission.Group == ec2types.PermissionGroupAll {
			return true
		}
	}
	return false
}

func s3AccessPointPublic(networkOrigin string, block *s3controltypes.PublicAccessBlockConfiguration, publicPolicy *bool) bool {
	if !strings.EqualFold(networkOrigin, string(s3controltypes.NetworkOriginInternet)) {
		return false
	}
	if publicPolicy != nil && *publicPolicy {
		return true
	}
	if block == nil {
		return true
	}
	return !awssdk.ToBool(block.BlockPublicAcls) || !awssdk.ToBool(block.BlockPublicPolicy) || !awssdk.ToBool(block.IgnorePublicAcls) || !awssdk.ToBool(block.RestrictPublicBuckets)
}

func s3MultiRegionAccessPointPublic(block *s3controltypes.PublicAccessBlockConfiguration, publicPolicy *bool) bool {
	if publicPolicy != nil && *publicPolicy {
		return true
	}
	if block == nil {
		return true
	}
	return !awssdk.ToBool(block.BlockPublicAcls) || !awssdk.ToBool(block.BlockPublicPolicy) || !awssdk.ToBool(block.IgnorePublicAcls) || !awssdk.ToBool(block.RestrictPublicBuckets)
}

func s3ControlPublicBlockBool(block *s3controltypes.PublicAccessBlockConfiguration, field string) bool {
	if block == nil {
		return false
	}
	switch field {
	case "block_public_acls":
		return awssdk.ToBool(block.BlockPublicAcls)
	case "block_public_policy":
		return awssdk.ToBool(block.BlockPublicPolicy)
	case "ignore_public_acls":
		return awssdk.ToBool(block.IgnorePublicAcls)
	case "restrict_public_buckets":
		return awssdk.ToBool(block.RestrictPublicBuckets)
	default:
		return false
	}
}

func s3AccessPointPublicBlock(detail *s3control.GetAccessPointOutput) *s3controltypes.PublicAccessBlockConfiguration {
	if detail == nil {
		return nil
	}
	return detail.PublicAccessBlockConfiguration
}

func s3AccessPointVPCID(record awsS3AccessPoint) string {
	if record.Detail != nil && record.Detail.VpcConfiguration != nil {
		return awssdk.ToString(record.Detail.VpcConfiguration.VpcId)
	}
	if record.Summary.VpcConfiguration != nil {
		return awssdk.ToString(record.Summary.VpcConfiguration.VpcId)
	}
	return ""
}

func s3AccessPointARN(settings settings, arn string, name string) string {
	if strings.TrimSpace(arn) != "" {
		return strings.TrimSpace(arn)
	}
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", settings.region, settings.accountID, strings.TrimSpace(name))
}

func s3MultiRegionAccessPointARN(settings settings, alias string, name string) string {
	resourceName := firstNonEmpty(alias, name)
	if strings.TrimSpace(resourceName) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:s3::%s:accesspoint/%s", settings.accountID, strings.TrimSpace(resourceName))
}

func ebsVolumeARN(settings settings, volumeID string) string {
	if strings.TrimSpace(volumeID) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", settings.region, settings.accountID, strings.TrimSpace(volumeID))
}

func ec2EBSEncryptionByDefaultResourceID(settings settings) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:ebs-encryption-by-default/default", settings.region, settings.accountID)
}

func s3AccessPointDetailARN(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.AccessPointArn)
}

func s3AccessPointDetailName(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.Name)
}

func s3AccessPointDetailAlias(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.Alias)
}

func s3AccessPointDetailBucket(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.Bucket)
}

func s3AccessPointDetailBucketAccount(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.BucketAccountId)
}

func s3AccessPointDetailDataSourceID(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.DataSourceId)
}

func s3AccessPointDetailDataSourceType(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return awssdk.ToString(detail.DataSourceType)
}

func s3AccessPointNetworkOrigin(detail *s3control.GetAccessPointOutput) string {
	if detail == nil {
		return ""
	}
	return string(detail.NetworkOrigin)
}

func s3AccessPointCreationDate(detail *s3control.GetAccessPointOutput) *time.Time {
	if detail == nil {
		return nil
	}
	return detail.CreationDate
}

func s3MultiRegionAccessPointRegions(regions []s3controltypes.RegionReport) []string {
	values := make([]string, 0, len(regions))
	for _, region := range regions {
		values = append(values, awssdk.ToString(region.Region))
	}
	return cleanStrings(values)
}

func s3MultiRegionAccessPointBuckets(regions []s3controltypes.RegionReport) []string {
	values := make([]string, 0, len(regions))
	for _, region := range regions {
		values = append(values, awssdk.ToString(region.Bucket))
	}
	return cleanStrings(values)
}

func ebsVolumeAttachmentInstanceIDs(attachments []ec2types.VolumeAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, awssdk.ToString(attachment.InstanceId))
	}
	return cleanStrings(values)
}

func ebsVolumeAttachmentStates(attachments []ec2types.VolumeAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, string(attachment.State))
	}
	return cleanStrings(values)
}

func s3ControlTagMap(tags []s3controltypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func dataSyncTagMap(tags []datasynctypes.TagListEntry) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func dataSyncInt64AttrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
