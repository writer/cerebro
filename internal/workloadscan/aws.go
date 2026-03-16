package workloadscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const defaultAWSProviderPollInterval = 5 * time.Second

var awsAttachmentDeviceNames = []string{
	"/dev/sdf",
	"/dev/sdg",
	"/dev/sdh",
	"/dev/sdi",
	"/dev/sdj",
	"/dev/sdk",
	"/dev/sdl",
	"/dev/sdm",
	"/dev/sdn",
	"/dev/sdo",
	"/dev/sdp",
	"/dev/sdq",
	"/dev/sdr",
	"/dev/sds",
	"/dev/sdt",
	"/dev/sdu",
	"/dev/sdv",
	"/dev/sdw",
	"/dev/sdx",
	"/dev/sdy",
	"/dev/sdz",
}

type awsEC2API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	CreateSnapshot(ctx context.Context, params *ec2.CreateSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error)
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	ModifySnapshotAttribute(ctx context.Context, params *ec2.ModifySnapshotAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error)
	CreateVolume(ctx context.Context, params *ec2.CreateVolumeInput, optFns ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	AttachVolume(ctx context.Context, params *ec2.AttachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(ctx context.Context, params *ec2.DetachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
	DeleteVolume(ctx context.Context, params *ec2.DeleteVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	DeleteSnapshot(ctx context.Context, params *ec2.DeleteSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

type AWSProvider struct {
	client       awsEC2API
	pollInterval time.Duration
	now          func() time.Time
}

func NewAWSProvider(ctx context.Context, region string) (*AWSProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(strings.TrimSpace(region)))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return NewAWSProviderWithClient(ec2.NewFromConfig(cfg)), nil
}

func NewAWSProviderWithClient(client awsEC2API) *AWSProvider {
	return &AWSProvider{
		client:       client,
		pollInterval: defaultAWSProviderPollInterval,
		now:          time.Now,
	}
}

func (p *AWSProvider) Kind() ProviderKind { return ProviderAWS }

func (p *AWSProvider) MaxConcurrentAttachments() int {
	return len(awsAttachmentDeviceNames)
}

func (p *AWSProvider) InventoryVolumes(ctx context.Context, target VMTarget) ([]SourceVolume, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	if strings.TrimSpace(target.InstanceID) == "" {
		return nil, fmt.Errorf("aws instance id is required")
	}
	resp, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{strings.TrimSpace(target.InstanceID)},
	})
	if err != nil {
		return nil, fmt.Errorf("describe instance %s: %w", target.InstanceID, err)
	}
	var instance *ec2types.Instance
	for _, reservation := range resp.Reservations {
		for i := range reservation.Instances {
			if aws.ToString(reservation.Instances[i].InstanceId) == target.InstanceID {
				instance = &reservation.Instances[i]
				break
			}
		}
	}
	if instance == nil {
		return nil, fmt.Errorf("aws instance not found: %s", target.InstanceID)
	}
	volumeIDs := make([]string, 0, len(instance.BlockDeviceMappings))
	deviceNames := make(map[string]string, len(instance.BlockDeviceMappings))
	for _, mapping := range instance.BlockDeviceMappings {
		volumeID := strings.TrimSpace(aws.ToString(mapping.Ebs.VolumeId))
		if volumeID == "" {
			continue
		}
		volumeIDs = append(volumeIDs, volumeID)
		deviceNames[volumeID] = strings.TrimSpace(aws.ToString(mapping.DeviceName))
	}
	if len(volumeIDs) == 0 {
		return nil, nil
	}
	volumesResp, err := p.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: volumeIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("describe volumes for %s: %w", target.InstanceID, err)
	}
	rootDevice := strings.TrimSpace(aws.ToString(instance.RootDeviceName))
	volumes := make([]SourceVolume, 0, len(volumesResp.Volumes))
	for _, volume := range volumesResp.Volumes {
		volumeID := strings.TrimSpace(aws.ToString(volume.VolumeId))
		deviceName := deviceNames[volumeID]
		volumes = append(volumes, SourceVolume{
			ID:         volumeID,
			Name:       volumeNameTag(volume.Tags),
			DeviceName: deviceName,
			Region:     strings.TrimSpace(target.Region),
			Zone:       strings.TrimSpace(aws.ToString(volume.AvailabilityZone)),
			SizeGiB:    int64(aws.ToInt32(volume.Size)),
			Encrypted:  aws.ToBool(volume.Encrypted),
			KMSKeyID:   strings.TrimSpace(aws.ToString(volume.KmsKeyId)),
			Boot:       rootDevice != "" && deviceName == rootDevice,
			Metadata: map[string]any{
				"state":                 string(volume.State),
				"instance_id":           target.InstanceID,
				"delete_on_termination": deleteOnTermination(instance.BlockDeviceMappings, volumeID),
			},
		})
	}
	return volumes, nil
}

func (p *AWSProvider) CreateSnapshot(ctx context.Context, target VMTarget, volume SourceVolume, metadata map[string]string) (*SnapshotArtifact, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	tags := []ec2types.Tag{
		{Key: aws.String("cerebro-scan"), Value: aws.String("true")},
		{Key: aws.String("cerebro-target-id"), Value: aws.String(strings.TrimSpace(target.InstanceID))},
		{Key: aws.String("cerebro-volume-id"), Value: aws.String(strings.TrimSpace(volume.ID))},
	}
	for key, value := range metadata {
		key = strings.TrimSpace(key)
		if key == "" || strings.TrimSpace(value) == "" {
			continue
		}
		tags = append(tags, ec2types.Tag{Key: aws.String("cerebro-meta-" + key), Value: aws.String(value)})
	}
	resp, err := p.client.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    aws.String(strings.TrimSpace(volume.ID)),
		Description: aws.String("Cerebro workload scan snapshot for " + target.InstanceID),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSnapshot,
				Tags:         tags,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create snapshot for %s: %w", volume.ID, err)
	}
	snapshotID := strings.TrimSpace(aws.ToString(resp.SnapshotId))
	if snapshotID == "" {
		return nil, fmt.Errorf("aws create snapshot returned empty snapshot id for %s", volume.ID)
	}
	readyAt, err := p.waitForSnapshotCompleted(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	createdAt := p.now().UTC()
	if resp.StartTime != nil && !resp.StartTime.IsZero() {
		createdAt = resp.StartTime.UTC()
	}
	return &SnapshotArtifact{
		ID:        snapshotID,
		VolumeID:  volume.ID,
		AccountID: strings.TrimSpace(target.AccountID),
		Region:    strings.TrimSpace(target.Region),
		Zone:      strings.TrimSpace(volume.Zone),
		SizeGiB:   volume.SizeGiB,
		CreatedAt: createdAt,
		ReadyAt:   &readyAt,
		Metadata: map[string]any{
			"source_volume_id": volume.ID,
		},
	}, nil
}

func (p *AWSProvider) ShareSnapshot(ctx context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	targetAccount := strings.TrimSpace(target.AccountID)
	scannerAccount := strings.TrimSpace(scannerHost.AccountID)
	if scannerAccount == "" || scannerAccount == targetAccount {
		return nil
	}
	_, err := p.client.ModifySnapshotAttribute(ctx, &ec2.ModifySnapshotAttributeInput{
		SnapshotId: aws.String(strings.TrimSpace(snapshot.ID)),
		Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{
			Add: []ec2types.CreateVolumePermission{
				{UserId: aws.String(scannerAccount)},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("share snapshot %s with account %s: %w", snapshot.ID, scannerAccount, err)
	}
	return nil
}

func (p *AWSProvider) CreateInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	if strings.TrimSpace(scannerHost.Zone) == "" {
		return nil, fmt.Errorf("aws scanner host zone is required to create inspection volume")
	}
	resp, err := p.client.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(strings.TrimSpace(scannerHost.Zone)),
		SnapshotId:       aws.String(strings.TrimSpace(snapshot.ID)),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeVolume,
				Tags: []ec2types.Tag{
					{Key: aws.String("cerebro-scan"), Value: aws.String("true")},
					{Key: aws.String("cerebro-snapshot-id"), Value: aws.String(strings.TrimSpace(snapshot.ID))},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create inspection volume from snapshot %s: %w", snapshot.ID, err)
	}
	volumeID := strings.TrimSpace(aws.ToString(resp.VolumeId))
	if volumeID == "" {
		return nil, fmt.Errorf("aws create volume returned empty volume id for snapshot %s", snapshot.ID)
	}
	readyAt, err := p.waitForVolumeState(ctx, volumeID, ec2types.VolumeStateAvailable)
	if err != nil {
		return nil, err
	}
	createdAt := p.now().UTC()
	if resp.CreateTime != nil && !resp.CreateTime.IsZero() {
		createdAt = resp.CreateTime.UTC()
	}
	return &InspectionVolume{
		ID:         volumeID,
		SnapshotID: snapshot.ID,
		Region:     strings.TrimSpace(scannerHost.Region),
		Zone:       strings.TrimSpace(scannerHost.Zone),
		SizeGiB:    int64(aws.ToInt32(resp.Size)),
		CreatedAt:  createdAt,
		ReadyAt:    &readyAt,
	}, nil
}

func (p *AWSProvider) AttachInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, volume InspectionVolume, index int) (*VolumeAttachment, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	deviceName, err := deviceNameForIndex(index)
	if err != nil {
		return nil, err
	}
	if _, err := p.client.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device:     aws.String(deviceName),
		InstanceId: aws.String(strings.TrimSpace(scannerHost.HostID)),
		VolumeId:   aws.String(strings.TrimSpace(volume.ID)),
	}); err != nil {
		return nil, fmt.Errorf("attach inspection volume %s to %s: %w", volume.ID, scannerHost.HostID, err)
	}
	attachedAt, err := p.waitForVolumeAttachment(ctx, volume.ID, scannerHost.HostID, ec2types.VolumeAttachmentStateAttached)
	if err != nil {
		return nil, err
	}
	return &VolumeAttachment{
		VolumeID:   volume.ID,
		HostID:     scannerHost.HostID,
		DeviceName: deviceName,
		ReadOnly:   true,
		AttachedAt: attachedAt,
	}, nil
}

func (p *AWSProvider) DetachInspectionVolume(ctx context.Context, attachment VolumeAttachment) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	if _, err := p.client.DetachVolume(ctx, &ec2.DetachVolumeInput{
		InstanceId: aws.String(strings.TrimSpace(attachment.HostID)),
		VolumeId:   aws.String(strings.TrimSpace(attachment.VolumeID)),
	}); err != nil {
		return fmt.Errorf("detach inspection volume %s: %w", attachment.VolumeID, err)
	}
	_, err := p.waitForVolumeState(ctx, attachment.VolumeID, ec2types.VolumeStateAvailable)
	return err
}

func (p *AWSProvider) DeleteInspectionVolume(ctx context.Context, volume InspectionVolume) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	if _, err := p.client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: aws.String(strings.TrimSpace(volume.ID)),
	}); err != nil {
		return fmt.Errorf("delete inspection volume %s: %w", volume.ID, err)
	}
	return nil
}

func (p *AWSProvider) DeleteSnapshot(ctx context.Context, snapshot SnapshotArtifact) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	if _, err := p.client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: aws.String(strings.TrimSpace(snapshot.ID)),
	}); err != nil {
		return fmt.Errorf("delete snapshot %s: %w", snapshot.ID, err)
	}
	return nil
}

func (p *AWSProvider) waitForSnapshotCompleted(ctx context.Context, snapshotID string) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := p.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			SnapshotIds: []string{strings.TrimSpace(snapshotID)},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("describe snapshot %s: %w", snapshotID, err)
		}
		if len(resp.Snapshots) == 0 {
			return time.Time{}, fmt.Errorf("snapshot not found: %s", snapshotID)
		}
		snapshot := resp.Snapshots[0]
		switch snapshot.State {
		case ec2types.SnapshotStateCompleted:
			if snapshot.CompletionTime != nil && !snapshot.CompletionTime.IsZero() {
				return snapshot.CompletionTime.UTC(), nil
			}
			if snapshot.StartTime != nil && !snapshot.StartTime.IsZero() {
				return snapshot.StartTime.UTC(), nil
			}
			return p.now().UTC(), nil
		case ec2types.SnapshotStateError:
			return time.Time{}, fmt.Errorf("snapshot %s entered error state", snapshotID)
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *AWSProvider) waitForVolumeState(ctx context.Context, volumeID string, state ec2types.VolumeState) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := p.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			VolumeIds: []string{strings.TrimSpace(volumeID)},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("describe volume %s: %w", volumeID, err)
		}
		if len(resp.Volumes) == 0 {
			return time.Time{}, fmt.Errorf("volume not found: %s", volumeID)
		}
		volume := resp.Volumes[0]
		if volume.State == state {
			if volume.CreateTime != nil && !volume.CreateTime.IsZero() {
				return volume.CreateTime.UTC(), nil
			}
			return p.now().UTC(), nil
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *AWSProvider) waitForVolumeAttachment(ctx context.Context, volumeID, instanceID string, state ec2types.VolumeAttachmentState) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := p.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			VolumeIds: []string{strings.TrimSpace(volumeID)},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("describe attachment volume %s: %w", volumeID, err)
		}
		if len(resp.Volumes) == 0 {
			return time.Time{}, fmt.Errorf("volume not found: %s", volumeID)
		}
		for _, attachment := range resp.Volumes[0].Attachments {
			if strings.TrimSpace(aws.ToString(attachment.InstanceId)) == strings.TrimSpace(instanceID) && attachment.State == state {
				if attachment.AttachTime != nil && !attachment.AttachTime.IsZero() {
					return attachment.AttachTime.UTC(), nil
				}
				return p.now().UTC(), nil
			}
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *AWSProvider) effectivePollInterval() time.Duration {
	if p == nil || p.pollInterval <= 0 {
		return defaultAWSProviderPollInterval
	}
	return p.pollInterval
}

func volumeNameTag(tags []ec2types.Tag) string {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(aws.ToString(tag.Key)), "Name") {
			return strings.TrimSpace(aws.ToString(tag.Value))
		}
	}
	return ""
}

func deleteOnTermination(mappings []ec2types.InstanceBlockDeviceMapping, volumeID string) bool {
	for _, mapping := range mappings {
		if strings.TrimSpace(aws.ToString(mapping.Ebs.VolumeId)) == strings.TrimSpace(volumeID) {
			return aws.ToBool(mapping.Ebs.DeleteOnTermination)
		}
	}
	return false
}

func deviceNameForIndex(index int) (string, error) {
	if index < 0 {
		index = 0
	}
	if index >= len(awsAttachmentDeviceNames) {
		return "", fmt.Errorf("aws attachment slot %d exceeds supported device count %d", index, len(awsAttachmentDeviceNames))
	}
	return awsAttachmentDeviceNames[index], nil
}
