package workloadscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
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
	CopySnapshot(ctx context.Context, params *ec2.CopySnapshotInput, optFns ...func(*ec2.Options)) (*ec2.CopySnapshotOutput, error)
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	ModifySnapshotAttribute(ctx context.Context, params *ec2.ModifySnapshotAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error)
	CreateVolume(ctx context.Context, params *ec2.CreateVolumeInput, optFns ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	AttachVolume(ctx context.Context, params *ec2.AttachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(ctx context.Context, params *ec2.DetachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
	DeleteVolume(ctx context.Context, params *ec2.DeleteVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	DeleteSnapshot(ctx context.Context, params *ec2.DeleteSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

type awsKMSAPI interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CreateGrant(ctx context.Context, params *kms.CreateGrantInput, optFns ...func(*kms.Options)) (*kms.CreateGrantOutput, error)
}

type AWSProviderOptions struct {
	ShareKMSKeyID      string
	InspectionKMSKeyID string
	PollInterval       time.Duration
	Now                func() time.Time
}

type AWSProvider struct {
	sourceClient       awsEC2API
	inspectionClient   awsEC2API
	sourceKMS          awsKMSAPI
	shareKMSKeyID      string
	inspectionKMSKeyID string
	pollInterval       time.Duration
	now                func() time.Time
}

func NewAWSProvider(ctx context.Context, region string) (*AWSProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(strings.TrimSpace(region)))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return NewAWSProviderWithConfigs(cfg, cfg, AWSProviderOptions{}), nil
}

func NewAWSProviderWithConfigs(sourceCfg, inspectionCfg aws.Config, opts AWSProviderOptions) *AWSProvider {
	return NewAWSProviderWithClients(
		ec2.NewFromConfig(sourceCfg),
		ec2.NewFromConfig(inspectionCfg),
		kms.NewFromConfig(sourceCfg),
		opts,
	)
}

func NewAWSProviderWithClient(client awsEC2API) *AWSProvider {
	return NewAWSProviderWithClients(client, client, nil, AWSProviderOptions{})
}

func NewAWSProviderWithClients(sourceClient, inspectionClient awsEC2API, sourceKMS awsKMSAPI, opts AWSProviderOptions) *AWSProvider {
	if inspectionClient == nil {
		inspectionClient = sourceClient
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultAWSProviderPollInterval
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &AWSProvider{
		sourceClient:       sourceClient,
		inspectionClient:   inspectionClient,
		sourceKMS:          sourceKMS,
		shareKMSKeyID:      strings.TrimSpace(opts.ShareKMSKeyID),
		inspectionKMSKeyID: strings.TrimSpace(opts.InspectionKMSKeyID),
		pollInterval:       pollInterval,
		now:                nowFn,
	}
}

func (p *AWSProvider) Kind() ProviderKind { return ProviderAWS }

func (p *AWSProvider) MaxConcurrentAttachments() int {
	return len(awsAttachmentDeviceNames)
}

func (p *AWSProvider) InventoryVolumes(ctx context.Context, target VMTarget) ([]SourceVolume, error) {
	if p == nil || p.sourceClient == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	if strings.TrimSpace(target.InstanceID) == "" {
		return nil, fmt.Errorf("aws instance id is required")
	}
	resp, err := p.sourceClient.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
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
	volumesResp, err := p.sourceClient.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
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
	if p == nil || p.sourceClient == nil {
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
	resp, err := p.sourceClient.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
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
	readyAt, err := p.waitForSnapshotCompletedWithClient(ctx, p.sourceClient, snapshotID)
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
		Encrypted: volume.Encrypted,
		KMSKeyID:  strings.TrimSpace(volume.KMSKeyID),
		Scope:     SnapshotScopeSource,
		CreatedAt: createdAt,
		ReadyAt:   &readyAt,
		Metadata: map[string]any{
			"source_volume_id": volume.ID,
		},
	}, nil
}

func (p *AWSProvider) ShareSnapshot(ctx context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*SnapshotArtifact, error) {
	if p == nil || p.sourceClient == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	targetAccount := strings.TrimSpace(target.AccountID)
	scannerAccount := strings.TrimSpace(scannerHost.AccountID)
	if scannerAccount == "" || scannerAccount == targetAccount {
		shared := cloneSnapshotArtifact(snapshot)
		shared.Shared = true
		return &shared, nil
	}

	shareableSnapshot, err := p.prepareShareableSnapshot(ctx, target, snapshot)
	if err != nil {
		return nil, err
	}
	if shareableSnapshot.Encrypted {
		if err := p.createSnapshotGrant(ctx, shareableSnapshot.KMSKeyID, scannerAccount); err != nil {
			return nil, err
		}
	}
	if err := p.shareSnapshotWithAccount(ctx, shareableSnapshot.ID, scannerAccount); err != nil {
		return nil, err
	}
	shareableSnapshot.Shared = true
	if p.inspectionKMSKeyID == "" {
		return shareableSnapshot, nil
	}
	inspectionSnapshot, err := p.copySnapshotForInspection(ctx, shareableSnapshot, scannerHost)
	if err != nil {
		return nil, err
	}
	inspectionSnapshot.Shared = true
	return inspectionSnapshot, nil
}

func (p *AWSProvider) CreateInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	if p == nil || p.inspectionClient == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	if strings.TrimSpace(scannerHost.Zone) == "" {
		return nil, fmt.Errorf("aws scanner host zone is required to create inspection volume")
	}
	resp, err := p.inspectionClient.CreateVolume(ctx, &ec2.CreateVolumeInput{
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
	readyAt, err := p.waitForVolumeStateWithClient(ctx, p.inspectionClient, volumeID, ec2types.VolumeStateAvailable)
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
	if p == nil || p.inspectionClient == nil {
		return nil, fmt.Errorf("aws provider is not configured")
	}
	deviceName, err := deviceNameForIndex(index)
	if err != nil {
		return nil, err
	}
	if _, err := p.inspectionClient.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device:     aws.String(deviceName),
		InstanceId: aws.String(strings.TrimSpace(scannerHost.HostID)),
		VolumeId:   aws.String(strings.TrimSpace(volume.ID)),
	}); err != nil {
		return nil, fmt.Errorf("attach inspection volume %s to %s: %w", volume.ID, scannerHost.HostID, err)
	}
	attachedAt, err := p.waitForVolumeAttachmentWithClient(ctx, p.inspectionClient, volume.ID, scannerHost.HostID, ec2types.VolumeAttachmentStateAttached)
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
	if p == nil || p.inspectionClient == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	if _, err := p.inspectionClient.DetachVolume(ctx, &ec2.DetachVolumeInput{
		InstanceId: aws.String(strings.TrimSpace(attachment.HostID)),
		VolumeId:   aws.String(strings.TrimSpace(attachment.VolumeID)),
	}); err != nil && !isAWSNotFoundError(err, "InvalidVolume.NotFound") {
		return fmt.Errorf("detach inspection volume %s: %w", attachment.VolumeID, err)
	}
	_, err := p.waitForVolumeStateWithClient(ctx, p.inspectionClient, attachment.VolumeID, ec2types.VolumeStateAvailable)
	if err != nil && !isAWSNotFoundError(err, "InvalidVolume.NotFound") {
		return err
	}
	return nil
}

func (p *AWSProvider) DeleteInspectionVolume(ctx context.Context, volume InspectionVolume) error {
	if p == nil || p.inspectionClient == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	if _, err := p.inspectionClient.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: aws.String(strings.TrimSpace(volume.ID)),
	}); err != nil && !isAWSNotFoundError(err, "InvalidVolume.NotFound") {
		return fmt.Errorf("delete inspection volume %s: %w", volume.ID, err)
	}
	return nil
}

func (p *AWSProvider) DeleteSnapshot(ctx context.Context, snapshot SnapshotArtifact) error {
	if p == nil || p.sourceClient == nil {
		return fmt.Errorf("aws provider is not configured")
	}
	var deleteErrs []string
	for _, ref := range snapshotCleanupRefs(snapshot) {
		client := p.clientForSnapshotScope(ref.Scope)
		if client == nil {
			deleteErrs = append(deleteErrs, fmt.Sprintf("no aws client configured for snapshot scope %s", ref.Scope))
			continue
		}
		if _, err := client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
			SnapshotId: aws.String(strings.TrimSpace(ref.ID)),
		}); err != nil && !isAWSNotFoundError(err, "InvalidSnapshot.NotFound") {
			deleteErrs = append(deleteErrs, fmt.Sprintf("delete snapshot %s: %v", ref.ID, err))
		}
	}
	if len(deleteErrs) > 0 {
		return errors.New(strings.Join(deleteErrs, "; "))
	}
	return nil
}

func (p *AWSProvider) prepareShareableSnapshot(ctx context.Context, target VMTarget, snapshot SnapshotArtifact) (*SnapshotArtifact, error) {
	shareKeyID := strings.TrimSpace(p.shareKMSKeyID)
	if !snapshot.Encrypted {
		shared := cloneSnapshotArtifact(snapshot)
		return &shared, nil
	}
	if strings.TrimSpace(snapshot.KMSKeyID) == "" {
		return nil, fmt.Errorf("encrypted snapshot %s is missing source kms key metadata", snapshot.ID)
	}
	keyMetadata, err := p.describeKMSKey(ctx, snapshot.KMSKeyID)
	if err != nil {
		return nil, err
	}
	shareableSnapshot := cloneSnapshotArtifact(snapshot)
	if shareKeyID != "" && !strings.EqualFold(shareKeyID, snapshot.KMSKeyID) {
		shareKeyMetadata, err := p.describeKMSKey(ctx, shareKeyID)
		if err != nil {
			return nil, err
		}
		if shareKeyMetadata.KeyManager != kmstypes.KeyManagerTypeCustomer {
			return nil, fmt.Errorf("share kms key %s must be customer-managed for cross-account snapshot copies", shareKeyID)
		}
		copiedSnapshot, err := p.copySnapshotWithClient(ctx, p.sourceClient, snapshot, snapshotCopyOptions{
			KMSKeyID:  shareKeyID,
			AccountID: strings.TrimSpace(target.AccountID),
			Region:    strings.TrimSpace(target.Region),
			Scope:     SnapshotScopeSource,
			Reason:    "shareable",
		})
		if err != nil {
			return nil, err
		}
		copiedSnapshot.CleanupSnapshots = mergeSnapshotCleanupRefs(
			[]SnapshotCleanupRef{snapshotRef(*copiedSnapshot)},
			snapshotCleanupRefs(snapshot),
		)
		shareableSnapshot = *copiedSnapshot
	} else if keyMetadata.KeyManager == kmstypes.KeyManagerTypeAws {
		return nil, fmt.Errorf("snapshot %s uses an AWS-managed KMS key that cannot be shared cross-account; provide --share-kms-key-id with a customer-managed source-account key", snapshot.ID)
	}
	return &shareableSnapshot, nil
}

func (p *AWSProvider) createSnapshotGrant(ctx context.Context, keyID, scannerAccount string) error {
	if p == nil || p.sourceKMS == nil {
		return fmt.Errorf("aws source kms client is not configured")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return fmt.Errorf("encrypted cross-account snapshot is missing a kms key id")
	}
	scannerAccount = strings.TrimSpace(scannerAccount)
	if scannerAccount == "" {
		return fmt.Errorf("scanner aws account id is required for encrypted cross-account scans")
	}
	principalARN := fmt.Sprintf("arn:aws:iam::%s:root", scannerAccount)
	_, err := p.sourceKMS.CreateGrant(ctx, &kms.CreateGrantInput{
		KeyId:            aws.String(keyID),
		GranteePrincipal: aws.String(principalARN),
		Name:             aws.String("cerebro-workload-scan"),
		Operations: []kmstypes.GrantOperation{
			kmstypes.GrantOperationDecrypt,
			kmstypes.GrantOperationDescribeKey,
			kmstypes.GrantOperationReEncryptFrom,
			kmstypes.GrantOperationReEncryptTo,
			kmstypes.GrantOperationCreateGrant,
			kmstypes.GrantOperationGenerateDataKeyWithoutPlaintext,
		},
	})
	if err != nil {
		return fmt.Errorf("create kms grant for snapshot key %s and scanner account %s: %w", keyID, scannerAccount, err)
	}
	return nil
}

func (p *AWSProvider) shareSnapshotWithAccount(ctx context.Context, snapshotID, scannerAccount string) error {
	_, err := p.sourceClient.ModifySnapshotAttribute(ctx, &ec2.ModifySnapshotAttributeInput{
		SnapshotId: aws.String(strings.TrimSpace(snapshotID)),
		Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{
			Add: []ec2types.CreateVolumePermission{
				{UserId: aws.String(strings.TrimSpace(scannerAccount))},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("share snapshot %s with account %s: %w", snapshotID, scannerAccount, err)
	}
	return nil
}

func (p *AWSProvider) copySnapshotForInspection(ctx context.Context, snapshot *SnapshotArtifact, scannerHost ScannerHost) (*SnapshotArtifact, error) {
	if p == nil || p.inspectionClient == nil {
		return nil, fmt.Errorf("aws inspection client is not configured")
	}
	copiedSnapshot, err := p.copySnapshotWithClient(ctx, p.inspectionClient, *snapshot, snapshotCopyOptions{
		KMSKeyID:  p.inspectionKMSKeyID,
		AccountID: strings.TrimSpace(scannerHost.AccountID),
		Region:    strings.TrimSpace(scannerHost.Region),
		Scope:     SnapshotScopeInspection,
		Reason:    "inspection",
	})
	if err != nil {
		return nil, err
	}
	copiedSnapshot.CleanupSnapshots = mergeSnapshotCleanupRefs(
		[]SnapshotCleanupRef{snapshotRef(*copiedSnapshot)},
		snapshotCleanupRefs(*snapshot),
	)
	return copiedSnapshot, nil
}

type snapshotCopyOptions struct {
	KMSKeyID  string
	AccountID string
	Region    string
	Scope     SnapshotScope
	Reason    string
}

func (p *AWSProvider) copySnapshotWithClient(ctx context.Context, client awsEC2API, snapshot SnapshotArtifact, opts snapshotCopyOptions) (*SnapshotArtifact, error) {
	if client == nil {
		return nil, fmt.Errorf("aws snapshot copy client is not configured")
	}
	description := "Cerebro workload scan snapshot copy"
	if reason := strings.TrimSpace(opts.Reason); reason != "" {
		description = fmt.Sprintf("Cerebro workload scan %s snapshot copy", reason)
	}
	resp, err := client.CopySnapshot(ctx, &ec2.CopySnapshotInput{
		Description:      aws.String(description),
		Encrypted:        aws.Bool(true),
		KmsKeyId:         aws.String(strings.TrimSpace(opts.KMSKeyID)),
		SourceRegion:     aws.String(strings.TrimSpace(snapshot.Region)),
		SourceSnapshotId: aws.String(strings.TrimSpace(snapshot.ID)),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSnapshot,
				Tags: []ec2types.Tag{
					{Key: aws.String("cerebro-scan"), Value: aws.String("true")},
					{Key: aws.String("cerebro-source-snapshot-id"), Value: aws.String(strings.TrimSpace(snapshot.ID))},
					{Key: aws.String("cerebro-volume-id"), Value: aws.String(strings.TrimSpace(snapshot.VolumeID))},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("copy snapshot %s: %w", snapshot.ID, err)
	}
	snapshotID := strings.TrimSpace(aws.ToString(resp.SnapshotId))
	if snapshotID == "" {
		return nil, fmt.Errorf("aws copy snapshot returned empty snapshot id for %s", snapshot.ID)
	}
	readyAt, err := p.waitForSnapshotCompletedWithClient(ctx, client, snapshotID)
	if err != nil {
		return nil, err
	}
	createdAt := p.now().UTC()
	copiedSnapshot := &SnapshotArtifact{
		ID:        snapshotID,
		VolumeID:  snapshot.VolumeID,
		AccountID: strings.TrimSpace(opts.AccountID),
		Region:    firstNonEmpty(strings.TrimSpace(opts.Region), strings.TrimSpace(snapshot.Region)),
		Zone:      strings.TrimSpace(snapshot.Zone),
		SizeGiB:   snapshot.SizeGiB,
		Encrypted: true,
		KMSKeyID:  strings.TrimSpace(opts.KMSKeyID),
		Scope:     opts.Scope,
		CreatedAt: createdAt,
		ReadyAt:   &readyAt,
		Metadata: map[string]any{
			"source_snapshot_id": snapshot.ID,
		},
	}
	return copiedSnapshot, nil
}

func (p *AWSProvider) describeKMSKey(ctx context.Context, keyID string) (*kmstypes.KeyMetadata, error) {
	if p == nil || p.sourceKMS == nil {
		return nil, fmt.Errorf("aws source kms client is not configured")
	}
	resp, err := p.sourceKMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(strings.TrimSpace(keyID))})
	if err != nil {
		return nil, fmt.Errorf("describe kms key %s: %w", keyID, err)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return nil, fmt.Errorf("kms key %s not found", keyID)
	}
	return resp.KeyMetadata, nil
}

func (p *AWSProvider) waitForSnapshotCompleted(ctx context.Context, snapshotID string) (time.Time, error) {
	return p.waitForSnapshotCompletedWithClient(ctx, p.sourceClient, snapshotID)
}

func (p *AWSProvider) waitForSnapshotCompletedWithClient(ctx context.Context, client awsEC2API, snapshotID string) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
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

func (p *AWSProvider) waitForVolumeStateWithClient(ctx context.Context, client awsEC2API, volumeID string, state ec2types.VolumeState) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
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

func (p *AWSProvider) waitForVolumeAttachmentWithClient(ctx context.Context, client awsEC2API, volumeID, instanceID string, state ec2types.VolumeAttachmentState) (time.Time, error) {
	ticker := time.NewTicker(p.effectivePollInterval())
	defer ticker.Stop()
	for {
		resp, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
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

func (p *AWSProvider) clientForSnapshotScope(scope SnapshotScope) awsEC2API {
	switch scope {
	case SnapshotScopeInspection:
		if p.inspectionClient != nil {
			return p.inspectionClient
		}
	}
	return p.sourceClient
}

func (p *AWSProvider) effectivePollInterval() time.Duration {
	if p == nil || p.pollInterval <= 0 {
		return defaultAWSProviderPollInterval
	}
	return p.pollInterval
}

func cloneSnapshotArtifact(snapshot SnapshotArtifact) SnapshotArtifact {
	cloned := snapshot
	cloned.Metadata = cloneAnyMap(snapshot.Metadata)
	cloned.CleanupSnapshots = append([]SnapshotCleanupRef(nil), snapshot.CleanupSnapshots...)
	return cloned
}

func snapshotCleanupRefs(snapshot SnapshotArtifact) []SnapshotCleanupRef {
	if len(snapshot.CleanupSnapshots) > 0 {
		return mergeSnapshotCleanupRefs(nil, snapshot.CleanupSnapshots)
	}
	return []SnapshotCleanupRef{snapshotRef(snapshot)}
}

func snapshotRef(snapshot SnapshotArtifact) SnapshotCleanupRef {
	scope := snapshot.Scope
	if scope == "" {
		scope = SnapshotScopeSource
	}
	return SnapshotCleanupRef{
		ID:        strings.TrimSpace(snapshot.ID),
		Scope:     scope,
		AccountID: strings.TrimSpace(snapshot.AccountID),
		Region:    strings.TrimSpace(snapshot.Region),
	}
}

func mergeSnapshotCleanupRefs(base []SnapshotCleanupRef, others []SnapshotCleanupRef) []SnapshotCleanupRef {
	merged := make([]SnapshotCleanupRef, 0, len(base)+len(others))
	seen := make(map[string]struct{}, len(base)+len(others))
	appendRef := func(ref SnapshotCleanupRef) {
		ref.ID = strings.TrimSpace(ref.ID)
		if ref.ID == "" {
			return
		}
		if ref.Scope == "" {
			ref.Scope = SnapshotScopeSource
		}
		key := string(ref.Scope) + ":" + ref.ID
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, ref)
	}
	for _, ref := range base {
		appendRef(ref)
	}
	for _, ref := range others {
		appendRef(ref)
	}
	return merged
}

func isAWSNotFoundError(err error, codes ...string) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	for _, code := range codes {
		if strings.EqualFold(strings.TrimSpace(apiErr.ErrorCode()), strings.TrimSpace(code)) {
			return true
		}
	}
	return false
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
