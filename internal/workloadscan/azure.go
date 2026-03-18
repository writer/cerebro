package workloadscan

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
)

const azureMaxDataDiskLUN = 63

type AzureProvider struct {
	credential azcore.TokenCredential
	now        func() time.Time
}

func NewAzureProvider() (*AzureProvider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure credential: %w", err)
	}
	return NewAzureProviderWithCredential(cred), nil
}

func NewAzureProviderWithCredential(credential azcore.TokenCredential) *AzureProvider {
	return &AzureProvider{credential: credential, now: time.Now}
}

func (p *AzureProvider) Kind() ProviderKind { return ProviderAzure }

func (p *AzureProvider) MaxConcurrentAttachments() int { return azureMaxDataDiskLUN + 1 }

func (p *AzureProvider) InventoryVolumes(ctx context.Context, target VMTarget) ([]SourceVolume, error) {
	if p == nil || p.credential == nil {
		return nil, fmt.Errorf("azure provider is not configured")
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(strings.TrimSpace(target.SubscriptionID), p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure vm client: %w", err)
	}
	diskClient, err := armcompute.NewDisksClient(strings.TrimSpace(target.SubscriptionID), p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure disks client: %w", err)
	}
	vm, err := vmClient.Get(ctx, strings.TrimSpace(target.ResourceGroup), strings.TrimSpace(target.InstanceName), nil)
	if err != nil {
		return nil, fmt.Errorf("get azure vm %s: %w", target.InstanceName, err)
	}
	if vm.Properties == nil || vm.Properties.StorageProfile == nil {
		return nil, nil
	}

	volumes := make([]SourceVolume, 0, 1+len(vm.Properties.StorageProfile.DataDisks))
	if osDisk := vm.Properties.StorageProfile.OSDisk; osDisk != nil && osDisk.ManagedDisk != nil && strings.TrimSpace(ptrString(osDisk.ManagedDisk.ID)) != "" {
		volume, err := p.azureSourceVolume(ctx, diskClient, target, ptrString(osDisk.ManagedDisk.ID), ptrString(osDisk.Name), true, "")
		if err != nil {
			return nil, err
		}
		volume.DeviceName = firstNonEmpty(volume.DeviceName, ptrString(osDisk.Name))
		volumes = append(volumes, volume)
	}
	for _, dataDisk := range vm.Properties.StorageProfile.DataDisks {
		if dataDisk == nil || dataDisk.ManagedDisk == nil || strings.TrimSpace(ptrString(dataDisk.ManagedDisk.ID)) == "" {
			continue
		}
		devicePath := ""
		if dataDisk.Lun != nil {
			devicePath = azureLUNDevicePath(*dataDisk.Lun)
		}
		volume, err := p.azureSourceVolume(ctx, diskClient, target, ptrString(dataDisk.ManagedDisk.ID), ptrString(dataDisk.Name), false, devicePath)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

func (p *AzureProvider) CreateSnapshot(ctx context.Context, target VMTarget, volume SourceVolume, metadata map[string]string) (*SnapshotArtifact, error) {
	if p == nil || p.credential == nil {
		return nil, fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := strings.TrimSpace(target.SubscriptionID)
	resourceGroup := strings.TrimSpace(target.ResourceGroup)
	snapshotName := azureWorkloadResourceName("snapshot", volume.ID, p.now())
	snapshotsClient, err := armcompute.NewSnapshotsClient(subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure snapshots client: %w", err)
	}
	poller, err := snapshotsClient.BeginCreateOrUpdate(ctx, resourceGroup, snapshotName, armcompute.Snapshot{
		Location: stringPtr(strings.TrimSpace(target.Region)),
		Properties: &armcompute.SnapshotProperties{
			CreationData: &armcompute.CreationData{
				CreateOption:     diskCreateOptionPtr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: stringPtr(volumeSourceID(volume)),
			},
		},
		Tags: azureTags(metadata, volume.ID),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure snapshot for %s: %w", volume.ID, err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return nil, fmt.Errorf("wait for azure snapshot %s: %w", snapshotName, err)
	}
	snapshotResp, err := snapshotsClient.Get(ctx, resourceGroup, snapshotName, nil)
	if err != nil {
		return nil, fmt.Errorf("get azure snapshot %s: %w", snapshotName, err)
	}
	createdAt := p.now().UTC()
	if snapshotResp.Properties != nil && snapshotResp.Properties.TimeCreated != nil {
		createdAt = snapshotResp.Properties.TimeCreated.UTC()
	}
	readyAt := p.now().UTC()
	return &SnapshotArtifact{
		ID:        snapshotName,
		VolumeID:  volume.ID,
		Region:    strings.TrimSpace(target.Region),
		SizeGiB:   volume.SizeGiB,
		CreatedAt: createdAt,
		ReadyAt:   &readyAt,
		Metadata: map[string]any{
			"snapshot_name":    snapshotName,
			"resource_group":   resourceGroup,
			"subscription_id":  subscriptionID,
			"snapshot_id":      ptrString(snapshotResp.ID),
			"source_disk_id":   volumeSourceID(volume),
			"source_volume_id": volume.ID,
		},
	}, nil
}

func (p *AzureProvider) ShareSnapshot(_ context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*SnapshotArtifact, error) {
	targetSub := strings.TrimSpace(target.SubscriptionID)
	scannerSub := firstNonEmpty(strings.TrimSpace(scannerHost.SubscriptionID), targetSub)
	if scannerSub == "" || scannerSub == targetSub {
		return &snapshot, nil
	}
	return nil, fmt.Errorf("cross-subscription azure workload scans are not supported by this runner")
}

func (p *AzureProvider) CreateInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	if p == nil || p.credential == nil {
		return nil, fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := firstNonEmpty(strings.TrimSpace(scannerHost.SubscriptionID), stringMetadata(snapshot.Metadata, "subscription_id"))
	resourceGroup := strings.TrimSpace(scannerHost.ResourceGroup)
	if subscriptionID == "" || resourceGroup == "" {
		return nil, fmt.Errorf("azure scanner host subscription and resource group are required")
	}
	diskName := azureWorkloadResourceName("disk", snapshot.VolumeID, p.now())
	disksClient, err := armcompute.NewDisksClient(subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure disks client: %w", err)
	}
	poller, err := disksClient.BeginCreateOrUpdate(ctx, resourceGroup, diskName, armcompute.Disk{
		Location: stringPtr(strings.TrimSpace(scannerHost.Region)),
		Properties: &armcompute.DiskProperties{
			CreationData: &armcompute.CreationData{
				CreateOption:     diskCreateOptionPtr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: stringPtr(stringMetadata(snapshot.Metadata, "snapshot_id")),
			},
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure inspection disk from snapshot %s: %w", snapshot.ID, err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return nil, fmt.Errorf("wait for azure inspection disk %s: %w", diskName, err)
	}
	diskResp, err := disksClient.Get(ctx, resourceGroup, diskName, nil)
	if err != nil {
		return nil, fmt.Errorf("get azure inspection disk %s: %w", diskName, err)
	}
	createdAt := p.now().UTC()
	if diskResp.Properties != nil && diskResp.Properties.TimeCreated != nil {
		createdAt = diskResp.Properties.TimeCreated.UTC()
	}
	readyAt := p.now().UTC()
	return &InspectionVolume{
		ID:         diskName,
		SnapshotID: snapshot.ID,
		Region:     strings.TrimSpace(scannerHost.Region),
		SizeGiB:    diskSizeGiBFromAzure(diskResp.Properties),
		CreatedAt:  createdAt,
		ReadyAt:    &readyAt,
		Metadata: map[string]any{
			"disk_name":       diskName,
			"disk_id":         ptrString(diskResp.ID),
			"resource_group":  resourceGroup,
			"subscription_id": subscriptionID,
		},
	}, nil
}

func (p *AzureProvider) AttachInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, volume InspectionVolume, _ int) (*VolumeAttachment, error) {
	if p == nil || p.credential == nil {
		return nil, fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := firstNonEmpty(strings.TrimSpace(scannerHost.SubscriptionID), stringMetadata(volume.Metadata, "subscription_id"))
	resourceGroup := strings.TrimSpace(scannerHost.ResourceGroup)
	if subscriptionID == "" || resourceGroup == "" {
		return nil, fmt.Errorf("azure scanner host subscription and resource group are required")
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure vm client: %w", err)
	}
	vm, err := vmClient.Get(ctx, resourceGroup, strings.TrimSpace(scannerHost.HostID), nil)
	if err != nil {
		return nil, fmt.Errorf("get azure scanner vm %s: %w", scannerHost.HostID, err)
	}
	if vm.Properties == nil || vm.Properties.StorageProfile == nil {
		return nil, fmt.Errorf("azure scanner vm %s has no storage profile", scannerHost.HostID)
	}
	dataDisks := cloneAzureDataDisks(vm.Properties.StorageProfile.DataDisks)
	lun, err := nextAzureLUN(dataDisks)
	if err != nil {
		return nil, err
	}
	dataDisks = append(dataDisks, &armcompute.DataDisk{
		CreateOption: diskCreateOptionTypesPtr(armcompute.DiskCreateOptionTypesAttach),
		Lun:          int32Ptr(lun),
		Caching:      cachingTypePtr(armcompute.CachingTypesReadOnly),
		Name:         stringPtr(strings.TrimSpace(volume.ID)),
		ManagedDisk: &armcompute.ManagedDiskParameters{
			ID: stringPtr(stringMetadata(volume.Metadata, "disk_id")),
		},
	})
	poller, err := vmClient.BeginUpdate(ctx, resourceGroup, strings.TrimSpace(scannerHost.HostID), armcompute.VirtualMachineUpdate{
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				OSDisk:         vm.Properties.StorageProfile.OSDisk,
				ImageReference: vm.Properties.StorageProfile.ImageReference,
				DataDisks:      dataDisks,
			},
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("attach azure inspection disk %s to %s: %w", volume.ID, scannerHost.HostID, err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return nil, fmt.Errorf("wait for azure disk attachment %s: %w", volume.ID, err)
	}
	attachedAt := p.now().UTC()
	return &VolumeAttachment{
		VolumeID:   volume.ID,
		HostID:     scannerHost.HostID,
		DeviceName: azureLUNDevicePath(lun),
		ReadOnly:   true,
		AttachedAt: attachedAt,
		Metadata: map[string]any{
			"lun":             strconv.Itoa(int(lun)),
			"resource_group":  resourceGroup,
			"subscription_id": subscriptionID,
		},
	}, nil
}

func (p *AzureProvider) DetachInspectionVolume(ctx context.Context, attachment VolumeAttachment) error {
	if p == nil || p.credential == nil {
		return fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := stringMetadata(attachment.Metadata, "subscription_id")
	resourceGroup := stringMetadata(attachment.Metadata, "resource_group")
	if subscriptionID == "" || resourceGroup == "" {
		return fmt.Errorf("azure attachment metadata is incomplete")
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("create azure vm client: %w", err)
	}
	vm, err := vmClient.Get(ctx, resourceGroup, strings.TrimSpace(attachment.HostID), nil)
	if err != nil {
		return fmt.Errorf("get azure scanner vm %s: %w", attachment.HostID, err)
	}
	if vm.Properties == nil || vm.Properties.StorageProfile == nil {
		return fmt.Errorf("azure scanner vm %s has no storage profile", attachment.HostID)
	}
	filtered := make([]*armcompute.DataDisk, 0, len(vm.Properties.StorageProfile.DataDisks))
	for _, disk := range vm.Properties.StorageProfile.DataDisks {
		if disk == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(ptrString(disk.Name)), strings.TrimSpace(attachment.VolumeID)) {
			continue
		}
		filtered = append(filtered, disk)
	}
	poller, err := vmClient.BeginUpdate(ctx, resourceGroup, strings.TrimSpace(attachment.HostID), armcompute.VirtualMachineUpdate{
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				OSDisk:         vm.Properties.StorageProfile.OSDisk,
				ImageReference: vm.Properties.StorageProfile.ImageReference,
				DataDisks:      filtered,
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("detach azure inspection disk %s: %w", attachment.VolumeID, err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("wait for azure disk detach %s: %w", attachment.VolumeID, err)
	}
	return nil
}

func (p *AzureProvider) DeleteInspectionVolume(ctx context.Context, volume InspectionVolume) error {
	if p == nil || p.credential == nil {
		return fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := stringMetadata(volume.Metadata, "subscription_id")
	resourceGroup := stringMetadata(volume.Metadata, "resource_group")
	diskName := firstNonEmpty(stringMetadata(volume.Metadata, "disk_name"), strings.TrimSpace(volume.ID))
	disksClient, err := armcompute.NewDisksClient(subscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("create azure disks client: %w", err)
	}
	poller, err := disksClient.BeginDelete(ctx, resourceGroup, diskName, nil)
	if err != nil {
		return fmt.Errorf("delete azure inspection disk %s: %w", diskName, err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("wait for azure disk delete %s: %w", diskName, err)
	}
	return nil
}

func (p *AzureProvider) DeleteSnapshot(ctx context.Context, snapshot SnapshotArtifact) error {
	if p == nil || p.credential == nil {
		return fmt.Errorf("azure provider is not configured")
	}
	subscriptionID := stringMetadata(snapshot.Metadata, "subscription_id")
	resourceGroup := stringMetadata(snapshot.Metadata, "resource_group")
	snapshotName := firstNonEmpty(stringMetadata(snapshot.Metadata, "snapshot_name"), strings.TrimSpace(snapshot.ID))
	snapshotsClient, err := armcompute.NewSnapshotsClient(subscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("create azure snapshots client: %w", err)
	}
	poller, err := snapshotsClient.BeginDelete(ctx, resourceGroup, snapshotName, nil)
	if err != nil {
		return fmt.Errorf("delete azure snapshot %s: %w", snapshotName, err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("wait for azure snapshot delete %s: %w", snapshotName, err)
	}
	return nil
}

func (p *AzureProvider) azureSourceVolume(ctx context.Context, diskClient *armcompute.DisksClient, target VMTarget, diskID, fallbackName string, boot bool, devicePath string) (SourceVolume, error) {
	diskName := resourceName(diskID)
	if diskName == "" {
		diskName = strings.TrimSpace(fallbackName)
	}
	resourceGroup := resourceGroupFromID(diskID)
	diskResp, err := diskClient.Get(ctx, resourceGroup, diskName, nil)
	if err != nil {
		return SourceVolume{}, fmt.Errorf("get azure disk %s: %w", diskName, err)
	}
	volume := SourceVolume{
		ID:         diskName,
		Name:       diskName,
		DeviceName: devicePath,
		Region:     strings.TrimSpace(target.Region),
		SizeGiB:    diskSizeGiBFromAzure(diskResp.Properties),
		Encrypted:  diskResp.Properties != nil && (diskResp.Properties.Encryption != nil || diskResp.Properties.EncryptionSettingsCollection != nil),
		Boot:       boot,
		Metadata: map[string]any{
			"disk_id":         diskID,
			"resource_group":  resourceGroup,
			"subscription_id": strings.TrimSpace(target.SubscriptionID),
		},
	}
	if diskResp.Properties != nil && diskResp.Properties.Encryption != nil {
		volume.KMSKeyID = strings.TrimSpace(ptrString(diskResp.Properties.Encryption.DiskEncryptionSetID))
	}
	return volume, nil
}

func cloneAzureDataDisks(disks []*armcompute.DataDisk) []*armcompute.DataDisk {
	if len(disks) == 0 {
		return nil
	}
	out := make([]*armcompute.DataDisk, 0, len(disks))
	for _, disk := range disks {
		if disk == nil {
			continue
		}
		copyDisk := *disk
		out = append(out, &copyDisk)
	}
	return out
}

func nextAzureLUN(disks []*armcompute.DataDisk) (int32, error) {
	used := make(map[int32]struct{}, len(disks))
	for _, disk := range disks {
		if disk == nil || disk.Lun == nil {
			continue
		}
		used[*disk.Lun] = struct{}{}
	}
	for lun := int32(0); lun <= azureMaxDataDiskLUN; lun++ {
		if _, ok := used[lun]; ok {
			continue
		}
		return lun, nil
	}
	return 0, fmt.Errorf("azure scanner vm has no free data disk attachment slots")
}

func diskSizeGiBFromAzure(props *armcompute.DiskProperties) int64 {
	if props == nil || props.DiskSizeGB == nil {
		return 0
	}
	return int64(*props.DiskSizeGB)
}

func azureWorkloadResourceName(prefix, source string, now time.Time) string {
	source = labelSafe(source)
	if source == "" {
		source = "disk"
	}
	name := fmt.Sprintf("cerebro-%s-%s-%d", labelSafe(prefix), source, now.UTC().Unix())
	if len(name) > 80 {
		name = name[:80]
	}
	return strings.TrimRight(name, "-")
}

func volumeSourceID(volume SourceVolume) string {
	return firstNonEmpty(stringMetadata(volume.Metadata, "disk_id"), strings.TrimSpace(volume.ID))
}

func resourceGroupFromID(resourceID string) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return ""
	}
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return strings.TrimSpace(parts[i+1])
		}
	}
	return ""
}

func azureLUNDevicePath(lun int32) string {
	return fmt.Sprintf("/dev/disk/azure/scsi1/lun%d", lun)
}

func azureTags(metadata map[string]string, volumeID string) map[string]*string {
	tags := map[string]*string{
		"cerebro-scan": stringPtr("true"),
		"source-disk":  stringPtr(volumeID),
	}
	for key, value := range metadata {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		tags["meta-"+key] = stringPtr(value)
	}
	return tags
}

func ptrString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func int32Ptr(value int32) *int32 {
	return &value
}

func diskCreateOptionPtr(value armcompute.DiskCreateOption) *armcompute.DiskCreateOption {
	return &value
}

func diskCreateOptionTypesPtr(value armcompute.DiskCreateOptionTypes) *armcompute.DiskCreateOptionTypes {
	return &value
}

func cachingTypePtr(value armcompute.CachingTypes) *armcompute.CachingTypes {
	return &value
}
