package workloadscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	gcpcompute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	gax "github.com/googleapis/gax-go/v2"
)

const defaultGCPProviderPollTimeout = 5 * time.Minute

type gcpInstancesAPI interface {
	Get(ctx context.Context, req *computepb.GetInstanceRequest, opts ...gax.CallOption) (*computepb.Instance, error)
	AttachDisk(ctx context.Context, req *computepb.AttachDiskInstanceRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	DetachDisk(ctx context.Context, req *computepb.DetachDiskInstanceRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	Close() error
}

type gcpDisksAPI interface {
	Get(ctx context.Context, req *computepb.GetDiskRequest, opts ...gax.CallOption) (*computepb.Disk, error)
	CreateSnapshot(ctx context.Context, req *computepb.CreateSnapshotDiskRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	Insert(ctx context.Context, req *computepb.InsertDiskRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	Delete(ctx context.Context, req *computepb.DeleteDiskRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	Close() error
}

type gcpSnapshotsAPI interface {
	Get(ctx context.Context, req *computepb.GetSnapshotRequest, opts ...gax.CallOption) (*computepb.Snapshot, error)
	Delete(ctx context.Context, req *computepb.DeleteSnapshotRequest, opts ...gax.CallOption) (*gcpcompute.Operation, error)
	Close() error
}

type gcpZoneOperationsAPI interface {
	Wait(ctx context.Context, req *computepb.WaitZoneOperationRequest, opts ...gax.CallOption) (*computepb.Operation, error)
	Close() error
}

type gcpGlobalOperationsAPI interface {
	Wait(ctx context.Context, req *computepb.WaitGlobalOperationRequest, opts ...gax.CallOption) (*computepb.Operation, error)
	Close() error
}

type GCPProvider struct {
	instances   gcpInstancesAPI
	disks       gcpDisksAPI
	snapshots   gcpSnapshotsAPI
	zoneOps     gcpZoneOperationsAPI
	globalOps   gcpGlobalOperationsAPI
	pollTimeout time.Duration
	now         func() time.Time
}

func NewGCPProvider(ctx context.Context) (*GCPProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	instances, err := gcpcompute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create gcp instances client: %w", err)
	}
	disks, err := gcpcompute.NewDisksRESTClient(ctx)
	if err != nil {
		_ = instances.Close()
		return nil, fmt.Errorf("create gcp disks client: %w", err)
	}
	snapshots, err := gcpcompute.NewSnapshotsRESTClient(ctx)
	if err != nil {
		_ = instances.Close()
		_ = disks.Close()
		return nil, fmt.Errorf("create gcp snapshots client: %w", err)
	}
	zoneOps, err := gcpcompute.NewZoneOperationsRESTClient(ctx)
	if err != nil {
		_ = instances.Close()
		_ = disks.Close()
		_ = snapshots.Close()
		return nil, fmt.Errorf("create gcp zone operations client: %w", err)
	}
	globalOps, err := gcpcompute.NewGlobalOperationsRESTClient(ctx)
	if err != nil {
		_ = instances.Close()
		_ = disks.Close()
		_ = snapshots.Close()
		_ = zoneOps.Close()
		return nil, fmt.Errorf("create gcp global operations client: %w", err)
	}
	return NewGCPProviderWithClients(instances, disks, snapshots, zoneOps, globalOps), nil
}

func NewGCPProviderWithClients(instances gcpInstancesAPI, disks gcpDisksAPI, snapshots gcpSnapshotsAPI, zoneOps gcpZoneOperationsAPI, globalOps gcpGlobalOperationsAPI) *GCPProvider {
	return &GCPProvider{
		instances:   instances,
		disks:       disks,
		snapshots:   snapshots,
		zoneOps:     zoneOps,
		globalOps:   globalOps,
		pollTimeout: defaultGCPProviderPollTimeout,
		now:         time.Now,
	}
}

func (p *GCPProvider) Kind() ProviderKind { return ProviderGCP }

func (p *GCPProvider) MaxConcurrentAttachments() int { return 15 }

func (p *GCPProvider) InventoryVolumes(ctx context.Context, target VMTarget) ([]SourceVolume, error) {
	if p == nil || p.instances == nil || p.disks == nil {
		return nil, fmt.Errorf("gcp provider is not configured")
	}
	projectID := strings.TrimSpace(target.ProjectID)
	zone := strings.TrimSpace(target.Zone)
	instanceName := strings.TrimSpace(target.InstanceName)
	if projectID == "" || zone == "" || instanceName == "" {
		return nil, fmt.Errorf("gcp target project id, zone, and instance name are required")
	}
	instance, err := p.instances.Get(ctx, &computepb.GetInstanceRequest{
		Project:  projectID,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return nil, fmt.Errorf("get gcp instance %s: %w", instanceName, err)
	}
	volumes := make([]SourceVolume, 0, len(instance.Disks))
	for _, attached := range instance.Disks {
		if attached == nil {
			continue
		}
		diskName := resourceName(attached.GetSource())
		if diskName == "" {
			diskName = strings.TrimSpace(attached.GetDeviceName())
		}
		if diskName == "" {
			continue
		}
		disk, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
			Project: projectID,
			Zone:    zone,
			Disk:    diskName,
		})
		if err != nil {
			return nil, fmt.Errorf("get gcp disk %s: %w", diskName, err)
		}
		volumes = append(volumes, SourceVolume{
			ID:         diskName,
			Name:       diskName,
			DeviceName: strings.TrimSpace(attached.GetDeviceName()),
			Region:     strings.TrimSpace(target.Region),
			Zone:       zone,
			SizeGiB:    attached.GetDiskSizeGb(),
			Encrypted:  disk.GetDiskEncryptionKey() != nil,
			KMSKeyID:   strings.TrimSpace(disk.GetDiskEncryptionKey().GetKmsKeyName()),
			Boot:       attached.GetBoot(),
			Metadata: map[string]any{
				"source":        strings.TrimSpace(attached.GetSource()),
				"mode":          strings.TrimSpace(attached.GetMode()),
				"auto_delete":   attached.GetAutoDelete(),
				"self_link":     strings.TrimSpace(disk.GetSelfLink()),
				"instance_id":   strings.TrimSpace(instance.GetSelfLink()),
				"instance_name": instanceName,
			},
		})
	}
	return volumes, nil
}

func (p *GCPProvider) CreateSnapshot(ctx context.Context, target VMTarget, volume SourceVolume, metadata map[string]string) (*SnapshotArtifact, error) {
	if p == nil || p.disks == nil || p.zoneOps == nil || p.snapshots == nil {
		return nil, fmt.Errorf("gcp provider is not configured")
	}
	projectID := strings.TrimSpace(target.ProjectID)
	zone := strings.TrimSpace(volume.Zone)
	if zone == "" {
		zone = strings.TrimSpace(target.Zone)
	}
	snapshotName := gcpWorkloadResourceName("snapshot", volume.ID, p.now())
	req := &computepb.CreateSnapshotDiskRequest{
		Project: projectID,
		Zone:    zone,
		Disk:    strings.TrimSpace(volume.ID),
		SnapshotResource: &computepb.Snapshot{
			Name:        stringPtr(snapshotName),
			Description: stringPtr("Cerebro workload scan snapshot for " + strings.TrimSpace(target.InstanceName)),
			Labels:      gcpSnapshotLabels(metadata, volume.ID),
		},
	}
	op, err := p.disks.CreateSnapshot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create gcp snapshot for %s: %w", volume.ID, err)
	}
	if err := p.waitForZoneOperation(ctx, projectID, zone, op); err != nil {
		return nil, err
	}
	snapshot, err := p.snapshots.Get(ctx, &computepb.GetSnapshotRequest{
		Project:  projectID,
		Snapshot: snapshotName,
	})
	if err != nil {
		return nil, fmt.Errorf("get gcp snapshot %s: %w", snapshotName, err)
	}
	createdAt := parseRFC3339(snapshot.GetCreationTimestamp(), p.now().UTC())
	readyAt := p.now().UTC()
	return &SnapshotArtifact{
		ID:        snapshotName,
		VolumeID:  volume.ID,
		ProjectID: projectID,
		Region:    strings.TrimSpace(target.Region),
		Zone:      zone,
		SizeGiB:   volume.SizeGiB,
		CreatedAt: createdAt,
		ReadyAt:   &readyAt,
		Metadata: map[string]any{
			"snapshot_name": snapshotName,
			"project_id":    projectID,
			"source_disk":   strings.TrimSpace(volume.ID),
			"self_link":     strings.TrimSpace(snapshot.GetSelfLink()),
		},
	}, nil
}

func (p *GCPProvider) ShareSnapshot(_ context.Context, target VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*SnapshotArtifact, error) {
	targetProject := strings.TrimSpace(target.ProjectID)
	scannerProject := strings.TrimSpace(scannerHost.ProjectID)
	if scannerProject == "" || scannerProject == targetProject {
		return &snapshot, nil
	}
	return nil, fmt.Errorf("cross-project gcp workload scans require explicit snapshot sharing identity and are not supported by this runner")
}

func (p *GCPProvider) CreateInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, snapshot SnapshotArtifact) (*InspectionVolume, error) {
	if p == nil || p.disks == nil || p.zoneOps == nil {
		return nil, fmt.Errorf("gcp provider is not configured")
	}
	projectID := firstNonEmpty(strings.TrimSpace(scannerHost.ProjectID), strings.TrimSpace(snapshot.ProjectID))
	zone := strings.TrimSpace(scannerHost.Zone)
	if projectID == "" || zone == "" {
		return nil, fmt.Errorf("gcp scanner host project id and zone are required")
	}
	diskName := gcpWorkloadResourceName("disk", snapshot.VolumeID, p.now())
	req := &computepb.InsertDiskRequest{
		Project: projectID,
		Zone:    zone,
		DiskResource: &computepb.Disk{
			Name:           stringPtr(diskName),
			SourceSnapshot: stringPtr(strings.TrimSpace(snapshotSelfLink(snapshot))),
			SizeGb:         int64Ptr(snapshot.SizeGiB),
		},
	}
	op, err := p.disks.Insert(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create gcp inspection disk from snapshot %s: %w", snapshot.ID, err)
	}
	if err := p.waitForZoneOperation(ctx, projectID, zone, op); err != nil {
		return nil, err
	}
	disk, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
		Project: projectID,
		Zone:    zone,
		Disk:    diskName,
	})
	if err != nil {
		return nil, fmt.Errorf("get gcp inspection disk %s: %w", diskName, err)
	}
	readyAt := p.now().UTC()
	return &InspectionVolume{
		ID:         diskName,
		SnapshotID: snapshot.ID,
		Region:     strings.TrimSpace(scannerHost.Region),
		Zone:       zone,
		SizeGiB:    disk.GetSizeGb(),
		CreatedAt:  parseRFC3339(disk.GetCreationTimestamp(), p.now().UTC()),
		ReadyAt:    &readyAt,
		Metadata: map[string]any{
			"disk_name":  diskName,
			"project_id": projectID,
			"self_link":  strings.TrimSpace(disk.GetSelfLink()),
		},
	}, nil
}

func (p *GCPProvider) AttachInspectionVolume(ctx context.Context, _ VMTarget, scannerHost ScannerHost, volume InspectionVolume, index int) (*VolumeAttachment, error) {
	if p == nil || p.instances == nil || p.zoneOps == nil {
		return nil, fmt.Errorf("gcp provider is not configured")
	}
	projectID := firstNonEmpty(strings.TrimSpace(scannerHost.ProjectID), stringMetadata(volume.Metadata, "project_id"))
	zone := strings.TrimSpace(scannerHost.Zone)
	deviceName := gcpWorkloadResourceName("attach", fmt.Sprintf("%s-%d", volume.ID, index), p.now())
	op, err := p.instances.AttachDisk(ctx, &computepb.AttachDiskInstanceRequest{
		Project:  projectID,
		Zone:     zone,
		Instance: strings.TrimSpace(scannerHost.HostID),
		AttachedDiskResource: &computepb.AttachedDisk{
			Source:     stringPtr(stringMetadata(volume.Metadata, "self_link")),
			DeviceName: stringPtr(deviceName),
			Mode:       stringPtr("READ_ONLY"),
			Type:       stringPtr("PERSISTENT"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("attach gcp inspection disk %s to %s: %w", volume.ID, scannerHost.HostID, err)
	}
	if err := p.waitForZoneOperation(ctx, projectID, zone, op); err != nil {
		return nil, err
	}
	attachedAt := p.now().UTC()
	return &VolumeAttachment{
		VolumeID:   volume.ID,
		HostID:     scannerHost.HostID,
		DeviceName: "/dev/disk/by-id/google-" + deviceName,
		ReadOnly:   true,
		AttachedAt: attachedAt,
		Metadata: map[string]any{
			"device_name": deviceName,
			"project_id":  projectID,
			"zone":        zone,
		},
	}, nil
}

func (p *GCPProvider) DetachInspectionVolume(ctx context.Context, attachment VolumeAttachment) error {
	if p == nil || p.instances == nil || p.zoneOps == nil {
		return fmt.Errorf("gcp provider is not configured")
	}
	projectID := stringMetadata(attachment.Metadata, "project_id")
	zone := stringMetadata(attachment.Metadata, "zone")
	deviceName := stringMetadata(attachment.Metadata, "device_name")
	if projectID == "" || zone == "" || deviceName == "" {
		return fmt.Errorf("gcp attachment metadata is incomplete")
	}
	op, err := p.instances.DetachDisk(ctx, &computepb.DetachDiskInstanceRequest{
		Project:    projectID,
		Zone:       zone,
		Instance:   strings.TrimSpace(attachment.HostID),
		DeviceName: deviceName,
	})
	if err != nil {
		return fmt.Errorf("detach gcp inspection disk %s: %w", attachment.VolumeID, err)
	}
	return p.waitForZoneOperation(ctx, projectID, zone, op)
}

func (p *GCPProvider) DeleteInspectionVolume(ctx context.Context, volume InspectionVolume) error {
	if p == nil || p.disks == nil || p.zoneOps == nil {
		return fmt.Errorf("gcp provider is not configured")
	}
	projectID := stringMetadata(volume.Metadata, "project_id")
	zone := strings.TrimSpace(volume.Zone)
	if zone == "" {
		zone = stringMetadata(volume.Metadata, "zone")
	}
	diskName := firstNonEmpty(stringMetadata(volume.Metadata, "disk_name"), strings.TrimSpace(volume.ID))
	op, err := p.disks.Delete(ctx, &computepb.DeleteDiskRequest{
		Project: projectID,
		Zone:    zone,
		Disk:    diskName,
	})
	if err != nil {
		return fmt.Errorf("delete gcp inspection disk %s: %w", diskName, err)
	}
	return p.waitForZoneOperation(ctx, projectID, zone, op)
}

func (p *GCPProvider) DeleteSnapshot(ctx context.Context, snapshot SnapshotArtifact) error {
	if p == nil || p.snapshots == nil || p.globalOps == nil {
		return fmt.Errorf("gcp provider is not configured")
	}
	projectID := firstNonEmpty(strings.TrimSpace(snapshot.ProjectID), stringMetadata(snapshot.Metadata, "project_id"))
	snapshotName := firstNonEmpty(stringMetadata(snapshot.Metadata, "snapshot_name"), strings.TrimSpace(snapshot.ID))
	op, err := p.snapshots.Delete(ctx, &computepb.DeleteSnapshotRequest{
		Project:  projectID,
		Snapshot: snapshotName,
	})
	if err != nil {
		return fmt.Errorf("delete gcp snapshot %s: %w", snapshotName, err)
	}
	return p.waitForGlobalOperation(ctx, projectID, op)
}

func (p *GCPProvider) waitForZoneOperation(ctx context.Context, projectID, zone string, op *gcpcompute.Operation) error {
	if p == nil || p.zoneOps == nil {
		return fmt.Errorf("gcp zone operations client is not configured")
	}
	if op == nil {
		return fmt.Errorf("gcp zone operation is nil")
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	result, err := p.zoneOps.Wait(waitCtx, &computepb.WaitZoneOperationRequest{
		Project:   projectID,
		Zone:      zone,
		Operation: strings.TrimSpace(op.Proto().GetName()),
	})
	if err != nil {
		return fmt.Errorf("wait for gcp zonal operation %s: %w", op.Proto().GetName(), err)
	}
	if err := gcpOperationError(result); err != nil {
		return err
	}
	return nil
}

func (p *GCPProvider) waitForGlobalOperation(ctx context.Context, projectID string, op *gcpcompute.Operation) error {
	if p == nil || p.globalOps == nil {
		return fmt.Errorf("gcp global operations client is not configured")
	}
	if op == nil {
		return fmt.Errorf("gcp global operation is nil")
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	result, err := p.globalOps.Wait(waitCtx, &computepb.WaitGlobalOperationRequest{
		Project:   projectID,
		Operation: strings.TrimSpace(op.Proto().GetName()),
	})
	if err != nil {
		return fmt.Errorf("wait for gcp global operation %s: %w", op.Proto().GetName(), err)
	}
	if err := gcpOperationError(result); err != nil {
		return err
	}
	return nil
}

func (p *GCPProvider) timeout() time.Duration {
	if p == nil || p.pollTimeout <= 0 {
		return defaultGCPProviderPollTimeout
	}
	return p.pollTimeout
}

func gcpOperationError(op *computepb.Operation) error {
	if op == nil {
		return fmt.Errorf("gcp operation result is nil")
	}
	if op.GetError() == nil && op.GetHttpErrorStatusCode() == 0 {
		return nil
	}
	return fmt.Errorf("gcp operation failed: status=%s http_status=%d message=%s", op.GetStatus().String(), op.GetHttpErrorStatusCode(), firstNonEmpty(op.GetHttpErrorMessage(), op.GetStatusMessage()))
}

func gcpSnapshotLabels(metadata map[string]string, volumeID string) map[string]string {
	labels := map[string]string{
		"cerebro-scan": "true",
		"source-disk":  labelSafe(volumeID),
	}
	for key, value := range metadata {
		key = labelSafe(key)
		value = labelSafe(value)
		if key == "" || value == "" {
			continue
		}
		labels["meta-"+key] = value
	}
	return labels
}

func labelSafe(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer("/", "-", "_", "-", ".", "-", ":", "-", " ", "-")
	value = replacer.Replace(value)
	if len(value) > 63 {
		value = value[:63]
	}
	return strings.Trim(value, "-")
}

func gcpWorkloadResourceName(prefix, source string, now time.Time) string {
	source = labelSafe(source)
	if source == "" {
		source = "volume"
	}
	name := fmt.Sprintf("cerebro-%s-%s-%d", labelSafe(prefix), source, now.UTC().Unix())
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-")
}

func snapshotSelfLink(snapshot SnapshotArtifact) string {
	if selfLink := stringMetadata(snapshot.Metadata, "self_link"); selfLink != "" {
		return selfLink
	}
	projectID := firstNonEmpty(strings.TrimSpace(snapshot.ProjectID), stringMetadata(snapshot.Metadata, "project_id"))
	if projectID == "" || strings.TrimSpace(snapshot.ID) == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/global/snapshots/%s", projectID, strings.TrimSpace(snapshot.ID))
}

func resourceName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	return strings.TrimSpace(parts[len(parts)-1])
}

func stringMetadata(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value := values[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	}
	return ""
}

func parseRFC3339(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fallback
	}
	return parsed.UTC()
}

func stringPtr(value string) *string {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}
