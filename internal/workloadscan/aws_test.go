package workloadscan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

type fakeAWSEC2Client struct {
	describeSnapshots       func(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	copySnapshot            func(context.Context, *ec2.CopySnapshotInput, ...func(*ec2.Options)) (*ec2.CopySnapshotOutput, error)
	modifySnapshotAttribute func(context.Context, *ec2.ModifySnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error)
	deleteSnapshot          func(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

func (f *fakeAWSEC2Client) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) CreateSnapshot(context.Context, *ec2.CreateSnapshotInput, ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) CopySnapshot(ctx context.Context, input *ec2.CopySnapshotInput, optFns ...func(*ec2.Options)) (*ec2.CopySnapshotOutput, error) {
	if f.copySnapshot != nil {
		return f.copySnapshot(ctx, input, optFns...)
	}
	return nil, nil
}

func (f *fakeAWSEC2Client) DescribeSnapshots(ctx context.Context, input *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.describeSnapshots != nil {
		return f.describeSnapshots(ctx, input, optFns...)
	}
	return nil, nil
}

func (f *fakeAWSEC2Client) ModifySnapshotAttribute(ctx context.Context, input *ec2.ModifySnapshotAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error) {
	if f.modifySnapshotAttribute != nil {
		return f.modifySnapshotAttribute(ctx, input, optFns...)
	}
	return nil, nil
}

func (f *fakeAWSEC2Client) CreateVolume(context.Context, *ec2.CreateVolumeInput, ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) AttachVolume(context.Context, *ec2.AttachVolumeInput, ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) DetachVolume(context.Context, *ec2.DetachVolumeInput, ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	return nil, nil
}

func (f *fakeAWSEC2Client) DeleteSnapshot(ctx context.Context, input *ec2.DeleteSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	if f.deleteSnapshot != nil {
		return f.deleteSnapshot(ctx, input, optFns...)
	}
	return nil, nil
}

type fakeAWSKMSClient struct {
	describeKey func(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	createGrant func(context.Context, *kms.CreateGrantInput, ...func(*kms.Options)) (*kms.CreateGrantOutput, error)
}

func (f *fakeAWSKMSClient) DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.describeKey != nil {
		return f.describeKey(ctx, input, optFns...)
	}
	return nil, nil
}

func (f *fakeAWSKMSClient) CreateGrant(ctx context.Context, input *kms.CreateGrantInput, optFns ...func(*kms.Options)) (*kms.CreateGrantOutput, error) {
	if f.createGrant != nil {
		return f.createGrant(ctx, input, optFns...)
	}
	return nil, nil
}

type fakeAWSAPIError struct {
	code string
	msg  string
}

func (e fakeAWSAPIError) Error() string                 { return e.msg }
func (e fakeAWSAPIError) ErrorCode() string             { return e.code }
func (e fakeAWSAPIError) ErrorMessage() string          { return e.msg }
func (e fakeAWSAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestAWSProviderWaitForSnapshotCompletedUsesCompletionTime(t *testing.T) {
	startTime := time.Date(2026, 3, 11, 20, 0, 0, 0, time.UTC)
	completionTime := startTime.Add(7 * time.Minute)
	provider := NewAWSProviderWithClient(&fakeAWSEC2Client{
		describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{
						State:          ec2types.SnapshotStateCompleted,
						StartTime:      &startTime,
						CompletionTime: &completionTime,
					},
				},
			}, nil
		},
	})
	provider.pollInterval = time.Millisecond

	readyAt, err := provider.waitForSnapshotCompleted(context.Background(), "snap-123")
	if err != nil {
		t.Fatalf("wait for snapshot completed: %v", err)
	}
	if !readyAt.Equal(completionTime) {
		t.Fatalf("expected completion time %s, got %s", completionTime, readyAt)
	}
}

func TestAWSProviderShareSnapshotCopiesIntoInspectionAccount(t *testing.T) {
	var modifiedSnapshotID string
	var copiedSourceSnapshotID string
	var grantInput *kms.CreateGrantInput

	sourceClient := &fakeAWSEC2Client{
		modifySnapshotAttribute: func(_ context.Context, input *ec2.ModifySnapshotAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error) {
			modifiedSnapshotID = *input.SnapshotId
			return &ec2.ModifySnapshotAttributeOutput{}, nil
		},
	}
	inspectionClient := &fakeAWSEC2Client{
		copySnapshot: func(_ context.Context, input *ec2.CopySnapshotInput, _ ...func(*ec2.Options)) (*ec2.CopySnapshotOutput, error) {
			copiedSourceSnapshotID = *input.SourceSnapshotId
			return &ec2.CopySnapshotOutput{SnapshotId: awsString("snap-inspection")}, nil
		},
		describeSnapshots: func(_ context.Context, _ *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{State: ec2types.SnapshotStateCompleted, CompletionTime: awsTime(time.Date(2026, 3, 12, 12, 5, 0, 0, time.UTC))},
				},
			}, nil
		},
	}
	kmsClient := &fakeAWSKMSClient{
		describeKey: func(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:      input.KeyId,
					KeyManager: kmstypes.KeyManagerTypeCustomer,
				},
			}, nil
		},
		createGrant: func(_ context.Context, input *kms.CreateGrantInput, _ ...func(*kms.Options)) (*kms.CreateGrantOutput, error) {
			grantInput = input
			return &kms.CreateGrantOutput{}, nil
		},
	}

	provider := NewAWSProviderWithClients(sourceClient, inspectionClient, kmsClient, AWSProviderOptions{
		InspectionKMSKeyID: "arn:aws:kms:us-east-1:222222222222:key/scanner",
	})
	provider.pollInterval = time.Millisecond

	shared, err := provider.ShareSnapshot(context.Background(),
		VMTarget{Provider: ProviderAWS, AccountID: "111111111111", Region: "us-east-1", InstanceID: "i-target"},
		ScannerHost{AccountID: "222222222222", Region: "us-east-1"},
		SnapshotArtifact{
			ID:        "snap-source",
			VolumeID:  "vol-123",
			AccountID: "111111111111",
			Region:    "us-east-1",
			Encrypted: true,
			KMSKeyID:  "arn:aws:kms:us-east-1:111111111111:key/source",
			Scope:     SnapshotScopeSource,
		},
	)
	if err != nil {
		t.Fatalf("share snapshot: %v", err)
	}
	if got := shared.ID; got != "snap-inspection" {
		t.Fatalf("expected copied snapshot id to match fake output, got %s", got)
	}
	if shared.Scope != SnapshotScopeInspection {
		t.Fatalf("expected inspection snapshot scope, got %s", shared.Scope)
	}
	if modifiedSnapshotID != "snap-source" {
		t.Fatalf("expected shared source snapshot id snap-source, got %s", modifiedSnapshotID)
	}
	if copiedSourceSnapshotID != "snap-source" {
		t.Fatalf("expected inspection copy to use shared source snapshot, got %s", copiedSourceSnapshotID)
	}
	if grantInput == nil {
		t.Fatal("expected kms grant to be created")
	}
	if got := strings.TrimSpace(*grantInput.GranteePrincipal); got != "arn:aws:iam::222222222222:root" {
		t.Fatalf("unexpected grant principal %s", got)
	}
	if len(shared.CleanupSnapshots) != 2 {
		t.Fatalf("expected inspection and source cleanup refs, got %#v", shared.CleanupSnapshots)
	}
	if shared.CleanupSnapshots[0].Scope != SnapshotScopeInspection {
		t.Fatalf("expected first cleanup ref to be inspection scoped, got %#v", shared.CleanupSnapshots[0])
	}
}

func TestAWSProviderShareSnapshotRequiresShareKeyForAWSManagedSource(t *testing.T) {
	kmsClient := &fakeAWSKMSClient{
		describeKey: func(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:      input.KeyId,
					KeyManager: kmstypes.KeyManagerTypeAws,
				},
			}, nil
		},
	}
	provider := NewAWSProviderWithClients(&fakeAWSEC2Client{}, &fakeAWSEC2Client{}, kmsClient, AWSProviderOptions{})

	_, err := provider.ShareSnapshot(context.Background(),
		VMTarget{Provider: ProviderAWS, AccountID: "111111111111", Region: "us-east-1"},
		ScannerHost{AccountID: "222222222222", Region: "us-east-1"},
		SnapshotArtifact{
			ID:        "snap-source",
			VolumeID:  "vol-123",
			AccountID: "111111111111",
			Region:    "us-east-1",
			Encrypted: true,
			KMSKeyID:  "arn:aws:kms:us-east-1:111111111111:key/aws-managed",
			Scope:     SnapshotScopeSource,
		},
	)
	if err == nil {
		t.Fatal("expected aws-managed key path to require a share key")
	}
	if !strings.Contains(err.Error(), "--share-kms-key-id") {
		t.Fatalf("expected share key guidance, got %v", err)
	}
}

func TestAWSProviderShareSnapshotReencryptsAWSManagedSourceBeforeSharing(t *testing.T) {
	var sourceCopyInput *ec2.CopySnapshotInput
	var modifiedSnapshotID string
	var grantInput *kms.CreateGrantInput

	sourceClient := &fakeAWSEC2Client{
		copySnapshot: func(_ context.Context, input *ec2.CopySnapshotInput, _ ...func(*ec2.Options)) (*ec2.CopySnapshotOutput, error) {
			sourceCopyInput = input
			return &ec2.CopySnapshotOutput{
				SnapshotId: awsString("snap-shareable"),
			}, nil
		},
		describeSnapshots: func(_ context.Context, _ *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{State: ec2types.SnapshotStateCompleted, CompletionTime: awsTime(time.Date(2026, 3, 12, 9, 3, 0, 0, time.UTC))},
				},
			}, nil
		},
		modifySnapshotAttribute: func(_ context.Context, input *ec2.ModifySnapshotAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error) {
			modifiedSnapshotID = strings.TrimSpace(*input.SnapshotId)
			return &ec2.ModifySnapshotAttributeOutput{}, nil
		},
	}
	kmsClient := &fakeAWSKMSClient{
		describeKey: func(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			keyID := strings.TrimSpace(*input.KeyId)
			manager := kmstypes.KeyManagerTypeAws
			if strings.Contains(keyID, "shareable") {
				manager = kmstypes.KeyManagerTypeCustomer
			}
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:      input.KeyId,
					KeyManager: manager,
				},
			}, nil
		},
		createGrant: func(_ context.Context, input *kms.CreateGrantInput, _ ...func(*kms.Options)) (*kms.CreateGrantOutput, error) {
			grantInput = input
			return &kms.CreateGrantOutput{}, nil
		},
	}

	provider := NewAWSProviderWithClients(sourceClient, sourceClient, kmsClient, AWSProviderOptions{
		ShareKMSKeyID: "arn:aws:kms:us-east-1:111111111111:key/shareable",
	})
	provider.pollInterval = time.Millisecond

	shared, err := provider.ShareSnapshot(context.Background(),
		VMTarget{Provider: ProviderAWS, AccountID: "111111111111", Region: "us-east-1"},
		ScannerHost{AccountID: "222222222222", Region: "us-east-1"},
		SnapshotArtifact{
			ID:        "snap-source",
			VolumeID:  "vol-123",
			AccountID: "111111111111",
			Region:    "us-east-1",
			Encrypted: true,
			KMSKeyID:  "arn:aws:kms:us-east-1:111111111111:key/aws-managed",
			Scope:     SnapshotScopeSource,
		},
	)
	if err != nil {
		t.Fatalf("share snapshot: %v", err)
	}
	if sourceCopyInput == nil {
		t.Fatal("expected source-side snapshot copy")
	}
	if got := strings.TrimSpace(*sourceCopyInput.KmsKeyId); got != "arn:aws:kms:us-east-1:111111111111:key/shareable" {
		t.Fatalf("expected source copy to use shareable key, got %s", got)
	}
	if modifiedSnapshotID != "snap-shareable" {
		t.Fatalf("expected shared snapshot to be the re-encrypted copy, got %s", modifiedSnapshotID)
	}
	if grantInput == nil || strings.TrimSpace(*grantInput.KeyId) != "arn:aws:kms:us-east-1:111111111111:key/shareable" {
		t.Fatalf("expected grant on shareable key, got %#v", grantInput)
	}
	if shared.ID != "snap-shareable" {
		t.Fatalf("expected returned snapshot to use shareable copy, got %s", shared.ID)
	}
	if len(shared.CleanupSnapshots) != 2 {
		t.Fatalf("expected cleanup refs for original and shareable snapshots, got %#v", shared.CleanupSnapshots)
	}
}

func TestAWSProviderDeleteSnapshotDeletesCleanupRefsAcrossScopes(t *testing.T) {
	var sourceDeletes []string
	var inspectionDeletes []string

	sourceClient := &fakeAWSEC2Client{
		deleteSnapshot: func(_ context.Context, input *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
			sourceDeletes = append(sourceDeletes, strings.TrimSpace(*input.SnapshotId))
			return &ec2.DeleteSnapshotOutput{}, nil
		},
	}
	inspectionClient := &fakeAWSEC2Client{
		deleteSnapshot: func(_ context.Context, input *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
			inspectionDeletes = append(inspectionDeletes, strings.TrimSpace(*input.SnapshotId))
			return &ec2.DeleteSnapshotOutput{}, nil
		},
	}
	provider := NewAWSProviderWithClients(sourceClient, inspectionClient, nil, AWSProviderOptions{})

	err := provider.DeleteSnapshot(context.Background(), SnapshotArtifact{
		ID:    "snap-inspection",
		Scope: SnapshotScopeInspection,
		CleanupSnapshots: []SnapshotCleanupRef{
			{ID: "snap-inspection", Scope: SnapshotScopeInspection},
			{ID: "snap-shareable", Scope: SnapshotScopeSource},
			{ID: "snap-source", Scope: SnapshotScopeSource},
		},
	})
	if err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if len(inspectionDeletes) != 1 || inspectionDeletes[0] != "snap-inspection" {
		t.Fatalf("unexpected inspection deletes: %#v", inspectionDeletes)
	}
	if len(sourceDeletes) != 2 || sourceDeletes[0] != "snap-shareable" || sourceDeletes[1] != "snap-source" {
		t.Fatalf("unexpected source deletes: %#v", sourceDeletes)
	}
}

func TestAWSProviderDeleteSnapshotIgnoresNotFound(t *testing.T) {
	sourceClient := &fakeAWSEC2Client{
		deleteSnapshot: func(_ context.Context, _ *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
			return nil, fakeAWSAPIError{code: "InvalidSnapshot.NotFound", msg: "gone"}
		},
	}
	provider := NewAWSProviderWithClients(sourceClient, sourceClient, nil, AWSProviderOptions{})
	if err := provider.DeleteSnapshot(context.Background(), SnapshotArtifact{ID: "snap-source", Scope: SnapshotScopeSource}); err != nil {
		t.Fatalf("expected not found delete to be ignored, got %v", err)
	}
}

func TestDeviceNameForIndexRejectsUnsupportedSlots(t *testing.T) {
	deviceName, err := deviceNameForIndex(0)
	if err != nil {
		t.Fatalf("device name for first slot: %v", err)
	}
	if deviceName != "/dev/sdf" {
		t.Fatalf("expected /dev/sdf, got %s", deviceName)
	}
	if _, err := deviceNameForIndex(len(awsAttachmentDeviceNames)); err == nil {
		t.Fatal("expected attachment slot exhaustion to return an error")
	}
}

func awsString(value string) *string { return &value }

func awsTime(value time.Time) *time.Time { return &value }
