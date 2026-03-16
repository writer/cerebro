package workloadscan

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeAWSEC2Client struct {
	describeSnapshots func(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
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

func (f *fakeAWSEC2Client) DescribeSnapshots(ctx context.Context, input *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.describeSnapshots != nil {
		return f.describeSnapshots(ctx, input, optFns...)
	}
	return nil, nil
}

func (f *fakeAWSEC2Client) ModifySnapshotAttribute(context.Context, *ec2.ModifySnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.ModifySnapshotAttributeOutput, error) {
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

func (f *fakeAWSEC2Client) DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	return nil, nil
}

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
