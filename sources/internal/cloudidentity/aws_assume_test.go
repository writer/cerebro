package cloudidentitysource

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func newTestAWSReader(t *testing.T, stsFake *fakeSTS, iamFake *fakeIAM, eksFake *fakeEKS) *awsReader {
	t.Helper()
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		Clock:            func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return stsFake },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return iamFake },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return eksFake },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	return readerAny.(*awsReader)
}

func TestAWSAssumeRoleCachedWithinRun(t *testing.T) {
	stsFake := &fakeSTS{assumeRole: func(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
		if aws.ToString(in.RoleArn) != "arn:aws:iam::111111111111:role/cerebro-org-scan-role" {
			t.Fatalf("unexpected role arn: %s", aws.ToString(in.RoleArn))
		}
		return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIDEXAMPLE"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      aws.Time(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)),
		}}, nil
	}}
	reader := newTestAWSReader(t, stsFake, &fakeIAM{}, &fakeEKS{})

	if _, err := reader.assumedConfig(context.Background(), "111111111111"); err != nil {
		t.Fatalf("first assume: %v", err)
	}
	if _, err := reader.assumedConfig(context.Background(), "111111111111"); err != nil {
		t.Fatalf("second assume: %v", err)
	}
	if stsFake.calls != 1 {
		t.Fatalf("expected sts:AssumeRole to be cached within the run, got %d calls", stsFake.calls)
	}
}

func TestAWSAssumeRoleFailureIsScopedNotEmptyPermissions(t *testing.T) {
	stsFake := &fakeSTS{assumeRole: func(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
		return nil, fmt.Errorf("access denied")
	}}
	reader := newTestAWSReader(t, stsFake, &fakeIAM{}, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "arn:aws:iam::111111111111:role/my-role", Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe returned error, want scoped gap: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false on assume-role failure")
	}
	if len(observation.Policy.Grants) != 0 || len(observation.Policy.Trust) != 0 {
		t.Fatalf("expected no fabricated grants on access failure, got %+v", observation.Policy)
	}
	if len(observation.Gaps) == 0 {
		t.Fatalf("expected a scoped gap on assume-role failure")
	}
}
