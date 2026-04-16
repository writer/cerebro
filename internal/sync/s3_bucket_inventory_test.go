package sync

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type mockS3BucketClient struct {
	listBucketsFn                        func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	getBucketLocationFn                  func(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	getBucketPolicyFn                    func(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	getBucketAclFn                       func(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	getBucketEncryptionFn                func(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	getBucketVersioningFn                func(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	getBucketLoggingFn                   func(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	getPublicAccessBlockFn               func(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	getBucketOwnershipControlsFn         func(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	getBucketPolicyStatusFn              func(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	getBucketNotificationConfigurationFn func(context.Context, *s3.GetBucketNotificationConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error)
	listBucketInventoryConfigurationsFn  func(context.Context, *s3.ListBucketInventoryConfigurationsInput, ...func(*s3.Options)) (*s3.ListBucketInventoryConfigurationsOutput, error)
	getObjectLockConfigurationFn         func(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	getBucketLifecycleConfigurationFn    func(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	getBucketReplicationFn               func(context.Context, *s3.GetBucketReplicationInput, ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error)
	listObjectsV2Fn                      func(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	getBucketCorsFn                      func(context.Context, *s3.GetBucketCorsInput, ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error)
	getBucketWebsiteFn                   func(context.Context, *s3.GetBucketWebsiteInput, ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error)
}

func unexpectedS3Method(name string) error {
	return fmt.Errorf("unexpected S3 call: %s", name)
}

func (m *mockS3BucketClient) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.listBucketsFn != nil {
		return m.listBucketsFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("ListBuckets")
}

func (m *mockS3BucketClient) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if m.getBucketLocationFn != nil {
		return m.getBucketLocationFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketLocation")
}

func (m *mockS3BucketClient) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.getBucketPolicyFn != nil {
		return m.getBucketPolicyFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketPolicy")
}

func (m *mockS3BucketClient) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if m.getBucketAclFn != nil {
		return m.getBucketAclFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketAcl")
}

func (m *mockS3BucketClient) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if m.getBucketEncryptionFn != nil {
		return m.getBucketEncryptionFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketEncryption")
}

func (m *mockS3BucketClient) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if m.getBucketVersioningFn != nil {
		return m.getBucketVersioningFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketVersioning")
}

func (m *mockS3BucketClient) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.getBucketLoggingFn != nil {
		return m.getBucketLoggingFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketLogging")
}

func (m *mockS3BucketClient) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if m.getPublicAccessBlockFn != nil {
		return m.getPublicAccessBlockFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetPublicAccessBlock")
}

func (m *mockS3BucketClient) GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, optFns ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	if m.getBucketOwnershipControlsFn != nil {
		return m.getBucketOwnershipControlsFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketOwnershipControls")
}

func (m *mockS3BucketClient) GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if m.getBucketPolicyStatusFn != nil {
		return m.getBucketPolicyStatusFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketPolicyStatus")
}

func (m *mockS3BucketClient) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	if m.getBucketNotificationConfigurationFn != nil {
		return m.getBucketNotificationConfigurationFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketNotificationConfiguration")
}

func (m *mockS3BucketClient) ListBucketInventoryConfigurations(ctx context.Context, params *s3.ListBucketInventoryConfigurationsInput, optFns ...func(*s3.Options)) (*s3.ListBucketInventoryConfigurationsOutput, error) {
	if m.listBucketInventoryConfigurationsFn != nil {
		return m.listBucketInventoryConfigurationsFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("ListBucketInventoryConfigurations")
}

func (m *mockS3BucketClient) GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if m.getObjectLockConfigurationFn != nil {
		return m.getObjectLockConfigurationFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetObjectLockConfiguration")
}

func (m *mockS3BucketClient) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if m.getBucketLifecycleConfigurationFn != nil {
		return m.getBucketLifecycleConfigurationFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketLifecycleConfiguration")
}

func (m *mockS3BucketClient) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	if m.getBucketReplicationFn != nil {
		return m.getBucketReplicationFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketReplication")
}

func (m *mockS3BucketClient) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.listObjectsV2Fn != nil {
		return m.listObjectsV2Fn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("ListObjectsV2")
}

func (m *mockS3BucketClient) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	if m.getBucketCorsFn != nil {
		return m.getBucketCorsFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketCors")
}

func (m *mockS3BucketClient) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	if m.getBucketWebsiteFn != nil {
		return m.getBucketWebsiteFn(ctx, params, optFns...)
	}
	return nil, unexpectedS3Method("GetBucketWebsite")
}

func withMockS3BucketClientFactory(t *testing.T, factory func(aws.Config, ...func(*s3.Options)) s3BucketClient) {
	t.Helper()
	original := newS3BucketClient
	newS3BucketClient = factory
	t.Cleanup(func() {
		newS3BucketClient = original
	})
}

func TestS3BucketFetchersReuseBucketInventoryAcrossTables(t *testing.T) {
	var listBucketsCalls int
	var getBucketLocationCalls int
	var policyBuckets []string
	var versioningBuckets []string

	mockClient := &mockS3BucketClient{
		listBucketsFn: func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			listBucketsCalls++
			createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("west-bucket"), CreationDate: &createdAt},
					{Name: aws.String("east-bucket"), CreationDate: &createdAt},
				},
			}, nil
		},
		getBucketLocationFn: func(_ context.Context, input *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			getBucketLocationCalls++
			switch aws.ToString(input.Bucket) {
			case "west-bucket":
				return &s3.GetBucketLocationOutput{LocationConstraint: types.BucketLocationConstraintUsWest2}, nil
			case "east-bucket":
				return &s3.GetBucketLocationOutput{}, nil
			default:
				return nil, fmt.Errorf("unexpected bucket %q", aws.ToString(input.Bucket))
			}
		},
		getBucketPolicyFn: func(_ context.Context, input *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			policyBuckets = append(policyBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketPolicyOutput{Policy: aws.String(`{"Version":"2012-10-17"}`)}, nil
		},
		getBucketVersioningFn: func(_ context.Context, input *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			versioningBuckets = append(versioningBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil
		},
	}

	withMockS3BucketClientFactory(t, func(aws.Config, ...func(*s3.Options)) s3BucketClient {
		return mockClient
	})

	engine := &SyncEngine{
		accountID: "123456789012",
		logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}

	rows, err := engine.fetchS3BucketPolicies(context.Background(), aws.Config{}, "us-west-2")
	if err != nil {
		t.Fatalf("fetchS3BucketPolicies returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["bucket"] != "west-bucket" {
		t.Fatalf("unexpected policy rows: %+v", rows)
	}

	rows, err = engine.fetchS3BucketVersioning(context.Background(), aws.Config{}, "us-west-2")
	if err != nil {
		t.Fatalf("fetchS3BucketVersioning returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["bucket"] != "west-bucket" {
		t.Fatalf("unexpected versioning rows: %+v", rows)
	}

	if listBucketsCalls != 1 {
		t.Fatalf("expected ListBuckets to run once across fetchers, got %d", listBucketsCalls)
	}
	if getBucketLocationCalls != 2 {
		t.Fatalf("expected GetBucketLocation to run once per bucket, got %d", getBucketLocationCalls)
	}
	if len(policyBuckets) != 1 || policyBuckets[0] != "west-bucket" {
		t.Fatalf("unexpected GetBucketPolicy calls: %v", policyBuckets)
	}
	if len(versioningBuckets) != 1 || versioningBuckets[0] != "west-bucket" {
		t.Fatalf("unexpected GetBucketVersioning calls: %v", versioningBuckets)
	}
}

func TestFetchS3BucketsUsesRegionalClientsForPerBucketCalls(t *testing.T) {
	eastVersioningBuckets := []string{}
	westVersioningBuckets := []string{}
	eastPublicAccessBuckets := []string{}
	westPublicAccessBuckets := []string{}
	eastLoggingBuckets := []string{}
	westLoggingBuckets := []string{}

	eastClient := &mockS3BucketClient{
		listBucketsFn: func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			createdAt := time.Date(2024, time.January, 2, 0, 0, 0, 0, time.UTC)
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("east-bucket"), CreationDate: &createdAt},
					{Name: aws.String("west-bucket"), CreationDate: &createdAt},
				},
			}, nil
		},
		getBucketLocationFn: func(_ context.Context, input *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			switch aws.ToString(input.Bucket) {
			case "east-bucket":
				return &s3.GetBucketLocationOutput{}, nil
			case "west-bucket":
				return &s3.GetBucketLocationOutput{LocationConstraint: types.BucketLocationConstraintUsWest2}, nil
			default:
				return nil, fmt.Errorf("unexpected bucket %q", aws.ToString(input.Bucket))
			}
		},
		getPublicAccessBlockFn: func(_ context.Context, input *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			eastPublicAccessBuckets = append(eastPublicAccessBuckets, aws.ToString(input.Bucket))
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(true),
					BlockPublicPolicy:     aws.Bool(true),
					IgnorePublicAcls:      aws.Bool(true),
					RestrictPublicBuckets: aws.Bool(true),
				},
			}, nil
		},
		getBucketVersioningFn: func(_ context.Context, input *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			eastVersioningBuckets = append(eastVersioningBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil
		},
		getBucketLoggingFn: func(_ context.Context, input *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
			eastLoggingBuckets = append(eastLoggingBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketLoggingOutput{
				LoggingEnabled: &types.LoggingEnabled{
					TargetBucket: aws.String("logs-east"),
					TargetPrefix: aws.String("east/"),
				},
			}, nil
		},
	}

	westClient := &mockS3BucketClient{
		getPublicAccessBlockFn: func(_ context.Context, input *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			westPublicAccessBuckets = append(westPublicAccessBuckets, aws.ToString(input.Bucket))
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(false),
					BlockPublicPolicy:     aws.Bool(false),
					IgnorePublicAcls:      aws.Bool(false),
					RestrictPublicBuckets: aws.Bool(false),
				},
			}, nil
		},
		getBucketVersioningFn: func(_ context.Context, input *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			westVersioningBuckets = append(westVersioningBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusSuspended}, nil
		},
		getBucketLoggingFn: func(_ context.Context, input *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
			westLoggingBuckets = append(westLoggingBuckets, aws.ToString(input.Bucket))
			return &s3.GetBucketLoggingOutput{
				LoggingEnabled: &types.LoggingEnabled{
					TargetBucket: aws.String("logs-west"),
					TargetPrefix: aws.String("west/"),
				},
			}, nil
		},
	}

	withMockS3BucketClientFactory(t, func(cfg aws.Config, _ ...func(*s3.Options)) s3BucketClient {
		if cfg.Region == "us-west-2" {
			return westClient
		}
		return eastClient
	})

	engine := &SyncEngine{
		accountID: "123456789012",
		logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}

	rows, err := engine.fetchS3Buckets(context.Background(), aws.Config{Region: "us-east-1"}, "us-east-1")
	if err != nil {
		t.Fatalf("fetchS3Buckets returned error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 bucket rows, got %d", len(rows))
	}

	if strings.Join(eastPublicAccessBuckets, ",") != "east-bucket" || strings.Join(eastVersioningBuckets, ",") != "east-bucket" || strings.Join(eastLoggingBuckets, ",") != "east-bucket" {
		t.Fatalf("expected east client to service only east bucket, got pab=%v versioning=%v logging=%v", eastPublicAccessBuckets, eastVersioningBuckets, eastLoggingBuckets)
	}
	if strings.Join(westPublicAccessBuckets, ",") != "west-bucket" || strings.Join(westVersioningBuckets, ",") != "west-bucket" || strings.Join(westLoggingBuckets, ",") != "west-bucket" {
		t.Fatalf("expected west client to service only west bucket, got pab=%v versioning=%v logging=%v", westPublicAccessBuckets, westVersioningBuckets, westLoggingBuckets)
	}

	rowByBucket := make(map[string]map[string]interface{}, len(rows))
	for _, row := range rows {
		rowByBucket[row["name"].(string)] = row
	}
	if got := rowByBucket["east-bucket"]["region"]; got != "us-east-1" {
		t.Fatalf("expected east-bucket region us-east-1, got %v", got)
	}
	if got := rowByBucket["west-bucket"]["region"]; got != "us-west-2" {
		t.Fatalf("expected west-bucket region us-west-2, got %v", got)
	}
	if got := rowByBucket["west-bucket"]["versioning_status"]; got != string(types.BucketVersioningStatusSuspended) {
		t.Fatalf("expected west-bucket versioning from west client, got %v", got)
	}
}

func TestFetchS3BucketPoliciesLogsUnexpectedBucketErrors(t *testing.T) {
	var logs bytes.Buffer

	mockClient := &mockS3BucketClient{
		listBucketsFn: func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			createdAt := time.Date(2024, time.January, 3, 0, 0, 0, 0, time.UTC)
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("policy-bucket"), CreationDate: &createdAt}},
			}, nil
		},
		getBucketLocationFn: func(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{LocationConstraint: types.BucketLocationConstraintUsWest2}, nil
		},
		getBucketPolicyFn: func(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
		},
	}

	withMockS3BucketClientFactory(t, func(aws.Config, ...func(*s3.Options)) s3BucketClient {
		return mockClient
	})

	engine := &SyncEngine{
		accountID: "123456789012",
		logger:    slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	rows, err := engine.fetchS3BucketPolicies(context.Background(), aws.Config{}, "us-west-2")
	if err != nil {
		t.Fatalf("fetchS3BucketPolicies returned error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no rows on denied bucket policy fetch, got %d", len(rows))
	}

	output := logs.String()
	if !strings.Contains(output, "table=aws_s3_bucket_policies") || !strings.Contains(output, "bucket=policy-bucket") || !strings.Contains(output, "operation=GetBucketPolicy") {
		t.Fatalf("expected warning log for denied bucket policy fetch, got %q", output)
	}
}

func TestS3BucketsDoesNotCacheDiscoveryFailures(t *testing.T) {
	var listBucketsCalls int

	mockClient := &mockS3BucketClient{
		listBucketsFn: func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			listBucketsCalls++
			if listBucketsCalls == 1 {
				return nil, fmt.Errorf("temporary failure")
			}
			createdAt := time.Date(2024, time.January, 4, 0, 0, 0, 0, time.UTC)
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("retry-bucket"), CreationDate: &createdAt}},
			}, nil
		},
		getBucketLocationFn: func(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{LocationConstraint: types.BucketLocationConstraintUsWest2}, nil
		},
	}

	withMockS3BucketClientFactory(t, func(aws.Config, ...func(*s3.Options)) s3BucketClient {
		return mockClient
	})

	engine := &SyncEngine{
		accountID: "123456789012",
		logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}

	if _, err := engine.s3Buckets(context.Background(), aws.Config{}); err == nil {
		t.Fatal("expected first discovery call to fail")
	}

	buckets, err := engine.s3Buckets(context.Background(), aws.Config{})
	if err != nil {
		t.Fatalf("expected second discovery call to succeed, got %v", err)
	}
	if listBucketsCalls != 2 {
		t.Fatalf("expected discovery to retry after failure, got %d ListBuckets calls", listBucketsCalls)
	}
	if len(buckets) != 1 || buckets[0].Name != "retry-bucket" {
		t.Fatalf("unexpected buckets after retry: %+v", buckets)
	}
}

func TestFetchS3BucketsPreservesBucketsWhenLocationLookupFails(t *testing.T) {
	var logs bytes.Buffer

	mockClient := &mockS3BucketClient{
		listBucketsFn: func(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			createdAt := time.Date(2024, time.January, 5, 0, 0, 0, 0, time.UTC)
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("unknown-region-bucket"), CreationDate: &createdAt}},
			}, nil
		},
		getBucketLocationFn: func(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
		},
		getPublicAccessBlockFn: func(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
					BlockPublicAcls: aws.Bool(true),
				},
			}, nil
		},
		getBucketVersioningFn: func(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil
		},
		getBucketLoggingFn: func(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
			return &s3.GetBucketLoggingOutput{
				LoggingEnabled: &types.LoggingEnabled{
					TargetBucket: aws.String("logs"),
					TargetPrefix: aws.String("prefix/"),
				},
			}, nil
		},
	}

	withMockS3BucketClientFactory(t, func(aws.Config, ...func(*s3.Options)) s3BucketClient {
		return mockClient
	})

	engine := &SyncEngine{
		accountID: "123456789012",
		logger:    slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	rows, err := engine.fetchS3Buckets(context.Background(), aws.Config{Region: "us-east-1"}, "us-east-1")
	if err != nil {
		t.Fatalf("fetchS3Buckets returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one bucket row, got %d", len(rows))
	}

	row := rows[0]
	if row["name"] != "unknown-region-bucket" {
		t.Fatalf("unexpected bucket row: %+v", row)
	}
	if _, ok := row["region"]; ok {
		t.Fatalf("expected bucket row without region when location lookup fails, got %+v", row)
	}
	if row["versioning_status"] != string(types.BucketVersioningStatusEnabled) {
		t.Fatalf("expected follow-on bucket calls to still populate row, got %+v", row)
	}
	if !strings.Contains(logs.String(), "operation=GetBucketLocation") {
		t.Fatalf("expected location warning log, got %q", logs.String())
	}
}
