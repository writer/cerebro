package sync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type s3BucketClient interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, optFns ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error)
	ListBucketInventoryConfigurations(ctx context.Context, params *s3.ListBucketInventoryConfigurationsInput, optFns ...func(*s3.Options)) (*s3.ListBucketInventoryConfigurationsOutput, error)
	GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error)
	GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error)
}

var newS3BucketClient = func(cfg aws.Config, optFns ...func(*s3.Options)) s3BucketClient {
	return s3.NewFromConfig(cfg, optFns...)
}

type s3BucketDescriptor struct {
	Name         string
	Region       string
	CreationDate *time.Time
}

type s3BucketInventoryState struct {
	mu      sync.Mutex
	ready   bool
	buckets []s3BucketDescriptor
	err     error
}

func (e *SyncEngine) s3Buckets(ctx context.Context, cfg aws.Config) ([]s3BucketDescriptor, error) {
	cacheKey := strings.TrimSpace(e.getAccountIDFromConfig(ctx, cfg))
	if cacheKey == "" {
		cacheKey = "default"
	}

	rawState, _ := e.s3BucketInventory.LoadOrStore(cacheKey, &s3BucketInventoryState{})
	state := rawState.(*s3BucketInventoryState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.ready {
		return cloneS3BucketDescriptors(state.buckets), state.err
	}

	discoveryCfg := cfg.Copy()
	discoveryCfg.Region = "us-east-1"
	client := newS3BucketClient(discoveryCfg)

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	buckets := make([]s3BucketDescriptor, 0, len(out.Buckets))
	for _, bucket := range out.Buckets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		name := strings.TrimSpace(aws.ToString(bucket.Name))
		if name == "" {
			continue
		}

		locOut, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(name),
		})
		if err != nil {
			e.warnS3BucketOperation("", name, "", "GetBucketLocation", err)
			buckets = append(buckets, s3BucketDescriptor{
				Name:         name,
				CreationDate: bucket.CreationDate,
			})
			continue
		}

		buckets = append(buckets, s3BucketDescriptor{
			Name:         name,
			Region:       normalizeS3BucketRegion(locOut.LocationConstraint),
			CreationDate: bucket.CreationDate,
		})
	}

	state.buckets = buckets
	state.err = nil
	state.ready = true
	return cloneS3BucketDescriptors(buckets), nil
}

func (e *SyncEngine) s3BucketsInRegion(ctx context.Context, cfg aws.Config, region string) ([]s3BucketDescriptor, error) {
	buckets, err := e.s3Buckets(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(region) == "" {
		return buckets, nil
	}

	filtered := make([]s3BucketDescriptor, 0, len(buckets))
	for _, bucket := range buckets {
		if strings.EqualFold(bucket.Region, region) {
			filtered = append(filtered, bucket)
		}
	}
	return filtered, nil
}

func cloneS3BucketDescriptors(buckets []s3BucketDescriptor) []s3BucketDescriptor {
	if len(buckets) == 0 {
		return nil
	}
	cloned := make([]s3BucketDescriptor, len(buckets))
	copy(cloned, buckets)
	return cloned
}

func newS3BucketRegionalClient(cfg aws.Config, region string) s3BucketClient {
	regionalCfg := cfg.Copy()
	if strings.TrimSpace(region) != "" {
		regionalCfg.Region = region
	}
	return newS3BucketClient(regionalCfg)
}

func normalizeS3BucketRegion(location types.BucketLocationConstraint) string {
	region := strings.TrimSpace(string(location))
	switch strings.ToUpper(region) {
	case "", "US", "US-EAST-1":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return strings.ToLower(region)
	}
}

func (e *SyncEngine) warnS3BucketOperation(table, bucket, region, operation string, err error, expectedCodes ...string) {
	if err == nil || isS3ExpectedBucketError(err, expectedCodes...) || e.logger == nil {
		return
	}

	args := []any{"bucket", bucket, "operation", operation, "error", err}
	if region != "" {
		args = append(args, "region", region)
	}
	if table != "" {
		args = append([]any{"table", table}, args...)
	}
	e.logger.Warn("s3 bucket operation failed", args...)
}

func isS3ExpectedBucketError(err error, expectedCodes ...string) bool {
	if len(expectedCodes) == 0 || err == nil {
		return false
	}

	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	code := strings.ToLower(strings.TrimSpace(apiErr.ErrorCode()))
	for _, expected := range expectedCodes {
		if code == strings.ToLower(strings.TrimSpace(expected)) {
			return true
		}
	}
	return false
}
