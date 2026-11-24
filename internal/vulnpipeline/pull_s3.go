package vulnpipeline

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	s3ModeIncremental    = "incremental"
	s3ModeLatestSnapshot = "latest_snapshot"
	defaultS3MaxObjects  = 50
	maxS3ListedKeys      = 20000
)

var (
	s3BucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3RegionPattern  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	s3RoleARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
)

// S3API is the subset of the S3 client the puller uses.
type S3API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Settings identifies the bucket and credentials for one pull.
type S3Settings struct {
	Region     string
	RoleARN    string
	ExternalID string
}

// S3Puller reads scanner exports dropped into an S3 bucket. In incremental
// mode every new object is one delivery; in latest_snapshot mode the newest
// object is the complete current set.
//
// Without AllowAmbientCredentials every profile must name a role_arn that the
// operator bound to the profile's tenant in the runtime assume-role
// allowlist; otherwise any tenant could read buckets that Cerebro's own
// identity can reach.
type S3Puller struct {
	NewClient               func(context.Context, S3Settings) (S3API, error)
	AllowAmbientCredentials bool
}

func (S3Puller) Kind() string { return PullKindS3 }

func (S3Puller) SecretKeys() []string { return nil }

func (p S3Puller) ValidateConfig(config map[string]string) error {
	if err := rejectUnknownKeys(config, "bucket", "prefix", "region", "role_arn", "external_id", "mode", "format", "max_objects"); err != nil {
		return err
	}
	if !p.AllowAmbientCredentials && strings.TrimSpace(config["role_arn"]) == "" {
		return errors.New("role_arn is required")
	}
	if !s3BucketPattern.MatchString(config["bucket"]) || strings.Contains(config["bucket"], "..") {
		return errors.New("bucket must be a valid S3 bucket name")
	}
	if prefix := config["prefix"]; len(prefix) > 512 || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\x00\r\n") {
		return errors.New("prefix must be a relative S3 key prefix")
	}
	if region := config["region"]; region != "" && !s3RegionPattern.MatchString(region) {
		return errors.New("region must be an AWS region name")
	}
	if role := config["role_arn"]; role != "" && !s3RoleARNPattern.MatchString(role) {
		return errors.New("role_arn must be an IAM role ARN")
	}
	if externalID := config["external_id"]; len(externalID) > 1224 {
		return errors.New("external_id is too long")
	}
	switch config["mode"] {
	case "", s3ModeIncremental, s3ModeLatestSnapshot:
	default:
		return fmt.Errorf("mode must be %s or %s", s3ModeIncremental, s3ModeLatestSnapshot)
	}
	if format := config["format"]; format != "" && (!validFormat(format) || format == FormatAuto) {
		return fmt.Errorf("unknown format %q", format)
	}
	_, err := configPositiveInt(config, "max_objects", defaultS3MaxObjects)
	return err
}

func (p S3Puller) client(ctx context.Context, config map[string]string) (S3API, error) {
	settings := S3Settings{Region: config["region"], RoleARN: config["role_arn"], ExternalID: config["external_id"]}
	if p.NewClient != nil {
		return p.NewClient(ctx, settings)
	}
	return NewS3Client(ctx, settings)
}

// NewS3Client builds an S3 client from the runtime's AWS credentials,
// optionally assuming a role.
func NewS3Client(ctx context.Context, settings S3Settings) (S3API, error) {
	region := configValue(map[string]string{"region": settings.Region}, "region", "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if settings.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), settings.RoleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = "cerebro-vulnerability-pull"
			if settings.ExternalID != "" {
				options.ExternalID = awssdk.String(settings.ExternalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}

func (p S3Puller) Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error) {
	config := request.Config
	if !p.AllowAmbientCredentials && !sourceconfig.AWSAssumeRoleARNAllowed(request.TenantID, config["role_arn"], config[sourceconfig.AWSAssumeRoleAllowlistKey]) {
		return PullOutcome{}, errors.New("role_arn is not allowlisted for this tenant")
	}
	client, err := p.client(ctx, config)
	if err != nil {
		return PullOutcome{}, err
	}
	bucket := config["bucket"]
	if config["mode"] == s3ModeLatestSnapshot {
		return p.pullLatest(ctx, client, bucket, config, emit)
	}
	maxObjects, _ := configPositiveInt(config, "max_objects", defaultS3MaxObjects)
	cursor := request.Cursor
	processed := 0
	for processed < maxObjects {
		input := &s3.ListObjectsV2Input{Bucket: awssdk.String(bucket), Prefix: awssdk.String(config["prefix"]), MaxKeys: awssdk.Int32(int32(min(maxObjects-processed, 1000)))} // #nosec G115 -- bounded to [1, 1000] by min and the loop condition.
		if cursor != "" {
			input.StartAfter = awssdk.String(cursor)
		}
		listing, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			return PullOutcome{Cursor: request.Cursor}, fmt.Errorf("list s3 objects: %w", err)
		}
		for _, object := range listing.Contents {
			key := awssdk.ToString(object.Key)
			if key == "" {
				continue
			}
			if !strings.HasSuffix(key, "/") && awssdk.ToInt64(object.Size) > 0 {
				if err := p.emitObject(ctx, client, bucket, key, awssdk.ToString(object.ETag), config["format"], emit); err != nil {
					return PullOutcome{}, err
				}
			}
			cursor = key
			processed++
		}
		if !awssdk.ToBool(listing.IsTruncated) || len(listing.Contents) == 0 {
			break
		}
	}
	return PullOutcome{Cursor: cursor}, nil
}

func (p S3Puller) pullLatest(ctx context.Context, client S3API, bucket string, config map[string]string, emit func(PullPage) error) (PullOutcome, error) {
	var latestKey, latestETag string
	var latestModified int64
	var token *string
	listed := 0
	for {
		listing, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: awssdk.String(bucket), Prefix: awssdk.String(config["prefix"]), ContinuationToken: token})
		if err != nil {
			return PullOutcome{}, fmt.Errorf("list s3 objects: %w", err)
		}
		for _, object := range listing.Contents {
			key := awssdk.ToString(object.Key)
			if key == "" || strings.HasSuffix(key, "/") || awssdk.ToInt64(object.Size) == 0 {
				continue
			}
			modified := int64(0)
			if object.LastModified != nil {
				modified = object.LastModified.UnixNano()
			}
			if modified > latestModified || (modified == latestModified && key > latestKey) {
				latestKey, latestETag, latestModified = key, awssdk.ToString(object.ETag), modified
			}
		}
		listed += len(listing.Contents)
		if !awssdk.ToBool(listing.IsTruncated) || listing.NextContinuationToken == nil {
			break
		}
		if listed >= maxS3ListedKeys {
			return PullOutcome{}, fmt.Errorf("s3 prefix lists more than %d objects; narrow the prefix for latest_snapshot mode", maxS3ListedKeys)
		}
		token = listing.NextContinuationToken
	}
	if latestKey == "" {
		return PullOutcome{}, nil
	}
	if err := p.emitObject(ctx, client, bucket, latestKey, latestETag, config["format"], emit); err != nil {
		return PullOutcome{}, err
	}
	return PullOutcome{Cursor: latestKey, Snapshot: true}, nil
}

func (p S3Puller) emitObject(ctx context.Context, client S3API, bucket string, key string, etag string, format string, emit func(PullPage) error) error {
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: awssdk.String(bucket), Key: awssdk.String(key)})
	if err != nil {
		return fmt.Errorf("get s3 object: %w", err)
	}
	defer func() { _ = object.Body.Close() }()
	if awssdk.ToInt64(object.ContentLength) > MaxPayloadBytes {
		return fmt.Errorf("s3 object exceeds %d bytes", MaxPayloadBytes)
	}
	var reader io.Reader = object.Body
	gzipped := strings.HasSuffix(strings.ToLower(key), ".gz") || strings.EqualFold(awssdk.ToString(object.ContentEncoding), "gzip")
	if gzipped {
		decompressed, err := gzip.NewReader(io.LimitReader(object.Body, MaxPayloadBytes+1))
		if err != nil {
			return fmt.Errorf("open gzip s3 object: %w", err)
		}
		defer func() { _ = decompressed.Close() }()
		reader = decompressed
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxPayloadBytes+1))
	if err != nil {
		return fmt.Errorf("read s3 object: %w", err)
	}
	if len(payload) > MaxPayloadBytes {
		return fmt.Errorf("s3 object exceeds %d bytes", MaxPayloadBytes)
	}
	contentType := awssdk.ToString(object.ContentType)
	lowerKey := strings.TrimSuffix(strings.ToLower(key), ".gz")
	if strings.HasSuffix(lowerKey, ".ndjson") || strings.HasSuffix(lowerKey, ".jsonl") {
		contentType = "application/x-ndjson"
	}
	return emit(PullPage{
		Payload:        bytes.TrimSpace(payload),
		ContentType:    contentType,
		Format:         format,
		IdempotencyKey: "s3:" + shortHash(bucket, key, strings.Trim(etag, `"`)),
	})
}
