package vulnpipeline

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	s3ModeIncremental    = "incremental"
	s3ModeLatestSnapshot = "latest_snapshot"
	defaultS3MaxObjects  = 50
	maxS3ListedKeys      = 20000
	maxS3SessionName     = 64
	// s3SourcesEnv names the operator allowlist of vulnerability S3 pulls,
	// read by internal/config.VulnerabilityPullS3Sources.
	s3SourcesEnv = "CEREBRO_VULNERABILITY_PULL_S3_SOURCES"
)

var (
	s3BucketPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3RegionPattern      = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	s3RoleARNPattern     = regexp.MustCompile(`^arn:(aws[a-z-]*):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	s3SessionNameInvalid = regexp.MustCompile(`[^A-Za-z0-9+=,.@_-]`)
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
	// SessionName names the assumed-role session for CloudTrail.
	SessionName string
	// SessionPolicy is an inline policy that narrows the assumed role to
	// listing and reading the profile's bucket prefix.
	SessionPolicy string
}

// S3Puller reads scanner exports dropped into an S3 bucket. In incremental
// mode every new object is one delivery; in latest_snapshot mode the newest
// object is the complete current set.
//
// Without AllowAmbientCredentials every profile must name a role_arn, and the
// operator must bind the profile's tenant to that role and its bucket (and
// optional prefix) in Sources (CEREBRO_VULNERABILITY_PULL_S3_SOURCES).
// Otherwise any tenant could read buckets that Cerebro's identity, or an
// inventory role, can reach.
type S3Puller struct {
	NewClient func(context.Context, S3Settings) (S3API, error)
	// Sources returns the allowlist: entries "tenant=role_arn|bucket[/prefix]"
	// separated by commas, semicolons, or whitespace.
	Sources                 func() string
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
	// Wildcard and policy-variable characters would widen the session policy.
	if prefix := config["prefix"]; len(prefix) > 512 || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\x00\r\n*?$") {
		return errors.New("prefix must be a relative S3 key prefix without wildcards")
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

// s3SourceAllowed reports whether allowlist binds tenantID to roleARN and a
// bucket location that contains prefix.
func s3SourceAllowed(tenantID string, roleARN string, bucket string, prefix string, allowlist string) bool {
	tenantID, roleARN = strings.TrimSpace(tenantID), strings.TrimSpace(roleARN)
	if tenantID == "" || roleARN == "" || bucket == "" {
		return false
	}
	for _, entry := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		tenant, binding, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(tenant) != tenantID {
			continue
		}
		role, location, ok := strings.Cut(binding, "|")
		if !ok || strings.TrimSpace(role) != roleARN {
			continue
		}
		allowedBucket, allowedPrefix, _ := strings.Cut(strings.TrimSpace(location), "/")
		if allowedBucket == bucket && strings.HasPrefix(prefix, allowedPrefix) {
			return true
		}
	}
	return false
}

func s3SessionPolicy(partition string, bucket string, prefix string) (string, error) {
	bucketARN := "arn:" + partition + ":s3:::" + bucket
	list := map[string]any{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucketARN}
	if prefix != "" {
		list["Condition"] = map[string]any{"StringLike": map[string]any{"s3:prefix": prefix + "*"}}
	}
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			list,
			map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": bucketARN + "/" + prefix + "*"},
		},
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode s3 session policy: %w", err)
	}
	return string(encoded), nil
}

func s3SessionName(tenantID string, profileID string) string {
	name := s3SessionNameInvalid.ReplaceAllString("cerebro-vp-"+tenantID+"-"+profileID, "-")
	if len(name) > maxS3SessionName {
		name = name[:maxS3SessionName]
	}
	return name
}

// s3Access is the resolved, allowlisted access of one pull.
type s3Access struct {
	settings    S3Settings
	bucketOwner *string
}

func (p S3Puller) access(request PullRequest) (s3Access, error) {
	config := request.Config
	bucket, prefix, role := config["bucket"], config["prefix"], strings.TrimSpace(config["role_arn"])
	access := s3Access{settings: S3Settings{Region: config["region"], RoleARN: role, ExternalID: config["external_id"]}}
	if !p.AllowAmbientCredentials {
		allowlist := ""
		if p.Sources != nil {
			allowlist = p.Sources()
		}
		if !s3SourceAllowed(request.TenantID, role, bucket, prefix, allowlist) {
			return s3Access{}, fmt.Errorf("role_arn, bucket, and prefix are not allowlisted for this tenant in %s", s3SourcesEnv)
		}
	}
	if role == "" {
		return access, nil
	}
	matches := s3RoleARNPattern.FindStringSubmatch(role)
	if len(matches) != 3 {
		return s3Access{}, errors.New("role_arn must be an IAM role ARN")
	}
	policy, err := s3SessionPolicy(matches[1], bucket, prefix)
	if err != nil {
		return s3Access{}, err
	}
	access.settings.SessionPolicy = policy
	access.settings.SessionName = s3SessionName(request.TenantID, request.ProfileID)
	access.bucketOwner = awssdk.String(matches[2])
	return access, nil
}

// NewS3Client builds an S3 client from the runtime's AWS credentials,
// optionally assuming a role narrowed by the session policy.
func NewS3Client(ctx context.Context, settings S3Settings) (S3API, error) {
	region := configValue(map[string]string{"region": settings.Region}, "region", "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if settings.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), settings.RoleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = configValue(map[string]string{"name": settings.SessionName}, "name", "cerebro-vulnerability-pull")
			if settings.SessionPolicy != "" {
				options.Policy = awssdk.String(settings.SessionPolicy)
			}
			if settings.ExternalID != "" {
				options.ExternalID = awssdk.String(settings.ExternalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}

// s3Cursor records the last ingested key with the location it belongs to, so
// a cursor is never applied to a different bucket, prefix, or mode.
type s3Cursor struct {
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix"`
	Mode   string `json:"mode"`
	Key    string `json:"key"`
}

func s3Mode(config map[string]string) string {
	if config["mode"] == s3ModeLatestSnapshot {
		return s3ModeLatestSnapshot
	}
	return s3ModeIncremental
}

func encodeS3Cursor(config map[string]string, key string) string {
	if key == "" {
		return ""
	}
	encoded, _ := json.Marshal(s3Cursor{Bucket: config["bucket"], Prefix: config["prefix"], Mode: s3Mode(config), Key: key})
	return string(encoded)
}

func decodeS3Cursor(config map[string]string, raw string) string {
	var cursor s3Cursor
	if err := json.Unmarshal([]byte(raw), &cursor); err != nil {
		return ""
	}
	if cursor.Bucket != config["bucket"] || cursor.Prefix != config["prefix"] || cursor.Mode != s3Mode(config) {
		return ""
	}
	return cursor.Key
}

// Pull reads objects. Incremental mode relies on S3 listing keys in
// lexicographic order: exporters must write keys that sort in delivery order
// (for example a timestamp prefix), or later objects that sort before the
// cursor are never read.
func (p S3Puller) Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error) {
	config := request.Config
	access, err := p.access(request)
	if err != nil {
		return PullOutcome{}, err
	}
	client, err := p.client(ctx, access.settings)
	if err != nil {
		return PullOutcome{}, err
	}
	reader := s3Reader{client: client, bucket: config["bucket"], prefix: config["prefix"], owner: access.bucketOwner, format: config["format"]}
	if s3Mode(config) == s3ModeLatestSnapshot {
		return reader.pullLatest(ctx, config, emit)
	}
	maxObjects, _ := configPositiveInt(config, "max_objects", defaultS3MaxObjects)
	cursor := decodeS3Cursor(config, request.Cursor)
	outcome := PullOutcome{}
	processed := 0
	for processed < maxObjects {
		input := &s3.ListObjectsV2Input{Bucket: awssdk.String(reader.bucket), Prefix: awssdk.String(reader.prefix), ExpectedBucketOwner: reader.owner, MaxKeys: awssdk.Int32(int32(min(maxObjects-processed, 1000)))} // #nosec G115 -- bounded to [1, 1000] by min and the loop condition.
		if cursor != "" {
			input.StartAfter = awssdk.String(cursor)
		}
		listing, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			outcome.Cursor = encodeS3Cursor(config, cursor)
			return outcome, fmt.Errorf("list s3 objects: %w", err)
		}
		for _, object := range listing.Contents {
			key := awssdk.ToString(object.Key)
			if key == "" {
				continue
			}
			if !strings.HasSuffix(key, "/") && awssdk.ToInt64(object.Size) > 0 {
				if err := reader.emitObject(ctx, key, awssdk.ToString(object.ETag), emit); err != nil {
					var permanent *permanentObjectError
					if !errors.As(err, &permanent) {
						// The cursor stays before this object so it is retried.
						outcome.Cursor = encodeS3Cursor(config, cursor)
						return outcome, err
					}
					outcome.Skipped = append(outcome.Skipped, fmt.Sprintf("s3 object %q skipped: %v", key, permanent.err))
				}
			}
			cursor = key
			processed++
		}
		if !awssdk.ToBool(listing.IsTruncated) || len(listing.Contents) == 0 {
			break
		}
	}
	outcome.Cursor = encodeS3Cursor(config, cursor)
	return outcome, nil
}

func (p S3Puller) client(ctx context.Context, settings S3Settings) (S3API, error) {
	if p.NewClient != nil {
		return p.NewClient(ctx, settings)
	}
	return NewS3Client(ctx, settings)
}

// permanentObjectError marks an object that will never be readable as is, so
// an incremental pull records it and moves past it instead of retrying it
// forever.
type permanentObjectError struct {
	err error
}

func (e *permanentObjectError) Error() string { return e.err.Error() }

func (e *permanentObjectError) Unwrap() error { return e.err }

func permanentObject(err error) error { return &permanentObjectError{err: err} }

func permanentGetError(err error) bool {
	var response *awshttp.ResponseError
	if !errors.As(err, &response) {
		return false
	}
	// Forbidden, not found, and unsatisfiable range do not change on retry.
	switch response.HTTPStatusCode() {
	case 403, 404, 416:
		return true
	default:
		return false
	}
}

func corruptCompression(err error) bool {
	var corrupt flate.CorruptInputError
	return errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.As(err, &corrupt)
}

type s3Reader struct {
	client S3API
	bucket string
	prefix string
	owner  *string
	format string
}

func (r s3Reader) pullLatest(ctx context.Context, config map[string]string, emit func(PullPage) error) (PullOutcome, error) {
	var latestKey, latestETag string
	var latestModified int64
	var token *string
	listed := 0
	for {
		listing, err := r.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: awssdk.String(r.bucket), Prefix: awssdk.String(r.prefix), ExpectedBucketOwner: r.owner, ContinuationToken: token})
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
	if err := r.emitObject(ctx, latestKey, latestETag, emit); err != nil {
		return PullOutcome{}, err
	}
	return PullOutcome{Cursor: encodeS3Cursor(config, latestKey), Snapshot: true}, nil
}

func (r s3Reader) emitObject(ctx context.Context, key string, etag string, emit func(PullPage) error) error {
	object, err := r.client.GetObject(ctx, &s3.GetObjectInput{Bucket: awssdk.String(r.bucket), Key: awssdk.String(key), ExpectedBucketOwner: r.owner})
	if err != nil {
		if permanentGetError(err) {
			return permanentObject(fmt.Errorf("get s3 object: %w", err))
		}
		return fmt.Errorf("get s3 object: %w", err)
	}
	defer func() { _ = object.Body.Close() }()
	if awssdk.ToInt64(object.ContentLength) > MaxPayloadBytes {
		return permanentObject(fmt.Errorf("s3 object exceeds %d bytes", MaxPayloadBytes))
	}
	var reader io.Reader = object.Body
	gzipped := strings.HasSuffix(strings.ToLower(key), ".gz") || strings.EqualFold(awssdk.ToString(object.ContentEncoding), "gzip")
	if gzipped {
		decompressed, err := gzip.NewReader(io.LimitReader(object.Body, MaxPayloadBytes+1))
		if err != nil {
			if corruptCompression(err) {
				return permanentObject(fmt.Errorf("open gzip s3 object: %w", err))
			}
			return fmt.Errorf("open gzip s3 object: %w", err)
		}
		defer func() { _ = decompressed.Close() }()
		reader = decompressed
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxPayloadBytes+1))
	if err != nil {
		if corruptCompression(err) {
			return permanentObject(fmt.Errorf("read s3 object: %w", err))
		}
		return fmt.Errorf("read s3 object: %w", err)
	}
	if len(payload) > MaxPayloadBytes {
		return permanentObject(fmt.Errorf("s3 object exceeds %d bytes", MaxPayloadBytes))
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return permanentObject(errors.New("s3 object is empty"))
	}
	contentType := awssdk.ToString(object.ContentType)
	lowerKey := strings.TrimSuffix(strings.ToLower(key), ".gz")
	if strings.HasSuffix(lowerKey, ".ndjson") || strings.HasSuffix(lowerKey, ".jsonl") {
		contentType = "application/x-ndjson"
	}
	return emit(PullPage{
		Payload:        payload,
		ContentType:    contentType,
		Format:         r.format,
		IdempotencyKey: "s3:" + shortHash(r.bucket, key, strings.Trim(etag, `"`)),
	})
}
