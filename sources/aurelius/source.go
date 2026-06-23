// Package aurelius implements the Cerebro source for the aurelius image attestation
// and scan-verdict pipeline. Aurelius writes NDJSON event archives to an S3 bucket
// (one prefix per emitted kind family). This source lists those prefixes incrementally,
// reads new archives since the last cursor, and emits canonical aurelius.* events.
package aurelius

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

//go:embed catalog.yaml
var catalogFS embed.FS

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

const (
	sourceID = "aurelius"

	defaultPageSize       = 100
	maxPageSize           = 1000
	defaultRegion         = "us-east-1"
	assumeRoleSessionName = "cerebro-aurelius-source"
	maxObjectBytes        = 64 << 20
	maxLineBytes          = 1 << 20
	maxEventsPerPull      = 1000
	cursorSource          = "aurelius/s3-ndjson/v1"

	familyVerdict          = "verdict"
	familyFinding          = "finding"
	familyImageScan        = "image_scan"
	familyCatalogPromotion = "catalog_promotion"
	familyPolicyException  = "policy_exception"

	schemaRefVerdict          = "aurelius/verdict/v1"
	schemaRefFinding          = "aurelius/finding/v1"
	schemaRefImageScan        = "aurelius/image_scan/v1"
	schemaRefCatalogPromotion = "aurelius/catalog_promotion/v1"
	schemaRefPolicyException  = "aurelius/policy_exception/v1"

	kindVerdict          = "aurelius.verdict"
	kindFinding          = "aurelius.finding"
	kindImageScan        = "aurelius.image_scan"
	kindCatalogPromotion = "aurelius.catalog_promotion"
	kindPolicyException  = "aurelius.policy_exception"

	urnPrefixVerdict          = "urn:cerebro:aurelius:verdict:"
	urnPrefixFinding          = "urn:cerebro:aurelius:finding:"
	urnPrefixImageScan        = "urn:cerebro:aurelius:image_scan:"
	urnPrefixCatalogPromotion = "urn:cerebro:aurelius:catalog_promotion:"
	urnPrefixPolicyException  = "urn:cerebro:aurelius:policy_exception:"
)

var (
	// ErrBucketRequired is returned when no S3 bucket is configured.
	ErrBucketRequired = errors.New("bucket is required")
	// ErrPrefixRequired is returned when no S3 key prefix is configured.
	ErrPrefixRequired = errors.New("prefix is required")
	// ErrInvalidPageSize is returned when page_size is not a positive integer.
	ErrInvalidPageSize = errors.New("invalid page_size")
	// ErrTenantIDRequired is returned when no explicit tenant scope is configured.
	ErrTenantIDRequired = errors.New("tenant_id is required")
	// ErrDecompressedObjectTooLarge is returned when a compressed archive expands past the configured limit.
	ErrDecompressedObjectTooLarge = errors.New("decompressed object exceeds limit")
	// ErrUnsupportedFamily is returned when the family is not one of the known kinds.
	ErrUnsupportedFamily = errors.New("unsupported family")
	// ErrInvalidBucket is returned when the bucket name contains illegal characters.
	ErrInvalidBucket = errors.New("invalid bucket")
)

// s3API is the narrow surface of *s3.Client this source uses, exposed for testing.
type s3API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Source emits aurelius.* events from NDJSON archives stored in S3.
type Source struct {
	spec      *cerebrov1.SourceSpec
	families  *sourcecdk.FamilyEngine[settings]
	newClient func(context.Context, settings) (s3API, error)
}

type settings struct {
	family         string
	bucket         string
	prefix         string
	region         string
	tenantID       string
	roleARN        string
	externalID     string
	assumeRoleARNs string
	perPage        int32
}

type aureliusRecord struct {
	EventID    string                 `json:"event_id"`
	OccurredAt time.Time              `json:"occurred_at"`
	TenantID   string                 `json:"tenant_id"`
	Attributes map[string]string      `json:"attributes"`
	Payload    map[string]interface{} `json:"payload"`
}

type aureliusCursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	LastKey             string `json:"last_key,omitempty"`
	PartialKey          string `json:"partial_key,omitempty"`
	RecordOffset        int    `json:"record_offset,omitempty"`
	Watermark           string `json:"watermark,omitempty"`
}

// New constructs the Aurelius source backed by an S3-NDJSON archive.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:      spec,
		newClient: defaultClientFactory,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns the static metadata for the Aurelius source.
func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

// Check verifies that the configured S3 bucket/prefix is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns the URN for the configured family runtime instance.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages new NDJSON archives since the cursor and emits aurelius.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func defaultClientFactory(ctx context.Context, st settings) (s3API, error) {
	region := st.region
	if strings.TrimSpace(region) == "" {
		region = defaultRegion
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if st.roleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), st.roleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = assumeRoleSessionName
			if st.externalID != "" {
				options.ExternalID = awssdk.String(st.externalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return s3.NewFromConfig(cfg), nil
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{
		s.familyFor(familyVerdict, kindVerdict, schemaRefVerdict, urnPrefixVerdict),
		s.familyFor(familyFinding, kindFinding, schemaRefFinding, urnPrefixFinding),
		s.familyFor(familyImageScan, kindImageScan, schemaRefImageScan, urnPrefixImageScan),
		s.familyFor(familyCatalogPromotion, kindCatalogPromotion, schemaRefCatalogPromotion, urnPrefixCatalogPromotion),
		s.familyFor(familyPolicyException, kindPolicyException, schemaRefPolicyException, urnPrefixPolicyException),
	}
	return sourcecdk.NewFamilyEngine[settings](parseSettings, func(st settings) string { return st.family }, families...)
}

func (s *Source) familyFor(family, kind, schemaRef, urnPrefix string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, st settings) error {
			return s.check(ctx, st)
		},
		Discover: func(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
			return discoverFamily(st, urnPrefix)
		},
		Read: func(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			return s.readFamily(ctx, st, cursor, kind, schemaRef)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	tenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	st := settings{
		family:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")),
		bucket:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "bucket")),
		prefix:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "prefix")),
		region:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "region")),
		tenantID:       tenantID,
		roleARN:        strings.TrimSpace(sourcecdk.ConfigValue(cfg, "role_arn")),
		externalID:     strings.TrimSpace(sourcecdk.ConfigValue(cfg, "external_id")),
		assumeRoleARNs: strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.AWSAssumeRoleAllowlistKey)),
		perPage:        defaultPageSize,
	}
	if st.family == "" {
		st.family = familyVerdict
	}
	if st.bucket == "" {
		return settings{}, ErrBucketRequired
	}
	if st.prefix == "" {
		return settings{}, ErrPrefixRequired
	}
	if !strings.HasSuffix(st.prefix, "/") {
		st.prefix += "/"
	}
	if st.region == "" {
		st.region = defaultRegion
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantIDRequired
	}
	if st.roleARN != "" {
		if err := validateAssumeRoleConfig(st); err != nil {
			return settings{}, err
		}
	} else if st.externalID != "" {
		return settings{}, fmt.Errorf("aurelius external_id requires role_arn")
	}
	rawPageSize, ok := cfg.Lookup("per_page")
	if ok && strings.TrimSpace(rawPageSize) != "" {
		size, err := strconv.ParseInt(strings.TrimSpace(rawPageSize), 10, 32)
		if err != nil {
			return settings{}, fmt.Errorf("%w: %w", ErrInvalidPageSize, err)
		}
		if size < 1 {
			return settings{}, fmt.Errorf("%w: must be >= 1", ErrInvalidPageSize)
		}
		if size > int64(maxPageSize) {
			size = int64(maxPageSize)
		}
		st.perPage = int32(size) // #nosec G109 G115 -- ParseInt bitSize 32 and maxPageSize bound ensure this conversion is safe.
	}
	if !isKnownFamily(st.family) {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedFamily, st.family)
	}
	if strings.ContainsRune(st.bucket, '/') {
		return settings{}, fmt.Errorf("%w: %q must not contain slashes", ErrInvalidBucket, st.bucket)
	}
	return st, nil
}

func validateAssumeRoleConfig(st settings) error {
	if len(awsRoleARNPattern.FindStringSubmatch(st.roleARN)) != 3 {
		return fmt.Errorf("aurelius role_arn must be an IAM role ARN")
	}
	if st.tenantID == "" {
		return fmt.Errorf("aurelius role_arn requires runtime tenant_id")
	}
	if !assumeRoleARNAllowed(st.tenantID, st.roleARN, st.assumeRoleARNs) {
		return fmt.Errorf("aurelius role_arn is not allowed")
	}
	return nil
}

func assumeRoleARNAllowed(tenantID string, roleARN string, allowlist string) bool {
	tenantID = strings.TrimSpace(tenantID)
	roleARN = strings.TrimSpace(roleARN)
	if tenantID == "" || roleARN == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		tenant, arn, ok := strings.Cut(strings.TrimSpace(value), "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(tenant) == tenantID && strings.TrimSpace(arn) == roleARN {
			return true
		}
	}
	return false
}

func isKnownFamily(name string) bool {
	switch name {
	case familyVerdict, familyFinding, familyImageScan, familyCatalogPromotion, familyPolicyException:
		return true
	}
	return false
}

func decodeCursor(cursor *cerebrov1.SourceCursor) aureliusCursor {
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return aureliusCursor{}
	}
	var decoded aureliusCursor
	if err := json.Unmarshal([]byte(opaque), &decoded); err == nil && decoded.Source == cursorSource {
		decoded.LastKey = strings.TrimSpace(decoded.LastKey)
		decoded.PartialKey = strings.TrimSpace(decoded.PartialKey)
		decoded.Watermark = strings.TrimSpace(decoded.Watermark)
		if decoded.PartialKey == "" || decoded.RecordOffset < 0 {
			decoded.RecordOffset = 0
		}
		return decoded
	}
	return aureliusCursor{LastKey: opaque}
}

func encodeCursor(cursor aureliusCursor) string {
	cursor.Source = cursorSource
	cursor.ResumableCheckpoint = true
	cursor.LastKey = strings.TrimSpace(cursor.LastKey)
	cursor.PartialKey = strings.TrimSpace(cursor.PartialKey)
	cursor.Watermark = strings.TrimSpace(cursor.Watermark)
	if cursor.PartialKey == "" || cursor.RecordOffset < 0 {
		cursor.RecordOffset = 0
	}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return cursor.LastKey
	}
	return string(raw)
}

func cursorWatermark(cursor aureliusCursor) time.Time {
	if cursor.Watermark == "" {
		return time.Time{}
	}
	value, err := time.Parse(time.RFC3339Nano, cursor.Watermark)
	if err != nil {
		return time.Time{}
	}
	return value.UTC()
}

func discoverFamily(st settings, urnPrefix string) ([]sourcecdk.URN, error) {
	urnRaw := urnPrefix + url.PathEscape(st.bucket+"/"+strings.TrimSuffix(st.prefix, "/"))
	urn, err := sourcecdk.ParseURN(urnRaw)
	if err != nil {
		return nil, fmt.Errorf("build aurelius urn: %w", err)
	}
	return []sourcecdk.URN{urn}, nil
}

func (s *Source) check(ctx context.Context, st settings) error {
	client, err := s.newClient(ctx, st)
	if err != nil {
		return err
	}
	_, err = client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  awssdk.String(st.bucket),
		Prefix:  awssdk.String(st.prefix),
		MaxKeys: awssdk.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("list objects in s3://%s/%s: %w", st.bucket, st.prefix, err)
	}
	return nil
}

func (s *Source) readFamily(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor, kind, schemaRef string) (sourcecdk.Pull, error) {
	client, err := s.newClient(ctx, st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	cursorState := decodeCursor(cursor)
	startAfter := cursorState.LastKey
	input := &s3.ListObjectsV2Input{
		Bucket:  awssdk.String(st.bucket),
		Prefix:  awssdk.String(st.prefix),
		MaxKeys: awssdk.Int32(st.perPage),
	}
	if startAfter != "" {
		input.StartAfter = awssdk.String(startAfter)
	}
	listing, err := client.ListObjectsV2(ctx, input)
	if err != nil {
		return sourcecdk.Pull{}, fmt.Errorf("list objects in s3://%s/%s: %w", st.bucket, st.prefix, err)
	}
	events := make([]*primitives.Event, 0, st.perPage)
	var watermark time.Time
	priorWatermark := cursorWatermark(cursorState)
	lastKey := startAfter
	nextCursor := ""
	for objectIndex, object := range listing.Contents {
		key := awssdk.ToString(object.Key)
		if key == "" {
			continue
		}
		if strings.HasSuffix(key, "/") {
			lastKey = key
			continue
		}
		if !isArchiveKey(key) {
			lastKey = key
			continue
		}
		recs, err := s.readArchive(ctx, client, st.bucket, key)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("read s3://%s/%s: %w", st.bucket, key, err)
		}
		startRecord := 0
		if key == cursorState.PartialKey {
			startRecord = cursorState.RecordOffset
			if startRecord > len(recs) {
				startRecord = len(recs)
			}
		}
		for recordIndex := startRecord; recordIndex < len(recs); recordIndex++ {
			rec := recs[recordIndex]
			if recordTenant := strings.TrimSpace(rec.TenantID); recordTenant != "" && recordTenant != st.tenantID {
				continue
			}
			event, err := buildEvent(st, rec, kind, schemaRef)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("convert event in s3://%s/%s: %w", st.bucket, key, err)
			}
			if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("invalid event in s3://%s/%s: %w", st.bucket, key, err)
			}
			events = append(events, event)
			if rec.OccurredAt.After(watermark) {
				watermark = rec.OccurredAt
			}
			if len(events) >= maxEventsPerPull {
				nextRecord := recordIndex + 1
				if nextRecord < len(recs) {
					nextCursor = encodeCursor(aureliusCursor{
						LastKey:      lastKey,
						PartialKey:   key,
						RecordOffset: nextRecord,
						Watermark:    sourcecdk.WatermarkString(watermark, priorWatermark),
					})
				} else {
					lastKey = key
					if objectIndex < len(listing.Contents)-1 || awssdk.ToBool(listing.IsTruncated) {
						nextCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: sourcecdk.WatermarkString(watermark, priorWatermark)})
					}
				}
				break
			}
		}
		if nextCursor != "" {
			break
		}
		lastKey = key
	}
	pull := sourcecdk.Pull{Events: events}
	if nextCursor == "" && awssdk.ToBool(listing.IsTruncated) && lastKey != "" {
		nextCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: sourcecdk.WatermarkString(watermark, priorWatermark)})
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	checkpointCursor := nextCursor
	if checkpointCursor == "" && lastKey != "" {
		checkpointCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: sourcecdk.WatermarkString(watermark, priorWatermark)})
	}
	madeProgress := lastKey != "" && lastKey != startAfter
	if checkpointCursor != "" && (!watermark.IsZero() || cursor != nil || nextCursor != "" || madeProgress) {
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{
			CursorOpaque: checkpointCursor,
		}
		checkpointWatermark := watermark
		if priorWatermark.After(checkpointWatermark) {
			checkpointWatermark = priorWatermark
		}
		if !checkpointWatermark.IsZero() {
			pull.Checkpoint.Watermark = timestamppb.New(checkpointWatermark.UTC())
		}
	}
	return pull, nil
}

func isArchiveKey(key string) bool {
	switch {
	case strings.HasSuffix(key, ".ndjson"):
		return true
	case strings.HasSuffix(key, ".ndjson.gz"):
		return true
	}
	return false
}

func (s *Source) readArchive(ctx context.Context, client s3API, bucket, key string) ([]aureliusRecord, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(bucket),
		Key:    awssdk.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}
	defer func() { _ = out.Body.Close() }()
	body := io.LimitReader(out.Body, maxObjectBytes+1)
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(raw) > maxObjectBytes {
		return nil, fmt.Errorf("object exceeds %d bytes", maxObjectBytes)
	}
	records, err := readArchiveRecords(bytes.NewReader(raw), key, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func readArchiveRecords(reader io.Reader, key string, decompressedLimitBytes int64) ([]aureliusRecord, error) {
	lines, err := sourcecdk.ReadNDJSONArchive(reader, strings.HasSuffix(key, ".gz"), decompressedLimitBytes, maxLineBytes)
	if err != nil {
		if errors.Is(err, sourcecdk.ErrNDJSONDecompressedTooLarge) {
			return nil, fmt.Errorf("%w: %d bytes", ErrDecompressedObjectTooLarge, decompressedLimitBytes)
		}
		return nil, err
	}
	records := make([]aureliusRecord, 0, len(lines))
	for index, line := range lines {
		var rec aureliusRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("decode line %d: %w", index+1, err)
		}
		records = append(records, rec)
	}
	return records, nil
}

func buildEvent(st settings, rec aureliusRecord, kind, schemaRef string) (*primitives.Event, error) {
	if strings.TrimSpace(rec.EventID) == "" {
		return nil, errors.New("event_id is required")
	}
	if rec.OccurredAt.IsZero() {
		return nil, errors.New("occurred_at is required")
	}
	payload, err := json.Marshal(rec.Payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	tenantID := strings.TrimSpace(rec.TenantID)
	if tenantID == "" {
		tenantID = st.tenantID
	}
	attributes := make(map[string]string, len(rec.Attributes))
	for k, v := range rec.Attributes {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		attributes[k] = v
	}
	promotePayloadAttributes(kind, attributes, rec.Payload)
	return &primitives.Event{
		Id:         rec.EventID,
		TenantId:   tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		SchemaRef:  schemaRef,
		OccurredAt: timestamppb.New(rec.OccurredAt.UTC()),
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func promotePayloadAttributes(kind string, attributes map[string]string, payload map[string]interface{}) {
	if len(payload) == 0 {
		return
	}
	for _, key := range payloadPromotedAttributeKeys(kind) {
		if strings.TrimSpace(attributes[key]) != "" {
			continue
		}
		if value := payloadAttributeString(payload[key]); value != "" {
			attributes[key] = value
		}
	}
}

func payloadPromotedAttributeKeys(kind string) []string {
	switch kind {
	case kindVerdict:
		return []string{"image_digest", "verdict"}
	case kindFinding:
		return []string{"image_digest", "severity", "cve_id", "package", "installed_version", "fixed_version"}
	case kindImageScan:
		return []string{"image_digest", "registry"}
	case kindCatalogPromotion:
		return []string{"track", "image_digest"}
	case kindPolicyException:
		return []string{"cve_id", "status"}
	default:
		return nil
	}
}

func payloadAttributeString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}
