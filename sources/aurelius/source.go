// Package aurelius implements the Cerebro source for the aurelius image attestation
// and scan-verdict pipeline. Aurelius writes NDJSON event archives to an S3 bucket
// (one prefix per emitted kind family). This source lists those prefixes incrementally,
// reads new archives since the last cursor, and emits canonical aurelius.* events.
package aurelius

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "aurelius"

	defaultPageSize  = 100
	maxPageSize      = 1000
	defaultRegion    = "us-east-1"
	maxObjectBytes   = 64 << 20
	maxLineBytes     = 1 << 20
	maxEventsPerPull = 10000
	cursorSource     = "aurelius/s3-ndjson/v1"

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
	family   string
	bucket   string
	prefix   string
	region   string
	tenantID string
	perPage  int32
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
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
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
	tenantID := strings.TrimSpace(configValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(configValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	st := settings{
		family:   strings.TrimSpace(configValue(cfg, "family")),
		bucket:   strings.TrimSpace(configValue(cfg, "bucket")),
		prefix:   strings.TrimSpace(configValue(cfg, "prefix")),
		region:   strings.TrimSpace(configValue(cfg, "region")),
		tenantID: tenantID,
		perPage:  defaultPageSize,
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
	rawPageSize, ok := cfg.Lookup("per_page")
	if !ok || strings.TrimSpace(rawPageSize) == "" {
		rawPageSize, ok = cfg.Lookup("page_size")
	}
	if ok && strings.TrimSpace(rawPageSize) != "" {
		size, err := strconv.Atoi(strings.TrimSpace(rawPageSize))
		if err != nil {
			return settings{}, fmt.Errorf("%w: %w", ErrInvalidPageSize, err)
		}
		if size < 1 {
			return settings{}, fmt.Errorf("%w: must be >= 1", ErrInvalidPageSize)
		}
		if size > maxPageSize {
			size = maxPageSize
		}
		st.perPage = int32(size)
	}
	if !isKnownFamily(st.family) {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedFamily, st.family)
	}
	if strings.ContainsRune(st.bucket, '/') {
		return settings{}, fmt.Errorf("%w: %q must not contain slashes", ErrInvalidBucket, st.bucket)
	}
	return st, nil
}

func isKnownFamily(name string) bool {
	switch name {
	case familyVerdict, familyFinding, familyImageScan, familyCatalogPromotion, familyPolicyException:
		return true
	}
	return false
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
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

func watermarkString(watermark time.Time, fallback time.Time) string {
	if !watermark.IsZero() && !fallback.IsZero() && fallback.After(watermark) {
		watermark = fallback
	} else if watermark.IsZero() {
		watermark = fallback
	}
	if watermark.IsZero() {
		return ""
	}
	return watermark.UTC().Format(time.RFC3339Nano)
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
						Watermark:    watermarkString(watermark, priorWatermark),
					})
				} else {
					lastKey = key
					if objectIndex < len(listing.Contents)-1 || awssdk.ToBool(listing.IsTruncated) {
						nextCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
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
		nextCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	checkpointCursor := nextCursor
	if checkpointCursor == "" && lastKey != "" {
		checkpointCursor = encodeCursor(aureliusCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
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
	if strings.HasSuffix(key, ".gz") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("gunzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	}
	counter := &countingReader{reader: io.LimitReader(reader, decompressedLimitBytes+1)}
	scanner := bufio.NewScanner(counter)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	records := make([]aureliusRecord, 0, 64)
	line := 0
	for scanner.Scan() {
		if counter.bytesRead > decompressedLimitBytes {
			return nil, fmt.Errorf("%w: %d bytes", ErrDecompressedObjectTooLarge, decompressedLimitBytes)
		}
		line++
		text := bytes.TrimSpace(scanner.Bytes())
		if len(text) == 0 {
			continue
		}
		var rec aureliusRecord
		if err := json.Unmarshal(text, &rec); err != nil {
			return nil, fmt.Errorf("decode line %d: %w", line, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan archive: %w", err)
	}
	if counter.bytesRead > decompressedLimitBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrDecompressedObjectTooLarge, decompressedLimitBytes)
	}
	return records, nil
}

type countingReader struct {
	reader    io.Reader
	bytesRead int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
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
