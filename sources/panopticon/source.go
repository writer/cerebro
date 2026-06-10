// Package panopticon implements the Cerebro source for Panopticon security
// operations exports. Panopticon writes canonical Cerebro event envelopes as
// NDJSON archives to S3, one prefix per event family. This source lists those
// prefixes incrementally, reads new archives since the last cursor, and emits
// validated panopticon.* events.
package panopticon

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
	"net"
	"net/http"
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
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

const (
	sourceID = "panopticon"

	defaultPageSize       = 100
	maxPageSize           = 1000
	defaultRegion         = "us-east-1"
	assumeRoleSessionName = "cerebro-panopticon-source"
	maxObjectBytes        = 64 << 20
	maxLineBytes          = 1 << 20
	maxEventsPerPull      = 1000
	cursorSource          = "panopticon/s3-ndjson/v1"
	cursorSourceAPI       = "panopticon/api/v1"
	modeAPI               = "api"

	familyAlert = "alert"
	familyCase  = "case"
	familyIOC   = "ioc"

	schemaRefAlert = "panopticon/alert/v1"
	schemaRefCase  = "panopticon/case/v1"
	schemaRefIOC   = "panopticon/ioc/v1"

	kindAlert = "panopticon.alert"
	kindCase  = "panopticon.case"
	kindIOC   = "panopticon.ioc"

	urnPrefixAlert = "urn:cerebro:panopticon:alert:"
	urnPrefixCase  = "urn:cerebro:panopticon:case:"
	urnPrefixIOC   = "urn:cerebro:panopticon:ioc:"
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
	// ErrBaseURLRequired is returned when API mode has no configured base URL.
	ErrBaseURLRequired = errors.New("base_url is required")
	// ErrTokenRequired is returned when API mode has no bearer token.
	ErrTokenRequired = errors.New("token is required")
	// ErrUnsupportedMode is returned when mode is not one of the known transports.
	ErrUnsupportedMode = errors.New("unsupported mode")
)

// s3API is the narrow surface of *s3.Client this source uses, exposed for testing.
type s3API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Source emits panopticon.* events from NDJSON archives stored in S3.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	newClient            func(context.Context, settings) (s3API, error)
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	mode           string
	family         string
	bucket         string
	prefix         string
	region         string
	baseURL        string
	apiPath        string
	token          string
	tenantID       string
	runtimeID      string
	roleARN        string
	externalID     string
	assumeRoleARNs string
	perPage        int32
}

type panopticonRecord struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	SourceID   string                 `json:"source_id"`
	Kind       string                 `json:"kind"`
	OccurredAt time.Time              `json:"occurred_at"`
	SchemaRef  string                 `json:"schema_ref"`
	Payload    map[string]interface{} `json:"payload"`
	Attributes map[string]string      `json:"attributes"`
}

type panopticonCursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	LastKey             string `json:"last_key,omitempty"`
	PartialKey          string `json:"partial_key,omitempty"`
	RecordOffset        int    `json:"record_offset,omitempty"`
	Watermark           string `json:"watermark,omitempty"`
}

// New constructs the Panopticon source backed by an S3-NDJSON archive.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		newClient:     defaultClientFactory,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns the static metadata for the Panopticon source.
func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

// Check verifies that the configured S3 bucket/prefix is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns the URN for the configured family runtime instance.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages new NDJSON archives since the cursor and emits panopticon.* events.
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
		s.familyFor(familyAlert, kindAlert, schemaRefAlert, urnPrefixAlert),
		s.familyFor(familyCase, kindCase, schemaRefCase, urnPrefixCase),
		s.familyFor(familyIOC, kindIOC, schemaRefIOC, urnPrefixIOC),
	}
	return sourcecdk.NewFamilyEngine[settings](
		func(cfg sourcecdk.Config) (settings, error) {
			return parseSettingsWithLoopback(cfg, s != nil && s.allowLoopbackBaseURL)
		},
		func(st settings) string { return st.family },
		families...,
	)
}

func (s *Source) familyFor(family, kind, schemaRef, urnPrefix string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, st settings) error {
			if st.mode == modeAPI {
				return s.checkAPI(ctx, st)
			}
			return s.check(ctx, st)
		},
		Discover: func(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
			if st.mode == modeAPI {
				return discoverAPIFamily(st, urnPrefix)
			}
			return discoverFamily(st, urnPrefix)
		},
		Read: func(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			if st.mode == modeAPI {
				return s.readAPIFamily(ctx, st, cursor, kind, schemaRef)
			}
			return s.readFamily(ctx, st, cursor, kind, schemaRef)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettingsWithLoopback(cfg, false)
}

func parseSettingsWithLoopback(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	tenantID := strings.TrimSpace(configValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(configValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	mode := strings.ToLower(strings.TrimSpace(configValue(cfg, "mode")))
	baseURL := strings.TrimSpace(configValue(cfg, "base_url"))
	token := strings.TrimSpace(firstConfigValue(cfg, "token", "api_key"))
	if mode == "" && (baseURL != "" || token != "") {
		mode = modeAPI
	}
	if mode == "s3" {
		mode = ""
	}
	if mode != "" && mode != modeAPI {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedMode, mode)
	}
	st := settings{
		mode:           mode,
		family:         strings.TrimSpace(configValue(cfg, "family")),
		bucket:         strings.TrimSpace(configValue(cfg, "bucket")),
		prefix:         strings.TrimSpace(configValue(cfg, "prefix")),
		region:         strings.TrimSpace(configValue(cfg, "region")),
		baseURL:        baseURL,
		apiPath:        strings.TrimSpace(configValue(cfg, "path")),
		token:          token,
		tenantID:       tenantID,
		runtimeID:      strings.TrimSpace(firstConfigValue(cfg, "runtime_id", "source_runtime_id")),
		roleARN:        strings.TrimSpace(configValue(cfg, "role_arn")),
		externalID:     strings.TrimSpace(configValue(cfg, "external_id")),
		assumeRoleARNs: strings.TrimSpace(configValue(cfg, sourceconfig.AWSAssumeRoleAllowlistKey)),
		perPage:        defaultPageSize,
	}
	if st.family == "" {
		st.family = familyAlert
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantIDRequired
	}
	rawPageSize, ok := cfg.Lookup("per_page")
	if !ok || strings.TrimSpace(rawPageSize) == "" {
		rawPageSize, ok = cfg.Lookup("page_size")
	}
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
	if st.mode == modeAPI {
		if st.baseURL == "" {
			return settings{}, ErrBaseURLRequired
		}
		if st.token == "" {
			return settings{}, ErrTokenRequired
		}
		baseURL, _, err := sourcehttp.NormalizeBaseURL(sourceID, st.baseURL, allowLoopback)
		if err != nil {
			return settings{}, err
		}
		st.baseURL = baseURL
		if st.apiPath == "" {
			st.apiPath = apiPathForFamily(st.family)
		}
		apiPath, err := sourcehttp.NormalizeRequestPath(sourceID, st.apiPath)
		if err != nil {
			return settings{}, err
		}
		st.apiPath = apiPath
		return st, nil
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
	if st.roleARN != "" {
		if err := validateAssumeRoleConfig(st); err != nil {
			return settings{}, err
		}
	} else if st.externalID != "" {
		return settings{}, fmt.Errorf("panopticon external_id requires role_arn")
	}
	if strings.ContainsRune(st.bucket, '/') {
		return settings{}, fmt.Errorf("%w: %q must not contain slashes", ErrInvalidBucket, st.bucket)
	}
	return st, nil
}

func validateAssumeRoleConfig(st settings) error {
	if len(awsRoleARNPattern.FindStringSubmatch(st.roleARN)) != 3 {
		return fmt.Errorf("panopticon role_arn must be an IAM role ARN")
	}
	if st.tenantID == "" {
		return fmt.Errorf("panopticon role_arn requires runtime tenant_id")
	}
	if !assumeRoleARNAllowed(st.tenantID, st.roleARN, st.assumeRoleARNs) {
		return fmt.Errorf("panopticon role_arn is not allowed")
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
	case familyAlert, familyCase, familyIOC:
		return true
	}
	return false
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func firstConfigValue(cfg sourcecdk.Config, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(configValue(cfg, key)); value != "" {
			return value
		}
	}
	return ""
}

func decodeCursor(cursor *cerebrov1.SourceCursor) panopticonCursor {
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return panopticonCursor{}
	}
	var decoded panopticonCursor
	if err := json.Unmarshal([]byte(opaque), &decoded); err == nil && decoded.Source == cursorSource {
		decoded.LastKey = strings.TrimSpace(decoded.LastKey)
		decoded.PartialKey = strings.TrimSpace(decoded.PartialKey)
		decoded.Watermark = strings.TrimSpace(decoded.Watermark)
		if decoded.PartialKey == "" || decoded.RecordOffset < 0 {
			decoded.RecordOffset = 0
		}
		return decoded
	}
	return panopticonCursor{LastKey: opaque}
}

func encodeCursor(cursor panopticonCursor) string {
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

func cursorWatermark(cursor panopticonCursor) time.Time {
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
		return nil, fmt.Errorf("build panopticon urn: %w", err)
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
			recordTenant := strings.TrimSpace(rec.TenantID)
			if recordTenant == "" {
				return sourcecdk.Pull{}, fmt.Errorf("invalid event in s3://%s/%s: tenant_id is required", st.bucket, key)
			}
			if recordTenant != rec.TenantID {
				return sourcecdk.Pull{}, fmt.Errorf("invalid event in s3://%s/%s: tenant_id must not have leading or trailing whitespace", st.bucket, key)
			}
			if recordTenant != st.tenantID {
				continue
			}
			if st.runtimeID != "" && strings.TrimSpace(rec.Attributes["runtime_id"]) != "" && strings.TrimSpace(rec.Attributes["runtime_id"]) != st.runtimeID {
				continue
			}
			event, err := buildEvent(rec, kind, schemaRef)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("convert event in s3://%s/%s: %w", st.bucket, key, err)
			}
			if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, sourcecdkEventContracts()); err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("invalid event in s3://%s/%s: %w", st.bucket, key, err)
			}
			if err := validateFamilyContract(event); err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("invalid event in s3://%s/%s: %w", st.bucket, key, err)
			}
			events = append(events, event)
			if rec.OccurredAt.After(watermark) {
				watermark = rec.OccurredAt
			}
			if len(events) >= maxEventsPerPull {
				nextRecord := recordIndex + 1
				if nextRecord < len(recs) {
					nextCursor = encodeCursor(panopticonCursor{
						LastKey:      lastKey,
						PartialKey:   key,
						RecordOffset: nextRecord,
						Watermark:    watermarkString(watermark, priorWatermark),
					})
				} else {
					lastKey = key
					if objectIndex < len(listing.Contents)-1 || awssdk.ToBool(listing.IsTruncated) {
						nextCursor = encodeCursor(panopticonCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
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
		nextCursor = encodeCursor(panopticonCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	checkpointCursor := nextCursor
	if checkpointCursor == "" && lastKey != "" {
		checkpointCursor = encodeCursor(panopticonCursor{LastKey: lastKey, Watermark: watermarkString(watermark, priorWatermark)})
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

func (s *Source) readArchive(ctx context.Context, client s3API, bucket, key string) ([]panopticonRecord, error) {
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

func readArchiveRecords(reader io.Reader, key string, decompressedLimitBytes int64) ([]panopticonRecord, error) {
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
	records := make([]panopticonRecord, 0, 64)
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
		var rec panopticonRecord
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

func buildEvent(rec panopticonRecord, kind, schemaRef string) (*primitives.Event, error) {
	if strings.TrimSpace(rec.ID) == "" {
		return nil, errors.New("id is required")
	}
	if rec.OccurredAt.IsZero() {
		return nil, errors.New("occurred_at is required")
	}
	if strings.TrimSpace(rec.SourceID) != sourceID {
		return nil, fmt.Errorf("source_id %q does not match %q", rec.SourceID, sourceID)
	}
	if strings.TrimSpace(rec.Kind) != kind {
		return nil, fmt.Errorf("kind %q does not match configured family kind %q", rec.Kind, kind)
	}
	if strings.TrimSpace(rec.SchemaRef) != schemaRef {
		return nil, fmt.Errorf("schema_ref %q does not match configured family schema_ref %q", rec.SchemaRef, schemaRef)
	}
	if rec.Payload == nil {
		return nil, errors.New("payload is required")
	}
	if err := validateRawFamilyContract(kind, rec.Attributes, rec.Payload); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(rec.Payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	tenantID := strings.TrimSpace(rec.TenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	attributes := make(map[string]string, len(rec.Attributes))
	for k, v := range rec.Attributes {
		attributes[k] = v
	}
	promotePayloadAttributes(kind, attributes, rec.Payload)
	return &primitives.Event{
		Id:         rec.ID,
		TenantId:   tenantID,
		SourceId:   rec.SourceID,
		Kind:       rec.Kind,
		SchemaRef:  rec.SchemaRef,
		OccurredAt: timestamppb.New(rec.OccurredAt.UTC()),
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func sourcecdkEventContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{
		{Kind: kindAlert, SchemaRef: schemaRefAlert, RequiredAttributes: []string{"alert_id", "severity", "status"}, RequiredPayloadFields: []string{"alert_id", "severity", "status", "title"}},
		{Kind: kindCase, SchemaRef: schemaRefCase, RequiredAttributes: []string{"case_id", "status"}, RequiredPayloadFields: []string{"case_id", "status", "title"}},
		{Kind: kindIOC, SchemaRef: schemaRefIOC, RequiredAttributes: []string{"ioc_id", "ioc_type", "value"}, RequiredPayloadFields: []string{"ioc_id", "ioc_type", "value"}},
	}
}

func validateRawFamilyContract(kind string, attributes map[string]string, payload map[string]interface{}) error {
	required, err := requiredAttributeKeys(kind)
	if err != nil {
		return err
	}
	for _, key := range required {
		attribute, ok := attributes[key]
		if !ok || strings.TrimSpace(attribute) == "" {
			return fmt.Errorf("kind %q missing required attribute %q", kind, key)
		}
		payloadValue := payloadAttributeString(payload[key])
		if payloadValue == "" {
			return fmt.Errorf("kind %q missing required payload field %q", kind, key)
		}
		if payloadValue != strings.TrimSpace(attribute) {
			return fmt.Errorf("kind %q attribute %q does not match payload", kind, key)
		}
	}
	if kind == kindAlert || kind == kindCase {
		if payloadAttributeString(payload["title"]) == "" {
			return fmt.Errorf("kind %q missing required payload field %q", kind, "title")
		}
	}
	return nil
}

func validateFamilyContract(event *primitives.Event) error {
	payload := map[string]interface{}{}
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return fmt.Errorf("decode payload object: %w", err)
	}
	required, err := requiredAttributeKeys(event.GetKind())
	if err != nil {
		return err
	}
	for _, key := range required {
		attribute := strings.TrimSpace(event.GetAttributes()[key])
		payloadValue := payloadAttributeString(payload[key])
		if attribute == "" {
			return fmt.Errorf("kind %q missing required attribute %q", event.GetKind(), key)
		}
		if payloadValue == "" {
			return fmt.Errorf("kind %q missing required payload field %q", event.GetKind(), key)
		}
		if payloadValue != attribute {
			return fmt.Errorf("kind %q attribute %q does not match payload", event.GetKind(), key)
		}
	}
	if event.GetKind() == kindAlert || event.GetKind() == kindCase {
		if payloadAttributeString(payload["title"]) == "" {
			return fmt.Errorf("kind %q missing required payload field %q", event.GetKind(), "title")
		}
	}
	return nil
}

func requiredAttributeKeys(kind string) ([]string, error) {
	switch kind {
	case kindAlert:
		return []string{"alert_id", "severity", "status"}, nil
	case kindCase:
		return []string{"case_id", "status"}, nil
	case kindIOC:
		return []string{"ioc_id", "ioc_type", "value"}, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}

func promotePayloadAttributes(kind string, attributes map[string]string, payload map[string]interface{}) {
	if len(payload) == 0 {
		return
	}
	for _, key := range payloadPromotedAttributeKeys(kind) {
		if _, ok := attributes[key]; ok {
			continue
		}
		if value := payloadAttributeString(payload[key]); value != "" {
			attributes[key] = value
		}
	}
}

func payloadPromotedAttributeKeys(kind string) []string {
	switch kind {
	case kindAlert:
		return []string{"alert_id", "severity", "status", "title"}
	case kindCase:
		return []string{"case_id", "status", "title"}
	case kindIOC:
		return []string{"ioc_id", "ioc_type", "value"}
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
