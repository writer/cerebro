package cerebro

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/sources/internal/s3ndjson"
)

//go:embed catalog.yaml
var catalogFS embed.FS

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

const (
	sourceID       = "cerebro"
	familyAccess   = "access"
	defaultRegion  = "us-east-1"
	defaultPerPage = 100
	maxPerPage     = 1000
	cursorSource   = "cerebro/access/s3-ndjson/v1"
	kindAccess     = "cerebro.api_access"
	schemaAccess   = "cerebro/api_access/v1"
)

var (
	ErrBucketRequired  = errors.New("bucket is required")
	ErrPrefixRequired  = errors.New("prefix is required")
	ErrTenantRequired  = errors.New("tenant_id is required")
	ErrInvalidBucket   = errors.New("invalid bucket")
	ErrInvalidPrefix   = errors.New("invalid prefix")
	ErrInvalidPageSize = errors.New("invalid page_size")
	ErrRoleNotAllowed  = errors.New("role_arn is not allowed")
	ErrTenantScope     = errors.New("tenant outside runtime tenant")
)

type Source struct {
	spec      *cerebrov1.SourceSpec
	families  *sourcecdk.FamilyEngine[settings]
	newClient func(context.Context, settings) (s3ndjson.API, error)
}

type settings struct {
	family         string
	bucket         string
	prefix         string
	region         string
	tenantID       string
	runtimeID      string
	roleARN        string
	externalID     string
	assumeRoleARNs string
	perPage        int32
}

func New() (*Source, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, err
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, newClient: defaultClientFactory}
	source.families, err = sourcecdk.NewFamilyEngine[settings](parseSettings, func(st settings) string { return st.family },
		sourcecdk.Family[settings]{
			Name: familyAccess,
			Check: func(ctx context.Context, st settings) error {
				client, err := source.newClient(ctx, st)
				if err != nil {
					return err
				}
				return s3ndjson.Check(ctx, client, ndjsonSettings(st))
			},
			Discover: func(_ context.Context, st settings) ([]sourcecdk.URN, error) {
				return s3ndjson.Discover(fmt.Sprintf("urn:cerebro:%s:cerebro_access:%s", st.tenantID, firstNonEmpty(st.runtimeID, familyAccess)))
			},
			Read: func(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				client, err := source.newClient(ctx, st)
				if err != nil {
					return sourcecdk.Pull{}, err
				}
				return s3ndjson.Read(ctx, client, ndjsonSettings(st), cursor)
			},
		})
	if err != nil {
		return nil, err
	}
	return source, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	tenantID := strings.TrimSpace(configValue(cfg, "tenant_id"))
	if runtimeTenant := strings.TrimSpace(configValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenant != "" {
		tenantID = runtimeTenant
	}
	perPage, err := s3ndjson.PositivePageSize(firstNonEmpty(configValue(cfg, "per_page"), configValue(cfg, "page_size")), defaultPerPage, maxPerPage)
	if err != nil {
		return settings{}, fmt.Errorf("%w: %w", ErrInvalidPageSize, err)
	}
	st := settings{
		family:         firstNonEmpty(configValue(cfg, "family"), familyAccess),
		bucket:         strings.TrimSpace(configValue(cfg, "bucket")),
		prefix:         strings.TrimSpace(configValue(cfg, "prefix")),
		region:         firstNonEmpty(configValue(cfg, "region"), defaultRegion),
		tenantID:       tenantID,
		runtimeID:      firstNonEmpty(configValue(cfg, "runtime_id"), configValue(cfg, "source_runtime_id")),
		roleARN:        strings.TrimSpace(configValue(cfg, "role_arn")),
		externalID:     strings.TrimSpace(configValue(cfg, "external_id")),
		assumeRoleARNs: strings.TrimSpace(configValue(cfg, sourceconfig.AWSAssumeRoleAllowlistKey)),
		perPage:        perPage,
	}
	if st.bucket == "" {
		return settings{}, ErrBucketRequired
	}
	if !s3ndjson.SafeS3Bucket(st.bucket) {
		return settings{}, ErrInvalidBucket
	}
	if st.prefix == "" {
		return settings{}, ErrPrefixRequired
	}
	if !strings.HasSuffix(st.prefix, "/") {
		st.prefix += "/"
	}
	if !s3ndjson.SafeS3Prefix(st.prefix) {
		return settings{}, ErrInvalidPrefix
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantRequired
	}
	if st.family != familyAccess {
		return settings{}, fmt.Errorf("%w: unsupported family %q", sourcecdk.ErrInvalidConfig, st.family)
	}
	if st.roleARN != "" && !roleAllowed(st) {
		return settings{}, ErrRoleNotAllowed
	}
	if st.roleARN == "" && st.externalID != "" {
		return settings{}, fmt.Errorf("cerebro external_id requires role_arn")
	}
	return st, nil
}

func defaultClientFactory(ctx context.Context, st settings) (s3ndjson.API, error) {
	return s3ndjson.NewClient(ctx, ndjsonSettings(st))
}

func ndjsonSettings(st settings) s3ndjson.Settings {
	return s3ndjson.Settings{
		Source:           cursorSource,
		Bucket:           st.bucket,
		Prefix:           st.prefix,
		Region:           st.region,
		RoleARN:          st.roleARN,
		ExternalID:       st.externalID,
		SessionName:      "cerebro-product-source",
		PerPage:          st.perPage,
		MarshalRawRecord: func(raw json.RawMessage) (*primitives.Event, error) { return accessEvent(st, raw) },
	}
}

func accessEvent(st settings, raw json.RawMessage) (*primitives.Event, error) {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if stringField(body, "name") != "cerebro.api.access" {
		return nil, fmt.Errorf("not a cerebro.api.access telemetry event")
	}
	occurredAt, err := parseTelemetryTime(stringField(body, "ts"))
	if err != nil {
		return nil, err
	}
	attrs := accessAttributes(body)
	event := &cerebrov1.EventEnvelope{
		Id:         accessEventID(body, raw),
		TenantId:   firstNonEmpty(attrs["tenant_id"], st.tenantID),
		SourceId:   sourceID,
		Kind:       kindAccess,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  schemaAccess,
		Payload:    []byte(raw),
		Attributes: attrs,
	}
	if event.TenantId != st.tenantID {
		return nil, fmt.Errorf("%w: %q != %q", ErrTenantScope, event.TenantId, st.tenantID)
	}
	return event, sourcecdk.ValidateEventEnvelope(event)
}

func accessAttributes(body map[string]any) map[string]string {
	attrs := map[string]string{
		"event_type":     firstNonEmpty(stringField(body, "route"), stringField(body, "connect_procedure"), "api_access"),
		"outcome_result": stringField(body, "outcome"),
		"route":          stringField(body, "route"),
		"method":         stringField(body, "method"),
		"source_ip":      firstNonEmpty(stringField(body, "client_ip"), stringField(body, "remote_ip")),
		"actor_user":     stringField(body, "principal"),
		"resource_type":  "cerebro_api_route",
	}
	for _, key := range []string{"auth_mode", "client_id", "connect_code", "connect_procedure", "credential_id", "denial_reason", "device_id", "duration_ms", "effective_status_code", "effective_tenant_id", "operation_family", "operation_type", "principal", "principal_tenant_id", "remote_ip", "request_id", "requested_tenant_id", "risk_level", "risk_score", "sensitive_action", "status", "status_code", "tenant_id", "tenant_mismatch"} {
		if value := stringField(body, key); value != "" {
			attrs[key] = value
		}
	}
	return attrs
}

func accessEventID(body map[string]any, raw []byte) string {
	hash := sha256.Sum256(raw)
	return "cerebro-api-access-" + firstNonEmpty(stringField(body, "request_id"), hex.EncodeToString(hash[:8]))
}

func parseTelemetryTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("ts is required")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func roleAllowed(st settings) bool {
	if !awsRoleARNPattern.MatchString(st.roleARN) || st.tenantID == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(st.assumeRoleARNs, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' ' }) {
		tenant, arn, ok := strings.Cut(strings.TrimSpace(value), "=")
		if ok && strings.TrimSpace(tenant) == st.tenantID && strings.TrimSpace(arn) == st.roleARN {
			return true
		}
	}
	return false
}

func stringField(body map[string]any, key string) string {
	switch value := body[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
