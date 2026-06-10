// Package panopticon implements the Cerebro source for Panopticon security
// operations events exposed by the Panopticon API.
package panopticon

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "panopticon"

	defaultPageSize  = 100
	maxPageSize      = 1000
	maxEventsPerPull = 1000
	cursorSourceAPI  = "panopticon/api/v1"
	modeAPI          = "api"

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
	// ErrInvalidPageSize is returned when page_size is not a positive integer.
	ErrInvalidPageSize = errors.New("invalid page_size")
	// ErrTenantIDRequired is returned when no explicit tenant scope is configured.
	ErrTenantIDRequired = errors.New("tenant_id is required")
	// ErrUnsupportedFamily is returned when the family is not one of the known kinds.
	ErrUnsupportedFamily = errors.New("unsupported family")
	// ErrBaseURLRequired is returned when no API base URL is configured.
	ErrBaseURLRequired = errors.New("base_url is required")
	// ErrTokenRequired is returned when no API bearer token is configured.
	ErrTokenRequired = errors.New("token is required")
	// ErrUnsupportedMode is returned when mode is not the API transport.
	ErrUnsupportedMode = errors.New("unsupported mode")
)

// Source emits panopticon.* events from the Panopticon API.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	family    string
	baseURL   string
	apiPath   string
	token     string
	tenantID  string
	runtimeID string
	perPage   int32
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

// New constructs the Panopticon API source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
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

// Check verifies that the configured Panopticon API family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns the URN for the configured family runtime instance.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages Panopticon API events since the cursor.
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

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{
		s.familyFor(familyAlert, kindAlert, schemaRefAlert, urnPrefixAlert),
		s.familyFor(familyCase, kindCase, schemaRefCase, urnPrefixCase),
		s.familyFor(familyIOC, kindIOC, schemaRefIOC, urnPrefixIOC),
	}
	return sourcecdk.NewFamilyEngine[settings](
		func(cfg sourcecdk.Config) (settings, error) {
			if s != nil && s.allowLoopbackBaseURL {
				return parseSettingsWithLoopback(cfg, true)
			}
			return parseSettings(cfg)
		},
		func(st settings) string { return st.family },
		families...,
	)
}

func (s *Source) familyFor(family, kind, schemaRef, urnPrefix string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, st settings) error {
			return s.checkAPI(ctx, st)
		},
		Discover: func(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
			return discoverAPIFamily(st, urnPrefix)
		},
		Read: func(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			return s.readAPIFamily(ctx, st, cursor, kind, schemaRef)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettingsWithLoopback(cfg, false)
}

func parseSettingsWithLoopback(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	mode := strings.ToLower(strings.TrimSpace(configValue(cfg, "mode")))
	if mode != "" && mode != modeAPI {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedMode, mode)
	}
	tenantID := strings.TrimSpace(configValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(configValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	st := settings{
		family:    strings.TrimSpace(configValue(cfg, "family")),
		baseURL:   strings.TrimSpace(configValue(cfg, "base_url")),
		apiPath:   strings.TrimSpace(configValue(cfg, "path")),
		token:     strings.TrimSpace(firstConfigValue(cfg, "token", "api_key")),
		tenantID:  tenantID,
		runtimeID: strings.TrimSpace(firstConfigValue(cfg, "runtime_id", "source_runtime_id")),
		perPage:   defaultPageSize,
	}
	if st.family == "" {
		st.family = familyAlert
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantIDRequired
	}
	if rawPageSize := strings.TrimSpace(firstConfigValue(cfg, "per_page", "page_size")); rawPageSize != "" {
		size, err := strconv.ParseInt(rawPageSize, 10, 32)
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
