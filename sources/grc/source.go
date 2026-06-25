package grc

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                = "grc"
	defaultProvider         = "vanta"
	defaultBaseURL          = "https://api.vanta.com"
	defaultReadScope        = "vanta-api.all:read"
	defaultPageSize         = 10
	maxPageSize             = 100
	httpTimeout             = 30 * time.Second
	maxBodyBytes            = 8 << 20
	tokenRefreshLeeway      = time.Minute
	defaultFamily           = familyControlTest
	familyFramework         = "framework"
	familyControl           = "control"
	familyControlTest       = "control_test"
	familyPolicy            = "policy"
	familyDocument          = "document"
	familyVendor            = "vendor"
	familyVulnerability     = "vulnerability"
	familyVulnerableAsset   = "vulnerable_asset"
	familyMonitoredComputer = "monitored_computer"
	familyRiskScenario      = "risk_scenario"
	familyPerson            = "person"
	familyUser              = "user"
	familyIntegration       = "integration"
)

// Source is the provider-neutral GRC source. Provider-specific APIs are kept
// behind drivers; emitted event kinds stay canonical grc.*.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	tokenRetryBackoffs   []time.Duration
	mu                   sync.Mutex
	tokenKey             string
	accessToken          string
	tokenExpiresAt       time.Time
}

type grcRecord struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type pageResponse struct {
	Results struct {
		PageInfo pageInfo          `json:"pageInfo"`
		Data     []json.RawMessage `json:"data"`
	} `json:"results"`
}

type pageInfo struct {
	EndCursor   string `json:"endCursor"`
	HasNextPage bool   `json:"hasNextPage"`
}

// New constructs the GRC source.
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

// Spec returns static metadata for the GRC source.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured GRC family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical GRC URNs for one configured family page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages provider records and emits canonical grc.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		s.family(familyFramework, "/v1/frameworks"),
		s.family(familyControl, "/v1/controls"),
		s.family(familyControlTest, "/v1/tests"),
		s.family(familyPolicy, "/v1/policies"),
		s.family(familyDocument, "/v1/documents"),
		s.family(familyVendor, "/v1/vendors"),
		s.family(familyVulnerability, "/v1/vulnerabilities"),
		s.family(familyVulnerableAsset, "/v1/vulnerable-assets"),
		s.family(familyMonitoredComputer, "/v1/monitored-computers"),
		s.family(familyRiskScenario, "/v1/risk-scenarios"),
		s.family(familyPerson, "/v1/people"),
		s.family(familyUser, "/v1/users"),
		s.family(familyIntegration, "/v1/integrations"),
	)
}

func (s *Source) family(name string, path string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, path, "", 1)
			if err != nil {
				return fmt.Errorf("grc %s for %s: %w", name, settings.provider, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, path, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("grc %s for %s: %w", name, settings.provider, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, path, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("grc %s for %s: %w", name, settings.provider, err)
			}
			return pullFromRecords(settings, name, records, next)
		},
	}
}

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]grcRecord, string, error) {
	token, err := s.token(ctx, settings)
	if err != nil {
		return nil, "", err
	}
	response, err := s.listPage(ctx, settings, path, cursor, pageSize, token)
	if err != nil && sourcecdk.IsHTTPStatus(err, http.StatusUnauthorized) {
		s.invalidateToken(settings)
		token, tokenErr := s.token(ctx, settings)
		if tokenErr != nil {
			return nil, "", tokenErr
		}
		response, err = s.listPage(ctx, settings, path, cursor, pageSize, token)
	}
	if err != nil {
		return nil, "", err
	}
	records := make([]grcRecord, 0, len(response.Results.Data))
	for _, raw := range response.Results.Data {
		record, err := parseRecord(settings.family, raw)
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	if response.Results.PageInfo.HasNextPage {
		return records, strings.TrimSpace(response.Results.PageInfo.EndCursor), nil
	}
	return records, "", nil
}

func (s *Source) listPage(ctx context.Context, settings settings, path string, cursor string, pageSize int, token string) (pageResponse, error) {
	query := url.Values{}
	query.Set("pageSize", strconv.Itoa(pageSize))
	if strings.TrimSpace(cursor) != "" {
		query.Set("pageCursor", strings.TrimSpace(cursor))
	}
	endpoint := settings.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return pageResponse{}, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	var response pageResponse
	if err := s.doJSON(req, &response); err != nil {
		return pageResponse{}, err
	}
	return response, nil
}

func (s *Source) doJSON(req *http.Request, target any) error {
	if s == nil {
		return fmt.Errorf("grc source is required")
	}
	client := s.client
	cloned := sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "grc",
		Timeout:       httpTimeout,
		AllowLoopback: s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
	resp, err := cloned.Do(req) // #nosec G704 -- requests are constructed from normalized GRC source URLs before this call.
	if err != nil {
		return fmt.Errorf("request %s: %w", req.URL.Path, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", req.URL.Path, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", req.URL.Path, err)
	}
	return nil
}

func parseRecord(family string, raw json.RawMessage) (grcRecord, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return grcRecord{}, fmt.Errorf("decode grc %s record: %w", family, err)
	}
	id := recordID(family, values, raw)
	return grcRecord{
		Raw:    append(json.RawMessage(nil), raw...),
		Values: values,
		ID:     id,
	}, nil
}

func urnsFor(settings settings, family string, records []grcRecord) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:grc_%s:%s:%s", settings.tenantID, family, settings.provider, record.ID))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family string, records []grcRecord, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec grcRecord) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec grcRecord) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family string, record grcRecord) *primitives.Event {
	occurredAt := occurredAtFor(family, record.Values)
	payload := append([]byte(nil), record.Raw...)
	return &primitives.Event{
		Id:         grcEventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "grc." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "grc/" + family + "/v1",
		Payload:    payload,
		Attributes: attributesFor(settings, family, record),
	}
}

func grcEventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{
		"grc",
		normalizeID(settings.provider),
		normalizeID(settings.tenantID),
		grcRuntimeScope(settings),
		normalizeID(family),
		normalizeID(recordID),
	}, "-")
}

func grcRuntimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func recordID(family string, values map[string]any, raw json.RawMessage) string {
	for _, key := range recordIDKeys(family) {
		if value := fieldString(values, key); value != "" {
			return normalizeID(value)
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func recordIDKeys(family string) []string {
	switch family {
	case familyRiskScenario:
		return []string{"riskId", "id"}
	case familyIntegration:
		return []string{"integrationId", "id"}
	case familyPerson:
		return []string{"id", "userId", "emailAddress"}
	case familyUser:
		return []string{"id", "email"}
	case familyVulnerableAsset:
		return []string{"id", "assetId", "targetId", "externalId", "name"}
	case familyMonitoredComputer:
		return []string{"id", "serialNumber", "udid"}
	default:
		return []string{"id", "externalId", "name"}
	}
}

func normalizeID(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "/", "_")
	return strings.ReplaceAll(value, " ", "_")
}

func occurredAtFor(family string, values map[string]any) time.Time {
	for _, key := range timestampKeys(family) {
		if value := fieldString(values, key); value != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
				return parsed.UTC()
			}
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Now().UTC()
}

func timestampKeys(family string) []string {
	switch family {
	case familyControl:
		return []string{"modificationDate", "creationDate"}
	case familyControlTest:
		return []string{"lastTestRunDate", "latestFlipDate"}
	case familyPolicy:
		return []string{"approvedAtDate"}
	case familyDocument:
		return []string{"uploadStatusDate"}
	case familyVendor:
		return []string{"lastSecurityReviewCompletionDate"}
	case familyVulnerability:
		return []string{"lastDetectedDate", "sourceDetectedDate", "firstDetectedDate"}
	case familyVulnerableAsset:
		return []string{"lastDetectedDate", "lastSeenDate", "updatedAt"}
	case familyMonitoredComputer:
		return []string{"lastCheckDate"}
	case familyRiskScenario:
		return []string{"identificationDate"}
	case familyPerson:
		return []string{"employment.startDate", "employment.endDate"}
	default:
		return nil
	}
}

func fieldString(values map[string]any, path string) string {
	value, ok := fieldValue(values, path)
	if !ok {
		return ""
	}
	return valueString(value)
}

func fieldValue(values map[string]any, path string) (any, bool) {
	var current any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func valueString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := valueString(item); value != "" {
				values = append(values, value)
			}
		}
		return strings.Join(values, ",")
	case map[string]any:
		for _, key := range []string{"displayName", "name", "id", "email"} {
			if value := valueString(typed[key]); value != "" {
				return value
			}
		}
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func arrayValue(values map[string]any, key string) []any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	return items
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error"} {
			if value := valueString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &sourcecdk.HTTPStatusError{Code: statusCode, Message: message}
}
