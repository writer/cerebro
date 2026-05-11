package grc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID            = "grc"
	defaultProvider     = "vanta"
	defaultBaseURL      = "https://api.vanta.com"
	defaultReadScope    = "vanta-api.all:read"
	defaultPageSize     = 10
	maxPageSize         = 100
	httpTimeout         = 30 * time.Second
	maxBodyBytes        = 8 << 20
	tokenRefreshLeeway  = time.Minute
	defaultFamily       = familyControlTest
	familyFramework     = "framework"
	familyControl       = "control"
	familyControlTest   = "control_test"
	familyPolicy        = "policy"
	familyDocument      = "document"
	familyVendor        = "vendor"
	familyVulnerability = "vulnerability"
	familyRiskScenario  = "risk_scenario"
	familyPerson        = "person"
	familyUser          = "user"
	familyIntegration   = "integration"
)

// Source is the provider-neutral GRC source. Provider-specific APIs are kept
// behind drivers; emitted event kinds stay canonical grc.*.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	mu                   sync.Mutex
	tokenKey             string
	accessToken          string
	tokenExpiresAt       time.Time
}

type settings struct {
	provider     string
	tenantID     string
	family       string
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	perPage      int
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

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string {
	return e.message
}

func (e *responseError) StatusCode() int {
	return e.statusCode
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

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	resolved := settings{
		provider:     configValue(cfg, "provider"),
		tenantID:     configValue(cfg, "tenant_id"),
		family:       configValue(cfg, "family"),
		baseURL:      configValue(cfg, "base_url"),
		tokenURL:     configValue(cfg, "token_url"),
		clientID:     configValue(cfg, "client_id"),
		clientSecret: configValue(cfg, "client_secret"),
		scope:        configValue(cfg, "scope"),
		perPage:      defaultPageSize,
	}
	if resolved.provider == "" {
		resolved.provider = defaultProvider
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	if resolved.baseURL == "" {
		resolved.baseURL = defaultBaseURL
	}
	if resolved.scope == "" {
		resolved.scope = defaultReadScope
	}
	if resolved.tenantID == "" {
		return resolved, fmt.Errorf("grc tenant_id is required")
	}
	if resolved.provider != defaultProvider {
		return resolved, fmt.Errorf("grc provider %q is not supported", resolved.provider)
	}
	if !isSupportedFamily(resolved.family) {
		return resolved, fmt.Errorf("grc family must be one of %s", strings.Join(supportedFamilies(), ", "))
	}
	normalizedBase, err := normalizeBaseURL(resolved.baseURL, allowLoopbackBaseURL)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	if resolved.tokenURL == "" {
		resolved.tokenURL = normalizedBase + "/oauth/token"
	} else {
		normalizedTokenURL, err := normalizeAbsoluteURL(resolved.tokenURL, allowLoopbackBaseURL)
		if err != nil {
			return resolved, err
		}
		resolved.tokenURL = normalizedTokenURL
	}
	if resolved.clientID == "" {
		return resolved, fmt.Errorf("grc client_id is required")
	}
	if resolved.clientSecret == "" {
		return resolved, fmt.Errorf("grc client_secret is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse grc per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("grc per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	return resolved, nil
}

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]grcRecord, string, error) {
	token, err := s.token(ctx, settings)
	if err != nil {
		return nil, "", err
	}
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
		return nil, "", fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	var response pageResponse
	if err := s.doJSON(req, &response); err != nil {
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

func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	cacheKey := strings.Join([]string{settings.provider, settings.tokenURL, settings.clientID, settings.scope}, "\x00")
	now := time.Now()
	s.mu.Lock()
	if s.tokenKey == cacheKey && s.accessToken != "" && now.Add(tokenRefreshLeeway).Before(s.tokenExpiresAt) {
		token := s.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	body, err := json.Marshal(map[string]string{
		"client_id":     settings.clientID,
		"client_secret": settings.clientSecret,
		"scope":         settings.scope,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return "", fmt.Errorf("marshal grc token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build grc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var response tokenResponse
	if err := s.doJSON(req, &response); err != nil {
		return "", fmt.Errorf("request grc token: %w", err)
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return "", fmt.Errorf("grc token response missing access_token")
	}
	expiresIn := response.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	s.mu.Lock()
	s.tokenKey = cacheKey
	s.accessToken = response.AccessToken
	s.tokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.mu.Unlock()
	return response.AccessToken, nil
}

func (s *Source) doJSON(req *http.Request, target any) error {
	if s == nil {
		return fmt.Errorf("grc source is required")
	}
	client := s.client
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	cloned := *client
	if cloned.CheckRedirect == nil {
		cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	transport := cloned.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	cloned.Transport = safeRoundTripper{
		base:          transport,
		allowLoopback: s.allowLoopbackBaseURL,
		lookupIPAddrs: lookupIPAddrs(s),
	}
	resp, err := cloned.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", req.URL.Path, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := readLimitedBody(resp.Body)
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
	if len(records) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := eventFromRecord(settings, family, record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointCursor(next, records[len(records)-1].ID),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func eventFromRecord(settings settings, family string, record grcRecord) (*primitives.Event, error) {
	occurredAt := occurredAtFor(family, record.Values)
	payload := append([]byte(nil), record.Raw...)
	return &primitives.Event{
		Id:         "grc-" + settings.provider + "-" + family + "-" + record.ID,
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "grc." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "grc/" + family + "/v1",
		Payload:    payload,
		Attributes: attributesFor(settings, family, record),
	}, nil
}

func attributesFor(settings settings, family string, record grcRecord) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"provider":        settings.provider,
		"source_provider": settings.provider,
		"external_id":     record.ID,
	}
	switch family {
	case familyFramework:
		copyFields(attrs, values, map[string]string{
			"framework_id":           "id",
			"display_name":           "displayName",
			"name":                   "shorthandName",
			"description":            "description",
			"num_controls_completed": "numControlsCompleted",
			"num_controls_total":     "numControlsTotal",
			"num_documents_passing":  "numDocumentsPassing",
			"num_documents_total":    "numDocumentsTotal",
			"num_tests_passing":      "numTestsPassing",
			"num_tests_total":        "numTestsTotal",
		})
	case familyControl:
		copyFields(attrs, values, map[string]string{
			"control_id":          "id",
			"control_external_id": "externalId",
			"name":                "name",
			"description":         "description",
			"source":              "source",
			"domains":             "domains",
			"owner_id":            "owner.id",
			"role":                "role",
			"created_at":          "creationDate",
			"modified_at":         "modificationDate",
		})
	case familyControlTest:
		copyFields(attrs, values, map[string]string{
			"test_id":                 "id",
			"name":                    "name",
			"description":             "description",
			"last_run_at":             "lastTestRunDate",
			"latest_flip_at":          "latestFlipDate",
			"failure_description":     "failureDescription",
			"remediation_description": "remediationDescription",
			"version":                 "version",
			"category":                "category",
			"integrations":            "integrations",
			"status":                  "status",
			"owner_id":                "owner.id",
		})
	case familyPolicy:
		copyFields(attrs, values, map[string]string{
			"policy_id":             "id",
			"name":                  "name",
			"description":           "description",
			"status":                "status",
			"approved_at":           "approvedAtDate",
			"latest_version_status": "latestVersion.status",
		})
	case familyDocument:
		copyFields(attrs, values, map[string]string{
			"document_id":        "id",
			"owner_id":           "ownerId",
			"category":           "category",
			"description":        "description",
			"is_sensitive":       "isSensitive",
			"title":              "title",
			"upload_status":      "uploadStatus",
			"upload_status_date": "uploadStatusDate",
			"url":                "url",
		})
	case familyVendor:
		copyFields(attrs, values, map[string]string{
			"vendor_id":                            "id",
			"name":                                 "name",
			"website_url":                          "websiteUrl",
			"account_manager_email":                "accountManagerEmail",
			"services_provided":                    "servicesProvided",
			"security_owner_user_id":               "securityOwnerUserId",
			"business_owner_user_id":               "businessOwnerUserId",
			"contract_start_date":                  "contractStartDate",
			"contract_renewal_date":                "contractRenewalDate",
			"contract_termination_date":            "contractTerminationDate",
			"next_security_review_due_date":        "nextSecurityReviewDueDate",
			"last_security_review_completion_date": "lastSecurityReviewCompletionDate",
			"category":                             "category.displayName",
			"status":                               "status",
			"inherent_risk_level":                  "inherentRiskLevel",
			"residual_risk_level":                  "residualRiskLevel",
		})
	case familyVulnerability:
		copyFields(attrs, values, map[string]string{
			"vulnerability_id":    "id",
			"name":                "name",
			"description":         "description",
			"integration_id":      "integrationId",
			"package_identifier":  "packageIdentifier",
			"package":             "packageIdentifier",
			"vulnerability_type":  "vulnerabilityType",
			"target_id":           "targetId",
			"first_detected_at":   "firstDetectedDate",
			"source_detected_at":  "sourceDetectedDate",
			"last_detected_at":    "lastDetectedDate",
			"severity":            "severity",
			"cvss_severity_score": "cvssSeverityScore",
			"scanner_score":       "scannerScore",
			"is_fixable":          "isFixable",
			"fixed_version":       "fixedVersion",
			"remediate_by_date":   "remediateByDate",
			"external_url":        "externalURL",
			"scan_source":         "scanSource",
		})
	case familyRiskScenario:
		copyFields(attrs, values, map[string]string{
			"risk_id":             "riskId",
			"description":         "description",
			"likelihood":          "likelihood",
			"impact":              "impact",
			"residual_likelihood": "residualLikelihood",
			"residual_impact":     "residualImpact",
			"categories":          "categories",
			"cia_categories":      "ciaCategories",
			"treatment":           "treatment",
			"owner":               "owner",
			"note":                "note",
			"risk_register":       "riskRegister",
			"review_status":       "reviewStatus",
			"type":                "type",
			"identified_at":       "identificationDate",
		})
	case familyPerson:
		copyFields(attrs, values, map[string]string{
			"person_id":             "id",
			"user_id":               "userId",
			"email":                 "emailAddress",
			"employment_end_date":   "employment.endDate",
			"job_title":             "employment.jobTitle",
			"employment_start_date": "employment.startDate",
			"employment_status":     "employment.status",
			"group_ids":             "groupIds",
		})
	case familyUser:
		copyFields(attrs, values, map[string]string{
			"user_id":      "id",
			"email":        "email",
			"display_name": "displayName",
			"is_active":    "isActive",
		})
	case familyIntegration:
		copyFields(attrs, values, map[string]string{
			"integration_id": "integrationId",
			"display_name":   "displayName",
			"resource_kinds": "resourceKinds",
		})
		attrs["connection_count"] = strconv.Itoa(len(arrayValue(values, "connections")))
		attrs["disabled_connection_count"] = strconv.Itoa(countConnections(values, true, false))
		attrs["connection_error_count"] = strconv.Itoa(countConnections(values, false, true))
	}
	return trimEmpty(attrs)
}

func copyFields(attrs map[string]string, values map[string]any, mapping map[string]string) {
	for target, source := range mapping {
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
		}
	}
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
	return values
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
		return []string{"lastSecurityReviewCompletionDate", "nextSecurityReviewDueDate", "contractRenewalDate"}
	case familyVulnerability:
		return []string{"lastDetectedDate", "sourceDetectedDate", "firstDetectedDate", "remediateByDate"}
	case familyRiskScenario:
		return []string{"identificationDate"}
	case familyPerson:
		return []string{"employment.startDate", "employment.endDate"}
	default:
		return nil
	}
}

func checkpointCursor(next string, fallback string) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(fallback)
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

func countConnections(values map[string]any, disabled bool, errored bool) int {
	count := 0
	for _, item := range arrayValue(values, "connections") {
		connection, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isDisabled, _ := connection["isDisabled"].(bool)
		hasError := strings.TrimSpace(valueString(connection["connectionErrorMessage"])) != ""
		if disabled && isDisabled {
			count++
		}
		if errored && hasError {
			count++
		}
	}
	return count
}

func supportedFamilies() []string {
	return []string{
		familyFramework,
		familyControl,
		familyControlTest,
		familyPolicy,
		familyDocument,
		familyVendor,
		familyVulnerability,
		familyRiskScenario,
		familyPerson,
		familyUser,
		familyIntegration,
	}
}

func isSupportedFamily(family string) bool {
	for _, candidate := range supportedFamilies() {
		if family == candidate {
			return true
		}
	}
	return false
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	normalized, err := normalizeAbsoluteURL(raw, allowLoopback)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(normalized, "/"), nil
}

func normalizeAbsoluteURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse grc url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && isLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("grc url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("grc url must include a host")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

type safeRoundTripper struct {
	base          http.RoundTripper
	allowLoopback bool
	lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)
}

func (rt safeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil {
		if err := rejectResolvedUnsafeHost(req.Context(), req.URL.Hostname(), rt.allowLoopback, rt.lookupIPAddrs); err != nil {
			return nil, err
		}
	}
	return rt.base.RoundTrip(req)
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func rejectResolvedUnsafeHost(ctx context.Context, host string, allowLoopback bool, lookup func(context.Context, string) ([]net.IPAddr, error)) error {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if normalized == "" {
		return fmt.Errorf("grc host is required")
	}
	if ip := net.ParseIP(normalized); ip != nil {
		if unsafeIP(ip, allowLoopback) {
			return fmt.Errorf("grc host must not target loopback, private, or link-local addresses")
		}
		return nil
	}
	addrs, err := lookup(ctx, normalized)
	if err != nil {
		return fmt.Errorf("resolve grc host %q: %w", normalized, err)
	}
	for _, addr := range addrs {
		if unsafeIP(addr.IP, allowLoopback) {
			return fmt.Errorf("grc host must not resolve to loopback, private, or link-local addresses")
		}
	}
	return nil
}

func unsafeIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if allowLoopback && ip.IsLoopback() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readLimitedBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBodyBytes)
	}
	return data, nil
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
	return &responseError{statusCode: statusCode, message: message}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}
