package grc

import (
	"bytes"
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
	sourceID              = "grc"
	defaultProvider       = "vanta"
	defaultBaseURL        = "https://api.vanta.com"
	defaultReadScope      = "vanta-api.all:read"
	defaultPageSize       = 10
	maxPageSize           = 100
	httpTimeout           = 30 * time.Second
	maxBodyBytes          = 8 << 20
	tokenRefreshLeeway    = time.Minute
	defaultFamily         = familyControlTest
	familyFramework       = "framework"
	familyControl         = "control"
	familyControlTest     = "control_test"
	familyPolicy          = "policy"
	familyDocument        = "document"
	familyVendor          = "vendor"
	familyVulnerability   = "vulnerability"
	familyVulnerableAsset = "vulnerable_asset"
	familyRiskScenario    = "risk_scenario"
	familyPerson          = "person"
	familyUser            = "user"
	familyIntegration     = "integration"
)

var defaultTokenRetryBackoffs = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second}

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
		s.family(familyVulnerableAsset, "/v1/vulnerable-assets"),
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
		tenantID:     firstNonEmptyString(configValue(cfg, "tenant_id"), configValue(cfg, "__cerebro_runtime_tenant_id")),
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
	if err := validateTrustedVantaOrigin(normalizedBase, allowLoopbackBaseURL); err != nil {
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
		if err := validateTrustedVantaOrigin(normalizedTokenURL, allowLoopbackBaseURL); err != nil {
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

func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	cacheKey := tokenCacheKey(settings)
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

	var response tokenResponse
	backoffs := s.tokenBackoffs()
	for attempt := 0; ; attempt++ {
		response, err = s.requestToken(ctx, settings, body)
		if err == nil {
			break
		}
		if !sourcecdk.IsRetryableHTTPStatus(err) || attempt >= len(backoffs) {
			return "", fmt.Errorf("request grc token: %w", err)
		}
		if sleepErr := sourcecdk.SleepContext(ctx, backoffs[attempt]); sleepErr != nil {
			return "", fmt.Errorf("request grc token retry: %w", sleepErr)
		}
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

func (s *Source) requestToken(ctx context.Context, settings settings, body []byte) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, bytes.NewReader(body))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("build grc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var response tokenResponse
	if err := s.doJSON(req, &response); err != nil {
		return tokenResponse{}, err
	}
	return response, nil
}

func (s *Source) tokenBackoffs() []time.Duration {
	if s != nil && s.tokenRetryBackoffs != nil {
		return s.tokenRetryBackoffs
	}
	return defaultTokenRetryBackoffs
}

func (s *Source) invalidateToken(settings settings) {
	if s == nil {
		return
	}
	cacheKey := tokenCacheKey(settings)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenKey != cacheKey {
		return
	}
	s.accessToken = ""
	s.tokenExpiresAt = time.Time{}
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
	if len(records) == 0 {
		pull := sourcecdk.Pull{}
		if strings.TrimSpace(next) != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
		}
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		events = append(events, eventFromRecord(settings, family, record))
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
			"control_id":              "controlId",
			"control_ids":             "controlIds",
			"control_external_id":     "controlExternalId",
			"control_external_ids":    "controlExternalIds",
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
		copyControlReferenceFields(attrs, values)
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
			"package_purl":        "packageIdentifier",
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
	case familyVulnerableAsset:
		copyFirstField(attrs, values, "asset_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "resource_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "hostname", "hostname", "host", "dnsName", "fqdn")
		copyFirstField(attrs, values, "ip", "ipAddress", "publicIp", "publicIP", "ip")
		copyFirstField(attrs, values, "asset_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "resource_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "integration_id", "integrationId", "integration.id")
		copyFirstField(attrs, values, "external_url", "externalURL", "url")
		copyFirstField(attrs, values, "target_url", "url", "externalURL")
		copyFirstField(attrs, values, "operating_system", "operatingSystem", "os")
		copyFirstField(attrs, values, "last_detected_at", "lastDetectedDate", "lastSeenDate", "updatedAt")
		copyVulnerableAssetPlatformReferences(attrs, values)
		copyVulnerableAssetReferences(attrs, values)
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
			"department":            "employment.department",
			"employment_end_date":   "employment.endDate",
			"employee_number":       "employment.employeeNumber",
			"job_title":             "employment.jobTitle",
			"manager":               "employment.manager",
			"manager_id":            "employment.managerId",
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

func tokenCacheKey(settings settings) string {
	secretHash := sha256.Sum256([]byte(settings.clientSecret))
	return strings.Join([]string{
		settings.provider,
		settings.tenantID,
		settings.baseURL,
		settings.tokenURL,
		settings.clientID,
		settings.scope,
		hex.EncodeToString(secretHash[:]),
	}, "\x00")
}
func copyFields(attrs map[string]string, values map[string]any, mapping map[string]string) {
	for target, source := range mapping {
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
		}
	}
}

func copyFirstField(attrs map[string]string, values map[string]any, target string, sources ...string) {
	if strings.TrimSpace(attrs[target]) != "" {
		return
	}
	for _, source := range sources {
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
			return
		}
	}
}

func copyControlReferenceFields(attrs map[string]string, values map[string]any) {
	copyFirstField(attrs, values, "control_id", "controlID", "control.id")
	copyFirstField(attrs, values, "control_external_id", "controlExternalID", "control.externalId", "control.externalID")
	if references := joinedControlReferences(values, "controls"); references != "" {
		attrs["control_references"] = references
	}
	if ids := joinedObjectFieldValues(values, "controls", "id"); ids != "" {
		attrs["control_ids"] = ids
		if strings.TrimSpace(attrs["control_id"]) == "" {
			attrs["control_id"] = firstDelimitedValue(ids)
		}
	}
	if externalIDs := joinedObjectFieldValues(values, "controls", "externalId", "externalID"); externalIDs != "" {
		attrs["control_external_ids"] = externalIDs
		if strings.TrimSpace(attrs["control_external_id"]) == "" {
			attrs["control_external_id"] = firstDelimitedValue(externalIDs)
		}
	}
}

type vulnerableAssetPlatformReference struct {
	Provider          string `json:"provider,omitempty"`
	ResourceID        string `json:"resource_id,omitempty"`
	ResourceName      string `json:"resource_name,omitempty"`
	ResourceType      string `json:"resource_type,omitempty"`
	ScannerResourceID string `json:"scanner_resource_id,omitempty"`
	Hostnames         string `json:"hostnames,omitempty"`
	IPs               string `json:"ips,omitempty"`
}

func copyVulnerableAssetPlatformReferences(attrs map[string]string, values map[string]any) {
	refs := vulnerableAssetPlatformReferences(values)
	if len(refs) == 0 {
		return
	}
	if raw, err := json.Marshal(refs); err == nil {
		attrs["platform_asset_refs"] = string(raw)
	}
	first := refs[0]
	addAttrIfMissing(attrs, "platform_provider", first.Provider)
	addAttrIfMissing(attrs, "platform_resource_id", first.ResourceID)
	addAttrIfMissing(attrs, "platform_resource_name", first.ResourceName)
	addAttrIfMissing(attrs, "platform_resource_type", first.ResourceType)
	addAttrIfMissing(attrs, "scanner_resource_id", first.ScannerResourceID)
	hostnames := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.Hostnames })
	ips := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.IPs })
	if hostnames != "" {
		attrs["hostnames"] = hostnames
		addAttrIfMissing(attrs, "hostname", firstDelimitedValue(hostnames))
	}
	if ips != "" {
		attrs["ip_addresses"] = ips
		addAttrIfMissing(attrs, "ip", firstDelimitedValue(ips))
	}
}

func vulnerableAssetPlatformReferences(values map[string]any) []vulnerableAssetPlatformReference {
	items := arrayValue(values, "scanners")
	refs := make([]vulnerableAssetPlatformReference, 0, len(items))
	seen := map[string]struct{}{}
	resourceName := firstNonEmptyString(fieldString(values, "displayName"), fieldString(values, "name"), fieldString(values, "hostname"), fieldString(values, "host"))
	resourceType := firstNonEmptyString(fieldString(values, "resourceType"), fieldString(values, "assetType"), fieldString(values, "type"))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		provider := firstNonEmptyString(fieldString(object, "integrationId"), fieldString(object, "integration.id"), fieldString(object, "provider"))
		resourceID := firstNonEmptyString(fieldString(object, "targetId"), fieldString(object, "resourceArn"), fieldString(object, "arn"))
		scannerResourceID := fieldString(object, "resourceId")
		if resourceID == "" && platformResourceIDLikelyExternal(scannerResourceID) {
			resourceID = scannerResourceID
		}
		hostnames := joinedPlatformObjectFieldValues(object, "hostnames", "fqdns", "hostname", "fqdn")
		ips := joinedPlatformObjectFieldValues(object, "ipv4s", "ipv6s", "ipAddresses", "ipAddress", "publicIp", "publicIP")
		if provider == "" && resourceID == "" && scannerResourceID == "" && hostnames == "" && ips == "" {
			continue
		}
		ref := vulnerableAssetPlatformReference{
			Provider:          provider,
			ResourceID:        resourceID,
			ResourceName:      resourceName,
			ResourceType:      firstNonEmptyString(fieldString(object, "resourceType"), fieldString(object, "assetType"), resourceType),
			ScannerResourceID: scannerResourceID,
			Hostnames:         normalizeDelimitedValues(hostnames),
			IPs:               normalizeDelimitedValues(ips),
		}
		key := strings.Join([]string{ref.Provider, ref.ResourceID, ref.ScannerResourceID, ref.Hostnames, ref.IPs}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func addAttrIfMissing(attrs map[string]string, key string, value string) {
	if strings.TrimSpace(attrs[key]) == "" {
		if value = strings.TrimSpace(value); value != "" {
			attrs[key] = value
		}
	}
}

func platformResourceIDLikelyExternal(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "arn:") || strings.Contains(value, "://") || strings.Contains(value, "/")
}

func joinedPlatformObjectFieldValues(object map[string]any, names ...string) string {
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, splitDelimitedValues(fieldString(object, name))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func joinedUniqueDelimitedValues(refs []vulnerableAssetPlatformReference, selectValue func(vulnerableAssetPlatformReference) string) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, splitDelimitedValues(selectValue(ref))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func normalizeDelimitedValues(value string) string {
	return strings.Join(uniqueStrings(splitDelimitedValues(value)), ",")
}

func splitDelimitedValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func copyVulnerableAssetReferences(attrs map[string]string, values map[string]any) {
	if ids := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "id", "vulnerabilityId"),
		fieldString(values, "vulnerabilityIds"),
	); ids != "" {
		attrs["vulnerability_ids"] = ids
	}
	if names := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "name", "title"),
		fieldString(values, "vulnerabilityNames"),
	); names != "" {
		attrs["vulnerability_names"] = names
	}
	if packages := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "packageIdentifier", "package", "packagePurl"),
		fieldString(values, "packageIdentifiers"),
		fieldString(values, "packages"),
	); packages != "" {
		attrs["package_identifiers"] = packages
	}
	if references := joinedVulnerableAssetReferences(values); references != "" {
		attrs["vulnerability_package_refs"] = references
	}
}

func joinedControlReferences(values map[string]any, arrayKey string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := valueString(object["id"])
		externalID := firstNonEmptyString(valueString(object["externalId"]), valueString(object["externalID"]))
		if id == "" && externalID == "" {
			continue
		}
		if id == "" {
			id = externalID
		}
		pair := id + "=" + externalID
		if _, exists := seen[pair]; exists {
			continue
		}
		seen[pair] = struct{}{}
		collected = append(collected, pair)
	}
	return strings.Join(collected, ";")
}

func joinedVulnerableAssetReferences(values map[string]any) string {
	items := arrayValue(values, "vulnerabilities")
	refs := make([]map[string]string, 0, len(items))
	seen := map[string]struct{}{}
	vulnerabilityIDs := splitVulnerableAssetReferenceValues(fieldString(values, "vulnerabilityIds"))
	vulnerabilityNames := splitVulnerableAssetReferenceValues(fieldString(values, "vulnerabilityNames"))
	packageIdentifiers := splitVulnerableAssetReferenceValues(firstNonEmptyString(fieldString(values, "packageIdentifiers"), fieldString(values, "packages")))
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vulnerabilityID := firstNonEmptyString(valueString(object["id"]), valueString(object["vulnerabilityId"]), valueAt(vulnerabilityIDs, i))
		vulnerabilityName := firstNonEmptyString(valueString(object["name"]), valueString(object["title"]), valueAt(vulnerabilityNames, i))
		packageIdentifier := firstNonEmptyString(valueString(object["packageIdentifier"]), valueString(object["package"]), valueString(object["packagePurl"]), valueAt(packageIdentifiers, i))
		if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
			continue
		}
		key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ref := map[string]string{}
		if vulnerabilityID != "" {
			ref["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName != "" {
			ref["vulnerability_name"] = vulnerabilityName
		}
		if packageIdentifier != "" {
			ref["package_identifier"] = packageIdentifier
		}
		refs = append(refs, ref)
	}
	for i, ref := range refs {
		if ref["vulnerability_id"] == "" {
			if vulnerabilityID := valueAt(vulnerabilityIDs, i); vulnerabilityID != "" {
				ref["vulnerability_id"] = vulnerabilityID
			}
		}
		if ref["vulnerability_name"] == "" {
			if vulnerabilityName := valueAt(vulnerabilityNames, i); vulnerabilityName != "" {
				ref["vulnerability_name"] = vulnerabilityName
			}
		}
		if ref["package_identifier"] == "" {
			if packageIdentifier := valueAt(packageIdentifiers, i); packageIdentifier != "" {
				ref["package_identifier"] = packageIdentifier
			}
		}
	}
	for i := len(refs); i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
		vulnerabilityID := valueAt(vulnerabilityIDs, i)
		vulnerabilityName := valueAt(vulnerabilityNames, i)
		packageIdentifier := valueAt(packageIdentifiers, i)
		if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
			continue
		}
		key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ref := map[string]string{}
		if vulnerabilityID != "" {
			ref["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName != "" {
			ref["vulnerability_name"] = vulnerabilityName
		}
		if packageIdentifier != "" {
			ref["package_identifier"] = packageIdentifier
		}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		for i := 0; i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
			vulnerabilityID := valueAt(vulnerabilityIDs, i)
			vulnerabilityName := valueAt(vulnerabilityNames, i)
			packageIdentifier := valueAt(packageIdentifiers, i)
			if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
				continue
			}
			key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ref := map[string]string{}
			if vulnerabilityID != "" {
				ref["vulnerability_id"] = vulnerabilityID
			}
			if vulnerabilityName != "" {
				ref["vulnerability_name"] = vulnerabilityName
			}
			if packageIdentifier != "" {
				ref["package_identifier"] = packageIdentifier
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return ""
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return string(raw)
}

func splitVulnerableAssetReferenceValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func valueAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func joinedObjectFieldValues(values map[string]any, arrayKey string, fields ...string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range fields {
			value := valueString(object[field])
			if value == "" {
				continue
			}
			if _, exists := seen[value]; !exists {
				collected = append(collected, value)
				seen[value] = struct{}{}
			}
			break
		}
	}
	return strings.Join(collected, ",")
}

func firstDelimitedValue(value string) string {
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
	case familyVulnerableAsset:
		return []string{"id", "assetId", "targetId", "externalId", "name"}
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
		familyVulnerableAsset,
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

func validateTrustedVantaOrigin(raw string, allowLoopback bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse grc url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if allowLoopback && isLoopbackHost(host) {
		return nil
	}
	if host == "api.vanta.com" || host == "api.eu.vanta.com" {
		return nil
	}
	return fmt.Errorf("grc Vanta host %q is not trusted", host)
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}
