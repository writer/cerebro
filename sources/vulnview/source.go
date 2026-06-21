package vulnview

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	sourceID              = "vulnview"
	defaultBaseURL        = "https://vulnview.writer-security.com/api"
	defaultScope          = "vulnview"
	defaultFamily         = familyVulnerability
	defaultPageSize       = 100
	maxPageSize           = 500
	dnsAlertDiscoverPages = 10
	httpTimeout           = 30 * time.Second
	maxBodyBytes          = 8 << 20
	tokenRefreshLeeway    = time.Minute

	familySite          = "site"
	familyScan          = "scan"
	familyVulnerability = "vulnerability"
	familyAsset         = "asset"
	familyDNSAlert      = "dns_alert"
)

// Source reads VulnView attack-surface and vulnerability data.
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
	tenantID     string
	family       string
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	siteID       string
	scanName     string
	severity     string
	search       string
	perPage      int
}

type record struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type listResponse struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"nextCursor"`
}

type dnsAlertCursor struct {
	AssetCursor string `json:"assetCursor,omitempty"`
	AlertOffset int    `json:"alertOffset,omitempty"`
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

// New constructs the VulnView source.
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

// Spec returns static VulnView source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured VulnView family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical VulnView URNs for one configured page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages VulnView records and emits vulnview.* events.
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
		s.family(familySite, "/sites"),
		s.family(familyScan, "/scans"),
		s.family(familyVulnerability, "/vulnerabilities"),
		s.family(familyAsset, "/assets"),
		s.dnsAlertFamily(),
	)
}

func (s *Source) family(name string, path string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, path, "", 1)
			if err != nil {
				return fmt.Errorf("vulnview %s: %w", name, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, path, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, path, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return pullFromRecords(settings, name, records, next)
		},
	}
}

func (s *Source) dnsAlertFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyDNSAlert,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.listDNSAlerts(ctx, settings, "", 1)
			if err != nil {
				return fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, err := s.discoverDNSAlerts(ctx, settings)
			if err != nil {
				return nil, fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return urnsFor(settings, familyDNSAlert, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.listDNSAlerts(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return pullFromRecords(settings, familyDNSAlert, records, next)
		},
	}
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	resolved := settings{
		tenantID:     firstNonEmpty(configValue(cfg, "tenant_id"), configValue(cfg, "__cerebro_runtime_tenant_id")),
		family:       configValue(cfg, "family"),
		baseURL:      configValue(cfg, "base_url"),
		tokenURL:     configValue(cfg, "token_url"),
		clientID:     configValue(cfg, "client_id"),
		clientSecret: configValue(cfg, "client_secret"),
		scope:        configValue(cfg, "scope"),
		siteID:       configValue(cfg, "site_id"),
		scanName:     configValue(cfg, "scan_name"),
		severity:     strings.ToLower(configValue(cfg, "severity")),
		search:       configValue(cfg, "search"),
		perPage:      defaultPageSize,
	}
	if resolved.tenantID == "" {
		return resolved, fmt.Errorf("vulnview tenant_id is required")
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	if !isSupportedFamily(resolved.family) {
		return resolved, fmt.Errorf("vulnview family must be one of %s", strings.Join(supportedFamilies(), ", "))
	}
	if resolved.baseURL == "" {
		resolved.baseURL = defaultBaseURL
	}
	normalizedBase, err := normalizeBaseURL(resolved.baseURL, allowLoopback)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	if err := validateBaseURL(resolved.baseURL, allowLoopback); err != nil {
		return resolved, err
	}
	if resolved.scope == "" {
		resolved.scope = defaultScope
	}
	if resolved.clientID == "" {
		return resolved, fmt.Errorf("vulnview client_id is required")
	}
	if resolved.clientSecret == "" {
		return resolved, fmt.Errorf("vulnview client_secret is required")
	}
	issuer := strings.TrimRight(configValue(cfg, "okta_issuer"), "/")
	if issuer == "" && !allowLoopback {
		return resolved, fmt.Errorf("vulnview okta_issuer is required")
	}
	if resolved.tokenURL == "" {
		if issuer == "" {
			return resolved, fmt.Errorf("vulnview okta_issuer or token_url is required")
		}
		resolved.tokenURL = issuer + "/v1/token"
	}
	normalizedTokenURL, err := normalizeAbsoluteURL(resolved.tokenURL, allowLoopback)
	if err != nil {
		return resolved, err
	}
	resolved.tokenURL = normalizedTokenURL
	if err := validateTokenURL(cfg, resolved.tokenURL, allowLoopback); err != nil {
		return resolved, err
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse vulnview per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("vulnview per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	return resolved, nil
}

func validateBaseURL(baseURL string, allowLoopback bool) error {
	if allowLoopback {
		return nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse vulnview base_url: %w", err)
	}
	trusted, err := url.Parse(defaultBaseURL)
	if err != nil {
		return fmt.Errorf("parse default VulnView base_url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, trusted.Scheme) || !strings.EqualFold(parsed.Host, trusted.Host) {
		return fmt.Errorf("vulnview base_url must use the trusted VulnView origin")
	}
	return nil
}

func validateTokenURL(cfg sourcecdk.Config, tokenURL string, allowLoopback bool) error {
	issuer := strings.TrimRight(configValue(cfg, "okta_issuer"), "/")
	if issuer == "" {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("vulnview okta_issuer is required")
	}
	expected, err := normalizeAbsoluteURL(issuer+"/v1/token", allowLoopback)
	if err != nil {
		return err
	}
	if tokenURL != expected {
		return fmt.Errorf("vulnview token_url must match okta_issuer token endpoint")
	}
	return nil
}

func isSupportedFamily(family string) bool {
	switch family {
	case familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert:
		return true
	default:
		return false
	}
}

func supportedFamilies() []string {
	return []string{familySite, familyScan, familyVulnerability, familyAsset, familyDNSAlert}
}

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]record, string, error) {
	var response listResponse
	query := settings.query()
	query.Set("limit", strconv.Itoa(pageSize))
	addQuery(query, "cursor", cursor)
	if err := s.getJSON(ctx, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	records := make([]record, 0, len(response.Items))
	for _, item := range response.Items {
		rec, err := recordFromRaw(settings.family, item)
		if err != nil {
			return nil, "", err
		}
		if rec.ID == "" {
			continue
		}
		records = append(records, rec)
	}
	if serverPaged(cursor, pageSize, len(records), response.NextCursor) {
		return records, strings.TrimSpace(response.NextCursor), nil
	}
	return sourcecdk.PageByOffset(records, cursor, pageSize)
}

func (s *Source) listDNSAlerts(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, string, error) {
	assetCursor, alertOffset, err := parseDNSAlertCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	familySettings := settings
	familySettings.family = familyAsset
	var response listResponse
	query := familySettings.query()
	query.Set("limit", strconv.Itoa(familySettings.perPage))
	addQuery(query, "cursor", assetCursor)
	if err := s.getJSON(ctx, familySettings, "/assets", query, &response); err != nil {
		return nil, "", err
	}
	records := []record{}
	for _, item := range response.Items {
		var asset map[string]any
		if err := json.Unmarshal(item, &asset); err != nil {
			return nil, "", fmt.Errorf("decode VulnView asset: %w", err)
		}
		alerts, _ := asset["dnsAlerts"].([]any)
		for index, rawAlert := range alerts {
			alert, ok := rawAlert.(map[string]any)
			if !ok {
				continue
			}
			values := map[string]any{
				"asset":     asset["asset"],
				"siteNames": asset["sites"],
				"scanNames": asset["scanNames"],
			}
			maps.Copy(values, alert)
			raw, err := json.Marshal(values)
			if err != nil {
				return nil, "", fmt.Errorf("marshal VulnView DNS alert: %w", err)
			}
			id := firstValueString(values, "id", "alert", "name", "type")
			assetID := valueString(asset["asset"])
			records = append(records, record{
				Raw:    raw,
				Values: values,
				ID:     stableID(assetID, id, strconv.Itoa(index)),
			})
		}
	}
	page, nextAlertOffset, err := sourcecdk.PageByOffset(records, strconv.Itoa(alertOffset), pageSize)
	if err != nil {
		return nil, "", err
	}
	if nextAlertOffset != "" {
		return page, encodeDNSAlertCursor(assetCursor, nextAlertOffset), nil
	}
	if strings.TrimSpace(response.NextCursor) != "" {
		return page, encodeDNSAlertCursor(response.NextCursor, "0"), nil
	}
	return page, "", nil
}

func (s *Source) discoverDNSAlerts(ctx context.Context, settings settings) ([]record, error) {
	cursor := ""
	for page := 0; page < dnsAlertDiscoverPages; page++ {
		records, next, err := s.listDNSAlerts(ctx, settings, cursor, settings.perPage)
		if err != nil {
			return nil, err
		}
		if len(records) > 0 || strings.TrimSpace(next) == "" {
			return records, nil
		}
		cursor = next
	}
	return nil, nil
}

func serverPaged(cursor string, pageSize int, recordCount int, nextCursor string) bool {
	return strings.TrimSpace(nextCursor) != "" || (strings.TrimSpace(cursor) != "" && recordCount <= pageSize)
}

func parseDNSAlertCursor(cursor string) (string, int, error) {
	trimmed := strings.TrimSpace(cursor)
	if trimmed == "" {
		return "", 0, nil
	}
	if !strings.HasPrefix(trimmed, "dns:") {
		return trimmed, 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, "dns:"))
	if err != nil {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	var decoded dnsAlertCursor
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	if decoded.AlertOffset < 0 {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	return strings.TrimSpace(decoded.AssetCursor), decoded.AlertOffset, nil
}

func encodeDNSAlertCursor(assetCursor string, alertOffset string) string {
	offset, err := strconv.Atoi(strings.TrimSpace(alertOffset))
	if err != nil || offset < 0 {
		offset = 0
	}
	payload, err := json.Marshal(dnsAlertCursor{AssetCursor: strings.TrimSpace(assetCursor), AlertOffset: offset})
	if err != nil {
		return ""
	}
	return "dns:" + base64.RawURLEncoding.EncodeToString(payload)
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) error {
	token, err := s.token(ctx, settings)
	if err != nil {
		return err
	}
	err = s.getJSONWithToken(ctx, settings, requestPath, query, token, target)
	if err != nil && isUnauthorizedResponse(err) {
		s.invalidateToken(settings)
		token, tokenErr := s.token(ctx, settings)
		if tokenErr != nil {
			return tokenErr
		}
		err = s.getJSONWithToken(ctx, settings, requestPath, query, token, target)
	}
	return err
}

func (s *Source) getJSONWithToken(ctx context.Context, settings settings, requestPath string, query url.Values, token string, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := s.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError("VulnView API", resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func (s *Source) token(ctx context.Context, settings settings) (string, error) {
	key := tokenCacheKey(settings)
	now := time.Now().UTC()
	s.mu.Lock()
	if key == s.tokenKey && s.accessToken != "" && now.Add(tokenRefreshLeeway).Before(s.tokenExpiresAt) {
		token := s.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()
	token, expiresAt, err := s.fetchToken(ctx, settings)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.tokenKey = key
	s.accessToken = token
	s.tokenExpiresAt = expiresAt
	s.mu.Unlock()
	return token, nil
}

func (s *Source) invalidateToken(settings settings) {
	key := tokenCacheKey(settings)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenKey == key {
		s.tokenKey = ""
		s.accessToken = ""
		s.tokenExpiresAt = time.Time{}
	}
}

func tokenCacheKey(settings settings) string {
	return strings.Join([]string{
		settings.baseURL,
		settings.tokenURL,
		settings.clientID,
		settings.scope,
		hashValue(settings.clientSecret),
	}, "\x00")
}

func hashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Source) fetchToken(ctx context.Context, settings settings) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", settings.scope)
	form.Set("client_id", settings.clientID)
	form.Set("client_secret", settings.clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build VulnView token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := s.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request VulnView token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read VulnView token response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return "", time.Time{}, decodeResponseError("VulnView token endpoint", resp.StatusCode, body)
	}
	var decoded tokenResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", time.Time{}, fmt.Errorf("decode VulnView token response: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("VulnView token endpoint returned empty access_token")
	}
	if decoded.TokenType != "" && !strings.EqualFold(decoded.TokenType, "Bearer") {
		return "", time.Time{}, fmt.Errorf("VulnView token endpoint returned unsupported token_type %q", decoded.TokenType)
	}
	expiresIn := decoded.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	return decoded.AccessToken, time.Now().UTC().Add(time.Duration(expiresIn) * time.Second), nil
}

func (s *Source) httpClient() *http.Client {
	var client *http.Client
	allowLoopback := false
	if s != nil {
		client = s.client
		allowLoopback = s.allowLoopbackBaseURL
	}
	return sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "vulnview",
		Timeout:       httpTimeout,
		AllowLoopback: allowLoopback,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func (settings settings) query() url.Values {
	query := url.Values{}
	addQuery(query, "siteId", settings.siteID)
	addQuery(query, "scanName", settings.scanName)
	addQuery(query, "name", settings.scanName)
	addQuery(query, "severity", settings.severity)
	addQuery(query, "search", settings.search)
	return query
}

func recordFromRaw(family string, raw json.RawMessage) (record, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return record{}, fmt.Errorf("decode VulnView %s record: %w", family, err)
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: recordID(family, values)}, nil
}

func recordID(family string, values map[string]any) string {
	switch family {
	case familySite:
		return firstValueString(values, "siteId", "id", "name")
	case familyScan:
		return firstValueString(values, "scanId", "id", "name")
	case familyVulnerability:
		return stableID(
			firstValueString(values, "scanId"),
			firstValueString(values, "templateId", "template-id", "id", "name"),
			firstValueString(values, "matchedAt", "matched-at", "host"),
		)
	case familyAsset:
		return firstValueString(values, "asset", "host", "matchedAt", "matched-at")
	default:
		return firstValueString(values, "id", "name")
	}
}

func urnsFor(settings settings, family string, records []record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:vulnview_%s:%s", settings.tenantID, family, normalizeID(record.ID)))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family string, records []record, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec record) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec record) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attributesFor(family, record),
	}
}

func eventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{
		sourceID,
		normalizeID(settings.tenantID),
		runtimeScope(settings),
		normalizeID(family),
		normalizeID(recordID),
	}, "-")
}

func runtimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func attributesFor(family string, record record) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"external_id":     record.ID,
		"family":          family,
		"provider":        sourceID,
		"source_provider": sourceID,
	}
	switch family {
	case familySite:
		copyFields(attrs, values, map[string]string{
			"site_id": "siteId",
			"name":    "name",
		})
	case familyScan:
		copyFields(attrs, values, map[string]string{
			"scan_id":          "scanId",
			"site_id":          "siteId",
			"name":             "name",
			"scan_type":        "scanType",
			"target":           "target",
			"status":           "status",
			"findings_count":   "findingsCount",
			"results_key":      "resultsKey",
			"created_at":       "createdAt",
			"started_at":       "startedAt",
			"completed_at":     "completedAt",
			"cloud_account_id": "cloudAccountId",
		})
	case familyVulnerability:
		copyFields(attrs, values, map[string]string{
			"vulnerability_id": "templateId",
			"template_id":      "templateId",
			"name":             "name",
			"severity":         "severity",
			"type":             "type",
			"target_id":        "host",
			"target_name":      "host",
			"host":             "host",
			"matched_at":       "matchedAt",
			"description":      "description",
			"remediation":      "remediation",
			"scan_id":          "scanId",
			"scan_name":        "scanName",
			"site_id":          "siteId",
			"site_name":        "siteName",
			"timestamp":        "timestamp",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		if attrs["template_id"] == "" {
			copyFields(attrs, values, map[string]string{"template_id": "template-id", "vulnerability_id": "template-id"})
		}
		if attrs["matched_at"] == "" {
			copyFields(attrs, values, map[string]string{"matched_at": "matched-at"})
		}
		attrs["target_type"] = "external_asset"
		attrs["vulnerability_type"] = firstNonEmpty(attrs["type"], "vulnview")
	case familyAsset:
		copyFields(attrs, values, map[string]string{
			"asset_id":          "asset",
			"asset_name":        "asset",
			"target_id":         "asset",
			"target_name":       "asset",
			"highest_severity":  "highestSeverity",
			"findings_count":    "findingsCount",
			"sites":             "sites",
			"scan_names":        "scanNames",
			"critical_count":    "severityCounts.critical",
			"high_count":        "severityCounts.high",
			"medium_count":      "severityCounts.medium",
			"low_count":         "severityCounts.low",
			"info_count":        "severityCounts.info",
			"dns_alerts_count":  "dnsAlertSummary.total",
			"dns_highest_alert": "dnsAlertSummary.highestSeverity",
		})
		attrs["target_type"] = "external_asset"
	case familyDNSAlert:
		copyFields(attrs, values, map[string]string{
			"asset_id":     "asset",
			"asset_name":   "asset",
			"target_id":    "asset",
			"target_name":  "asset",
			"alert":        "alert",
			"name":         "alert",
			"severity":     "severity",
			"description":  "description",
			"record_type":  "recordType",
			"record_value": "recordValue",
			"sites":        "siteNames",
			"scan_names":   "scanNames",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		attrs["target_type"] = "external_asset"
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func addVulnViewFindingStateAttributes(attrs map[string]string, values map[string]any) {
	stateFields := map[string][]string{
		"vulnview_status":            {"status"},
		"vulnview_state":             {"state"},
		"vulnview_finding_status":    {"findingStatus", "finding_status"},
		"vulnview_remediation_state": {"remediationState", "remediation_state"},
		"vulnview_lifecycle_state":   {"lifecycleState", "lifecycle_state"},
	}
	for attr, fields := range stateFields {
		if value := firstValueString(values, fields...); value != "" {
			attrs[attr] = value
		}
	}
	attrs["vulnview_finding_state"] = firstNonEmpty(
		attrs["vulnview_status"],
		attrs["vulnview_state"],
		attrs["vulnview_finding_status"],
		attrs["vulnview_remediation_state"],
		attrs["vulnview_lifecycle_state"],
	)
}

func occurredAtFor(values map[string]any) time.Time {
	for _, key := range []string{"timestamp", "completedAt", "startedAt", "createdAt", "matchedAt", "matched-at"} {
		if parsed, ok := parseTime(valueString(valueAt(values, key))); ok {
			return parsed
		}
	}
	return time.Now().UTC()
}

func parseTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse vulnview base_url: %w", err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("vulnview base_url must not include user info, query, or fragment")
	}
	normalized, err := normalizeParsedURL(parsed, allowLoopback)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(normalized, "/"), nil
}

func normalizeAbsoluteURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse vulnview url: %w", err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("vulnview url must not include user info, query, or fragment")
	}
	return normalizeParsedURL(parsed, allowLoopback)
}

func normalizeParsedURL(parsed *url.URL, allowLoopback bool) (string, error) {
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && isLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("vulnview url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("vulnview url must include a host")
	}
	allowCustomPort := allowLoopback && isLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomPort {
		return "", fmt.Errorf("vulnview url must not include a custom port")
	}
	if isUnsafeHost(host) && (!allowLoopback || !isLoopbackHost(host)) {
		return "", fmt.Errorf("vulnview url must not target loopback, private, or link-local hosts")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func isUnsafeHost(host string) bool {
	value := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && unsafeIP(ip, false)
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
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func decodeResponseError(service string, statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error", "detail"} {
			if value := valueString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &responseError{statusCode: statusCode, message: fmt.Sprintf("%s returned %d: %s", service, statusCode, message)}
}

func isUnauthorizedResponse(err error) bool {
	var responseErr *responseError
	return errors.As(err, &responseErr) && responseErr.statusCode == http.StatusUnauthorized
}

func copyFields(attrs map[string]string, values map[string]any, fields map[string]string) {
	for attr, field := range fields {
		if value := valueString(valueAt(values, field)); value != "" {
			attrs[attr] = value
		}
	}
}

func valueAt(values map[string]any, path string) any {
	current := any(values)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func firstValueString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueString(valueAt(values, key)); value != "" {
			return value
		}
	}
	return ""
}

func valueString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if value := valueString(item); value != "" {
				parts = append(parts, value)
			}
		}
		return strings.Join(parts, ",")
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func stableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ":")
}

func normalizeID(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-")
	return replacer.Replace(normalized)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
