package okta

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultPageSize   = 10
	maxPageSize       = 200
	defaultFamily     = familyAudit
	defaultAuditOrder = "ASCENDING"
	defaultUserOrder  = "asc"
	familyAudit       = "audit"
	familyUser        = "user"
)

var oktaDomainSuffixes = []string{
	".okta.com",
	".oktapreview.com",
	".okta-emea.com",
	".okta-gov.com",
}

// Source is the live Okta source preview used by the builtin registry.
type Source struct {
	spec   *cerebrov1.SourceSpec
	client *http.Client
}

type settings struct {
	family    string
	domain    string
	baseURL   string
	token     string
	filter    string
	q         string
	search    string
	sortBy    string
	sortOrder string
	since     string
	until     string
	perPage   int
}

type auditRecord struct {
	UUID           string           `json:"uuid"`
	Published      time.Time        `json:"published"`
	EventType      string           `json:"eventType"`
	DisplayMessage string           `json:"displayMessage"`
	Severity       string           `json:"severity"`
	Actor          map[string]any   `json:"actor"`
	Outcome        map[string]any   `json:"outcome"`
	Client         map[string]any   `json:"client"`
	Transaction    map[string]any   `json:"transaction"`
	Target         []map[string]any `json:"target"`
	raw            json.RawMessage
}

type userRecord struct {
	ID              string         `json:"id"`
	Status          string         `json:"status"`
	Created         *time.Time     `json:"created"`
	Activated       *time.Time     `json:"activated"`
	LastLogin       *time.Time     `json:"lastLogin"`
	LastUpdated     *time.Time     `json:"lastUpdated"`
	PasswordChanged *time.Time     `json:"passwordChanged"`
	StatusChanged   *time.Time     `json:"statusChanged"`
	RealmID         string         `json:"realmId"`
	Type            map[string]any `json:"type"`
	Profile         map[string]any `json:"profile"`
	raw             json.RawMessage
}

type auditPayload struct {
	UUID           string            `json:"uuid"`
	Domain         string            `json:"domain"`
	Published      time.Time         `json:"published"`
	EventType      string            `json:"event_type"`
	DisplayMessage string            `json:"display_message,omitempty"`
	Severity       string            `json:"severity,omitempty"`
	Actor          identityPayload   `json:"actor,omitempty"`
	Outcome        outcomePayload    `json:"outcome,omitempty"`
	Client         clientPayload     `json:"client,omitempty"`
	Transaction    eventPayload      `json:"transaction,omitempty"`
	Targets        []identityPayload `json:"targets,omitempty"`
	ResourceID     string            `json:"resource_id,omitempty"`
	ResourceType   string            `json:"resource_type,omitempty"`
	Raw            map[string]any    `json:"raw,omitempty"`
}

type userPayload struct {
	ID         string                 `json:"id"`
	Domain     string                 `json:"domain"`
	Status     string                 `json:"status,omitempty"`
	RealmID    string                 `json:"realm_id,omitempty"`
	Timestamps *userTimestampsPayload `json:"timestamps,omitempty"`
	Type       *userTypePayload       `json:"type,omitempty"`
	Profile    *userProfilePayload    `json:"profile,omitempty"`
	Employment *userEmploymentPayload `json:"employment,omitempty"`
	Raw        map[string]any         `json:"raw,omitempty"`
}

type userTimestampsPayload struct {
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	ActivatedAt       *time.Time `json:"activated_at,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	LastUpdatedAt     *time.Time `json:"last_updated_at,omitempty"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	StatusChangedAt   *time.Time `json:"status_changed_at,omitempty"`
}

type userTypePayload struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type userProfilePayload struct {
	Login       string `json:"login,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
}

type userEmploymentPayload struct {
	Department     string `json:"department,omitempty"`
	Title          string `json:"title,omitempty"`
	Organization   string `json:"organization,omitempty"`
	Manager        string `json:"manager,omitempty"`
	ManagerID      string `json:"manager_id,omitempty"`
	EmployeeNumber string `json:"employee_number,omitempty"`
	UserType       string `json:"user_type,omitempty"`
}

type identityPayload struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
	AlternateID string `json:"alternate_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type outcomePayload struct {
	Result string `json:"result,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type clientPayload struct {
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Zone      string `json:"zone,omitempty"`
}

type eventPayload struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

type apiError struct {
	ErrorSummary string `json:"errorSummary"`
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string {
	return e.message
}

// New constructs the live Okta source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{
		spec: spec,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Spec returns static metadata for the Okta source.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured Okta family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	settings, err := parseSettings(cfg)
	if err != nil {
		return err
	}
	switch settings.family {
	case familyAudit:
		_, _, err = s.listAudit(ctx, settings, "", 1)
		if err != nil {
			return wrapLookupError(fmt.Sprintf("okta audit log for %s", settings.domain), err)
		}
	case familyUser:
		_, _, err = s.listUsers(ctx, settings, "", 1)
		if err != nil {
			return wrapLookupError(fmt.Sprintf("okta users for %s", settings.domain), err)
		}
	}
	return nil
}

// Discover returns live Okta URNs for the selected family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return nil, err
	}
	switch settings.family {
	case familyAudit:
		if err := s.Check(ctx, cfg); err != nil {
			return nil, err
		}
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:org:%s", settings.domain, settings.domain))
		if err != nil {
			return nil, err
		}
		return []sourcecdk.URN{urn}, nil
	case familyUser:
		users, _, err := s.listUsers(ctx, settings, "", settings.perPage)
		if err != nil {
			return nil, wrapLookupError(fmt.Sprintf("okta users for %s", settings.domain), err)
		}
		urns := make([]sourcecdk.URN, 0, len(users))
		for _, user := range users {
			urn, err := userURN(settings.domain, user.ID)
			if err != nil {
				return nil, err
			}
			urns = append(urns, urn)
		}
		return urns, nil
	default:
		return nil, fmt.Errorf("unsupported okta family %q", settings.family)
	}
}

// Read pages through the configured live Okta event family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	after := strings.TrimSpace(cursor.GetOpaque())
	switch settings.family {
	case familyAudit:
		entries, next, err := s.listAudit(ctx, settings, after, settings.perPage)
		if err != nil {
			return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("okta audit log for %s", settings.domain), err)
		}
		if len(entries) == 0 {
			return sourcecdk.Pull{}, nil
		}
		events := make([]*primitives.Event, 0, len(entries))
		for _, entry := range entries {
			event, err := auditEvent(settings, entry)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		pull := sourcecdk.Pull{
			Events: events,
			Checkpoint: &cerebrov1.SourceCheckpoint{
				Watermark:    events[len(events)-1].OccurredAt,
				CursorOpaque: checkpointCursor(next, entries[len(entries)-1].UUID, events[len(events)-1].OccurredAt.AsTime()),
			},
		}
		if next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		}
		return pull, nil
	case familyUser:
		users, next, err := s.listUsers(ctx, settings, after, settings.perPage)
		if err != nil {
			return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("okta users for %s", settings.domain), err)
		}
		if len(users) == 0 {
			return sourcecdk.Pull{}, nil
		}
		events := make([]*primitives.Event, 0, len(users))
		for _, user := range users {
			event, err := userEvent(settings, user)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		pull := sourcecdk.Pull{
			Events: events,
			Checkpoint: &cerebrov1.SourceCheckpoint{
				Watermark:    events[len(events)-1].OccurredAt,
				CursorOpaque: checkpointCursor(next, users[len(users)-1].ID, events[len(events)-1].OccurredAt.AsTime()),
			},
		}
		if next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		}
		return pull, nil
	default:
		return sourcecdk.Pull{}, fmt.Errorf("unsupported okta family %q", settings.family)
	}
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

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:    configValue(cfg, "family"),
		domain:    configValue(cfg, "domain"),
		baseURL:   configValue(cfg, "base_url"),
		token:     configValue(cfg, "token"),
		filter:    configValue(cfg, "filter"),
		q:         configValue(cfg, "q"),
		search:    configValue(cfg, "search"),
		sortBy:    configValue(cfg, "sort_by"),
		sortOrder: configValue(cfg, "sort_order"),
		since:     configValue(cfg, "since"),
		until:     configValue(cfg, "until"),
		perPage:   defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAudit, familyUser:
	default:
		return settings, fmt.Errorf("okta family must be one of %s or %s", familyAudit, familyUser)
	}
	if settings.domain == "" {
		return settings, fmt.Errorf("okta domain is required")
	}
	domain, err := normalizeDomain(settings.domain)
	if err != nil {
		return settings, err
	}
	settings.domain = domain
	if settings.baseURL == "" {
		settings.baseURL = "https://" + settings.domain
	} else {
		settings.baseURL, err = normalizeBaseURL(settings.baseURL, settings.domain)
		if err != nil {
			return settings, err
		}
	}
	if settings.token == "" {
		return settings, fmt.Errorf("okta token is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse okta per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("okta per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyAudit:
		if settings.search != "" || settings.sortBy != "" {
			return settings, fmt.Errorf("okta search and sort_by are only supported when family=%q", familyUser)
		}
		settings.sortOrder, err = normalizeAuditSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	case familyUser:
		if settings.since != "" || settings.until != "" {
			return settings, fmt.Errorf("okta since and until are only supported when family=%q", familyAudit)
		}
		settings.sortOrder, err = normalizeUserSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	}
	return settings, nil
}

func normalizeDomain(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("okta domain is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse okta domain: %w", err)
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("okta domain must be a valid host")
	}
	if strings.ToLower(strings.TrimSpace(parsed.Scheme)) != "https" {
		return "", fmt.Errorf("okta domain must use https")
	}
	if parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("okta domain must be a bare hostname")
	}
	if path := strings.TrimSpace(parsed.EscapedPath()); path != "" && path != "/" {
		return "", fmt.Errorf("okta domain must be a bare hostname")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(host) != nil || !validDNSHostname(host) || !allowedOktaDomain(host) {
		return "", fmt.Errorf("okta domain must be an Okta tenant hostname")
	}
	return host, nil
}

func allowedOktaDomain(host string) bool {
	for _, suffix := range oktaDomainSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

func validDNSHostname(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return false
	}
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeBaseURL(raw string, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse okta base_url: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(parsed.Scheme)) != "https" || strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("okta base_url must use https and include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("okta base_url must not include userinfo, query, or fragment")
	}
	if !strings.EqualFold(parsed.Hostname(), domain) || (parsed.Port() != "" && parsed.Port() != "443") {
		return "", fmt.Errorf("okta base_url host must match okta domain")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func normalizeAuditSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return defaultAuditOrder, nil
	case "desc", "descending":
		return "DESCENDING", nil
	case "asc", "ascending":
		return "ASCENDING", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyAudit)
	}
}

func normalizeUserSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "asc", "ascending":
		return defaultUserOrder, nil
	case "desc", "descending":
		return "desc", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyUser)
	}
}

func (s *Source) listAudit(ctx context.Context, settings settings, after string, limit int) ([]auditRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "filter", settings.filter)
	addQuery(query, "q", settings.q)
	addQuery(query, "since", settings.since)
	addQuery(query, "until", settings.until)
	addQuery(query, "sortOrder", settings.sortOrder)

	var rawRecords []json.RawMessage
	headers, err := s.getJSON(ctx, settings, "/api/v1/logs", query, &rawRecords)
	if err != nil {
		return nil, "", err
	}
	records := make([]auditRecord, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		var record auditRecord
		if err := json.Unmarshal(rawRecord, &record); err != nil {
			return nil, "", fmt.Errorf("decode okta audit event: %w", err)
		}
		record.raw = append(json.RawMessage(nil), rawRecord...)
		records = append(records, record)
	}
	return records, nextAfter(headers), nil
}

func (s *Source) listUsers(ctx context.Context, settings settings, after string, limit int) ([]userRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "filter", settings.filter)
	addQuery(query, "q", settings.q)
	addQuery(query, "search", settings.search)
	addQuery(query, "sortBy", settings.sortBy)
	addQuery(query, "sortOrder", settings.sortOrder)

	var rawRecords []json.RawMessage
	headers, err := s.getJSON(ctx, settings, "/api/v1/users", query, &rawRecords)
	if err != nil {
		return nil, "", err
	}
	records := make([]userRecord, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		var record userRecord
		if err := json.Unmarshal(rawRecord, &record); err != nil {
			return nil, "", fmt.Errorf("decode okta user: %w", err)
		}
		record.raw = append(json.RawMessage(nil), rawRecord...)
		records = append(records, record)
	}
	return records, nextAfter(headers), nil
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) (http.Header, error) {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "SSWS "+settings.token)

	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	headers := resp.Header.Clone()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return headers, fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return headers, decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return headers, nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return headers, fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return headers, nil
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.ErrorSummary) != "" {
		message = strings.TrimSpace(apiErr.ErrorSummary)
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("okta API returned %d: %s", statusCode, message),
	}
}

func auditEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	occurredAt := record.Published.UTC()
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("okta audit event %q missing published timestamp", record.UUID)
	}
	raw, err := decodeRawPayload(record.raw, "okta audit")
	if err != nil {
		return nil, err
	}
	actor := identityFromMap(record.Actor)
	targets := identitiesFromMaps(record.Target)
	resourceID, resourceType := auditResource(record, actor, targets, settings.domain)
	payload, err := json.Marshal(auditPayload{
		UUID:           record.UUID,
		Domain:         settings.domain,
		Published:      occurredAt,
		EventType:      record.EventType,
		DisplayMessage: record.DisplayMessage,
		Severity:       record.Severity,
		Actor:          actor,
		Outcome: outcomePayload{
			Result: stringMap(record.Outcome, "result"),
			Reason: stringMap(record.Outcome, "reason"),
		},
		Client: clientPayload{
			IPAddress: stringMap(record.Client, "ipAddress"),
			UserAgent: stringMap(nestedMap(record.Client, "userAgent"), "rawUserAgent"),
			Zone:      stringMap(record.Client, "zone"),
		},
		Transaction: eventPayload{
			ID:   stringMap(record.Transaction, "id"),
			Type: stringMap(record.Transaction, "type"),
		},
		Targets:      targets,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Raw:          raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta audit payload: %w", err)
	}
	eventID := strings.TrimSpace(record.UUID)
	if eventID == "" {
		eventID = fmt.Sprintf("%s-%d", strings.ReplaceAll(record.EventType, ".", "-"), occurredAt.UnixMilli())
	}
	return &primitives.Event{
		Id:         "okta-audit-" + eventID,
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/audit/v1",
		Payload:    payload,
		Attributes: auditAttributes(settings, record, actor, resourceID, resourceType),
	}, nil
}

func userEvent(settings settings, record userRecord) (*primitives.Event, error) {
	occurredAt := userOccurredAt(record)
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("okta user %q missing timestamps", record.ID)
	}
	raw, err := decodeRawPayload(record.raw, "okta user")
	if err != nil {
		return nil, err
	}
	profile := record.Profile
	payload, err := json.Marshal(userPayload{
		ID:         record.ID,
		Domain:     settings.domain,
		Status:     record.Status,
		RealmID:    record.RealmID,
		Timestamps: userTimestamps(record),
		Type:       userType(record.Type),
		Profile:    userProfile(profile),
		Employment: userEmployment(profile),
		Raw:        raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta user payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-user-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.user",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/user/v1",
		Payload:    payload,
		Attributes: userAttributes(settings, record),
	}, nil
}

func auditAttributes(settings settings, record auditRecord, actor identityPayload, resourceID string, resourceType string) map[string]string {
	attributes := map[string]string{
		"domain":        settings.domain,
		"event_type":    record.EventType,
		"family":        familyAudit,
		"resource_id":   resourceID,
		"resource_type": resourceType,
	}
	addAttribute(attributes, "actor_id", actor.ID)
	addAttribute(attributes, "actor_type", actor.Type)
	addAttribute(attributes, "actor_alternate_id", actor.AlternateID)
	addAttribute(attributes, "actor_display_name", actor.DisplayName)
	addAttribute(attributes, "client_ip", stringMap(record.Client, "ipAddress"))
	addAttribute(attributes, "outcome_reason", stringMap(record.Outcome, "reason"))
	addAttribute(attributes, "outcome_result", stringMap(record.Outcome, "result"))
	addAttribute(attributes, "severity", record.Severity)
	addAttribute(attributes, "transaction_id", stringMap(record.Transaction, "id"))
	return attributes
}

func userAttributes(settings settings, record userRecord) map[string]string {
	attributes := map[string]string{
		"domain":  settings.domain,
		"family":  familyUser,
		"user_id": record.ID,
	}
	addAttribute(attributes, "email", stringMap(record.Profile, "email"))
	addAttribute(attributes, "login", stringMap(record.Profile, "login"))
	addAttribute(attributes, "realm_id", record.RealmID)
	addAttribute(attributes, "status", record.Status)
	addAttribute(attributes, "type_id", stringMap(record.Type, "id"))
	addAttribute(attributes, "type_name", stringMap(record.Type, "name"))
	addAttribute(attributes, "user_type", stringMap(record.Profile, "userType"))
	return attributes
}

func userTimestamps(record userRecord) *userTimestampsPayload {
	payload := &userTimestampsPayload{
		CreatedAt:         utcTime(record.Created),
		ActivatedAt:       utcTime(record.Activated),
		LastLoginAt:       utcTime(record.LastLogin),
		LastUpdatedAt:     utcTime(record.LastUpdated),
		PasswordChangedAt: utcTime(record.PasswordChanged),
		StatusChangedAt:   utcTime(record.StatusChanged),
	}
	if payload.CreatedAt == nil &&
		payload.ActivatedAt == nil &&
		payload.LastLoginAt == nil &&
		payload.LastUpdatedAt == nil &&
		payload.PasswordChangedAt == nil &&
		payload.StatusChangedAt == nil {
		return nil
	}
	return payload
}

func userType(values map[string]any) *userTypePayload {
	payload := &userTypePayload{
		ID:   stringMap(values, "id"),
		Name: stringMap(values, "name"),
	}
	if payload.ID == "" && payload.Name == "" {
		return nil
	}
	return payload
}

func userProfile(values map[string]any) *userProfilePayload {
	payload := &userProfilePayload{
		Login:       stringMap(values, "login"),
		Email:       stringMap(values, "email"),
		DisplayName: firstNonEmpty(stringMap(values, "displayName"), strings.TrimSpace(strings.Join([]string{stringMap(values, "firstName"), stringMap(values, "lastName")}, " "))),
		FirstName:   stringMap(values, "firstName"),
		LastName:    stringMap(values, "lastName"),
	}
	if payload.Login == "" &&
		payload.Email == "" &&
		payload.DisplayName == "" &&
		payload.FirstName == "" &&
		payload.LastName == "" {
		return nil
	}
	return payload
}

func userEmployment(values map[string]any) *userEmploymentPayload {
	payload := &userEmploymentPayload{
		Department:     stringMap(values, "department"),
		Title:          stringMap(values, "title"),
		Organization:   stringMap(values, "organization"),
		Manager:        stringMap(values, "manager"),
		ManagerID:      stringMap(values, "managerId"),
		EmployeeNumber: stringMap(values, "employeeNumber"),
		UserType:       stringMap(values, "userType"),
	}
	if payload.Department == "" &&
		payload.Title == "" &&
		payload.Organization == "" &&
		payload.Manager == "" &&
		payload.ManagerID == "" &&
		payload.EmployeeNumber == "" &&
		payload.UserType == "" {
		return nil
	}
	return payload
}

func auditResource(record auditRecord, actor identityPayload, targets []identityPayload, domain string) (string, string) {
	for _, target := range targets {
		resourceID := firstNonEmpty(target.ID, target.AlternateID, target.DisplayName)
		resourceType := strings.TrimSpace(target.Type)
		if resourceID != "" || resourceType != "" {
			return resourceID, firstNonEmpty(resourceType, auditEventResourceType(record.EventType))
		}
	}
	if actor.AlternateID != "" || actor.ID != "" {
		return firstNonEmpty(actor.AlternateID, actor.ID), firstNonEmpty(actor.Type, auditEventResourceType(record.EventType))
	}
	return domain, auditEventResourceType(record.EventType)
}

func auditEventResourceType(eventType string) string {
	value := strings.TrimSpace(eventType)
	if value == "" {
		return "audit"
	}
	prefix, _, ok := strings.Cut(value, ".")
	if !ok {
		return value
	}
	return prefix
}

func identityFromMap(values map[string]any) identityPayload {
	return identityPayload{
		ID:          stringMap(values, "id"),
		Type:        stringMap(values, "type"),
		AlternateID: stringMap(values, "alternateId"),
		DisplayName: stringMap(values, "displayName"),
	}
}

func identitiesFromMaps(values []map[string]any) []identityPayload {
	identities := make([]identityPayload, 0, len(values))
	for _, value := range values {
		identity := identityFromMap(value)
		if identity != (identityPayload{}) {
			identities = append(identities, identity)
		}
	}
	return identities
}

func userOccurredAt(record userRecord) time.Time {
	for _, stamp := range []*time.Time{
		record.LastUpdated,
		record.Created,
		record.Activated,
		record.StatusChanged,
		record.LastLogin,
		record.PasswordChanged,
	} {
		if stamp != nil && !stamp.IsZero() {
			return stamp.UTC()
		}
	}
	return time.Time{}
}

func decodeRawPayload(raw json.RawMessage, label string) (map[string]any, error) {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s raw payload: %w", label, err)
	}
	return decoded, nil
}

func userURN(domain string, userID string) (sourcecdk.URN, error) {
	id := strings.TrimSpace(userID)
	if id == "" {
		return "", fmt.Errorf("okta user id is required")
	}
	return sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:user:%s", domain, id))
}

func nextAfter(headers http.Header) string {
	if headers == nil {
		return ""
	}
	for _, header := range headers.Values("Link") {
		for _, part := range strings.Split(header, ",") {
			link, rel := parseLink(part)
			if rel != "next" {
				continue
			}
			parsed, err := url.Parse(link)
			if err != nil {
				continue
			}
			if after := strings.TrimSpace(parsed.Query().Get("after")); after != "" {
				return after
			}
		}
	}
	return ""
}

func parseLink(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "<") {
		return "", ""
	}
	end := strings.Index(trimmed, ">")
	if end <= 1 {
		return "", ""
	}
	link := trimmed[1:end]
	params := strings.Split(trimmed[end+1:], ";")
	for _, param := range params {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || key != "rel" {
			continue
		}
		return link, strings.Trim(rawValue, "\"")
	}
	return link, ""
}

func checkpointCursor(next string, fallback string, occurredAt time.Time) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	if occurredAt.IsZero() {
		return ""
	}
	return occurredAt.UTC().Format(time.RFC3339Nano)
}

func utcTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	query.Set(key, value)
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func nestedMap(values map[string]any, key string) map[string]any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func stringMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func isNotFound(err error) bool {
	var responseErr *responseError
	return errors.As(err, &responseErr) && responseErr.statusCode == http.StatusNotFound
}

func wrapLookupError(subject string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s not found", subject)
	}
	return fmt.Errorf("%s: %w", subject, err)
}
