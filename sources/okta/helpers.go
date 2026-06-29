package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/oktaasset"
	"github.com/writer/cerebro/sources/internal/oktaevent"
	"github.com/writer/cerebro/sources/internal/textutil"
)

const (
	oktaHTTPTimeout  = 30 * time.Second
	maxOktaBodyBytes = 4 << 20
)

var defaultMFAFactorRetryBackoffs = []time.Duration{
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
}

var oktaMFAEnrollmentFactorKinds = map[string]struct{}{
	"call":                {},
	"custom":              {},
	"email":               {},
	"hotp":                {},
	"push":                {},
	"question":            {},
	"signed_nonce":        {},
	"sms":                 {},
	"token:hardware":      {},
	"token:software:totp": {},
	"u2f":                 {},
	"webauthn":            {},
}

type auditRecord struct {
	UUID                  string           `json:"uuid"`
	Published             time.Time        `json:"published"`
	EventType             string           `json:"eventType"`
	DisplayMessage        string           `json:"displayMessage"`
	Severity              string           `json:"severity"`
	Actor                 map[string]any   `json:"actor"`
	Outcome               map[string]any   `json:"outcome"`
	Client                map[string]any   `json:"client"`
	Request               map[string]any   `json:"request"`
	SecurityContext       map[string]any   `json:"securityContext"`
	AuthenticationContext map[string]any   `json:"authenticationContext"`
	DebugContext          map[string]any   `json:"debugContext"`
	Transaction           map[string]any   `json:"transaction"`
	Target                []map[string]any `json:"target"`
	raw                   json.RawMessage
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
	mfa             userMFASummary
}

type userFactorRecord struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	FactorType string `json:"factorType"`
	Status     string `json:"status"`
}

type userMFASummary struct {
	known             bool
	activeFactorCount int
	factorTypes       []string
	phishingResistant bool
}

type groupRecord struct {
	ID                    string         `json:"id"`
	Created               *time.Time     `json:"created"`
	LastUpdated           *time.Time     `json:"lastUpdated"`
	LastMembershipUpdated *time.Time     `json:"lastMembershipUpdated"`
	Type                  string         `json:"type"`
	Profile               map[string]any `json:"profile"`
	raw                   json.RawMessage
}

type appRecord struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Label       string         `json:"label"`
	Status      string         `json:"status"`
	SignOnMode  string         `json:"signOnMode"`
	Created     *time.Time     `json:"created"`
	LastUpdated *time.Time     `json:"lastUpdated"`
	Credentials map[string]any `json:"credentials"`
	Settings    map[string]any `json:"settings"`
	raw         json.RawMessage
}

type appAssignmentRecord struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Scope       string         `json:"scope"`
	Created     *time.Time     `json:"created"`
	LastUpdated *time.Time     `json:"lastUpdated"`
	Credentials map[string]any `json:"credentials"`
	Profile     map[string]any `json:"profile"`
	AppID       string         `json:"-"`
	SubjectType string         `json:"-"`
	raw         json.RawMessage
}

type adminRoleRecord struct {
	ID             string     `json:"id"`
	Label          string     `json:"label"`
	Type           string     `json:"type"`
	AssignmentType string     `json:"assignmentType"`
	Status         string     `json:"status"`
	Created        *time.Time `json:"created"`
	LastUpdated    *time.Time `json:"lastUpdated"`
	raw            json.RawMessage
}

type auditPayload struct {
	UUID                  string            `json:"uuid"`
	Domain                string            `json:"domain"`
	Published             time.Time         `json:"published"`
	EventType             string            `json:"event_type"`
	DisplayMessage        string            `json:"display_message,omitempty"`
	Severity              string            `json:"severity,omitempty"`
	Actor                 identityPayload   `json:"actor,omitempty"`
	Outcome               outcomePayload    `json:"outcome,omitempty"`
	Client                clientPayload     `json:"client,omitempty"`
	Transaction           eventPayload      `json:"transaction,omitempty"`
	Targets               []identityPayload `json:"targets,omitempty"`
	ResourceID            string            `json:"resource_id,omitempty"`
	ResourceType          string            `json:"resource_type,omitempty"`
	AuthenticationContext map[string]any    `json:"authentication_context,omitempty"`
	SecurityContext       map[string]any    `json:"security_context,omitempty"`
	DebugData             map[string]any    `json:"debug_data,omitempty"`
	Request               map[string]any    `json:"request,omitempty"`
	Raw                   map[string]any    `json:"raw,omitempty"`
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

type identityPayload = oktaevent.Identity

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

type oktaListFunc[T any] func(context.Context, settings, string, int) ([]T, string, error)

type oktaFamilyOptions[T any] struct {
	Name           string
	Label          string
	List           oktaListFunc[T]
	Enrich         func(context.Context, settings, []T) ([]T, error)
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

func oktaFamily[T any](options oktaFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name, IncrementalWatermark: true,
		Check: func(ctx context.Context, settings settings) error {
			return oktaCheck(ctx, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, settings)
			}
			records, _, err := options.List(ctx, settings, "", settings.perPage)
			if err != nil {
				return nil, wrapLookupError(oktaLabel(options.Label, settings), err)
			}
			return oktaURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, settings, sourcecdk.CursorToken(cursor), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, wrapLookupError(oktaLabel(options.Label, settings), err)
			}
			if options.Enrich != nil && len(records) > 0 {
				records, err = options.Enrich(ctx, settings, records)
				if err != nil {
					return sourcecdk.Pull{}, wrapLookupError(oktaLabel(options.Label, settings), err)
				}
			}
			build := func(record T) (*primitives.Event, error) {
				return options.Event(settings, record)
			}
			return oktaPullFromRecordsWithCursor(records, next, build, options.CursorFallback)
		},
	}
}

func oktaAssetSettings(settings settings) oktaasset.Settings {
	return oktaasset.Settings{Domain: settings.domain, Filter: settings.filter, Q: settings.q, PerPage: settings.perPage}
}

func oktaCheck[T any](ctx context.Context, settings settings, list oktaListFunc[T], label string) error {
	_, _, err := list(ctx, settings, "", 1)
	if err != nil {
		return wrapLookupError(oktaLabel(label, settings), err)
	}
	return nil
}

func oktaLabel(label string, settings settings) string {
	return fmt.Sprintf("%s for %s", label, settings.domain)
}

func oktaURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func oktaPullFromRecordsWithCursor[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: sourcecdk.ResolveCursorOpaque(next, fallback, events[len(events)-1].OccurredAt.AsTime()),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func listJSONRecords[T any](ctx context.Context, source *Source, settings settings, requestPath string, query url.Values, label string, setRaw func(*T, json.RawMessage)) ([]T, string, error) {
	var rawRecords []json.RawMessage
	headers, err := source.getJSON(ctx, settings, requestPath, query, &rawRecords)
	if err != nil {
		return nil, "", err
	}
	records := make([]T, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		var record T
		if err := json.Unmarshal(rawRecord, &record); err != nil {
			return nil, "", fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, rawRecord)
		}
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
		client = oktaHTTPClientNoRedirect(nil, s != nil && s.allowLoopbackBaseURL, oktaLookupIPAddrs(s))
	} else {
		client = oktaHTTPClientNoRedirect(client, s != nil && s.allowLoopbackBaseURL, oktaLookupIPAddrs(s))
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{MaxBodyBytes: maxOktaBodyBytes})
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", requestPath, err)
	}
	headers := resp.Header.Clone()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return headers, decodeResponseError(resp.StatusCode, resp.Body)
	}
	if target == nil || len(resp.Body) == 0 {
		return headers, nil
	}
	if err := json.Unmarshal(resp.Body, target); err != nil {
		return headers, fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return headers, nil
}

func (s *Source) getJSONWithRetry(ctx context.Context, settings settings, requestPath string, query url.Values, target any, retryable func(error) bool) error {
	backoffs := s.mfaFactorRetryBackoffs()
	var err error
	for attempt := 0; ; attempt++ {
		_, err = s.getJSON(ctx, settings, requestPath, query, target)
		if err == nil {
			return nil
		}
		if retryable == nil || !retryable(err) || attempt >= len(backoffs) {
			return err
		}
		if sleepErr := sleepContext(ctx, backoffs[attempt]); sleepErr != nil {
			return sleepErr
		}
	}
}

func (s *Source) mfaFactorRetryBackoffs() []time.Duration {
	if s != nil && s.mfaFactorBackoffs != nil {
		return s.mfaFactorBackoffs
	}
	return defaultMFAFactorRetryBackoffs
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func oktaHTTPClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenSourceClient(client, "okta", oktaHTTPTimeout, allowLoopback, lookupIPAddrs)
}

func oktaLookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
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

func (s *Source) listAudit(ctx context.Context, settings settings, after string, limit int) ([]auditRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	sourcecdk.AddQueryParam(query, "filter", settings.filter)
	sourcecdk.AddQueryParam(query, "q", settings.q)
	sourcecdk.AddQueryParam(query, "since", settings.since)
	sourcecdk.AddQueryParam(query, "until", settings.until)
	sourcecdk.AddQueryParam(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/logs", query, "okta audit event", func(record *auditRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listUsers(ctx context.Context, settings settings, after string, limit int) ([]userRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	sourcecdk.AddQueryParam(query, "filter", settings.filter)
	sourcecdk.AddQueryParam(query, "q", settings.q)
	sourcecdk.AddQueryParam(query, "search", settings.search)
	sourcecdk.AddQueryParam(query, "sortBy", settings.sortBy)
	sourcecdk.AddQueryParam(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/users", query, "okta user", func(record *userRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) enrichUsersWithMFAFactors(ctx context.Context, settings settings, records []userRecord) ([]userRecord, error) {
	for i := range records {
		summary, err := s.userMFASummary(ctx, settings, records[i].ID)
		if err != nil {
			return nil, err
		}
		records[i].mfa = summary
	}
	return records, nil
}

func (s *Source) userMFASummary(ctx context.Context, settings settings, userID string) (userMFASummary, error) {
	if strings.TrimSpace(userID) == "" {
		return userMFASummary{}, nil
	}
	var factors []userFactorRecord
	requestPath := "/api/v1/users/" + url.PathEscape(userID) + "/factors"
	if err := s.getJSONWithRetry(ctx, settings, requestPath, nil, &factors, isRetryableMFAFactorError); err != nil {
		if isUnknownMFAFactorError(err) {
			return userMFASummary{}, nil
		}
		return userMFASummary{}, fmt.Errorf("list okta user %q factors: %w", userID, err)
	}
	activeCount := 0
	var factorTypes []string
	phishingResistant := false
	for _, factor := range factors {
		if oktaMFAFactorEnrolled(factor) {
			activeCount++
			kind := strings.ToLower(strings.TrimSpace(firstNonEmpty(factor.Kind, factor.FactorType)))
			factorTypes = append(factorTypes, kind)
			if kind == "webauthn" || kind == "u2f" || kind == "signed_nonce" {
				phishingResistant = true
			}
		}
	}
	return userMFASummary{known: true, activeFactorCount: activeCount, factorTypes: factorTypes, phishingResistant: phishingResistant}, nil
}

func (s *Source) listGroups(ctx context.Context, settings settings, after string, limit int) ([]groupRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	sourcecdk.AddQueryParam(query, "q", settings.q)
	sourcecdk.AddQueryParam(query, "search", settings.search)
	sourcecdk.AddQueryParam(query, "sortBy", settings.sortBy)
	sourcecdk.AddQueryParam(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/groups", query, "okta group", func(record *groupRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listGroupMembers(ctx context.Context, settings settings, after string, limit int) ([]userRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/groups/"+url.PathEscape(settings.groupID)+"/users", query, "okta group member", func(record *userRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listApplications(ctx context.Context, settings settings, after string, limit int) ([]appRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	sourcecdk.AddQueryParam(query, "q", settings.q)
	sourcecdk.AddQueryParam(query, "filter", settings.filter)

	return listJSONRecords(ctx, s, settings, "/api/v1/apps", query, "okta application", func(record *appRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listAppAssignments(ctx context.Context, settings settings, after string, limit int) ([]appAssignmentRecord, string, error) {
	phase, cursor := oktaevent.AssignmentCursor(after)
	if phase == "groups" {
		groups, next, err := s.listAppGroupAssignments(ctx, settings, cursor, limit)
		if next != "" {
			next = oktaevent.PhasedCursor("groups", next)
		}
		return groups, next, err
	}

	users, next, err := s.listAppUserAssignments(ctx, settings, cursor, limit)
	if err != nil || next != "" || len(users) >= limit {
		if next != "" {
			next = oktaevent.PhasedCursor("users", next)
		} else if len(users) >= limit {
			next = "groups:"
		}
		return users, next, err
	}

	groups, groupNext, err := s.listAppGroupAssignments(ctx, settings, "", limit-len(users))
	if err != nil {
		return nil, "", err
	}
	records := append(users, groups...)
	if groupNext != "" {
		groupNext = oktaevent.PhasedCursor("groups", groupNext)
	}
	return records, groupNext, nil
}

func (s *Source) listAppUserAssignments(ctx context.Context, settings settings, after string, limit int) ([]appAssignmentRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/apps/"+url.PathEscape(settings.appID)+"/users", query, "okta app user assignment", func(record *appAssignmentRecord, raw json.RawMessage) {
		record.AppID = settings.appID
		record.SubjectType = "user"
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listAppGroupAssignments(ctx context.Context, settings settings, after string, limit int) ([]appAssignmentRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/apps/"+url.PathEscape(settings.appID)+"/groups", query, "okta app group assignment", func(record *appAssignmentRecord, raw json.RawMessage) {
		record.AppID = settings.appID
		record.SubjectType = "group"
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listAdminRoles(ctx context.Context, settings settings, after string, limit int) ([]adminRoleRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/users/"+url.PathEscape(settings.userID)+"/roles", query, "okta admin role", func(record *adminRoleRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
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
		Targets:               targets,
		ResourceID:            resourceID,
		ResourceType:          resourceType,
		AuthenticationContext: record.AuthenticationContext,
		SecurityContext:       record.SecurityContext,
		DebugData:             nestedMap(record.DebugContext, "debugData"),
		Request:               record.Request,
		Raw:                   raw,
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
		Attributes: auditAttributes(settings, record, actor, targets, resourceID, resourceType),
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

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created, record.LastMembershipUpdated)
	raw, err := decodeRawPayload(record.raw, "okta group")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"id":      record.ID,
		"domain":  settings.domain,
		"type":    record.Type,
		"profile": record.Profile,
		"raw":     raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta group payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-group-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.group",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/group/v1",
		Payload:    payload,
		Attributes: groupAttributes(settings, record),
	}, nil
}

func groupMembershipEvent(settings settings, record userRecord) (*primitives.Event, error) {
	occurredAt := userOccurredAt(record)
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	raw, err := decodeRawPayload(record.raw, "okta group membership")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":   settings.domain,
		"group_id": settings.groupID,
		"user_id":  record.ID,
		"profile":  record.Profile,
		"raw":      raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta group membership payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-group-membership-%s-%s-%d", settings.groupID, record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.group_membership",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/group_membership/v1",
		Payload:    payload,
		Attributes: groupMembershipAttributes(settings, record),
	}, nil
}

func applicationEvent(settings settings, record appRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta application")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"id":           record.ID,
		"domain":       settings.domain,
		"name":         record.Name,
		"label":        record.Label,
		"status":       record.Status,
		"sign_on_mode": record.SignOnMode,
		"raw":          raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta application payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-application-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.application",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/application/v1",
		Payload:    payload,
		Attributes: applicationAttributes(settings, record),
	}, nil
}

func appAssignmentEvent(settings settings, record appAssignmentRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta app assignment")
	if err != nil {
		return nil, err
	}
	appID := firstNonEmpty(record.AppID, settings.appID)
	subjectType := firstNonEmpty(record.SubjectType, "user")
	payload, err := json.Marshal(map[string]any{
		"domain":       settings.domain,
		"app_id":       appID,
		"subject_id":   record.ID,
		"subject_type": subjectType,
		"status":       record.Status,
		"scope":        record.Scope,
		"credentials":  record.Credentials,
		"profile":      record.Profile,
		"raw":          raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta app assignment payload: %w", err)
	}
	eventID := fmt.Sprintf("okta-app-assignment-%s-%s-%d", appID, record.ID, occurredAt.UnixMilli())
	if subjectType != "user" {
		eventID = fmt.Sprintf("okta-app-assignment-%s-%s-%s-%d", appID, subjectType, record.ID, occurredAt.UnixMilli())
	}
	return &primitives.Event{
		Id:         eventID,
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.app_assignment",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/app_assignment/v1",
		Payload:    payload,
		Attributes: appAssignmentAttributes(settings, record),
	}, nil
}

func adminRoleEvent(settings settings, record adminRoleRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta admin role")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":     settings.domain,
		"user_id":    settings.userID,
		"user_email": settings.userEmail,
		"id":         record.ID,
		"label":      record.Label,
		"type":       record.Type,
		"status":     record.Status,
		"assignment": record.AssignmentType,
		"raw":        raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta admin role payload: %w", err)
	}
	roleID := firstNonEmpty(record.ID, record.Type, record.Label)
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-admin-role-%s-%s-%d", settings.userID, roleID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.admin_role",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/admin_role/v1",
		Payload:    payload,
		Attributes: adminRoleAttributes(settings, record),
	}, nil
}

func auditAttributes(settings settings, record auditRecord, actor identityPayload, targets []identityPayload, resourceID string, resourceType string) map[string]string {
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
	addAttribute(attributes, "actor_email", actor.AlternateID)
	addAttribute(attributes, "actor_display_name", actor.DisplayName)
	addAttribute(attributes, "client_ip", stringMap(record.Client, "ipAddress"))
	addAttribute(attributes, "client_user_agent", stringMap(nestedMap(record.Client, "userAgent"), "rawUserAgent"))
	addAttribute(attributes, "client_zone", stringMap(record.Client, "zone"))
	addAttribute(attributes, "client_device", stringMap(record.Client, "device"))
	addAttribute(attributes, "client_city", stringMap(nestedMap(record.Client, "geographicalContext"), "city"))
	addAttribute(attributes, "client_state", stringMap(nestedMap(record.Client, "geographicalContext"), "state"))
	addAttribute(attributes, "client_country", stringMap(nestedMap(record.Client, "geographicalContext"), "country"))
	addAttribute(attributes, "outcome_reason", stringMap(record.Outcome, "reason"))
	addAttribute(attributes, "outcome_result", stringMap(record.Outcome, "result"))
	addAttribute(attributes, "severity", record.Severity)
	addAttribute(attributes, "transaction_id", stringMap(record.Transaction, "id"))
	oktaevent.AddSystemLogAttributes(attributes, oktaevent.SystemLogContext{
		Client:                record.Client,
		Request:               record.Request,
		SecurityContext:       record.SecurityContext,
		AuthenticationContext: record.AuthenticationContext,
		DebugContext:          record.DebugContext,
		Transaction:           record.Transaction,
	})
	oktaevent.AddTargetAttributes(attributes, targets)
	if len(targets) != 0 {
		target := targets[0]
		addAttribute(attributes, "target_id", target.ID)
		addAttribute(attributes, "target_type", target.Type)
		addAttribute(attributes, "target_alternate_id", target.AlternateID)
		addAttribute(attributes, "target_display_name", target.DisplayName)
	}
	if category := oktaevent.OAuthEventCategory(record.EventType); category != "" {
		attributes["oauth_event_category"] = category
		addAttribute(attributes, "grant_type", oktaevent.OAuthGrantType(record.EventType))
		if client := oktaevent.OAuthClientIdentity(actor, targets); client != (identityPayload{}) {
			addAttribute(attributes, "oauth_client_id", client.ID)
			addAttribute(attributes, "oauth_client_type", client.Type)
			addAttribute(attributes, "oauth_client_label", firstNonEmpty(client.DisplayName, client.AlternateID, client.ID))
			addAttribute(attributes, "client_id", client.ID)
		}
	}
	return attributes
}

func userAttributes(settings settings, record userRecord) map[string]string {
	attributes := map[string]string{
		"domain":           settings.domain,
		"family":           familyUser,
		"mfa_enrolled":     "",
		"mfa_factor_count": "",
		"user_id":          record.ID,
	}
	if record.mfa.known {
		attributes["mfa_enrolled"] = boolString(record.mfa.activeFactorCount > 0)
		attributes["mfa_factor_count"] = strconv.Itoa(record.mfa.activeFactorCount)
		if len(record.mfa.factorTypes) > 0 {
			sort.Strings(record.mfa.factorTypes)
			attributes["mfa_factor_types"] = strings.Join(record.mfa.factorTypes, ",")
		}
		attributes["mfa_phishing_resistant"] = boolString(record.mfa.phishingResistant)
	}
	addAttribute(attributes, "email", stringMap(record.Profile, "email"))
	addAttribute(attributes, "login", stringMap(record.Profile, "login"))
	addAttribute(attributes, "realm_id", record.RealmID)
	addAttribute(attributes, "status", record.Status)
	addAttribute(attributes, "type_id", stringMap(record.Type, "id"))
	addAttribute(attributes, "type_name", stringMap(record.Type, "name"))
	addAttribute(attributes, "user_type", stringMap(record.Profile, "userType"))
	addAttribute(attributes, "department", stringMap(record.Profile, "department"))
	addAttribute(attributes, "job_title", stringMap(record.Profile, "title"))
	addAttribute(attributes, "title", stringMap(record.Profile, "title"))
	addAttribute(attributes, "organization", stringMap(record.Profile, "organization"))
	addAttribute(attributes, "manager", stringMap(record.Profile, "manager"))
	addAttribute(attributes, "manager_id", stringMap(record.Profile, "managerId"))
	addAttribute(attributes, "employee_number", stringMap(record.Profile, "employeeNumber"))
	return attributes
}

func groupAttributes(settings settings, record groupRecord) map[string]string {
	attributes := map[string]string{
		"domain":   settings.domain,
		"family":   familyGroup,
		"group_id": record.ID,
	}
	addAttribute(attributes, "group_name", stringMap(record.Profile, "name"))
	addAttribute(attributes, "name", stringMap(record.Profile, "name"))
	addAttribute(attributes, "description", stringMap(record.Profile, "description"))
	addAttribute(attributes, "group_email", firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login")))
	addAttribute(attributes, "email", firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login")))
	addAttribute(attributes, "type", record.Type)
	return attributes
}

func groupMembershipAttributes(settings settings, record userRecord) map[string]string {
	memberEmail := firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login"))
	attributes := map[string]string{
		"domain":         settings.domain,
		"family":         familyGroupMember,
		"group_id":       settings.groupID,
		"member_id":      record.ID,
		"member_user_id": record.ID,
		"member_type":    "user",
		"user_id":        record.ID,
	}
	addAttribute(attributes, "member_email", memberEmail)
	addAttribute(attributes, "email", memberEmail)
	addAttribute(attributes, "member_name", firstNonEmpty(stringMap(record.Profile, "displayName"), strings.TrimSpace(strings.Join([]string{stringMap(record.Profile, "firstName"), stringMap(record.Profile, "lastName")}, " "))))
	addAttribute(attributes, "member_status", record.Status)
	if strings.Contains(settings.groupID, "@") {
		addAttribute(attributes, "group_email", settings.groupID)
	}
	return attributes
}

func applicationAttributes(settings settings, record appRecord) map[string]string {
	mode := strings.ToLower(record.Name + " " + record.SignOnMode)
	oauthClient := nestedMap(record.Settings, "oauthClient")
	oauthCredential := nestedMap(record.Credentials, "oauthClient")
	applicationType := stringMap(oauthClient, "application_type")
	tokenAuthMethod := stringMap(oauthCredential, "token_endpoint_auth_method")
	grantTypes := stringSliceMap(oauthClient, "grant_types")
	responseTypes := stringSliceMap(oauthClient, "response_types")
	attributes := map[string]string{
		"domain":   settings.domain,
		"family":   familyApplication,
		"app_id":   record.ID,
		"status":   record.Status,
		"app_name": firstNonEmpty(record.Label, record.Name),
	}
	addAttribute(attributes, "app_label", record.Label)
	addAttribute(attributes, "name", record.Name)
	addAttribute(attributes, "sign_on_mode", record.SignOnMode)
	addAttribute(attributes, "client_id", stringMap(oauthCredential, "client_id"))
	addAttribute(attributes, "application_type", applicationType)
	addAttribute(attributes, "grant_types", strings.Join(grantTypes, ","))
	addAttribute(attributes, "response_types", strings.Join(responseTypes, ","))
	addAttribute(attributes, "token_endpoint_auth_method", tokenAuthMethod)
	addAttribute(attributes, "oauth_client_type", oktaOAuthClientType(applicationType, tokenAuthMethod))
	addAttribute(attributes, "oauth_public_client", boolString(oktaOAuthPublicClient(applicationType, tokenAuthMethod)))
	oktaasset.AddOAuthRedirectAttributes(attributes, oktaasset.OAuthRedirectSettings{RedirectURIs: stringSliceMap(oauthClient, "redirect_uris"), PostLogoutRedirectURIs: stringSliceMap(oauthClient, "post_logout_redirect_uris")})
	addAttribute(attributes, "wildcard_redirect", boolString(oktaOAuthWildcardRedirect(oauthClient)))
	addAttribute(attributes, "oauth2", boolString(strings.Contains(mode, "oidc") || strings.Contains(mode, "oauth") || len(grantTypes) != 0 || len(responseTypes) != 0 || applicationType != ""))
	addAttribute(attributes, "saml", boolString(strings.Contains(mode, "saml")))
	return attributes
}

func oktaOAuthClientType(applicationType string, tokenAuthMethod string) string {
	if oktaOAuthPublicClient(applicationType, tokenAuthMethod) {
		return "PublicClientApp"
	}
	if strings.TrimSpace(applicationType) != "" || strings.TrimSpace(tokenAuthMethod) != "" {
		return "ConfidentialClientApp"
	}
	return ""
}

func oktaOAuthPublicClient(applicationType string, tokenAuthMethod string) bool {
	switch strings.ToLower(strings.TrimSpace(applicationType)) {
	case "browser", "native", "spa":
		return true
	}
	return strings.EqualFold(strings.TrimSpace(tokenAuthMethod), "none")
}

func oktaOAuthWildcardRedirect(oauthClient map[string]any) bool {
	for _, key := range []string{"redirect_uris", "post_logout_redirect_uris"} {
		for _, uri := range stringSliceMap(oauthClient, key) {
			if strings.Contains(uri, "*") {
				return true
			}
		}
	}
	return false
}

func appAssignmentAttributes(settings settings, record appAssignmentRecord) map[string]string {
	subjectEmail := assignmentEmail(record)
	subjectType := firstNonEmpty(record.SubjectType, "user")
	appID := firstNonEmpty(record.AppID, settings.appID)
	attributes := oktaevent.AppAssignmentAttributes(settings.domain, familyAppAssign, appID, record.ID, subjectType, record.Status)
	addAttribute(attributes, "subject_email", subjectEmail)
	addAttribute(attributes, "email", subjectEmail)
	addAttribute(attributes, "subject_name", firstNonEmpty(stringMap(record.Profile, "displayName"), stringMap(record.Profile, "name"), subjectEmail, record.ID))
	if subjectType == "group" {
		addAttribute(attributes, "group_id", record.ID)
		addAttribute(attributes, "group_name", firstNonEmpty(stringMap(record.Profile, "name"), stringMap(record.Profile, "displayName")))
	}
	addAttribute(attributes, "scope", record.Scope)
	return attributes
}

func adminRoleAttributes(settings settings, record adminRoleRecord) map[string]string {
	roleID := firstNonEmpty(record.ID, record.Type, record.Label)
	attributes := map[string]string{
		"domain":           settings.domain,
		"family":           familyAdminRole,
		"role_id":          roleID,
		"role_name":        firstNonEmpty(record.Label, record.Type, roleID),
		"role_type":        record.Type,
		"subject_id":       settings.userID,
		"subject_type":     "user",
		"event_type":       "admin.role.assignment",
		"action":           "admin.role.assignment",
		"is_admin":         "true",
		"actor_privileged": "true",
	}
	addAttribute(attributes, "assigned_to", settings.userID)
	addAttribute(attributes, "subject_email", settings.userEmail)
	addAttribute(attributes, "email", settings.userEmail)
	addAttribute(attributes, "status", record.Status)
	addAttribute(attributes, "assignment_type", record.AssignmentType)
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

func firstRecordTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func assignmentEmail(record appAssignmentRecord) string {
	return firstNonEmpty(
		stringMap(record.Profile, "email"),
		stringMap(record.Profile, "login"),
		stringMap(record.Profile, "userName"),
		stringMap(record.Credentials, "userName"),
	)
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

func utcTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
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

func stringSliceMap(values map[string]any, key string) []string {
	value, ok := values[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(text)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	return textutil.FirstNonEmpty(values...)
}

func boolString(value bool) string {
	return strconv.FormatBool(value)
}

func oktaMFAFactorEnrolled(factor userFactorRecord) bool {
	if !strings.EqualFold(strings.TrimSpace(factor.Status), "ACTIVE") {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(firstNonEmpty(factor.Kind, factor.FactorType)))
	_, ok := oktaMFAEnrollmentFactorKinds[kind]
	return ok
}

func isRetryableMFAFactorError(err error) bool {
	var responseErr *responseError
	if !errors.As(err, &responseErr) {
		return false
	}
	return responseErr.statusCode == http.StatusTooManyRequests || responseErr.statusCode >= http.StatusInternalServerError
}

func isUnknownMFAFactorError(err error) bool {
	var responseErr *responseError
	if !errors.As(err, &responseErr) {
		return false
	}
	return responseErr.statusCode == http.StatusForbidden ||
		responseErr.statusCode == http.StatusTooManyRequests ||
		responseErr.statusCode >= http.StatusInternalServerError
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
