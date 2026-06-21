package cosmo

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
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
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/internal/sourceidentity"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID        = "cosmo"
	defaultFamily   = familySession
	defaultPageSize = 100
	maxPageSize     = 500
	httpTimeout     = 30 * time.Second
	maxBodyBytes    = 8 << 20

	familyFact                         = "fact"
	familyMessage                      = "message"
	familySession                      = "session"
	familySurveyFeedback               = "survey_feedback"
	messageExportCursorSource          = "cosmo.message"
	defaultMessageExportInitialSince   = "1970-01-01T00:00:00Z"
	defaultMessageExportEventTypes     = "message,completion"
	defaultMessageExportMaxWindowHours = 24
	messageExportMaxWindowHours        = 24
	messageExportMaxPageSize           = 100
	messageExportMaxOffset             = 10000
)

// Source reads Cosmo memory and feedback data.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	tenantID      string
	family        string
	baseURL       string
	token         string
	webhookSecret string
	query         string
	user          string
	status        string
	category      string
	ticketID      string
	eventType     string
	clientID      string
	exportSecret  string
	eventTypes    []string
	initialSince  time.Time
	maxWindow     time.Duration
	perPage       int
}

type messageCursor struct {
	Source              string `json:"source"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	Since               string `json:"since"`
	Until               string `json:"until,omitempty"`
	EventTypeIndex      int    `json:"event_type_index,omitempty"`
	Offset              int    `json:"offset,omitempty"`
}

type messageWindow struct {
	since          time.Time
	until          time.Time
	eventTypeIndex int
	offset         int
}

type record struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type listResponse struct {
	OK       bool              `json:"ok"`
	Count    int               `json:"count"`
	Sessions []json.RawMessage `json:"sessions"`
	Facts    []json.RawMessage `json:"facts"`
	Messages []json.RawMessage `json:"messages"`
	Feedback []json.RawMessage `json:"feedback"`
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

// New constructs the Cosmo source.
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

// Spec returns static Cosmo source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured Cosmo family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical Cosmo URNs for one configured page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages Cosmo records and emits cosmo.* events.
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
		s.memoryFamily(familySession, "/api/ui/memory/sessions", "sessions"),
		s.memoryFamily(familyFact, "/api/ui/memory/facts", "facts"),
		s.messageFamily(),
		s.surveyFeedbackFamily(),
	)
}

func (s *Source) memoryFamily(family string, path string, collection string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.listMemory(ctx, settings, path, collection, 0, 1)
			if err != nil {
				return fmt.Errorf("cosmo %s: %w", family, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.listMemory(ctx, settings, path, collection, 0, familyPageSize(settings, family))
			if err != nil {
				return nil, fmt.Errorf("cosmo %s: %w", family, err)
			}
			return urnsFor(settings, family, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			offset, err := readOffset(cursor)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			limit := familyPageSize(settings, family)
			records, next, err := s.listMemory(ctx, settings, path, collection, offset, limit)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo %s: %w", family, err)
			}
			return pullFromRecords(settings, family, records, next)
		},
	}
}

func (s *Source) messageFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyMessage,
		Check: func(ctx context.Context, settings settings) error {
			window, ok, err := readMessageCursor(settings, nil, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			_, err = s.listMessages(ctx, settings, window, 1)
			if err != nil {
				return fmt.Errorf("cosmo message: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			window, ok, err := readMessageCursor(settings, nil, time.Now())
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, nil
			}
			records := make([]record, 0, settings.perPage)
			for eventTypeIndex := range settings.eventTypes {
				if len(records) >= settings.perPage {
					break
				}
				eventWindow := window
				eventWindow.eventTypeIndex = eventTypeIndex
				eventWindow.offset = 0
				remaining := settings.perPage - len(records)
				page, err := s.listMessages(ctx, settings, eventWindow, remaining)
				if err != nil {
					return nil, fmt.Errorf("cosmo message: %w", err)
				}
				records = append(records, page...)
			}
			return urnsFor(settings, familyMessage, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			window, ok, err := readMessageCursor(settings, cursor, time.Now())
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			if !ok {
				checkpoint := messageCheckpointCursor(window.since)
				return messagePullFromRecords(settings, nil, "", checkpoint, window.since)
			}
			records, err := s.listMessages(ctx, settings, window, settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo message: %w", err)
			}
			next, checkpoint := nextMessageCursor(settings, window, len(records), settings.perPage)
			return messagePullFromRecords(settings, records, next, checkpoint, window.until)
		},
	}
}

func (s *Source) surveyFeedbackFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familySurveyFeedback,
		Check: func(ctx context.Context, settings settings) error {
			_, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return nil, fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			page, _ := pageRecords(records, 0, settings.perPage)
			return urnsFor(settings, familySurveyFeedback, page)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			offset, err := readOffset(cursor)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := s.listSurveyFeedback(ctx, settings)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("cosmo survey_feedback: %w", err)
			}
			page, next := pageRecords(records, offset, settings.perPage)
			return pullFromRecords(settings, familySurveyFeedback, page, next)
		},
	}
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	settings := settings{
		tenantID:      configValue(cfg, "tenant_id"),
		family:        configValue(cfg, "family"),
		baseURL:       configValue(cfg, "base_url"),
		token:         configValue(cfg, "token"),
		webhookSecret: configValue(cfg, "webhook_secret"),
		query:         configValue(cfg, "q"),
		user:          configValue(cfg, "user"),
		status:        configValue(cfg, "status"),
		category:      configValue(cfg, "category"),
		ticketID:      configValue(cfg, "ticket_id"),
		eventType:     configValue(cfg, "event_type"),
		clientID:      configValue(cfg, "client_id"),
		exportSecret:  configValue(cfg, "export_secret"),
		perPage:       defaultPageSize,
	}
	if settings.tenantID == "" {
		return settings, fmt.Errorf("cosmo tenant_id is required")
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyFact, familyMessage, familySession, familySurveyFeedback:
	default:
		return settings, fmt.Errorf("cosmo family must be one of fact, message, session, or survey_feedback")
	}
	if settings.baseURL == "" {
		return settings, fmt.Errorf("cosmo base_url is required")
	}
	normalizedBase, err := normalizeBaseURL(settings.baseURL, allowLoopback)
	if err != nil {
		return settings, err
	}
	settings.baseURL = normalizedBase
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse cosmo per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("cosmo per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	if settings.family == familySurveyFeedback {
		if settings.token == "" && settings.webhookSecret == "" {
			return settings, fmt.Errorf("cosmo token or webhook_secret is required when family=%q", familySurveyFeedback)
		}
		if settings.token != "" && settings.webhookSecret != "" {
			return settings, fmt.Errorf("cosmo token and webhook_secret are mutually exclusive when family=%q", familySurveyFeedback)
		}
		return settings, nil
	}
	if settings.token == "" {
		return settings, fmt.Errorf("cosmo token is required")
	}
	if settings.webhookSecret != "" {
		return settings, fmt.Errorf("cosmo webhook_secret is only supported when family=%q", familySurveyFeedback)
	}
	switch settings.family {
	case familySession:
		if settings.category != "" || settings.ticketID != "" || settings.eventType != "" {
			return settings, fmt.Errorf("cosmo category, ticket_id, and event_type are not supported when family=%q", familySession)
		}
	case familyFact:
		if settings.user != "" || settings.status != "" || settings.ticketID != "" || settings.eventType != "" {
			return settings, fmt.Errorf("cosmo user, status, ticket_id, and event_type are not supported when family=%q", familyFact)
		}
	case familyMessage:
		if settings.query != "" || settings.user != "" || settings.status != "" || settings.category != "" {
			return settings, fmt.Errorf("cosmo q, user, status, and category are not supported when family=%q", familyMessage)
		}
		if settings.ticketID != "" {
			return settings, fmt.Errorf("cosmo ticket_id is not supported when family=%q", familyMessage)
		}
		if settings.clientID == "" {
			return settings, fmt.Errorf("cosmo client_id is required when family=%q", familyMessage)
		}
		if settings.exportSecret == "" {
			return settings, fmt.Errorf("cosmo export_secret is required when family=%q", familyMessage)
		}
		if settings.perPage > messageExportMaxPageSize {
			return settings, fmt.Errorf("cosmo per_page must be between 1 and %d when family=%q", messageExportMaxPageSize, familyMessage)
		}
		eventTypes, err := parseMessageEventTypes(configValue(cfg, "event_types"), settings.eventType)
		if err != nil {
			return settings, err
		}
		settings.eventTypes = eventTypes
		maxWindow, err := parseMessageMaxWindow(configValue(cfg, "max_window_hours"))
		if err != nil {
			return settings, err
		}
		settings.maxWindow = maxWindow
		initialSince, err := parseMessageInitialSince(configValue(cfg, "since"))
		if err != nil {
			return settings, err
		}
		settings.initialSince = initialSince
	}
	return settings, nil
}

func parseMessageEventTypes(raw string, fallback string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = strings.TrimSpace(fallback)
	}
	if value == "" {
		value = defaultMessageExportEventTypes
	}
	seen := map[string]struct{}{}
	parts := strings.Split(value, ",")
	eventTypes := make([]string, 0, len(parts))
	for _, part := range parts {
		eventType := strings.TrimSpace(part)
		if eventType == "" {
			continue
		}
		if _, ok := seen[eventType]; ok {
			continue
		}
		seen[eventType] = struct{}{}
		eventTypes = append(eventTypes, eventType)
	}
	if len(eventTypes) == 0 {
		return nil, fmt.Errorf("cosmo event_types must include at least one value when family=%q", familyMessage)
	}
	return eventTypes, nil
}

func parseMessageMaxWindow(raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = strconv.Itoa(defaultMessageExportMaxWindowHours)
	}
	hours, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse cosmo max_window_hours: %w", err)
	}
	if hours < 1 || hours > messageExportMaxWindowHours {
		return 0, fmt.Errorf("cosmo max_window_hours must be between 1 and %d when family=%q", messageExportMaxWindowHours, familyMessage)
	}
	return time.Duration(hours) * time.Hour, nil
}

func parseMessageInitialSince(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = defaultMessageExportInitialSince
	}
	parsed, ok := parseMessageCursorTime(value)
	if !ok {
		return time.Time{}, fmt.Errorf("cosmo since must be an ISO timestamp when family=%q", familyMessage)
	}
	return parsed, nil
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse cosmo base_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("cosmo base_url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("cosmo base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("cosmo base_url must not include user info, query, or fragment")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", fmt.Errorf("cosmo base_url must be an origin URL")
	}
	allowCustomLoopbackPort := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomLoopbackPort {
		return "", fmt.Errorf("cosmo base_url must not include a custom port")
	}
	if sourcecdk.IsUnsafeHost(host) && !allowCustomLoopbackPort {
		return "", fmt.Errorf("cosmo base_url must not target loopback, private, or link-local hosts")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (s *Source) listMemory(ctx context.Context, settings settings, path string, collection string, offset int, limit int) ([]record, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(offset))
	addQuery(query, "q", settings.query)
	addQuery(query, "user", settings.user)
	addQuery(query, "status", settings.status)
	addQuery(query, "category", settings.category)

	var response listResponse
	if err := s.getJSON(ctx, settings, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := responseRecords(response, collection, settings.family)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(records) == limit {
		next = strconv.Itoa(offset + limit)
	}
	return records, next, nil
}

func (s *Source) listMessages(ctx context.Context, settings settings, window messageWindow, limit int) ([]record, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(window.offset))
	query.Set("event_type", settings.eventTypes[window.eventTypeIndex])
	query.Set("since", window.since.Format(time.RFC3339Nano))
	query.Set("until", window.until.Format(time.RFC3339Nano))

	var response listResponse
	if err := s.getJSON(ctx, settings, http.MethodGet, "/api/cerebro/messages", query, nil, &response); err != nil {
		return nil, err
	}
	records, err := responseRecords(response, "messages", familyMessage)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Source) listSurveyFeedback(ctx context.Context, settings settings) ([]record, error) {
	var response listResponse
	if settings.token != "" {
		if err := s.getJSON(ctx, settings, http.MethodGet, "/api/ui/memory/survey-results", nil, nil, &response); err != nil {
			return nil, err
		}
	} else {
		if err := s.getJSON(ctx, settings, http.MethodPost, "/api/survey-results", nil, []byte("{}"), &response); err != nil {
			return nil, err
		}
	}
	return responseRecords(response, "feedback", familySurveyFeedback)
}

func (s *Source) getJSON(ctx context.Context, settings settings, method string, requestPath string, query url.Values, body []byte, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if settings.family == familySurveyFeedback && settings.webhookSecret != "" {
		req.Header.Set("X-Webhook-Secret", settings.webhookSecret)
	} else {
		req.Header.Set("Authorization", "Bearer "+settings.token)
	}
	if settings.family == familyMessage {
		req.Header.Set("X-Cosmo-Client", settings.clientID)
		req.Header.Set("X-Cerebro-Export-Secret", settings.exportSecret)
	}

	client := s.client
	if client == nil {
		client = httpClientNoRedirect(nil, s != nil && s.allowLoopbackBaseURL, lookupIPAddrs(s))
	} else {
		client = httpClientNoRedirect(client, s != nil && s.allowLoopbackBaseURL, lookupIPAddrs(s))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	payload, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, payload)
	}
	if target == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func responseRecords(response listResponse, collection string, family string) ([]record, error) {
	var rawRecords []json.RawMessage
	switch collection {
	case "sessions":
		rawRecords = response.Sessions
	case "facts":
		rawRecords = response.Facts
	case "messages":
		rawRecords = response.Messages
	case "feedback":
		rawRecords = response.Feedback
	default:
		return nil, fmt.Errorf("unsupported cosmo collection %q", collection)
	}
	records := make([]record, 0, len(rawRecords))
	for _, raw := range rawRecords {
		record, err := parseRecord(family, raw)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func parseRecord(family string, raw json.RawMessage) (record, error) {
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return record{}, fmt.Errorf("decode cosmo %s record: %w", family, err)
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: recordID(family, values)}, nil
}

func recordID(family string, values map[string]any) string {
	switch family {
	case familySession:
		return firstValueString(values, "thread_key", "ticket_id", "id")
	case familyFact:
		return firstValueString(values, "key", "id")
	case familyMessage:
		return firstNonEmpty(firstValueString(values, "id"), stableID(
			firstValueString(values, "ticket_id"),
			firstValueString(values, "event_type"),
			firstValueString(values, "created_at"),
		))
	case familySurveyFeedback:
		return firstNonEmpty(firstValueString(values, "key"), stableID(
			firstValueString(values, "ticketId"),
			firstValueString(values, "messageTs"),
			firstValueString(values, "userId"),
		))
	default:
		return firstValueString(values, "id", "key")
	}
}

func urnsFor(settings settings, family string, records []record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := recordURN(settings, family, record.ID)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func recordURN(settings settings, family string, id string) (sourcecdk.URN, error) {
	return sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", normalizeID(settings.tenantID), family, sourceidentity.HashedExternalIDKey(id, "unknown")))
}

func pullFromRecords(settings settings, family string, records []record, next string) (sourcecdk.Pull, error) {
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
			CursorOpaque: checkpointCursor(next, events[len(events)-1].Id),
		},
	}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return pull, nil
}

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	attrs := attributesFor(family, record.Values)
	attrs["record_id"] = record.ID
	trimEmptyAttributes(attrs)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "cosmo." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "cosmo/" + family + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attrs,
	}
}

func eventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{sourceID, normalizeID(settings.tenantID), family, sourceidentity.HashedExternalIDKey(recordID, "unknown")}, "-")
}

func attributesFor(family string, values map[string]any) map[string]string {
	attrs := map[string]string{}
	switch family {
	case familySession:
		attrs["ticket_id"] = firstValueString(values, "ticket_id")
		attrs["thread_key"] = firstValueString(values, "thread_key")
		attrs["user"] = firstValueString(values, "user")
		attrs["agent_type"] = firstValueString(values, "agent_type")
		attrs["status"] = firstValueString(values, "status")
		attrs["source"] = firstValueString(values, "source")
	case familyFact:
		attrs["key"], attrs["category"] = firstValueString(values, "key"), firstValueString(values, "category")
		attrs["source"], attrs["confidence"] = firstValueString(values, "source"), firstValueString(values, "confidence")
		attrs["risk_reason"] = firstValueString(values, "risk_reason")
		attrs["risk_severity"] = firstValueString(values, "risk_severity", "severity")
	case familyMessage:
		attrs["ticket_id"] = firstValueString(values, "ticket_id")
		attrs["event_type"] = firstValueString(values, "event_type")
		attrs["role"] = firstValueString(values, "role")
		attrs["user"] = firstValueString(values, "user", "username")
		attrs["user_id"] = firstValueString(values, "user_id", "userId", "user.id")
		attrs["email"] = firstValueString(values, "email", "user_email", "userEmail", "user.email")
		attrs["tool_name"] = firstValueString(values, "tool_name")
		attrs["agent_type"] = firstValueString(values, "agent_type")
		attrs["run_url"] = firstValueString(values, "run_url")
	case familySurveyFeedback:
		attrs["ticket_id"] = firstValueString(values, "ticketId")
		attrs["channel"] = firstValueString(values, "channel")
		attrs["user_id"] = firstValueString(values, "userId")
		attrs["reaction"] = firstValueString(values, "reaction")
		attrs["sentiment"] = firstValueString(values, "sentiment")
		attrs["workflow_run_url"] = firstValueString(values, "workflowRunUrl")
	}
	return attrs
}

func familyPageSize(settings settings, family string) int {
	limit := settings.perPage
	switch family {
	case familySession:
		if limit > 100 {
			return 100
		}
	case familyFact:
		if limit > 200 {
			return 200
		}
	}
	return limit
}

func pageRecords(records []record, offset int, limit int) ([]record, string) {
	if offset >= len(records) {
		return nil, ""
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	next := ""
	if end < len(records) {
		next = strconv.Itoa(end)
	}
	return records[offset:end], next
}

func readOffset(cursor *cerebrov1.SourceCursor) (int, error) {
	if cursor == nil || strings.TrimSpace(cursor.Opaque) == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(strings.TrimSpace(cursor.Opaque))
	if err != nil {
		return 0, fmt.Errorf("parse cosmo cursor: %w", err)
	}
	if offset < 0 {
		return 0, fmt.Errorf("cosmo cursor must be non-negative")
	}
	return offset, nil
}

func readMessageCursor(settings settings, cursor *cerebrov1.SourceCursor, now time.Time) (messageWindow, bool, error) {
	now = now.UTC()
	if cursor == nil || strings.TrimSpace(cursor.Opaque) == "" {
		since := settings.initialSince
		until := minTime(since.Add(settings.maxWindow), now)
		window := messageWindow{since: since, until: until}
		return window, until.After(since), nil
	}
	var payload messageCursor
	if err := json.Unmarshal([]byte(strings.TrimSpace(cursor.Opaque)), &payload); err != nil {
		return messageWindow{}, false, fmt.Errorf("parse cosmo message cursor: %w", err)
	}
	if payload.Source != messageExportCursorSource {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor source = %q, want %q", payload.Source, messageExportCursorSource)
	}
	if payload.EventTypeIndex < 0 || payload.EventTypeIndex >= len(settings.eventTypes) {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor event_type_index is out of range")
	}
	if payload.Offset < 0 {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor offset must be non-negative")
	}
	since, ok := parseMessageCursorTime(payload.Since)
	if !ok {
		return messageWindow{}, false, fmt.Errorf("cosmo message cursor since must be an ISO timestamp")
	}
	eventTypeIndex := payload.EventTypeIndex
	offset := payload.Offset
	var until time.Time
	if strings.TrimSpace(payload.Until) == "" {
		until = minTime(since.Add(settings.maxWindow), now)
		eventTypeIndex = 0
		offset = 0
	} else {
		var parsed bool
		until, parsed = parseMessageCursorTime(payload.Until)
		if !parsed {
			return messageWindow{}, false, fmt.Errorf("cosmo message cursor until must be an ISO timestamp")
		}
		if until.Sub(since) > settings.maxWindow {
			return messageWindow{}, false, fmt.Errorf("cosmo message cursor window exceeds max_window_hours")
		}
	}
	window := messageWindow{since: since, until: until, eventTypeIndex: eventTypeIndex, offset: offset}
	if !until.After(since) {
		return window, false, nil
	}
	return window, true, nil
}

func parseMessageCursorTime(value string) (time.Time, bool) {
	parsed, ok := parseTime(value)
	if !ok {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func nextMessageCursor(settings settings, window messageWindow, records int, limit int) (string, string) {
	if records == limit && window.offset+limit < messageExportMaxOffset {
		next := encodeMessageCursor(window.since, window.until, window.eventTypeIndex, window.offset+limit)
		return next, next
	}
	if window.eventTypeIndex+1 < len(settings.eventTypes) {
		next := encodeMessageCursor(window.since, window.until, window.eventTypeIndex+1, 0)
		return next, next
	}
	checkpoint := messageCheckpointCursor(window.until)
	return "", checkpoint
}

func messageCheckpointCursor(since time.Time) string {
	return encodeMessageCursor(since, time.Time{}, 0, 0)
}

func encodeMessageCursor(since time.Time, until time.Time, eventTypeIndex int, offset int) string {
	payload := messageCursor{
		Source:              messageExportCursorSource,
		ResumableCheckpoint: true,
		Since:               since.UTC().Format(time.RFC3339Nano),
		EventTypeIndex:      eventTypeIndex,
		Offset:              offset,
	}
	if !until.IsZero() {
		payload.Until = until.UTC().Format(time.RFC3339Nano)
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}

func messagePullFromRecords(settings settings, records []record, next string, checkpoint string, watermark time.Time) (sourcecdk.Pull, error) {
	pull := sourcecdk.Pull{
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    timestamppb.New(watermark.UTC()),
			CursorOpaque: strings.TrimSpace(checkpointCursor(next, checkpoint)),
		},
	}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	if len(records) == 0 {
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		events = append(events, eventFromRecord(settings, familyMessage, record))
	}
	pull.Events = events
	pull.Checkpoint.Watermark = events[len(events)-1].OccurredAt
	return pull, nil
}

func minTime(left time.Time, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func httpClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "cosmo",
		Timeout:       httpTimeout,
		AllowLoopback: allowLoopback,
		LookupIPAddrs: lookupIPAddrs,
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
		message = strings.TrimSpace(apiErr.Error)
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("cosmo API returned %d: %s", statusCode, message),
	}
}

func occurredAtFor(values map[string]any) time.Time {
	for _, key := range []string{"updated_at", "created_at", "feedbackAt", "surveyCreatedAt", "date"} {
		if parsed, ok := parseTime(valueString(valueAt(values, key))); ok {
			return parsed.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

func parseTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func checkpointCursor(next string, fallback string) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(fallback)
}

func stableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ":")
}

func normalizeID(value string) string {
	if value = strings.TrimSpace(value); value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-")
	return replacer.Replace(value)
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

func cloneRaw(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}
