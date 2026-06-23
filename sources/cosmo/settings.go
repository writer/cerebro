package cosmo

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	defaultFamily                      = familySession
	defaultPageSize                    = 100
	maxPageSize                        = 500
	messageExportCursorSource          = "cosmo.message"
	defaultMessageExportInitialSince   = "1970-01-01T00:00:00Z"
	defaultMessageExportEventTypes     = "message,completion"
	defaultMessageExportMaxWindowHours = 24
	messageExportMaxWindowHours        = 24
	messageExportMaxPageSize           = 100
	messageExportMaxOffset             = 10000
)

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

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	settings := settings{
		tenantID:      sourcecdk.ConfigValue(cfg, "tenant_id"),
		family:        sourcecdk.ConfigValue(cfg, "family"),
		baseURL:       sourcecdk.ConfigValue(cfg, "base_url"),
		token:         sourcecdk.ConfigValue(cfg, "token"),
		webhookSecret: sourcecdk.ConfigValue(cfg, "webhook_secret"),
		query:         sourcecdk.ConfigValue(cfg, "q"),
		user:          sourcecdk.ConfigValue(cfg, "user"),
		status:        sourcecdk.ConfigValue(cfg, "status"),
		category:      sourcecdk.ConfigValue(cfg, "category"),
		ticketID:      sourcecdk.ConfigValue(cfg, "ticket_id"),
		eventType:     sourcecdk.ConfigValue(cfg, "event_type"),
		clientID:      sourcecdk.ConfigValue(cfg, "client_id"),
		exportSecret:  sourcecdk.ConfigValue(cfg, "export_secret"),
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
		eventTypes, err := parseMessageEventTypes(sourcecdk.ConfigValue(cfg, "event_types"), settings.eventType)
		if err != nil {
			return settings, err
		}
		settings.eventTypes = eventTypes
		maxWindow, err := parseMessageMaxWindow(sourcecdk.ConfigValue(cfg, "max_window_hours"))
		if err != nil {
			return settings, err
		}
		settings.maxWindow = maxWindow
		initialSince, err := parseMessageInitialSince(sourcecdk.ConfigValue(cfg, "since"))
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
