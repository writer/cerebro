package sentinelone

import (
	"context"
	"embed"
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
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultPageSize = 10
	maxPageSize     = 200
	httpTimeout     = 30 * time.Second
	maxBodyBytes    = 8 << 20
	defaultFamily   = familyThreat

	familyActivity    = "activity"
	familyAgent       = "agent"
	familyApplication = "application"
	familyExclusion   = "exclusion"
	familyGroup       = "group"
	familySite        = "site"
	familyThreat      = "threat"
)

// Source is the live SentinelOne source preview used by the builtin registry.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	family   string
	baseURL  string
	host     string
	token    string
	siteID   string
	groupID  string
	agentID  string
	since    string
	until    string
	activity string
	perPage  int
}

type listResponse struct {
	Data       json.RawMessage `json:"data"`
	Pagination paginationInfo  `json:"pagination"`
}

type paginationInfo struct {
	NextCursor string `json:"nextCursor"`
	TotalItems int    `json:"totalItems"`
}

type apiError struct {
	Errors []apiErrorDetail `json:"errors"`
}

type apiErrorDetail struct {
	Code   int    `json:"code"`
	Detail string `json:"detail"`
	Title  string `json:"title"`
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

func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages through the configured SentinelOne family.
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

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	resolved := settings{
		family:   configValue(cfg, "family"),
		baseURL:  configValue(cfg, "base_url"),
		token:    configValue(cfg, "token"),
		siteID:   configValue(cfg, "site_id"),
		groupID:  configValue(cfg, "group_id"),
		agentID:  configValue(cfg, "agent_id"),
		since:    configValue(cfg, "since"),
		until:    configValue(cfg, "until"),
		activity: configValue(cfg, "activity_type"),
		perPage:  defaultPageSize,
	}
	if resolved.family == "" {
		resolved.family = defaultFamily
	}
	switch resolved.family {
	case familyActivity, familyAgent, familyApplication, familyExclusion, familyGroup, familySite, familyThreat:
	default:
		return resolved, fmt.Errorf("sentinelone family must be one of activity, agent, application, exclusion, group, site, or threat")
	}
	if resolved.baseURL == "" {
		return resolved, fmt.Errorf("sentinelone base_url is required")
	}
	normalizedBase, host, err := normalizeBaseURL(resolved.baseURL, allowLoopbackBaseURL)
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = normalizedBase
	resolved.host = host
	if resolved.token == "" {
		return resolved, fmt.Errorf("sentinelone token is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return resolved, fmt.Errorf("parse sentinelone per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("sentinelone per_page must be between 1 and %d", maxPageSize)
		}
		resolved.perPage = perPage
	}
	switch resolved.family {
	case familyActivity, familyThreat:
	default:
		if resolved.since != "" || resolved.until != "" {
			return resolved, fmt.Errorf("sentinelone since/until are only supported when family is %q or %q", familyActivity, familyThreat)
		}
	}
	return resolved, nil
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse sentinelone base_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && sourcecdk.IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", "", fmt.Errorf("sentinelone base_url must use https")
	}
	if host == "" {
		return "", "", fmt.Errorf("sentinelone base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", "", fmt.Errorf("sentinelone base_url must not include user info, query, or fragment")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", "", fmt.Errorf("sentinelone base_url must be an origin URL")
	}
	allowCustomPort := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomPort {
		return "", "", fmt.Errorf("sentinelone base_url must not include a custom port")
	}
	allowLoopbackHost := allowLoopback && sourcecdk.IsLoopbackHost(host)
	if sourcecdk.IsUnsafeHost(host) && !allowLoopbackHost {
		return "", "", fmt.Errorf("sentinelone base_url must not target loopback, private, or link-local hosts")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), host, nil
}

type listFunc[T any] func(context.Context, settings, string, int) ([]T, string, error)

type familyOptions[T any] struct {
	Name           string
	Label          string
	List           listFunc[T]
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		family(familyOptions[threatRecord]{
			Name:  familyThreat,
			Label: "sentinelone threat",
			List:  s.listThreats,
			Event: threatEvent,
			URN: func(settings settings, threat threatRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:threat:%s", settings.host, threat.ID), nil
			},
			CursorFallback: func(t threatRecord) string { return t.ID },
		}),
		family(familyOptions[agentRecord]{
			Name:  familyAgent,
			Label: "sentinelone agent",
			List:  s.listAgents,
			Event: agentEvent,
			URN: func(settings settings, agent agentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, agent.ID), nil
			},
			CursorFallback: func(a agentRecord) string { return a.ID },
		}),
		family(familyOptions[siteRecord]{
			Name:  familySite,
			Label: "sentinelone site",
			List:  s.listSites,
			Event: siteEvent,
			URN: func(settings settings, site siteRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:site:%s", settings.host, site.ID), nil
			},
			CursorFallback: func(r siteRecord) string { return r.ID },
		}),
		family(familyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "sentinelone group",
			List:  s.listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group:%s", settings.host, group.ID), nil
			},
			CursorFallback: func(r groupRecord) string { return r.ID },
		}),
		family(familyOptions[exclusionRecord]{
			Name:  familyExclusion,
			Label: "sentinelone exclusion",
			List:  s.listExclusions,
			Event: exclusionEvent,
			URN: func(settings settings, exclusion exclusionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:exclusion:%s", settings.host, exclusion.ID), nil
			},
			CursorFallback: func(r exclusionRecord) string { return r.ID },
		}),
		family(familyOptions[activityRecord]{
			Name:  familyActivity,
			Label: "sentinelone activity",
			List:  s.listActivities,
			Event: activityEvent,
			URN: func(settings settings, activity activityRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:activity:%s", settings.host, activity.ID), nil
			},
			CursorFallback: func(r activityRecord) string { return r.ID },
		}),
		family(familyOptions[applicationRecord]{
			Name:  familyApplication,
			Label: "sentinelone application inventory",
			List:  s.listApplications,
			Event: applicationEvent,
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				if err := agentApplicationCheck(ctx, s, settings); err != nil {
					return nil, err
				}
				if settings.agentID != "" {
					urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, settings.agentID))
					if err != nil {
						return nil, err
					}
					return []sourcecdk.URN{urn}, nil
				}
				agents, _, err := s.listAgents(ctx, settings, "", settings.perPage)
				if err != nil {
					return nil, wrapLookupError(label("sentinelone agents", settings), err)
				}
				urns := make([]sourcecdk.URN, 0, len(agents))
				for _, agent := range agents {
					if strings.TrimSpace(agent.ID) == "" {
						continue
					}
					urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, agent.ID))
					if err != nil {
						return nil, err
					}
					urns = append(urns, urn)
				}
				return urns, nil
			},
			URN: func(settings settings, app applicationRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:application_inventory:%s:%s", settings.host, applicationAgentID(settings, app), applicationID(settings, app)), nil
			},
			CursorFallback: func(app applicationRecord) string { return applicationID(settings{}, app) },
		}),
	)
}

func family[T any](options familyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := options.List(ctx, settings, "", 1)
			if err != nil {
				return wrapLookupError(label(options.Label, settings), err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, settings)
			}
			records, _, err := options.List(ctx, settings, "", settings.perPage)
			if err != nil {
				return nil, wrapLookupError(label(options.Label, settings), err)
			}
			return urnsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, wrapLookupError(label(options.Label, settings), err)
			}
			build := func(record T) (*primitives.Event, error) {
				return options.Event(settings, record)
			}
			return pullFromRecords(records, next, build, options.CursorFallback)
		},
	}
}

func label(prefix string, settings settings) string {
	return fmt.Sprintf("%s for %s", prefix, settings.host)
}

func urnsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
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

func pullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		pull := sourcecdk.Pull{}
		if next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		}
		return pull, nil
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

func agentApplicationCheck(ctx context.Context, source *Source, settings settings) error {
	_, _, err := source.listApplications(ctx, settings, "", 1)
	if err != nil {
		return wrapLookupError(label("sentinelone application inventory", settings), err)
	}
	return nil
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "ApiToken "+settings.token)

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

	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func httpClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenSourceClient(client, "sentinelone", httpTimeout, allowLoopback, lookupIPAddrs)
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && len(apiErr.Errors) > 0 {
		first := apiErr.Errors[0]
		title := strings.TrimSpace(first.Title)
		detail := strings.TrimSpace(first.Detail)
		switch {
		case title != "" && detail != "":
			message = fmt.Sprintf("%s: %s", title, detail)
		case detail != "":
			message = detail
		case title != "":
			message = title
		}
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("sentinelone API returned %d: %s", statusCode, message),
	}
}

func listJSONRecords[T any, P interface {
	*T
	rawCarrier
}](ctx context.Context, source *Source, settings settings, requestPath string, query url.Values) ([]T, string, error) {
	var resp listResponse
	if err := source.getJSON(ctx, settings, requestPath, query, &resp); err != nil {
		return nil, "", err
	}
	items, pagination, err := sourcecdk.DecodeListResponseData(resp.Data, requestPath, "activities", "agents", "applications", "exclusions", "groups", "sites", "threats")
	if err != nil {
		return nil, "", err
	}
	records := make([]T, 0, len(items))
	for _, item := range items {
		var record T
		if err := json.Unmarshal(item, &record); err != nil {
			return nil, "", fmt.Errorf("decode %s record: %w", requestPath, err)
		}
		P(&record).setRaw(cloneRaw(item))
		records = append(records, record)
	}
	return records, strings.TrimSpace(firstNonEmpty(pagination.NextCursor, resp.Pagination.NextCursor)), nil
}

func (s *Source) listThreats(ctx context.Context, settings settings, cursor string, limit int) ([]threatRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	addQuery(query, "createdAt__gte", settings.since)
	addQuery(query, "createdAt__lte", settings.until)
	addQuery(query, "siteIds", settings.siteID)
	return listJSONRecords[threatRecord, *threatRecord](ctx, s, settings, "/web/api/v2.1/threats", query)
}

func (s *Source) listAgents(ctx context.Context, settings settings, cursor string, limit int) ([]agentRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	addQuery(query, "siteIds", settings.siteID)
	addQuery(query, "groupIds", settings.groupID)
	return listJSONRecords[agentRecord, *agentRecord](ctx, s, settings, "/web/api/v2.1/agents", query)
}

func (s *Source) listSites(ctx context.Context, settings settings, cursor string, limit int) ([]siteRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	return listJSONRecords[siteRecord, *siteRecord](ctx, s, settings, "/web/api/v2.1/sites", query)
}

func (s *Source) listGroups(ctx context.Context, settings settings, cursor string, limit int) ([]groupRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	addQuery(query, "siteIds", settings.siteID)
	return listJSONRecords[groupRecord, *groupRecord](ctx, s, settings, "/web/api/v2.1/groups", query)
}

func (s *Source) listExclusions(ctx context.Context, settings settings, cursor string, limit int) ([]exclusionRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	addQuery(query, "siteIds", settings.siteID)
	return listJSONRecords[exclusionRecord, *exclusionRecord](ctx, s, settings, "/web/api/v2.1/exclusions", query)
}

func (s *Source) listActivities(ctx context.Context, settings settings, cursor string, limit int) ([]activityRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	addQuery(query, "createdAt__gte", settings.since)
	addQuery(query, "createdAt__lte", settings.until)
	addQuery(query, "activityTypes", settings.activity)
	addQuery(query, "siteIds", settings.siteID)
	addQuery(query, "groupIds", settings.groupID)
	return listJSONRecords[activityRecord, *activityRecord](ctx, s, settings, "/web/api/v2.1/activities", query)
}

func (s *Source) listApplications(ctx context.Context, settings settings, cursor string, limit int) ([]applicationRecord, string, error) {
	if strings.TrimSpace(settings.agentID) == "" {
		agents, next, err := s.listAgents(ctx, settings, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		records := make([]applicationRecord, 0)
		for _, agent := range agents {
			agentID := strings.TrimSpace(agent.ID)
			if agentID == "" {
				continue
			}
			applications, _, err := s.listApplicationsForAgent(ctx, settings, agentID)
			if err != nil {
				return nil, "", err
			}
			records = append(records, applications...)
		}
		return records, next, nil
	}
	if cursor != "" {
		return nil, "", nil
	}
	return s.listApplicationsForAgent(ctx, settings, settings.agentID)
}

func (s *Source) listApplicationsForAgent(ctx context.Context, settings settings, agentID string) ([]applicationRecord, string, error) {
	query := url.Values{}
	addQuery(query, "ids", agentID)
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := s.getJSON(ctx, settings, "/web/api/v2.1/agents/applications", query, &resp); err != nil {
		return nil, "", err
	}
	records := make([]applicationRecord, 0, len(resp.Data))
	for _, item := range resp.Data {
		var record applicationRecord
		if err := json.Unmarshal(item, &record); err != nil {
			return nil, "", fmt.Errorf("decode sentinelone application record: %w", err)
		}
		record.AgentID = agentID
		record.setRaw(cloneRaw(item))
		records = append(records, record)
	}
	return records, "", nil
}

func buildPagedQuery(cursor string, limit int) url.Values {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if strings.TrimSpace(cursor) != "" {
		query.Set("cursor", strings.TrimSpace(cursor))
	}
	return query
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	query.Set(key, value)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func sortedStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		cleaned = append(cleaned, v)
	}
	sort.Strings(cleaned)
	return cleaned
}

func intToString(value int) string {
	return strconv.Itoa(value)
}

func parseTimestamp(value string) time.Time {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z"} {
		if parsed, err := time.Parse(layout, v); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func decodeRaw(raw json.RawMessage, label string) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s raw payload: %w", label, err)
	}
	return decoded, nil
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}

// Records and event builders live in records.go.

func eventID(prefix string, settings settings, parts ...string) string {
	values := make([]string, 0, len(parts)+2)
	values = append(values, prefix, settings.host)
	for _, part := range parts {
		values = append(values, strings.TrimSpace(part))
	}
	return strings.Join(values, "-")
}

func eventOccurredAt(values ...time.Time) time.Time {
	for _, t := range values {
		if !t.IsZero() {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func toTimestamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}
