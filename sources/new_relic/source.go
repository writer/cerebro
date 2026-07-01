package new_relic

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "new_relic"
	defaultFamily          = familyAssets
	defaultGraphQLPath     = "/graphql"
	defaultBaseURLTemplate = "https://api.newrelic.com"
	familyAssets           = "assets"
	familyFindings         = "findings"
	familyAuditEvents      = "audit_events"
	defaultEntityQuery     = "name LIKE '%'"
	defaultAuditNRQL       = "SELECT * FROM NrAuditEvent SINCE 1 day ago LIMIT 100"
)

var templateKeys = []string{"api_key"}

type Source struct {
	spec          *cerebrov1.SourceSpec
	allowLoopback bool
}

type runtimeConfig struct {
	tenantID    string
	family      string
	baseURL     string
	apiKey      string
	accountID   int
	entityQuery string
	auditNRQL   string
}

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{spec: spec}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return s.spec
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	settings, err := s.runtimeConfig(cfg)
	if err != nil {
		return err
	}
	var out struct {
		Actor struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"actor"`
	}
	return s.graphQL(ctx, settings, graphQLRequest{Query: `query NewRelicSourceHealth { actor { user { name } } }`}, &out)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	pull, err := s.Read(ctx, cfg, nil)
	if err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, 0, len(pull.Events))
	for _, event := range pull.Events {
		rawURN := ""
		if event.GetKind() == sourceID+"."+familyFindings {
			rawURN = strings.TrimSpace(event.GetAttributes()["finding_urn"])
		}
		if rawURN == "" {
			rawURN = strings.TrimSpace(event.GetAttributes()["resource_urn"])
		}
		if rawURN == "" {
			rawURN = fmt.Sprintf("urn:cerebro:%s:%s:%s", event.GetTenantId(), event.GetKind(), event.GetId())
		}
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := s.runtimeConfig(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	switch settings.family {
	case familyAssets:
		return s.readAssets(ctx, settings, sourcecdk.CursorToken(cursor))
	case familyFindings:
		return s.readFindings(ctx, settings, sourcecdk.CursorToken(cursor))
	case familyAuditEvents:
		return s.readAuditEvents(ctx, settings)
	default:
		return sourcecdk.Pull{}, fmt.Errorf("%w: new_relic family must be one of %s, %s, %s", sourcecdk.ErrInvalidConfig, familyAssets, familyFindings, familyAuditEvents)
	}
}

func (s *Source) readAssets(ctx context.Context, settings runtimeConfig, cursor string) (sourcecdk.Pull, error) {
	var out struct {
		Actor struct {
			EntitySearch struct {
				Results struct {
					NextCursor string           `json:"nextCursor"`
					Entities   []map[string]any `json:"entities"`
				} `json:"results"`
			} `json:"entitySearch"`
		} `json:"actor"`
	}
	req := graphQLRequest{
		Query: `query NewRelicEntitySearch($query: String!, $cursor: String) {
  actor {
    entitySearch(query: $query) {
      results(cursor: $cursor) {
        nextCursor
        entities {
          guid
          name
          type
          entityType
          domain
          permalink
          reporting
          account { id name }
        }
      }
    }
  }
}`,
		Variables: map[string]any{"query": settings.entityQuery, "cursor": nullableString(cursor)},
	}
	if err := s.graphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.EntitySearch.Results.Entities))
	for _, entity := range out.Actor.EntitySearch.Results.Entities {
		events = append(events, newAssetEvent(settings, entity))
	}
	return pullWithCursor(events, out.Actor.EntitySearch.Results.NextCursor), nil
}

func (s *Source) readFindings(ctx context.Context, settings runtimeConfig, cursor string) (sourcecdk.Pull, error) {
	if settings.accountID == 0 {
		return sourcecdk.Pull{}, fmt.Errorf("%w: account_id is required for new_relic findings", sourcecdk.ErrInvalidConfig)
	}
	var out struct {
		Actor struct {
			Account struct {
				AIIssues struct {
					Issues struct {
						NextCursor string           `json:"nextCursor"`
						Issues     []map[string]any `json:"issues"`
					} `json:"issues"`
				} `json:"aiIssues"`
			} `json:"account"`
		} `json:"actor"`
	}
	req := graphQLRequest{
		Query: `query NewRelicIssues($accountId: Int!, $cursor: String) {
  actor {
    account(id: $accountId) {
      aiIssues {
        issues(cursor: $cursor) {
          nextCursor
          issues {
            issueId
            title
            description
            priority
            state
            createdAt
            updatedAt
            entityGuids
          }
        }
      }
    }
  }
}`,
		Variables: map[string]any{"accountId": settings.accountID, "cursor": nullableString(cursor)},
	}
	if err := s.graphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.Account.AIIssues.Issues.Issues))
	for _, issue := range out.Actor.Account.AIIssues.Issues.Issues {
		events = append(events, newFindingEvent(settings, issue))
	}
	return pullWithCursor(events, out.Actor.Account.AIIssues.Issues.NextCursor), nil
}

func (s *Source) readAuditEvents(ctx context.Context, settings runtimeConfig) (sourcecdk.Pull, error) {
	if settings.accountID == 0 {
		return sourcecdk.Pull{}, fmt.Errorf("%w: account_id is required for new_relic audit_events", sourcecdk.ErrInvalidConfig)
	}
	var out struct {
		Actor struct {
			Account struct {
				NRQL struct {
					Results []map[string]any `json:"results"`
				} `json:"nrql"`
			} `json:"account"`
		} `json:"actor"`
	}
	req := graphQLRequest{
		Query: `query NewRelicAuditEvents($accountId: Int!, $nrql: Nrql!) {
  actor {
    account(id: $accountId) {
      nrql(query: $nrql) {
        results
      }
    }
  }
}`,
		Variables: map[string]any{"accountId": settings.accountID, "nrql": settings.auditNRQL},
	}
	if err := s.graphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.Account.NRQL.Results))
	for _, row := range out.Actor.Account.NRQL.Results {
		events = append(events, newAuditEvent(settings, row))
	}
	return sourcecdk.Pull{Events: events}, nil
}

func (s *Source) graphQL(ctx context.Context, settings runtimeConfig, request graphQLRequest, target any) error {
	req, err := sourcehttp.NewJSONRequest(ctx, sourceID, settings.baseURL, s != nil && s.allowLoopback, http.MethodPost, defaultGraphQLPath, nil, request)
	if err != nil {
		return fmt.Errorf("build new_relic GraphQL request: %w", err)
	}
	req.Header.Set("API-Key", settings.apiKey)
	resp, err := sourcehttp.DoWithRetry(ctx, sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: sourceID, AllowLoopback: s != nil && s.allowLoopback}), req, sourcehttp.RetryOptions{})
	if err != nil {
		return fmt.Errorf("new_relic GraphQL request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("new_relic GraphQL status %d: %s", resp.StatusCode, strings.TrimSpace(string(resp.Body)))
	}
	var envelope graphQLResponse
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		return fmt.Errorf("decode new_relic GraphQL response: %w", err)
	}
	if len(envelope.Errors) != 0 {
		messages := make([]string, 0, len(envelope.Errors))
		for _, gqlErr := range envelope.Errors {
			messages = append(messages, strings.TrimSpace(gqlErr.Message))
		}
		return fmt.Errorf("new_relic GraphQL errors: %s", strings.Join(messages, "; "))
	}
	if target == nil {
		return nil
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("new_relic GraphQL response missing data")
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return fmt.Errorf("decode new_relic GraphQL data: %w", err)
	}
	return nil
}

func (s *Source) runtimeConfig(cfg sourcecdk.Config) (runtimeConfig, error) {
	resolved, err := sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
	if err != nil {
		return runtimeConfig{}, err
	}
	settings := runtimeConfig{
		tenantID:    firstNonEmpty(sourcecdk.ConfigValue(resolved, "tenant_id"), sourcecdk.ConfigValue(resolved, "runtime_tenant_id")),
		family:      firstNonEmpty(sourcecdk.ConfigValue(resolved, "family"), defaultFamily),
		baseURL:     firstNonEmpty(sourcecdk.ConfigValue(resolved, "base_url"), defaultBaseURLTemplate),
		apiKey:      firstNonEmpty(sourcecdk.ConfigValue(resolved, "api_key"), sourcecdk.ConfigValue(resolved, "api_token"), sourcecdk.ConfigValue(resolved, "token")),
		entityQuery: firstNonEmpty(sourcecdk.ConfigValue(resolved, "entity_query"), defaultEntityQuery),
		auditNRQL:   firstNonEmpty(sourcecdk.ConfigValue(resolved, "audit_nrql"), defaultAuditNRQL),
	}
	if settings.tenantID == "" {
		return runtimeConfig{}, fmt.Errorf("%w: new_relic tenant_id is required", sourcecdk.ErrInvalidConfig)
	}
	if settings.apiKey == "" {
		return runtimeConfig{}, fmt.Errorf("%w: new_relic api_key is required", sourcecdk.ErrInvalidConfig)
	}
	if rawAccountID := sourcecdk.ConfigValue(resolved, "account_id"); rawAccountID != "" {
		accountID, err := strconv.Atoi(rawAccountID)
		if err != nil || accountID <= 0 {
			return runtimeConfig{}, fmt.Errorf("%w: new_relic account_id must be a positive integer", sourcecdk.ErrInvalidConfig)
		}
		settings.accountID = accountID
	}
	switch settings.family {
	case familyAssets:
	case familyFindings, familyAuditEvents:
		if settings.accountID == 0 {
			return runtimeConfig{}, fmt.Errorf("%w: account_id is required for new_relic %s", sourcecdk.ErrInvalidConfig, settings.family)
		}
	default:
		return runtimeConfig{}, fmt.Errorf("%w: new_relic family must be one of %s, %s, %s", sourcecdk.ErrInvalidConfig, familyAssets, familyFindings, familyAuditEvents)
	}
	return settings, nil
}

func newAssetEvent(settings runtimeConfig, entity map[string]any) *primitives.Event {
	guid := firstNonEmpty(stringValue(entity, "guid"), stringValue(entity, "id"), stringValue(entity, "name"))
	resourceType := firstNonEmpty(stringValue(entity, "entityType"), stringValue(entity, "type"), stringValue(entity, "domain"), "entity")
	resourceURN := projectionURN(settings.tenantID, "runtime_new_relic_entity", guid)
	attrs := map[string]string{
		"external_id":     guid,
		"family":          familyAssets,
		"provider":        sourceID,
		"record_class":    "asset",
		"resource_id":     guid,
		"resource_name":   firstNonEmpty(stringValue(entity, "name"), guid),
		"resource_type":   resourceType,
		"resource_urn":    resourceURN,
		"schema":          familyAssets,
		"source_event_id": guid,
		"source_provider": sourceID,
		"source_system":   sourceID,
		"tenant_id":       settings.tenantID,
	}
	return eventFromPayload(settings, familyAssets, guid, entity, attrs, observedAt(entity))
}

func newFindingEvent(settings runtimeConfig, issue map[string]any) *primitives.Event {
	findingID := firstNonEmpty(stringValue(issue, "issueId"), stringValue(issue, "id"), stableHash(issue))
	resourceID := firstStringFromList(issue["entityGuids"])
	if resourceID == "" {
		resourceID = firstNonEmpty(stringValue(issue, "entityGuid"), findingID)
	}
	attrs := map[string]string{
		"description":     stringValue(issue, "description"),
		"external_id":     findingID,
		"family":          familyFindings,
		"finding_id":      findingID,
		"finding_urn":     projectionURN(settings.tenantID, "finding", findingID),
		"provider":        sourceID,
		"record_class":    "finding",
		"resource_id":     resourceID,
		"resource_name":   firstNonEmpty(stringValue(issue, "entityName"), resourceID),
		"resource_type":   firstNonEmpty(stringValue(issue, "entityType"), "new_relic_entity"),
		"resource_urn":    projectionURN(settings.tenantID, "runtime_new_relic_entity", resourceID),
		"schema":          familyFindings,
		"severity":        firstNonEmpty(stringValue(issue, "priority"), stringValue(issue, "severity")),
		"source_event_id": findingID,
		"source_provider": sourceID,
		"source_system":   sourceID,
		"status":          firstNonEmpty(stringValue(issue, "state"), stringValue(issue, "status")),
		"tenant_id":       settings.tenantID,
		"title":           firstNonEmpty(stringValue(issue, "title"), findingID),
	}
	return eventFromPayload(settings, familyFindings, findingID, issue, attrs, observedAt(issue))
}

func newAuditEvent(settings runtimeConfig, row map[string]any) *primitives.Event {
	eventID := firstNonEmpty(stringValue(row, "eventId"), stringValue(row, "id"), stringValue(row, "uuid"), stableHash(row))
	resourceURN := projectionURN(settings.tenantID, "new_relic_audit_events", eventID)
	attrs := map[string]string{
		"actor_email":     firstNonEmpty(stringValue(row, "actorEmail"), stringValue(row, "userEmail"), stringValue(row, "email")),
		"actor_id":        firstNonEmpty(stringValue(row, "actorId"), stringValue(row, "userId"), stringValue(row, "user")),
		"actor_name":      firstNonEmpty(stringValue(row, "actorName"), stringValue(row, "userName"), stringValue(row, "user")),
		"event_type":      firstNonEmpty(stringValue(row, "eventType"), stringValue(row, "action"), stringValue(row, "category")),
		"external_id":     eventID,
		"family":          familyAuditEvents,
		"id":              eventID,
		"provider":        sourceID,
		"record_class":    "audit_event",
		"resource_id":     firstNonEmpty(stringValue(row, "targetId"), stringValue(row, "entityGuid"), stringValue(row, "entityId"), eventID),
		"resource_name":   firstNonEmpty(stringValue(row, "targetName"), stringValue(row, "entityName")),
		"resource_type":   firstNonEmpty(stringValue(row, "targetType"), stringValue(row, "entityType")),
		"resource_urn":    resourceURN,
		"schema":          familyAuditEvents,
		"source_event_id": eventID,
		"source_provider": sourceID,
		"source_system":   sourceID,
		"tenant_id":       settings.tenantID,
	}
	return eventFromPayload(settings, familyAuditEvents, eventID, row, attrs, observedAt(row))
}

func eventFromPayload(settings runtimeConfig, family string, id string, payload map[string]any, attrs map[string]string, occurredAt time.Time) *primitives.Event {
	trimEmptyAttributes(attrs)
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{}`)
	}
	return &primitives.Event{
		Id:         sanitizeEventID(sourceID + "-" + settings.tenantID + "-" + family + "-" + id),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    raw,
		Attributes: attrs,
	}
}

func pullWithCursor(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return pull
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

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func observedAt(values map[string]any) time.Time {
	for _, key := range []string{"updatedAt", "createdAt", "timestamp", "observed_at", "eventTimestamp"} {
		if ts, ok := parseTimeValue(values[key]); ok {
			return ts
		}
	}
	return time.Now().UTC()
}

func parseTimeValue(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, typed); err == nil {
				return parsed, true
			}
		}
	case float64:
		if typed > 1_000_000_000_000 {
			return time.UnixMilli(int64(typed)).UTC(), true
		}
		if typed > 0 {
			return time.Unix(int64(typed), 0).UTC(), true
		}
	case int64:
		if typed > 1_000_000_000_000 {
			return time.UnixMilli(typed).UTC(), true
		}
		if typed > 0 {
			return time.Unix(typed, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

func stringValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	switch value := values[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return strconv.FormatInt(int64(value), 10)
	case bool:
		return strconv.FormatBool(value)
	case json.Number:
		return value.String()
	default:
		return ""
	}
}

func firstStringFromList(value any) string {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				return strings.TrimSpace(item)
			}
		}
	}
	return ""
}

func stableHash(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func projectionURN(tenantID string, kind string, id string) string {
	urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", tenantID, kind, id))
	if err != nil {
		return ""
	}
	return urn.String()
}

func sanitizeEventID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return sourceID + "-event"
	}
	replacer := strings.NewReplacer(":", "-", "/", "-", " ", "-")
	return strings.Trim(replacer.Replace(value), "-")
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil {
		s.allowLoopback = true
	}
}
