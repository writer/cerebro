package newrelicapi

import (
	"context"
	"crypto/sha256"
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

const (
	SourceID               = "new_relic"
	DefaultGraphQLPath     = "/graphql"
	DefaultBaseURLTemplate = "https://api.newrelic.com"
	FamilyAssets           = "assets"
	FamilyFindings         = "findings"
	FamilyAuditEvents      = "audit_events"
	DefaultEntityQuery     = "name LIKE '%'"
	DefaultAuditNRQL       = "SELECT * FROM NrAuditEvent SINCE 1 day ago LIMIT 100"
)

var templateKeys = []string{"api_key"}

type Settings struct {
	TenantID    string
	Family      string
	BaseURL     string
	APIKey      string
	AccountID   int
	EntityQuery string
	AuditNRQL   string
}

type DecodeTarget interface{}

type Record map[string]any

type VariableValue interface{}

type Request struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type Client struct {
	AllowLoopback bool
}

type response struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func ResolveConfig(cfg sourcecdk.Config) (Settings, error) {
	resolved, err := sourcecdk.ResolveBaseURLConfig(SourceID, DefaultBaseURLTemplate, cfg, templateKeys)
	if err != nil {
		return Settings{}, err
	}
	settings := Settings{
		TenantID:    FirstNonEmpty(sourcecdk.ConfigValue(resolved, "tenant_id"), sourcecdk.ConfigValue(resolved, "runtime_tenant_id")),
		Family:      FirstNonEmpty(sourcecdk.ConfigValue(resolved, "family"), FamilyAssets),
		BaseURL:     FirstNonEmpty(sourcecdk.ConfigValue(resolved, "base_url"), DefaultBaseURLTemplate),
		APIKey:      FirstNonEmpty(sourcecdk.ConfigValue(resolved, "api_key"), sourcecdk.ConfigValue(resolved, "api_token"), sourcecdk.ConfigValue(resolved, "token")),
		EntityQuery: FirstNonEmpty(sourcecdk.ConfigValue(resolved, "entity_query"), DefaultEntityQuery),
		AuditNRQL:   FirstNonEmpty(sourcecdk.ConfigValue(resolved, "audit_nrql"), DefaultAuditNRQL),
	}
	if settings.TenantID == "" {
		return Settings{}, fmt.Errorf("%w: new_relic tenant_id is required", sourcecdk.ErrInvalidConfig)
	}
	if settings.APIKey == "" {
		return Settings{}, fmt.Errorf("%w: new_relic api_key is required", sourcecdk.ErrInvalidConfig)
	}
	if rawAccountID := sourcecdk.ConfigValue(resolved, "account_id"); rawAccountID != "" {
		accountID, err := strconv.Atoi(rawAccountID)
		if err != nil || accountID <= 0 {
			return Settings{}, fmt.Errorf("%w: new_relic account_id must be a positive integer", sourcecdk.ErrInvalidConfig)
		}
		settings.AccountID = accountID
	}
	switch settings.Family {
	case FamilyAssets:
	case FamilyFindings, FamilyAuditEvents:
		if settings.AccountID == 0 {
			return Settings{}, fmt.Errorf("%w: account_id is required for new_relic %s", sourcecdk.ErrInvalidConfig, settings.Family)
		}
	default:
		return Settings{}, fmt.Errorf("%w: new_relic family must be one of %s, %s, %s", sourcecdk.ErrInvalidConfig, FamilyAssets, FamilyFindings, FamilyAuditEvents)
	}
	return settings, nil
}

func (c Client) GraphQL(ctx context.Context, settings Settings, request Request, target DecodeTarget) error {
	req, err := sourcehttp.NewJSONRequest(ctx, SourceID, settings.BaseURL, c.AllowLoopback, http.MethodPost, DefaultGraphQLPath, nil, request)
	if err != nil {
		return fmt.Errorf("build new_relic GraphQL request: %w", err)
	}
	req.Header.Set("API-Key", settings.APIKey)
	resp, err := sourcehttp.DoWithRetry(ctx, sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: SourceID, AllowLoopback: c.AllowLoopback}), req, sourcehttp.RetryOptions{})
	if err != nil {
		return fmt.Errorf("new_relic GraphQL request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("new_relic GraphQL status %d: %s", resp.StatusCode, strings.TrimSpace(string(resp.Body)))
	}
	var envelope response
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

func NewAssetEvent(settings Settings, entity Record) *primitives.Event {
	guid := FirstNonEmpty(stringValue(entity, "guid"), stringValue(entity, "id"), stringValue(entity, "name"))
	resourceType := FirstNonEmpty(stringValue(entity, "entityType"), stringValue(entity, "type"), stringValue(entity, "domain"), "entity")
	resourceURN := ProjectionURN(settings.TenantID, "runtime_new_relic_entity", guid)
	attrs := map[string]string{
		"external_id":     guid,
		"family":          FamilyAssets,
		"provider":        SourceID,
		"record_class":    "asset",
		"resource_id":     guid,
		"resource_name":   FirstNonEmpty(stringValue(entity, "name"), guid),
		"resource_type":   resourceType,
		"resource_urn":    resourceURN,
		"schema":          FamilyAssets,
		"source_event_id": guid,
		"source_provider": SourceID,
		"source_system":   SourceID,
		"tenant_id":       settings.TenantID,
	}
	return eventFromPayload(settings, FamilyAssets, guid, entity, attrs, observedAt(entity))
}

func NewFindingEvent(settings Settings, issue Record) *primitives.Event {
	findingID := FirstNonEmpty(stringValue(issue, "issueId"), stringValue(issue, "id"), stableHash(issue))
	resourceID := firstStringFromList(issue["entityGuids"])
	if resourceID == "" {
		resourceID = FirstNonEmpty(stringValue(issue, "entityGuid"), findingID)
	}
	attrs := map[string]string{
		"description":     stringValue(issue, "description"),
		"external_id":     findingID,
		"family":          FamilyFindings,
		"finding_id":      findingID,
		"finding_urn":     ProjectionURN(settings.TenantID, "finding", findingID),
		"provider":        SourceID,
		"record_class":    "finding",
		"resource_id":     resourceID,
		"resource_name":   FirstNonEmpty(stringValue(issue, "entityName"), resourceID),
		"resource_type":   FirstNonEmpty(stringValue(issue, "entityType"), "new_relic_entity"),
		"resource_urn":    ProjectionURN(settings.TenantID, "runtime_new_relic_entity", resourceID),
		"schema":          FamilyFindings,
		"severity":        FirstNonEmpty(stringValue(issue, "priority"), stringValue(issue, "severity")),
		"source_event_id": findingID,
		"source_provider": SourceID,
		"source_system":   SourceID,
		"status":          FirstNonEmpty(stringValue(issue, "state"), stringValue(issue, "status")),
		"tenant_id":       settings.TenantID,
		"title":           FirstNonEmpty(stringValue(issue, "title"), findingID),
	}
	return eventFromPayload(settings, FamilyFindings, findingID, issue, attrs, observedAt(issue))
}

func NewAuditEvent(settings Settings, row Record) *primitives.Event {
	eventID := FirstNonEmpty(stringValue(row, "eventId"), stringValue(row, "id"), stringValue(row, "uuid"), stableHash(row))
	resourceURN := ProjectionURN(settings.TenantID, "new_relic_audit_events", eventID)
	attrs := map[string]string{
		"actor_email":     FirstNonEmpty(stringValue(row, "actorEmail"), stringValue(row, "userEmail"), stringValue(row, "email")),
		"actor_id":        FirstNonEmpty(stringValue(row, "actorId"), stringValue(row, "userId"), stringValue(row, "user")),
		"actor_name":      FirstNonEmpty(stringValue(row, "actorName"), stringValue(row, "userName"), stringValue(row, "user")),
		"event_type":      FirstNonEmpty(stringValue(row, "eventType"), stringValue(row, "action"), stringValue(row, "category")),
		"external_id":     eventID,
		"family":          FamilyAuditEvents,
		"id":              eventID,
		"provider":        SourceID,
		"record_class":    "audit_event",
		"resource_id":     FirstNonEmpty(stringValue(row, "targetId"), stringValue(row, "entityGuid"), stringValue(row, "entityId"), eventID),
		"resource_name":   FirstNonEmpty(stringValue(row, "targetName"), stringValue(row, "entityName")),
		"resource_type":   FirstNonEmpty(stringValue(row, "targetType"), stringValue(row, "entityType")),
		"resource_urn":    resourceURN,
		"schema":          FamilyAuditEvents,
		"source_event_id": eventID,
		"source_provider": SourceID,
		"source_system":   SourceID,
		"tenant_id":       settings.TenantID,
	}
	return eventFromPayload(settings, FamilyAuditEvents, eventID, row, attrs, observedAt(row))
}

func eventFromPayload(settings Settings, family string, id string, payload Record, attrs map[string]string, occurredAt time.Time) *primitives.Event {
	TrimEmptyAttributes(attrs)
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{}`)
	}
	return &primitives.Event{
		Id:         SanitizeEventID(SourceID + "-" + settings.TenantID + "-" + family + "-" + id),
		TenantId:   settings.TenantID,
		SourceId:   SourceID,
		Kind:       SourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  SourceID + "/" + family + "/v1",
		Payload:    raw,
		Attributes: attrs,
	}
}

func PullWithCursor(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return pull
}

func NullableString(value string) VariableValue {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func observedAt(values Record) time.Time {
	for _, key := range []string{"updatedAt", "createdAt", "timestamp", "observed_at", "eventTimestamp"} {
		if ts, ok := parseTimeValue(values[key]); ok {
			return ts
		}
	}
	return time.Now().UTC()
}

func stringValue(values Record, key string) string {
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

func ProjectionURN(tenantID string, kind string, id string) string {
	urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", tenantID, kind, id))
	if err != nil {
		return ""
	}
	return urn.String()
}

func SanitizeEventID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return SourceID + "-event"
	}
	replacer := strings.NewReplacer(":", "-", "/", "-", " ", "-")
	return strings.Trim(replacer.Replace(value), "-")
}

func TrimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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
