package jumpcloudapi

import (
	"bytes"
	"context"
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

const auditEventsPath = "/events"

type auditEventsRequest struct {
	Service     []string `json:"service"`
	StartTime   string   `json:"start_time"`
	EndTime     string   `json:"end_time,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	Sort        string   `json:"sort,omitempty"`
	SearchAfter any      `json:"search_after,omitempty"`
}

func CheckAuditEvents(ctx context.Context, cfg sourcecdk.Config, allowLoopback bool) error {
	values := cfg.Values()
	if strings.TrimSpace(values["per_page"]) == "" {
		values["per_page"] = "1"
	}
	_, err := ReadAuditEvents(ctx, sourcecdk.NewConfig(values), nil, nil, allowLoopback)
	return err
}

func DiscoverAuditEvents(ctx context.Context, cfg sourcecdk.Config, allowLoopback bool) ([]sourcecdk.URN, error) {
	pull, err := ReadAuditEvents(ctx, cfg, nil, nil, allowLoopback)
	if err != nil {
		return nil, err
	}
	seen := map[sourcecdk.URN]struct{}{}
	urns := []sourcecdk.URN{}
	for _, event := range pull.Events {
		eventID := firstNonEmpty(event.GetAttributes()["source_event_id"], event.GetId())
		if eventID == "" {
			continue
		}
		urn, err := sourcecdk.URNFor(event.GetTenantId(), "jumpcloud_audit_events", sourcecdk.StableExternalID(eventID, "event"))
		if err != nil {
			return nil, err
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns, nil
}

func ReadAuditEvents(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, allowLoopback bool) (sourcecdk.Pull, error) {
	requestBody, requestedLimit, err := auditRequestBody(cfg, cursor, checkpoint)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	baseURL := insightsBaseURL(cfg)
	req, err := sourcehttp.NewJSONRequest(ctx, SourceID, baseURL, allowLoopback, http.MethodPost, auditEventsPath, nil, requestBody)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	apiKey := firstNonEmpty(sourcecdk.ConfigValue(cfg, "api_key"), sourcecdk.ConfigValue(cfg, "api_token"), sourcecdk.ConfigValue(cfg, "token"))
	if apiKey == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%w: %s api_key is required", sourcecdk.ErrInvalidConfig, SourceID)
	}
	req.Header.Set(TokenHeader, apiKey)
	if orgID := sourcecdk.ConfigValue(cfg, "org_id"); orgID != "" {
		req.Header.Set("x-org-id", orgID)
	}
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: SourceID, AllowLoopback: allowLoopback})
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return sourcecdk.Pull{}, fmt.Errorf("%s audit_events returned HTTP %d: %s", SourceID, resp.StatusCode, responseMessage(resp.Body))
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		return sourcecdk.Pull{}, fmt.Errorf("decode %s audit_events response: %w", SourceID, err)
	}
	events := make([]*primitives.Event, 0, len(rows))
	for _, row := range rows {
		event, err := auditEventFromRow(cfg, baseURL, row)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	next := auditNextCursor(resp.Header, requestedLimit)
	return auditPull(events, next), nil
}

func auditRequestBody(cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (auditEventsRequest, int, error) {
	limit, err := auditPageSize(cfg)
	if err != nil {
		return auditEventsRequest{}, 0, err
	}
	body := auditEventsRequest{
		Service:   auditServices(cfg),
		StartTime: auditStartTime(cfg, checkpoint),
		EndTime:   firstNonEmpty(sourcecdk.ConfigValue(cfg, "audit_end_time"), sourcecdk.ConfigValue(cfg, "end_time")),
		Limit:     limit,
		Sort:      firstNonEmpty(sourcecdk.ConfigValue(cfg, "audit_sort"), sourcecdk.ConfigValue(cfg, "sort"), "ASC"),
	}
	if token := sourcecdk.CursorToken(cursor); token != "" {
		searchAfter, err := auditSearchAfter(token)
		if err != nil {
			return auditEventsRequest{}, 0, err
		}
		body.SearchAfter = searchAfter
	}
	return body, limit, nil
}

func auditServices(cfg sourcecdk.Config) []string {
	values := configListValues(cfg, "audit_services", "audit_service", "service")
	if len(values) == 0 {
		return []string{"all"}
	}
	return values
}

func auditStartTime(cfg sourcecdk.Config, checkpoint *cerebrov1.SourceCheckpoint) string {
	if value := firstNonEmpty(sourcecdk.ConfigValue(cfg, "audit_start_time"), sourcecdk.ConfigValue(cfg, "start_time")); value != "" {
		return value
	}
	if checkpoint != nil && checkpoint.GetWatermark() != nil {
		if watermark := checkpoint.GetWatermark().AsTime(); !watermark.IsZero() {
			return watermark.UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
}

func auditPageSize(cfg sourcecdk.Config) (int, error) {
	raw := firstNonEmpty(sourcecdk.ConfigValue(cfg, "audit_per_page"), sourcecdk.ConfigValue(cfg, "per_page"))
	if raw == "" {
		return 1000, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: parse %s audit page size: %w", sourcecdk.ErrInvalidConfig, SourceID, err)
	}
	if parsed < 1 || parsed > 10000 {
		return 0, fmt.Errorf("%w: %s audit page size must be between 1 and 10000", sourcecdk.ErrInvalidConfig, SourceID)
	}
	return parsed, nil
}

func auditSearchAfter(raw string) (any, error) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: parse %s search_after cursor: %w", sourcecdk.ErrInvalidConfig, SourceID, err)
	}
	return value, nil
}

func auditNextCursor(headers http.Header, requestedLimit int) string {
	resultCount, resultOK := headerInt(headers, "X-Result-Count")
	limit, limitOK := headerInt(headers, "X-Limit")
	if !limitOK {
		limit = requestedLimit
	}
	if !resultOK || resultCount < limit || limit <= 0 {
		return ""
	}
	return strings.TrimSpace(headers.Get("X-Search_after"))
}

func headerInt(headers http.Header, key string) (int, bool) {
	value := strings.TrimSpace(headers.Get(key))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil
}

func auditEventFromRow(cfg sourcecdk.Config, baseURL string, raw json.RawMessage) (*primitives.Event, error) {
	values := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("decode %s audit event row: %w", SourceID, err)
	}
	tenantID := firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, "runtime_tenant_id"))
	if tenantID == "" {
		return nil, fmt.Errorf("%w: %s tenant_id is required", sourcecdk.ErrInvalidConfig, SourceID)
	}
	rowID := firstNonEmpty(auditValueString(values, "id", "event_id", "uuid", "request_id"), sourcecdk.EventID(string(raw)))
	occurredAt := auditEventTime(values)
	attrs := map[string]string{
		"external_id":     rowID,
		"family":          FamilyAuditEvents,
		"provider":        SourceID,
		"record_class":    "audit_event",
		"schema":          "audit_events",
		"source_event_id": rowID,
		"source_provider": SourceID,
		"source_system":   SourceID,
		"tenant_id":       tenantID,
		"event_type":      auditValueString(values, "event_type", "type", "action"),
		"actor_id":        auditValueString(values, "initiated_by.id", "actor.id", "admin.id", "user.id", "user_id", "resource.id", "username"),
		"actor_email":     auditValueString(values, "initiated_by.email", "actor.email", "admin.email", "user.email", "resource.email", "email", "username"),
		"actor_name":      auditValueString(values, "initiated_by.name", "actor.name", "admin.name", "user.name", "username"),
		"resource_id":     auditValueString(values, "resource.id", "target.id", "object.id", "application.id", "system.id"),
		"resource_type":   auditValueString(values, "resource.type", "target.type", "object.type"),
		"resource_email":  auditValueString(values, "resource.email", "target.email", "object.email"),
		"resource_name":   auditValueString(values, "resource.name", "target.name", "object.name", "application.name", "system.hostname"),
		"client_ip":       auditValueString(values, "client_ip", "ip", "src_ip"),
		"success":         auditValueString(values, "success"),
		"organization":    auditValueString(values, "organization", "org_id"),
		"observed_at":     occurredAt.Format(time.RFC3339Nano),
	}
	if attrs["resource_type"] == "" && attrs["resource_id"] != "" {
		attrs["resource_type"] = "jumpcloud_resource"
	}
	if attrs["resource_id"] != "" {
		if urn, err := sourcecdk.URNForEscaped(tenantID, "jumpcloud_"+strings.ReplaceAll(attrs["resource_type"], " ", "_"), attrs["resource_id"]); err == nil {
			attrs["resource_urn"] = urn.String()
		}
	}
	trimAttributes(attrs)
	return &primitives.Event{
		Id:         sourcecdk.EventID(SourceID, tenantID, baseURL, FamilyAuditEvents, rowID),
		TenantId:   tenantID,
		SourceId:   SourceID,
		Kind:       SourceID + "." + FamilyAuditEvents,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  SourceID + "/" + FamilyAuditEvents + "/v1",
		Payload:    append([]byte(nil), raw...),
		Attributes: attrs,
	}, nil
}

func auditPull(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	if len(events) == 0 {
		return pull
	}
	last := events[len(events)-1]
	pull.Checkpoint = &cerebrov1.SourceCheckpoint{
		Watermark:    last.GetOccurredAt(),
		CursorOpaque: firstNonEmpty(next, last.GetAttributes()["source_event_id"], last.GetId()),
	}
	return pull
}

func auditEventTime(values map[string]any) time.Time {
	for _, path := range []string{"timestamp", "date", "observed_at", "updated_at", "created_at"} {
		if parsed, ok := parseAuditTime(auditValueString(values, path)); ok {
			return parsed
		}
	}
	return time.Now().UTC()
}

func parseAuditTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func insightsBaseURL(cfg sourcecdk.Config) string {
	if baseURL := sourcecdk.ConfigValue(cfg, "insights_base_url"); baseURL != "" {
		return baseURL
	}
	switch strings.ToLower(sourcecdk.ConfigValue(cfg, "region")) {
	case "eu", "europe":
		return "https://api.eu.jumpcloud.com/insights/directory/v1"
	case "in", "india":
		return "https://api.in.jumpcloud.com/insights/directory/v1"
	default:
		return DefaultInsightsBaseURLTemplate
	}
}

func responseMessage(body []byte) string {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error", "detail"} {
			if value := auditString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		return "empty response"
	}
	if len(message) > 512 {
		return message[:512]
	}
	return message
}

func auditValueString(values map[string]any, paths ...string) string {
	for _, path := range paths {
		for _, candidate := range strings.Split(path, "|") {
			if value := auditString(auditValueAt(values, strings.TrimSpace(candidate))); value != "" {
				return value
			}
		}
	}
	return ""
}

func auditValueAt(values map[string]any, path string) any {
	if path == "" {
		return nil
	}
	var current any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	return current
}

func auditString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64, float32, int, int64, int32, uint, uint64, uint32:
		return strings.TrimSpace(fmt.Sprint(typed))
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
}

func trimAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			delete(attrs, key)
		}
	}
}

func ConfigListValues(cfg sourcecdk.Config, keys ...string) []string {
	return configListValues(cfg, keys...)
}

func FamilyName(cfg sourcecdk.Config) string {
	if family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")); family != "" {
		return family
	}
	return DefaultFamily
}

func FirstNonEmpty(values ...string) string {
	return firstNonEmpty(values...)
}

func configListValues(cfg sourcecdk.Config, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		for _, value := range strings.Split(sourcecdk.ConfigValue(cfg, key), ",") {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
