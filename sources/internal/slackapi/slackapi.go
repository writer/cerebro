package slackapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

const (
	SourceID              = "slack"
	FamilyChannelMember   = "channel_member"
	FamilyUserGroupMember = "user_group_member"
	FamilyAuditLog        = "audit_log"

	DefaultWebAPIBaseURL = "https://slack.com/api"
	DefaultAuditBaseURL  = "https://api.slack.com/audit/v1"
)

// Options controls Slack Web API readers that cannot be expressed as plain
// JSON API families because they return scalar arrays or use a separate API
// hostname.
type Options struct {
	AllowLoopback bool
	Client        *http.Client
	PageSize      int
}

// CustomFamily reports whether family is handled by this package instead of
// the generic JSON API runtime.
func CustomFamily(family string) bool {
	switch strings.TrimSpace(family) {
	case FamilyChannelMember, FamilyUserGroupMember, FamilyAuditLog:
		return true
	default:
		return false
	}
}

// ResponseError converts Slack's ok=false envelope into a source error.
func ResponseError(body []byte) error {
	var payload struct {
		OK       *bool  `json:"ok"`
		Error    string `json:"error"`
		Needed   string `json:"needed"`
		Provided string `json:"provided"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode slack response: %w", err)
	}
	if payload.OK == nil || *payload.OK {
		return nil
	}
	message := strings.TrimSpace(payload.Error)
	if message == "" {
		message = "request_failed"
	}
	details := []string{}
	if needed := strings.TrimSpace(payload.Needed); needed != "" {
		details = append(details, "needed="+needed)
	}
	if provided := strings.TrimSpace(payload.Provided); provided != "" {
		details = append(details, "provided="+provided)
	}
	if len(details) != 0 {
		return fmt.Errorf("slack API returned ok=false: %s (%s)", message, strings.Join(details, ", "))
	}
	return fmt.Errorf("slack API returned ok=false: %s", message)
}

// Discover reads the configured custom family and converts returned events to
// runtime URNs.
func Discover(ctx context.Context, cfg sourcecdk.Config, options Options) ([]sourcecdk.URN, error) {
	pull, err := Read(ctx, cfg, nil, options)
	if err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, 0, len(pull.Events))
	tenantID := tenantID(cfg, SourceID)
	for _, event := range pull.Events {
		if event == nil {
			continue
		}
		urnKind := strings.ReplaceAll(event.GetKind(), ".", "_")
		recordID := firstNonEmpty(event.GetAttributes()["external_id"], event.GetId())
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", tenantID, urnKind, recordID))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

// Read runs one Slack custom family read.
func Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, options Options) (sourcecdk.Pull, error) {
	pageSize := options.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	options.PageSize = pageSize
	switch strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")) {
	case FamilyChannelMember:
		return readScalarMembership(ctx, cfg, cursor, options, membershipRequest{
			Family:       FamilyChannelMember,
			Path:         "/conversations.members",
			ContainerKey: "channel_id",
			QueryKey:     "channel",
			ListKey:      "members",
			MemberKind:   "channel",
		})
	case FamilyUserGroupMember:
		return readScalarMembership(ctx, cfg, cursor, options, membershipRequest{
			Family:       FamilyUserGroupMember,
			Path:         "/usergroups.users.list",
			ContainerKey: "usergroup_id",
			QueryKey:     "usergroup",
			ListKey:      "users",
			MemberKind:   "user_group",
			Query:        url.Values{"include_disabled": []string{"true"}},
		})
	case FamilyAuditLog:
		return readAuditLogs(ctx, cfg, cursor, options)
	default:
		return sourcecdk.Pull{}, fmt.Errorf("%s family must be one of %s", SourceID, strings.Join([]string{
			"team",
			"user",
			"channel",
			"user_group",
			"access_log",
			FamilyChannelMember,
			FamilyUserGroupMember,
			FamilyAuditLog,
		}, ", "))
	}
}

type membershipRequest struct {
	Family       string
	Path         string
	ContainerKey string
	QueryKey     string
	ListKey      string
	MemberKind   string
	Query        url.Values
}

func readScalarMembership(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, options Options, spec membershipRequest) (sourcecdk.Pull, error) {
	tenantID := tenantID(cfg, "")
	if tenantID == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%s tenant_id is required", SourceID)
	}
	containerID, err := sourcecdk.RequiredConfigValue(SourceID, cfg, spec.ContainerKey)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	query := url.Values{}
	for key, values := range spec.Query {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	query.Set(spec.QueryKey, containerID)
	query.Set("limit", strconv.Itoa(options.PageSize))
	if cursorToken := sourcecdk.CursorToken(cursor); cursorToken != "" {
		query.Set("cursor", cursorToken)
	}
	var response map[string]any
	if err := getJSON(ctx, cfg, options, DefaultWebAPIBaseURL, "base_url", spec.Path, query, &response); err != nil {
		return sourcecdk.Pull{}, err
	}
	items, _ := response[spec.ListKey].([]any)
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		userID := (sourcecdk.JSONScalar{Value: item}).SourceString()
		if userID == "" {
			continue
		}
		externalID := containerID + "-" + userID
		payload := map[string]any{spec.ContainerKey: containerID, "user_id": userID}
		attrs := baseAttributes(spec.Family, externalID)
		attrs[spec.ContainerKey] = containerID
		attrs["user_id"] = userID
		attrs["membership_type"] = spec.MemberKind
		events = append(events, event(tenantID, spec.Family, externalID, payload, attrs, time.Now().UTC()))
	}
	return pull(events, nestedString(response, "response_metadata.next_cursor")), nil
}

func readAuditLogs(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, options Options) (sourcecdk.Pull, error) {
	tenantID := tenantID(cfg, "")
	if tenantID == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%s tenant_id is required", SourceID)
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(options.PageSize))
	for _, key := range []string{"oldest", "latest", "action", "actor", "entity"} {
		if value := sourcecdk.ConfigValue(cfg, key); value != "" {
			query.Set(key, value)
		}
	}
	if cursorToken := sourcecdk.CursorToken(cursor); cursorToken != "" {
		query.Set("cursor", cursorToken)
	}
	var response map[string]any
	if err := getJSON(ctx, cfg, options, DefaultAuditBaseURL, "audit_log_base_url", "/logs", query, &response); err != nil {
		return sourcecdk.Pull{}, err
	}
	items, _ := response["entries"].([]any)
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entryID := firstNonEmpty(fieldString(entry, "id"), stableID(item))
		attrs := baseAttributes(FamilyAuditLog, entryID)
		attrs["event_type"] = fieldString(entry, "action")
		attrs["actor_type"] = fieldString(entry, "actor.type")
		attrs["actor_id"] = firstNonEmpty(fieldString(entry, "actor.user.id"), fieldString(entry, "actor.id"))
		attrs["actor_name"] = firstNonEmpty(fieldString(entry, "actor.user.name"), fieldString(entry, "actor.name"))
		attrs["actor_email"] = fieldString(entry, "actor.user.email")
		attrs["resource_type"] = fieldString(entry, "entity.type")
		attrs["resource_id"] = firstNonEmpty(fieldString(entry, "entity.user.id"), fieldString(entry, "entity.channel.id"), fieldString(entry, "entity.file.id"), fieldString(entry, "entity.id"))
		attrs["resource_name"] = firstNonEmpty(fieldString(entry, "entity.user.name"), fieldString(entry, "entity.channel.name"), fieldString(entry, "entity.file.name"), fieldString(entry, "entity.name"))
		attrs["team_id"] = firstNonEmpty(fieldString(entry, "actor.user.team"), fieldString(entry, "entity.user.team"), fieldString(entry, "entity.channel.team"), fieldString(entry, "context.team_id"))
		attrs["ip_address"] = fieldString(entry, "context.ip_address")
		attrs["user_agent"] = fieldString(entry, "context.ua")
		trimEmpty(attrs)
		events = append(events, event(tenantID, FamilyAuditLog, entryID, entry, attrs, unixTime(entry["date_create"])))
	}
	next := firstNonEmpty(nestedString(response, "response_metadata.next_cursor"), nestedString(response, "response_metadata.cursor"))
	return pull(events, next), nil
}

func getJSON(ctx context.Context, cfg sourcecdk.Config, options Options, defaultBaseURL string, configKey string, path string, query url.Values, target any) error {
	baseURL := firstNonEmpty(sourcecdk.ConfigValue(cfg, configKey), defaultBaseURL)
	normalizedBaseURL, _, err := sourcehttp.NormalizeBaseURLWithOptions(SourceID, baseURL, sourcehttp.URLValidationOptions{AllowLoopback: options.AllowLoopback})
	if err != nil {
		return err
	}
	endpoint := normalizedBaseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build %s request: %w", SourceID, err)
	}
	token := firstNonEmpty(sourcecdk.ConfigValue(cfg, "token"), sourcecdk.ConfigValue(cfg, "api_token"), sourcecdk.ConfigValue(cfg, "access_token"))
	if token == "" {
		return fmt.Errorf("%s token is required", SourceID)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := options.Client
	if client == nil {
		client = sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: SourceID, AllowLoopback: options.AllowLoopback})
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, slackRetryOptions())
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s API returned HTTP %d: %s", SourceID, resp.StatusCode, strings.TrimSpace(string(resp.Body)))
	}
	if err := ResponseError(resp.Body); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(resp.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s response: %w", SourceID, err)
	}
	return nil
}

func slackRetryOptions() sourcehttp.RetryOptions {
	return sourcehttp.RetryOptions{
		MaxAttempts: sourcehttp.DefaultRetryMaxAttempts,
		Backoff:     sourcehttp.DefaultRetryBackoff,
	}
}

// PageSize returns a bounded Slack page size from config.
func PageSize(cfg sourcecdk.Config, fallback int) int {
	raw := sourcecdk.ConfigValue(cfg, "per_page")
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 {
		return fallback
	}
	if parsed > 9999 {
		return 9999
	}
	return parsed
}

func tenantID(cfg sourcecdk.Config, fallback string) string {
	return firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), fallback)
}

func event(tenantID string, family string, externalID string, payload map[string]any, attrs map[string]string, occurredAt time.Time) *primitives.Event {
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	attrs["external_id"] = externalID
	trimEmpty(attrs)
	return &primitives.Event{
		Id:         "slack-" + strings.ReplaceAll(family, "_", "-") + "-" + normalizeID(externalID),
		TenantId:   tenantID,
		SourceId:   SourceID,
		Kind:       SourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  SourceID + "/" + family + "/v1",
		Payload:    mustRaw(payload),
		Attributes: attrs,
	}
}

func pull(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if len(events) != 0 {
		last := events[len(events)-1]
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{
			Watermark:    last.OccurredAt,
			CursorOpaque: firstNonEmpty(next, last.Id),
		}
	}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return pull
}

func baseAttributes(family string, externalID string) map[string]string {
	return map[string]string{
		"external_id":     externalID,
		"family":          family,
		"provider":        SourceID,
		"source_product":  SourceID,
		"source_provider": SourceID,
	}
}

func mustRaw(payload any) json.RawMessage {
	raw, err := json.Marshal(payload)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func fieldString(object map[string]any, path string) string {
	return (sourcecdk.JSONObject(object)).FieldString(path)
}

func nestedString(object map[string]any, path string) string {
	return (sourcecdk.JSONObject(object)).FieldString(path)
}

func unixTime(value any) time.Time {
	raw := (sourcecdk.JSONScalar{Value: value}).SourceString()
	if raw == "" {
		return time.Now().UTC()
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds > 0 {
		return time.Unix(seconds, 0).UTC()
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
		return time.Unix(int64(parsed), 0).UTC()
	}
	return time.Now().UTC()
}

func stableID(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func normalizeID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", ":", "-", " ", "-")
	return replacer.Replace(value)
}

func trimEmpty(values map[string]string) {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
