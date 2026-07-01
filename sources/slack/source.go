package slack

import (
	"context"
	"crypto/sha256"
	"embed"
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
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID              = "slack"
	defaultFamily         = familyUser
	familyTeam            = "team"
	familyUser            = "user"
	familyChannel         = "channel"
	familyUserGroup       = "user_group"
	familyChannelMember   = "channel_member"
	familyUserGroupMember = "user_group_member"
	familyAccessLog       = "access_log"
	familyAuditLog        = "audit_log"

	slackNextCursor      = "response_metadata.next_cursor"
	defaultWebAPIBaseURL = "https://slack.com/api"
	defaultAuditBaseURL  = "https://api.slack.com/audit/v1"
)

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultWebAPIBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		ResponseError:   slackResponseError,
		Families:        slackFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if slackCustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		_, err := s.readCustom(ctx, cfg, nil, 1)
		return err
	}
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if slackCustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		pull, err := s.readCustom(ctx, cfg, nil, slackPageSize(cfg, 100))
		if err != nil {
			return nil, err
		}
		urns := make([]sourcecdk.URN, 0, len(pull.Events))
		tenantID := slackTenantID(cfg, "slack")
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
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if slackCustomFamily(sourcecdk.ConfigValue(cfg, "family")) {
		return s.readCustom(ctx, cfg, cursor, slackPageSize(cfg, 100))
	}
	return s.inner.Read(ctx, cfg, cursor)
}
func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func slackFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		slackTeamFamily(),
		slackUserFamily(),
		slackChannelFamily(),
		slackUserGroupFamily(),
		slackAccessLogFamily(),
	}
}

func slackTeamFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:     familyTeam,
		Method:   http.MethodPost,
		Path:     "/auth.teams.list",
		URNKind:  "slack_team",
		IDKeys:   []string{"id", "team_id"},
		ListKeys: []string{"teams"},
		Attributes: map[string]string{
			"team_id": "id|team_id",
			"name":    "name",
			"domain":  "domain",
		},
		StaticAttributes: slackStaticAttributes(),
	})
}

func slackUserFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:          familyUser,
		Path:          "/users.list",
		URNKind:       "slack_user",
		IDKeys:        []string{"id", "user_id"},
		TimestampKeys: []string{"updated"},
		ListKeys:      []string{"members"},
		Attributes: map[string]string{
			"user_id":             "id|user_id",
			"team_id":             "team_id",
			"email":               "profile.email|email",
			"real_name":           "real_name|profile.real_name",
			"name":                "name",
			"deleted":             "deleted",
			"is_admin":            "is_admin",
			"is_owner":            "is_owner",
			"is_primary_owner":    "is_primary_owner",
			"is_bot":              "is_bot",
			"is_restricted":       "is_restricted",
			"is_ultra_restricted": "is_ultra_restricted",
			"has_2fa":             "has_2fa",
			"has_mfa":             "has_2fa",
			"two_factor_type":     "two_factor_type",
		},
		StaticAttributes: slackStaticAttributes(),
	})
}

func slackChannelFamily() jsonapi.Family {
	return slackPagedFamily(jsonapi.Family{
		Name:          familyChannel,
		Path:          "/conversations.list",
		URNKind:       "slack_channel",
		IDKeys:        []string{"id", "channel_id"},
		TimestampKeys: []string{"updated", "created"},
		Attributes: map[string]string{
			"channel_id":      "id|channel_id",
			"team_id":         "context_team_id",
			"shared_team_ids": "shared_team_ids|internal_team_ids",
			"name":            "name",
			"is_private":      "is_private",
			"is_archived":     "is_archived",
			"creator":         "creator",
			"num_members":     "num_members",
		},
		StaticAttributes: slackStaticAttributes(),
		Config: jsonapi.FamilyConfig{StaticQuery: map[string]string{
			"exclude_archived": "false",
			"types":            "public_channel,private_channel",
		}},
	})
}

func slackUserGroupFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyUserGroup,
		Path:            "/usergroups.list",
		URNKind:         "slack_user_group",
		IDKeys:          []string{"id", "group_id"},
		ListKeys:        []string{"usergroups"},
		TimestampKeys:   []string{"date_update", "date_create"},
		DisablePageSize: true,
		Attributes: map[string]string{
			"group_id":    "id|group_id",
			"team_id":     "team_id",
			"handle":      "handle",
			"name":        "name",
			"description": "description",
			"is_disabled": "is_disabled",
		},
		StaticAttributes: slackStaticAttributes(),
	}
}

func slackAccessLogFamily() jsonapi.Family {
	return jsonapi.Family{
		Name:            familyAccessLog,
		Path:            "/team.accessLogs",
		URNKind:         "slack_access_log",
		ListKeys:        []string{"logins"},
		CursorParam:     "page",
		PageFirstCursor: "1",
		PageSizeParams:  []string{"count"},
		TimestampKeys:   []string{"date_last", "date_first"},
		Attributes: map[string]string{
			"actor_id":      "user_id",
			"actor_name":    "username",
			"user_id":       "user_id",
			"username":      "username",
			"ip_address":    "ip",
			"user_agent":    "user_agent",
			"isp":           "isp",
			"country":       "country",
			"region":        "region",
			"login_count":   "count",
			"first_seen_at": "date_first",
			"last_seen_at":  "date_last",
		},
		StaticAttributes: map[string]string{
			"event_type":     "team_access",
			"source_product": "slack",
		},
		Config: jsonapi.FamilyConfig{ConfigQuery: map[string]string{"before": "before"}},
	}
}

func slackPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.NextCursorKeys = []string{slackNextCursor}
	family.PageSizeParams = []string{"limit"}
	return family
}

func slackStaticAttributes() map[string]string {
	return map[string]string{"source_product": "slack"}
}

func slackResponseError(body []byte) error {
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

func slackCustomFamily(family string) bool {
	switch strings.TrimSpace(family) {
	case familyChannelMember, familyUserGroupMember, familyAuditLog:
		return true
	default:
		return false
	}
}

func (s *Source) readCustom(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, pageSize int) (sourcecdk.Pull, error) {
	switch strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")) {
	case familyChannelMember:
		return s.readScalarMembership(ctx, cfg, cursor, pageSize, slackMembershipRequest{
			Family:       familyChannelMember,
			Path:         "/conversations.members",
			ContainerKey: "channel_id",
			QueryKey:     "channel",
			ListKey:      "members",
			MemberKind:   "channel",
		})
	case familyUserGroupMember:
		return s.readScalarMembership(ctx, cfg, cursor, pageSize, slackMembershipRequest{
			Family:       familyUserGroupMember,
			Path:         "/usergroups.users.list",
			ContainerKey: "usergroup_id",
			QueryKey:     "usergroup",
			ListKey:      "users",
			MemberKind:   "user_group",
			Query:        url.Values{"include_disabled": []string{"true"}},
		})
	case familyAuditLog:
		return s.readAuditLogs(ctx, cfg, cursor, pageSize)
	default:
		return sourcecdk.Pull{}, fmt.Errorf("%s family must be one of %s", sourceID, strings.Join([]string{familyTeam, familyUser, familyChannel, familyUserGroup, familyAccessLog, familyChannelMember, familyUserGroupMember, familyAuditLog}, ", "))
	}
}

type slackMembershipRequest struct {
	Family       string
	Path         string
	ContainerKey string
	QueryKey     string
	ListKey      string
	MemberKind   string
	Query        url.Values
}

func (s *Source) readScalarMembership(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, pageSize int, spec slackMembershipRequest) (sourcecdk.Pull, error) {
	tenantID := slackTenantID(cfg, "")
	if tenantID == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%s tenant_id is required", sourceID)
	}
	containerID, err := sourcecdk.RequiredConfigValue(sourceID, cfg, spec.ContainerKey)
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
	query.Set("limit", strconv.Itoa(pageSize))
	if cursorToken := sourcecdk.CursorToken(cursor); cursorToken != "" {
		query.Set("cursor", cursorToken)
	}
	var response map[string]any
	if err := s.getSlackJSON(ctx, cfg, defaultWebAPIBaseURL, "base_url", spec.Path, query, &response); err != nil {
		return sourcecdk.Pull{}, err
	}
	items, _ := response[spec.ListKey].([]any)
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		userID := (sourcecdk.JSONScalar{Value: item}).SourceString()
		if userID == "" {
			continue
		}
		payload := map[string]any{spec.ContainerKey: containerID, "user_id": userID}
		attrs := slackBaseAttributes(spec.Family, containerID+"-"+userID)
		attrs[spec.ContainerKey] = containerID
		attrs["user_id"] = userID
		attrs["membership_type"] = spec.MemberKind
		events = append(events, slackEvent(tenantID, spec.Family, containerID+"-"+userID, payload, attrs, time.Now().UTC()))
	}
	next := slackNestedString(response, "response_metadata.next_cursor")
	return slackPull(events, next), nil
}

func (s *Source) readAuditLogs(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, pageSize int) (sourcecdk.Pull, error) {
	tenantID := slackTenantID(cfg, "")
	if tenantID == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%s tenant_id is required", sourceID)
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(pageSize))
	for _, key := range []string{"oldest", "latest", "action", "actor", "entity"} {
		if value := sourcecdk.ConfigValue(cfg, key); value != "" {
			query.Set(key, value)
		}
	}
	if cursorToken := sourcecdk.CursorToken(cursor); cursorToken != "" {
		query.Set("cursor", cursorToken)
	}
	var response map[string]any
	if err := s.getSlackJSON(ctx, cfg, defaultAuditBaseURL, "audit_base_url", "/logs", query, &response); err != nil {
		return sourcecdk.Pull{}, err
	}
	items, _ := response["entries"].([]any)
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entryID := firstNonEmpty(slackFieldString(entry, "id"), slackStableID(item))
		attrs := slackBaseAttributes(familyAuditLog, entryID)
		attrs["event_type"] = slackFieldString(entry, "action")
		attrs["actor_type"] = slackFieldString(entry, "actor.type")
		attrs["actor_id"] = firstNonEmpty(slackFieldString(entry, "actor.user.id"), slackFieldString(entry, "actor.id"))
		attrs["actor_name"] = firstNonEmpty(slackFieldString(entry, "actor.user.name"), slackFieldString(entry, "actor.name"))
		attrs["actor_email"] = slackFieldString(entry, "actor.user.email")
		attrs["resource_type"] = slackFieldString(entry, "entity.type")
		attrs["resource_id"] = firstNonEmpty(slackFieldString(entry, "entity.user.id"), slackFieldString(entry, "entity.channel.id"), slackFieldString(entry, "entity.file.id"), slackFieldString(entry, "entity.id"))
		attrs["resource_name"] = firstNonEmpty(slackFieldString(entry, "entity.user.name"), slackFieldString(entry, "entity.channel.name"), slackFieldString(entry, "entity.file.name"), slackFieldString(entry, "entity.name"))
		attrs["team_id"] = firstNonEmpty(slackFieldString(entry, "actor.user.team"), slackFieldString(entry, "entity.user.team"), slackFieldString(entry, "entity.channel.team"), slackFieldString(entry, "context.team_id"))
		attrs["ip_address"] = slackFieldString(entry, "context.ip_address")
		attrs["user_agent"] = slackFieldString(entry, "context.ua")
		trimEmpty(attrs)
		events = append(events, slackEvent(tenantID, familyAuditLog, entryID, entry, attrs, slackUnixTime(entry["date_create"])))
	}
	next := firstNonEmpty(slackNestedString(response, "response_metadata.next_cursor"), slackNestedString(response, "response_metadata.cursor"))
	return slackPull(events, next), nil
}

func (s *Source) getSlackJSON(ctx context.Context, cfg sourcecdk.Config, defaultBaseURL string, configKey string, path string, query url.Values, target any) error {
	baseURL := firstNonEmpty(sourcecdk.ConfigValue(cfg, configKey), defaultBaseURL)
	normalizedBaseURL, _, err := sourcehttp.NormalizeBaseURLWithOptions(sourceID, baseURL, sourcehttp.URLValidationOptions{AllowLoopback: s != nil && s.inner != nil && s.inner.AllowLoopbackBaseURL})
	if err != nil {
		return err
	}
	endpoint := normalizedBaseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build %s request: %w", sourceID, err)
	}
	token := firstNonEmpty(sourcecdk.ConfigValue(cfg, "token"), sourcecdk.ConfigValue(cfg, "api_token"), sourcecdk.ConfigValue(cfg, "access_token"))
	if token == "" {
		return fmt.Errorf("%s token is required", sourceID)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: sourceID, AllowLoopback: s != nil && s.inner != nil && s.inner.AllowLoopbackBaseURL})
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s API returned HTTP %d: %s", sourceID, resp.StatusCode, strings.TrimSpace(string(resp.Body)))
	}
	if err := slackResponseError(resp.Body); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(resp.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s response: %w", sourceID, err)
	}
	return nil
}

func slackPageSize(cfg sourcecdk.Config, fallback int) int {
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

func slackTenantID(cfg sourcecdk.Config, fallback string) string {
	return firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), fallback)
}

func slackEvent(tenantID string, family string, externalID string, payload map[string]any, attrs map[string]string, occurredAt time.Time) *primitives.Event {
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	attrs["external_id"] = externalID
	trimEmpty(attrs)
	return &primitives.Event{
		Id:         "slack-" + strings.ReplaceAll(family, "_", "-") + "-" + normalizeSlackID(externalID),
		TenantId:   tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    mustRaw(payload),
		Attributes: attrs,
	}
}

func slackPull(events []*primitives.Event, next string) sourcecdk.Pull {
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

func slackBaseAttributes(family string, externalID string) map[string]string {
	return map[string]string{
		"external_id":     externalID,
		"family":          family,
		"provider":        sourceID,
		"source_product":  sourceID,
		"source_provider": sourceID,
	}
}

func mustRaw(payload any) json.RawMessage {
	raw, err := json.Marshal(payload)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func slackFieldString(object map[string]any, path string) string {
	return (sourcecdk.JSONObject(object)).FieldString(path)
}

func slackNestedString(object map[string]any, path string) string {
	return (sourcecdk.JSONObject(object)).FieldString(path)
}

func slackUnixTime(value any) time.Time {
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

func slackStableID(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func normalizeSlackID(value string) string {
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
