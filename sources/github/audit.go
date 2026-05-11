package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type auditPayload struct {
	Action                   string         `json:"action"`
	Actor                    string         `json:"actor,omitempty"`
	ActorID                  int64          `json:"actor_id,omitempty"`
	ActorIP                  string         `json:"actor_ip,omitempty"`
	ActorIsAgent             bool           `json:"actor_is_agent,omitempty"`
	ActorIsBot               bool           `json:"actor_is_bot,omitempty"`
	ActorType                string         `json:"actor_type,omitempty"`
	Business                 string         `json:"business,omitempty"`
	BusinessID               int64          `json:"business_id,omitempty"`
	ExternalIdentityNameID   string         `json:"external_identity_nameid,omitempty"`
	ExternalIdentityUsername string         `json:"external_identity_username,omitempty"`
	OperationType            string         `json:"operation_type,omitempty"`
	Org                      string         `json:"org"`
	ProgrammaticAccessType   string         `json:"programmatic_access_type,omitempty"`
	PublicRepo               bool           `json:"public_repo,omitempty"`
	Repo                     string         `json:"repo,omitempty"`
	ResourceID               string         `json:"resource_id,omitempty"`
	ResourceType             string         `json:"resource_type,omitempty"`
	Scope                    string         `json:"scope,omitempty"`
	User                     string         `json:"user,omitempty"`
	UserID                   int64          `json:"user_id,omitempty"`
	Visibility               string         `json:"visibility,omitempty"`
	Raw                      map[string]any `json:"raw,omitempty"`
}

func (s *Source) checkAudit(ctx context.Context, client *gogithub.Client, settings settings) error {
	_, _, err := client.Organizations.GetAuditLog(ctx, settings.owner, auditOptions(settings, "", 1))
	if err != nil {
		return wrapLookupError(fmt.Sprintf("github audit log for org %s", settings.owner), err)
	}
	return nil
}

func (s *Source) discoverAudit(ctx context.Context, client *gogithub.Client, settings settings) ([]sourcecdk.URN, error) {
	if err := s.checkAudit(ctx, client, settings); err != nil {
		return nil, err
	}
	urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:org:%s", settings.owner, settings.owner))
	if err != nil {
		return nil, err
	}
	return []sourcecdk.URN{urn}, nil
}

func (s *Source) readAudit(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	after, err := readAuditCursor(cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	entries, resp, err := client.Organizations.GetAuditLog(ctx, settings.owner, auditOptions(settings, after, settings.perPage))
	if err != nil {
		return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("github audit log for org %s", settings.owner), err)
	}
	if len(entries) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(entries))
	actorResolutionCache := map[string]auditActorResolution{}
	for _, entry := range entries {
		actorResolution := auditActorResolution{}
		if strings.TrimSpace(entry.GetActor()) != "" && entry.GetActorID() <= 0 {
			actorResolution = resolveAuditActor(ctx, client, entry.GetActor(), actorResolutionCache)
		}
		event, err := auditEvent(settings, entry, actorResolution)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	nextCursor := nextAuditCursor(resp)
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointAuditCursor(entries, nextCursor),
		},
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	return pull, nil
}

func auditOptions(settings settings, after string, perPage int) *gogithub.GetAuditLogOptions {
	opts := &gogithub.GetAuditLogOptions{
		Include: gogithub.String(settings.auditInclude),
		Order:   gogithub.String(settings.auditOrder),
		ListCursorOptions: gogithub.ListCursorOptions{
			After:   after,
			PerPage: perPage,
		},
	}
	if settings.auditPhrase != "" {
		opts.Phrase = gogithub.String(settings.auditPhrase)
	}
	return opts
}

func readAuditCursor(cursor *cerebrov1.SourceCursor) (string, error) {
	if cursor == nil {
		return "", nil
	}
	return strings.TrimSpace(cursor.GetOpaque()), nil
}

type auditActorResolution struct {
	Login string
	Type  string
	ID    int64
}

func resolveAuditActor(ctx context.Context, client *gogithub.Client, actor string, cache map[string]auditActorResolution) auditActorResolution {
	normalized := strings.TrimSpace(actor)
	if normalized == "" || client == nil {
		return auditActorResolution{}
	}
	if cached, ok := cache[normalized]; ok {
		return cached
	}
	resolution := auditActorResolution{Login: normalized}
	user, resp, err := client.Users.Get(ctx, normalized)
	if err != nil {
		var errResponse *gogithub.ErrorResponse
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			resolution.Type = "Unresolved"
		} else if errors.As(err, &errResponse) && errResponse.Response != nil && errResponse.Response.StatusCode == http.StatusNotFound {
			resolution.Type = "Unresolved"
		}
		cache[normalized] = resolution
		return resolution
	}
	resolution.Type = strings.TrimSpace(user.GetType())
	resolution.ID = user.GetID()
	if login := strings.TrimSpace(user.GetLogin()); login != "" {
		resolution.Login = login
	}
	cache[normalized] = resolution
	return resolution
}

func auditEvent(settings settings, entry *gogithub.AuditEntry, actorResolution auditActorResolution) (*primitives.Event, error) {
	occurredAt := auditOccurredAt(entry)
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github audit event %q missing timestamps", entry.GetDocumentID())
	}
	raw, err := auditRaw(entry)
	if err != nil {
		return nil, err
	}
	actorID := firstPositiveInt64(entry.GetActorID(), actorResolution.ID)
	payload, err := json.Marshal(auditPayload{
		Action:                   entry.GetAction(),
		Actor:                    entry.GetActor(),
		ActorID:                  actorID,
		ActorIP:                  rawString(raw, "actor_ip"),
		ActorIsAgent:             rawBool(raw, "actor_is_agent"),
		ActorIsBot:               rawBool(raw, "actor_is_bot"),
		ActorType:                actorResolution.Type,
		Business:                 entry.GetBusiness(),
		BusinessID:               entry.GetBusinessID(),
		ExternalIdentityNameID:   entry.GetExternalIdentityNameID(),
		ExternalIdentityUsername: entry.GetExternalIdentityUsername(),
		OperationType:            rawString(raw, "operation_type"),
		Org:                      valueOrDefault(entry.GetOrg(), settings.owner),
		ProgrammaticAccessType:   rawString(raw, "programmatic_access_type"),
		PublicRepo:               rawBool(raw, "public_repo"),
		Repo:                     rawString(raw, "repo"),
		ResourceID:               auditResourceID(entry, raw, settings),
		ResourceType:             auditResourceType(entry),
		Scope:                    auditScope(entry, raw, settings),
		User:                     entry.GetUser(),
		UserID:                   entry.GetUserID(),
		Visibility:               rawString(raw, "visibility"),
		Raw:                      raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal github audit payload: %w", err)
	}
	return &primitives.Event{
		Id:         auditEventID(entry, occurredAt),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "github/audit/v1",
		Payload:    payload,
		Attributes: auditAttributes(entry, raw, settings, actorResolution),
	}, nil
}

func auditOccurredAt(entry *gogithub.AuditEntry) time.Time {
	if entry == nil {
		return time.Time{}
	}
	if stamp := entry.GetTimestamp(); !stamp.IsZero() {
		return stamp.UTC()
	}
	if stamp := entry.GetCreatedAt(); !stamp.IsZero() {
		return stamp.UTC()
	}
	return time.Time{}
}

func auditRaw(entry *gogithub.AuditEntry) (map[string]any, error) {
	bytes, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal github audit raw payload: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal github audit raw payload: %w", err)
	}
	return raw, nil
}

func auditEventID(entry *gogithub.AuditEntry, occurredAt time.Time) string {
	documentID := strings.TrimSpace(entry.GetDocumentID())
	if documentID != "" {
		return "github-audit-" + documentID
	}
	return fmt.Sprintf("github-audit-%s-%d", entry.GetAction(), occurredAt.UnixMilli())
}

func nextAuditCursor(resp *gogithub.Response) string {
	if resp == nil {
		return ""
	}
	switch {
	case strings.TrimSpace(resp.After) != "":
		return strings.TrimSpace(resp.After)
	case strings.TrimSpace(resp.Cursor) != "":
		return strings.TrimSpace(resp.Cursor)
	case strings.TrimSpace(resp.NextPageToken) != "":
		return strings.TrimSpace(resp.NextPageToken)
	case resp.NextPage > 0:
		return strconv.Itoa(resp.NextPage)
	default:
		return ""
	}
}

func checkpointAuditCursor(_ []*gogithub.AuditEntry, cursor string) string {
	// Only persist genuine GitHub pagination cursors; document IDs and
	// occurrence timestamps are not valid `After` tokens for the audit log
	// API, so a caller that resumes from a stored opaque must never receive
	// one of those terminal-page fallbacks.
	return strings.TrimSpace(cursor)
}

func auditAttributes(entry *gogithub.AuditEntry, raw map[string]any, settings settings, actorResolution auditActorResolution) map[string]string {
	attributes := map[string]string{
		"action":         entry.GetAction(),
		"family":         familyAudit,
		"operation_type": rawString(raw, "operation_type"),
		"org":            valueOrDefault(entry.GetOrg(), settings.owner),
		"resource_id":    auditResourceID(entry, raw, settings),
		"resource_type":  auditResourceType(entry),
		"scope":          auditScope(entry, raw, settings),
	}
	addAttribute(attributes, "actor", entry.GetActor())
	addAttribute(attributes, "actor_id", positiveInt64String(firstPositiveInt64(entry.GetActorID(), actorResolution.ID)))
	addAttribute(attributes, "actor_is_agent", boolString(raw, "actor_is_agent"))
	addAttribute(attributes, "actor_is_bot", boolString(raw, "actor_is_bot"))
	addAttribute(attributes, "actor_type", actorResolution.Type)
	addAttribute(attributes, "external_identity_nameid", entry.GetExternalIdentityNameID())
	addAttribute(attributes, "external_identity_username", entry.GetExternalIdentityUsername())
	// org_id is the numeric ID GitHub stamps on every audit event for the org
	// the action belongs to. We surface it on the event so the projector can
	// detect the org-as-actor pattern (actor_id == org_id), which occurs on
	// system-level events like integration_installation.version_updated where
	// GitHub names the org itself as the audit actor rather than a user.
	addAttribute(attributes, "org_id", positiveInt64String(rawInt64(raw, "org_id")))
	addAttribute(attributes, "programmatic_access_type", rawString(raw, "programmatic_access_type"))
	addAttribute(attributes, "repo", rawString(raw, "repo"))
	addAttribute(attributes, "token_id", positiveInt64String(rawInt64(raw, "token_id")))
	addAttribute(attributes, "user", entry.GetUser())
	addAttribute(attributes, "user_id", positiveInt64String(entry.GetUserID()))
	addAttribute(attributes, "visibility", rawString(raw, "visibility"))
	for _, key := range auditAdditionalAttributeKeys {
		addAttribute(attributes, key, rawScalarString(raw, key))
	}
	return attributes
}

func firstPositiveInt64(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

var auditAdditionalAttributeKeys = []string{
	"branch",
	"bypass_actor_added",
	"change_type",
	"changes",
	"deletions_allowed",
	"enforcement",
	"force_pushes_allowed",
	"hook_id",
	"integration",
	"name",
	"new_enforcement",
	"number",
	"permission",
	"previous_visibility",
	"repository_public",
	"required_review_removed",
	"required_status_check_removed",
	"ruleset_enforcement",
	"ruleset_id",
	"ruleset_name",
	"runner_group_name",
	"runner_name",
	"transport_protocol_name",
	"user_agent",
}

func auditResourceType(entry *gogithub.AuditEntry) string {
	action := strings.TrimSpace(entry.GetAction())
	if action == "" {
		return "audit"
	}
	prefix, _, ok := strings.Cut(action, ".")
	if !ok {
		return action
	}
	return prefix
}

func auditResourceID(entry *gogithub.AuditEntry, raw map[string]any, settings settings) string {
	if repo := strings.TrimSpace(rawString(raw, "repo")); repo != "" {
		return repo
	}
	if user := strings.TrimSpace(entry.GetUser()); user != "" {
		return user
	}
	if org := strings.TrimSpace(entry.GetOrg()); org != "" {
		return org
	}
	return settings.owner
}

func auditScope(entry *gogithub.AuditEntry, raw map[string]any, settings settings) string {
	if strings.TrimSpace(rawString(raw, "repo")) != "" {
		return "repository"
	}
	if strings.TrimSpace(entry.GetOrg()) != "" || strings.TrimSpace(settings.owner) != "" {
		return "organization"
	}
	return "audit"
}

func rawString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok {
		return ""
	}
	stringValue, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue)
}

func rawScalarString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case map[string]any, []any:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	default:
		return ""
	}
}

func rawBool(raw map[string]any, key string) bool {
	value, ok := raw[key]
	if !ok {
		return false
	}
	boolValue, ok := value.(bool)
	if !ok {
		return false
	}
	return boolValue
}

func boolString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok {
		return ""
	}
	boolValue, ok := value.(bool)
	if !ok {
		return ""
	}
	return strconv.FormatBool(boolValue)
}

// rawInt64 reads a numeric field from the raw audit log payload. The GitHub
// audit log API returns IDs as JSON numbers, which json.Unmarshal turns into
// float64 inside map[string]any; encoding/json never falls back to int64 for
// untyped maps. We round to int64 here so the projector sees stable integer
// IDs and the actor_id == org_id comparison in the rule is exact.
func rawInt64(raw map[string]any, key string) int64 {
	value, ok := raw[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int:
		return int64(typed)
	case int64:
		return typed
	default:
		return 0
	}
}

// positiveInt64String returns the decimal form of a positive int64 or empty
// when the value is non-positive. We use empty rather than "0" so the
// downstream addAttribute helper drops the key; "0" is not a valid GitHub
// numeric ID and is what GitHub returns when no real actor is associated
// (deploy keys, anonymous webhook events). Suppressing the attribute keeps
// the projected node free of placeholder zeros that a rule could trip on.
func positiveInt64String(value int64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = value
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
