package github

import (
	"context"
	"encoding/json"
	"fmt"
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
	for _, entry := range entries {
		event, err := auditEvent(settings, entry)
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

func auditEvent(settings settings, entry *gogithub.AuditEntry) (*primitives.Event, error) {
	occurredAt := auditOccurredAt(entry)
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github audit event %q missing timestamps", entry.GetDocumentID())
	}
	raw, err := auditRaw(entry)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(auditPayload{
		Action:                   entry.GetAction(),
		Actor:                    entry.GetActor(),
		ActorID:                  entry.GetActorID(),
		ActorIP:                  rawString(raw, "actor_ip"),
		ActorIsAgent:             rawBool(raw, "actor_is_agent"),
		ActorIsBot:               rawBool(raw, "actor_is_bot"),
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
		Scope:                    auditScope(entry, raw),
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
		Attributes: auditAttributes(entry, raw, settings),
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

func checkpointAuditCursor(entries []*gogithub.AuditEntry, cursor string) string {
	if cursor != "" {
		return cursor
	}
	if len(entries) == 0 {
		return ""
	}
	if documentID := strings.TrimSpace(entries[len(entries)-1].GetDocumentID()); documentID != "" {
		return documentID
	}
	occurredAt := auditOccurredAt(entries[len(entries)-1])
	if occurredAt.IsZero() {
		return ""
	}
	return occurredAt.Format(time.RFC3339Nano)
}

func auditAttributes(entry *gogithub.AuditEntry, raw map[string]any, settings settings) map[string]string {
	attributes := map[string]string{
		"action":         entry.GetAction(),
		"family":         familyAudit,
		"operation_type": rawString(raw, "operation_type"),
		"org":            valueOrDefault(entry.GetOrg(), settings.owner),
		"resource_id":    auditResourceID(entry, raw, settings),
		"resource_type":  auditResourceType(entry),
		"scope":          auditScope(entry, raw),
	}
	addAttribute(attributes, "actor", entry.GetActor())
	addAttribute(attributes, "actor_is_agent", boolString(raw, "actor_is_agent"))
	addAttribute(attributes, "actor_is_bot", boolString(raw, "actor_is_bot"))
	addAttribute(attributes, "programmatic_access_type", rawString(raw, "programmatic_access_type"))
	addAttribute(attributes, "repo", rawString(raw, "repo"))
	addAttribute(attributes, "user", entry.GetUser())
	addAttribute(attributes, "visibility", rawString(raw, "visibility"))
	return attributes
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

func auditScope(entry *gogithub.AuditEntry, raw map[string]any) string {
	if strings.TrimSpace(rawString(raw, "repo")) != "" {
		return "repository"
	}
	return "organization"
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
