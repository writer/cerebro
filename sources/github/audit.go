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
	"github.com/writer/cerebro/sources/internal/githubaudit"
)

type auditPayload struct {
	Action                   string         `json:"action"`
	Actor                    string         `json:"actor,omitempty"`
	ActorEmail               string         `json:"actor_email,omitempty"`
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
	_, _, err := client.Organizations.GetAuditLog(ctx, settings.owner, githubaudit.Options(settings.auditInclude, settings.auditPhrase, settings.auditOrder, "", 1))
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

func (s *Source) readAudit(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	readCheckpoint, shortCircuit, err := sourcecdk.BeginFamilyFreshnessReadWithOptions("github", familyAudit, cursor, checkpoint, func(checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.ChangeProbe, error) {
		probe, err := githubaudit.LatestEventChangeProbe(ctx, settings.owner, settings.auditInclude, settings.auditPhrase, checkpoint, func(ctx context.Context, opts *gogithub.GetAuditLogOptions) ([]*gogithub.AuditEntry, *gogithub.Response, error) {
			return client.Organizations.GetAuditLog(ctx, settings.owner, opts)
		})
		if err != nil {
			return sourcecdk.ChangeProbe{}, wrapLookupError(fmt.Sprintf("github audit log canary for org %s", settings.owner), err)
		}
		return probe, nil
	}, githubaudit.FreshnessReadOptions())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if shortCircuit != nil {
		return *shortCircuit, nil
	}
	after := readAuditCursor(cursor)
	entries, resp, err := client.Organizations.GetAuditLog(ctx, settings.owner, githubaudit.Options(settings.auditInclude, settings.auditPhrase, settings.auditOrder, after, settings.perPage))
	if err != nil {
		return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("github audit log for org %s", settings.owner), err)
	}
	if len(entries) == 0 {
		return sourcecdk.NotModifiedPull(readCheckpoint), nil
	}
	events := make([]*primitives.Event, 0, len(entries))
	actorResolutionCache := map[string]auditActorResolution{}
	for _, entry := range entries {
		// Resolve every non-empty actor login. The audit log raw payload
		// does NOT include an actor_type field; without resolution the
		// projector sees only entry.ActorID (which GitHub stamps even on
		// GitHub-App / Bot / Organization-self actors) and therefore
		// can't tell a bot apart from a user. Resolution returns
		// Type=Bot for GitHub Apps, Type=Organization for org-self
		// events, Type=Unresolved for deleted/placeholder logins
		// (deploy_key, retired bot apps), and Type=User otherwise.
		// Resolutions are cached per page to avoid repeated actor lookups.
		actorResolution := auditActorResolution{}
		if strings.TrimSpace(entry.GetActor()) != "" {
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
		Checkpoint: sourcecdk.FamilyFreshnessCheckpointFromCheckpoint("github", familyAudit, readCheckpoint, &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointAuditCursor(entries, nextCursor),
		}),
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: sourcecdk.FamilyFreshnessCursor("github", familyAudit, readCheckpoint, nextCursor)}
	}
	return pull, nil
}

func readAuditCursor(cursor *cerebrov1.SourceCursor) string {
	if cursor == nil {
		return ""
	}
	return strings.TrimSpace(sourcecdk.CursorToken(cursor))
}

type auditActorResolution struct {
	Login string
	Type  string
	ID    int64
	Email string
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
	resolution.Email = strings.TrimSpace(user.GetEmail())
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
		ActorEmail:               actorResolution.Email,
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
	action := strings.TrimSpace(entry.GetAction())
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
	addAttribute(attributes, "actor_email", actorResolution.Email)
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
	if strings.HasPrefix(action, "integration_installation.") {
		addAttribute(attributes, "github_app_id", githubAppIDFromAuditInstallation(raw))
	}
	if strings.HasPrefix(action, "secret_scanning_alert.") {
		addAttribute(attributes, "secret_scanning_alert.resolution", rawNestedOrFlatScalarString(raw, "secret_scanning_alert", "resolution"))
		addAttribute(attributes, "secret_scanning_alert.state", rawNestedOrFlatScalarString(raw, "secret_scanning_alert", "state"))
		addAttribute(attributes, "secret_scanning_alert.resolution_comment", rawNestedOrFlatScalarString(raw, "secret_scanning_alert", "resolution_comment"))
	}
	if auditHasRunnerContext(action, raw) {
		addAttribute(attributes, "runner_scope", auditRunnerScope(raw, settings))
	}
	for _, key := range auditAdditionalAttributeKeys {
		if key == "runner_scope" && auditHasRunnerContext(action, raw) && attributes["runner_scope"] != "" {
			continue
		}
		addAttribute(attributes, key, rawScalarString(raw, key))
	}
	return attributes
}

func githubAppIDFromAuditInstallation(raw map[string]any) string {
	if appID := rawNestedPositiveInt64String(raw, "installation", "app_id"); appID != "" {
		return appID
	}
	return rawNestedPositiveInt64String(raw, "installation", "id")
}

func rawNestedOrFlatScalarString(raw map[string]any, objectKey string, key string) string {
	if value := rawScalarString(raw, objectKey+"."+key); value != "" {
		return value
	}
	nested, ok := raw[objectKey].(map[string]any)
	if !ok {
		return ""
	}
	return rawScalarString(nested, key)
}

func rawNestedPositiveInt64String(raw map[string]any, objectKey string, key string) string {
	if value := positiveInt64String(rawInt64(raw, objectKey+"."+key)); value != "" {
		return value
	}
	nested, ok := raw[objectKey].(map[string]any)
	if !ok {
		return ""
	}
	return positiveInt64String(rawInt64(nested, key))
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
	"advanced_security_enabled",
	"allowed_cidrs_compliant",
	"allowlisted_destination",
	"auth_control_weakened",
	"branch",
	"bypass_actor_added",
	"change_type",
	"changes",
	"code_security_enabled",
	"deletions_allowed",
	"dependabot_alerts_enabled",
	"dependabot_enabled",
	"dependabot_security_updates_enabled",
	"destination_allowlisted",
	"destination_non_allowlisted",
	"enforcement",
	"ephemeral",
	"force_pushes_allowed",
	"github_advanced_security_enabled",
	"hook_destination_allowlisted",
	"hook_destination_non_allowlisted",
	"hook_id",
	"hook_url_allowlisted",
	"hook_url_non_allowlisted",
	"host_trusted",
	"host_untrusted",
	"integration",
	"ip_allow_list_disabled",
	"ip_allow_list_enabled",
	"ip_allow_list_entries_compliant",
	"is_ephemeral",
	"is_registered",
	"mfa_required",
	"name",
	"new_enforcement",
	"non_allowlisted_cidr_count",
	"non_allowlisted_cidrs",
	"non_allowlisted_destination",
	"number",
	"oauth_app_restrictions_enabled",
	"oauth_app_restrictions_enforced",
	"permission",
	"previous_visibility",
	"private_forking_enabled",
	"private_repository_forking_enabled",
	"registered",
	"repository_public",
	"repository_secret_scanning_enabled",
	"repository_vulnerability_alerts_enabled",
	"required_review_removed",
	"required_status_check_removed",
	"ruleset_enforcement",
	"ruleset_id",
	"ruleset_name",
	"runner_ephemeral",
	"runner_group_name",
	"runner_host_trusted",
	"runner_id",
	"runner_name",
	"runner_registered",
	"runner_scope",
	"runner_state",
	"runner_untrusted",
	"saml_enabled",
	"saml_enforced",
	"saml_provider_settings_weakened",
	"saml_required",
	"saml_sso_enabled",
	"secret_scanning_enabled",
	"secret_scanning_push_protection_enabled",
	"transport_protocol_name",
	"trusted_host",
	"two_factor_enforced",
	"two_factor_required",
	"two_factor_requirement_enabled",
	"untrusted_host",
	"url_allowlisted",
	"url_non_allowlisted",
	"user_agent",
	"vulnerability_alerts_enabled",
	"webhook_destination_allowlisted",
	"webhook_destination_non_allowlisted",
	"webhook_url_allowlisted",
	"webhook_url_non_allowlisted",
}

func auditHasRunnerContext(action string, raw map[string]any) bool {
	if rawScalarString(raw, "runner_id") != "" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(action)), "runner")
}

func auditRunnerScope(raw map[string]any, settings settings) string {
	for _, key := range []string{"runner_scope", "runner_scope_id"} {
		if scope := normalizeAuditRunnerScope(rawScalarString(raw, key)); scope != "" {
			return scope
		}
	}
	if rawScope := strings.TrimSpace(rawScalarString(raw, "scope")); rawScope != "" && !isGenericAuditScope(rawScope) {
		if scope := normalizeAuditRunnerScope(rawScope); scope != "" {
			return scope
		}
	}
	if repo := strings.TrimSpace(rawString(raw, "repo")); repo != "" {
		return "repo:" + repo
	}
	resourceID := strings.TrimSpace(rawScalarString(raw, "resource_id"))
	resourceType := strings.ToLower(strings.TrimSpace(rawScalarString(raw, "resource_type")))
	if resourceID != "" && (strings.Contains(resourceID, "/") || strings.Contains(resourceType, "repo")) {
		return "repo:" + resourceID
	}
	if resourceID != "" && strings.Contains(resourceType, "enterprise") {
		return "enterprise:" + resourceID
	}
	for _, key := range []string{"enterprise", "enterprise_slug", "enterprise_id", "business", "business_id"} {
		if enterprise := strings.TrimSpace(rawScalarString(raw, key)); enterprise != "" {
			return "enterprise:" + enterprise
		}
	}
	if org := strings.TrimSpace(valueOrDefault(rawString(raw, "org"), settings.owner)); org != "" {
		return "org:" + org
	}
	if resourceID != "" && (strings.Contains(resourceType, "org") || resourceType == "") {
		return "org:" + resourceID
	}
	return ""
}

func isGenericAuditScope(scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "repository", "repo", "organization", "org", "audit":
		return true
	default:
		return false
	}
}

func normalizeAuditRunnerScope(scope string) string {
	normalized := strings.TrimSpace(scope)
	if normalized == "" {
		return ""
	}
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "repo:"), strings.HasPrefix(lower, "org:"), strings.HasPrefix(lower, "enterprise:"):
		return normalized
	case strings.Contains(normalized, "/"):
		return "repo:" + normalized
	case lower == "repository", lower == "repo", lower == "organization", lower == "org", lower == "audit":
		return ""
	default:
		return "org:" + normalized
	}
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
	case json.Number:
		value, err := typed.Int64()
		if err != nil {
			return 0
		}
		return value
	case string:
		value, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0
		}
		return value
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
