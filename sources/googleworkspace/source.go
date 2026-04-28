package googleworkspace

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultBaseURL    = "https://admin.googleapis.com"
	defaultCustomerID = "my_customer"
	defaultFamily     = familyUser
	defaultPageSize   = 10
	maxPageSize       = 200
	familyAudit       = "audit"
	familyGroup       = "group"
	familyGroupMember = "group_member"
	familyRoleAssign  = "role_assignment"
	familyUser        = "user"
)

// Source reads Google Workspace Directory and Admin audit records.
type Source struct {
	spec   *cerebrov1.SourceSpec
	client *http.Client
}

type settings struct {
	family      string
	domain      string
	customerID  string
	token       string
	baseURL     string
	groupKey    string
	application string
	perPage     int
}

type userRecord struct {
	ID               string     `json:"id"`
	PrimaryEmail     string     `json:"primaryEmail"`
	Name             nameRecord `json:"name"`
	IsAdmin          bool       `json:"isAdmin"`
	IsDelegatedAdmin bool       `json:"isDelegatedAdmin"`
	IsEnrolledIn2SV  bool       `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2SV  bool       `json:"isEnforcedIn2Sv"`
	Suspended        bool       `json:"suspended"`
	Archived         bool       `json:"archived"`
	CreationTime     string     `json:"creationTime"`
	LastLoginTime    string     `json:"lastLoginTime"`
	OrgUnitPath      string     `json:"orgUnitPath"`
	raw              json.RawMessage
}

type nameRecord struct {
	FullName string `json:"fullName"`
}

type groupRecord struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	AdminCreated       bool   `json:"adminCreated"`
	DirectMembersCount string `json:"directMembersCount"`
	raw                json.RawMessage
}

type memberRecord struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Type   string `json:"type"`
	Role   string `json:"role"`
	Status string `json:"status"`
	raw    json.RawMessage
}

type roleAssignmentRecord struct {
	RoleAssignmentID string `json:"roleAssignmentId"`
	RoleID           string `json:"roleId"`
	AssignedTo       string `json:"assignedTo"`
	AssigneeType     string `json:"assigneeType"`
	ScopeType        string `json:"scopeType"`
	OrgUnitID        string `json:"orgUnitId"`
	raw              json.RawMessage
}

type auditRecord struct {
	ID     auditID      `json:"id"`
	Actor  auditActor   `json:"actor"`
	Events []auditEvent `json:"events"`
	raw    json.RawMessage
}

type auditID struct {
	Time            string `json:"time"`
	UniqueQualifier string `json:"uniqueQualifier"`
	ApplicationName string `json:"applicationName"`
	CustomerID      string `json:"customerId"`
}

type auditActor struct {
	Email     string `json:"email"`
	ProfileID string `json:"profileId"`
}

type auditEvent struct {
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	Parameters []auditParameter `json:"parameters"`
}

type auditParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type pageResponse struct {
	Users         []json.RawMessage `json:"users"`
	Groups        []json.RawMessage `json:"groups"`
	Members       []json.RawMessage `json:"members"`
	Items         []json.RawMessage `json:"items"`
	NextPageToken string            `json:"nextPageToken"`
}

// New constructs the live Google Workspace source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{spec: spec, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	settings, err := parseSettings(cfg)
	if err != nil {
		return err
	}
	_, _, err = s.readRawPage(ctx, settings, "", 1)
	return err
}

// Discover returns tenant-scoped URNs for the selected family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return nil, err
	}
	rawRecords, _, err := s.readRawPage(ctx, settings, "", settings.perPage)
	if err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, 0, len(rawRecords))
	for _, raw := range rawRecords {
		urn, err := discoverURN(settings, raw)
		if err != nil {
			return nil, err
		}
		if urn != "" {
			urns = append(urns, urn)
		}
	}
	return urns, nil
}

// Read returns one page of normalized Google Workspace events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	pageToken := strings.TrimSpace(cursor.GetOpaque())
	rawRecords, next, err := s.readRawPage(ctx, settings, pageToken, settings.perPage)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if len(rawRecords) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(rawRecords))
	for _, raw := range rawRecords {
		event, err := sourceEvent(settings, raw)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointCursor(next, events[len(events)-1].GetId()),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
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

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:      configValue(cfg, "family"),
		domain:      configValue(cfg, "domain"),
		customerID:  configValue(cfg, "customer_id"),
		token:       configValue(cfg, "token"),
		baseURL:     configValue(cfg, "base_url"),
		groupKey:    configValue(cfg, "group_key"),
		application: configValue(cfg, "application"),
		perPage:     defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser:
	default:
		return settings, fmt.Errorf("google_workspace family must be one of audit, group, group_member, role_assignment, or user")
	}
	if settings.domain == "" {
		return settings, fmt.Errorf("google_workspace domain is required")
	}
	if settings.customerID == "" {
		settings.customerID = defaultCustomerID
	}
	if settings.token == "" {
		return settings, fmt.Errorf("google_workspace token is required")
	}
	if settings.baseURL == "" {
		settings.baseURL = defaultBaseURL
	} else {
		parsed, err := url.Parse(strings.TrimSpace(settings.baseURL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return settings, fmt.Errorf("google_workspace base_url must include scheme and host")
		}
		settings.baseURL = strings.TrimRight(parsed.String(), "/")
	}
	if settings.family == familyGroupMember && settings.groupKey == "" {
		return settings, fmt.Errorf("google_workspace group_key is required when family=%q", familyGroupMember)
	}
	if settings.application == "" {
		settings.application = "admin"
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse google_workspace per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("google_workspace per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	return settings, nil
}

func (s *Source) readRawPage(ctx context.Context, settings settings, pageToken string, limit int) ([]json.RawMessage, string, error) {
	query := url.Values{}
	query.Set("maxResults", strconv.Itoa(limit))
	addQuery(query, "pageToken", pageToken)
	var path string
	var field string
	switch settings.family {
	case familyUser:
		path = "/admin/directory/v1/users"
		query.Set("customer", settings.customerID)
		field = "users"
	case familyGroup:
		path = "/admin/directory/v1/groups"
		query.Set("customer", settings.customerID)
		field = "groups"
	case familyGroupMember:
		path = "/admin/directory/v1/groups/" + url.PathEscape(settings.groupKey) + "/members"
		field = "members"
	case familyRoleAssign:
		path = "/admin/directory/v1/customer/" + url.PathEscape(settings.customerID) + "/roleassignments"
		field = "items"
	case familyAudit:
		path = "/admin/reports/v1/activity/users/all/applications/" + url.PathEscape(settings.application)
		query.Set("customerId", settings.customerID)
		field = "items"
	}
	var response pageResponse
	if err := s.getJSON(ctx, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	return response.records(field), response.NextPageToken, nil
}

func (r pageResponse) records(field string) []json.RawMessage {
	switch field {
	case "users":
		return r.Users
	case "groups":
		return r.Groups
	case "members":
		return r.Members
	default:
		return r.Items
	}
}

func (s *Source) getJSON(ctx context.Context, settings settings, path string, query url.Values, target any) error {
	endpoint := settings.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+settings.token)
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", path, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("google_workspace API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

func sourceEvent(settings settings, raw json.RawMessage) (*primitives.Event, error) {
	switch settings.family {
	case familyUser:
		var record userRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode google_workspace user: %w", err)
		}
		record.raw = append(json.RawMessage(nil), raw...)
		return userEvent(settings, record)
	case familyGroup:
		var record groupRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode google_workspace group: %w", err)
		}
		record.raw = append(json.RawMessage(nil), raw...)
		return groupEvent(settings, record)
	case familyGroupMember:
		var record memberRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode google_workspace group member: %w", err)
		}
		record.raw = append(json.RawMessage(nil), raw...)
		return groupMemberEvent(settings, record)
	case familyRoleAssign:
		var record roleAssignmentRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode google_workspace role assignment: %w", err)
		}
		record.raw = append(json.RawMessage(nil), raw...)
		return roleAssignmentEvent(settings, record)
	case familyAudit:
		var record auditRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode google_workspace audit: %w", err)
		}
		record.raw = append(json.RawMessage(nil), raw...)
		return auditSourceEvent(settings, record)
	default:
		return nil, fmt.Errorf("unsupported google_workspace family %q", settings.family)
	}
}

func userEvent(settings settings, record userRecord) (*primitives.Event, error) {
	occurredAt := firstParsedTime(record.LastLoginTime, record.CreationTime)
	payload, err := payloadWithRaw(record.raw, map[string]any{"domain": settings.domain})
	if err != nil {
		return nil, err
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("google-workspace-user-%s", firstNonEmpty(record.ID, record.PrimaryEmail)),
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.user",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "google_workspace/user/v1",
		Payload:    payload,
		Attributes: userAttributes(settings, record),
	}, nil
}

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	payload, err := payloadWithRaw(record.raw, map[string]any{"domain": settings.domain})
	if err != nil {
		return nil, err
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("google-workspace-group-%s", firstNonEmpty(record.ID, record.Email)),
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.group",
		OccurredAt: timestamppb.New(time.Now().UTC()),
		SchemaRef:  "google_workspace/group/v1",
		Payload:    payload,
		Attributes: groupAttributes(settings, record),
	}, nil
}

func groupMemberEvent(settings settings, record memberRecord) (*primitives.Event, error) {
	payload, err := payloadWithRaw(record.raw, map[string]any{"domain": settings.domain, "group_key": settings.groupKey})
	if err != nil {
		return nil, err
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("google-workspace-group-member-%s-%s", settings.groupKey, firstNonEmpty(record.ID, record.Email)),
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.group_member",
		OccurredAt: timestamppb.New(time.Now().UTC()),
		SchemaRef:  "google_workspace/group_member/v1",
		Payload:    payload,
		Attributes: groupMemberAttributes(settings, record),
	}, nil
}

func roleAssignmentEvent(settings settings, record roleAssignmentRecord) (*primitives.Event, error) {
	payload, err := payloadWithRaw(record.raw, map[string]any{"domain": settings.domain})
	if err != nil {
		return nil, err
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("google-workspace-role-assignment-%s", record.RoleAssignmentID),
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.role_assignment",
		OccurredAt: timestamppb.New(time.Now().UTC()),
		SchemaRef:  "google_workspace/role_assignment/v1",
		Payload:    payload,
		Attributes: roleAssignmentAttributes(settings, record),
	}, nil
}

func auditSourceEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	occurredAt := firstParsedTime(record.ID.Time)
	eventName := ""
	eventType := ""
	if len(record.Events) > 0 {
		eventName = record.Events[0].Name
		eventType = record.Events[0].Type
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"domain": settings.domain})
	if err != nil {
		return nil, err
	}
	id := firstNonEmpty(record.ID.UniqueQualifier, eventName, strconv.FormatInt(occurredAt.UnixMilli(), 10))
	return &primitives.Event{
		Id:         "google-workspace-audit-" + id,
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.audit",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "google_workspace/audit/v1",
		Payload:    payload,
		Attributes: auditAttributes(settings, record, eventName, eventType),
	}, nil
}

func userAttributes(settings settings, record userRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyUser,
		"user_id":            record.ID,
		"primary_email":      record.PrimaryEmail,
		"email":              record.PrimaryEmail,
		"login":              record.PrimaryEmail,
		"display_name":       record.Name.FullName,
		"created_at":         record.CreationTime,
		"last_login_at":      record.LastLoginTime,
		"is_admin":           boolString(record.IsAdmin),
		"is_delegated_admin": boolString(record.IsDelegatedAdmin),
		"mfa_enrolled":       boolString(record.IsEnrolledIn2SV),
		"mfa_enforced":       boolString(record.IsEnforcedIn2SV),
		"suspended":          boolString(record.Suspended),
		"archived":           boolString(record.Archived),
		"org_unit_path":      record.OrgUnitPath,
	})
}

func groupAttributes(settings settings, record groupRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":               settings.domain,
		"family":               familyGroup,
		"group_id":             record.ID,
		"group_email":          record.Email,
		"email":                record.Email,
		"group_name":           record.Name,
		"name":                 record.Name,
		"description":          record.Description,
		"admin_created":        boolString(record.AdminCreated),
		"direct_members_count": record.DirectMembersCount,
	})
}

func groupMemberAttributes(settings settings, record memberRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":         settings.domain,
		"family":         familyGroupMember,
		"group_id":       settings.groupKey,
		"group_email":    settings.groupKey,
		"member_id":      record.ID,
		"member_email":   record.Email,
		"member_user_id": record.ID,
		"email":          record.Email,
		"member_type":    strings.ToLower(record.Type),
		"role":           record.Role,
		"member_status":  record.Status,
		"user_id":        record.ID,
	})
}

func roleAssignmentAttributes(settings settings, record roleAssignmentRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyRoleAssign,
		"role_assignment_id": record.RoleAssignmentID,
		"role_id":            record.RoleID,
		"subject_id":         record.AssignedTo,
		"assigned_to":        record.AssignedTo,
		"subject_type":       strings.ToLower(record.AssigneeType),
		"principal_type":     strings.ToLower(record.AssigneeType),
		"scope_type":         record.ScopeType,
		"org_unit_id":        record.OrgUnitID,
		"event_type":         "admin.role.assignment",
		"action":             "admin.role.assignment",
	})
}

func auditAttributes(settings settings, record auditRecord, eventName string, eventType string) map[string]string {
	parameters := auditParameters(record)
	resourceID := firstNonEmpty(parameters["USER_EMAIL"], parameters["GROUP_EMAIL"], parameters["APP_NAME"], parameters["CLIENT_ID"], parameters["ROLE_NAME"], eventName)
	resourceType := firstNonEmpty(parameters["RESOURCE_TYPE"], eventType, "security_setting")
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyAudit,
		"event_type":         eventName,
		"event_name":         eventName,
		"action":             eventName,
		"resource_id":        resourceID,
		"resource_type":      normalizeResourceType(resourceType),
		"resource_name":      resourceID,
		"actor_email":        record.Actor.Email,
		"actor_id":           record.Actor.ProfileID,
		"actor_alternate_id": record.Actor.Email,
		"application":        record.ID.ApplicationName,
		"customer_id":        record.ID.CustomerID,
	})
}

func auditParameters(record auditRecord) map[string]string {
	values := map[string]string{}
	if len(record.Events) == 0 {
		return values
	}
	for _, parameter := range record.Events[0].Parameters {
		values[strings.ToUpper(strings.TrimSpace(parameter.Name))] = strings.TrimSpace(parameter.Value)
	}
	return values
}

func discoverURN(settings settings, raw json.RawMessage) (sourcecdk.URN, error) {
	event, err := sourceEvent(settings, raw)
	if err != nil {
		return "", err
	}
	kind := strings.TrimPrefix(strings.ReplaceAll(event.Kind, ".", "_"), "google_workspace_")
	id := firstNonEmpty(event.Attributes["user_id"], event.Attributes["group_id"], event.Attributes["role_assignment_id"], event.Attributes["event_type"])
	return sourcecdk.ParseURN("urn:cerebro:" + settings.domain + ":google_workspace_" + kind + ":" + id)
}

func payloadWithRaw(raw json.RawMessage, extra map[string]any) ([]byte, error) {
	payload := map[string]any{}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, err
		}
	}
	for key, value := range extra {
		payload[key] = value
	}
	return json.Marshal(payload)
}

func firstParsedTime(values ...string) time.Time {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || trimmed == "1970-01-01T00:00:00.000Z" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func addQuery(values url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		values.Set(key, strings.TrimSpace(value))
	}
}

func checkpointCursor(next string, fallback string) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(fallback)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
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

func normalizeResourceType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return normalized
}
