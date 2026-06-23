package googleworkspace

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
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
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
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
	SubjectEmail     string
	SubjectName      string
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
	source := &Source{spec: spec, lookupIPAddrs: net.DefaultResolver.LookupIPAddr}
	source.client = source.safeClient()
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns tenant-scoped URNs for the selected family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized Google Workspace events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{}
	for _, family := range []string{familyAudit, familyGroup, familyGroupMember, familyRoleAssign, familyUser} {
		familyName := family
		families = append(families, sourcecdk.Family[settings]{
			Name: familyName, IncrementalWatermark: true,
			Check: func(ctx context.Context, settings settings) error {
				_, _, err := s.readRawPage(ctx, settings, "", 1)
				return err
			},
			Discover: s.discoverFamily,
			Read:     s.readFamily,
		})
	}
	return sourcecdk.NewFamilyEngineWithSourceID("google_workspace", parseSettings, func(settings settings) string {
		return settings.family
	}, families...)
}

func (s *Source) discoverFamily(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
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

func (s *Source) readFamily(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	rawRecords, next, err := s.readRawPage(ctx, settings, sourcecdk.CursorToken(cursor), settings.perPage)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if len(rawRecords) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(rawRecords))
	userCache := map[string]googleWorkspaceUserLookup{}
	for _, raw := range rawRecords {
		var event *primitives.Event
		var err error
		if settings.family == familyRoleAssign {
			event, err = s.roleAssignmentEvent(ctx, settings, raw, userCache)
		} else {
			event, err = s.sourceEvent(ctx, settings, raw)
		}
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
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) readRawPage(ctx context.Context, settings settings, pageToken string, limit int) ([]json.RawMessage, string, error) {
	query := url.Values{}
	query.Set("maxResults", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "pageToken", pageToken)
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
	baseURL, _, err := sourcehttp.NormalizeBaseURL("google_workspace", settings.baseURL, s != nil && s.allowLoopbackBaseURL)
	if err != nil {
		return err
	}
	requestPath, err := sourcehttp.NormalizeRequestPath("google_workspace", path)
	if err != nil {
		return err
	}
	endpoint := baseURL + requestPath
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
		client = sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: "google_workspace"})
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := sourcehttp.ReadLimitedBody(resp.Body)
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

func (s *Source) safeClient() *http.Client {
	return sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      "google_workspace",
		Timeout:       30 * time.Second,
		AllowLoopback: s != nil && s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func (s *Source) sourceEvent(ctx context.Context, settings settings, raw json.RawMessage) (*primitives.Event, error) {
	if settings.family != familyRoleAssign {
		return sourceEvent(settings, raw)
	}
	return s.roleAssignmentEvent(ctx, settings, raw, nil)
}

func (s *Source) roleAssignmentEvent(ctx context.Context, settings settings, raw json.RawMessage, userCache map[string]googleWorkspaceUserLookup) (*primitives.Event, error) {
	var record roleAssignmentRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("decode google_workspace role assignment: %w", err)
	}
	record.raw = append(json.RawMessage(nil), raw...)
	if strings.EqualFold(record.AssigneeType, "user") {
		if user, ok := s.lookupUserCached(ctx, settings, record.AssignedTo, userCache); ok {
			record.SubjectEmail = user.PrimaryEmail
			record.SubjectName = user.Name.FullName
		}
	}
	return roleAssignmentEvent(settings, record)
}

type googleWorkspaceUserLookup struct {
	record userRecord
	ok     bool
}

func (s *Source) lookupUserCached(ctx context.Context, settings settings, userKey string, cache map[string]googleWorkspaceUserLookup) (userRecord, bool) {
	userKey = strings.TrimSpace(userKey)
	if userKey == "" {
		return userRecord{}, false
	}
	if cache == nil {
		return s.lookupUser(ctx, settings, userKey)
	}
	if cached, ok := cache[userKey]; ok {
		return cached.record, cached.ok
	}
	user, ok := s.lookupUser(ctx, settings, userKey)
	cache[userKey] = googleWorkspaceUserLookup{record: user, ok: ok}
	return user, ok
}

func (s *Source) lookupUser(ctx context.Context, settings settings, userKey string) (userRecord, bool) {
	userKey = strings.TrimSpace(userKey)
	if userKey == "" {
		return userRecord{}, false
	}
	var user userRecord
	if err := s.getJSON(ctx, settings, "/admin/directory/v1/users/"+url.PathEscape(userKey), nil, &user); err != nil {
		return userRecord{}, false
	}
	return user, true
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
	payload, err := sourcecdk.NewPayloadOverlay().Set("domain", settings.domain).MergeRawJSON(record.raw)
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
	payload, err := sourcecdk.NewPayloadOverlay().Set("domain", settings.domain).MergeRawJSON(record.raw)
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
	payload, err := sourcecdk.NewPayloadOverlay().Set("domain", settings.domain).Set("group_key", settings.groupKey).MergeRawJSON(record.raw)
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
	payload, err := sourcecdk.NewPayloadOverlay().Set("domain", settings.domain).MergeRawJSON(record.raw)
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
