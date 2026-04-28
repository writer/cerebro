package gcp

import (
	"bytes"
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
	defaultFamily     = familyAudit
	defaultPageSize   = 10
	maxPageSize       = 200
	familyAudit       = "audit"
	familyGroup       = "group"
	familyGroupMember = "group_membership"
	familyRoleAssign  = "iam_role_assignment"
	familyServiceAcct = "service_account"
)

// Source reads GCP IAM, Cloud Identity, and Cloud Audit surfaces.
type Source struct {
	spec     *cerebrov1.SourceSpec
	client   *http.Client
	families *sourcecdk.FamilyEngine[settings]
}

type settings struct {
	family     string
	projectID  string
	customerID string
	groupKey   string
	token      string
	baseURL    string
	filter     string
	perPage    int
}

type pageResponse struct {
	Accounts      []json.RawMessage `json:"accounts"`
	Groups        []json.RawMessage `json:"groups"`
	Memberships   []json.RawMessage `json:"memberships"`
	Entries       []json.RawMessage `json:"entries"`
	NextPageToken string            `json:"nextPageToken"`
}

type serviceAccountRecord struct {
	Name           string `json:"name"`
	ProjectID      string `json:"projectId"`
	UniqueID       string `json:"uniqueId"`
	Email          string `json:"email"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description"`
	Disabled       bool   `json:"disabled"`
	OAuth2ClientID string `json:"oauth2ClientId"`
	raw            json.RawMessage
}

type groupRecord struct {
	Name        string    `json:"name"`
	GroupKey    entityKey `json:"groupKey"`
	DisplayName string    `json:"displayName"`
	Description string    `json:"description"`
	raw         json.RawMessage
}

type lookupGroupResponse struct {
	Name     string    `json:"name"`
	GroupKey entityKey `json:"groupKey"`
}

type membershipRecord struct {
	Name               string           `json:"name"`
	PreferredMemberKey entityKey        `json:"preferredMemberKey"`
	Roles              []membershipRole `json:"roles"`
	Type               string           `json:"type"`
	raw                json.RawMessage
}

type membershipRole struct {
	Name string `json:"name"`
}

type entityKey struct {
	ID string `json:"id"`
}

type policyResponse struct {
	Bindings []policyBinding `json:"bindings"`
}

type policyBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type roleAssignmentRecord struct {
	Role   string
	Member string
	raw    json.RawMessage
}

type auditRecord struct {
	InsertID     string        `json:"insertId"`
	Timestamp    string        `json:"timestamp"`
	ProtoPayload auditProto    `json:"protoPayload"`
	Resource     auditResource `json:"resource"`
	raw          json.RawMessage
}

type auditProto struct {
	MethodName         string                  `json:"methodName"`
	ServiceName        string                  `json:"serviceName"`
	ResourceName       string                  `json:"resourceName"`
	AuthenticationInfo auditAuthenticationInfo `json:"authenticationInfo"`
}

type auditAuthenticationInfo struct {
	PrincipalEmail   string `json:"principalEmail"`
	PrincipalSubject string `json:"principalSubject"`
}

type auditResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type gcpFamilyOptions[T any] struct {
	Name     string
	Label    string
	List     func(context.Context, *Source, settings, string, int) ([]T, string, error)
	Event    func(settings, T) (*primitives.Event, error)
	URN      func(settings, T) (string, error)
	Discover func(context.Context, *Source, settings) ([]sourcecdk.URN, error)
}

// New constructs the live GCP source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, client: &http.Client{Timeout: 30 * time.Second}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
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

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns tenant-scoped GCP URNs.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized GCP events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family },
		gcpFamily(s, gcpFamilyOptions[auditRecord]{
			Name:  familyAudit,
			Label: "gcp audit logs",
			List:  listAuditRecords,
			Event: auditEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := gcpCheck(ctx, source, settings, listAuditRecords, "gcp audit logs"); err != nil {
					return nil, err
				}
				return parseGCPURNs(fmt.Sprintf("urn:cerebro:%s:gcp_project:%s", settings.projectID, settings.projectID))
			},
		}),
		gcpFamily(s, gcpFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "gcp cloud identity groups",
			List:  listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group:%s", tenantID(settings), firstNonEmpty(group.GroupKey.ID, group.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[membershipRecord]{
			Name:  familyGroupMember,
			Label: "gcp cloud identity group memberships",
			List:  listGroupMemberships,
			Event: groupMembershipEvent,
			URN: func(settings settings, member membershipRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group_membership:%s:%s", tenantID(settings), settings.groupKey, firstNonEmpty(member.PreferredMemberKey.ID, member.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[roleAssignmentRecord]{
			Name:  familyRoleAssign,
			Label: "gcp iam role assignments",
			List:  listRoleAssignments,
			Event: roleAssignmentEvent,
			URN: func(settings settings, assignment roleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_iam_role_assignment:%s:%s", tenantID(settings), sanitizeURNPart(assignment.Member), sanitizeURNPart(assignment.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountRecord]{
			Name:  familyServiceAcct,
			Label: "gcp service accounts",
			List:  listServiceAccounts,
			Event: serviceAccountEvent,
			URN: func(settings settings, account serviceAccountRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account:%s", tenantID(settings), firstNonEmpty(account.UniqueID, account.Email)), nil
			},
		}),
	)
}

func gcpFamily[T any](source *Source, options gcpFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			return gcpCheck(ctx, source, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, source, settings)
			}
			records, _, err := options.List(ctx, source, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			return gcpURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return gcpPullFromRecords(records, next, build)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:     configValue(cfg, "family"),
		projectID:  configValue(cfg, "project_id"),
		customerID: configValue(cfg, "customer_id"),
		groupKey:   configValue(cfg, "group_key"),
		token:      configValue(cfg, "token"),
		baseURL:    strings.TrimRight(configValue(cfg, "base_url"), "/"),
		filter:     configValue(cfg, "filter"),
		perPage:    defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse gcp per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("gcp per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	if settings.token == "" {
		return settings, fmt.Errorf("gcp token is required")
	}
	switch settings.family {
	case familyAudit, familyRoleAssign, familyServiceAcct:
		if settings.projectID == "" {
			return settings, fmt.Errorf("gcp project_id is required when family=%q", settings.family)
		}
	case familyGroup:
		if settings.customerID == "" {
			return settings, fmt.Errorf("gcp customer_id is required when family=%q", familyGroup)
		}
	case familyGroupMember:
		if settings.groupKey == "" {
			return settings, fmt.Errorf("gcp group_key is required when family=%q", familyGroupMember)
		}
	default:
		return settings, fmt.Errorf("gcp family must be one of audit, group, group_membership, iam_role_assignment, or service_account")
	}
	return settings, nil
}

func listServiceAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, "pageToken", pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, "/v1/projects/"+url.PathEscape(settings.projectID)+"/serviceAccounts", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, _, err := decodeRecords(response.Accounts, "gcp service account", func(record *serviceAccountRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "parent": {"customers/" + settings.customerID}}
	addQuery(query, "pageToken", pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, _, err := decodeRecords(response.Groups, "gcp group", func(record *groupRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]membershipRecord, string, error) {
	groupName, err := resolveGroupName(ctx, source, settings)
	if err != nil {
		return nil, "", err
	}
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, "pageToken", pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/"+groupName+"/memberships", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, _, err := decodeRecords(response.Memberships, "gcp group membership", func(record *membershipRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func resolveGroupName(ctx context.Context, source *Source, settings settings) (string, error) {
	if strings.HasPrefix(settings.groupKey, "groups/") {
		return settings.groupKey, nil
	}
	query := url.Values{"groupKey.id": {settings.groupKey}}
	var response lookupGroupResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups:lookup", query, nil, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Name) == "" {
		return "", fmt.Errorf("gcp group lookup returned empty name for %q", settings.groupKey)
	}
	return response.Name, nil
}

func listRoleAssignments(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]roleAssignmentRecord, string, error) {
	var response policyResponse
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodPost, "/v1/projects/"+url.PathEscape(settings.projectID)+":getIamPolicy", nil, map[string]any{}, &response); err != nil {
		return nil, "", err
	}
	records := make([]roleAssignmentRecord, 0)
	for _, binding := range response.Bindings {
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		for _, member := range binding.Members {
			records = append(records, roleAssignmentRecord{Role: binding.Role, Member: member, raw: raw})
		}
	}
	return records, "", nil
}

func listAuditRecords(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]auditRecord, string, error) {
	body := map[string]any{"resourceNames": []string{"projects/" + settings.projectID}, "pageSize": limit}
	if settings.filter != "" {
		body["filter"] = settings.filter
	}
	if pageToken != "" {
		body["pageToken"] = pageToken
	}
	var response pageResponse
	if err := getJSON(ctx, source, settings, loggingBaseURL, http.MethodPost, "/v2/entries:list", nil, body, &response); err != nil {
		return nil, "", err
	}
	records, _, err := decodeRecords(response.Entries, "gcp audit log", func(record *auditRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func serviceAccountEvent(settings settings, record serviceAccountRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":         tenantID(settings),
		"email":          record.Email,
		"family":         familyServiceAcct,
		"mfa_enrolled":   "false",
		"principal_type": "service_account",
		"status":         disabledStatus(record.Disabled),
		"unique_id":      record.UniqueID,
		"user_id":        firstNonEmpty(record.Email, record.UniqueID, record.Name),
		"display_name":   firstNonEmpty(record.DisplayName, record.Email),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-service-account-"+firstNonEmpty(record.UniqueID, record.Email), "gcp.service_account", "gcp/service_account/v1", payload, attributes, time.Now().UTC())
}

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":      tenantID(settings),
		"family":      familyGroup,
		"group_email": emailLike(record.GroupKey.ID),
		"group_id":    firstNonEmpty(record.GroupKey.ID, record.Name),
		"group_name":  firstNonEmpty(record.DisplayName, record.GroupKey.ID),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"customer_id": settings.customerID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-group-"+firstNonEmpty(record.GroupKey.ID, record.Name), "gcp.group", "gcp/group/v1", payload, attributes, time.Now().UTC())
}

func groupMembershipEvent(settings settings, record membershipRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.PreferredMemberKey.ID)
	attributes := map[string]string{
		"domain":       tenantID(settings),
		"family":       familyGroupMember,
		"group_email":  emailLike(settings.groupKey),
		"group_id":     settings.groupKey,
		"member_email": memberEmail,
		"member_id":    memberID,
		"member_type":  memberType,
		"role":         membershipRoleName(record.Roles),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"group_key": settings.groupKey})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("gcp-group-membership-%s-%s", settings.groupKey, firstNonEmpty(memberID, record.Name))
	return sourceEvent(settings, id, "gcp.group_membership", "gcp/group_membership/v1", payload, attributes, time.Now().UTC())
}

func roleAssignmentEvent(settings settings, record roleAssignmentRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	attributes := map[string]string{
		"domain":         tenantID(settings),
		"family":         familyRoleAssign,
		"is_admin":       boolString(isAdminRole(record.Role)),
		"principal_type": memberType,
		"role_id":        record.Role,
		"role_name":      record.Role,
		"role_type":      "gcp_iam_role",
		"subject_email":  memberEmail,
		"subject_id":     memberID,
		"subject_type":   memberType,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("gcp-iam-role-assignment-%s-%s", sanitizeURNPart(memberID), sanitizeURNPart(record.Role))
	return sourceEvent(settings, id, "gcp.iam_role_assignment", "gcp/iam_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func auditEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ProtoPayload.ResourceName, record.Resource.Labels["project_id"], settings.projectID)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalEmail, record.ProtoPayload.AuthenticationInfo.PrincipalSubject),
		"actor_email":        emailLike(record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"actor_id":           firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalSubject, record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"domain":             tenantID(settings),
		"event_name":         record.ProtoPayload.MethodName,
		"event_type":         record.ProtoPayload.MethodName,
		"family":             familyAudit,
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_type":      firstNonEmpty(record.Resource.Type, record.ProtoPayload.ServiceName, "resource"),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.Timestamp); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "gcp-audit-"+firstNonEmpty(record.InsertID, record.ProtoPayload.MethodName), "gcp.audit", "gcp/audit/v1", payload, attributes, occurredAt)
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: tenantID(settings), SourceId: "gcp", Kind: kind, OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: schemaRef, Payload: payload, Attributes: attributes}, nil
}

func getJSON(ctx context.Context, source *Source, settings settings, defaultBaseURL func() string, method string, requestPath string, query url.Values, body any, target any) error {
	baseURL := settings.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL()
	}
	endpoint := baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	var requestBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s request: %w", requestPath, err)
		}
		requestBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+settings.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.DefaultClient
	if source != nil && source.client != nil {
		client = source.client
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("gcp API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(content)))
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func decodeRecords[T any](rawRecords []json.RawMessage, label string, setRaw func(*T, json.RawMessage)) ([]T, string, error) {
	records := make([]T, 0, len(rawRecords))
	for _, raw := range rawRecords {
		var record T
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, "", fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, raw)
		}
		records = append(records, record)
	}
	return records, "", nil
}

func gcpPullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error)) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: events[len(events)-1].OccurredAt, CursorOpaque: firstNonEmpty(next, events[len(events)-1].GetId())}}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func gcpCheck[T any](ctx context.Context, source *Source, settings settings, list func(context.Context, *Source, settings, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, source, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, tenantID(settings), err)
	}
	return nil
}

func gcpURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return parseGCPURNs(values...)
}

func parseGCPURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func payloadWithRaw(raw json.RawMessage, values map[string]any) ([]byte, error) {
	payload := map[string]any{}
	for key, value := range values {
		payload[key] = value
	}
	if len(raw) != 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, err
		}
		payload["raw"] = decoded
	}
	return json.Marshal(payload)
}

func parseMember(value string) (string, string, string) {
	trimmed := strings.TrimSpace(value)
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		if trimmed == "allUsers" || trimmed == "allAuthenticatedUsers" {
			return "public", trimmed, ""
		}
		return "user", trimmed, emailLike(trimmed)
	}
	memberType := strings.ToLower(strings.ReplaceAll(parts[0], "serviceAccount", "service_account"))
	if memberType == "allusers" || memberType == "allauthenticatedusers" {
		memberType = "public"
	}
	return memberType, parts[1], emailLike(parts[1])
}

func membershipRoleName(roles []membershipRole) string {
	if len(roles) == 0 {
		return "member"
	}
	return firstNonEmpty(roles[0].Name, "member")
}

func isAdminRole(value string) bool {
	role := strings.ToLower(value)
	return strings.Contains(role, "owner") || strings.Contains(role, "editor") || strings.Contains(role, "admin")
}

func disabledStatus(disabled bool) string {
	if disabled {
		return "DISABLED"
	}
	return "ACTIVE"
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func tenantID(settings settings) string {
	return firstNonEmpty(settings.projectID, settings.customerID, settings.groupKey)
}

func serviceBaseURL() string         { return "https://iam.googleapis.com" }
func identityBaseURL() string        { return "https://cloudidentity.googleapis.com" }
func loggingBaseURL() string         { return "https://logging.googleapis.com" }
func resourceManagerBaseURL() string { return "https://cloudresourcemanager.googleapis.com" }

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}

func sanitizeURNPart(value string) string {
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return strings.Trim(value, "_")
}
