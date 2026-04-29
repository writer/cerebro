package okta

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultPageSize   = 10
	maxPageSize       = 200
	oktaHTTPTimeout   = 30 * time.Second
	maxOktaBodyBytes  = 4 << 20
	defaultFamily     = familyAudit
	defaultAuditOrder = "DESCENDING"
	defaultUserOrder  = "asc"
	familyAudit       = "audit"
	familyApplication = "application"
	familyAppAssign   = "app_assignment"
	familyAdminRole   = "admin_role"
	familyGroup       = "group"
	familyGroupMember = "group_membership"
	familyUser        = "user"
)

// Source is the live Okta source preview used by the builtin registry.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
}

type settings struct {
	family    string
	domain    string
	baseURL   string
	token     string
	filter    string
	q         string
	search    string
	sortBy    string
	sortOrder string
	since     string
	until     string
	groupID   string
	appID     string
	userID    string
	userEmail string
	perPage   int
}

type auditRecord struct {
	UUID           string           `json:"uuid"`
	Published      time.Time        `json:"published"`
	EventType      string           `json:"eventType"`
	DisplayMessage string           `json:"displayMessage"`
	Severity       string           `json:"severity"`
	Actor          map[string]any   `json:"actor"`
	Outcome        map[string]any   `json:"outcome"`
	Client         map[string]any   `json:"client"`
	Transaction    map[string]any   `json:"transaction"`
	Target         []map[string]any `json:"target"`
	raw            json.RawMessage
}

type userRecord struct {
	ID              string         `json:"id"`
	Status          string         `json:"status"`
	Created         *time.Time     `json:"created"`
	Activated       *time.Time     `json:"activated"`
	LastLogin       *time.Time     `json:"lastLogin"`
	LastUpdated     *time.Time     `json:"lastUpdated"`
	PasswordChanged *time.Time     `json:"passwordChanged"`
	StatusChanged   *time.Time     `json:"statusChanged"`
	RealmID         string         `json:"realmId"`
	Type            map[string]any `json:"type"`
	Profile         map[string]any `json:"profile"`
	raw             json.RawMessage
}

type groupRecord struct {
	ID                    string         `json:"id"`
	Created               *time.Time     `json:"created"`
	LastUpdated           *time.Time     `json:"lastUpdated"`
	LastMembershipUpdated *time.Time     `json:"lastMembershipUpdated"`
	Type                  string         `json:"type"`
	Profile               map[string]any `json:"profile"`
	raw                   json.RawMessage
}

type appRecord struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Label       string     `json:"label"`
	Status      string     `json:"status"`
	SignOnMode  string     `json:"signOnMode"`
	Created     *time.Time `json:"created"`
	LastUpdated *time.Time `json:"lastUpdated"`
	raw         json.RawMessage
}

type appAssignmentRecord struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Scope       string         `json:"scope"`
	Created     *time.Time     `json:"created"`
	LastUpdated *time.Time     `json:"lastUpdated"`
	Credentials map[string]any `json:"credentials"`
	Profile     map[string]any `json:"profile"`
	raw         json.RawMessage
}

type adminRoleRecord struct {
	ID             string     `json:"id"`
	Label          string     `json:"label"`
	Type           string     `json:"type"`
	AssignmentType string     `json:"assignmentType"`
	Status         string     `json:"status"`
	Created        *time.Time `json:"created"`
	LastUpdated    *time.Time `json:"lastUpdated"`
	raw            json.RawMessage
}

type auditPayload struct {
	UUID           string            `json:"uuid"`
	Domain         string            `json:"domain"`
	Published      time.Time         `json:"published"`
	EventType      string            `json:"event_type"`
	DisplayMessage string            `json:"display_message,omitempty"`
	Severity       string            `json:"severity,omitempty"`
	Actor          identityPayload   `json:"actor,omitempty"`
	Outcome        outcomePayload    `json:"outcome,omitempty"`
	Client         clientPayload     `json:"client,omitempty"`
	Transaction    eventPayload      `json:"transaction,omitempty"`
	Targets        []identityPayload `json:"targets,omitempty"`
	ResourceID     string            `json:"resource_id,omitempty"`
	ResourceType   string            `json:"resource_type,omitempty"`
	Raw            map[string]any    `json:"raw,omitempty"`
}

type userPayload struct {
	ID         string                 `json:"id"`
	Domain     string                 `json:"domain"`
	Status     string                 `json:"status,omitempty"`
	RealmID    string                 `json:"realm_id,omitempty"`
	Timestamps *userTimestampsPayload `json:"timestamps,omitempty"`
	Type       *userTypePayload       `json:"type,omitempty"`
	Profile    *userProfilePayload    `json:"profile,omitempty"`
	Employment *userEmploymentPayload `json:"employment,omitempty"`
	Raw        map[string]any         `json:"raw,omitempty"`
}

type userTimestampsPayload struct {
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	ActivatedAt       *time.Time `json:"activated_at,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	LastUpdatedAt     *time.Time `json:"last_updated_at,omitempty"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	StatusChangedAt   *time.Time `json:"status_changed_at,omitempty"`
}

type userTypePayload struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type userProfilePayload struct {
	Login       string `json:"login,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
}

type userEmploymentPayload struct {
	Department     string `json:"department,omitempty"`
	Title          string `json:"title,omitempty"`
	Organization   string `json:"organization,omitempty"`
	Manager        string `json:"manager,omitempty"`
	ManagerID      string `json:"manager_id,omitempty"`
	EmployeeNumber string `json:"employee_number,omitempty"`
	UserType       string `json:"user_type,omitempty"`
}

type identityPayload struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
	AlternateID string `json:"alternate_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type outcomePayload struct {
	Result string `json:"result,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type clientPayload struct {
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Zone      string `json:"zone,omitempty"`
}

type eventPayload struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

type apiError struct {
	ErrorSummary string `json:"errorSummary"`
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string {
	return e.message
}

// New constructs the live Okta source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec: spec,
		client: &http.Client{
			Timeout: oktaHTTPTimeout,
		},
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns static metadata for the Okta source.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured Okta family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns live Okta URNs for the selected family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages through the configured live Okta event family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

type oktaListFunc[T any] func(context.Context, settings, string, int) ([]T, string, error)

type oktaFamilyOptions[T any] struct {
	Name           string
	Label          string
	List           oktaListFunc[T]
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	auditList := s.listAudit
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		oktaFamily(oktaFamilyOptions[auditRecord]{
			Name:  familyAudit,
			Label: "okta audit log",
			List:  auditList,
			Event: auditEvent,
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				if err := oktaCheck(ctx, settings, auditList, "okta audit log"); err != nil {
					return nil, err
				}
				urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:org:%s", settings.domain, settings.domain))
				if err != nil {
					return nil, err
				}
				return []sourcecdk.URN{urn}, nil
			},
			CursorFallback: func(entry auditRecord) string { return entry.UUID },
		}),
		oktaFamily(oktaFamilyOptions[adminRoleRecord]{
			Name:  familyAdminRole,
			Label: "okta admin roles",
			List:  s.listAdminRoles,
			Event: adminRoleEvent,
			URN: func(settings settings, role adminRoleRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:admin_role:%s:%s", settings.domain, settings.userID, firstNonEmpty(role.ID, role.Type, role.Label)), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[appAssignmentRecord]{
			Name:  familyAppAssign,
			Label: "okta app assignments",
			List:  s.listAppAssignments,
			Event: appAssignmentEvent,
			URN: func(settings settings, assignment appAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:app_assignment:%s:%s", settings.domain, settings.appID, firstNonEmpty(assignment.ID, assignmentEmail(assignment))), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[appRecord]{
			Name:  familyApplication,
			Label: "okta applications",
			List:  s.listApplications,
			Event: applicationEvent,
			URN: func(settings settings, app appRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:application:%s", settings.domain, app.ID), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "okta groups",
			List:  s.listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group:%s", settings.domain, group.ID), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[userRecord]{
			Name:  familyGroupMember,
			Label: "okta group memberships",
			List:  s.listGroupMembers,
			Event: groupMembershipEvent,
			URN: func(settings settings, member userRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group_membership:%s:%s", settings.domain, settings.groupID, member.ID), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[userRecord]{
			Name:  familyUser,
			Label: "okta users",
			List:  s.listUsers,
			Event: userEvent,
			URN: func(settings settings, user userRecord) (string, error) {
				urn, err := userURN(settings.domain, user.ID)
				if err != nil {
					return "", err
				}
				return urn.String(), nil
			},
			CursorFallback: func(user userRecord) string { return user.ID },
		}),
	)
}

func oktaFamily[T any](options oktaFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			return oktaCheck(ctx, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, settings)
			}
			records, _, err := options.List(ctx, settings, "", settings.perPage)
			if err != nil {
				return nil, wrapLookupError(oktaLabel(options.Label, settings), err)
			}
			return oktaURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, wrapLookupError(oktaLabel(options.Label, settings), err)
			}
			build := func(record T) (*primitives.Event, error) {
				return options.Event(settings, record)
			}
			return oktaPullFromRecordsWithCursor(records, next, build, options.CursorFallback)
		},
	}
}

func oktaCheck[T any](ctx context.Context, settings settings, list oktaListFunc[T], label string) error {
	_, _, err := list(ctx, settings, "", 1)
	if err != nil {
		return wrapLookupError(oktaLabel(label, settings), err)
	}
	return nil
}

func oktaLabel(label string, settings settings) string {
	return fmt.Sprintf("%s for %s", label, settings.domain)
}

func oktaURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
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

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
}

func parseSettings(cfg sourcecdk.Config, allowLoopbackBaseURL bool) (settings, error) {
	settings := settings{
		family:    configValue(cfg, "family"),
		domain:    configValue(cfg, "domain"),
		baseURL:   configValue(cfg, "base_url"),
		token:     configValue(cfg, "token"),
		filter:    configValue(cfg, "filter"),
		q:         configValue(cfg, "q"),
		search:    configValue(cfg, "search"),
		sortBy:    configValue(cfg, "sort_by"),
		sortOrder: configValue(cfg, "sort_order"),
		since:     configValue(cfg, "since"),
		until:     configValue(cfg, "until"),
		groupID:   configValue(cfg, "group_id"),
		appID:     configValue(cfg, "app_id"),
		userID:    configValue(cfg, "user_id"),
		userEmail: configValue(cfg, "user_email"),
		perPage:   defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAdminRole, familyAppAssign, familyApplication, familyAudit, familyGroup, familyGroupMember, familyUser:
	default:
		return settings, fmt.Errorf("okta family must be one of admin_role, app_assignment, application, audit, group, group_membership, or user")
	}
	if settings.domain == "" {
		return settings, fmt.Errorf("okta domain is required")
	}
	domain, err := normalizeDomain(settings.domain, allowLoopbackBaseURL)
	if err != nil {
		return settings, err
	}
	settings.domain = domain
	if settings.baseURL == "" {
		settings.baseURL, err = normalizeBaseURL("https://"+settings.domain, settings.domain, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
	} else {
		settings.baseURL, err = normalizeBaseURL(settings.baseURL, settings.domain, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
	}
	if settings.token == "" {
		return settings, fmt.Errorf("okta token is required")
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse okta per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("okta per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyAudit:
		if settings.search != "" || settings.sortBy != "" {
			return settings, fmt.Errorf("okta search and sort_by are only supported when family=%q", familyUser)
		}
		settings.sortOrder, err = normalizeAuditSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	case familyAdminRole:
		if settings.userID == "" {
			return settings, fmt.Errorf("okta user_id is required when family=%q", familyAdminRole)
		}
	case familyAppAssign:
		if settings.appID == "" {
			return settings, fmt.Errorf("okta app_id is required when family=%q", familyAppAssign)
		}
	case familyApplication, familyGroup:
		if settings.since != "" || settings.until != "" {
			return settings, fmt.Errorf("okta since and until are only supported when family=%q", familyAudit)
		}
	case familyGroupMember:
		if settings.groupID == "" {
			return settings, fmt.Errorf("okta group_id is required when family=%q", familyGroupMember)
		}
	case familyUser:
		if settings.since != "" || settings.until != "" {
			return settings, fmt.Errorf("okta since and until are only supported when family=%q", familyAudit)
		}
		settings.sortOrder, err = normalizeUserSortOrder(settings.sortOrder)
		if err != nil {
			return settings, err
		}
	}
	return settings, nil
}

func normalizeDomain(raw string, allowLoopback bool) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("okta domain is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse okta domain: %w", err)
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("okta domain must be a valid host")
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if isUnsafeHost(host) && (!allowLoopback || !isLoopbackHost(host)) {
		return "", fmt.Errorf("okta domain must not target loopback, private, or link-local hosts")
	}
	return host, nil
}

func normalizeBaseURL(raw string, domain string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse okta base_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && isLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("okta base_url must use https")
	}
	if host == "" {
		return "", fmt.Errorf("okta base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("okta base_url must not include user info, query, or fragment")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", fmt.Errorf("okta base_url must be an origin URL")
	}
	allowCustomLoopbackPort := allowLoopback && isLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomLoopbackPort {
		return "", fmt.Errorf("okta base_url must not include a custom port")
	}
	allowLoopbackHost := allowLoopback && isLoopbackHost(host)
	if isUnsafeHost(host) && !allowLoopbackHost {
		return "", fmt.Errorf("okta base_url must not target loopback, private, or link-local hosts")
	}
	if host != strings.ToLower(strings.TrimSpace(domain)) && !allowLoopbackHost {
		return "", fmt.Errorf("okta base_url host must match okta domain")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isUnsafeHost(host string) bool {
	value := normalizedIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericIPv4Host(value)
	}
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

func isLoopbackHost(host string) bool {
	value := normalizedIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericIPv4Host(value)
	}
	return ip != nil && ip.IsLoopback()
}

func normalizedIPHost(host string) string {
	value := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	value = strings.Trim(value, "[]")
	if address, _, ok := strings.Cut(value, "%"); ok {
		value = address
	}
	return value
}

func parseNumericIPv4Host(host string) net.IP {
	if strings.Contains(host, ":") {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return nil
		}
		values[i] = value
	}
	var ipv4 uint32
	switch len(values) {
	case 1:
		ipv4 = uint32(values[0])
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		ipv4 = uint32(values[0]<<24 | values[1])
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		ipv4 = uint32(values[0]<<24 | values[1]<<16 | values[2])
	case 4:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xff || values[3] > 0xff {
			return nil
		}
		ipv4 = uint32(values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3])
	}
	return net.IPv4(byte(ipv4>>24), byte(ipv4>>16), byte(ipv4>>8), byte(ipv4))
}

func normalizeAuditSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "desc", "descending":
		return defaultAuditOrder, nil
	case "asc", "ascending":
		return "ASCENDING", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyAudit)
	}
}

func normalizeUserSortOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "asc", "ascending":
		return defaultUserOrder, nil
	case "desc", "descending":
		return "desc", nil
	default:
		return "", fmt.Errorf("okta sort_order must be one of asc, desc, ascending, or descending when family=%q", familyUser)
	}
}

func (s *Source) listAudit(ctx context.Context, settings settings, after string, limit int) ([]auditRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "filter", settings.filter)
	addQuery(query, "q", settings.q)
	addQuery(query, "since", settings.since)
	addQuery(query, "until", settings.until)
	addQuery(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/logs", query, "okta audit event", func(record *auditRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listUsers(ctx context.Context, settings settings, after string, limit int) ([]userRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "filter", settings.filter)
	addQuery(query, "q", settings.q)
	addQuery(query, "search", settings.search)
	addQuery(query, "sortBy", settings.sortBy)
	addQuery(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/users", query, "okta user", func(record *userRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listGroups(ctx context.Context, settings settings, after string, limit int) ([]groupRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "q", settings.q)
	addQuery(query, "search", settings.search)
	addQuery(query, "sortBy", settings.sortBy)
	addQuery(query, "sortOrder", settings.sortOrder)

	return listJSONRecords(ctx, s, settings, "/api/v1/groups", query, "okta group", func(record *groupRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listGroupMembers(ctx context.Context, settings settings, after string, limit int) ([]userRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/groups/"+url.PathEscape(settings.groupID)+"/users", query, "okta group member", func(record *userRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listApplications(ctx context.Context, settings settings, after string, limit int) ([]appRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)
	addQuery(query, "q", settings.q)
	addQuery(query, "filter", settings.filter)

	return listJSONRecords(ctx, s, settings, "/api/v1/apps", query, "okta application", func(record *appRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listAppAssignments(ctx context.Context, settings settings, after string, limit int) ([]appAssignmentRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/apps/"+url.PathEscape(settings.appID)+"/users", query, "okta app assignment", func(record *appAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func (s *Source) listAdminRoles(ctx context.Context, settings settings, after string, limit int) ([]adminRoleRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	addQuery(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/users/"+url.PathEscape(settings.userID)+"/roles", query, "okta admin role", func(record *adminRoleRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func listJSONRecords[T any](ctx context.Context, source *Source, settings settings, requestPath string, query url.Values, label string, setRaw func(*T, json.RawMessage)) ([]T, string, error) {
	var rawRecords []json.RawMessage
	headers, err := source.getJSON(ctx, settings, requestPath, query, &rawRecords)
	if err != nil {
		return nil, "", err
	}
	records := make([]T, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		var record T
		if err := json.Unmarshal(rawRecord, &record); err != nil {
			return nil, "", fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, rawRecord)
		}
		records = append(records, record)
	}
	return records, nextAfter(headers), nil
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) (http.Header, error) {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "SSWS "+settings.token)

	client := s.client
	if client == nil {
		client = &http.Client{Timeout: oktaHTTPTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	headers := resp.Header.Clone()

	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return headers, fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return headers, decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return headers, nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return headers, fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return headers, nil
}

func readLimitedBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxOktaBodyBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxOktaBodyBytes {
		return nil, fmt.Errorf("okta response body exceeds %d bytes", maxOktaBodyBytes)
	}
	return payload, nil
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.ErrorSummary) != "" {
		message = strings.TrimSpace(apiErr.ErrorSummary)
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("okta API returned %d: %s", statusCode, message),
	}
}

func auditEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	occurredAt := record.Published.UTC()
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("okta audit event %q missing published timestamp", record.UUID)
	}
	raw, err := decodeRawPayload(record.raw, "okta audit")
	if err != nil {
		return nil, err
	}
	actor := identityFromMap(record.Actor)
	targets := identitiesFromMaps(record.Target)
	resourceID, resourceType := auditResource(record, actor, targets, settings.domain)
	payload, err := json.Marshal(auditPayload{
		UUID:           record.UUID,
		Domain:         settings.domain,
		Published:      occurredAt,
		EventType:      record.EventType,
		DisplayMessage: record.DisplayMessage,
		Severity:       record.Severity,
		Actor:          actor,
		Outcome: outcomePayload{
			Result: stringMap(record.Outcome, "result"),
			Reason: stringMap(record.Outcome, "reason"),
		},
		Client: clientPayload{
			IPAddress: stringMap(record.Client, "ipAddress"),
			UserAgent: stringMap(nestedMap(record.Client, "userAgent"), "rawUserAgent"),
			Zone:      stringMap(record.Client, "zone"),
		},
		Transaction: eventPayload{
			ID:   stringMap(record.Transaction, "id"),
			Type: stringMap(record.Transaction, "type"),
		},
		Targets:      targets,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Raw:          raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta audit payload: %w", err)
	}
	eventID := strings.TrimSpace(record.UUID)
	if eventID == "" {
		eventID = fmt.Sprintf("%s-%d", strings.ReplaceAll(record.EventType, ".", "-"), occurredAt.UnixMilli())
	}
	return &primitives.Event{
		Id:         "okta-audit-" + eventID,
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/audit/v1",
		Payload:    payload,
		Attributes: auditAttributes(settings, record, actor, resourceID, resourceType),
	}, nil
}

func userEvent(settings settings, record userRecord) (*primitives.Event, error) {
	occurredAt := userOccurredAt(record)
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("okta user %q missing timestamps", record.ID)
	}
	raw, err := decodeRawPayload(record.raw, "okta user")
	if err != nil {
		return nil, err
	}
	profile := record.Profile
	payload, err := json.Marshal(userPayload{
		ID:         record.ID,
		Domain:     settings.domain,
		Status:     record.Status,
		RealmID:    record.RealmID,
		Timestamps: userTimestamps(record),
		Type:       userType(record.Type),
		Profile:    userProfile(profile),
		Employment: userEmployment(profile),
		Raw:        raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta user payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-user-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.user",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/user/v1",
		Payload:    payload,
		Attributes: userAttributes(settings, record),
	}, nil
}

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created, record.LastMembershipUpdated)
	raw, err := decodeRawPayload(record.raw, "okta group")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"id":      record.ID,
		"domain":  settings.domain,
		"type":    record.Type,
		"profile": record.Profile,
		"raw":     raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta group payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-group-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.group",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/group/v1",
		Payload:    payload,
		Attributes: groupAttributes(settings, record),
	}, nil
}

func groupMembershipEvent(settings settings, record userRecord) (*primitives.Event, error) {
	occurredAt := userOccurredAt(record)
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	raw, err := decodeRawPayload(record.raw, "okta group membership")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":   settings.domain,
		"group_id": settings.groupID,
		"user_id":  record.ID,
		"profile":  record.Profile,
		"raw":      raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta group membership payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-group-membership-%s-%s-%d", settings.groupID, record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.group_membership",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/group_membership/v1",
		Payload:    payload,
		Attributes: groupMembershipAttributes(settings, record),
	}, nil
}

func applicationEvent(settings settings, record appRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta application")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"id":           record.ID,
		"domain":       settings.domain,
		"name":         record.Name,
		"label":        record.Label,
		"status":       record.Status,
		"sign_on_mode": record.SignOnMode,
		"raw":          raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta application payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-application-%s-%d", record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.application",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/application/v1",
		Payload:    payload,
		Attributes: applicationAttributes(settings, record),
	}, nil
}

func appAssignmentEvent(settings settings, record appAssignmentRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta app assignment")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":      settings.domain,
		"app_id":      settings.appID,
		"subject_id":  record.ID,
		"status":      record.Status,
		"scope":       record.Scope,
		"credentials": record.Credentials,
		"profile":     record.Profile,
		"raw":         raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta app assignment payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-app-assignment-%s-%s-%d", settings.appID, record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.app_assignment",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/app_assignment/v1",
		Payload:    payload,
		Attributes: appAssignmentAttributes(settings, record),
	}, nil
}

func adminRoleEvent(settings settings, record adminRoleRecord) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.LastUpdated, record.Created)
	raw, err := decodeRawPayload(record.raw, "okta admin role")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":     settings.domain,
		"user_id":    settings.userID,
		"user_email": settings.userEmail,
		"id":         record.ID,
		"label":      record.Label,
		"type":       record.Type,
		"status":     record.Status,
		"assignment": record.AssignmentType,
		"raw":        raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal okta admin role payload: %w", err)
	}
	roleID := firstNonEmpty(record.ID, record.Type, record.Label)
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-admin-role-%s-%s-%d", settings.userID, roleID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.admin_role",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/admin_role/v1",
		Payload:    payload,
		Attributes: adminRoleAttributes(settings, record),
	}, nil
}

func oktaPullFromRecordsWithCursor[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
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
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointCursor(next, fallback, events[len(events)-1].OccurredAt.AsTime()),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func auditAttributes(settings settings, record auditRecord, actor identityPayload, resourceID string, resourceType string) map[string]string {
	attributes := map[string]string{
		"domain":        settings.domain,
		"event_type":    record.EventType,
		"family":        familyAudit,
		"resource_id":   resourceID,
		"resource_type": resourceType,
	}
	addAttribute(attributes, "actor_id", actor.ID)
	addAttribute(attributes, "actor_type", actor.Type)
	addAttribute(attributes, "actor_alternate_id", actor.AlternateID)
	addAttribute(attributes, "actor_display_name", actor.DisplayName)
	addAttribute(attributes, "client_ip", stringMap(record.Client, "ipAddress"))
	addAttribute(attributes, "outcome_reason", stringMap(record.Outcome, "reason"))
	addAttribute(attributes, "outcome_result", stringMap(record.Outcome, "result"))
	addAttribute(attributes, "severity", record.Severity)
	addAttribute(attributes, "transaction_id", stringMap(record.Transaction, "id"))
	return attributes
}

func userAttributes(settings settings, record userRecord) map[string]string {
	attributes := map[string]string{
		"domain":  settings.domain,
		"family":  familyUser,
		"user_id": record.ID,
	}
	addAttribute(attributes, "email", stringMap(record.Profile, "email"))
	addAttribute(attributes, "login", stringMap(record.Profile, "login"))
	addAttribute(attributes, "realm_id", record.RealmID)
	addAttribute(attributes, "status", record.Status)
	addAttribute(attributes, "type_id", stringMap(record.Type, "id"))
	addAttribute(attributes, "type_name", stringMap(record.Type, "name"))
	addAttribute(attributes, "user_type", stringMap(record.Profile, "userType"))
	return attributes
}

func groupAttributes(settings settings, record groupRecord) map[string]string {
	attributes := map[string]string{
		"domain":   settings.domain,
		"family":   familyGroup,
		"group_id": record.ID,
	}
	addAttribute(attributes, "group_name", stringMap(record.Profile, "name"))
	addAttribute(attributes, "name", stringMap(record.Profile, "name"))
	addAttribute(attributes, "description", stringMap(record.Profile, "description"))
	addAttribute(attributes, "group_email", firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login")))
	addAttribute(attributes, "email", firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login")))
	addAttribute(attributes, "type", record.Type)
	return attributes
}

func groupMembershipAttributes(settings settings, record userRecord) map[string]string {
	memberEmail := firstNonEmpty(stringMap(record.Profile, "email"), stringMap(record.Profile, "login"))
	attributes := map[string]string{
		"domain":         settings.domain,
		"family":         familyGroupMember,
		"group_id":       settings.groupID,
		"member_id":      record.ID,
		"member_user_id": record.ID,
		"member_type":    "user",
		"user_id":        record.ID,
	}
	addAttribute(attributes, "member_email", memberEmail)
	addAttribute(attributes, "email", memberEmail)
	addAttribute(attributes, "member_name", firstNonEmpty(stringMap(record.Profile, "displayName"), strings.TrimSpace(strings.Join([]string{stringMap(record.Profile, "firstName"), stringMap(record.Profile, "lastName")}, " "))))
	addAttribute(attributes, "member_status", record.Status)
	if strings.Contains(settings.groupID, "@") {
		addAttribute(attributes, "group_email", settings.groupID)
	}
	return attributes
}

func applicationAttributes(settings settings, record appRecord) map[string]string {
	mode := strings.ToLower(record.Name + " " + record.SignOnMode)
	attributes := map[string]string{
		"domain":   settings.domain,
		"family":   familyApplication,
		"app_id":   record.ID,
		"status":   record.Status,
		"app_name": firstNonEmpty(record.Label, record.Name),
	}
	addAttribute(attributes, "app_label", record.Label)
	addAttribute(attributes, "name", record.Name)
	addAttribute(attributes, "sign_on_mode", record.SignOnMode)
	addAttribute(attributes, "oauth2", boolString(strings.Contains(mode, "oidc") || strings.Contains(mode, "oauth")))
	addAttribute(attributes, "saml", boolString(strings.Contains(mode, "saml")))
	return attributes
}

func appAssignmentAttributes(settings settings, record appAssignmentRecord) map[string]string {
	subjectEmail := assignmentEmail(record)
	attributes := map[string]string{
		"domain":         settings.domain,
		"family":         familyAppAssign,
		"app_id":         settings.appID,
		"subject_id":     record.ID,
		"subject_type":   "user",
		"principal_type": "user",
		"status":         record.Status,
	}
	addAttribute(attributes, "subject_email", subjectEmail)
	addAttribute(attributes, "email", subjectEmail)
	addAttribute(attributes, "subject_name", firstNonEmpty(stringMap(record.Profile, "displayName"), stringMap(record.Profile, "name"), subjectEmail))
	addAttribute(attributes, "scope", record.Scope)
	return attributes
}

func adminRoleAttributes(settings settings, record adminRoleRecord) map[string]string {
	roleID := firstNonEmpty(record.ID, record.Type, record.Label)
	attributes := map[string]string{
		"domain":           settings.domain,
		"family":           familyAdminRole,
		"role_id":          roleID,
		"role_name":        firstNonEmpty(record.Label, record.Type, roleID),
		"role_type":        record.Type,
		"subject_id":       settings.userID,
		"subject_type":     "user",
		"event_type":       "admin.role.assignment",
		"action":           "admin.role.assignment",
		"is_admin":         "true",
		"actor_privileged": "true",
	}
	addAttribute(attributes, "assigned_to", settings.userID)
	addAttribute(attributes, "subject_email", settings.userEmail)
	addAttribute(attributes, "email", settings.userEmail)
	addAttribute(attributes, "status", record.Status)
	addAttribute(attributes, "assignment_type", record.AssignmentType)
	return attributes
}

func userTimestamps(record userRecord) *userTimestampsPayload {
	payload := &userTimestampsPayload{
		CreatedAt:         utcTime(record.Created),
		ActivatedAt:       utcTime(record.Activated),
		LastLoginAt:       utcTime(record.LastLogin),
		LastUpdatedAt:     utcTime(record.LastUpdated),
		PasswordChangedAt: utcTime(record.PasswordChanged),
		StatusChangedAt:   utcTime(record.StatusChanged),
	}
	if payload.CreatedAt == nil &&
		payload.ActivatedAt == nil &&
		payload.LastLoginAt == nil &&
		payload.LastUpdatedAt == nil &&
		payload.PasswordChangedAt == nil &&
		payload.StatusChangedAt == nil {
		return nil
	}
	return payload
}

func userType(values map[string]any) *userTypePayload {
	payload := &userTypePayload{
		ID:   stringMap(values, "id"),
		Name: stringMap(values, "name"),
	}
	if payload.ID == "" && payload.Name == "" {
		return nil
	}
	return payload
}

func userProfile(values map[string]any) *userProfilePayload {
	payload := &userProfilePayload{
		Login:       stringMap(values, "login"),
		Email:       stringMap(values, "email"),
		DisplayName: firstNonEmpty(stringMap(values, "displayName"), strings.TrimSpace(strings.Join([]string{stringMap(values, "firstName"), stringMap(values, "lastName")}, " "))),
		FirstName:   stringMap(values, "firstName"),
		LastName:    stringMap(values, "lastName"),
	}
	if payload.Login == "" &&
		payload.Email == "" &&
		payload.DisplayName == "" &&
		payload.FirstName == "" &&
		payload.LastName == "" {
		return nil
	}
	return payload
}

func userEmployment(values map[string]any) *userEmploymentPayload {
	payload := &userEmploymentPayload{
		Department:     stringMap(values, "department"),
		Title:          stringMap(values, "title"),
		Organization:   stringMap(values, "organization"),
		Manager:        stringMap(values, "manager"),
		ManagerID:      stringMap(values, "managerId"),
		EmployeeNumber: stringMap(values, "employeeNumber"),
		UserType:       stringMap(values, "userType"),
	}
	if payload.Department == "" &&
		payload.Title == "" &&
		payload.Organization == "" &&
		payload.Manager == "" &&
		payload.ManagerID == "" &&
		payload.EmployeeNumber == "" &&
		payload.UserType == "" {
		return nil
	}
	return payload
}

func auditResource(record auditRecord, actor identityPayload, targets []identityPayload, domain string) (string, string) {
	for _, target := range targets {
		resourceID := firstNonEmpty(target.ID, target.AlternateID, target.DisplayName)
		resourceType := strings.TrimSpace(target.Type)
		if resourceID != "" || resourceType != "" {
			return resourceID, firstNonEmpty(resourceType, auditEventResourceType(record.EventType))
		}
	}
	if actor.AlternateID != "" || actor.ID != "" {
		return firstNonEmpty(actor.AlternateID, actor.ID), firstNonEmpty(actor.Type, auditEventResourceType(record.EventType))
	}
	return domain, auditEventResourceType(record.EventType)
}

func auditEventResourceType(eventType string) string {
	value := strings.TrimSpace(eventType)
	if value == "" {
		return "audit"
	}
	prefix, _, ok := strings.Cut(value, ".")
	if !ok {
		return value
	}
	return prefix
}

func identityFromMap(values map[string]any) identityPayload {
	return identityPayload{
		ID:          stringMap(values, "id"),
		Type:        stringMap(values, "type"),
		AlternateID: stringMap(values, "alternateId"),
		DisplayName: stringMap(values, "displayName"),
	}
}

func identitiesFromMaps(values []map[string]any) []identityPayload {
	identities := make([]identityPayload, 0, len(values))
	for _, value := range values {
		identity := identityFromMap(value)
		if identity != (identityPayload{}) {
			identities = append(identities, identity)
		}
	}
	return identities
}

func userOccurredAt(record userRecord) time.Time {
	for _, stamp := range []*time.Time{
		record.LastUpdated,
		record.Created,
		record.Activated,
		record.StatusChanged,
		record.LastLogin,
		record.PasswordChanged,
	} {
		if stamp != nil && !stamp.IsZero() {
			return stamp.UTC()
		}
	}
	return time.Time{}
}

func firstRecordTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func assignmentEmail(record appAssignmentRecord) string {
	return firstNonEmpty(
		stringMap(record.Profile, "email"),
		stringMap(record.Profile, "login"),
		stringMap(record.Profile, "userName"),
		stringMap(record.Credentials, "userName"),
	)
}

func decodeRawPayload(raw json.RawMessage, label string) (map[string]any, error) {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s raw payload: %w", label, err)
	}
	return decoded, nil
}

func userURN(domain string, userID string) (sourcecdk.URN, error) {
	id := strings.TrimSpace(userID)
	if id == "" {
		return "", fmt.Errorf("okta user id is required")
	}
	return sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:user:%s", domain, id))
}

func nextAfter(headers http.Header) string {
	if headers == nil {
		return ""
	}
	for _, header := range headers.Values("Link") {
		for _, part := range strings.Split(header, ",") {
			link, rel := parseLink(part)
			if rel != "next" {
				continue
			}
			parsed, err := url.Parse(link)
			if err != nil {
				continue
			}
			if after := strings.TrimSpace(parsed.Query().Get("after")); after != "" {
				return after
			}
		}
	}
	return ""
}

func parseLink(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "<") {
		return "", ""
	}
	end := strings.Index(trimmed, ">")
	if end <= 1 {
		return "", ""
	}
	link := trimmed[1:end]
	params := strings.Split(trimmed[end+1:], ";")
	for _, param := range params {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || key != "rel" {
			continue
		}
		return link, strings.Trim(rawValue, "\"")
	}
	return link, ""
}

func checkpointCursor(next string, fallback string, occurredAt time.Time) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	if occurredAt.IsZero() {
		return ""
	}
	return occurredAt.UTC().Format(time.RFC3339Nano)
}

func utcTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	query.Set(key, value)
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func nestedMap(values map[string]any, key string) map[string]any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func stringMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func isNotFound(err error) bool {
	var responseErr *responseError
	return errors.As(err, &responseErr) && responseErr.statusCode == http.StatusNotFound
}

func wrapLookupError(subject string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s not found", subject)
	}
	return fmt.Errorf("%s: %w", subject, err)
}
