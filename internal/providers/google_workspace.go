package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

// GoogleWorkspaceProvider syncs identity data from Google Workspace
type GoogleWorkspaceProvider struct {
	*BaseProvider
	client       *http.Client
	domain       string
	adminEmail   string
	credentials  []byte
	impersonator string

	calendarRowsLoaded      bool
	calendarEventRows       []map[string]interface{}
	calendarGuestRows       []map[string]interface{}
	calendarRowsErr         error
	tokenActivityRowsLoaded bool
	tokenActivityRows       []map[string]interface{}
	tokenActivityRowsErr    error
}

const (
	googleWorkspaceCalendarLookbackDays      = 180
	googleWorkspaceTokenActivityLookbackDays = 180
)

func NewGoogleWorkspaceProvider() *GoogleWorkspaceProvider {
	return &GoogleWorkspaceProvider{
		BaseProvider: NewBaseProvider("google_workspace", ProviderTypeIdentity),
	}
}

func (g *GoogleWorkspaceProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := g.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	g.domain = strings.TrimSpace(g.GetConfigString("domain"))
	g.adminEmail = strings.TrimSpace(g.GetConfigString("admin_email"))
	g.impersonator = strings.TrimSpace(g.GetConfigString("impersonator_email"))
	g.credentials = nil

	if g.domain == "" {
		return fmt.Errorf("google workspace domain required")
	}

	// Handle credentials - can be path or JSON string
	if credsPath := strings.TrimSpace(g.GetConfigString("credentials_file")); credsPath != "" {
		credentials, err := os.ReadFile(credsPath) // #nosec G304 -- credentials_file is explicit operator configuration
		if err != nil {
			return fmt.Errorf("read google workspace credentials_file %q: %w", credsPath, err)
		}
		g.credentials = credentials
	}

	if len(g.credentials) == 0 {
		if credsJSON := strings.TrimSpace(g.GetConfigString("credentials_json")); credsJSON != "" {
			g.credentials = []byte(credsJSON)
		}
	}

	if len(g.credentials) == 0 {
		return fmt.Errorf("google workspace credentials required")
	}

	subject := g.impersonator
	if subject == "" {
		subject = g.adminEmail
	}
	if subject == "" {
		return fmt.Errorf("google workspace domain-wide delegation requires impersonator_email or admin_email")
	}

	// Create OAuth2 client with domain-wide delegation
	conf, err := google.JWTConfigFromJSON(g.credentials,
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.user.security",
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
		"https://www.googleapis.com/auth/admin.directory.domain.readonly",
		"https://www.googleapis.com/auth/admin.reports.audit.readonly",
		"https://www.googleapis.com/auth/calendar.readonly",
	)
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	// Impersonate admin user for domain-wide access
	conf.Subject = subject

	g.client = conf.Client(ctx)
	return nil
}

func (g *GoogleWorkspaceProvider) Test(ctx context.Context) error {
	if g.client == nil {
		return fmt.Errorf("provider not configured")
	}
	// Try to list one user to verify access
	_, err := g.request(ctx, "https://admin.googleapis.com/admin/directory/v1/users?maxResults=1&domain="+g.domain)
	return err
}

func (g *GoogleWorkspaceProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "google_workspace_users",
			Description: "Google Workspace users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "primary_email", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "given_name", Type: "string"},
				{Name: "family_name", Type: "string"},
				{Name: "is_admin", Type: "boolean"},
				{Name: "is_delegated_admin", Type: "boolean"},
				{Name: "suspended", Type: "boolean"},
				{Name: "archived", Type: "boolean"},
				{Name: "is_enrolled_in_2sv", Type: "boolean"},
				{Name: "is_enforced_in_2sv", Type: "boolean"},
				{Name: "creation_time", Type: "timestamp"},
				{Name: "last_login_time", Type: "timestamp"},
				{Name: "org_unit_path", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_groups",
			Description: "Google Workspace groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "direct_members_count", Type: "integer"},
				{Name: "admin_created", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_group_members",
			Description: "Google Workspace group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "member_id", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "status", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_domains",
			Description: "Google Workspace domains",
			Columns: []ColumnSchema{
				{Name: "domain_name", Type: "string", Required: true},
				{Name: "is_primary", Type: "boolean"},
				{Name: "verified", Type: "boolean"},
				{Name: "creation_time", Type: "timestamp"},
			},
			PrimaryKey: []string{"domain_name"},
		},
		{
			Name:        "google_workspace_tokens",
			Description: "Google Workspace third-party OAuth tokens",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "user_email", Type: "string"},
				{Name: "client_id", Type: "string", Required: true},
				{Name: "display_text", Type: "string"},
				{Name: "anonymous", Type: "boolean"},
				{Name: "native_app", Type: "boolean"},
				{Name: "scope", Type: "string"},
				{Name: "scope_count", Type: "integer"},
				{Name: "app_type", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_token_activities",
			Description: "Recent Google Workspace OAuth token audit activity",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "event_time", Type: "timestamp"},
				{Name: "event_name", Type: "string", Required: true},
				{Name: "actor_email", Type: "string"},
				{Name: "client_id", Type: "string", Required: true},
				{Name: "display_text", Type: "string"},
				{Name: "scope", Type: "string"},
				{Name: "ip_address", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_calendar_events",
			Description: "Google Calendar event metadata (privacy-safe)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "calendar_id", Type: "string"},
				{Name: "organizer_email", Type: "string"},
				{Name: "title_hash", Type: "string"},
				{Name: "start_time", Type: "timestamp"},
				{Name: "end_time", Type: "timestamp"},
				{Name: "duration_minutes", Type: "integer"},
				{Name: "is_recurring", Type: "boolean"},
				{Name: "recurrence_pattern", Type: "string"},
				{Name: "attendee_count", Type: "integer"},
				{Name: "response_status", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "updated", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "google_workspace_calendar_attendees",
			Description: "Google Calendar event attendees",
			Columns: []ColumnSchema{
				{Name: "event_id", Type: "string", Required: true},
				{Name: "attendee_email", Type: "string", Required: true},
				{Name: "response_status", Type: "string"},
				{Name: "is_organizer", Type: "boolean"},
				{Name: "is_optional", Type: "boolean"},
			},
			PrimaryKey: []string{"event_id", "attendee_email"},
		},
	}
}

func (g *GoogleWorkspaceProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(g.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (g *GoogleWorkspaceProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	g.resetCalendarRowsCache()
	g.resetTokenActivityRowsCache()
	result := &SyncResult{
		Provider:  g.Name(),
		StartedAt: start,
	}

	// Sync users
	users, err := g.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync groups
	groups, err := g.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	groupMembers, err := g.syncGroupMembers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "group_members: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groupMembers)
		result.TotalRows += groupMembers.Rows
	}

	// Sync domains
	domains, err := g.syncDomains(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "domains: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *domains)
		result.TotalRows += domains.Rows
	}

	tokens, err := g.syncTokens(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "tokens: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *tokens)
		result.TotalRows += tokens.Rows
	}

	tokenActivities, err := g.syncTokenActivities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "token_activities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *tokenActivities)
		result.TotalRows += tokenActivities.Rows
	}

	calendarEvents, err := g.syncCalendarEvents(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "calendar_events: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *calendarEvents)
		result.TotalRows += calendarEvents.Rows
	}

	calendarAttendees, err := g.syncCalendarAttendees(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "calendar_attendees: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *calendarAttendees)
		result.TotalRows += calendarAttendees.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (g *GoogleWorkspaceProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_users")
	result := &TableResult{Name: "google_workspace_users"}
	if err != nil {
		return result, err
	}

	users, err := g.listAll(ctx, "https://admin.googleapis.com/admin/directory/v1/users", map[string]string{
		"domain":     g.domain,
		"maxResults": "500",
		"projection": "full",
	}, "users")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		rows = append(rows, normalizeGoogleUser(user))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GoogleWorkspaceProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_groups")
	result := &TableResult{Name: "google_workspace_groups"}
	if err != nil {
		return result, err
	}

	groups, err := g.listAll(ctx, "https://admin.googleapis.com/admin/directory/v1/groups", map[string]string{
		"domain":     g.domain,
		"maxResults": "200",
	}, "groups")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, normalizeGoogleGroup(group))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GoogleWorkspaceProvider) syncDomains(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_domains")
	result := &TableResult{Name: "google_workspace_domains"}
	if err != nil {
		return result, err
	}

	// Domains API doesn't paginate in the same way
	body, err := g.request(ctx, "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains")
	if err != nil {
		return result, err
	}

	var resp struct {
		Domains []map[string]interface{} `json:"domains"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(resp.Domains))
	for _, domain := range resp.Domains {
		rows = append(rows, normalizeGoogleRow(domain))
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GoogleWorkspaceProvider) syncGroupMembers(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_group_members")
	result := &TableResult{Name: "google_workspace_group_members"}
	if err != nil {
		return result, err
	}

	groups, err := g.listAll(ctx, "https://admin.googleapis.com/admin/directory/v1/groups", map[string]string{
		"domain":     g.domain,
		"maxResults": "200",
	}, "groups")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, rawGroup := range groups {
		group := normalizeGoogleGroup(rawGroup)
		groupID := providerStringValue(group["id"])
		if groupID == "" {
			groupID = providerStringValue(group["email"])
		}
		if groupID == "" {
			continue
		}

		membersURL := fmt.Sprintf("https://admin.googleapis.com/admin/directory/v1/groups/%s/members", url.PathEscape(groupID))
		members, memberErr := g.listAll(ctx, membersURL, map[string]string{
			"maxResults": "200",
		}, "members")
		if memberErr != nil {
			if isGoogleWorkspaceIgnorableError(memberErr) {
				continue
			}
			return result, fmt.Errorf("list group members for %q: %w", groupID, memberErr)
		}

		for _, rawMember := range members {
			member := normalizeGoogleRow(rawMember)
			memberID := providerStringValue(member["id"])
			if memberID == "" {
				memberID = providerStringValue(member["email"])
			}
			if memberID == "" {
				continue
			}

			id := groupID + "|" + memberID
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":        id,
				"group_id":  groupID,
				"member_id": member["id"],
				"email":     member["email"],
				"role":      member["role"],
				"type":      member["type"],
				"status":    member["status"],
			})
		}
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GoogleWorkspaceProvider) syncTokens(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_tokens")
	result := &TableResult{Name: "google_workspace_tokens"}
	if err != nil {
		return result, err
	}

	users, err := g.listAll(ctx, "https://admin.googleapis.com/admin/directory/v1/users", map[string]string{
		"domain":     g.domain,
		"maxResults": "500",
		"projection": "basic",
	}, "users")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, rawUser := range users {
		user := normalizeGoogleUser(rawUser)
		userID := strings.TrimSpace(providerStringValue(user["id"]))
		userEmail := strings.ToLower(strings.TrimSpace(providerStringValue(user["primary_email"])))
		if userID == "" {
			continue
		}
		if suspended, _ := user["suspended"].(bool); suspended {
			continue
		}

		body, tokenErr := g.request(ctx, fmt.Sprintf("https://admin.googleapis.com/admin/directory/v1/users/%s/tokens", url.PathEscape(userID)))
		if tokenErr != nil {
			if isGoogleWorkspaceIgnorableError(tokenErr) {
				continue
			}
			return result, fmt.Errorf("list tokens for %q: %w", userID, tokenErr)
		}

		var resp struct {
			Items []map[string]interface{} `json:"items"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return result, err
		}

		for _, rawToken := range resp.Items {
			row := normalizeGoogleToken(rawToken)
			clientID := strings.TrimSpace(providerStringValue(row["client_id"]))
			if clientID == "" {
				continue
			}

			rowID := userID + "|" + clientID
			if _, ok := seen[rowID]; ok {
				continue
			}
			seen[rowID] = struct{}{}

			row["id"] = rowID
			row["user_id"] = userID
			row["user_email"] = userEmail
			rows = append(rows, row)
		}
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GoogleWorkspaceProvider) syncTokenActivities(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_token_activities")
	result := &TableResult{Name: "google_workspace_token_activities"}
	if err != nil {
		return result, err
	}
	if err := g.ensureTokenActivityRows(ctx); err != nil {
		return result, err
	}
	return g.syncTable(ctx, schema, g.tokenActivityRows)
}

func (g *GoogleWorkspaceProvider) syncCalendarEvents(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_calendar_events")
	result := &TableResult{Name: "google_workspace_calendar_events"}
	if err != nil {
		return result, err
	}
	if err := g.ensureCalendarRows(ctx); err != nil {
		return result, err
	}
	return g.syncTable(ctx, schema, g.calendarEventRows)
}

func (g *GoogleWorkspaceProvider) syncCalendarAttendees(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("google_workspace_calendar_attendees")
	result := &TableResult{Name: "google_workspace_calendar_attendees"}
	if err != nil {
		return result, err
	}
	if err := g.ensureCalendarRows(ctx); err != nil {
		return result, err
	}
	return g.syncTable(ctx, schema, g.calendarGuestRows)
}

func (g *GoogleWorkspaceProvider) ensureCalendarRows(ctx context.Context) error {
	if g.calendarRowsLoaded {
		return g.calendarRowsErr
	}

	since := time.Now().AddDate(0, 0, -googleWorkspaceCalendarLookbackDays)
	g.calendarEventRows, g.calendarGuestRows, g.calendarRowsErr = g.listCalendarActivity(ctx, since)
	g.calendarRowsLoaded = true
	return g.calendarRowsErr
}

func (g *GoogleWorkspaceProvider) resetCalendarRowsCache() {
	g.calendarRowsLoaded = false
	g.calendarEventRows = nil
	g.calendarGuestRows = nil
	g.calendarRowsErr = nil
}

func (g *GoogleWorkspaceProvider) ensureTokenActivityRows(ctx context.Context) error {
	if g.tokenActivityRowsLoaded {
		return g.tokenActivityRowsErr
	}

	since := time.Now().AddDate(0, 0, -googleWorkspaceTokenActivityLookbackDays)
	g.tokenActivityRows, g.tokenActivityRowsErr = g.listTokenActivities(ctx, since)
	g.tokenActivityRowsLoaded = true
	return g.tokenActivityRowsErr
}

func (g *GoogleWorkspaceProvider) resetTokenActivityRowsCache() {
	g.tokenActivityRowsLoaded = false
	g.tokenActivityRows = nil
	g.tokenActivityRowsErr = nil
}

func (g *GoogleWorkspaceProvider) listTokenActivities(ctx context.Context, since time.Time) ([]map[string]interface{}, error) {
	baseURL := "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token"
	pageToken := ""
	rows := make([]map[string]interface{}, 0)

	for {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		query := parsed.Query()
		query.Set("maxResults", "1000")
		if !since.IsZero() {
			query.Set("startTime", since.UTC().Format(time.RFC3339))
		}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		parsed.RawQuery = query.Encode()

		body, err := g.request(ctx, parsed.String())
		if err != nil {
			if isGoogleWorkspaceIgnorableError(err) {
				return nil, nil
			}
			return nil, err
		}

		var resp struct {
			Items         []map[string]interface{} `json:"items"`
			NextPageToken string                   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		for _, rawItem := range resp.Items {
			rows = append(rows, normalizeGoogleTokenActivityRows(rawItem)...)
		}

		if strings.TrimSpace(resp.NextPageToken) == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return rows, nil
}

func normalizeGoogleTokenActivityRows(item map[string]interface{}) []map[string]interface{} {
	normalized := normalizeGoogleRow(item)
	eventTime := strings.TrimSpace(getGoogleNestedString(normalized, "id", "time"))
	uniqueQualifier := strings.TrimSpace(getGoogleNestedString(normalized, "id", "unique_qualifier"))
	actorEmail := strings.ToLower(strings.TrimSpace(getGoogleNestedString(normalized, "actor", "email")))
	ipAddress := strings.TrimSpace(providerStringValue(normalized["ip_address"]))
	rawEvents := googleActivityMaps(normalized["events"])
	rows := make([]map[string]interface{}, 0, len(rawEvents))

	for index, eventMap := range rawEvents {
		event := normalizeGoogleRow(eventMap)
		eventName := strings.TrimSpace(providerStringValue(event["name"]))
		if eventName == "" {
			continue
		}
		params := googleActivityParameters(event["parameters"])
		clientID := firstNonEmptyString(
			params["client_id"],
			params["clientid"],
			params["oauth_client_id"],
			params["app_id"],
		)
		displayText := firstNonEmptyString(
			params["app_name"],
			params["application_name"],
			params["client_name"],
			params["display_text"],
		)
		if strings.TrimSpace(clientID) == "" {
			continue
		}
		scopes := stringSliceValue(firstNonEmptyString(params["scope"], params["scopes"]))
		sort.Strings(scopes)
		rowID := firstNonEmptyString(uniqueQualifier, eventTime)
		rowID = strings.TrimSpace(rowID)
		if rowID == "" {
			rowID = fmt.Sprintf("%s|%s|%s|%d", actorEmail, clientID, eventName, index)
		} else {
			rowID = fmt.Sprintf("%s|%s|%d", rowID, clientID, index)
		}
		rows = append(rows, map[string]interface{}{
			"id":           rowID,
			"event_time":   eventTime,
			"event_name":   eventName,
			"actor_email":  actorEmail,
			"client_id":    clientID,
			"display_text": displayText,
			"scope":        strings.Join(scopes, " "),
			"ip_address":   ipAddress,
		})
	}

	return rows
}

func googleActivityParameters(raw interface{}) map[string]string {
	params := make(map[string]string)
	for _, row := range googleActivityMaps(raw) {
		normalized := normalizeGoogleRow(row)
		name := strings.TrimSpace(providerStringValue(normalized["name"]))
		if name == "" {
			continue
		}
		value := firstNonEmptyString(
			strings.TrimSpace(providerStringValue(normalized["value"])),
			strings.Join(stringSliceValue(normalized["multi_value"]), " "),
			strings.TrimSpace(providerStringValue(normalized["bool_value"])),
			strings.TrimSpace(providerStringValue(normalized["int_value"])),
		)
		if value == "" {
			continue
		}
		params[name] = value
	}
	return params
}

func googleActivityMaps(raw interface{}) []map[string]interface{} {
	switch typed := raw.(type) {
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			row, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			rows = append(rows, row)
		}
		return rows
	case []map[string]interface{}:
		return typed
	default:
		return nil
	}
}

func (g *GoogleWorkspaceProvider) request(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google workspace API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (g *GoogleWorkspaceProvider) listCalendarActivity(ctx context.Context, since time.Time) ([]map[string]interface{}, []map[string]interface{}, error) {
	users, err := g.listAll(ctx, "https://admin.googleapis.com/admin/directory/v1/users", map[string]string{
		"domain":     g.domain,
		"maxResults": "500",
		"projection": "basic",
	}, "users")
	if err != nil {
		return nil, nil, err
	}

	eventsByID := make(map[string]map[string]interface{})
	attendees := make([]map[string]interface{}, 0)
	seenAttendees := make(map[string]struct{})

	for _, rawUser := range users {
		user := normalizeGoogleUser(rawUser)
		calendarID := strings.ToLower(providerStringValue(user["primary_email"]))
		if calendarID == "" {
			continue
		}
		if suspended, _ := user["suspended"].(bool); suspended {
			continue
		}

		calendarEvents, eventErr := g.listCalendarEvents(ctx, calendarID, since)
		if eventErr != nil {
			if isGoogleWorkspaceIgnorableError(eventErr) {
				continue
			}
			return nil, nil, fmt.Errorf("list calendar events for %q: %w", calendarID, eventErr)
		}

		for _, rawEvent := range calendarEvents {
			event := normalizeGoogleRow(rawEvent)
			eventID := googleCalendarEventID(event)
			if eventID == "" {
				continue
			}

			if _, exists := eventsByID[eventID]; !exists {
				eventsByID[eventID] = normalizeGoogleCalendarEvent(eventID, calendarID, event)
			}

			eventAttendees := googleCalendarAttendees(event["attendees"])
			for _, attendee := range eventAttendees {
				email := strings.ToLower(providerStringValue(attendee["email"]))
				if email == "" {
					continue
				}

				attendeeKey := eventID + "|" + email
				if _, exists := seenAttendees[attendeeKey]; exists {
					continue
				}
				seenAttendees[attendeeKey] = struct{}{}

				attendees = append(attendees, map[string]interface{}{
					"event_id":        eventID,
					"attendee_email":  email,
					"response_status": attendee["response_status"],
					"is_organizer":    attendee["organizer"],
					"is_optional":     attendee["optional"],
				})
			}
		}
	}

	eventIDs := make([]string, 0, len(eventsByID))
	for eventID := range eventsByID {
		eventIDs = append(eventIDs, eventID)
	}
	sort.Strings(eventIDs)

	events := make([]map[string]interface{}, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		events = append(events, eventsByID[eventID])
	}

	return events, attendees, nil
}

func (g *GoogleWorkspaceProvider) listCalendarEvents(ctx context.Context, calendarID string, since time.Time) ([]map[string]interface{}, error) {
	baseURL := fmt.Sprintf("https://www.googleapis.com/calendar/v3/calendars/%s/events", url.PathEscape(calendarID))
	pageToken := ""
	events := make([]map[string]interface{}, 0)

	for {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		query := parsed.Query()
		query.Set("maxResults", "250")
		query.Set("showDeleted", "false")
		query.Set("singleEvents", "false")
		if !since.IsZero() {
			query.Set("timeMin", since.UTC().Format(time.RFC3339))
		}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		parsed.RawQuery = query.Encode()

		body, err := g.request(ctx, parsed.String())
		if err != nil {
			return nil, err
		}

		var resp struct {
			Items         []map[string]interface{} `json:"items"`
			NextPageToken string                   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		events = append(events, resp.Items...)
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return events, nil
}

func (g *GoogleWorkspaceProvider) listAll(ctx context.Context, baseURL string, params map[string]string, itemsKey string) ([]map[string]interface{}, error) {
	var allItems []map[string]interface{}
	pageToken := ""

	for {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		query := parsed.Query()
		for k, v := range params {
			query.Set(k, v)
		}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		parsed.RawQuery = query.Encode()

		body, err := g.request(ctx, parsed.String())
		if err != nil {
			return nil, err
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		if items, ok := resp[itemsKey].([]interface{}); ok {
			for _, item := range items {
				if m, ok := item.(map[string]interface{}); ok {
					allItems = append(allItems, m)
				}
			}
		}

		if nextToken, ok := resp["nextPageToken"].(string); ok && nextToken != "" {
			pageToken = nextToken
		} else {
			break
		}
	}

	return allItems, nil
}

func isGoogleWorkspaceIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "API error 403") || strings.Contains(message, "API error 404")
}

func normalizeGoogleUser(user map[string]interface{}) map[string]interface{} {
	normalized := normalizeGoogleRow(user)
	return map[string]interface{}{
		"id":                 normalized["id"],
		"primary_email":      normalized["primary_email"],
		"name":               getGoogleNestedString(normalized, "name", "full_name"),
		"given_name":         getGoogleNestedString(normalized, "name", "given_name"),
		"family_name":        getGoogleNestedString(normalized, "name", "family_name"),
		"is_admin":           normalized["is_admin"],
		"is_delegated_admin": normalized["is_delegated_admin"],
		"suspended":          normalized["suspended"],
		"archived":           normalized["archived"],
		"is_enrolled_in_2sv": normalized["is_enrolled_in_2sv"],
		"is_enforced_in_2sv": normalized["is_enforced_in_2sv"],
		"creation_time":      normalized["creation_time"],
		"last_login_time":    normalized["last_login_time"],
		"org_unit_path":      normalized["org_unit_path"],
	}
}

func normalizeGoogleGroup(group map[string]interface{}) map[string]interface{} {
	normalized := normalizeGoogleRow(group)
	return map[string]interface{}{
		"id":                   normalized["id"],
		"email":                normalized["email"],
		"name":                 normalized["name"],
		"description":          normalized["description"],
		"direct_members_count": parseGoogleCount(normalized["direct_members_count"]),
		"admin_created":        normalized["admin_created"],
	}
}

func normalizeGoogleToken(token map[string]interface{}) map[string]interface{} {
	normalized := normalizeGoogleRow(token)
	scopes := stringSliceValue(normalized["scopes"])
	sort.Strings(scopes)

	appType := "web"
	if nativeApp, _ := normalized["native_app"].(bool); nativeApp {
		appType = "native"
	}
	if anonymous, _ := normalized["anonymous"].(bool); anonymous {
		appType = "anonymous"
	}

	return map[string]interface{}{
		"client_id":    normalized["client_id"],
		"display_text": normalized["display_text"],
		"anonymous":    normalized["anonymous"],
		"native_app":   normalized["native_app"],
		"scope":        strings.Join(scopes, " "),
		"scope_count":  len(scopes),
		"app_type":     appType,
	}
}

func normalizeGoogleCalendarEvent(eventID string, calendarID string, event map[string]interface{}) map[string]interface{} {
	startTime := googleCalendarEventTime(event["start"])
	endTime := googleCalendarEventTime(event["end"])
	recurrence := googleCalendarRecurrencePattern(event["recurrence"])
	attendees := googleCalendarAttendees(event["attendees"])
	organizerEmail := strings.ToLower(getGoogleNestedString(event, "organizer", "email"))
	responseStatus := googleCalendarResponseStatus(calendarID, organizerEmail, attendees)

	return map[string]interface{}{
		"id":                 eventID,
		"calendar_id":        calendarID,
		"organizer_email":    organizerEmail,
		"title_hash":         hashGoogleWorkspaceTitle(providerStringValue(event["summary"])),
		"start_time":         startTime,
		"end_time":           endTime,
		"duration_minutes":   googleCalendarDurationMinutes(startTime, endTime),
		"is_recurring":       recurrence != "",
		"recurrence_pattern": recurrence,
		"attendee_count":     len(attendees),
		"response_status":    responseStatus,
		"created":            event["created"],
		"updated":            event["updated"],
	}
}

func googleCalendarEventID(event map[string]interface{}) string {
	if iCalUID := strings.TrimSpace(providerStringValue(event["i_cal_uid"])); iCalUID != "" {
		return iCalUID
	}
	if iCalUID := strings.TrimSpace(providerStringValue(event["i_cal_u_i_d"])); iCalUID != "" {
		return iCalUID
	}
	return strings.TrimSpace(providerStringValue(event["id"]))
}

func googleCalendarEventTime(value interface{}) string {
	data, ok := value.(map[string]interface{})
	if !ok {
		return ""
	}
	if dateTime := strings.TrimSpace(providerStringValue(data["date_time"])); dateTime != "" {
		return dateTime
	}
	if date := strings.TrimSpace(providerStringValue(data["date"])); date != "" {
		return date + "T00:00:00Z"
	}
	return ""
}

func googleCalendarDurationMinutes(startTime string, endTime string) interface{} {
	if startTime == "" || endTime == "" {
		return nil
	}
	start, startErr := time.Parse(time.RFC3339, startTime)
	end, endErr := time.Parse(time.RFC3339, endTime)
	if startErr != nil || endErr != nil || end.Before(start) {
		return nil
	}
	return int(end.Sub(start).Minutes())
}

func googleCalendarRecurrencePattern(value interface{}) string {
	list, ok := value.([]interface{})
	if !ok {
		return ""
	}
	patterns := make([]string, 0, len(list))
	for _, item := range list {
		pattern := strings.TrimSpace(providerStringValue(item))
		if pattern == "" {
			continue
		}
		patterns = append(patterns, pattern)
	}
	return strings.Join(patterns, ";")
}

func googleCalendarAttendees(value interface{}) []map[string]interface{} {
	list, ok := value.([]interface{})
	if !ok {
		return nil
	}
	attendees := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		attendee, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		attendees = append(attendees, normalizeGoogleRow(attendee))
	}
	return attendees
}

func googleCalendarResponseStatus(calendarID string, organizerEmail string, attendees []map[string]interface{}) string {
	calendarID = strings.ToLower(strings.TrimSpace(calendarID))
	organizerEmail = strings.ToLower(strings.TrimSpace(organizerEmail))

	for _, attendee := range attendees {
		email := strings.ToLower(providerStringValue(attendee["email"]))
		if email == "" {
			continue
		}
		if self, _ := attendee["self"].(bool); self {
			return providerStringValue(attendee["response_status"])
		}
		if calendarID != "" && email == calendarID {
			return providerStringValue(attendee["response_status"])
		}
	}
	for _, attendee := range attendees {
		email := strings.ToLower(providerStringValue(attendee["email"]))
		if email == organizerEmail {
			return providerStringValue(attendee["response_status"])
		}
	}
	return ""
}

func hashGoogleWorkspaceTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(title))
	return hex.EncodeToString(sum[:])
}

func normalizeGoogleRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func getGoogleNestedString(data map[string]interface{}, path ...string) string {
	value := getGoogleNestedValue(data, path...)
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func getGoogleNestedValue(data map[string]interface{}, path ...string) interface{} {
	var current interface{} = data
	for _, key := range path {
		asMap, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = asMap[key]
	}
	return current
}

func parseGoogleCount(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		if count, err := strconv.Atoi(typed); err == nil {
			return count
		}
		return typed
	default:
		return value
	}
}

func stringSliceValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			out = append(out, entry)
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			text := strings.TrimSpace(providerStringValue(entry))
			if text == "" {
				continue
			}
			out = append(out, text)
		}
		return out
	default:
		text := strings.TrimSpace(providerStringValue(value))
		if text == "" {
			return nil
		}
		return strings.Fields(text)
	}
}

// MFA status helpers
func (g *GoogleWorkspaceProvider) GetUserMFAStatus(user map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"is_enrolled_in_2sv": user["isEnrolledIn2Sv"],
		"is_enforced_in_2sv": user["isEnforcedIn2Sv"],
	}
}

// AdminStatus helpers
func (g *GoogleWorkspaceProvider) IsUserAdmin(user map[string]interface{}) bool {
	isAdmin, _ := user["isAdmin"].(bool)
	isDelegatedAdmin, _ := user["isDelegatedAdmin"].(bool)
	return isAdmin || isDelegatedAdmin
}
