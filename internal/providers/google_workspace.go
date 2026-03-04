package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
}

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
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
		"https://www.googleapis.com/auth/admin.directory.domain.readonly",
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
				"id":       id,
				"group_id": groupID,
				"email":    member["email"],
				"role":     member["role"],
				"type":     member["type"],
				"status":   member["status"],
			})
		}
	}

	return g.syncTable(ctx, schema, rows)
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
