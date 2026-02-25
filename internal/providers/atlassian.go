package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AtlassianProvider syncs Jira Cloud identity and project metadata.
type AtlassianProvider struct {
	*BaseProvider
	baseURL  string
	email    string
	apiToken string
	client   *http.Client
}

func NewAtlassianProvider() *AtlassianProvider {
	return &AtlassianProvider{
		BaseProvider: NewBaseProvider("atlassian", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (a *AtlassianProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := a.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	a.baseURL = strings.TrimSuffix(strings.TrimSpace(a.GetConfigString("base_url")), "/")
	if a.baseURL == "" {
		a.baseURL = strings.TrimSuffix(strings.TrimSpace(a.GetConfigString("api_url")), "/")
	}
	if a.baseURL == "" {
		return fmt.Errorf("atlassian base_url required")
	}

	parsed, err := url.Parse(a.baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid atlassian base_url %q", a.baseURL)
	}

	a.email = strings.TrimSpace(a.GetConfigString("email"))
	if a.email == "" {
		return fmt.Errorf("atlassian email required")
	}

	a.apiToken = strings.TrimSpace(a.GetConfigString("api_token"))
	if a.apiToken == "" {
		return fmt.Errorf("atlassian api_token required")
	}

	return nil
}

func (a *AtlassianProvider) Test(ctx context.Context) error {
	_, err := a.request(ctx, "/rest/api/3/myself")
	return err
}

func (a *AtlassianProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "atlassian_projects",
			Description: "Atlassian Jira projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "key", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "project_type_key", Type: "string"},
				{Name: "simplified", Type: "boolean"},
				{Name: "style", Type: "string"},
				{Name: "is_private", Type: "boolean"},
				{Name: "archived", Type: "boolean"},
				{Name: "lead_account_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "atlassian_users",
			Description: "Atlassian Jira users",
			Columns: []ColumnSchema{
				{Name: "account_id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "email_address", Type: "string"},
				{Name: "account_type", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "time_zone", Type: "string"},
				{Name: "locale", Type: "string"},
			},
			PrimaryKey: []string{"account_id"},
		},
		{
			Name:        "atlassian_groups",
			Description: "Atlassian Jira groups",
			Columns: []ColumnSchema{
				{Name: "group_id", Type: "string", Required: true},
				{Name: "name", Type: "string", Required: true},
				{Name: "self", Type: "string"},
			},
			PrimaryKey: []string{"group_id"},
		},
		{
			Name:        "atlassian_group_memberships",
			Description: "Atlassian Jira group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "account_id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "email_address", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "account_type", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (a *AtlassianProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(a.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (a *AtlassianProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  a.Name(),
		StartedAt: start,
	}

	syncTable := func(name string, fn func(context.Context) (*TableResult, error)) {
		table, err := fn(ctx)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	syncTable("projects", a.syncProjects)
	syncTable("users", a.syncUsers)
	syncTable("groups", a.syncGroups)
	syncTable("group_memberships", a.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (a *AtlassianProvider) syncProjects(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_projects")
	result := &TableResult{Name: "atlassian_projects"}
	if err != nil {
		return result, err
	}

	projects, err := a.listProjects(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(projects))
	for _, project := range projects {
		row := normalizeAtlassianRow(project)
		if id := firstAtlassianString(row, "id", "project_id", "key"); id != "" {
			row["id"] = id
		}
		if key := firstAtlassianString(row, "key", "project_key"); key != "" {
			row["key"] = key
		}
		if row["lead_account_id"] == nil {
			if lead := atlassianMap(row["lead"]); len(lead) > 0 {
				row["lead_account_id"] = firstAtlassianValue(lead, "account_id", "id")
			}
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_users")
	result := &TableResult{Name: "atlassian_users"}
	if err != nil {
		return result, err
	}

	users, err := a.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		row := normalizeAtlassianRow(user)
		if accountID := firstAtlassianString(row, "account_id", "accountid", "id"); accountID != "" {
			row["account_id"] = accountID
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_groups")
	result := &TableResult{Name: "atlassian_groups"}
	if err != nil {
		return result, err
	}

	groups, err := a.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		row := normalizeAtlassianRow(group)
		if groupID := firstAtlassianString(row, "group_id", "id", "name"); groupID != "" {
			row["group_id"] = groupID
		}
		if row["name"] == nil {
			row["name"] = firstAtlassianValue(row, "name", "group_name")
		}
		rows = append(rows, row)
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("atlassian_group_memberships")
	result := &TableResult{Name: "atlassian_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := a.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeAtlassianRow(group)
		groupID := firstAtlassianString(normalizedGroup, "group_id", "id", "name")
		if groupID == "" {
			continue
		}
		groupName := firstAtlassianString(normalizedGroup, "name", "group_name")

		members, err := a.listGroupMembers(ctx, groupID)
		if err != nil {
			if isAtlassianIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizeAtlassianRow(member)
			accountID := firstAtlassianString(normalizedMember, "account_id", "accountid", "id")
			if accountID == "" {
				continue
			}

			membershipID := groupID + "|" + accountID
			if _, ok := seen[membershipID]; ok {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":           membershipID,
				"group_id":     groupID,
				"group_name":   groupName,
				"account_id":   accountID,
				"display_name": firstAtlassianValue(normalizedMember, "display_name"),
				"email_address": firstAtlassianValue(normalizedMember,
					"email_address", "email"),
				"active":       firstAtlassianValue(normalizedMember, "active"),
				"account_type": firstAtlassianValue(normalizedMember, "account_type"),
			})
		}
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *AtlassianProvider) listProjects(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 50
	startAt := 0
	all := make([]map[string]interface{}, 0)

	for {
		path := addQueryParams("/rest/api/3/project/search", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func (a *AtlassianProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for {
		path := addQueryParams("/rest/api/3/users/search", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		var users []map[string]interface{}
		if err := json.Unmarshal(body, &users); err != nil {
			return nil, err
		}
		if len(users) == 0 {
			break
		}

		for _, user := range users {
			normalized := normalizeAtlassianRow(user)
			id := firstAtlassianString(normalized, "account_id", "accountid", "id")
			if id != "" {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
			}
			all = append(all, normalized)
		}

		if len(users) < pageSize {
			break
		}
		startAt += len(users)
	}

	return all, nil
}

func (a *AtlassianProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)

	for {
		path := addQueryParams("/rest/api/3/group/bulk", map[string]string{
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func (a *AtlassianProvider) listGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	pageSize := 100
	startAt := 0
	all := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for {
		path := addQueryParams("/rest/api/3/group/member", map[string]string{
			"groupId":    groupID,
			"startAt":    strconv.Itoa(startAt),
			"maxResults": strconv.Itoa(pageSize),
		})

		body, err := a.request(ctx, path)
		if err != nil {
			return nil, err
		}

		items, isLast, respStartAt, respMaxResults, err := decodeAtlassianValuesPage(body)
		if err != nil {
			return nil, err
		}

		for _, item := range items {
			normalized := normalizeAtlassianRow(item)
			accountID := firstAtlassianString(normalized, "account_id", "accountid", "id")
			if accountID != "" {
				if _, ok := seen[accountID]; ok {
					continue
				}
				seen[accountID] = struct{}{}
			}
			all = append(all, normalized)
		}

		if isLast || len(items) == 0 {
			break
		}

		next := respStartAt + respMaxResults
		if next <= startAt {
			next = startAt + len(items)
		}
		if next <= startAt {
			break
		}
		startAt = next
	}

	return all, nil
}

func decodeAtlassianValuesPage(body []byte) ([]map[string]interface{}, bool, int, int, error) {
	var page struct {
		Values     []map[string]interface{} `json:"values"`
		IsLast     bool                     `json:"isLast"`
		StartAt    int                      `json:"startAt"`
		MaxResults int                      `json:"maxResults"`
	}
	if err := json.Unmarshal(body, &page); err == nil && (page.Values != nil || page.IsLast || page.StartAt > 0 || page.MaxResults > 0) {
		if page.MaxResults <= 0 {
			page.MaxResults = len(page.Values)
		}
		return page.Values, page.IsLast, page.StartAt, page.MaxResults, nil
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(body, &list); err == nil {
		return list, true, 0, len(list), nil
	}

	return nil, false, 0, 0, fmt.Errorf("failed to parse atlassian paginated response")
}

func (a *AtlassianProvider) request(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(a.email, a.apiToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("atlassian API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeAtlassianRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func atlassianMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func firstAtlassianString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func firstAtlassianValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text == "" {
			continue
		}
		return value
	}
	return nil
}

func isAtlassianIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
