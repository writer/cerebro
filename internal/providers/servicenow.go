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

const (
	serviceNowDefaultPageSize = 200
	serviceNowMaxPages        = 500
)

// ServiceNowProvider syncs ServiceNow identity and access metadata.
type ServiceNowProvider struct {
	*BaseProvider
	baseURL  string
	token    string
	username string
	password string
	client   *http.Client
}

func NewServiceNowProvider() *ServiceNowProvider {
	return &ServiceNowProvider{
		BaseProvider: NewBaseProvider("servicenow", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *ServiceNowProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.baseURL = strings.TrimSpace(s.GetConfigString("url"))
	if s.baseURL == "" {
		s.baseURL = strings.TrimSpace(s.GetConfigString("base_url"))
	}
	if s.baseURL == "" {
		s.baseURL = strings.TrimSpace(s.GetConfigString("instance_url"))
	}
	s.baseURL = strings.TrimSuffix(s.baseURL, "/")
	if s.baseURL == "" {
		return fmt.Errorf("servicenow url required")
	}

	s.token = strings.TrimSpace(s.GetConfigString("token"))
	if s.token == "" {
		s.token = strings.TrimSpace(s.GetConfigString("api_token"))
	}

	s.username = strings.TrimSpace(s.GetConfigString("username"))
	s.password = strings.TrimSpace(s.GetConfigString("password"))

	if s.token == "" && (s.username == "" || s.password == "") {
		return fmt.Errorf("servicenow auth required: token or username/password")
	}

	if err := validateServiceNowURL(s.baseURL); err != nil {
		return err
	}

	return nil
}

func (s *ServiceNowProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, addQueryParams("/api/now/table/sys_user", map[string]string{
		"sysparm_limit":                  "1",
		"sysparm_offset":                 "0",
		"sysparm_display_value":          "false",
		"sysparm_exclude_reference_link": "true",
	}))
	return err
}

func (s *ServiceNowProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "servicenow_users",
			Description: "ServiceNow users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "last_login_at", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "servicenow_groups",
			Description: "ServiceNow groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "manager_id", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "servicenow_group_memberships",
			Description: "ServiceNow group membership mappings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string"},
				{Name: "group_id", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *ServiceNowProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(s.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (s *ServiceNowProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
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

	syncTable("users", s.syncUsers)
	syncTable("groups", s.syncGroups)
	syncTable("group_memberships", s.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (s *ServiceNowProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("servicenow_users")
	result := &TableResult{Name: "servicenow_users"}
	if err != nil {
		return result, err
	}

	users, err := s.listTableEntries(ctx, "sys_user", []string{
		"sys_id", "name", "user_name", "email", "title", "department", "active", "last_login_time", "sys_created_on", "sys_updated_on",
	})
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeServiceNowRow(user)
		department := serviceNowReferenceMap(normalized["department"])

		userID := firstServiceNowString(normalized, "sys_id", "id")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":       userID,
			"name":     firstServiceNowValue(normalized, "name"),
			"username": firstServiceNowValue(normalized, "user_name", "username"),
			"email":    firstServiceNowValue(normalized, "email"),
			"title":    firstServiceNowValue(normalized, "title"),
			"department": firstNonNilServiceNowValue(
				serviceNowReferenceValue(normalized["department"]),
				firstServiceNowValue(department, "value", "display_value", "name"),
			),
			"active":        firstServiceNowValue(normalized, "active"),
			"last_login_at": firstServiceNowValue(normalized, "last_login_time", "last_login_at"),
			"created_at":    firstServiceNowValue(normalized, "sys_created_on", "created_at"),
			"updated_at":    firstServiceNowValue(normalized, "sys_updated_on", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *ServiceNowProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("servicenow_groups")
	result := &TableResult{Name: "servicenow_groups"}
	if err != nil {
		return result, err
	}

	groups, err := s.listTableEntries(ctx, "sys_user_group", []string{
		"sys_id", "name", "description", "manager", "active", "sys_created_on", "sys_updated_on",
	})
	if err != nil {
		if isServiceNowIgnorableError(err) {
			return s.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeServiceNowRow(group)
		manager := serviceNowReferenceMap(normalized["manager"])

		groupID := firstServiceNowString(normalized, "sys_id", "id")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":          groupID,
			"name":        firstServiceNowValue(normalized, "name"),
			"description": firstServiceNowValue(normalized, "description"),
			"manager_id": firstNonNilServiceNowValue(
				serviceNowReferenceValue(normalized["manager"]),
				firstServiceNowValue(manager, "value", "sys_id", "id"),
			),
			"active":     firstServiceNowValue(normalized, "active"),
			"created_at": firstServiceNowValue(normalized, "sys_created_on", "created_at"),
			"updated_at": firstServiceNowValue(normalized, "sys_updated_on", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *ServiceNowProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("servicenow_group_memberships")
	result := &TableResult{Name: "servicenow_group_memberships"}
	if err != nil {
		return result, err
	}

	memberships, err := s.listTableEntries(ctx, "sys_user_grmember", []string{
		"sys_id", "user", "group", "active", "sys_created_on", "sys_updated_on",
	})
	if err != nil {
		if isServiceNowIgnorableError(err) {
			return s.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(memberships))
	for _, membership := range memberships {
		normalized := normalizeServiceNowRow(membership)
		user := serviceNowReferenceMap(normalized["user"])
		group := serviceNowReferenceMap(normalized["group"])

		membershipID := firstServiceNowString(normalized, "sys_id", "id")
		if membershipID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id": membershipID,
			"user_id": firstNonNilServiceNowValue(
				serviceNowReferenceValue(normalized["user"]),
				firstServiceNowValue(user, "value", "sys_id", "id"),
			),
			"group_id": firstNonNilServiceNowValue(
				serviceNowReferenceValue(normalized["group"]),
				firstServiceNowValue(group, "value", "sys_id", "id"),
			),
			"active":     firstServiceNowValue(normalized, "active"),
			"created_at": firstServiceNowValue(normalized, "sys_created_on", "created_at"),
			"updated_at": firstServiceNowValue(normalized, "sys_updated_on", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *ServiceNowProvider) listTableEntries(ctx context.Context, table string, fields []string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	offset := 0
	path := "/api/now/table/" + url.PathEscape(table)

	for page := 0; page < serviceNowMaxPages; page++ {
		params := map[string]string{
			"sysparm_limit":                  strconv.Itoa(serviceNowDefaultPageSize),
			"sysparm_offset":                 strconv.Itoa(offset),
			"sysparm_display_value":          "false",
			"sysparm_exclude_reference_link": "true",
		}
		if len(fields) > 0 {
			params["sysparm_fields"] = strings.Join(fields, ",")
		}

		requestPath := addQueryParams(path, params)
		body, err := s.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		entries := serviceNowExtractResults(normalizeServiceNowRow(payload))
		for _, entry := range entries {
			rows = append(rows, normalizeServiceNowRow(entry))
		}

		if len(entries) < serviceNowDefaultPageSize {
			break
		}

		nextOffset := offset + len(entries)
		if nextOffset <= offset {
			return nil, fmt.Errorf("servicenow pagination loop detected for %s", table)
		}
		offset = nextOffset
	}

	return rows, nil
}

func (s *ServiceNowProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := serviceNowResolveRequestURL(s.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}

	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	} else {
		req.SetBasicAuth(s.username, s.password)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("servicenow API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func serviceNowResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("servicenow request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid servicenow URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid servicenow base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("servicenow request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateServiceNowURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid servicenow url %q", rawURL)
	}
	return nil
}

func normalizeServiceNowRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func serviceNowReferenceMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func serviceNowMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if m, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, m)
			}
		}
		return rows
	default:
		return nil
	}
}

func serviceNowExtractResults(payload map[string]interface{}) []map[string]interface{} {
	if results := serviceNowMapSlice(payload["result"]); len(results) > 0 {
		return results
	}
	if result := serviceNowReferenceMap(payload["result"]); len(result) > 0 {
		return []map[string]interface{}{result}
	}
	if results := serviceNowMapSlice(payload["results"]); len(results) > 0 {
		return results
	}
	return nil
}

func serviceNowReferenceValue(value interface{}) interface{} {
	normalized := serviceNowReferenceMap(value)
	if len(normalized) > 0 {
		for _, key := range []string{"value", "sys_id", "id", "display_value", "name"} {
			if candidate := firstServiceNowValue(normalized, key); candidate != nil {
				return candidate
			}
		}
		return nil
	}

	text := strings.TrimSpace(providerStringValue(value))
	if text == "" {
		return nil
	}
	return text
}

func firstServiceNowString(row map[string]interface{}, keys ...string) string {
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

func firstServiceNowValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		if strings.TrimSpace(providerStringValue(value)) == "" {
			continue
		}
		return value
	}
	return nil
}

func firstNonNilServiceNowValue(values ...interface{}) interface{} {
	for _, value := range values {
		if value == nil {
			continue
		}
		if strings.TrimSpace(providerStringValue(value)) == "" {
			continue
		}
		return value
	}
	return nil
}

func isServiceNowIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
