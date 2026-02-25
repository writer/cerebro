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
	workdayDefaultPageSize = 100
	workdayMaxPages        = 500
)

// WorkdayProvider syncs Workday SCIM users, groups, and memberships.
type WorkdayProvider struct {
	*BaseProvider
	baseURL string
	token   string
	client  *http.Client
}

func NewWorkdayProvider() *WorkdayProvider {
	return &WorkdayProvider{
		BaseProvider: NewBaseProvider("workday", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (w *WorkdayProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := w.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	w.baseURL = strings.TrimSpace(w.GetConfigString("url"))
	if w.baseURL == "" {
		w.baseURL = strings.TrimSpace(w.GetConfigString("base_url"))
	}
	if w.baseURL == "" {
		w.baseURL = strings.TrimSpace(w.GetConfigString("instance_url"))
	}
	if w.baseURL == "" {
		return fmt.Errorf("workday url required")
	}

	w.baseURL = strings.TrimSuffix(w.baseURL, "/")
	if !strings.Contains(strings.ToLower(w.baseURL), "/scim/") {
		w.baseURL += "/scim/v2"
	}

	w.token = strings.TrimSpace(w.GetConfigString("token"))
	if w.token == "" {
		w.token = strings.TrimSpace(w.GetConfigString("api_token"))
	}
	if w.token == "" {
		return fmt.Errorf("workday token required")
	}

	if err := validateWorkdayURL(w.baseURL); err != nil {
		return err
	}

	return nil
}

func (w *WorkdayProvider) Test(ctx context.Context) error {
	_, err := w.request(ctx, addQueryParams("/Users", map[string]string{
		"startIndex": "1",
		"count":      "1",
	}))
	return err
}

func (w *WorkdayProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "workday_users",
			Description: "Workday users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "given_name", Type: "string"},
				{Name: "family_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "employee_id", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "workday_groups",
			Description: "Workday groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "external_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "workday_group_memberships",
			Description: "Workday group membership mappings",
			Columns: []ColumnSchema{
				{Name: "group_id", Type: "string", Required: true},
				{Name: "user_id", Type: "string", Required: true},
			},
			PrimaryKey: []string{"group_id", "user_id"},
		},
	}
}

func (w *WorkdayProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(w.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (w *WorkdayProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  w.Name(),
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

	syncTable("users", w.syncUsers)
	syncTable("groups", w.syncGroups)
	syncTable("group_memberships", w.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (w *WorkdayProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := w.schemaFor("workday_users")
	result := &TableResult{Name: "workday_users"}
	if err != nil {
		return result, err
	}

	users, err := w.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeWorkdayRow(user)
		name := workdayMap(normalized["name"])
		meta := workdayMap(normalized["meta"])
		emails := workdayMapSlice(normalized["emails"])
		enterprise := workdayEnterpriseExtension(normalized)

		userID := firstWorkdayString(normalized, "id", "external_id", "user_name")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           userID,
			"username":     firstWorkdayValue(normalized, "user_name", "username"),
			"given_name":   firstNonNilWorkdayValue(firstWorkdayValue(name, "given_name"), firstWorkdayValue(normalized, "given_name")),
			"family_name":  firstNonNilWorkdayValue(firstWorkdayValue(name, "family_name"), firstWorkdayValue(normalized, "family_name")),
			"display_name": firstWorkdayValue(normalized, "display_name"),
			"email": firstNonNilWorkdayValue(
				workdayPrimaryCollectionValue(emails, "value"),
				firstWorkdayValue(normalized, "email", "email_address"),
			),
			"active": firstWorkdayValue(normalized, "active"),
			"employee_id": firstNonNilWorkdayValue(
				firstWorkdayValue(normalized, "employee_id", "employee_number", "worker_id"),
				firstWorkdayValue(enterprise, "employee_id", "employee_number", "worker_id"),
			),
			"department": firstNonNilWorkdayValue(
				firstWorkdayValue(normalized, "department", "organization"),
				firstWorkdayValue(enterprise, "department", "organization"),
			),
			"title": firstNonNilWorkdayValue(
				firstWorkdayValue(normalized, "title", "job_title"),
				firstWorkdayValue(enterprise, "title", "job_title"),
			),
			"created_at": firstNonNilWorkdayValue(
				firstWorkdayValue(meta, "created"),
				firstWorkdayValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilWorkdayValue(
				firstWorkdayValue(meta, "last_modified", "updated"),
				firstWorkdayValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return w.syncTable(ctx, schema, rows)
}

func (w *WorkdayProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := w.schemaFor("workday_groups")
	result := &TableResult{Name: "workday_groups"}
	if err != nil {
		return result, err
	}

	groups, err := w.listGroups(ctx)
	if err != nil {
		if isWorkdayIgnorableError(err) {
			return w.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeWorkdayRow(group)
		meta := workdayMap(normalized["meta"])

		groupID := firstWorkdayString(normalized, "id", "external_id", "display_name")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           groupID,
			"display_name": firstWorkdayValue(normalized, "display_name", "name"),
			"external_id":  firstWorkdayValue(normalized, "external_id"),
			"created_at": firstNonNilWorkdayValue(
				firstWorkdayValue(meta, "created"),
				firstWorkdayValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilWorkdayValue(
				firstWorkdayValue(meta, "last_modified", "updated"),
				firstWorkdayValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return w.syncTable(ctx, schema, rows)
}

func (w *WorkdayProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := w.schemaFor("workday_group_memberships")
	result := &TableResult{Name: "workday_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := w.listGroups(ctx)
	if err != nil {
		if isWorkdayIgnorableError(err) {
			return w.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})
	for _, group := range groups {
		normalized := normalizeWorkdayRow(group)
		groupID := firstWorkdayString(normalized, "id")
		if groupID == "" {
			continue
		}

		members := workdayMapSlice(normalized["members"])
		for _, member := range members {
			normalizedMember := normalizeWorkdayRow(member)
			userID := firstWorkdayString(normalizedMember, "value", "id", "user_id")
			if userID == "" {
				continue
			}

			key := groupID + "|" + userID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"group_id": groupID,
				"user_id":  userID,
			})
		}
	}

	return w.syncTable(ctx, schema, rows)
}

func (w *WorkdayProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return w.listSCIMResources(ctx, "/Users")
}

func (w *WorkdayProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return w.listSCIMResources(ctx, "/Groups")
}

func (w *WorkdayProvider) listSCIMResources(ctx context.Context, resourcePath string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	startIndex := 1
	seenStartIndices := make(map[int]struct{})

	for page := 0; page < workdayMaxPages; page++ {
		if _, exists := seenStartIndices[startIndex]; exists {
			return nil, fmt.Errorf("workday pagination loop detected for %s", resourcePath)
		}
		seenStartIndices[startIndex] = struct{}{}

		requestPath := addQueryParams(resourcePath, map[string]string{
			"startIndex": strconv.Itoa(startIndex),
			"count":      strconv.Itoa(workdayDefaultPageSize),
		})

		body, err := w.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalizedPayload := normalizeWorkdayRow(payload)
		resources := workdayExtractResources(normalizedPayload)
		for _, resource := range resources {
			rows = append(rows, normalizeWorkdayRow(resource))
		}

		if len(resources) == 0 {
			break
		}

		totalResults := firstWorkdayInt(normalizedPayload, "total_results", "totalresults")
		itemsPerPage := firstWorkdayInt(normalizedPayload, "items_per_page", "itemsperpage")
		if itemsPerPage <= 0 {
			itemsPerPage = len(resources)
		}

		nextStartIndex := startIndex + len(resources)
		if nextStartIndex <= startIndex {
			return nil, fmt.Errorf("workday pagination loop detected for %s", resourcePath)
		}

		if totalResults > 0 {
			if nextStartIndex > totalResults {
				break
			}
		} else if len(resources) < itemsPerPage || len(resources) < workdayDefaultPageSize {
			break
		}

		startIndex = nextStartIndex
	}

	return rows, nil
}

func (w *WorkdayProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := workdayResolveRequestURL(w.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("workday API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func workdayResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("workday request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid workday URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid workday base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("workday request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateWorkdayURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid workday url %q", rawURL)
	}
	return nil
}

func normalizeWorkdayRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func workdayMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func workdayMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if normalized, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, normalized)
			}
		}
		return rows
	default:
		return nil
	}
}

func workdayExtractResources(payload map[string]interface{}) []map[string]interface{} {
	if resources := workdayMapSlice(payload["resources"]); len(resources) > 0 {
		return resources
	}
	if resources := workdayMapSlice(payload["result"]); len(resources) > 0 {
		return resources
	}
	if resource := workdayMap(payload["resource"]); len(resource) > 0 {
		return []map[string]interface{}{resource}
	}
	return nil
}

func workdayEnterpriseExtension(row map[string]interface{}) map[string]interface{} {
	for key, value := range row {
		if strings.Contains(key, "enterprise") {
			if extension := workdayMap(value); len(extension) > 0 {
				return extension
			}
		}
	}
	return nil
}

func workdayPrimaryCollectionValue(items []map[string]interface{}, keys ...string) interface{} {
	for _, primaryOnly := range []bool{true, false} {
		for _, item := range items {
			normalized := normalizeWorkdayRow(item)
			if primaryOnly && !workdayBool(normalized["primary"]) {
				continue
			}
			if value := firstWorkdayValue(normalized, keys...); value != nil {
				return value
			}
		}
	}
	return nil
}

func firstWorkdayString(row map[string]interface{}, keys ...string) string {
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

func firstWorkdayValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilWorkdayValue(values ...interface{}) interface{} {
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

func firstWorkdayInt(row map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		parsed, ok := parseWorkdayInt(value)
		if ok {
			return parsed
		}
	}
	return 0
}

func parseWorkdayInt(value interface{}) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	default:
		text := strings.TrimSpace(providerStringValue(value))
		if text == "" {
			return 0, false
		}
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
}

func workdayBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		text := strings.ToLower(strings.TrimSpace(providerStringValue(value)))
		return text == "1" || text == "true" || text == "yes"
	}
}

func isWorkdayIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
