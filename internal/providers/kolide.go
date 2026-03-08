package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const kolideDefaultAPIURL = "https://api.kolide.com/v1"

// KolideProvider syncs Kolide identity, device, and issue metadata.
type KolideProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewKolideProvider() *KolideProvider {
	return &KolideProvider{
		BaseProvider: NewBaseProvider("kolide", ProviderTypeSaaS),
		baseURL:      kolideDefaultAPIURL,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (k *KolideProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := k.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	k.apiToken = strings.TrimSpace(k.GetConfigString("api_token"))
	if baseURL := strings.TrimSpace(k.GetConfigString("base_url")); baseURL != "" {
		k.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	if k.apiToken == "" {
		return fmt.Errorf("kolide api_token required")
	}
	if err := validateKolideURL(k.baseURL); err != nil {
		return err
	}

	return nil
}

func (k *KolideProvider) Test(ctx context.Context) error {
	_, err := k.request(ctx, "/users?limit=1")
	return err
}

func (k *KolideProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "kolide_users",
			Description: "Kolide users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "last_seen_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "kolide_devices",
			Description: "Kolide devices",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "hostname", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "last_seen_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "kolide_issues",
			Description: "Kolide issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "title", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "device_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "resolved_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (k *KolideProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(k.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (k *KolideProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  k.Name(),
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

	syncTable("users", k.syncUsers)
	syncTable("devices", k.syncDevices)
	syncTable("issues", k.syncIssues)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (k *KolideProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kolide_users")
	result := &TableResult{Name: "kolide_users"}
	if err != nil {
		return result, err
	}

	users, err := k.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeKolideRow(user)
		userID := firstKolideString(normalized, "id", "user_id", "email")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           userID,
			"email":        firstKolideValue(normalized, "email"),
			"name":         firstKolideValue(normalized, "name", "full_name", "display_name"),
			"role":         firstKolideValue(normalized, "role", "user_role"),
			"status":       firstKolideValue(normalized, "status", "state"),
			"last_seen_at": firstKolideValue(normalized, "last_seen_at", "last_seen", "updated_at"),
		})
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KolideProvider) syncDevices(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kolide_devices")
	result := &TableResult{Name: "kolide_devices"}
	if err != nil {
		return result, err
	}

	devices, err := k.listDevices(ctx)
	if err != nil {
		if isKolideIgnorableError(err) {
			return k.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(devices))
	for _, device := range devices {
		normalized := normalizeKolideRow(device)
		deviceID := firstKolideString(normalized, "id", "device_id", "host_id", "hostname")
		if deviceID == "" {
			continue
		}

		owner := kolideMap(normalized["owner"])
		user := kolideMap(normalized["user"])

		rows = append(rows, map[string]interface{}{
			"id":         deviceID,
			"hostname":   firstKolideValue(normalized, "hostname", "name"),
			"platform":   firstKolideValue(normalized, "platform", "os", "operating_system"),
			"os_version": firstKolideValue(normalized, "os_version", "version"),
			"user_email": firstNonNilKolideValue(
				firstKolideValue(normalized, "user_email"),
				firstKolideValue(owner, "email"),
				firstKolideValue(user, "email"),
			),
			"last_seen_at": firstKolideValue(normalized, "last_seen_at", "last_seen", "updated_at"),
		})
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KolideProvider) syncIssues(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kolide_issues")
	result := &TableResult{Name: "kolide_issues"}
	if err != nil {
		return result, err
	}

	issues, err := k.listIssues(ctx)
	if err != nil {
		if isKolideIgnorableError(err) {
			return k.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(issues))
	for _, issue := range issues {
		normalized := normalizeKolideRow(issue)
		issueID := firstKolideString(normalized, "id", "issue_id", "finding_id", "alert_id")
		if issueID == "" {
			continue
		}

		device := kolideMap(normalized["device"])

		rows = append(rows, map[string]interface{}{
			"id":       issueID,
			"title":    firstKolideValue(normalized, "title", "name", "summary"),
			"severity": firstKolideValue(normalized, "severity", "priority"),
			"status":   firstKolideValue(normalized, "status", "state"),
			"device_id": firstNonNilKolideValue(
				firstKolideValue(normalized, "device_id", "host_id"),
				firstKolideValue(device, "id", "device_id", "host_id"),
			),
			"created_at":  firstKolideValue(normalized, "created_at", "created", "first_seen_at"),
			"resolved_at": firstKolideValue(normalized, "resolved_at", "closed_at", "last_resolved_at"),
		})
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KolideProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return k.listCollection(ctx, "/users", "users")
}

func (k *KolideProvider) listDevices(ctx context.Context) ([]map[string]interface{}, error) {
	return k.listCollection(ctx, "/devices", "devices")
}

func (k *KolideProvider) listIssues(ctx context.Context) ([]map[string]interface{}, error) {
	return k.listCollection(ctx, "/issues", "issues")
}

func (k *KolideProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"limit": "200"})
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextCursor != "" {
			requestPath = kolideCursorPath(basePath, nextCursor)
		}

		body, err := k.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeKolideRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeKolideRow(payload)
		items := kolideExtractItems(normalized, primaryKey, "items", "data", "results", "values", "records")
		for _, item := range items {
			rows = append(rows, normalizeKolideRow(item))
		}

		cursor := kolideNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("kolide pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (k *KolideProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := kolideResolveRequestURL(k.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("kolide API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeKolideRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func kolideMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func kolideMapSlice(value interface{}) []map[string]interface{} {
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

func kolideExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := kolideMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func kolideNextCursor(payload map[string]interface{}) string {
	if cursor := firstKolideString(payload, "next_cursor", "cursor", "next", "next_token", "offset"); cursor != "" {
		return cursor
	}

	if links := kolideMap(payload["links"]); len(links) > 0 {
		if cursor := firstKolideString(links, "next", "next_url", "next_page"); cursor != "" {
			return cursor
		}
	}

	if page := kolideMap(payload["page"]); len(page) > 0 {
		if cursor := firstKolideString(page, "next_cursor", "cursor", "next", "next_token", "offset"); cursor != "" {
			return cursor
		}
	}

	if paging := kolideMap(payload["paging"]); len(paging) > 0 {
		if cursor := firstKolideString(paging, "next_cursor", "cursor", "next", "next_token", "offset"); cursor != "" {
			return cursor
		}
	}

	if pagination := kolideMap(payload["pagination"]); len(pagination) > 0 {
		if cursor := firstKolideString(pagination, "next_cursor", "cursor", "next", "next_token", "offset"); cursor != "" {
			return cursor
		}
	}

	if metadata := kolideMap(payload["metadata"]); len(metadata) > 0 {
		if cursor := firstKolideString(metadata, "next_cursor", "cursor", "next", "next_token", "offset"); cursor != "" {
			return cursor
		}
	}

	return ""
}

func kolideCursorPath(basePath string, cursor string) string {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return basePath
	}

	lower := strings.ToLower(cursor)
	if strings.HasPrefix(cursor, "/") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return cursor
	}

	return addQueryParams(basePath, map[string]string{"cursor": cursor})
}

func kolideResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("kolide request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid kolide pagination URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid kolide base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Host, resolved.Host) || !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) {
			return "", fmt.Errorf("kolide pagination URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func firstKolideString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstKolideValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilKolideValue(values ...interface{}) interface{} {
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

func isKolideIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateKolideURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid kolide base_url %q", rawURL)
	}
	return nil
}
