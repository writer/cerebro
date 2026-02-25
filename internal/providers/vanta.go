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

const vantaDefaultAPIURL = "https://api.vanta.com"

// VantaProvider syncs Vanta user, device, and alert metadata.
type VantaProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewVantaProvider() *VantaProvider {
	return &VantaProvider{
		BaseProvider: NewBaseProvider("vanta", ProviderTypeSaaS),
		baseURL:      vantaDefaultAPIURL,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (v *VantaProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := v.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	v.apiToken = strings.TrimSpace(v.GetConfigString("api_token"))
	if baseURL := strings.TrimSpace(v.GetConfigString("base_url")); baseURL != "" {
		v.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	if v.apiToken == "" {
		return fmt.Errorf("vanta api_token required")
	}
	if err := validateVantaURL(v.baseURL); err != nil {
		return err
	}

	return nil
}

func (v *VantaProvider) Test(ctx context.Context) error {
	_, err := v.request(ctx, "/v1/users?page_size=1")
	return err
}

func (v *VantaProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "vanta_users",
			Description: "Vanta users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "last_login_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "vanta_devices",
			Description: "Vanta devices",
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
			Name:        "vanta_alerts",
			Description: "Vanta alerts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "title", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "resolved_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (v *VantaProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(v.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (v *VantaProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  v.Name(),
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

	syncTable("users", v.syncUsers)
	syncTable("devices", v.syncDevices)
	syncTable("alerts", v.syncAlerts)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (v *VantaProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := v.schemaFor("vanta_users")
	result := &TableResult{Name: "vanta_users"}
	if err != nil {
		return result, err
	}

	users, err := v.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeVantaRow(user)
		userID := firstVantaString(normalized, "id", "user_id", "email")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":            userID,
			"email":         firstVantaValue(normalized, "email"),
			"name":          firstVantaValue(normalized, "name", "full_name"),
			"role":          firstVantaValue(normalized, "role", "user_role"),
			"status":        firstVantaValue(normalized, "status", "state"),
			"last_login_at": firstVantaValue(normalized, "last_login_at", "last_login"),
		})
	}

	return v.syncTable(ctx, schema, rows)
}

func (v *VantaProvider) syncDevices(ctx context.Context) (*TableResult, error) {
	schema, err := v.schemaFor("vanta_devices")
	result := &TableResult{Name: "vanta_devices"}
	if err != nil {
		return result, err
	}

	devices, err := v.listDevices(ctx)
	if err != nil {
		if isVantaIgnorableError(err) {
			return v.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(devices))
	for _, device := range devices {
		normalized := normalizeVantaRow(device)
		deviceID := firstVantaString(normalized, "id", "device_id", "hostname")
		if deviceID == "" {
			continue
		}

		owner := vantaMap(normalized["owner"])
		user := vantaMap(normalized["user"])

		rows = append(rows, map[string]interface{}{
			"id":         deviceID,
			"hostname":   firstVantaValue(normalized, "hostname", "name"),
			"platform":   firstVantaValue(normalized, "platform", "os", "operating_system"),
			"os_version": firstVantaValue(normalized, "os_version", "version"),
			"user_email": firstNonNilVantaValue(
				firstVantaValue(normalized, "user_email"),
				firstVantaValue(owner, "email"),
				firstVantaValue(user, "email"),
			),
			"last_seen_at": firstVantaValue(normalized, "last_seen_at", "last_seen", "updated_at"),
		})
	}

	return v.syncTable(ctx, schema, rows)
}

func (v *VantaProvider) syncAlerts(ctx context.Context) (*TableResult, error) {
	schema, err := v.schemaFor("vanta_alerts")
	result := &TableResult{Name: "vanta_alerts"}
	if err != nil {
		return result, err
	}

	alerts, err := v.listAlerts(ctx)
	if err != nil {
		if isVantaIgnorableError(err) {
			return v.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(alerts))
	for _, alert := range alerts {
		normalized := normalizeVantaRow(alert)
		alertID := firstVantaString(normalized, "id", "alert_id")
		if alertID == "" {
			continue
		}

		resource := vantaMap(normalized["resource"])

		rows = append(rows, map[string]interface{}{
			"id":       alertID,
			"title":    firstVantaValue(normalized, "title", "name"),
			"severity": firstVantaValue(normalized, "severity", "priority"),
			"status":   firstVantaValue(normalized, "status", "state"),
			"resource_type": firstNonNilVantaValue(
				firstVantaValue(normalized, "resource_type"),
				firstVantaValue(resource, "type"),
			),
			"created_at":  firstVantaValue(normalized, "created_at", "created"),
			"resolved_at": firstVantaValue(normalized, "resolved_at", "closed_at"),
		})
	}

	return v.syncTable(ctx, schema, rows)
}

func (v *VantaProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return v.listCollection(ctx, "/v1/users", "users")
}

func (v *VantaProvider) listDevices(ctx context.Context) ([]map[string]interface{}, error) {
	return v.listCollection(ctx, "/v1/devices", "devices")
}

func (v *VantaProvider) listAlerts(ctx context.Context) ([]map[string]interface{}, error) {
	return v.listCollection(ctx, "/v1/alerts", "alerts")
}

func (v *VantaProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"page_size": "200"})
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextCursor != "" {
			requestPath = addQueryParams(basePath, map[string]string{"cursor": nextCursor})
		}

		body, err := v.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeVantaRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeVantaRow(payload)
		items := vantaExtractItems(normalized, primaryKey, "records", "items", "data", "results", "values")
		for _, item := range items {
			rows = append(rows, normalizeVantaRow(item))
		}

		cursor := vantaNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("vanta pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (v *VantaProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL := v.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+v.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("vanta API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeVantaRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func vantaMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func vantaMapSlice(value interface{}) []map[string]interface{} {
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

func vantaExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := vantaMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func vantaNextCursor(payload map[string]interface{}) string {
	if cursor := firstVantaString(payload, "next_cursor", "cursor", "next", "offset"); cursor != "" {
		return cursor
	}

	if page := vantaMap(payload["page"]); len(page) > 0 {
		if cursor := firstVantaString(page, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if paging := vantaMap(payload["paging"]); len(paging) > 0 {
		if cursor := firstVantaString(paging, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if metadata := vantaMap(payload["metadata"]); len(metadata) > 0 {
		if cursor := firstVantaString(metadata, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	return ""
}

func firstVantaString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstVantaValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilVantaValue(values ...interface{}) interface{} {
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

func isVantaIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateVantaURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid vanta base_url %q", rawURL)
	}
	return nil
}
