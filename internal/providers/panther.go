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

const pantherDefaultAPIURL = "https://api.runpanther.io/public_api/v1"

// PantherProvider syncs Panther alert, rule, and user metadata.
type PantherProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewPantherProvider() *PantherProvider {
	return &PantherProvider{
		BaseProvider: NewBaseProvider("panther", ProviderTypeSaaS),
		baseURL:      pantherDefaultAPIURL,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *PantherProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := p.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	p.apiToken = strings.TrimSpace(p.GetConfigString("api_token"))
	if baseURL := strings.TrimSpace(p.GetConfigString("base_url")); baseURL != "" {
		p.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	if p.apiToken == "" {
		return fmt.Errorf("panther api_token required")
	}
	if err := validatePantherURL(p.baseURL); err != nil {
		return err
	}

	return nil
}

func (p *PantherProvider) Test(ctx context.Context) error {
	_, err := p.request(ctx, "/alerts?limit=1")
	return err
}

func (p *PantherProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "panther_users",
			Description: "Panther users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "panther_rules",
			Description: "Panther detection rules",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "enabled", Type: "boolean"},
				{Name: "log_types", Type: "variant"},
				{Name: "last_modified", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "panther_alerts",
			Description: "Panther alerts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "title", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "log_type", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (p *PantherProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(p.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (p *PantherProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  p.Name(),
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

	syncTable("users", p.syncUsers)
	syncTable("rules", p.syncRules)
	syncTable("alerts", p.syncAlerts)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (p *PantherProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("panther_users")
	result := &TableResult{Name: "panther_users"}
	if err != nil {
		return result, err
	}

	users, err := p.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizePantherRow(user)
		userID := firstPantherString(normalized, "id", "user_id", "email")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":         userID,
			"email":      firstPantherValue(normalized, "email"),
			"name":       firstPantherValue(normalized, "name", "full_name", "display_name"),
			"role":       firstPantherValue(normalized, "role", "user_role"),
			"status":     firstPantherValue(normalized, "status", "state"),
			"created_at": firstPantherValue(normalized, "created_at", "created"),
		})
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PantherProvider) syncRules(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("panther_rules")
	result := &TableResult{Name: "panther_rules"}
	if err != nil {
		return result, err
	}

	rules, err := p.listRules(ctx)
	if err != nil {
		if isPantherIgnorableError(err) {
			return p.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		normalized := normalizePantherRow(rule)
		ruleID := firstPantherString(normalized, "id", "rule_id", "name", "display_name")
		if ruleID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           ruleID,
			"display_name": firstPantherValue(normalized, "display_name", "name", "rule_name"),
			"severity":     firstPantherValue(normalized, "severity", "priority"),
			"enabled":      firstPantherValue(normalized, "enabled", "is_enabled"),
			"log_types":    firstNonNilPantherValue(firstPantherValue(normalized, "log_types"), firstPantherValue(normalized, "log_type")),
			"last_modified": firstPantherValue(
				normalized,
				"last_modified",
				"updated_at",
				"modified_at",
			),
		})
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PantherProvider) syncAlerts(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("panther_alerts")
	result := &TableResult{Name: "panther_alerts"}
	if err != nil {
		return result, err
	}

	alerts, err := p.listAlerts(ctx)
	if err != nil {
		if isPantherIgnorableError(err) {
			return p.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(alerts))
	for _, alert := range alerts {
		normalized := normalizePantherRow(alert)
		alertID := firstPantherString(normalized, "id", "alert_id", "detection_id", "event_id")
		if alertID == "" {
			continue
		}

		rule := pantherMap(normalized["rule"])

		rows = append(rows, map[string]interface{}{
			"id":       alertID,
			"title":    firstPantherValue(normalized, "title", "name", "description"),
			"severity": firstPantherValue(normalized, "severity", "priority"),
			"status":   firstPantherValue(normalized, "status", "state"),
			"rule_id": firstNonNilPantherValue(
				firstPantherValue(normalized, "rule_id"),
				firstPantherValue(rule, "id", "rule_id", "name"),
			),
			"log_type": firstNonNilPantherValue(
				firstPantherValue(normalized, "log_type", "log_source"),
				firstPantherValue(rule, "log_type"),
			),
			"created_at": firstPantherValue(normalized, "created_at", "created", "first_seen_at"),
			"updated_at": firstPantherValue(normalized, "updated_at", "last_seen_at", "resolved_at"),
		})
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PantherProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return p.listCollection(ctx, "/users", "users")
}

func (p *PantherProvider) listRules(ctx context.Context) ([]map[string]interface{}, error) {
	return p.listCollection(ctx, "/rules", "rules")
}

func (p *PantherProvider) listAlerts(ctx context.Context) ([]map[string]interface{}, error) {
	return p.listCollection(ctx, "/alerts", "alerts")
}

func (p *PantherProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"limit": "200"})
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextCursor != "" {
			requestPath = pantherCursorPath(basePath, nextCursor)
		}

		body, err := p.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizePantherRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizePantherRow(payload)
		items := pantherExtractItems(normalized, primaryKey, "items", "data", "results", "values", "entities")
		for _, item := range items {
			rows = append(rows, normalizePantherRow(item))
		}

		cursor := pantherNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("panther pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (p *PantherProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := pantherResolveRequestURL(p.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", p.apiToken)
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("panther API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizePantherRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func pantherMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func pantherMapSlice(value interface{}) []map[string]interface{} {
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

func pantherExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := pantherMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func pantherNextCursor(payload map[string]interface{}) string {
	if cursor := firstPantherString(payload, "next_cursor", "cursor", "next_token", "next", "offset"); cursor != "" {
		return cursor
	}

	if links := pantherMap(payload["links"]); len(links) > 0 {
		if cursor := firstPantherString(links, "next", "next_url", "next_page"); cursor != "" {
			return cursor
		}
	}

	if page := pantherMap(payload["page"]); len(page) > 0 {
		if cursor := firstPantherString(page, "next_cursor", "cursor", "next_token", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if paging := pantherMap(payload["paging"]); len(paging) > 0 {
		if cursor := firstPantherString(paging, "next_cursor", "cursor", "next_token", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if pagination := pantherMap(payload["pagination"]); len(pagination) > 0 {
		if cursor := firstPantherString(pagination, "next_cursor", "cursor", "next_token", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if metadata := pantherMap(payload["metadata"]); len(metadata) > 0 {
		if cursor := firstPantherString(metadata, "next_cursor", "cursor", "next_token", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	return ""
}

func pantherCursorPath(basePath string, cursor string) string {
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

func pantherResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("panther request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid panther pagination URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid panther base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Host, resolved.Host) || !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) {
			return "", fmt.Errorf("panther pagination URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func firstPantherString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstPantherValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilPantherValue(values ...interface{}) interface{} {
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

func isPantherIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validatePantherURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid panther base_url %q", rawURL)
	}
	return nil
}
