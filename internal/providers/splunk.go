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
	splunkDefaultPageSize = 200
	splunkMaxPages        = 500
)

// SplunkProvider syncs Splunk users, roles, and index metadata.
type SplunkProvider struct {
	*BaseProvider
	baseURL string
	token   string
	client  *http.Client
}

func NewSplunkProvider() *SplunkProvider {
	return &SplunkProvider{
		BaseProvider: NewBaseProvider("splunk", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SplunkProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.baseURL = strings.TrimSpace(s.GetConfigString("url"))
	if s.baseURL == "" {
		s.baseURL = strings.TrimSpace(s.GetConfigString("base_url"))
	}
	s.baseURL = strings.TrimSuffix(s.baseURL, "/")
	if s.baseURL == "" {
		return fmt.Errorf("splunk url required")
	}

	s.token = strings.TrimSpace(s.GetConfigString("token"))
	if s.token == "" {
		s.token = strings.TrimSpace(s.GetConfigString("api_token"))
	}
	if s.token == "" {
		return fmt.Errorf("splunk token required")
	}

	if err := validateSplunkURL(s.baseURL); err != nil {
		return err
	}

	return nil
}

func (s *SplunkProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/services/server/info?output_mode=json")
	return err
}

func (s *SplunkProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "splunk_users",
			Description: "Splunk users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "real_name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "roles", Type: "variant"},
				{Name: "default_app", Type: "string"},
				{Name: "timezone", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "splunk_roles",
			Description: "Splunk roles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "imported_roles", Type: "variant"},
				{Name: "srch_filter", Type: "string"},
				{Name: "srch_indexes_allowed", Type: "variant"},
				{Name: "srch_indexes_default", Type: "variant"},
				{Name: "cumulative_srch_jobs_quota", Type: "integer"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "splunk_indexes",
			Description: "Splunk indexes",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "datatype", Type: "string"},
				{Name: "max_total_data_size_mb", Type: "integer"},
				{Name: "home_path", Type: "string"},
				{Name: "cold_path", Type: "string"},
				{Name: "thawed_path", Type: "string"},
				{Name: "frozen_time_period_secs", Type: "integer"},
				{Name: "is_internal", Type: "boolean"},
				{Name: "disabled", Type: "boolean"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SplunkProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(s.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (s *SplunkProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
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
	syncTable("roles", s.syncRoles)
	syncTable("indexes", s.syncIndexes)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (s *SplunkProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("splunk_users")
	result := &TableResult{Name: "splunk_users"}
	if err != nil {
		return result, err
	}

	users, err := s.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeSplunkRow(user)
		content := splunkMap(normalized["content"])

		userID := firstSplunkString(normalized, "id", "name")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":          userID,
			"name":        firstSplunkValue(normalized, "name"),
			"real_name":   firstSplunkValue(content, "real_name", "realname"),
			"email":       firstSplunkValue(content, "email"),
			"roles":       firstSplunkValue(content, "roles"),
			"default_app": firstSplunkValue(content, "default_app", "defaultapp"),
			"timezone":    firstSplunkValue(content, "timezone", "tz"),
			"status": firstNonNilSplunkValue(
				firstSplunkValue(content, "status", "state"),
				firstSplunkValue(content, "locked_out", "lockedout"),
			),
			"created_at": firstSplunkValue(normalized, "published", "created_at"),
			"updated_at": firstSplunkValue(normalized, "updated", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SplunkProvider) syncRoles(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("splunk_roles")
	result := &TableResult{Name: "splunk_roles"}
	if err != nil {
		return result, err
	}

	roles, err := s.listRoles(ctx)
	if err != nil {
		if isSplunkIgnorableError(err) {
			return s.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		normalized := normalizeSplunkRow(role)
		content := splunkMap(normalized["content"])

		roleID := firstSplunkString(normalized, "id", "name")
		if roleID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":                         roleID,
			"name":                       firstSplunkValue(normalized, "name"),
			"imported_roles":             firstSplunkValue(content, "imported_roles"),
			"srch_filter":                firstSplunkValue(content, "srch_filter"),
			"srch_indexes_allowed":       firstSplunkValue(content, "srch_indexes_allowed"),
			"srch_indexes_default":       firstSplunkValue(content, "srch_indexes_default"),
			"cumulative_srch_jobs_quota": firstSplunkValue(content, "cumulative_srch_jobs_quota"),
			"updated_at":                 firstSplunkValue(normalized, "updated", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SplunkProvider) syncIndexes(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("splunk_indexes")
	result := &TableResult{Name: "splunk_indexes"}
	if err != nil {
		return result, err
	}

	indexes, err := s.listIndexes(ctx)
	if err != nil {
		if isSplunkIgnorableError(err) {
			return s.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(indexes))
	for _, index := range indexes {
		normalized := normalizeSplunkRow(index)
		content := splunkMap(normalized["content"])

		indexID := firstSplunkString(normalized, "id", "name")
		if indexID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":                      indexID,
			"name":                    firstSplunkValue(normalized, "name"),
			"datatype":                firstSplunkValue(content, "datatype"),
			"max_total_data_size_mb":  firstSplunkValue(content, "max_total_data_size_mb"),
			"home_path":               firstSplunkValue(content, "home_path"),
			"cold_path":               firstSplunkValue(content, "cold_path"),
			"thawed_path":             firstSplunkValue(content, "thawed_path"),
			"frozen_time_period_secs": firstNonNilSplunkValue(firstSplunkValue(content, "frozen_time_period_secs"), firstSplunkValue(content, "frozen_time_period_in_secs")),
			"is_internal":             firstSplunkValue(content, "is_internal", "internal"),
			"disabled":                firstSplunkValue(content, "disabled"),
			"updated_at":              firstSplunkValue(normalized, "updated", "updated_at"),
		})
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SplunkProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return s.listEntries(ctx, "/services/authentication/users")
}

func (s *SplunkProvider) listRoles(ctx context.Context) ([]map[string]interface{}, error) {
	return s.listEntries(ctx, "/services/authorization/roles")
}

func (s *SplunkProvider) listIndexes(ctx context.Context) ([]map[string]interface{}, error) {
	return s.listEntries(ctx, "/services/data/indexes")
}

func (s *SplunkProvider) listEntries(ctx context.Context, path string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	offset := 0

	for page := 0; page < splunkMaxPages; page++ {
		requestPath := addQueryParams(path, map[string]string{
			"output_mode": "json",
			"count":       strconv.Itoa(splunkDefaultPageSize),
			"offset":      strconv.Itoa(offset),
		})

		body, err := s.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalized := normalizeSplunkRow(payload)
		entries := splunkEntries(normalized["entry"])
		for _, entry := range entries {
			rows = append(rows, normalizeSplunkRow(entry))
		}

		if len(entries) < splunkDefaultPageSize {
			break
		}

		nextOffset := offset + len(entries)
		if nextOffset <= offset {
			return nil, fmt.Errorf("splunk pagination loop detected for %s", path)
		}
		offset = nextOffset
	}

	return rows, nil
}

func (s *SplunkProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := splunkResolveRequestURL(s.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", splunkAuthorizationHeader(s.token))
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
		return nil, fmt.Errorf("splunk API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func splunkAuthorizationHeader(token string) string {
	trimmed := strings.TrimSpace(token)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "splunk ") || strings.HasPrefix(lower, "bearer ") {
		return trimmed
	}
	return "Splunk " + trimmed
}

func splunkResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("splunk request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid splunk URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid splunk base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("splunk request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateSplunkURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid splunk url %q", rawURL)
	}
	return nil
}

func normalizeSplunkRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func splunkMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func splunkEntries(value interface{}) []map[string]interface{} {
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

func firstSplunkString(row map[string]interface{}, keys ...string) string {
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

func firstSplunkValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilSplunkValue(values ...interface{}) interface{} {
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

func isSplunkIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
