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

const socketDefaultAPIURL = "https://api.socket.dev/v0"

// SocketProvider syncs Socket organization, repository, and alert metadata.
type SocketProvider struct {
	*BaseProvider
	apiToken string
	orgSlug  string
	baseURL  string
	client   *http.Client
}

func NewSocketProvider() *SocketProvider {
	return &SocketProvider{
		BaseProvider: NewBaseProvider("socket", ProviderTypeSaaS),
		baseURL:      socketDefaultAPIURL,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (s *SocketProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiToken = strings.TrimSpace(s.GetConfigString("api_token"))
	s.orgSlug = strings.TrimSpace(s.GetConfigString("org_slug"))
	if apiURL := strings.TrimSpace(s.GetConfigString("api_url")); apiURL != "" {
		s.baseURL = strings.TrimSuffix(apiURL, "/")
	}

	if s.apiToken == "" {
		return fmt.Errorf("socket api_token required")
	}
	if err := validateSocketURL(s.baseURL); err != nil {
		return err
	}

	return nil
}

func (s *SocketProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/orgs")
	return err
}

func (s *SocketProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "socket_orgs",
			Description: "Socket organizations",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "slug", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "plan", Type: "string"},
				{Name: "status", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "socket_repos",
			Description: "Socket repositories",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "org_id", Type: "string"},
				{Name: "org_slug", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "full_name", Type: "string"},
				{Name: "default_branch", Type: "string"},
				{Name: "visibility", Type: "string"},
				{Name: "archived", Type: "boolean"},
				{Name: "last_synced_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "socket_alerts",
			Description: "Socket alerts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "org_id", Type: "string"},
				{Name: "org_slug", Type: "string"},
				{Name: "repo_id", Type: "string"},
				{Name: "repo_name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "package_name", Type: "string"},
				{Name: "ecosystem", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SocketProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(s.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (s *SocketProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	syncRows := func(tableName string, rows []map[string]interface{}) {
		schema, err := s.schemaFor(tableName)
		if err != nil {
			result.Errors = append(result.Errors, tableName+": "+err.Error())
			return
		}
		table, err := s.syncTable(ctx, schema, rows)
		if err != nil {
			result.Errors = append(result.Errors, tableName+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	orgs, err := s.listOrganizations(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "organizations: "+err.Error())
	} else {
		orgs = s.filterOrganizations(orgs)
		syncRows("socket_orgs", s.buildOrganizationRows(orgs))

		repoRows, alertRows := s.buildChildRows(ctx, orgs, &result.Errors)
		syncRows("socket_repos", repoRows)
		syncRows("socket_alerts", alertRows)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (s *SocketProvider) filterOrganizations(orgs []map[string]interface{}) []map[string]interface{} {
	if s.orgSlug == "" {
		return orgs
	}

	filtered := make([]map[string]interface{}, 0)
	for _, org := range orgs {
		normalized := normalizeSocketRow(org)
		slug := strings.ToLower(firstSocketString(normalized, "slug", "name", "id"))
		if slug == strings.ToLower(s.orgSlug) {
			filtered = append(filtered, org)
		}
	}

	if len(filtered) == 0 {
		return []map[string]interface{}{{
			"id":   s.orgSlug,
			"slug": s.orgSlug,
			"name": s.orgSlug,
		}}
	}

	return filtered
}

func (s *SocketProvider) buildOrganizationRows(orgs []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0, len(orgs))
	for _, org := range orgs {
		row := normalizeSocketRow(org)
		orgID := firstSocketString(row, "id", "slug", "name")
		if orgID == "" {
			continue
		}
		row["id"] = orgID
		rows = append(rows, row)
	}
	return rows
}

func (s *SocketProvider) buildChildRows(ctx context.Context, orgs []map[string]interface{}, errors *[]string) ([]map[string]interface{}, []map[string]interface{}) {
	repoRows := make([]map[string]interface{}, 0)
	alertRows := make([]map[string]interface{}, 0)
	seenRepos := make(map[string]struct{})
	seenAlerts := make(map[string]struct{})

	for _, org := range orgs {
		normalizedOrg := normalizeSocketRow(org)
		orgID := firstSocketString(normalizedOrg, "id", "slug", "name")
		orgSlug := firstSocketString(normalizedOrg, "slug", "name", "id")
		if s.orgSlug != "" {
			orgSlug = s.orgSlug
		}
		if orgID == "" {
			orgID = orgSlug
		}
		if orgSlug == "" {
			continue
		}

		repos, err := s.listOrganizationRepos(ctx, orgSlug)
		if err != nil {
			if !isSocketIgnorableError(err) {
				*errors = append(*errors, "repos("+orgSlug+"): "+err.Error())
			}
		} else {
			for _, repo := range repos {
				normalizedRepo := normalizeSocketRow(repo)
				repoID := firstSocketString(normalizedRepo, "id", "repository_id", "full_name", "name")
				if repoID == "" {
					continue
				}

				rowID := orgID + "|" + repoID
				if _, ok := seenRepos[rowID]; ok {
					continue
				}
				seenRepos[rowID] = struct{}{}

				repoRows = append(repoRows, map[string]interface{}{
					"id":             rowID,
					"org_id":         orgID,
					"org_slug":       orgSlug,
					"name":           firstSocketValue(normalizedRepo, "name"),
					"full_name":      firstSocketValue(normalizedRepo, "full_name", "name_with_owner"),
					"default_branch": firstSocketValue(normalizedRepo, "default_branch"),
					"visibility":     firstSocketValue(normalizedRepo, "visibility"),
					"archived":       firstSocketValue(normalizedRepo, "archived", "is_archived"),
					"last_synced_at": firstSocketValue(normalizedRepo, "last_synced_at", "updated_at"),
				})
			}
		}

		alerts, err := s.listOrganizationAlerts(ctx, orgSlug)
		if err != nil {
			if !isSocketIgnorableError(err) {
				*errors = append(*errors, "alerts("+orgSlug+"): "+err.Error())
			}
			continue
		}

		for _, alert := range alerts {
			normalizedAlert := normalizeSocketRow(alert)
			alertID := firstSocketString(normalizedAlert, "id", "alert_id", "key")
			if alertID == "" {
				continue
			}

			rowID := orgID + "|" + alertID
			if _, ok := seenAlerts[rowID]; ok {
				continue
			}
			seenAlerts[rowID] = struct{}{}

			repoMap := socketMap(normalizedAlert["repository"])
			if len(repoMap) == 0 {
				repoMap = socketMap(normalizedAlert["repo"])
			}
			packageMap := socketMap(normalizedAlert["package"])

			alertRows = append(alertRows, map[string]interface{}{
				"id":           rowID,
				"org_id":       orgID,
				"org_slug":     orgSlug,
				"repo_id":      firstSocketValue(normalizedAlert, "repo_id", "repository_id", "project_id", "source_repo_id", "source_repository_id"),
				"repo_name":    firstNonNilSocketValue(firstSocketValue(repoMap, "name", "full_name", "slug"), firstSocketValue(normalizedAlert, "repo_name", "repository_name", "project_name")),
				"type":         firstSocketValue(normalizedAlert, "type", "alert_type", "category"),
				"severity":     firstSocketValue(normalizedAlert, "severity", "risk_level"),
				"status":       firstSocketValue(normalizedAlert, "status", "state"),
				"package_name": firstNonNilSocketValue(firstSocketValue(packageMap, "name", "purl"), firstSocketValue(normalizedAlert, "package_name", "dependency_name", "package")),
				"ecosystem":    firstNonNilSocketValue(firstSocketValue(packageMap, "ecosystem"), firstSocketValue(normalizedAlert, "ecosystem", "package_ecosystem")),
				"created_at":   firstSocketValue(normalizedAlert, "created_at", "first_seen_at"),
				"updated_at":   firstSocketValue(normalizedAlert, "updated_at", "last_seen_at"),
			})
		}
	}

	return repoRows, alertRows
}

func firstNonNilSocketValue(values ...interface{}) interface{} {
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

func (s *SocketProvider) listOrganizations(ctx context.Context) ([]map[string]interface{}, error) {
	return s.listCollection(ctx, "/orgs", "orgs")
}

func (s *SocketProvider) listOrganizationRepos(ctx context.Context, orgSlug string) ([]map[string]interface{}, error) {
	path := "/orgs/" + url.PathEscape(orgSlug) + "/repos"
	return s.listCollection(ctx, path, "repos")
}

func (s *SocketProvider) listOrganizationAlerts(ctx context.Context, orgSlug string) ([]map[string]interface{}, error) {
	path := "/orgs/" + url.PathEscape(orgSlug) + "/alerts"
	return s.listCollection(ctx, path, "alerts")
}

func (s *SocketProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := path
		if nextCursor != "" {
			requestPath = addQueryParams(path, map[string]string{"cursor": nextCursor})
		}

		body, err := s.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeSocketRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeSocketRow(payload)
		items := socketExtractItems(normalized, primaryKey, "items", "data", "results", "values")
		for _, item := range items {
			rows = append(rows, normalizeSocketRow(item))
		}

		cursor := socketNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("socket pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (s *SocketProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL := s.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
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
		return nil, fmt.Errorf("socket API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeSocketRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func socketMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func socketMapSlice(value interface{}) []map[string]interface{} {
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

func socketExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := socketMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func socketNextCursor(payload map[string]interface{}) string {
	if cursor := firstSocketString(payload, "next_cursor", "next_page_token", "cursor", "next"); cursor != "" {
		return cursor
	}
	if pagination := socketMap(payload["pagination"]); len(pagination) > 0 {
		return firstSocketString(pagination, "next_cursor", "next_page_token", "cursor", "next")
	}
	return ""
}

func firstSocketString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstSocketValue(row map[string]interface{}, keys ...string) interface{} {
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

func isSocketIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateSocketURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid socket api_url %q", rawURL)
	}
	return nil
}
