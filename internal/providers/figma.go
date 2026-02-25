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

const figmaDefaultAPIURL = "https://api.figma.com"

// FigmaProvider syncs Figma project and team metadata.
type FigmaProvider struct {
	*BaseProvider
	apiToken string
	teamID   string
	baseURL  string
	client   *http.Client
}

func NewFigmaProvider() *FigmaProvider {
	return &FigmaProvider{
		BaseProvider: NewBaseProvider("figma", ProviderTypeSaaS),
		baseURL:      figmaDefaultAPIURL,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *FigmaProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := f.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	f.apiToken = strings.TrimSpace(f.GetConfigString("api_token"))
	f.teamID = strings.TrimSpace(f.GetConfigString("team_id"))
	if baseURL := strings.TrimSpace(f.GetConfigString("base_url")); baseURL != "" {
		f.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	if f.apiToken == "" || f.teamID == "" {
		return fmt.Errorf("figma api_token and team_id required")
	}
	if err := validateFigmaURL(f.baseURL); err != nil {
		return err
	}

	return nil
}

func (f *FigmaProvider) Test(ctx context.Context) error {
	_, err := f.request(ctx, "/v1/me")
	return err
}

func (f *FigmaProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "figma_projects",
			Description: "Figma team projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "team_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "figma_files",
			Description: "Figma files by project",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "project_id", Type: "string"},
				{Name: "project_name", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "thumbnail_url", Type: "string"},
				{Name: "last_modified", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "figma_team_members",
			Description: "Figma team members",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "team_id", Type: "string"},
				{Name: "handle", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "img_url", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "role", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (f *FigmaProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(f.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (f *FigmaProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  f.Name(),
		StartedAt: start,
	}

	syncRows := func(tableName string, rows []map[string]interface{}) {
		schema, err := f.schemaFor(tableName)
		if err != nil {
			result.Errors = append(result.Errors, tableName+": "+err.Error())
			return
		}
		table, err := f.syncTable(ctx, schema, rows)
		if err != nil {
			result.Errors = append(result.Errors, tableName+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	projects, err := f.listProjects(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "projects: "+err.Error())
	} else {
		syncRows("figma_projects", f.buildProjectRows(projects))
		syncRows("figma_files", f.buildFileRows(ctx, projects, &result.Errors))
	}

	members, err := f.listTeamMembers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "team_members: "+err.Error())
	} else {
		syncRows("figma_team_members", f.buildTeamMemberRows(members))
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (f *FigmaProvider) buildProjectRows(projects []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0, len(projects))
	for _, project := range projects {
		row := normalizeFigmaRow(project)
		projectID := firstFigmaString(row, "id", "project_id", "name")
		if projectID == "" {
			continue
		}
		row["id"] = projectID
		row["team_id"] = f.teamID
		rows = append(rows, row)
	}
	return rows
}

func (f *FigmaProvider) buildFileRows(ctx context.Context, projects []map[string]interface{}, errors *[]string) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, project := range projects {
		normalizedProject := normalizeFigmaRow(project)
		projectID := firstFigmaString(normalizedProject, "id", "project_id")
		if projectID == "" {
			continue
		}
		projectName := firstFigmaString(normalizedProject, "name")

		files, err := f.listProjectFiles(ctx, projectID)
		if err != nil {
			if isFigmaIgnorableError(err) {
				continue
			}
			*errors = append(*errors, "project_files("+projectID+"): "+err.Error())
			continue
		}

		for _, file := range files {
			normalizedFile := normalizeFigmaRow(file)
			fileID := firstFigmaString(normalizedFile, "key", "id", "name")
			if fileID == "" {
				continue
			}

			rowID := projectID + "|" + fileID
			if _, ok := seen[rowID]; ok {
				continue
			}
			seen[rowID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":           rowID,
				"project_id":   projectID,
				"project_name": projectName,
				"name":         firstFigmaValue(normalizedFile, "name"),
				"thumbnail_url": firstFigmaValue(normalizedFile,
					"thumbnail_url"),
				"last_modified": firstFigmaValue(normalizedFile,
					"last_modified"),
			})
		}
	}

	return rows
}

func (f *FigmaProvider) buildTeamMemberRows(members []map[string]interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0, len(members))
	for _, member := range members {
		normalizedMember := normalizeFigmaRow(member)

		if user := figmaMap(normalizedMember["user"]); len(user) > 0 {
			for key, value := range user {
				if _, exists := normalizedMember[key]; !exists {
					normalizedMember[key] = value
				}
			}
		}

		memberID := firstFigmaString(normalizedMember, "id", "user_id", "email", "handle")
		if memberID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":      memberID,
			"team_id": f.teamID,
			"handle":  firstFigmaValue(normalizedMember, "handle"),
			"email":   firstFigmaValue(normalizedMember, "email"),
			"img_url": firstFigmaValue(normalizedMember, "img_url", "avatar_url"),
			"status":  firstFigmaValue(normalizedMember, "status"),
			"role":    firstFigmaValue(normalizedMember, "role"),
		})
	}
	return rows
}

func (f *FigmaProvider) listProjects(ctx context.Context) ([]map[string]interface{}, error) {
	path := "/v1/teams/" + url.PathEscape(f.teamID) + "/projects"
	return f.listCollection(ctx, path, "projects")
}

func (f *FigmaProvider) listProjectFiles(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	path := "/v1/projects/" + url.PathEscape(projectID) + "/files"
	return f.listCollection(ctx, path, "files")
}

func (f *FigmaProvider) listTeamMembers(ctx context.Context) ([]map[string]interface{}, error) {
	path := "/v1/teams/" + url.PathEscape(f.teamID) + "/members"
	return f.listCollection(ctx, path, "members")
}

func (f *FigmaProvider) listCollection(ctx context.Context, path string, itemsKey string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := path
		if nextCursor != "" {
			requestPath = addQueryParams(path, map[string]string{"cursor": nextCursor})
		}

		body, err := f.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeFigmaRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeFigmaRow(payload)
		items := figmaExtractItems(normalized, itemsKey)
		for _, item := range items {
			rows = append(rows, normalizeFigmaRow(item))
		}

		cursor := figmaNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("figma pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (f *FigmaProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL := f.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Figma-Token", f.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("figma API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeFigmaRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func figmaMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func figmaMapSlice(value interface{}) []map[string]interface{} {
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

func figmaExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := figmaMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func figmaNextCursor(payload map[string]interface{}) string {
	if cursor := firstFigmaString(payload, "cursor", "next_cursor", "next_page", "next_page_cursor"); cursor != "" {
		return cursor
	}
	if pagination := figmaMap(payload["pagination"]); len(pagination) > 0 {
		return firstFigmaString(pagination, "cursor", "next_cursor", "next_page", "next_page_cursor")
	}
	return ""
}

func firstFigmaString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstFigmaValue(row map[string]interface{}, keys ...string) interface{} {
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

func isFigmaIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateFigmaURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid figma base_url %q", rawURL)
	}
	return nil
}
