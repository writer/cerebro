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
	zoomDefaultAPIURL   = "https://api.zoom.us/v2"
	zoomDefaultTokenURL = "https://zoom.us/oauth/token"
	zoomPageSize        = 300
)

// ZoomProvider syncs Zoom identity and access metadata.
type ZoomProvider struct {
	*BaseProvider
	accountID    string
	clientID     string
	clientSecret string
	baseURL      string
	tokenURL     string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewZoomProvider() *ZoomProvider {
	return &ZoomProvider{
		BaseProvider: NewBaseProvider("zoom", ProviderTypeSaaS),
		baseURL:      zoomDefaultAPIURL,
		tokenURL:     zoomDefaultTokenURL,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (z *ZoomProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := z.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	z.accountID = strings.TrimSpace(z.GetConfigString("account_id"))
	z.clientID = strings.TrimSpace(z.GetConfigString("client_id"))
	z.clientSecret = strings.TrimSpace(z.GetConfigString("client_secret"))

	if baseURL := strings.TrimSpace(z.GetConfigString("base_url")); baseURL != "" {
		z.baseURL = strings.TrimSuffix(baseURL, "/")
	}
	if tokenURL := strings.TrimSpace(z.GetConfigString("token_url")); tokenURL != "" {
		z.tokenURL = strings.TrimSuffix(tokenURL, "/")
	}

	if z.accountID == "" || z.clientID == "" || z.clientSecret == "" {
		return fmt.Errorf("zoom account_id, client_id, and client_secret required")
	}
	if err := validateZoomURL(z.baseURL, "base_url"); err != nil {
		return err
	}
	if err := validateZoomURL(z.tokenURL, "token_url"); err != nil {
		return err
	}

	return nil
}

func (z *ZoomProvider) Test(ctx context.Context) error {
	_, err := z.request(ctx, "/users?page_size=1")
	return err
}

func (z *ZoomProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "zoom_users",
			Description: "Zoom users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "type", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "role_id", Type: "string"},
				{Name: "role_name", Type: "string"},
				{Name: "dept", Type: "string"},
				{Name: "timezone", Type: "string"},
				{Name: "last_login_time", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "zoom_groups",
			Description: "Zoom groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "total_members", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "zoom_roles",
			Description: "Zoom roles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "total_members", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "zoom_group_memberships",
			Description: "Zoom group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "type", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "role_id", Type: "string"},
				{Name: "role_name", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (z *ZoomProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(z.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (z *ZoomProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  z.Name(),
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

	syncTable("users", z.syncUsers)
	syncTable("groups", z.syncGroups)
	syncTable("roles", z.syncRoles)
	syncTable("group_memberships", z.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (z *ZoomProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := z.schemaFor("zoom_users")
	result := &TableResult{Name: "zoom_users"}
	if err != nil {
		return result, err
	}

	users, err := z.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		row := normalizeZoomRow(user)
		if id := firstZoomString(row, "id", "email"); id != "" {
			row["id"] = id
		}
		rows = append(rows, row)
	}

	return z.syncTable(ctx, schema, rows)
}

func (z *ZoomProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := z.schemaFor("zoom_groups")
	result := &TableResult{Name: "zoom_groups"}
	if err != nil {
		return result, err
	}

	groups, err := z.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		row := normalizeZoomRow(group)
		if id := firstZoomString(row, "id", "name"); id != "" {
			row["id"] = id
		}
		rows = append(rows, row)
	}

	return z.syncTable(ctx, schema, rows)
}

func (z *ZoomProvider) syncRoles(ctx context.Context) (*TableResult, error) {
	schema, err := z.schemaFor("zoom_roles")
	result := &TableResult{Name: "zoom_roles"}
	if err != nil {
		return result, err
	}

	roles, err := z.listRoles(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		row := normalizeZoomRow(role)
		if id := firstZoomString(row, "id", "name"); id != "" {
			row["id"] = id
		}
		rows = append(rows, row)
	}

	return z.syncTable(ctx, schema, rows)
}

func (z *ZoomProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := z.schemaFor("zoom_group_memberships")
	result := &TableResult{Name: "zoom_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := z.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeZoomRow(group)
		groupID := firstZoomString(normalizedGroup, "id", "name")
		if groupID == "" {
			continue
		}
		groupName := firstZoomString(normalizedGroup, "name")

		members, err := z.listGroupMembers(ctx, groupID)
		if err != nil {
			if isZoomIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizeZoomRow(member)
			userID := firstZoomString(normalizedMember, "id", "user_id", "email")
			if userID == "" {
				continue
			}

			membershipID := groupID + "|" + userID
			if _, ok := seen[membershipID]; ok {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":         membershipID,
				"group_id":   groupID,
				"group_name": groupName,
				"user_id":    userID,
				"email": firstZoomValue(normalizedMember,
					"email"),
				"first_name": firstZoomValue(normalizedMember, "first_name"),
				"last_name":  firstZoomValue(normalizedMember, "last_name"),
				"type":       firstZoomValue(normalizedMember, "type"),
				"status":     firstZoomValue(normalizedMember, "status"),
				"role_id":    firstZoomValue(normalizedMember, "role_id"),
				"role_name":  firstZoomValue(normalizedMember, "role_name"),
			})
		}
	}

	return z.syncTable(ctx, schema, rows)
}

func (z *ZoomProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return z.listCollection(ctx, "/users", "users")
}

func (z *ZoomProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return z.listCollection(ctx, "/groups", "groups")
}

func (z *ZoomProvider) listRoles(ctx context.Context) ([]map[string]interface{}, error) {
	return z.listCollection(ctx, "/roles", "roles")
}

func (z *ZoomProvider) listGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	path := "/groups/" + url.PathEscape(groupID) + "/members"
	return z.listCollection(ctx, path, "members")
}

func (z *ZoomProvider) listCollection(ctx context.Context, path string, itemsKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{
		"page_size": strconv.Itoa(zoomPageSize),
	})

	rows := make([]map[string]interface{}, 0)
	nextPageToken := ""
	seenPageTokens := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextPageToken != "" {
			requestPath = addQueryParams(basePath, map[string]string{"next_page_token": nextPageToken})
		}

		body, err := z.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeZoomRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeZoomRow(payload)
		items := zoomExtractItems(normalized, itemsKey)
		for _, item := range items {
			rows = append(rows, normalizeZoomRow(item))
		}

		nextToken := strings.TrimSpace(providerStringValue(normalized["next_page_token"]))
		if nextToken == "" {
			break
		}
		if _, exists := seenPageTokens[nextToken]; exists {
			return nil, fmt.Errorf("zoom pagination loop detected for %s", path)
		}
		seenPageTokens[nextToken] = struct{}{}
		nextPageToken = nextToken
	}

	return rows, nil
}

func (z *ZoomProvider) authenticate(ctx context.Context) (string, error) {
	if z.token != "" && time.Now().Add(30*time.Second).Before(z.tokenExpiry) {
		return z.token, nil
	}

	parsedTokenURL, err := url.Parse(z.tokenURL)
	if err != nil {
		return "", err
	}

	query := parsedTokenURL.Query()
	query.Set("grant_type", "account_credentials")
	query.Set("account_id", z.accountID)
	parsedTokenURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedTokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(z.clientID, z.clientSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := z.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("zoom token API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenPayload); err != nil {
		return "", err
	}
	if tokenPayload.AccessToken == "" {
		return "", fmt.Errorf("zoom token API response missing access_token")
	}
	if tokenPayload.ExpiresIn <= 0 {
		tokenPayload.ExpiresIn = 3600
	}

	z.token = tokenPayload.AccessToken
	z.tokenExpiry = time.Now().Add(time.Duration(tokenPayload.ExpiresIn) * time.Second)
	return z.token, nil
}

func (z *ZoomProvider) request(ctx context.Context, path string) ([]byte, error) {
	call := func(token string) ([]byte, int, error) {
		requestURL := z.baseURL + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := z.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}
		return body, resp.StatusCode, nil
	}

	token, err := z.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	body, statusCode, err := call(token)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized {
		z.token = ""
		z.tokenExpiry = time.Time{}

		token, err = z.authenticate(ctx)
		if err != nil {
			return nil, err
		}
		body, statusCode, err = call(token)
		if err != nil {
			return nil, err
		}
	}

	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("zoom API error %d: %s", statusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeZoomRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func zoomExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := zoomMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func zoomMapSlice(value interface{}) []map[string]interface{} {
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

func firstZoomString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstZoomValue(row map[string]interface{}, keys ...string) interface{} {
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

func isZoomIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateZoomURL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid zoom %s %q", field, rawURL)
	}
	return nil
}
