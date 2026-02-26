package providers

import (
	"bytes"
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
	pingIdentityDefaultAPIURL   = "https://api.pingone.com"
	pingIdentityDefaultAuthURL  = "https://auth.pingone.com"
	pingIdentityDefaultPageSize = 100
	pingIdentityMaxPages        = 1000
)

// PingIdentityProvider syncs PingIdentity users, groups, and group memberships.
type PingIdentityProvider struct {
	*BaseProvider
	environmentID string
	baseURL       string
	tokenURL      string
	clientID      string
	clientSecret  string
	token         string
	tokenExpiry   time.Time
	client        *http.Client
}

func NewPingIdentityProvider() *PingIdentityProvider {
	return &PingIdentityProvider{
		BaseProvider: NewBaseProvider("pingidentity", ProviderTypeIdentity),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *PingIdentityProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := p.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	p.environmentID = strings.TrimSpace(p.GetConfigString("environment_id"))
	if p.environmentID == "" {
		p.environmentID = strings.TrimSpace(p.GetConfigString("env_id"))
	}
	if p.environmentID == "" {
		p.environmentID = strings.TrimSpace(p.GetConfigString("tenant_id"))
	}
	if p.environmentID == "" {
		return fmt.Errorf("pingidentity environment_id required")
	}

	p.clientID = strings.TrimSpace(p.GetConfigString("client_id"))
	if p.clientID == "" {
		p.clientID = strings.TrimSpace(p.GetConfigString("id"))
	}
	p.clientSecret = strings.TrimSpace(p.GetConfigString("client_secret"))
	if p.clientSecret == "" {
		p.clientSecret = strings.TrimSpace(p.GetConfigString("secret"))
	}
	if p.clientID == "" || p.clientSecret == "" {
		return fmt.Errorf("pingidentity client_id and client_secret required")
	}

	apiURL := strings.TrimSpace(p.GetConfigString("api_url"))
	if apiURL == "" {
		apiURL = strings.TrimSpace(p.GetConfigString("base_url"))
	}
	if apiURL == "" {
		apiURL = pingIdentityDefaultAPIURL
	}
	if !strings.Contains(apiURL, "://") {
		apiURL = "https://" + apiURL
	}
	apiURL = strings.TrimSuffix(apiURL, "/")

	parsedAPI, err := url.Parse(apiURL)
	if err != nil || parsedAPI.Scheme == "" || parsedAPI.Host == "" {
		return fmt.Errorf("invalid pingidentity api_url %q", apiURL)
	}

	lowerPath := strings.ToLower(strings.Trim(parsedAPI.Path, "/"))
	envPath := "environments/" + url.PathEscape(p.environmentID)
	if strings.Contains(lowerPath, "/environments/") || strings.HasPrefix(lowerPath, "environments/") {
		p.baseURL = parsedAPI.Scheme + "://" + parsedAPI.Host + strings.TrimSuffix(parsedAPI.Path, "/")
	} else if strings.HasSuffix(lowerPath, "v1") || strings.HasSuffix(lowerPath, "v1/") {
		p.baseURL = parsedAPI.Scheme + "://" + parsedAPI.Host + strings.TrimSuffix(parsedAPI.Path, "/") + "/" + envPath
	} else {
		basePath := strings.TrimSuffix(parsedAPI.Path, "/")
		if basePath == "" {
			basePath = "/v1"
		} else {
			basePath += "/v1"
		}
		p.baseURL = parsedAPI.Scheme + "://" + parsedAPI.Host + basePath + "/" + envPath
	}

	p.tokenURL = strings.TrimSpace(p.GetConfigString("token_url"))
	if p.tokenURL == "" {
		authURL := strings.TrimSpace(p.GetConfigString("auth_url"))
		if authURL == "" {
			authURL = pingIdentityDefaultAuthURL
		}
		if !strings.Contains(authURL, "://") {
			authURL = "https://" + authURL
		}
		authURL = strings.TrimSuffix(authURL, "/")
		p.tokenURL = authURL + "/" + url.PathEscape(p.environmentID) + "/as/token"
	}
	p.tokenURL = strings.TrimSuffix(p.tokenURL, "/")

	if err := validatePingIdentityURL(p.baseURL, "api_url"); err != nil {
		return err
	}
	if err := validatePingIdentityURL(p.tokenURL, "token_url"); err != nil {
		return err
	}

	return nil
}

func (p *PingIdentityProvider) Test(ctx context.Context) error {
	_, err := p.request(ctx, addQueryParams("/users", map[string]string{"limit": "1"}))
	return err
}

func (p *PingIdentityProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "pingidentity_users",
			Description: "PingIdentity users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "given_name", Type: "string"},
				{Name: "family_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "enabled", Type: "boolean"},
				{Name: "population_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "last_sign_on", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "pingidentity_groups",
			Description: "PingIdentity groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "population_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "pingidentity_group_memberships",
			Description: "PingIdentity group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "type", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (p *PingIdentityProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(p.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (p *PingIdentityProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
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
	syncTable("groups", p.syncGroups)
	syncTable("group_memberships", p.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (p *PingIdentityProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("pingidentity_users")
	result := &TableResult{Name: "pingidentity_users"}
	if err != nil {
		return result, err
	}

	users, err := p.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizePingIdentityRow(user)
		userID := firstPingIdentityString(normalized, "id", "user_id", "subject", "username", "email")
		if userID == "" {
			continue
		}

		name := pingIdentityMap(normalized["name"])
		population := pingIdentityMap(normalized["population"])

		rows = append(rows, map[string]interface{}{
			"id":            userID,
			"username":      firstPingIdentityValue(normalized, "username", "preferred_username"),
			"email":         firstPingIdentityValue(normalized, "email", "primary_email"),
			"name":          firstPingIdentityValue(normalized, "name", "display_name"),
			"given_name":    firstNonNilPingIdentityValue(firstPingIdentityValue(normalized, "given_name", "first_name"), firstPingIdentityValue(name, "given", "given_name")),
			"family_name":   firstNonNilPingIdentityValue(firstPingIdentityValue(normalized, "family_name", "last_name"), firstPingIdentityValue(name, "family", "family_name")),
			"status":        firstPingIdentityValue(normalized, "status", "lifecycle_status"),
			"enabled":       firstPingIdentityValue(normalized, "enabled"),
			"population_id": firstNonNilPingIdentityValue(firstPingIdentityValue(normalized, "population_id"), firstPingIdentityValue(population, "id", "population_id")),
			"created_at":    firstPingIdentityValue(normalized, "created_at", "created_time", "created"),
			"updated_at":    firstPingIdentityValue(normalized, "updated_at", "updated_time", "modified_at", "last_modified"),
			"last_sign_on":  firstPingIdentityValue(normalized, "last_sign_on", "last_signon", "last_login", "last_login_at"),
		})
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PingIdentityProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("pingidentity_groups")
	result := &TableResult{Name: "pingidentity_groups"}
	if err != nil {
		return result, err
	}

	groups, err := p.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizePingIdentityRow(group)
		groupID := firstPingIdentityString(normalized, "id", "group_id", "name")
		if groupID == "" {
			continue
		}

		population := pingIdentityMap(normalized["population"])

		rows = append(rows, map[string]interface{}{
			"id":            groupID,
			"name":          firstPingIdentityValue(normalized, "name", "display_name"),
			"description":   firstPingIdentityValue(normalized, "description", "desc"),
			"population_id": firstNonNilPingIdentityValue(firstPingIdentityValue(normalized, "population_id"), firstPingIdentityValue(population, "id", "population_id")),
			"created_at":    firstPingIdentityValue(normalized, "created_at", "created_time", "created"),
			"updated_at":    firstPingIdentityValue(normalized, "updated_at", "updated_time", "modified_at", "last_modified"),
		})
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PingIdentityProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := p.schemaFor("pingidentity_group_memberships")
	result := &TableResult{Name: "pingidentity_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := p.listGroups(ctx)
	if err != nil {
		return result, err
	}

	users, err := p.listUsers(ctx)
	if err != nil {
		return result, err
	}

	usersByID := make(map[string]map[string]interface{}, len(users))
	for _, user := range users {
		normalized := normalizePingIdentityRow(user)
		userID := firstPingIdentityString(normalized, "id", "user_id")
		if userID == "" {
			continue
		}
		usersByID[userID] = normalized
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizePingIdentityRow(group)
		groupID := firstPingIdentityString(normalizedGroup, "id", "group_id")
		if groupID == "" {
			continue
		}
		groupName := firstPingIdentityValue(normalizedGroup, "name", "display_name")

		members, err := p.listGroupMembers(ctx, groupID)
		if err != nil {
			if isPingIdentityIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizePingIdentityRow(member)
			userID, username, email := pingIdentityMembershipUser(normalizedMember)
			if userID == "" {
				continue
			}

			user := usersByID[userID]
			username = firstNonNilPingIdentityValue(username, firstPingIdentityValue(user, "username", "name", "preferred_username"))
			email = firstNonNilPingIdentityValue(email, firstPingIdentityValue(user, "email", "primary_email"))

			membershipID := groupID + "|" + userID
			if _, exists := seen[membershipID]; exists {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":         membershipID,
				"group_id":   groupID,
				"group_name": groupName,
				"user_id":    userID,
				"username":   username,
				"email":      email,
				"type":       firstPingIdentityValue(normalizedMember, "type", "member_type", "kind"),
			})
		}
	}

	return p.syncTable(ctx, schema, rows)
}

func (p *PingIdentityProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return p.listCollection(ctx, "/users", "users")
}

func (p *PingIdentityProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return p.listCollection(ctx, "/groups", "groups")
}

func (p *PingIdentityProvider) listGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	candidates := []string{
		"/groups/" + url.PathEscape(groupID) + "/members",
		"/groups/" + url.PathEscape(groupID) + "/users",
		"/groups/" + url.PathEscape(groupID) + "/memberships",
	}

	var lastErr error
	for _, path := range candidates {
		rows, err := p.listCollection(ctx, path, "members", "users", "memberships")
		if err == nil {
			return rows, nil
		}
		if isPingIdentityIgnorableError(err) || isPingIdentityEndpointNotFound(err) {
			lastErr = err
			continue
		}
		return nil, err
	}

	if lastErr != nil && (isPingIdentityIgnorableError(lastErr) || isPingIdentityEndpointNotFound(lastErr)) {
		return nil, nil
	}

	return nil, nil
}

func (p *PingIdentityProvider) listCollection(ctx context.Context, path string, keys ...string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"limit": strconv.Itoa(pingIdentityDefaultPageSize)})
	nextPath := basePath
	rows := make([]map[string]interface{}, 0)
	seenPaths := make(map[string]struct{})

	for page := 0; page < pingIdentityMaxPages; page++ {
		if nextPath == "" {
			return rows, nil
		}
		if _, exists := seenPaths[nextPath]; exists {
			return nil, fmt.Errorf("pingidentity pagination loop detected for %s", path)
		}
		seenPaths[nextPath] = struct{}{}

		body, err := p.request(ctx, nextPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizePingIdentityRow(item))
				}
				return rows, nil
			}
			return nil, err
		}

		normalized := normalizePingIdentityRow(payload)
		items := pingIdentityExtractItems(normalized, keys...)
		for _, item := range items {
			rows = append(rows, normalizePingIdentityRow(item))
		}

		nextRaw := pingIdentityNextPath(normalized)
		if nextRaw == "" {
			return rows, nil
		}

		resolved, err := p.resolveNextPath(basePath, nextPath, nextRaw)
		if err != nil {
			return nil, err
		}
		nextPath = resolved
	}

	return nil, fmt.Errorf("pingidentity pagination exceeded %d pages", pingIdentityMaxPages)
}

func (p *PingIdentityProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := pingIdentityResolveRequestURL(p.baseURL, path)
	if err != nil {
		return nil, err
	}

	body, statusCode, err := p.requestWithToken(ctx, requestURL, false)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized {
		body, statusCode, err = p.requestWithToken(ctx, requestURL, true)
		if err != nil {
			return nil, err
		}
	}

	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("pingidentity API error %d: %s", statusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func (p *PingIdentityProvider) requestWithToken(ctx context.Context, requestURL string, forceRefresh bool) ([]byte, int, error) {
	token, err := p.ensureAccessToken(ctx, forceRefresh)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
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

func (p *PingIdentityProvider) ensureAccessToken(ctx context.Context, forceRefresh bool) (string, error) {
	if !forceRefresh && p.token != "" && time.Now().Before(p.tokenExpiry.Add(-30*time.Second)) {
		return p.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(p.clientID, p.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("pingidentity token API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}

	normalized := normalizePingIdentityRow(payload)
	token := firstPingIdentityString(normalized, "access_token", "token")
	if token == "" {
		return "", fmt.Errorf("pingidentity token response missing access_token")
	}

	expiresIn := parsePingIdentityInt(firstPingIdentityValue(normalized, "expires_in", "expires"))
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	p.token = token
	p.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return p.token, nil
}

func (p *PingIdentityProvider) resolveNextPath(basePath string, currentPath string, nextRaw string) (string, error) {
	nextRaw = strings.TrimSpace(nextRaw)
	if nextRaw == "" {
		return "", nil
	}

	lower := strings.ToLower(nextRaw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := pingIdentityResolveRequestURL(p.baseURL, nextRaw)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}

	if strings.HasPrefix(nextRaw, "/") {
		return nextRaw, nil
	}

	if strings.HasPrefix(nextRaw, "?") {
		parsedCurrent, err := url.Parse(currentPath)
		if err != nil {
			return "", err
		}
		path := parsedCurrent.Path
		if path == "" {
			parsedBase, baseErr := url.Parse(basePath)
			if baseErr == nil {
				path = parsedBase.Path
			}
		}
		if path == "" {
			path = "/"
		}
		return path + nextRaw, nil
	}

	if strings.Contains(nextRaw, "/") || strings.Contains(nextRaw, "?") {
		return "/" + strings.TrimPrefix(nextRaw, "/"), nil
	}

	return addQueryParams(basePath, map[string]string{"cursor": nextRaw}), nil
}

func pingIdentityResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("pingidentity request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid pingidentity URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid pingidentity base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("pingidentity request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid pingidentity base URL %q", baseURL)
		}

		basePath := strings.TrimSuffix(baseParsed.Path, "/")
		if basePath != "" && (cleanPath == basePath || strings.HasPrefix(cleanPath, basePath+"/")) {
			return baseParsed.Scheme + "://" + baseParsed.Host + cleanPath, nil
		}

		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validatePingIdentityURL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid pingidentity %s %q", field, rawURL)
	}
	return nil
}

func normalizePingIdentityRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func pingIdentityMap(value interface{}) map[string]interface{} {
	if row, ok := normalizeMapKeys(value).(map[string]interface{}); ok {
		return row
	}
	return nil
}

func pingIdentityMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if row, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, row)
			}
		}
		return rows
	default:
		return nil
	}
}

func pingIdentityExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if rows := pingIdentityMapSlice(payload[key]); len(rows) > 0 {
			return rows
		}
	}

	for _, key := range []string{"items", "data", "results", "resources", "records", "response"} {
		if rows := pingIdentityMapSlice(payload[key]); len(rows) > 0 {
			return rows
		}
	}

	embedded := pingIdentityMap(payload["embedded"])
	if len(embedded) > 0 {
		for _, key := range keys {
			if rows := pingIdentityMapSlice(embedded[key]); len(rows) > 0 {
				return rows
			}
		}
		for _, key := range []string{"users", "groups", "members", "memberships", "items", "data", "resources", "records"} {
			if rows := pingIdentityMapSlice(embedded[key]); len(rows) > 0 {
				return rows
			}
		}
	}

	if firstPingIdentityString(payload, "id", "user_id", "group_id", "member_id", "username", "name", "email") != "" {
		return []map[string]interface{}{payload}
	}

	return nil
}

func pingIdentityNextPath(payload map[string]interface{}) string {
	if next := firstPingIdentityString(payload, "next", "next_cursor", "cursor", "next_token"); next != "" {
		return next
	}

	if links := pingIdentityMap(payload["links"]); len(links) > 0 {
		if next := pingIdentityLinkPath(links["next"]); next != "" {
			return next
		}
	}

	if page := pingIdentityMap(payload["page"]); len(page) > 0 {
		if next := firstPingIdentityString(page, "next", "next_cursor", "cursor", "next_token"); next != "" {
			return next
		}
	}

	if pagination := pingIdentityMap(payload["pagination"]); len(pagination) > 0 {
		if next := firstPingIdentityString(pagination, "next", "next_cursor", "cursor", "next_token"); next != "" {
			return next
		}
	}

	if metadata := pingIdentityMap(payload["metadata"]); len(metadata) > 0 {
		if next := firstPingIdentityString(metadata, "next", "next_cursor", "cursor", "next_token"); next != "" {
			return next
		}
	}

	return ""
}

func pingIdentityLinkPath(value interface{}) string {
	if value == nil {
		return ""
	}

	if asMap := pingIdentityMap(value); len(asMap) > 0 {
		return firstPingIdentityString(asMap, "href", "url", "uri")
	}

	if text := strings.TrimSpace(providerStringValue(value)); text != "" {
		return text
	}

	return ""
}

func pingIdentityMembershipUser(row map[string]interface{}) (string, interface{}, interface{}) {
	userID := firstPingIdentityString(row, "user_id", "subject_id", "member_id", "subject")
	username := firstPingIdentityValue(row, "username", "name")
	email := firstPingIdentityValue(row, "email")

	for _, key := range []string{"user", "member", "subject", "actor"} {
		nested := pingIdentityMap(row[key])
		if len(nested) == 0 {
			continue
		}
		if userID == "" {
			userID = firstPingIdentityString(nested, "id", "user_id", "subject_id")
		}
		username = firstNonNilPingIdentityValue(username, firstPingIdentityValue(nested, "username", "name", "preferred_username"))
		email = firstNonNilPingIdentityValue(email, firstPingIdentityValue(nested, "email", "primary_email"))
	}

	if userID == "" {
		if links := pingIdentityMap(row["links"]); len(links) > 0 {
			if userLink := pingIdentityMap(links["user"]); len(userLink) > 0 {
				if href := firstPingIdentityString(userLink, "href", "url", "uri"); href != "" {
					userID = pingIdentityIDFromPath(href, "users")
				}
			}
		}
	}

	if userID == "" {
		userID = firstPingIdentityString(row, "id")
	}

	if userID == "" {
		if href := firstPingIdentityString(row, "href", "url", "uri"); href != "" {
			userID = pingIdentityIDFromPath(href, "users")
		}
	}

	return userID, username, email
}

func pingIdentityIDFromPath(value string, resource string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	parsed, err := url.Parse(value)
	if err == nil && parsed.Path != "" {
		value = parsed.Path
	}

	segments := strings.Split(strings.Trim(value, "/"), "/")
	for i := 0; i < len(segments)-1; i++ {
		if strings.EqualFold(segments[i], resource) {
			candidate := strings.TrimSpace(segments[i+1])
			if candidate != "" {
				return candidate
			}
		}
	}

	if len(segments) > 0 {
		return strings.TrimSpace(segments[len(segments)-1])
	}

	return ""
}

func firstPingIdentityString(row map[string]interface{}, keys ...string) string {
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

func firstPingIdentityValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilPingIdentityValue(values ...interface{}) interface{} {
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

func parsePingIdentityInt(value interface{}) int {
	if value == nil {
		return 0
	}
	text := strings.TrimSpace(providerStringValue(value))
	if text == "" {
		return 0
	}
	number, err := strconv.Atoi(text)
	if err != nil {
		return 0
	}
	return number
}

func isPingIdentityIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func isPingIdentityEndpointNotFound(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 404") || strings.Contains(message, "api error 405")
}
