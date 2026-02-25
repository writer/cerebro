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
	auth0DefaultPageSize = 100
	auth0MaxPages        = 10000
)

// Auth0Provider syncs Auth0 identity and role metadata.
type Auth0Provider struct {
	*BaseProvider
	domain       string
	baseURL      string
	tokenURL     string
	audience     string
	clientID     string
	clientSecret string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewAuth0Provider() *Auth0Provider {
	return &Auth0Provider{
		BaseProvider: NewBaseProvider("auth0", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *Auth0Provider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := a.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	domain := strings.TrimSpace(a.GetConfigString("domain"))
	if domain == "" {
		return fmt.Errorf("auth0 domain required")
	}

	normalizedDomain, err := normalizeAuth0Domain(domain)
	if err != nil {
		return err
	}
	a.domain = normalizedDomain

	a.baseURL = strings.TrimSpace(a.GetConfigString("base_url"))
	if a.baseURL == "" {
		a.baseURL = a.domain + "/api/v2"
	}
	a.baseURL = strings.TrimSuffix(a.baseURL, "/")

	a.tokenURL = strings.TrimSpace(a.GetConfigString("token_url"))
	if a.tokenURL == "" {
		a.tokenURL = a.domain + "/oauth/token"
	}
	a.tokenURL = strings.TrimSuffix(a.tokenURL, "/")

	a.audience = strings.TrimSpace(a.GetConfigString("audience"))
	if a.audience == "" {
		a.audience = strings.TrimSuffix(a.baseURL, "/") + "/"
	}

	a.clientID = strings.TrimSpace(a.GetConfigString("client_id"))
	a.clientSecret = strings.TrimSpace(a.GetConfigString("client_secret"))
	if a.clientID == "" || a.clientSecret == "" {
		return fmt.Errorf("auth0 client_id and client_secret required")
	}

	if err := validateAuth0URL(a.baseURL, "base_url"); err != nil {
		return err
	}
	if err := validateAuth0URL(a.tokenURL, "token_url"); err != nil {
		return err
	}

	return nil
}

func (a *Auth0Provider) Test(ctx context.Context) error {
	_, err := a.request(ctx, addQueryParams("/users", map[string]string{"per_page": "1", "page": "0"}))
	return err
}

func (a *Auth0Provider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "auth0_users",
			Description: "Auth0 users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "nickname", Type: "string"},
				{Name: "picture", Type: "string"},
				{Name: "blocked", Type: "boolean"},
				{Name: "email_verified", Type: "boolean"},
				{Name: "logins_count", Type: "integer"},
				{Name: "last_login", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "auth0_roles",
			Description: "Auth0 roles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "auth0_role_memberships",
			Description: "Auth0 role memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "role_id", Type: "string", Required: true},
				{Name: "role_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "nickname", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (a *Auth0Provider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(a.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (a *Auth0Provider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  a.Name(),
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

	syncTable("users", a.syncUsers)
	syncTable("roles", a.syncRoles)
	syncTable("role_memberships", a.syncRoleMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (a *Auth0Provider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("auth0_users")
	result := &TableResult{Name: "auth0_users"}
	if err != nil {
		return result, err
	}

	users, err := a.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeAuth0Row(user)
		userID := firstAuth0String(normalized, "user_id", "id")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":             userID,
			"email":          firstAuth0Value(normalized, "email"),
			"name":           firstAuth0Value(normalized, "name"),
			"nickname":       firstAuth0Value(normalized, "nickname"),
			"picture":        firstAuth0Value(normalized, "picture"),
			"blocked":        firstAuth0Value(normalized, "blocked"),
			"email_verified": firstAuth0Value(normalized, "email_verified"),
			"logins_count":   firstAuth0Value(normalized, "logins_count"),
			"last_login":     firstAuth0Value(normalized, "last_login"),
			"created_at":     firstAuth0Value(normalized, "created_at"),
			"updated_at":     firstAuth0Value(normalized, "updated_at"),
		})
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *Auth0Provider) syncRoles(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("auth0_roles")
	result := &TableResult{Name: "auth0_roles"}
	if err != nil {
		return result, err
	}

	roles, err := a.listRoles(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		normalized := normalizeAuth0Row(role)
		roleID := firstAuth0String(normalized, "id", "role_id", "name")
		if roleID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":          roleID,
			"name":        firstAuth0Value(normalized, "name"),
			"description": firstAuth0Value(normalized, "description"),
		})
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *Auth0Provider) syncRoleMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := a.schemaFor("auth0_role_memberships")
	result := &TableResult{Name: "auth0_role_memberships"}
	if err != nil {
		return result, err
	}

	roles, err := a.listRoles(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, role := range roles {
		normalizedRole := normalizeAuth0Row(role)
		roleID := firstAuth0String(normalizedRole, "id", "role_id", "name")
		if roleID == "" {
			continue
		}
		roleName := firstAuth0String(normalizedRole, "name")

		users, err := a.listRoleUsers(ctx, roleID)
		if err != nil {
			if isAuth0IgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, user := range users {
			normalizedUser := normalizeAuth0Row(user)
			userID := firstAuth0String(normalizedUser, "user_id", "id")
			if userID == "" {
				continue
			}

			membershipID := roleID + "|" + userID
			if _, ok := seen[membershipID]; ok {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":         membershipID,
				"role_id":    roleID,
				"role_name":  roleName,
				"user_id":    userID,
				"email":      firstAuth0Value(normalizedUser, "email"),
				"name":       firstAuth0Value(normalizedUser, "name"),
				"nickname":   firstAuth0Value(normalizedUser, "nickname"),
				"created_at": firstAuth0Value(normalizedUser, "created_at"),
				"updated_at": firstAuth0Value(normalizedUser, "updated_at"),
			})
		}
	}

	return a.syncTable(ctx, schema, rows)
}

func (a *Auth0Provider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return a.listCollection(ctx, "/users", "users")
}

func (a *Auth0Provider) listRoles(ctx context.Context) ([]map[string]interface{}, error) {
	return a.listCollection(ctx, "/roles", "roles")
}

func (a *Auth0Provider) listRoleUsers(ctx context.Context, roleID string) ([]map[string]interface{}, error) {
	path := "/roles/" + url.PathEscape(roleID) + "/users"
	return a.listCollection(ctx, path, "users")
}

func (a *Auth0Provider) listCollection(ctx context.Context, path string, itemsKey string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)

	for page := 0; page < auth0MaxPages; page++ {
		requestPath := addQueryParams(path, map[string]string{
			"page":     strconv.Itoa(page),
			"per_page": strconv.Itoa(auth0DefaultPageSize),
		})

		body, err := a.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var list []map[string]interface{}
		if err := json.Unmarshal(body, &list); err == nil {
			for _, item := range list {
				rows = append(rows, normalizeAuth0Row(item))
			}
			if len(list) < auth0DefaultPageSize {
				break
			}
			continue
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalized := normalizeAuth0Row(payload)
		items := auth0ExtractItems(normalized, itemsKey, "items", "data", "results", "values", "records")
		for _, item := range items {
			rows = append(rows, normalizeAuth0Row(item))
		}
		if len(items) < auth0DefaultPageSize {
			break
		}
	}

	return rows, nil
}

func (a *Auth0Provider) authenticate(ctx context.Context) (string, error) {
	if a.token != "" && time.Now().Add(30*time.Second).Before(a.tokenExpiry) {
		return a.token, nil
	}

	payload := map[string]string{
		"client_id":     a.clientID,
		"client_secret": a.clientSecret,
		"audience":      a.audience,
		"grant_type":    "client_credentials",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("auth0 token API error %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenPayload); err != nil {
		return "", err
	}
	if tokenPayload.AccessToken == "" {
		return "", fmt.Errorf("auth0 token response missing access_token")
	}
	if tokenPayload.ExpiresIn <= 0 {
		tokenPayload.ExpiresIn = 3600
	}

	a.token = tokenPayload.AccessToken
	a.tokenExpiry = time.Now().Add(time.Duration(tokenPayload.ExpiresIn) * time.Second)
	return a.token, nil
}

func (a *Auth0Provider) request(ctx context.Context, path string) ([]byte, error) {
	call := func(token string) ([]byte, int, error) {
		requestURL, err := auth0ResolveRequestURL(a.baseURL, path)
		if err != nil {
			return nil, 0, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := a.client.Do(req)
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

	token, err := a.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	body, statusCode, err := call(token)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized {
		a.token = ""
		a.tokenExpiry = time.Time{}

		token, err = a.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		body, statusCode, err = call(token)
		if err != nil {
			return nil, err
		}
	}

	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("auth0 API error %d: %s", statusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeAuth0Domain(domain string) (string, error) {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return "", fmt.Errorf("auth0 domain required")
	}

	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid auth0 domain %q", domain)
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}

func auth0ResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("auth0 request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid auth0 URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid auth0 base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("auth0 request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateAuth0URL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid auth0 %s %q", field, rawURL)
	}
	return nil
}

func normalizeAuth0Row(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func auth0MapSlice(value interface{}) []map[string]interface{} {
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

func auth0ExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := auth0MapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func firstAuth0String(row map[string]interface{}, keys ...string) string {
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

func firstAuth0Value(row map[string]interface{}, keys ...string) interface{} {
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

func isAuth0IgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
