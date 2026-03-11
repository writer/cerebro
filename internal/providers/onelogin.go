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
	oneLoginDefaultPageSize = 100
	oneLoginMaxPages        = 1000
)

// OneLoginProvider syncs OneLogin identity and role metadata.
type OneLoginProvider struct {
	*BaseProvider
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewOneLoginProvider() *OneLoginProvider {
	return &OneLoginProvider{
		BaseProvider: NewBaseProvider("onelogin", ProviderTypeSaaS),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (o *OneLoginProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := o.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	o.baseURL = strings.TrimSpace(o.GetConfigString("url"))
	if o.baseURL == "" {
		o.baseURL = strings.TrimSpace(o.GetConfigString("base_url"))
	}
	if o.baseURL == "" {
		o.baseURL = strings.TrimSpace(o.GetConfigString("instance_url"))
	}
	o.baseURL = strings.TrimSuffix(o.baseURL, "/")
	if o.baseURL == "" {
		return fmt.Errorf("onelogin url required")
	}
	if !strings.Contains(strings.ToLower(o.baseURL), "/api/2") {
		o.baseURL += "/api/2"
	}

	o.clientID = strings.TrimSpace(o.GetConfigString("client_id"))
	if o.clientID == "" {
		o.clientID = strings.TrimSpace(o.GetConfigString("id"))
	}
	o.clientSecret = strings.TrimSpace(o.GetConfigString("client_secret"))
	if o.clientSecret == "" {
		o.clientSecret = strings.TrimSpace(o.GetConfigString("secret"))
	}
	if o.clientID == "" || o.clientSecret == "" {
		return fmt.Errorf("onelogin client_id and client_secret required")
	}

	o.tokenURL = strings.TrimSpace(o.GetConfigString("token_url"))
	if o.tokenURL == "" {
		baseParsed, err := url.Parse(o.baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return fmt.Errorf("invalid onelogin url %q", o.baseURL)
		}
		o.tokenURL = baseParsed.Scheme + "://" + baseParsed.Host + "/auth/oauth2/v2/token"
	}
	o.tokenURL = strings.TrimSuffix(o.tokenURL, "/")

	if err := validateOneLoginURL(o.baseURL, "url"); err != nil {
		return err
	}
	if err := validateOneLoginURL(o.tokenURL, "token_url"); err != nil {
		return err
	}

	return nil
}

func (o *OneLoginProvider) Test(ctx context.Context) error {
	_, err := o.request(ctx, addQueryParams("/users", map[string]string{"page": "1", "limit": "1"}))
	return err
}

func (o *OneLoginProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "onelogin_users",
			Description: "OneLogin users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "status", Type: "integer"},
				{Name: "distinguished_name", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "last_login", Type: "timestamp"},
				{Name: "activated_at", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "onelogin_roles",
			Description: "OneLogin roles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "users_count", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "onelogin_role_memberships",
			Description: "OneLogin role memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "role_id", Type: "string", Required: true},
				{Name: "role_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "status", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (o *OneLoginProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(o.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (o *OneLoginProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  o.Name(),
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

	syncTable("users", o.syncUsers)
	syncTable("roles", o.syncRoles)
	syncTable("role_memberships", o.syncRoleMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (o *OneLoginProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("onelogin_users")
	result := &TableResult{Name: "onelogin_users"}
	if err != nil {
		return result, err
	}

	users, err := o.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeOneLoginRow(user)
		userID := firstOneLoginString(normalized, "id", "user_id")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":                 userID,
			"username":           firstOneLoginValue(normalized, "username", "samaccountname"),
			"email":              firstOneLoginValue(normalized, "email"),
			"first_name":         firstOneLoginValue(normalized, "firstname", "first_name"),
			"last_name":          firstOneLoginValue(normalized, "lastname", "last_name"),
			"status":             firstOneLoginValue(normalized, "status"),
			"distinguished_name": firstOneLoginValue(normalized, "distinguished_name"),
			"department":         firstOneLoginValue(normalized, "department"),
			"title":              firstOneLoginValue(normalized, "title"),
			"last_login":         firstOneLoginValue(normalized, "last_login"),
			"activated_at":       firstOneLoginValue(normalized, "activated_at"),
			"created_at":         firstOneLoginValue(normalized, "created_at"),
			"updated_at":         firstOneLoginValue(normalized, "updated_at"),
		})
	}

	return o.syncTable(ctx, schema, rows)
}

func (o *OneLoginProvider) syncRoles(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("onelogin_roles")
	result := &TableResult{Name: "onelogin_roles"}
	if err != nil {
		return result, err
	}

	roles, err := o.listRoles(ctx)
	if err != nil {
		if isOneLoginIgnorableError(err) {
			return o.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		normalized := normalizeOneLoginRow(role)
		roleID := firstOneLoginString(normalized, "id", "role_id", "name")
		if roleID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":          roleID,
			"name":        firstOneLoginValue(normalized, "name", "display_name"),
			"users_count": firstOneLoginValue(normalized, "users_count"),
		})
	}

	return o.syncTable(ctx, schema, rows)
}

func (o *OneLoginProvider) syncRoleMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := o.schemaFor("onelogin_role_memberships")
	result := &TableResult{Name: "onelogin_role_memberships"}
	if err != nil {
		return result, err
	}

	roles, err := o.listRoles(ctx)
	if err != nil {
		if isOneLoginIgnorableError(err) {
			return o.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, role := range roles {
		normalizedRole := normalizeOneLoginRow(role)
		roleID := firstOneLoginString(normalizedRole, "id", "role_id", "name")
		if roleID == "" {
			continue
		}
		roleName := firstOneLoginValue(normalizedRole, "name", "display_name")

		users, err := o.listRoleUsers(ctx, roleID)
		if err != nil {
			if isOneLoginIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, user := range users {
			normalizedUser := normalizeOneLoginRow(user)
			userID := firstOneLoginString(normalizedUser, "id", "user_id")
			if userID == "" {
				continue
			}

			membershipID := roleID + "|" + userID
			if _, exists := seen[membershipID]; exists {
				continue
			}
			seen[membershipID] = struct{}{}

			rows = append(rows, map[string]interface{}{
				"id":        membershipID,
				"role_id":   roleID,
				"role_name": roleName,
				"user_id":   userID,
				"username":  firstOneLoginValue(normalizedUser, "username", "samaccountname"),
				"email":     firstOneLoginValue(normalizedUser, "email"),
				"status":    firstOneLoginValue(normalizedUser, "status"),
			})
		}
	}

	return o.syncTable(ctx, schema, rows)
}

func (o *OneLoginProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return o.listCollection(ctx, "/users", "users")
}

func (o *OneLoginProvider) listRoles(ctx context.Context) ([]map[string]interface{}, error) {
	return o.listCollection(ctx, "/roles", "roles")
}

func (o *OneLoginProvider) listRoleUsers(ctx context.Context, roleID string) ([]map[string]interface{}, error) {
	path := "/roles/" + url.PathEscape(roleID) + "/users"
	return o.listCollection(ctx, path, "users")
}

func (o *OneLoginProvider) listCollection(ctx context.Context, path string, itemsKey string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	seenPageSignatures := make(map[string]struct{})

	for page := 1; page <= oneLoginMaxPages; page++ {
		requestPath := addQueryParams(path, map[string]string{
			"page":  strconv.Itoa(page),
			"limit": strconv.Itoa(oneLoginDefaultPageSize),
		})

		body, err := o.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		items, err := oneLoginDecodeItems(body, itemsKey)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}

		firstID := firstOneLoginString(normalizeOneLoginRow(items[0]), "id", "user_id", "role_id", "name")
		signature := fmt.Sprintf("%s:%d", firstID, len(items))
		if _, exists := seenPageSignatures[signature]; exists {
			return nil, fmt.Errorf("onelogin pagination loop detected for %s", itemsKey)
		}
		seenPageSignatures[signature] = struct{}{}

		for _, item := range items {
			rows = append(rows, normalizeOneLoginRow(item))
		}

		if len(items) < oneLoginDefaultPageSize {
			break
		}
	}

	return rows, nil
}

func oneLoginDecodeItems(body []byte, keys ...string) ([]map[string]interface{}, error) {
	var list []map[string]interface{}
	if err := json.Unmarshal(body, &list); err == nil {
		rows := make([]map[string]interface{}, 0, len(list))
		for _, item := range list {
			rows = append(rows, normalizeOneLoginRow(item))
		}
		return rows, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	normalized := normalizeOneLoginRow(payload)
	searchKeys := append([]string{}, keys...)
	searchKeys = append(searchKeys, "data", "result", "results", "items", "users", "roles")
	return oneLoginExtractItems(normalized, searchKeys...), nil
}

func (o *OneLoginProvider) authenticate(ctx context.Context) (string, error) {
	if o.token != "" && time.Now().Add(30*time.Second).Before(o.tokenExpiry) {
		return o.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(o.clientID, o.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("onelogin token API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	token, expiresIn, err := oneLoginParseToken(body)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("onelogin token response missing access_token")
	}
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	o.token = token
	o.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return o.token, nil
}

func (o *OneLoginProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := oneLoginResolveRequestURL(o.baseURL, path)
	if err != nil {
		return nil, err
	}

	call := func(token string) ([]byte, int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := o.client.Do(req)
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

	token, err := o.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	body, statusCode, err := call(token)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized {
		o.token = ""
		o.tokenExpiry = time.Time{}

		token, err = o.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		body, statusCode, err = call(token)
		if err != nil {
			return nil, err
		}
	}

	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("onelogin API error %d: %s", statusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func oneLoginParseToken(body []byte) (string, int, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, err
	}

	normalized := normalizeOneLoginRow(payload)
	token := firstOneLoginString(normalized, "access_token", "token")
	expiresIn := parseOneLoginInt(firstOneLoginValue(normalized, "expires_in", "expires"))
	if token != "" {
		return token, expiresIn, nil
	}

	items := oneLoginExtractItems(normalized, "data", "result", "results", "items")
	if len(items) == 0 {
		return "", 0, nil
	}

	first := normalizeOneLoginRow(items[0])
	token = firstOneLoginString(first, "access_token", "token")
	expiresIn = parseOneLoginInt(firstOneLoginValue(first, "expires_in", "expires"))
	return token, expiresIn, nil
}

func oneLoginResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("onelogin request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid onelogin URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid onelogin base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("onelogin request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateOneLoginURL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid onelogin %s %q", field, rawURL)
	}
	return nil
}

func normalizeOneLoginRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func oneLoginMapSlice(value interface{}) []map[string]interface{} {
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

func oneLoginExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if rows := oneLoginMapSlice(payload[key]); len(rows) > 0 {
			return rows
		}
	}

	if rows := oneLoginMapSlice(payload["data"]); len(rows) > 0 {
		return rows
	}

	if firstOneLoginString(payload, "id", "user_id", "role_id", "name") != "" {
		return []map[string]interface{}{payload}
	}

	return nil
}

func firstOneLoginString(row map[string]interface{}, keys ...string) string {
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

func firstOneLoginValue(row map[string]interface{}, keys ...string) interface{} {
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

func parseOneLoginInt(value interface{}) int {
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

func isOneLoginIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
