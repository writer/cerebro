package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Duo Admin API signing requires HMAC-SHA1
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	duoDefaultUsersPageSize   = 300
	duoDefaultGroupsPageSize  = 100
	duoDefaultMembersPageSize = 500
	duoMaxPages               = 1000
)

// DuoProvider syncs Duo users, groups, and group memberships.
type DuoProvider struct {
	*BaseProvider
	baseURL        string
	host           string
	integrationKey string
	secretKey      string
	client         *http.Client
	now            func() time.Time
}

func NewDuoProvider() *DuoProvider {
	return &DuoProvider{
		BaseProvider: NewBaseProvider("duo", ProviderTypeIdentity),
		client:       &http.Client{Timeout: 30 * time.Second},
		now:          time.Now,
	}
}

func (d *DuoProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := d.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	d.integrationKey = strings.TrimSpace(d.GetConfigString("integration_key"))
	if d.integrationKey == "" {
		d.integrationKey = strings.TrimSpace(d.GetConfigString("ikey"))
	}
	if d.integrationKey == "" {
		d.integrationKey = strings.TrimSpace(d.GetConfigString("client_id"))
	}

	d.secretKey = strings.TrimSpace(d.GetConfigString("secret_key"))
	if d.secretKey == "" {
		d.secretKey = strings.TrimSpace(d.GetConfigString("skey"))
	}
	if d.secretKey == "" {
		d.secretKey = strings.TrimSpace(d.GetConfigString("client_secret"))
	}

	if d.integrationKey == "" || d.secretKey == "" {
		return fmt.Errorf("duo integration_key and secret_key required")
	}

	rawURL := strings.TrimSpace(d.GetConfigString("url"))
	if rawURL == "" {
		rawURL = strings.TrimSpace(d.GetConfigString("base_url"))
	}
	if rawURL == "" {
		rawURL = strings.TrimSpace(d.GetConfigString("api_url"))
	}
	if rawURL == "" {
		host := strings.TrimSpace(d.GetConfigString("host"))
		if host == "" {
			host = strings.TrimSpace(d.GetConfigString("api_hostname"))
		}
		if host == "" {
			return fmt.Errorf("duo url or host required")
		}
		rawURL = host
	}

	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(strings.TrimSuffix(rawURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid duo url %q", rawURL)
	}

	d.baseURL = parsed.Scheme + "://" + parsed.Host
	d.host = parsed.Host
	return nil
}

func (d *DuoProvider) Test(ctx context.Context) error {
	_, err := d.request(ctx, http.MethodGet, "/admin/v1/users", map[string]string{
		"limit":  "1",
		"offset": "0",
	})
	return err
}

func (d *DuoProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "duo_users",
			Description: "Duo users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "real_name", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "is_enrolled", Type: "boolean"},
				{Name: "lockout_reason", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "last_login_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "duo_groups",
			Description: "Duo groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "push_enabled", Type: "boolean"},
				{Name: "sms_enabled", Type: "boolean"},
				{Name: "voice_enabled", Type: "boolean"},
				{Name: "mobile_otp_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "duo_group_memberships",
			Description: "Duo group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (d *DuoProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(d.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (d *DuoProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  d.Name(),
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

	syncTable("users", d.syncUsers)
	syncTable("groups", d.syncGroups)
	syncTable("group_memberships", d.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (d *DuoProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := d.schemaFor("duo_users")
	result := &TableResult{Name: "duo_users"}
	if err != nil {
		return result, err
	}

	users, err := d.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeDuoRow(user)
		userID := firstDuoString(normalized, "user_id", "id")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":             userID,
			"username":       firstDuoValue(normalized, "username"),
			"email":          firstDuoValue(normalized, "email"),
			"real_name":      firstDuoValue(normalized, "realname", "display_name"),
			"first_name":     firstDuoValue(normalized, "firstname", "first_name"),
			"last_name":      firstDuoValue(normalized, "lastname", "last_name"),
			"status":         firstDuoValue(normalized, "status"),
			"is_enrolled":    firstDuoValue(normalized, "is_enrolled"),
			"lockout_reason": firstDuoValue(normalized, "lockout_reason"),
			"created_at":     duoTimestampValue(firstDuoValue(normalized, "created")),
			"last_login_at":  duoTimestampValue(firstDuoValue(normalized, "last_login")),
		})
	}

	return d.syncTable(ctx, schema, rows)
}

func (d *DuoProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := d.schemaFor("duo_groups")
	result := &TableResult{Name: "duo_groups"}
	if err != nil {
		return result, err
	}

	groups, err := d.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeDuoRow(group)
		groupID := firstDuoString(normalized, "group_id", "id")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":                 groupID,
			"name":               firstDuoValue(normalized, "name"),
			"description":        firstDuoValue(normalized, "desc", "description"),
			"status":             firstDuoValue(normalized, "status"),
			"push_enabled":       firstDuoValue(normalized, "push_enabled"),
			"sms_enabled":        firstDuoValue(normalized, "sms_enabled"),
			"voice_enabled":      firstDuoValue(normalized, "voice_enabled"),
			"mobile_otp_enabled": firstDuoValue(normalized, "mobile_otp_enabled"),
		})
	}

	return d.syncTable(ctx, schema, rows)
}

func (d *DuoProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := d.schemaFor("duo_group_memberships")
	result := &TableResult{Name: "duo_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := d.listGroups(ctx)
	if err != nil {
		return result, err
	}

	users, err := d.listUsers(ctx)
	if err != nil {
		return result, err
	}

	usersByID := make(map[string]map[string]interface{}, len(users))
	for _, user := range users {
		normalized := normalizeDuoRow(user)
		userID := firstDuoString(normalized, "user_id", "id")
		if userID == "" {
			continue
		}
		usersByID[userID] = normalized
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeDuoRow(group)
		groupID := firstDuoString(normalizedGroup, "group_id", "id")
		if groupID == "" {
			continue
		}
		groupName := firstDuoValue(normalizedGroup, "name")

		members, err := d.listGroupUsers(ctx, groupID)
		if err != nil {
			if isDuoIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizeDuoRow(member)
			userID := firstDuoString(normalizedMember, "user_id", "id")
			if userID == "" {
				continue
			}

			membershipID := groupID + "|" + userID
			if _, exists := seen[membershipID]; exists {
				continue
			}
			seen[membershipID] = struct{}{}

			user := usersByID[userID]
			rows = append(rows, map[string]interface{}{
				"id":         membershipID,
				"group_id":   groupID,
				"group_name": groupName,
				"user_id":    userID,
				"username":   firstNonNilDuoValue(firstDuoValue(normalizedMember, "username"), firstDuoValue(user, "username")),
			})
		}
	}

	return d.syncTable(ctx, schema, rows)
}

func (d *DuoProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return d.listPagedCollection(ctx, "/admin/v1/users", duoDefaultUsersPageSize)
}

func (d *DuoProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return d.listPagedCollection(ctx, "/admin/v1/groups", duoDefaultGroupsPageSize)
}

func (d *DuoProvider) listGroupUsers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	path := "/admin/v2/groups/" + url.PathEscape(groupID) + "/users"
	return d.listPagedCollection(ctx, path, duoDefaultMembersPageSize)
}

func (d *DuoProvider) listPagedCollection(ctx context.Context, path string, pageSize int) ([]map[string]interface{}, error) {
	offset := 0
	rows := make([]map[string]interface{}, 0)
	seenOffsets := map[int]struct{}{}

	for page := 0; page < duoMaxPages; page++ {
		payload, err := d.request(ctx, http.MethodGet, path, map[string]string{
			"limit":  strconv.Itoa(pageSize),
			"offset": strconv.Itoa(offset),
		})
		if err != nil {
			return nil, err
		}

		items, err := duoResponseItems(payload)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			rows = append(rows, normalizeDuoRow(item))
		}

		nextOffset, hasNext := duoNextOffset(payload)
		if !hasNext {
			return rows, nil
		}
		if nextOffset == offset {
			return nil, fmt.Errorf("duo pagination loop detected")
		}
		if _, exists := seenOffsets[nextOffset]; exists {
			return nil, fmt.Errorf("duo pagination loop detected")
		}
		seenOffsets[nextOffset] = struct{}{}
		offset = nextOffset
	}

	return nil, fmt.Errorf("duo pagination exceeded %d pages", duoMaxPages)
}

func (d *DuoProvider) request(ctx context.Context, method string, requestPath string, params map[string]string) (map[string]interface{}, error) {
	targetURL, signPath, encodedParams, err := d.resolveRequest(requestPath, params)
	if err != nil {
		return nil, err
	}

	now := d.now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000")
	authorization := duoAuthorizationHeader(now, method, d.host, signPath, encodedParams, d.integrationKey, d.secretKey)

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Date", now)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("duo API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	normalized := normalizeDuoRow(payload)
	if !strings.EqualFold(firstDuoString(normalized, "stat"), "OK") {
		message := firstDuoString(normalized, "message")
		if message == "" {
			message = strings.TrimSpace(string(body))
		}
		code := firstDuoString(normalized, "code")
		if code != "" {
			return nil, fmt.Errorf("duo API failure (%s): %s", code, message)
		}
		return nil, fmt.Errorf("duo API failure: %s", message)
	}

	return normalized, nil
}

func (d *DuoProvider) resolveRequest(requestPath string, params map[string]string) (string, string, string, error) {
	path := strings.TrimSpace(requestPath)
	if path == "" {
		return "", "", "", fmt.Errorf("duo request path is empty")
	}

	mergedParams := make(map[string]string, len(params))
	for key, value := range params {
		if strings.TrimSpace(key) == "" {
			continue
		}
		mergedParams[key] = value
	}

	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(path)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return "", "", "", fmt.Errorf("invalid duo URL %q", path)
		}
		if !strings.EqualFold(parsed.Host, d.host) {
			return "", "", "", fmt.Errorf("duo request URL host mismatch: %q", path)
		}

		for key, values := range parsed.Query() {
			if len(values) == 0 {
				continue
			}
			if _, exists := mergedParams[key]; !exists {
				mergedParams[key] = values[len(values)-1]
			}
		}

		signPath := parsed.EscapedPath()
		if signPath == "" {
			signPath = "/"
		}
		encoded := duoEncodeParams(mergedParams)
		target := d.baseURL + signPath
		if encoded != "" {
			target += "?" + encoded
		}
		return target, signPath, encoded, nil
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + strings.TrimPrefix(path, "/")
	}

	encoded := duoEncodeParams(mergedParams)
	target := d.baseURL + path
	if encoded != "" {
		target += "?" + encoded
	}

	return target, path, encoded, nil
}

func duoAuthorizationHeader(date string, method string, host string, path string, encodedParams string, integrationKey string, secretKey string) string {
	canonical := strings.Join([]string{
		date,
		strings.ToUpper(strings.TrimSpace(method)),
		strings.ToLower(strings.TrimSpace(host)),
		path,
		encodedParams,
	}, "\n")

	signature := hmac.New(sha1.New, []byte(secretKey))
	_, _ = signature.Write([]byte(canonical))
	sigHex := hex.EncodeToString(signature.Sum(nil))

	auth := integrationKey + ":" + sigHex
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func duoEncodeParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, duoEncodeComponent(key)+"="+duoEncodeComponent(params[key]))
	}
	return strings.Join(parts, "&")
}

func duoEncodeComponent(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

func duoResponseItems(payload map[string]interface{}) ([]map[string]interface{}, error) {
	response, ok := payload["response"]
	if !ok || response == nil {
		return nil, nil
	}

	switch typed := response.(type) {
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if row, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, row)
			}
		}
		return rows, nil
	case []map[string]interface{}:
		return typed, nil
	case map[string]interface{}:
		return []map[string]interface{}{normalizeDuoRow(typed)}, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil, nil
		}
	}

	return nil, fmt.Errorf("unexpected duo response format")
}

func duoNextOffset(payload map[string]interface{}) (int, bool) {
	metadata := duoMap(payload["metadata"])
	next, ok := metadata["next_offset"]
	if !ok || next == nil {
		return 0, false
	}

	switch typed := next.(type) {
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func duoTimestampValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	toTime := func(unix int64) interface{} {
		if unix <= 0 {
			return nil
		}
		return time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}

	switch typed := value.(type) {
	case float64:
		return toTime(int64(typed))
	case float32:
		return toTime(int64(typed))
	case int:
		return toTime(int64(typed))
	case int64:
		return toTime(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return value
		}
		return toTime(parsed)
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		parsed, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return typed
		}
		return toTime(parsed)
	default:
		return value
	}
}

func normalizeDuoRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func duoMap(value interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	if row, ok := normalizeMapKeys(value).(map[string]interface{}); ok {
		return row
	}
	return map[string]interface{}{}
}

func firstDuoString(row map[string]interface{}, keys ...string) string {
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

func firstDuoValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilDuoValue(values ...interface{}) interface{} {
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

func isDuoIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
