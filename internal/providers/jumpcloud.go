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
	jumpCloudDefaultBaseURL  = "https://console.jumpcloud.com"
	jumpCloudDefaultPageSize = 100
	jumpCloudMaxPages        = 1000
)

// JumpCloudProvider syncs JumpCloud users, groups, and memberships.
type JumpCloudProvider struct {
	*BaseProvider
	v1BaseURL string
	v2BaseURL string
	apiToken  string
	orgID     string
	client    *http.Client
}

func NewJumpCloudProvider() *JumpCloudProvider {
	return &JumpCloudProvider{
		BaseProvider: NewBaseProvider("jumpcloud", ProviderTypeIdentity),
		v1BaseURL:    jumpCloudDefaultBaseURL + "/api",
		v2BaseURL:    jumpCloudDefaultBaseURL + "/api/v2",
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (j *JumpCloudProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := j.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	j.apiToken = strings.TrimSpace(j.GetConfigString("api_token"))
	if j.apiToken == "" {
		j.apiToken = strings.TrimSpace(j.GetConfigString("token"))
	}
	if j.apiToken == "" {
		return fmt.Errorf("jumpcloud api token required")
	}

	j.orgID = strings.TrimSpace(j.GetConfigString("org_id"))

	baseURL := strings.TrimSpace(j.GetConfigString("url"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(j.GetConfigString("base_url"))
	}
	if baseURL == "" {
		baseURL = strings.TrimSpace(j.GetConfigString("api_url"))
	}
	if baseURL == "" {
		baseURL = jumpCloudDefaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	v1BaseURL, v2BaseURL := deriveJumpCloudBaseURLs(baseURL)
	if err := validateJumpCloudURL(v1BaseURL, "url"); err != nil {
		return err
	}
	if err := validateJumpCloudURL(v2BaseURL, "url"); err != nil {
		return err
	}

	j.v1BaseURL = v1BaseURL
	j.v2BaseURL = v2BaseURL
	return nil
}

func (j *JumpCloudProvider) Test(ctx context.Context) error {
	_, err := j.requestV1(ctx, addQueryParams("/systemusers", map[string]string{
		"limit": "1",
		"skip":  "0",
	}))
	return err
}

func (j *JumpCloudProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "jumpcloud_users",
			Description: "JumpCloud users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "job_title", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "employee_identifier", Type: "string"},
				{Name: "employee_type", Type: "string"},
				{Name: "suspended", Type: "boolean"},
				{Name: "activated", Type: "boolean"},
				{Name: "mfa_enabled", Type: "boolean"},
				{Name: "password_never_expires", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "password_expires_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jumpcloud_groups",
			Description: "JumpCloud user groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "membership_method", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jumpcloud_group_memberships",
			Description: "JumpCloud user group memberships",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "user_email", Type: "string"},
				{Name: "user_username", Type: "string"},
				{Name: "relation_type", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (j *JumpCloudProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(j.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (j *JumpCloudProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  j.Name(),
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

	syncTable("users", j.syncUsers)
	syncTable("groups", j.syncGroups)
	syncTable("group_memberships", j.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (j *JumpCloudProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := j.schemaFor("jumpcloud_users")
	result := &TableResult{Name: "jumpcloud_users"}
	if err != nil {
		return result, err
	}

	users, err := j.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeJumpCloudRow(user)
		userID := firstJumpCloudString(normalized, "id", "_id", "user_id")
		if userID == "" {
			continue
		}

		mfa := jumpCloudMap(normalized["mfa"])

		rows = append(rows, map[string]interface{}{
			"id":                     userID,
			"username":               firstJumpCloudValue(normalized, "username"),
			"email":                  firstJumpCloudValue(normalized, "email", "alternate_email", "alternateemail"),
			"first_name":             firstJumpCloudValue(normalized, "firstname", "first_name"),
			"last_name":              firstJumpCloudValue(normalized, "lastname", "last_name"),
			"display_name":           firstJumpCloudValue(normalized, "displayname", "display_name"),
			"department":             firstJumpCloudValue(normalized, "department"),
			"job_title":              firstJumpCloudValue(normalized, "job_title", "jobtitle"),
			"location":               firstJumpCloudValue(normalized, "location"),
			"employee_identifier":    firstJumpCloudValue(normalized, "employee_identifier", "employeeidentifier"),
			"employee_type":          firstJumpCloudValue(normalized, "employee_type", "employeetype"),
			"suspended":              firstJumpCloudValue(normalized, "suspended"),
			"activated":              firstJumpCloudValue(normalized, "activated"),
			"mfa_enabled":            firstNonNilJumpCloudValue(firstJumpCloudValue(mfa, "configured"), firstJumpCloudValue(normalized, "enable_user_portal_multifactor")),
			"password_never_expires": firstJumpCloudValue(normalized, "password_never_expires"),
			"created_at":             firstJumpCloudValue(normalized, "created"),
			"password_expires_at":    firstJumpCloudValue(normalized, "password_expiration_date"),
			"updated_at":             firstJumpCloudValue(normalized, "updated", "updated_at"),
		})
	}

	return j.syncTable(ctx, schema, rows)
}

func (j *JumpCloudProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := j.schemaFor("jumpcloud_groups")
	result := &TableResult{Name: "jumpcloud_groups"}
	if err != nil {
		return result, err
	}

	groups, err := j.listGroups(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeJumpCloudRow(group)
		groupID := firstJumpCloudString(normalized, "id", "_id", "group_id", "name")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":                groupID,
			"name":              firstJumpCloudValue(normalized, "name"),
			"description":       firstJumpCloudValue(normalized, "description"),
			"email":             firstJumpCloudValue(normalized, "email"),
			"membership_method": firstJumpCloudValue(normalized, "membership_method"),
			"type":              firstJumpCloudValue(normalized, "type"),
			"created_at":        firstJumpCloudValue(normalized, "created", "created_at"),
			"updated_at":        firstJumpCloudValue(normalized, "updated", "updated_at"),
		})
	}

	return j.syncTable(ctx, schema, rows)
}

func (j *JumpCloudProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := j.schemaFor("jumpcloud_group_memberships")
	result := &TableResult{Name: "jumpcloud_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := j.listGroups(ctx)
	if err != nil {
		return result, err
	}

	users, err := j.listUsers(ctx)
	if err != nil {
		return result, err
	}

	usersByID := make(map[string]map[string]interface{}, len(users))
	for _, user := range users {
		normalized := normalizeJumpCloudRow(user)
		userID := firstJumpCloudString(normalized, "id", "_id", "user_id")
		if userID == "" {
			continue
		}
		usersByID[userID] = normalized
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeJumpCloudRow(group)
		groupID := firstJumpCloudString(normalizedGroup, "id", "_id", "group_id", "name")
		if groupID == "" {
			continue
		}
		groupName := firstJumpCloudValue(normalizedGroup, "name")

		members, err := j.listGroupMembers(ctx, groupID)
		if err != nil {
			if isJumpCloudIgnorableError(err) {
				continue
			}
			return result, err
		}

		for _, member := range members {
			normalizedMember := normalizeJumpCloudRow(member)
			userID := jumpCloudMembershipUserID(normalizedMember, groupID)
			if userID == "" {
				continue
			}

			membershipID := groupID + "|" + userID
			if _, ok := seen[membershipID]; ok {
				continue
			}
			seen[membershipID] = struct{}{}

			user := usersByID[userID]
			memberFrom := jumpCloudMap(normalizedMember["from"])
			memberTo := jumpCloudMap(normalizedMember["to"])

			rows = append(rows, map[string]interface{}{
				"id":            membershipID,
				"group_id":      groupID,
				"group_name":    groupName,
				"user_id":       userID,
				"user_email":    firstNonNilJumpCloudValue(firstJumpCloudValue(normalizedMember, "email", "user_email"), firstJumpCloudValue(user, "email", "alternate_email", "alternateemail"), firstJumpCloudValue(jumpCloudMap(memberTo["attributes"]), "email"), firstJumpCloudValue(jumpCloudMap(memberFrom["attributes"]), "email")),
				"user_username": firstNonNilJumpCloudValue(firstJumpCloudValue(normalizedMember, "username", "user_name"), firstJumpCloudValue(user, "username"), firstJumpCloudValue(jumpCloudMap(memberTo["attributes"]), "username"), firstJumpCloudValue(jumpCloudMap(memberFrom["attributes"]), "username")),
				"relation_type": firstNonNilJumpCloudValue(firstJumpCloudValue(memberFrom, "type"), firstJumpCloudValue(memberTo, "type")),
			})
		}
	}

	return j.syncTable(ctx, schema, rows)
}

func (j *JumpCloudProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return j.listCollection(ctx, j.requestV1, "/systemusers", []string{"results", "users", "systemusers"})
}

func (j *JumpCloudProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return j.listCollection(ctx, j.requestV2, "/usergroups", []string{"results", "data", "groups", "usergroups"})
}

func (j *JumpCloudProvider) listGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	path := "/usergroups/" + url.PathEscape(groupID) + "/members"
	return j.listCollection(ctx, j.requestV2, path, []string{"results", "data", "members"})
}

func (j *JumpCloudProvider) listCollection(ctx context.Context, requestFn func(context.Context, string) ([]byte, error), path string, keys []string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	seenPageSignatures := make(map[string]struct{})

	for page := 0; page < jumpCloudMaxPages; page++ {
		skip := page * jumpCloudDefaultPageSize
		requestPath := addQueryParams(path, map[string]string{
			"limit": strconv.Itoa(jumpCloudDefaultPageSize),
			"skip":  strconv.Itoa(skip),
		})

		body, err := requestFn(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		items, err := jumpCloudDecodeItems(body, keys...)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}

		signature := jumpCloudPageSignature(items[0], len(items))
		if _, exists := seenPageSignatures[signature]; exists {
			return nil, fmt.Errorf("jumpcloud pagination loop detected")
		}
		seenPageSignatures[signature] = struct{}{}

		for _, item := range items {
			rows = append(rows, normalizeJumpCloudRow(item))
		}

		if len(items) < jumpCloudDefaultPageSize {
			break
		}
	}

	return rows, nil
}

func (j *JumpCloudProvider) requestV1(ctx context.Context, path string) ([]byte, error) {
	return j.request(ctx, j.v1BaseURL, path)
}

func (j *JumpCloudProvider) requestV2(ctx context.Context, path string) ([]byte, error) {
	return j.request(ctx, j.v2BaseURL, path)
}

func (j *JumpCloudProvider) request(ctx context.Context, baseURL string, path string) ([]byte, error) {
	requestURL, err := jumpCloudResolveRequestURL(baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", j.apiToken)
	req.Header.Set("Accept", "application/json")
	if j.orgID != "" {
		req.Header.Set("x-org-id", j.orgID)
	}

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("jumpcloud API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func deriveJumpCloudBaseURLs(baseURL string) (string, string) {
	normalized := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	lower := strings.ToLower(normalized)

	if idx := strings.Index(lower, "/api/v2"); idx >= 0 {
		prefix := normalized[:idx]
		return prefix + "/api", prefix + "/api/v2"
	}

	if idx := strings.Index(lower, "/api"); idx >= 0 {
		prefix := normalized[:idx]
		return prefix + "/api", prefix + "/api/v2"
	}

	return normalized + "/api", normalized + "/api/v2"
}

func jumpCloudDecodeItems(body []byte, keys ...string) ([]map[string]interface{}, error) {
	var list []map[string]interface{}
	if err := json.Unmarshal(body, &list); err == nil {
		rows := make([]map[string]interface{}, 0, len(list))
		for _, item := range list {
			rows = append(rows, normalizeJumpCloudRow(item))
		}
		return rows, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	normalized := normalizeJumpCloudRow(payload)
	searchKeys := append([]string{}, keys...)
	searchKeys = append(searchKeys, "results", "data", "items", "members", "users", "groups")
	for _, key := range searchKeys {
		if rows := jumpCloudMapSlice(normalized[key]); len(rows) > 0 {
			return rows, nil
		}
	}

	if firstJumpCloudString(normalized, "id", "_id", "name") != "" {
		return []map[string]interface{}{normalized}, nil
	}

	return nil, nil
}

func jumpCloudPageSignature(item map[string]interface{}, count int) string {
	normalized := normalizeJumpCloudRow(item)
	primary := firstJumpCloudString(normalized, "id", "_id", "name")
	if primary == "" {
		from := jumpCloudMap(normalized["from"])
		to := jumpCloudMap(normalized["to"])
		primary = firstJumpCloudString(from, "id", "_id") + "->" + firstJumpCloudString(to, "id", "_id")
	}
	return fmt.Sprintf("%s:%d", primary, count)
}

func jumpCloudMembershipUserID(member map[string]interface{}, groupID string) string {
	from := jumpCloudMap(member["from"])
	to := jumpCloudMap(member["to"])

	fromID := firstJumpCloudString(from, "id", "_id")
	toID := firstJumpCloudString(to, "id", "_id")
	fromType := strings.ToLower(firstJumpCloudString(from, "type"))
	toType := strings.ToLower(firstJumpCloudString(to, "type"))

	if strings.Contains(fromType, "group") || fromID == groupID {
		if toID != "" && toID != groupID {
			return toID
		}
	}
	if strings.Contains(toType, "group") || toID == groupID {
		if fromID != "" && fromID != groupID {
			return fromID
		}
	}

	if userID := firstJumpCloudString(member, "user_id", "userid", "id"); userID != "" && userID != groupID {
		return userID
	}

	if strings.Contains(toType, "user") && toID != "" {
		return toID
	}
	if strings.Contains(fromType, "user") && fromID != "" {
		return fromID
	}

	if toID != "" && toID != groupID {
		return toID
	}
	if fromID != "" && fromID != groupID {
		return fromID
	}

	return ""
}

func jumpCloudResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("jumpcloud request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid jumpcloud URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid jumpcloud base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("jumpcloud request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateJumpCloudURL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid jumpcloud %s %q", field, rawURL)
	}
	return nil
}

func normalizeJumpCloudRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func jumpCloudMap(value interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	if row, ok := normalizeMapKeys(value).(map[string]interface{}); ok {
		return row
	}
	return map[string]interface{}{}
}

func jumpCloudMapSlice(value interface{}) []map[string]interface{} {
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

func firstJumpCloudString(row map[string]interface{}, keys ...string) string {
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

func firstJumpCloudValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilJumpCloudValue(values ...interface{}) interface{} {
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

func isJumpCloudIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}
