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
	oracleIDCSDefaultPageSize = 100
	oracleIDCSMaxPages        = 500
)

// OracleIDCSProvider syncs OracleIDCS Identity SCIM users, groups, and memberships.
type OracleIDCSProvider struct {
	*BaseProvider
	baseURL string
	token   string
	client  *http.Client
}

func NewOracleIDCSProvider() *OracleIDCSProvider {
	return &OracleIDCSProvider{
		BaseProvider: NewBaseProvider("oracle_idcs", ProviderTypeIdentity),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (c *OracleIDCSProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := c.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	c.baseURL = strings.TrimSpace(c.GetConfigString("url"))
	if c.baseURL == "" {
		c.baseURL = strings.TrimSpace(c.GetConfigString("base_url"))
	}
	if c.baseURL == "" {
		c.baseURL = strings.TrimSpace(c.GetConfigString("tenant_url"))
	}
	if c.baseURL == "" {
		return fmt.Errorf("oracle_idcs url required")
	}

	c.baseURL = strings.TrimSuffix(c.baseURL, "/")
	lowerBaseURL := strings.ToLower(c.baseURL)
	if !strings.Contains(lowerBaseURL, "/scim/") && !strings.Contains(lowerBaseURL, "/admin/v1") {
		c.baseURL += "/admin/v1"
	}

	c.token = strings.TrimSpace(c.GetConfigString("token"))
	if c.token == "" {
		c.token = strings.TrimSpace(c.GetConfigString("api_token"))
	}
	if c.token == "" {
		return fmt.Errorf("oracle_idcs token required")
	}

	if err := validateOracleIDCSURL(c.baseURL); err != nil {
		return err
	}

	return nil
}

func (c *OracleIDCSProvider) Test(ctx context.Context) error {
	_, err := c.request(ctx, addQueryParams("/Users", map[string]string{
		"startIndex": "1",
		"count":      "1",
	}))
	return err
}

func (c *OracleIDCSProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "oracle_idcs_users",
			Description: "OracleIDCS users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "given_name", Type: "string"},
				{Name: "family_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "oracle_idcs_groups",
			Description: "OracleIDCS groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "external_id", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "oracle_idcs_group_memberships",
			Description: "OracleIDCS group membership mappings",
			Columns: []ColumnSchema{
				{Name: "group_id", Type: "string", Required: true},
				{Name: "group_name", Type: "string"},
				{Name: "user_id", Type: "string", Required: true},
				{Name: "username", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "type", Type: "string"},
			},
			PrimaryKey: []string{"group_id", "user_id"},
		},
	}
}

func (c *OracleIDCSProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(c.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (c *OracleIDCSProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  c.Name(),
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

	syncTable("users", c.syncUsers)
	syncTable("groups", c.syncGroups)
	syncTable("group_memberships", c.syncGroupMemberships)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (c *OracleIDCSProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("oracle_idcs_users")
	result := &TableResult{Name: "oracle_idcs_users"}
	if err != nil {
		return result, err
	}

	users, err := c.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeOracleIDCSRow(user)
		name := oracleIDCSMap(normalized["name"])
		meta := oracleIDCSMap(normalized["meta"])
		emails := oracleIDCSMapSlice(normalized["emails"])

		userID := firstOracleIDCSString(normalized, "id", "external_id", "user_name")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           userID,
			"username":     firstOracleIDCSValue(normalized, "user_name", "username"),
			"given_name":   firstNonNilOracleIDCSValue(firstOracleIDCSValue(name, "given_name"), firstOracleIDCSValue(normalized, "given_name")),
			"family_name":  firstNonNilOracleIDCSValue(firstOracleIDCSValue(name, "family_name"), firstOracleIDCSValue(normalized, "family_name")),
			"display_name": firstOracleIDCSValue(normalized, "display_name", "name"),
			"email": firstNonNilOracleIDCSValue(
				oracleIDCSPrimaryCollectionValue(emails, "value"),
				firstOracleIDCSValue(normalized, "email", "primary_email"),
			),
			"active": firstOracleIDCSValue(normalized, "active", "enabled"),
			"created_at": firstNonNilOracleIDCSValue(
				firstOracleIDCSValue(meta, "created"),
				firstOracleIDCSValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilOracleIDCSValue(
				firstOracleIDCSValue(meta, "last_modified", "updated"),
				firstOracleIDCSValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *OracleIDCSProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("oracle_idcs_groups")
	result := &TableResult{Name: "oracle_idcs_groups"}
	if err != nil {
		return result, err
	}

	groups, err := c.listGroups(ctx)
	if err != nil {
		if isOracleIDCSIgnorableError(err) {
			return c.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeOracleIDCSRow(group)
		meta := oracleIDCSMap(normalized["meta"])

		groupID := firstOracleIDCSString(normalized, "id", "external_id", "display_name")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           groupID,
			"display_name": firstOracleIDCSValue(normalized, "display_name", "name"),
			"external_id":  firstOracleIDCSValue(normalized, "external_id"),
			"description":  firstOracleIDCSValue(normalized, "description", "desc"),
			"created_at": firstNonNilOracleIDCSValue(
				firstOracleIDCSValue(meta, "created"),
				firstOracleIDCSValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilOracleIDCSValue(
				firstOracleIDCSValue(meta, "last_modified", "updated"),
				firstOracleIDCSValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *OracleIDCSProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("oracle_idcs_group_memberships")
	result := &TableResult{Name: "oracle_idcs_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := c.listGroups(ctx)
	if err != nil {
		if isOracleIDCSIgnorableError(err) {
			return c.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	users, err := c.listUsers(ctx)
	if err != nil {
		return result, err
	}

	usersByID := make(map[string]map[string]interface{}, len(users))
	for _, user := range users {
		normalized := normalizeOracleIDCSRow(user)
		userID := firstOracleIDCSString(normalized, "id", "external_id", "user_name")
		if userID == "" {
			continue
		}
		usersByID[userID] = normalized
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeOracleIDCSRow(group)
		groupID := firstOracleIDCSString(normalizedGroup, "id", "external_id")
		if groupID == "" {
			continue
		}

		groupName := firstOracleIDCSValue(normalizedGroup, "display_name", "name")
		members := oracleIDCSExtractMembers(normalizedGroup)
		if len(members) == 0 {
			fetched, fetchErr := c.fetchGroupMembers(ctx, groupID)
			if fetchErr != nil {
				if isOracleIDCSIgnorableError(fetchErr) || isOracleIDCSNotSupportedError(fetchErr) {
					continue
				}
				return result, fetchErr
			}
			members = fetched
		}

		for _, member := range members {
			normalizedMember := normalizeOracleIDCSRow(member)
			userID := firstOracleIDCSString(normalizedMember, "value", "user_id", "member_id", "id")
			if userID == "" {
				ref := firstOracleIDCSString(normalizedMember, "$ref", "ref", "href", "location")
				userID = oracleIDCSIDFromReference(ref, "Users")
			}
			if userID == "" {
				continue
			}

			membershipKey := groupID + "|" + userID
			if _, exists := seen[membershipKey]; exists {
				continue
			}
			seen[membershipKey] = struct{}{}

			user := usersByID[userID]
			rows = append(rows, map[string]interface{}{
				"group_id":   groupID,
				"group_name": groupName,
				"user_id":    userID,
				"username": firstNonNilOracleIDCSValue(
					firstOracleIDCSValue(normalizedMember, "display", "username", "name"),
					firstOracleIDCSValue(user, "user_name", "username", "display_name"),
				),
				"email": firstNonNilOracleIDCSValue(
					oracleIDCSPrimaryCollectionValue(oracleIDCSMapSlice(user["emails"]), "value"),
					firstOracleIDCSValue(user, "email", "primary_email"),
				),
				"type": firstOracleIDCSValue(normalizedMember, "type", "member_type"),
			})
		}
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *OracleIDCSProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return c.listSCIMResources(ctx, "/Users")
}

func (c *OracleIDCSProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return c.listSCIMResources(ctx, "/Groups")
}

func (c *OracleIDCSProvider) listSCIMResources(ctx context.Context, resourcePath string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	startIndex := 1
	seenStartIndices := make(map[int]struct{})

	for page := 0; page < oracleIDCSMaxPages; page++ {
		if _, exists := seenStartIndices[startIndex]; exists {
			return nil, fmt.Errorf("oracle_idcs pagination loop detected for %s", resourcePath)
		}
		seenStartIndices[startIndex] = struct{}{}

		requestPath := addQueryParams(resourcePath, map[string]string{
			"startIndex": strconv.Itoa(startIndex),
			"count":      strconv.Itoa(oracleIDCSDefaultPageSize),
		})

		body, err := c.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalizedPayload := normalizeOracleIDCSRow(payload)
		resources := oracleIDCSExtractResources(normalizedPayload)
		for _, resource := range resources {
			rows = append(rows, normalizeOracleIDCSRow(resource))
		}

		if len(resources) == 0 {
			break
		}

		totalResults := firstOracleIDCSInt(normalizedPayload, "total_results", "totalresults")
		itemsPerPage := firstOracleIDCSInt(normalizedPayload, "items_per_page", "itemsperpage")
		if itemsPerPage <= 0 {
			itemsPerPage = len(resources)
		}

		nextStartIndex := startIndex + len(resources)
		if nextStartIndex <= startIndex {
			return nil, fmt.Errorf("oracle_idcs pagination loop detected for %s", resourcePath)
		}

		if totalResults > 0 {
			if nextStartIndex > totalResults {
				break
			}
		} else if len(resources) < itemsPerPage || len(resources) < oracleIDCSDefaultPageSize {
			break
		}

		startIndex = nextStartIndex
	}

	return rows, nil
}

func (c *OracleIDCSProvider) fetchGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	if strings.TrimSpace(groupID) == "" {
		return nil, nil
	}

	path := "/Groups/" + url.PathEscape(groupID)
	candidates := []string{path, path + "?attributes=members", path + "/members"}

	var lastErr error
	for _, candidate := range candidates {
		body, err := c.request(ctx, candidate)
		if err != nil {
			if isOracleIDCSIgnorableError(err) || isOracleIDCSNotSupportedError(err) {
				lastErr = err
				continue
			}
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			normalizedPayload := normalizeOracleIDCSRow(payload)
			if members := oracleIDCSExtractMembers(normalizedPayload); len(members) > 0 {
				return members, nil
			}

			for _, resource := range oracleIDCSExtractResources(normalizedPayload) {
				if members := oracleIDCSExtractMembers(normalizeOracleIDCSRow(resource)); len(members) > 0 {
					return members, nil
				}
			}

			continue
		}

		var list []interface{}
		if err := json.Unmarshal(body, &list); err == nil {
			if members := oracleIDCSFilterMemberRows(oracleIDCSMapSlice(list)); len(members) > 0 {
				return members, nil
			}
		}
	}

	if lastErr != nil && (isOracleIDCSIgnorableError(lastErr) || isOracleIDCSNotSupportedError(lastErr)) {
		return nil, nil
	}

	return nil, nil
}

func (c *OracleIDCSProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := oracleIDCSResolveRequestURL(c.baseURL, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("oracle_idcs API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func oracleIDCSResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("oracle_idcs request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid oracle_idcs URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid oracle_idcs base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("oracle_idcs request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateOracleIDCSURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid oracle_idcs url %q", rawURL)
	}
	return nil
}

func normalizeOracleIDCSRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func oracleIDCSMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func oracleIDCSMapSlice(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			if normalized, ok := normalizeMapKeys(item).(map[string]interface{}); ok {
				rows = append(rows, normalized)
			}
		}
		return rows
	default:
		return nil
	}
}

func oracleIDCSExtractResources(payload map[string]interface{}) []map[string]interface{} {
	for _, key := range []string{"resources", "items", "result", "data"} {
		if resources := oracleIDCSMapSlice(payload[key]); len(resources) > 0 {
			return resources
		}
	}
	if resource := oracleIDCSMap(payload["resource"]); len(resource) > 0 {
		return []map[string]interface{}{resource}
	}
	return nil
}

func oracleIDCSExtractMembers(payload map[string]interface{}) []map[string]interface{} {
	for _, key := range []string{"members", "member", "users", "resources", "items", "data"} {
		if rows := oracleIDCSFilterMemberRows(oracleIDCSMapSlice(payload[key])); len(rows) > 0 {
			return rows
		}
	}

	if oracleIDCSLooksLikeMember(payload) {
		return []map[string]interface{}{payload}
	}

	return nil
}

func oracleIDCSFilterMemberRows(rows []map[string]interface{}) []map[string]interface{} {
	if len(rows) == 0 {
		return nil
	}

	filtered := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		normalized := normalizeOracleIDCSRow(row)
		if oracleIDCSLooksLikeMember(normalized) {
			filtered = append(filtered, normalized)
		}
	}

	return filtered
}

func oracleIDCSLooksLikeMember(row map[string]interface{}) bool {
	if len(row) == 0 {
		return false
	}

	if firstOracleIDCSString(row, "value", "user_id", "member_id", "$ref", "ref", "href", "location") != "" {
		return true
	}

	if _, hasID := row["id"]; hasID {
		if _, hasMembers := row["members"]; hasMembers {
			return false
		}
		if firstOracleIDCSString(row, "user_name", "username", "email") != "" {
			return true
		}
		if _, hasEmails := row["emails"]; hasEmails {
			return true
		}
		if _, hasDisplay := row["display"]; hasDisplay {
			return true
		}
		if _, hasType := row["type"]; hasType {
			return true
		}
		if _, hasDisplayName := row["display_name"]; hasDisplayName {
			return false
		}
		return true
	}

	return false
}

func oracleIDCSPrimaryCollectionValue(items []map[string]interface{}, keys ...string) interface{} {
	for _, primaryOnly := range []bool{true, false} {
		for _, item := range items {
			normalized := normalizeOracleIDCSRow(item)
			if primaryOnly && !oracleIDCSBool(normalized["primary"]) {
				continue
			}
			if value := firstOracleIDCSValue(normalized, keys...); value != nil {
				return value
			}
		}
	}
	return nil
}

func oracleIDCSIDFromReference(reference string, resource string) string {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return ""
	}

	parsed, err := url.Parse(reference)
	if err == nil && parsed.Path != "" {
		reference = parsed.Path
	}

	segments := strings.Split(strings.Trim(reference, "/"), "/")
	for i := 0; i < len(segments)-1; i++ {
		if strings.EqualFold(segments[i], resource) {
			candidate := strings.TrimSpace(segments[i+1])
			if decoded, decodeErr := url.PathUnescape(candidate); decodeErr == nil {
				candidate = decoded
			}
			if candidate != "" {
				return candidate
			}
		}
	}

	if len(segments) > 0 {
		candidate := strings.TrimSpace(segments[len(segments)-1])
		if decoded, decodeErr := url.PathUnescape(candidate); decodeErr == nil {
			candidate = decoded
		}
		return candidate
	}

	return ""
}

func firstOracleIDCSString(row map[string]interface{}, keys ...string) string {
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

func firstOracleIDCSValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilOracleIDCSValue(values ...interface{}) interface{} {
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

func firstOracleIDCSInt(row map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if parsed, ok := parseOracleIDCSInt(value); ok {
			return parsed
		}
	}
	return 0
}

func parseOracleIDCSInt(value interface{}) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	default:
		text := strings.TrimSpace(providerStringValue(value))
		if text == "" {
			return 0, false
		}
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
}

func oracleIDCSBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		text := strings.ToLower(strings.TrimSpace(providerStringValue(value)))
		return text == "1" || text == "true" || text == "yes"
	}
}

func isOracleIDCSIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func isOracleIDCSNotSupportedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 405") || strings.Contains(message, "api error 501")
}
