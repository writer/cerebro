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
	cyberArkDefaultPageSize = 100
	cyberArkMaxPages        = 500
)

// CyberArkProvider syncs CyberArk Identity SCIM users, groups, and memberships.
type CyberArkProvider struct {
	*BaseProvider
	baseURL string
	token   string
	client  *http.Client
}

func NewCyberArkProvider() *CyberArkProvider {
	return &CyberArkProvider{
		BaseProvider: NewBaseProvider("cyberark", ProviderTypeIdentity),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CyberArkProvider) Configure(ctx context.Context, config map[string]interface{}) error {
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
		return fmt.Errorf("cyberark url required")
	}

	c.baseURL = strings.TrimSuffix(c.baseURL, "/")
	if !strings.Contains(strings.ToLower(c.baseURL), "/scim/") {
		c.baseURL += "/scim/v2"
	}

	c.token = strings.TrimSpace(c.GetConfigString("token"))
	if c.token == "" {
		c.token = strings.TrimSpace(c.GetConfigString("api_token"))
	}
	if c.token == "" {
		return fmt.Errorf("cyberark token required")
	}

	if err := validateCyberArkURL(c.baseURL); err != nil {
		return err
	}

	return nil
}

func (c *CyberArkProvider) Test(ctx context.Context) error {
	_, err := c.request(ctx, addQueryParams("/Users", map[string]string{
		"startIndex": "1",
		"count":      "1",
	}))
	return err
}

func (c *CyberArkProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "cyberark_users",
			Description: "CyberArk users",
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
			Name:        "cyberark_groups",
			Description: "CyberArk groups",
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
			Name:        "cyberark_group_memberships",
			Description: "CyberArk group membership mappings",
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

func (c *CyberArkProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(c.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (c *CyberArkProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
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

func (c *CyberArkProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("cyberark_users")
	result := &TableResult{Name: "cyberark_users"}
	if err != nil {
		return result, err
	}

	users, err := c.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeCyberArkRow(user)
		name := cyberArkMap(normalized["name"])
		meta := cyberArkMap(normalized["meta"])
		emails := cyberArkMapSlice(normalized["emails"])

		userID := firstCyberArkString(normalized, "id", "external_id", "user_name")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           userID,
			"username":     firstCyberArkValue(normalized, "user_name", "username"),
			"given_name":   firstNonNilCyberArkValue(firstCyberArkValue(name, "given_name"), firstCyberArkValue(normalized, "given_name")),
			"family_name":  firstNonNilCyberArkValue(firstCyberArkValue(name, "family_name"), firstCyberArkValue(normalized, "family_name")),
			"display_name": firstCyberArkValue(normalized, "display_name", "name"),
			"email": firstNonNilCyberArkValue(
				cyberArkPrimaryCollectionValue(emails, "value"),
				firstCyberArkValue(normalized, "email", "primary_email"),
			),
			"active": firstCyberArkValue(normalized, "active", "enabled"),
			"created_at": firstNonNilCyberArkValue(
				firstCyberArkValue(meta, "created"),
				firstCyberArkValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilCyberArkValue(
				firstCyberArkValue(meta, "last_modified", "updated"),
				firstCyberArkValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CyberArkProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("cyberark_groups")
	result := &TableResult{Name: "cyberark_groups"}
	if err != nil {
		return result, err
	}

	groups, err := c.listGroups(ctx)
	if err != nil {
		if isCyberArkIgnorableError(err) {
			return c.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		normalized := normalizeCyberArkRow(group)
		meta := cyberArkMap(normalized["meta"])

		groupID := firstCyberArkString(normalized, "id", "external_id", "display_name")
		if groupID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":           groupID,
			"display_name": firstCyberArkValue(normalized, "display_name", "name"),
			"external_id":  firstCyberArkValue(normalized, "external_id"),
			"description":  firstCyberArkValue(normalized, "description", "desc"),
			"created_at": firstNonNilCyberArkValue(
				firstCyberArkValue(meta, "created"),
				firstCyberArkValue(normalized, "created_at"),
			),
			"updated_at": firstNonNilCyberArkValue(
				firstCyberArkValue(meta, "last_modified", "updated"),
				firstCyberArkValue(normalized, "updated_at", "last_modified"),
			),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CyberArkProvider) syncGroupMemberships(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("cyberark_group_memberships")
	result := &TableResult{Name: "cyberark_group_memberships"}
	if err != nil {
		return result, err
	}

	groups, err := c.listGroups(ctx)
	if err != nil {
		if isCyberArkIgnorableError(err) {
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
		normalized := normalizeCyberArkRow(user)
		userID := firstCyberArkString(normalized, "id", "external_id", "user_name")
		if userID == "" {
			continue
		}
		usersByID[userID] = normalized
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, group := range groups {
		normalizedGroup := normalizeCyberArkRow(group)
		groupID := firstCyberArkString(normalizedGroup, "id", "external_id")
		if groupID == "" {
			continue
		}

		groupName := firstCyberArkValue(normalizedGroup, "display_name", "name")
		members := cyberArkExtractMembers(normalizedGroup)
		if len(members) == 0 {
			fetched, fetchErr := c.fetchGroupMembers(ctx, groupID)
			if fetchErr != nil {
				if isCyberArkIgnorableError(fetchErr) || isCyberArkNotSupportedError(fetchErr) {
					continue
				}
				return result, fetchErr
			}
			members = fetched
		}

		for _, member := range members {
			normalizedMember := normalizeCyberArkRow(member)
			userID := firstCyberArkString(normalizedMember, "value", "user_id", "member_id", "id")
			if userID == "" {
				ref := firstCyberArkString(normalizedMember, "$ref", "ref", "href", "location")
				userID = cyberArkIDFromReference(ref, "Users")
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
				"username": firstNonNilCyberArkValue(
					firstCyberArkValue(normalizedMember, "display", "username", "name"),
					firstCyberArkValue(user, "user_name", "username", "display_name"),
				),
				"email": firstNonNilCyberArkValue(
					cyberArkPrimaryCollectionValue(cyberArkMapSlice(user["emails"]), "value"),
					firstCyberArkValue(user, "email", "primary_email"),
				),
				"type": firstCyberArkValue(normalizedMember, "type", "member_type"),
			})
		}
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CyberArkProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return c.listSCIMResources(ctx, "/Users")
}

func (c *CyberArkProvider) listGroups(ctx context.Context) ([]map[string]interface{}, error) {
	return c.listSCIMResources(ctx, "/Groups")
}

func (c *CyberArkProvider) listSCIMResources(ctx context.Context, resourcePath string) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	startIndex := 1
	seenStartIndices := make(map[int]struct{})

	for page := 0; page < cyberArkMaxPages; page++ {
		if _, exists := seenStartIndices[startIndex]; exists {
			return nil, fmt.Errorf("cyberark pagination loop detected for %s", resourcePath)
		}
		seenStartIndices[startIndex] = struct{}{}

		requestPath := addQueryParams(resourcePath, map[string]string{
			"startIndex": strconv.Itoa(startIndex),
			"count":      strconv.Itoa(cyberArkDefaultPageSize),
		})

		body, err := c.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		normalizedPayload := normalizeCyberArkRow(payload)
		resources := cyberArkExtractResources(normalizedPayload)
		for _, resource := range resources {
			rows = append(rows, normalizeCyberArkRow(resource))
		}

		if len(resources) == 0 {
			break
		}

		totalResults := firstCyberArkInt(normalizedPayload, "total_results", "totalresults")
		itemsPerPage := firstCyberArkInt(normalizedPayload, "items_per_page", "itemsperpage")
		if itemsPerPage <= 0 {
			itemsPerPage = len(resources)
		}

		nextStartIndex := startIndex + len(resources)
		if nextStartIndex <= startIndex {
			return nil, fmt.Errorf("cyberark pagination loop detected for %s", resourcePath)
		}

		if totalResults > 0 {
			if nextStartIndex > totalResults {
				break
			}
		} else if len(resources) < itemsPerPage || len(resources) < cyberArkDefaultPageSize {
			break
		}

		startIndex = nextStartIndex
	}

	return rows, nil
}

func (c *CyberArkProvider) fetchGroupMembers(ctx context.Context, groupID string) ([]map[string]interface{}, error) {
	if strings.TrimSpace(groupID) == "" {
		return nil, nil
	}

	path := "/Groups/" + url.PathEscape(groupID)
	candidates := []string{path, path + "?attributes=members", path + "/members"}

	var lastErr error
	for _, candidate := range candidates {
		body, err := c.request(ctx, candidate)
		if err != nil {
			if isCyberArkIgnorableError(err) || isCyberArkNotSupportedError(err) {
				lastErr = err
				continue
			}
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			normalizedPayload := normalizeCyberArkRow(payload)
			if members := cyberArkExtractMembers(normalizedPayload); len(members) > 0 {
				return members, nil
			}

			for _, resource := range cyberArkExtractResources(normalizedPayload) {
				if members := cyberArkExtractMembers(normalizeCyberArkRow(resource)); len(members) > 0 {
					return members, nil
				}
			}

			continue
		}

		var list []interface{}
		if err := json.Unmarshal(body, &list); err == nil {
			if members := cyberArkFilterMemberRows(cyberArkMapSlice(list)); len(members) > 0 {
				return members, nil
			}
		}
	}

	if lastErr != nil && (isCyberArkIgnorableError(lastErr) || isCyberArkNotSupportedError(lastErr)) {
		return nil, nil
	}

	return nil, nil
}

func (c *CyberArkProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL, err := cyberArkResolveRequestURL(c.baseURL, path)
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
		return nil, fmt.Errorf("cyberark API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func cyberArkResolveRequestURL(baseURL string, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("cyberark request path is empty")
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resolved, err := url.Parse(cleanPath)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			return "", fmt.Errorf("invalid cyberark URL %q", cleanPath)
		}

		baseParsed, err := url.Parse(baseURL)
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			return "", fmt.Errorf("invalid cyberark base URL %q", baseURL)
		}

		if !strings.EqualFold(baseParsed.Scheme, resolved.Scheme) || !strings.EqualFold(baseParsed.Host, resolved.Host) {
			return "", fmt.Errorf("cyberark request URL host mismatch: %q", cleanPath)
		}

		return resolved.String(), nil
	}

	if strings.HasPrefix(cleanPath, "/") {
		return baseURL + cleanPath, nil
	}

	return baseURL + "/" + strings.TrimPrefix(cleanPath, "/"), nil
}

func validateCyberArkURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid cyberark url %q", rawURL)
	}
	return nil
}

func normalizeCyberArkRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func cyberArkMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func cyberArkMapSlice(value interface{}) []map[string]interface{} {
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

func cyberArkExtractResources(payload map[string]interface{}) []map[string]interface{} {
	for _, key := range []string{"resources", "items", "result", "data"} {
		if resources := cyberArkMapSlice(payload[key]); len(resources) > 0 {
			return resources
		}
	}
	if resource := cyberArkMap(payload["resource"]); len(resource) > 0 {
		return []map[string]interface{}{resource}
	}
	return nil
}

func cyberArkExtractMembers(payload map[string]interface{}) []map[string]interface{} {
	for _, key := range []string{"members", "member", "users", "resources", "items", "data"} {
		if rows := cyberArkFilterMemberRows(cyberArkMapSlice(payload[key])); len(rows) > 0 {
			return rows
		}
	}

	if cyberArkLooksLikeMember(payload) {
		return []map[string]interface{}{payload}
	}

	return nil
}

func cyberArkFilterMemberRows(rows []map[string]interface{}) []map[string]interface{} {
	if len(rows) == 0 {
		return nil
	}

	filtered := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		normalized := normalizeCyberArkRow(row)
		if cyberArkLooksLikeMember(normalized) {
			filtered = append(filtered, normalized)
		}
	}

	return filtered
}

func cyberArkLooksLikeMember(row map[string]interface{}) bool {
	if len(row) == 0 {
		return false
	}

	if firstCyberArkString(row, "value", "user_id", "member_id", "$ref", "ref", "href", "location") != "" {
		return true
	}

	if _, hasID := row["id"]; hasID {
		if _, hasMembers := row["members"]; hasMembers {
			return false
		}
		if firstCyberArkString(row, "user_name", "username", "email") != "" {
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

func cyberArkPrimaryCollectionValue(items []map[string]interface{}, keys ...string) interface{} {
	for _, primaryOnly := range []bool{true, false} {
		for _, item := range items {
			normalized := normalizeCyberArkRow(item)
			if primaryOnly && !cyberArkBool(normalized["primary"]) {
				continue
			}
			if value := firstCyberArkValue(normalized, keys...); value != nil {
				return value
			}
		}
	}
	return nil
}

func cyberArkIDFromReference(reference string, resource string) string {
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

func firstCyberArkString(row map[string]interface{}, keys ...string) string {
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

func firstCyberArkValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilCyberArkValue(values ...interface{}) interface{} {
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

func firstCyberArkInt(row map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if parsed, ok := parseCyberArkInt(value); ok {
			return parsed
		}
	}
	return 0
}

func parseCyberArkInt(value interface{}) (int, bool) {
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

func cyberArkBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		text := strings.ToLower(strings.TrimSpace(providerStringValue(value)))
		return text == "1" || text == "true" || text == "yes"
	}
}

func isCyberArkIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func isCyberArkNotSupportedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 405") || strings.Contains(message, "api error 501")
}
