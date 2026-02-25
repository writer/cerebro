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

const gongDefaultAPIURL = "https://api.gong.io"

// GongProvider syncs Gong user and call metadata.
type GongProvider struct {
	*BaseProvider
	accessKey    string
	accessSecret string
	baseURL      string
	client       *http.Client
}

func NewGongProvider() *GongProvider {
	return &GongProvider{
		BaseProvider: NewBaseProvider("gong", ProviderTypeSaaS),
		baseURL:      gongDefaultAPIURL,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GongProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := g.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	g.accessKey = strings.TrimSpace(g.GetConfigString("access_key"))
	g.accessSecret = strings.TrimSpace(g.GetConfigString("access_secret"))
	if baseURL := strings.TrimSpace(g.GetConfigString("base_url")); baseURL != "" {
		g.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	if g.accessKey == "" || g.accessSecret == "" {
		return fmt.Errorf("gong access_key and access_secret required")
	}
	if err := validateGongURL(g.baseURL); err != nil {
		return err
	}

	return nil
}

func (g *GongProvider) Test(ctx context.Context) error {
	_, err := g.request(ctx, "/v2/users?page_size=1")
	return err
}

func (g *GongProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "gong_users",
			Description: "Gong users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "active", Type: "boolean"},
				{Name: "title", Type: "string"},
				{Name: "manager_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gong_calls",
			Description: "Gong calls",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "start_time", Type: "timestamp"},
				{Name: "end_time", Type: "timestamp"},
				{Name: "direction", Type: "string"},
				{Name: "primary_user_id", Type: "string"},
				{Name: "client_company", Type: "string"},
				{Name: "duration_seconds", Type: "number"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "gong_call_participants",
			Description: "Gong call participants",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "call_id", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "join_time", Type: "timestamp"},
				{Name: "leave_time", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (g *GongProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(g.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (g *GongProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  g.Name(),
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

	syncTable("users", g.syncUsers)

	callsTable, participantsTable, err := g.syncCallsAndParticipants(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "calls: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *callsTable, *participantsTable)
		result.TotalRows += callsTable.Rows + participantsTable.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (g *GongProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := g.schemaFor("gong_users")
	result := &TableResult{Name: "gong_users"}
	if err != nil {
		return result, err
	}

	users, err := g.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeGongRow(user)
		userID := firstGongString(normalized, "id", "user_id", "email")
		if userID == "" {
			continue
		}

		rows = append(rows, map[string]interface{}{
			"id":         userID,
			"email":      firstGongValue(normalized, "email"),
			"first_name": firstGongValue(normalized, "first_name", "firstname"),
			"last_name":  firstGongValue(normalized, "last_name", "lastname"),
			"active":     firstGongValue(normalized, "active", "is_active"),
			"title":      firstGongValue(normalized, "title"),
			"manager_id": firstGongValue(normalized, "manager_id", "manager"),
		})
	}

	return g.syncTable(ctx, schema, rows)
}

func (g *GongProvider) syncCallsAndParticipants(ctx context.Context) (*TableResult, *TableResult, error) {
	callsSchema, err := g.schemaFor("gong_calls")
	if err != nil {
		return &TableResult{Name: "gong_calls"}, &TableResult{Name: "gong_call_participants"}, err
	}
	participantsSchema, err := g.schemaFor("gong_call_participants")
	if err != nil {
		return &TableResult{Name: "gong_calls"}, &TableResult{Name: "gong_call_participants"}, err
	}

	calls, err := g.listCalls(ctx)
	if err != nil {
		if isGongIgnorableError(err) {
			callsTable, syncErr := g.syncTable(ctx, callsSchema, nil)
			if syncErr != nil {
				return &TableResult{Name: "gong_calls"}, &TableResult{Name: "gong_call_participants"}, syncErr
			}
			participantsTable, syncErr := g.syncTable(ctx, participantsSchema, nil)
			if syncErr != nil {
				return callsTable, &TableResult{Name: "gong_call_participants"}, syncErr
			}
			return callsTable, participantsTable, nil
		}
		return &TableResult{Name: "gong_calls"}, &TableResult{Name: "gong_call_participants"}, err
	}

	callRows := make([]map[string]interface{}, 0, len(calls))
	participantRows := make([]map[string]interface{}, 0)
	seenParticipants := make(map[string]struct{})

	for _, call := range calls {
		normalizedCall := normalizeGongRow(call)
		callID := firstGongString(normalizedCall, "id", "call_id")
		if callID == "" {
			continue
		}

		callRows = append(callRows, map[string]interface{}{
			"id": firstNonNilGongValue(
				firstGongValue(normalizedCall, "id", "call_id"),
				callID,
			),
			"start_time": firstGongValue(normalizedCall, "start_time", "started_at", "start"),
			"end_time":   firstGongValue(normalizedCall, "end_time", "ended_at", "end"),
			"direction":  firstGongValue(normalizedCall, "direction"),
			"primary_user_id": firstNonNilGongValue(
				firstGongValue(normalizedCall, "primary_user_id"),
				firstGongValue(gongMap(normalizedCall["primary_user"]), "id", "user_id"),
			),
			"client_company": firstNonNilGongValue(
				firstGongValue(normalizedCall, "client_company", "company"),
				firstGongValue(gongMap(normalizedCall["customer"]), "name", "company"),
			),
			"duration_seconds": firstGongValue(normalizedCall, "duration_seconds", "duration", "duration_secs"),
		})

		participants := gongExtractItems(normalizedCall, "participants", "speakers", "attendees", "users")
		for index, participant := range participants {
			normalizedParticipant := normalizeGongRow(participant)
			userMap := gongMap(normalizedParticipant["user"])

			participantID := firstGongString(normalizedParticipant, "id", "participant_id", "user_id", "email")
			if participantID == "" {
				participantID = fmt.Sprintf("index-%d", index)
			}

			rowID := callID + "|" + participantID
			if _, exists := seenParticipants[rowID]; exists {
				continue
			}
			seenParticipants[rowID] = struct{}{}

			participantRows = append(participantRows, map[string]interface{}{
				"id":      rowID,
				"call_id": callID,
				"user_id": firstNonNilGongValue(
					firstGongValue(normalizedParticipant, "user_id", "id"),
					firstGongValue(userMap, "id", "user_id"),
				),
				"email": firstNonNilGongValue(
					firstGongValue(normalizedParticipant, "email"),
					firstGongValue(userMap, "email"),
				),
				"role": firstGongValue(normalizedParticipant, "role", "speaker_role", "type"),
				"join_time": firstGongValue(normalizedParticipant,
					"join_time", "joined_at", "start_time", "start"),
				"leave_time": firstGongValue(normalizedParticipant,
					"leave_time", "left_at", "end_time", "end"),
			})
		}
	}

	callsTable, err := g.syncTable(ctx, callsSchema, callRows)
	if err != nil {
		return &TableResult{Name: "gong_calls"}, &TableResult{Name: "gong_call_participants"}, err
	}
	participantsTable, err := g.syncTable(ctx, participantsSchema, participantRows)
	if err != nil {
		return callsTable, &TableResult{Name: "gong_call_participants"}, err
	}

	return callsTable, participantsTable, nil
}

func (g *GongProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return g.listCollection(ctx, "/v2/users", "users")
}

func (g *GongProvider) listCalls(ctx context.Context) ([]map[string]interface{}, error) {
	return g.listCollection(ctx, "/v2/calls", "calls")
}

func (g *GongProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"page_size": "200"})
	rows := make([]map[string]interface{}, 0)
	nextCursor := ""
	seenCursors := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextCursor != "" {
			requestPath = addQueryParams(basePath, map[string]string{"cursor": nextCursor})
		}

		body, err := g.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeGongRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeGongRow(payload)
		items := gongExtractItems(normalized, primaryKey, "records", "items", "data", "results", "values")
		for _, item := range items {
			rows = append(rows, normalizeGongRow(item))
		}

		cursor := gongNextCursor(normalized)
		if cursor == "" {
			break
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, fmt.Errorf("gong pagination loop detected for %s", path)
		}
		seenCursors[cursor] = struct{}{}
		nextCursor = cursor
	}

	return rows, nil
}

func (g *GongProvider) request(ctx context.Context, path string) ([]byte, error) {
	requestURL := g.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(g.accessKey, g.accessSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("gong API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeGongRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func gongMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func gongMapSlice(value interface{}) []map[string]interface{} {
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

func gongExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := gongMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func gongNextCursor(payload map[string]interface{}) string {
	if cursor := firstGongString(payload, "next_cursor", "cursor", "next", "offset"); cursor != "" {
		return cursor
	}

	if paging := gongMap(payload["paging"]); len(paging) > 0 {
		if cursor := firstGongString(paging, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if page := gongMap(payload["page"]); len(page) > 0 {
		if cursor := firstGongString(page, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	if metadata := gongMap(payload["metadata"]); len(metadata) > 0 {
		if cursor := firstGongString(metadata, "next_cursor", "cursor", "next", "offset"); cursor != "" {
			return cursor
		}
	}

	return ""
}

func firstGongString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstGongValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilGongValue(values ...interface{}) interface{} {
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

func isGongIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateGongURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid gong base_url %q", rawURL)
	}
	return nil
}
