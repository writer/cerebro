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

const (
	rampDefaultAPIURL   = "https://api.ramp.com/developer/v1"
	rampDefaultTokenURL = "https://api.ramp.com/developer/v1/token"
	rampPageSize        = "250"
)

// RampProvider syncs Ramp identity and spend metadata.
type RampProvider struct {
	*BaseProvider
	clientID     string
	clientSecret string
	baseURL      string
	tokenURL     string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewRampProvider() *RampProvider {
	return &RampProvider{
		BaseProvider: NewBaseProvider("ramp", ProviderTypeSaaS),
		baseURL:      rampDefaultAPIURL,
		tokenURL:     rampDefaultTokenURL,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (r *RampProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := r.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	r.clientID = strings.TrimSpace(r.GetConfigString("client_id"))
	r.clientSecret = strings.TrimSpace(r.GetConfigString("client_secret"))
	if baseURL := strings.TrimSpace(r.GetConfigString("base_url")); baseURL != "" {
		r.baseURL = strings.TrimSuffix(baseURL, "/")
	}
	if tokenURL := strings.TrimSpace(r.GetConfigString("token_url")); tokenURL != "" {
		r.tokenURL = strings.TrimSuffix(tokenURL, "/")
	}

	if r.clientID == "" || r.clientSecret == "" {
		return fmt.Errorf("ramp client_id and client_secret required")
	}
	if err := validateRampURL(r.baseURL, "base_url"); err != nil {
		return err
	}
	if err := validateRampURL(r.tokenURL, "token_url"); err != nil {
		return err
	}

	return nil
}

func (r *RampProvider) Test(ctx context.Context) error {
	_, err := r.request(ctx, "/users?page_size=1")
	return err
}

func (r *RampProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "ramp_users",
			Description: "Ramp users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "department", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "ramp_cards",
			Description: "Ramp cards",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "spend_limit", Type: "number"},
				{Name: "currency", Type: "string"},
				{Name: "last4", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "ramp_transactions",
			Description: "Ramp transactions",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "user_id", Type: "string"},
				{Name: "card_id", Type: "string"},
				{Name: "merchant_name", Type: "string"},
				{Name: "amount", Type: "number"},
				{Name: "currency", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "transaction_time", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (r *RampProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(r.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (r *RampProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  r.Name(),
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

	syncTable("users", r.syncUsers)
	syncTable("cards", r.syncCards)
	syncTable("transactions", r.syncTransactions)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)
	return result, nil
}

func (r *RampProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := r.schemaFor("ramp_users")
	result := &TableResult{Name: "ramp_users"}
	if err != nil {
		return result, err
	}

	users, err := r.listUsers(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		normalized := normalizeRampRow(user)
		userID := firstRampString(normalized, "id", "user_id", "email")
		if userID == "" {
			continue
		}
		department := firstRampValue(normalized, "department")
		if dept := rampMap(normalized["department"]); len(dept) > 0 {
			department = firstRampValue(dept, "name", "id")
		}

		rows = append(rows, map[string]interface{}{
			"id":         userID,
			"email":      firstRampValue(normalized, "email"),
			"first_name": firstRampValue(normalized, "first_name", "given_name"),
			"last_name":  firstRampValue(normalized, "last_name", "family_name"),
			"status":     firstRampValue(normalized, "status", "state"),
			"role":       firstRampValue(normalized, "role", "user_role"),
			"department": department,
		})
	}

	return r.syncTable(ctx, schema, rows)
}

func (r *RampProvider) syncCards(ctx context.Context) (*TableResult, error) {
	schema, err := r.schemaFor("ramp_cards")
	result := &TableResult{Name: "ramp_cards"}
	if err != nil {
		return result, err
	}

	cards, err := r.listCards(ctx)
	if err != nil {
		if isRampIgnorableError(err) {
			return r.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(cards))
	for _, card := range cards {
		normalized := normalizeRampRow(card)
		cardID := firstRampString(normalized, "id", "card_id")
		if cardID == "" {
			continue
		}

		userMap := rampMap(normalized["user"])
		spendMap := rampMap(normalized["spend_limit"])

		rows = append(rows, map[string]interface{}{
			"id":         cardID,
			"user_id":    firstNonNilRampValue(firstRampValue(normalized, "user_id", "holder_id"), firstRampValue(userMap, "id", "user_id")),
			"user_email": firstNonNilRampValue(firstRampValue(normalized, "user_email", "holder_email"), firstRampValue(userMap, "email")),
			"status":     firstRampValue(normalized, "status", "state"),
			"spend_limit": firstNonNilRampValue(
				firstRampValue(normalized, "spend_limit", "spending_limit"),
				firstRampValue(spendMap, "amount", "value"),
			),
			"currency": firstNonNilRampValue(
				firstRampValue(normalized, "currency"),
				firstRampValue(spendMap, "currency"),
			),
			"last4": firstRampValue(normalized, "last4", "last_four", "pan_last4"),
		})
	}

	return r.syncTable(ctx, schema, rows)
}

func (r *RampProvider) syncTransactions(ctx context.Context) (*TableResult, error) {
	schema, err := r.schemaFor("ramp_transactions")
	result := &TableResult{Name: "ramp_transactions"}
	if err != nil {
		return result, err
	}

	transactions, err := r.listTransactions(ctx)
	if err != nil {
		if isRampIgnorableError(err) {
			return r.syncTable(ctx, schema, nil)
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(transactions))
	for _, transaction := range transactions {
		normalized := normalizeRampRow(transaction)
		transactionID := firstRampString(normalized, "id", "transaction_id")
		if transactionID == "" {
			continue
		}

		amountMap := rampMap(normalized["amount"])
		merchantMap := rampMap(normalized["merchant"])

		rows = append(rows, map[string]interface{}{
			"id":            transactionID,
			"user_id":       firstRampValue(normalized, "user_id", "cardholder_id"),
			"card_id":       firstRampValue(normalized, "card_id", "card"),
			"merchant_name": firstNonNilRampValue(firstRampValue(normalized, "merchant_name"), firstRampValue(merchantMap, "name")),
			"amount": firstNonNilRampValue(
				firstRampValue(normalized, "amount", "amount_cents", "billed_amount"),
				firstRampValue(amountMap, "amount", "value"),
			),
			"currency": firstNonNilRampValue(
				firstRampValue(normalized, "currency", "billed_currency"),
				firstRampValue(amountMap, "currency"),
			),
			"state":            firstRampValue(normalized, "state", "status"),
			"transaction_time": firstRampValue(normalized, "transaction_time", "timestamp", "created_at"),
		})
	}

	return r.syncTable(ctx, schema, rows)
}

func (r *RampProvider) listUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return r.listCollection(ctx, "/users", "users")
}

func (r *RampProvider) listCards(ctx context.Context) ([]map[string]interface{}, error) {
	return r.listCollection(ctx, "/cards", "cards")
}

func (r *RampProvider) listTransactions(ctx context.Context) ([]map[string]interface{}, error) {
	return r.listCollection(ctx, "/transactions", "transactions")
}

func (r *RampProvider) listCollection(ctx context.Context, path string, primaryKey string) ([]map[string]interface{}, error) {
	basePath := addQueryParams(path, map[string]string{"page_size": rampPageSize})
	rows := make([]map[string]interface{}, 0)
	nextPageToken := ""
	seenPageTokens := make(map[string]struct{})

	for {
		requestPath := basePath
		if nextPageToken != "" {
			requestPath = addQueryParams(basePath, map[string]string{"next_page_token": nextPageToken})
		}

		body, err := r.request(ctx, requestPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			var list []map[string]interface{}
			if fallbackErr := json.Unmarshal(body, &list); fallbackErr == nil {
				for _, item := range list {
					rows = append(rows, normalizeRampRow(item))
				}
				break
			}
			return nil, err
		}

		normalized := normalizeRampRow(payload)
		items := rampExtractItems(normalized, primaryKey, "items", "data", "results", "values")
		for _, item := range items {
			rows = append(rows, normalizeRampRow(item))
		}

		nextToken := rampNextPageToken(normalized)
		if nextToken == "" {
			break
		}
		if _, exists := seenPageTokens[nextToken]; exists {
			return nil, fmt.Errorf("ramp pagination loop detected for %s", path)
		}
		seenPageTokens[nextToken] = struct{}{}
		nextPageToken = nextToken
	}

	return rows, nil
}

func (r *RampProvider) authenticate(ctx context.Context) (string, error) {
	if r.token != "" && time.Now().Add(30*time.Second).Before(r.tokenExpiry) {
		return r.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(r.clientID, r.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("ramp token API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenPayload); err != nil {
		return "", err
	}
	if tokenPayload.AccessToken == "" {
		return "", fmt.Errorf("ramp token API response missing access_token")
	}
	if tokenPayload.ExpiresIn <= 0 {
		tokenPayload.ExpiresIn = 3600
	}

	r.token = tokenPayload.AccessToken
	r.tokenExpiry = time.Now().Add(time.Duration(tokenPayload.ExpiresIn) * time.Second)
	return r.token, nil
}

func (r *RampProvider) request(ctx context.Context, path string) ([]byte, error) {
	call := func(token string) ([]byte, int, error) {
		requestURL := r.baseURL + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := r.client.Do(req)
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

	token, err := r.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	body, statusCode, err := call(token)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized {
		r.token = ""
		r.tokenExpiry = time.Time{}
		token, err = r.authenticate(ctx)
		if err != nil {
			return nil, err
		}
		body, statusCode, err = call(token)
		if err != nil {
			return nil, err
		}
	}

	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("ramp API error %d: %s", statusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func normalizeRampRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func rampMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func rampMapSlice(value interface{}) []map[string]interface{} {
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

func rampExtractItems(payload map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, key := range keys {
		if items := rampMapSlice(payload[key]); len(items) > 0 {
			return items
		}
	}
	return nil
}

func rampNextPageToken(payload map[string]interface{}) string {
	if token := firstRampString(payload, "next_page_token", "next_cursor", "next", "cursor"); token != "" {
		return token
	}

	if pagination := rampMap(payload["pagination"]); len(pagination) > 0 {
		if token := firstRampString(pagination, "next_page_token", "next_cursor", "next", "cursor"); token != "" {
			return token
		}
	}

	if page := rampMap(payload["page"]); len(page) > 0 {
		if token := firstRampString(page, "next_page_token", "next_cursor", "next", "cursor"); token != "" {
			return token
		}
	}

	if meta := rampMap(payload["meta"]); len(meta) > 0 {
		if token := firstRampString(meta, "next_page_token", "next_cursor", "next", "cursor"); token != "" {
			return token
		}
	}

	return ""
}

func firstRampString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			if text := strings.TrimSpace(providerStringValue(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstRampValue(row map[string]interface{}, keys ...string) interface{} {
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

func firstNonNilRampValue(values ...interface{}) interface{} {
	for _, value := range values {
		if value == nil {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text == "" {
			continue
		}
		return value
	}
	return nil
}

func isRampIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

func validateRampURL(rawURL string, field string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid ramp %s %q", field, rawURL)
	}
	return nil
}
