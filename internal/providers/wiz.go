package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	wizDefaultTokenURL = "https://auth.app.wiz.io/oauth/token"
	wizDefaultAudience = "wiz-api"
	wizPageSize        = 100
)

// WizProvider syncs CNAPP posture and issue data from Wiz GraphQL APIs.
type WizProvider struct {
	*BaseProvider
	clientID     string
	clientSecret string
	apiURL       string
	tokenURL     string
	audience     string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

type wizGraphQLError struct {
	Message string `json:"message"`
}

type wizPageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

func NewWizProvider() *WizProvider {
	return &WizProvider{
		BaseProvider: NewBaseProvider("wiz", ProviderTypeSaaS),
		tokenURL:     wizDefaultTokenURL,
		audience:     wizDefaultAudience,
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (w *WizProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := w.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	w.clientID = strings.TrimSpace(w.GetConfigString("client_id"))
	w.clientSecret = strings.TrimSpace(w.GetConfigString("client_secret"))
	w.apiURL = strings.TrimSpace(w.GetConfigString("api_url"))
	if tokenURL := strings.TrimSpace(w.GetConfigString("token_url")); tokenURL != "" {
		w.tokenURL = tokenURL
	}
	if audience := strings.TrimSpace(w.GetConfigString("audience")); audience != "" {
		w.audience = audience
	}

	if w.clientID == "" || w.clientSecret == "" {
		return fmt.Errorf("wiz client_id and client_secret required")
	}
	if w.apiURL == "" {
		return fmt.Errorf("wiz api_url required")
	}

	return nil
}

func (w *WizProvider) Test(ctx context.Context) error {
	_, err := w.authenticate(ctx)
	return err
}

func (w *WizProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "wiz_projects",
			Description: "Wiz projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "cloud_account_id", Type: "string"},
				{Name: "cloud_account_name", Type: "string"},
				{Name: "cloud_provider", Type: "string"},
				{Name: "archived", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_cloud_accounts",
			Description: "Wiz cloud accounts linked to projects",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "cloud_provider", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "wiz_issues",
			Description: "Wiz security issues",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "title", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "project_id", Type: "string"},
				{Name: "project_name", Type: "string"},
				{Name: "control_id", Type: "string"},
				{Name: "control_name", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "resource_name", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "resource_region", Type: "string"},
				{Name: "cloud_provider", Type: "string"},
				{Name: "due_at", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (w *WizProvider) Sync(ctx context.Context, _ SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  w.Name(),
		StartedAt: start,
	}

	schemas := w.Schema()
	syncTable := func(name string, rows []map[string]interface{}) {
		schema, ok := schemaByName(schemas, name)
		if !ok {
			result.Errors = append(result.Errors, name+": schema not found")
			return
		}
		tableResult, err := w.syncTable(ctx, schema, rows)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *tableResult)
		result.TotalRows += tableResult.Rows
	}

	projectRows, accountRows, err := w.fetchProjectsAndAccounts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "projects: "+err.Error())
	} else {
		syncTable("wiz_projects", projectRows)
		syncTable("wiz_cloud_accounts", accountRows)
	}

	issueRows, err := w.fetchIssues(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "issues: "+err.Error())
	} else {
		syncTable("wiz_issues", issueRows)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	if len(result.Errors) > 0 {
		return result, fmt.Errorf("wiz sync finished with %d error(s)", len(result.Errors))
	}

	return result, nil
}

func (w *WizProvider) fetchProjectsAndAccounts(ctx context.Context) ([]map[string]interface{}, []map[string]interface{}, error) {
	const query = `
query CerebroWizProjects($first: Int!, $after: String) {
  projects(first: $first, after: $after) {
    nodes {
      id
      name
      archived
      createdAt
      updatedAt
      cloudAccount {
        id
        name
        cloudProvider
        provider
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`

	projectRows := make([]map[string]interface{}, 0)
	accountsByID := make(map[string]map[string]interface{})

	after := ""
	for {
		variables := map[string]interface{}{"first": wizPageSize}
		if after != "" {
			variables["after"] = after
		}

		var data struct {
			Projects struct {
				Nodes    []map[string]interface{} `json:"nodes"`
				PageInfo wizPageInfo              `json:"pageInfo"`
			} `json:"projects"`
		}

		if err := w.queryGraphQL(ctx, query, variables, &data); err != nil {
			return nil, nil, err
		}

		for _, node := range data.Projects.Nodes {
			normalized := normalizeWizRow(node)
			accountID := getNestedString(normalized, "cloud_account", "id")
			accountName := getNestedString(normalized, "cloud_account", "name")
			cloudProvider := firstNonEmptyString(
				getNestedString(normalized, "cloud_account", "cloud_provider"),
				getNestedString(normalized, "cloud_account", "provider"),
			)

			projectRows = append(projectRows, map[string]interface{}{
				"id":                 normalized["id"],
				"name":               normalized["name"],
				"cloud_account_id":   accountID,
				"cloud_account_name": accountName,
				"cloud_provider":     cloudProvider,
				"archived":           wizBool(normalized["archived"]),
				"created_at":         normalized["created_at"],
				"updated_at":         normalized["updated_at"],
			})

			if accountID != "" {
				accountsByID[accountID] = map[string]interface{}{
					"id":             accountID,
					"name":           accountName,
					"cloud_provider": cloudProvider,
				}
			}
		}

		if !data.Projects.PageInfo.HasNextPage || data.Projects.PageInfo.EndCursor == "" {
			break
		}
		after = data.Projects.PageInfo.EndCursor
	}

	accountIDs := make([]string, 0, len(accountsByID))
	for id := range accountsByID {
		accountIDs = append(accountIDs, id)
	}
	sort.Strings(accountIDs)

	accountRows := make([]map[string]interface{}, 0, len(accountIDs))
	for _, id := range accountIDs {
		accountRows = append(accountRows, accountsByID[id])
	}

	return projectRows, accountRows, nil
}

func (w *WizProvider) fetchIssues(ctx context.Context) ([]map[string]interface{}, error) {
	const query = `
query CerebroWizIssues($first: Int!, $after: String) {
  issues(first: $first, after: $after) {
    nodes {
      id
      title
      severity
      status
      type
      dueAt
      createdAt
      updatedAt
      project {
        id
        name
      }
      control {
        id
        name
      }
      entitySnapshot {
        id
        providerUniqueId
        name
        type
        region
        cloudPlatform
        cloudProvider
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`

	rows := make([]map[string]interface{}, 0)
	after := ""
	for {
		variables := map[string]interface{}{"first": wizPageSize}
		if after != "" {
			variables["after"] = after
		}

		var data struct {
			Issues struct {
				Nodes    []map[string]interface{} `json:"nodes"`
				PageInfo wizPageInfo              `json:"pageInfo"`
			} `json:"issues"`
		}

		if err := w.queryGraphQL(ctx, query, variables, &data); err != nil {
			return nil, err
		}

		for _, node := range data.Issues.Nodes {
			normalized := normalizeWizRow(node)
			rows = append(rows, map[string]interface{}{
				"id":              normalized["id"],
				"title":           normalized["title"],
				"severity":        normalized["severity"],
				"status":          normalized["status"],
				"type":            normalized["type"],
				"project_id":      getNestedString(normalized, "project", "id"),
				"project_name":    getNestedString(normalized, "project", "name"),
				"control_id":      getNestedString(normalized, "control", "id"),
				"control_name":    getNestedString(normalized, "control", "name"),
				"resource_id":     firstNonEmptyString(getNestedString(normalized, "entity_snapshot", "id"), getNestedString(normalized, "entity_snapshot", "provider_unique_id")),
				"resource_name":   getNestedString(normalized, "entity_snapshot", "name"),
				"resource_type":   getNestedString(normalized, "entity_snapshot", "type"),
				"resource_region": getNestedString(normalized, "entity_snapshot", "region"),
				"cloud_provider":  firstNonEmptyString(getNestedString(normalized, "entity_snapshot", "cloud_platform"), getNestedString(normalized, "entity_snapshot", "cloud_provider")),
				"due_at":          normalized["due_at"],
				"created_at":      normalized["created_at"],
				"updated_at":      normalized["updated_at"],
			})
		}

		if !data.Issues.PageInfo.HasNextPage || data.Issues.PageInfo.EndCursor == "" {
			break
		}
		after = data.Issues.PageInfo.EndCursor
	}

	return rows, nil
}

func (w *WizProvider) queryGraphQL(ctx context.Context, query string, variables map[string]interface{}, target interface{}) error {
	token, err := w.authenticate(ctx)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		errorBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("wiz API error %d: %s", resp.StatusCode, string(errorBody))
	}

	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []wizGraphQLError `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}

	if len(envelope.Errors) > 0 {
		messages := make([]string, 0, len(envelope.Errors))
		for _, graphErr := range envelope.Errors {
			if message := strings.TrimSpace(graphErr.Message); message != "" {
				messages = append(messages, message)
			}
		}
		if len(messages) == 0 {
			messages = append(messages, "unknown graphql error")
		}
		return fmt.Errorf("wiz graphql error: %s", strings.Join(messages, "; "))
	}

	if len(envelope.Data) == 0 {
		return fmt.Errorf("wiz graphql response missing data")
	}

	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return err
	}

	return nil
}

func (w *WizProvider) authenticate(ctx context.Context) (string, error) {
	if w.token != "" && time.Now().Before(w.tokenExpiry) {
		return w.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", w.clientID)
	form.Set("client_secret", w.clientSecret)
	if w.audience != "" {
		form.Set("audience", w.audience)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		errorBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("wiz auth failed (%d): %s", resp.StatusCode, string(errorBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", fmt.Errorf("wiz auth response missing access_token")
	}

	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 15 * time.Minute
	}
	if expiresIn > time.Minute {
		expiresIn -= time.Minute
	}

	w.token = tokenResp.AccessToken
	w.tokenExpiry = time.Now().Add(expiresIn)
	return w.token, nil
}

func normalizeWizRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return row
	}
	return normalized
}

func wizBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}
