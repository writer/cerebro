package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OktaProvider syncs identity data from Okta
type OktaProvider struct {
	*BaseProvider
	domain   string
	apiToken string
	client   *http.Client
}

func NewOktaProvider() *OktaProvider {
	return &OktaProvider{
		BaseProvider: NewBaseProvider("okta", ProviderTypeIdentity),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OktaProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := o.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	o.domain = o.GetConfigString("domain")
	o.apiToken = o.GetConfigString("api_token")

	return nil
}

func (o *OktaProvider) Test(ctx context.Context) error {
	_, err := o.request(ctx, "/api/v1/users?limit=1")
	return err
}

func (o *OktaProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "okta_users",
			Description: "Okta users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "login", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "first_name", Type: "string"},
				{Name: "last_name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "last_login", Type: "timestamp"},
				{Name: "mfa_enrolled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_groups",
			Description: "Okta groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_applications",
			Description: "Okta applications",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "label", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "sign_on_mode", Type: "string"},
				{Name: "created", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "okta_system_logs",
			Description: "Okta system log events",
			Columns: []ColumnSchema{
				{Name: "uuid", Type: "string", Required: true},
				{Name: "event_type", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "actor_id", Type: "string"},
				{Name: "actor_type", Type: "string"},
				{Name: "target_id", Type: "string"},
				{Name: "target_type", Type: "string"},
				{Name: "outcome", Type: "string"},
				{Name: "published", Type: "timestamp"},
			},
			PrimaryKey: []string{"uuid"},
		},
	}
}

func (o *OktaProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  o.Name(),
		StartedAt: start,
	}

	// Sync users
	users, err := o.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync groups
	groups, err := o.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	// Sync applications
	apps, err := o.syncApplications(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "applications: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *apps)
		result.TotalRows += apps.Rows
	}

	if opts.FullSync || opts.Since != nil {
		logs, err := o.syncSystemLogs(ctx, opts)
		if err != nil {
			result.Errors = append(result.Errors, "system_logs: "+err.Error())
		} else {
			result.Tables = append(result.Tables, *logs)
			result.TotalRows += logs.Rows
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (o *OktaProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "okta_users"}

	users, err := o.requestAll(ctx, "/api/v1/users?limit=200")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(users))
	result.Inserted = result.Rows
	return result, nil
}

func (o *OktaProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "okta_groups"}

	groups, err := o.requestAll(ctx, "/api/v1/groups?limit=200")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(groups))
	result.Inserted = result.Rows
	return result, nil
}

func (o *OktaProvider) syncApplications(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "okta_applications"}

	apps, err := o.requestAll(ctx, "/api/v1/apps?limit=200")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(apps))
	result.Inserted = result.Rows
	return result, nil
}

func (o *OktaProvider) syncSystemLogs(ctx context.Context, opts SyncOptions) (*TableResult, error) {
	result := &TableResult{Name: "okta_system_logs"}

	path := "/api/v1/logs?limit=200"
	if opts.Since != nil {
		path = fmt.Sprintf("%s&since=%s", path, opts.Since.UTC().Format(time.RFC3339))
	}

	logs, err := o.requestAll(ctx, path)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(logs))
	result.Inserted = result.Rows
	return result, nil
}

func (o *OktaProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("https://%s%s", o.domain, path)
	body, _, err := o.requestWithResponse(ctx, url)
	return body, err
}

func (o *OktaProvider) requestAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	nextURL := fmt.Sprintf("https://%s%s", o.domain, path)
	items := make([]map[string]interface{}, 0)

	for nextURL != "" {
		body, headers, err := o.requestWithResponse(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		var page []map[string]interface{}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		items = append(items, page...)
		nextURL = parseNextLink(headers.Get("Link"))
	}

	return items, nil
}

func (o *OktaProvider) requestWithResponse(ctx context.Context, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "SSWS "+o.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("okta API error %d: %s", resp.StatusCode, string(body))
	}

	return body, resp.Header, nil
}

func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}
		if !strings.Contains(parts[1], "rel=\"next\"") {
			continue
		}
		url := strings.TrimSpace(parts[0])
		url = strings.TrimPrefix(url, "<")
		url = strings.TrimSuffix(url, ">")
		return url
	}

	return ""
}
