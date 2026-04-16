package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// SlackProvider syncs data from Slack Enterprise Grid
type SlackProvider struct {
	*BaseProvider
	apiURL string
	token  string
	client *http.Client
}

func NewSlackProvider() *SlackProvider {
	return &SlackProvider{
		BaseProvider: NewBaseProvider("slack", ProviderTypeSaaS),
		apiURL:       "https://slack.com/api",
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (s *SlackProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.token = s.GetConfigString("token")
	if s.token == "" {
		return fmt.Errorf("slack token required")
	}

	return nil
}

func (s *SlackProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/auth.test", nil)
	return err
}

func (s *SlackProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "slack_users",
			Description: "Slack workspace users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "team_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "real_name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "is_admin", Type: "boolean"},
				{Name: "is_owner", Type: "boolean"},
				{Name: "is_primary_owner", Type: "boolean"},
				{Name: "is_restricted", Type: "boolean"},
				{Name: "is_ultra_restricted", Type: "boolean"},
				{Name: "is_bot", Type: "boolean"},
				{Name: "is_app_user", Type: "boolean"},
				{Name: "deleted", Type: "boolean"},
				{Name: "has_2fa", Type: "boolean"},
				{Name: "updated", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "slack_channels",
			Description: "Slack channels",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "is_channel", Type: "boolean"},
				{Name: "is_group", Type: "boolean"},
				{Name: "is_im", Type: "boolean"},
				{Name: "is_private", Type: "boolean"},
				{Name: "is_archived", Type: "boolean"},
				{Name: "is_general", Type: "boolean"},
				{Name: "is_shared", Type: "boolean"},
				{Name: "is_ext_shared", Type: "boolean"},
				{Name: "is_org_shared", Type: "boolean"},
				{Name: "num_members", Type: "integer"},
				{Name: "created", Type: "timestamp"},
				{Name: "creator", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "slack_integrations",
			Description: "Slack installed apps/integrations",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "app_id", Type: "string"},
				{Name: "is_distributed", Type: "boolean"},
				{Name: "is_internal", Type: "boolean"},
				{Name: "scopes", Type: "array"},
				{Name: "installed_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "slack_teams",
			Description: "Slack workspaces/teams (Enterprise Grid)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "domain", Type: "string"},
				{Name: "email_domain", Type: "string"},
				{Name: "is_verified", Type: "boolean"},
				{Name: "enterprise_id", Type: "string"},
				{Name: "enterprise_name", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "slack_audit_logs",
			Description: "Slack Enterprise Grid audit logs",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "date_create", Type: "timestamp"},
				{Name: "action", Type: "string"},
				{Name: "actor_user_id", Type: "string"},
				{Name: "actor_user_email", Type: "string"},
				{Name: "entity_type", Type: "string"},
				{Name: "entity_id", Type: "string"},
				{Name: "context_location_type", Type: "string"},
				{Name: "context_location_id", Type: "string"},
				{Name: "context_ip_address", Type: "string"},
				{Name: "context_ua", Type: "string"},
				{Name: "details", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "slack_user_sessions",
			Description: "Slack user active sessions",
			Columns: []ColumnSchema{
				{Name: "user_id", Type: "string", Required: true},
				{Name: "session_id", Type: "string", Required: true},
				{Name: "team_id", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "recent", Type: "timestamp"},
			},
			PrimaryKey: []string{"user_id", "session_id"},
		},
	}
}

func (s *SlackProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	// Sync users
	users, err := s.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync channels
	channels, err := s.syncChannels(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "channels: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *channels)
		result.TotalRows += channels.Rows
	}

	// Sync team info
	team, err := s.syncTeam(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "team: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *team)
		result.TotalRows += team.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (s *SlackProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "slack_users"}

	users, err := s.listAllUsers(ctx)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(users))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SlackProvider) syncChannels(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "slack_channels"}

	channels, err := s.listAllChannels(ctx)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(channels))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SlackProvider) syncTeam(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "slack_teams"}

	body, err := s.request(ctx, "/team.info", nil)
	if err != nil {
		return result, err
	}

	var resp struct {
		OK    bool                   `json:"ok"`
		Team  map[string]interface{} `json:"team"`
		Error string                 `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	if !resp.OK {
		return result, fmt.Errorf("slack API error: %s", resp.Error)
	}

	result.Rows = 1
	result.Inserted = 1
	return result, nil
}

func (s *SlackProvider) listAllUsers(ctx context.Context) ([]map[string]interface{}, error) {
	var allUsers []map[string]interface{}
	cursor := ""
	guard := newPaginationGuard("slack", "/users.list")

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := guard.nextPage(); err != nil {
			return nil, err
		}

		params := url.Values{}
		params.Set("limit", "200")
		if cursor != "" {
			params.Set("cursor", cursor)
		}

		body, err := s.request(ctx, "/users.list", params)
		if err != nil {
			return nil, err
		}

		var resp struct {
			OK               bool                     `json:"ok"`
			Members          []map[string]interface{} `json:"members"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		if !resp.OK {
			return nil, fmt.Errorf("slack API error: %s", resp.Error)
		}

		allUsers = append(allUsers, resp.Members...)

		if resp.ResponseMetadata.NextCursor == "" {
			break
		}
		if err := guard.nextToken(resp.ResponseMetadata.NextCursor); err != nil {
			return nil, err
		}
		cursor = resp.ResponseMetadata.NextCursor
	}

	return allUsers, nil
}

func (s *SlackProvider) listAllChannels(ctx context.Context) ([]map[string]interface{}, error) {
	var allChannels []map[string]interface{}
	cursor := ""
	guard := newPaginationGuard("slack", "/conversations.list")

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := guard.nextPage(); err != nil {
			return nil, err
		}

		params := url.Values{}
		params.Set("limit", "200")
		params.Set("types", "public_channel,private_channel")
		if cursor != "" {
			params.Set("cursor", cursor)
		}

		body, err := s.request(ctx, "/conversations.list", params)
		if err != nil {
			return nil, err
		}

		var resp struct {
			OK               bool                     `json:"ok"`
			Channels         []map[string]interface{} `json:"channels"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		if !resp.OK {
			return nil, fmt.Errorf("slack API error: %s", resp.Error)
		}

		allChannels = append(allChannels, resp.Channels...)

		if resp.ResponseMetadata.NextCursor == "" {
			break
		}
		if err := guard.nextToken(resp.ResponseMetadata.NextCursor); err != nil {
			return nil, err
		}
		cursor = resp.ResponseMetadata.NextCursor
	}

	return allChannels, nil
}

func (s *SlackProvider) request(ctx context.Context, path string, params url.Values) ([]byte, error) {
	urlStr := s.apiURL + path
	if params != nil {
		urlStr += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("slack API HTTP error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetUsersWithout2FA returns users without 2FA enabled
func (s *SlackProvider) GetUsersWithout2FA(users []map[string]interface{}) []map[string]interface{} {
	var without2FA []map[string]interface{}

	for _, user := range users {
		// Skip bots and app users
		if isBot, _ := user["is_bot"].(bool); isBot {
			continue
		}
		if isAppUser, _ := user["is_app_user"].(bool); isAppUser {
			continue
		}
		if deleted, _ := user["deleted"].(bool); deleted {
			continue
		}

		if has2FA, _ := user["has_2fa"].(bool); !has2FA {
			without2FA = append(without2FA, user)
		}
	}

	return without2FA
}

// GetExternalSharedChannels returns channels shared with external organizations
func (s *SlackProvider) GetExternalSharedChannels(channels []map[string]interface{}) []map[string]interface{} {
	var external []map[string]interface{}

	for _, channel := range channels {
		if isExtShared, _ := channel["is_ext_shared"].(bool); isExtShared {
			external = append(external, channel)
		}
	}

	return external
}

// GetAdminUsers returns users with admin privileges
func (s *SlackProvider) GetAdminUsers(users []map[string]interface{}) []map[string]interface{} {
	var admins []map[string]interface{}

	for _, user := range users {
		if deleted, _ := user["deleted"].(bool); deleted {
			continue
		}

		isAdmin, _ := user["is_admin"].(bool)
		isOwner, _ := user["is_owner"].(bool)
		isPrimaryOwner, _ := user["is_primary_owner"].(bool)

		if isAdmin || isOwner || isPrimaryOwner {
			admins = append(admins, user)
		}
	}

	return admins
}
