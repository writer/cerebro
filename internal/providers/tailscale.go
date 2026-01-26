package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TailscaleProvider syncs network access data from Tailscale
type TailscaleProvider struct {
	*BaseProvider
	apiURL  string
	apiKey  string
	tailnet string
	client  *http.Client
}

func NewTailscaleProvider() *TailscaleProvider {
	return &TailscaleProvider{
		BaseProvider: NewBaseProvider("tailscale", ProviderTypeNetwork),
		apiURL:       "https://api.tailscale.com/api/v2",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (t *TailscaleProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := t.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	t.apiKey = t.GetConfigString("api_key")
	if t.apiKey == "" {
		return fmt.Errorf("tailscale api_key required")
	}

	t.tailnet = t.GetConfigString("tailnet")
	if t.tailnet == "" {
		return fmt.Errorf("tailscale tailnet required")
	}

	return nil
}

func (t *TailscaleProvider) Test(ctx context.Context) error {
	_, err := t.request(ctx, fmt.Sprintf("/tailnet/%s/devices", t.tailnet))
	return err
}

func (t *TailscaleProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "tailscale_devices",
			Description: "Tailscale connected devices",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "node_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "hostname", Type: "string"},
				{Name: "user", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "os", Type: "string"},
				{Name: "client_version", Type: "string"},
				{Name: "addresses", Type: "array"},
				{Name: "is_external", Type: "boolean"},
				{Name: "authorized", Type: "boolean"},
				{Name: "blocks_incoming_connections", Type: "boolean"},
				{Name: "expires", Type: "timestamp"},
				{Name: "last_seen", Type: "timestamp"},
				{Name: "created", Type: "timestamp"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "tailscale_users",
			Description: "Tailscale users",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "login_name", Type: "string"},
				{Name: "display_name", Type: "string"},
				{Name: "profile_pic_url", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "last_seen", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "tailscale_acl",
			Description: "Tailscale ACL rules",
			Columns: []ColumnSchema{
				{Name: "rule_index", Type: "integer", Required: true},
				{Name: "action", Type: "string"},
				{Name: "src", Type: "array"},
				{Name: "dst", Type: "array"},
				{Name: "users", Type: "array"},
				{Name: "ports", Type: "array"},
			},
			PrimaryKey: []string{"rule_index"},
		},
		{
			Name:        "tailscale_keys",
			Description: "Tailscale auth keys",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "key", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created", Type: "timestamp"},
				{Name: "expires", Type: "timestamp"},
				{Name: "revoked", Type: "timestamp"},
				{Name: "invalid", Type: "boolean"},
				{Name: "reusable", Type: "boolean"},
				{Name: "ephemeral", Type: "boolean"},
				{Name: "preauthorized", Type: "boolean"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (t *TailscaleProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  t.Name(),
		StartedAt: start,
	}

	// Sync devices
	devices, err := t.syncDevices(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "devices: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *devices)
		result.TotalRows += devices.Rows
	}

	// Sync users
	users, err := t.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync ACL
	acl, err := t.syncACL(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "acl: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *acl)
		result.TotalRows += acl.Rows
	}

	// Sync keys
	keys, err := t.syncKeys(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "keys: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *keys)
		result.TotalRows += keys.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (t *TailscaleProvider) syncDevices(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tailscale_devices"}

	body, err := t.request(ctx, fmt.Sprintf("/tailnet/%s/devices", t.tailnet))
	if err != nil {
		return result, err
	}

	var resp struct {
		Devices []map[string]interface{} `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	result.Rows = int64(len(resp.Devices))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TailscaleProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tailscale_users"}

	body, err := t.request(ctx, fmt.Sprintf("/tailnet/%s/users", t.tailnet))
	if err != nil {
		return result, err
	}

	var resp struct {
		Users []map[string]interface{} `json:"users"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	result.Rows = int64(len(resp.Users))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TailscaleProvider) syncACL(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tailscale_acl"}

	body, err := t.request(ctx, fmt.Sprintf("/tailnet/%s/acl", t.tailnet))
	if err != nil {
		return result, err
	}

	var acl map[string]interface{}
	if err := json.Unmarshal(body, &acl); err != nil {
		return result, err
	}

	// Count ACL rules
	if acls, ok := acl["acls"].([]interface{}); ok {
		result.Rows = int64(len(acls))
	}
	result.Inserted = result.Rows
	return result, nil
}

func (t *TailscaleProvider) syncKeys(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tailscale_keys"}

	body, err := t.request(ctx, fmt.Sprintf("/tailnet/%s/keys", t.tailnet))
	if err != nil {
		return result, err
	}

	var resp struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	result.Rows = int64(len(resp.Keys))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TailscaleProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := t.apiURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(t.apiKey, "")
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tailscale API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetStaleDevices returns devices that haven't been seen recently
func (t *TailscaleProvider) GetStaleDevices(devices []map[string]interface{}, staleDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, -staleDays)
	var stale []map[string]interface{}

	for _, device := range devices {
		if lastSeenStr, ok := device["lastSeen"].(string); ok {
			lastSeen, err := time.Parse(time.RFC3339, lastSeenStr)
			if err == nil && lastSeen.Before(cutoff) {
				stale = append(stale, device)
			}
		}
	}

	return stale
}

// GetUnauthorizedDevices returns devices that are not authorized
func (t *TailscaleProvider) GetUnauthorizedDevices(devices []map[string]interface{}) []map[string]interface{} {
	var unauthorized []map[string]interface{}

	for _, device := range devices {
		if authorized, ok := device["authorized"].(bool); ok && !authorized {
			unauthorized = append(unauthorized, device)
		}
	}

	return unauthorized
}
