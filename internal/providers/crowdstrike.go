package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// CrowdStrikeProvider syncs endpoint data from CrowdStrike Falcon
type CrowdStrikeProvider struct {
	*BaseProvider
	clientID     string
	clientSecret string
	baseURL      string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

type CrowdStrikeConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	BaseURL      string `json:"base_url"` // e.g., https://api.crowdstrike.com
}

func NewCrowdStrikeProvider() *CrowdStrikeProvider {
	return &CrowdStrikeProvider{
		BaseProvider: NewBaseProvider("crowdstrike", ProviderTypeEndpoint),
		baseURL:      "https://api.crowdstrike.com",
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (c *CrowdStrikeProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := c.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	c.clientID = c.GetConfigString("client_id")
	c.clientSecret = c.GetConfigString("client_secret")

	if baseURL := c.GetConfigString("base_url"); baseURL != "" {
		c.baseURL = baseURL
	}

	return nil
}

func (c *CrowdStrikeProvider) Test(ctx context.Context) error {
	_, err := c.authenticate(ctx)
	return err
}

func (c *CrowdStrikeProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "crowdstrike_hosts",
			Description: "CrowdStrike Falcon managed hosts",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "hostname", Type: "string"},
				{Name: "platform_name", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "last_seen", Type: "timestamp"},
				{Name: "status", Type: "string"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"device_id"},
		},
		{
			Name:        "crowdstrike_detections",
			Description: "CrowdStrike Falcon detections",
			Columns: []ColumnSchema{
				{Name: "detection_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string"},
				{Name: "severity", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "tactic", Type: "string"},
				{Name: "technique", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"detection_id"},
		},
		{
			Name:        "crowdstrike_vulnerabilities",
			Description: "CrowdStrike Spotlight vulnerabilities",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "host_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "app_name", Type: "string"},
				{Name: "app_version", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (c *CrowdStrikeProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  c.Name(),
		StartedAt: start,
	}

	token, err := c.authenticate(ctx)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	c.token = token

	// Sync hosts
	hosts, err := c.syncHosts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "hosts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *hosts)
		result.TotalRows += hosts.Rows
	}

	// Sync detections
	detections, err := c.syncDetections(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "detections: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *detections)
		result.TotalRows += detections.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (c *CrowdStrikeProvider) authenticate(ctx context.Context) (string, error) {
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}

	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth2/token",
		bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: %s", string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	c.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, nil
}

func (c *CrowdStrikeProvider) syncHosts(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "crowdstrike_hosts"}

	// Get host IDs
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/devices/queries/devices/v1", nil)
	if err != nil {
		return result, err
	}
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()

	var queryResult struct {
		Resources []string `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&queryResult); err != nil {
		return result, err
	}

	result.Rows = int64(len(queryResult.Resources))
	return result, nil
}

func (c *CrowdStrikeProvider) syncDetections(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "crowdstrike_detections"}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/detects/queries/detects/v1", nil)
	if err != nil {
		return result, err
	}
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()

	var queryResult struct {
		Resources []string `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&queryResult); err != nil {
		return result, err
	}

	result.Rows = int64(len(queryResult.Resources))
	return result, nil
}

func (c *CrowdStrikeProvider) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
}
