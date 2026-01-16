package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CloudflareProvider syncs network security data from Cloudflare
type CloudflareProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewCloudflareProvider() *CloudflareProvider {
	return &CloudflareProvider{
		BaseProvider: NewBaseProvider("cloudflare", ProviderTypeNetwork),
		baseURL:      "https://api.cloudflare.com/client/v4",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CloudflareProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := c.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	c.apiToken = c.GetConfigString("api_token")

	return nil
}

func (c *CloudflareProvider) Test(ctx context.Context) error {
	_, err := c.request(ctx, "/user/tokens/verify")
	return err
}

func (c *CloudflareProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "cloudflare_accounts",
			Description: "Cloudflare accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "settings", Type: "object"},
				{Name: "created_on", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "cloudflare_zones",
			Description: "Cloudflare zones (domains)",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "paused", Type: "boolean"},
				{Name: "type", Type: "string"},
				{Name: "plan", Type: "object"},
				{Name: "name_servers", Type: "array"},
				{Name: "created_on", Type: "timestamp"},
				{Name: "modified_on", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "cloudflare_dns_records",
			Description: "Cloudflare DNS records",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "zone_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "content", Type: "string"},
				{Name: "proxied", Type: "boolean"},
				{Name: "ttl", Type: "integer"},
				{Name: "created_on", Type: "timestamp"},
				{Name: "modified_on", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "cloudflare_firewall_rules",
			Description: "Cloudflare firewall rules",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "zone_id", Type: "string"},
				{Name: "action", Type: "string"},
				{Name: "expression", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "paused", Type: "boolean"},
				{Name: "priority", Type: "integer"},
				{Name: "created_on", Type: "timestamp"},
				{Name: "modified_on", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "cloudflare_waf_rules",
			Description: "Cloudflare WAF managed rules",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "zone_id", Type: "string"},
				{Name: "package_id", Type: "string"},
				{Name: "mode", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "group_id", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "cloudflare_access_applications",
			Description: "Cloudflare Access applications",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "account_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "domain", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "session_duration", Type: "string"},
				{Name: "auto_redirect_to_identity", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (c *CloudflareProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  c.Name(),
		StartedAt: start,
	}

	// Sync zones
	zones, err := c.syncZones(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "zones: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *zones)
		result.TotalRows += zones.Rows
	}

	// Get zone IDs for other syncs
	zoneIDs, _ := c.getZoneIDs(ctx)

	// Sync DNS records for each zone
	for _, zoneID := range zoneIDs {
		dns, err := c.syncDNSRecords(ctx, zoneID)
		if err != nil {
			continue
		}
		result.TotalRows += dns.Rows
	}

	// Sync firewall rules for each zone
	for _, zoneID := range zoneIDs {
		fw, err := c.syncFirewallRules(ctx, zoneID)
		if err != nil {
			continue
		}
		result.TotalRows += fw.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (c *CloudflareProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloudflare API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *CloudflareProvider) syncZones(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "cloudflare_zones"}

	body, err := c.request(ctx, "/zones?per_page=50")
	if err != nil {
		return result, err
	}

	var response struct {
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Result))
	result.Inserted = result.Rows
	return result, nil
}

func (c *CloudflareProvider) getZoneIDs(ctx context.Context) ([]string, error) {
	body, err := c.request(ctx, "/zones?per_page=50")
	if err != nil {
		return nil, err
	}

	var response struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	ids := make([]string, len(response.Result))
	for i, z := range response.Result {
		ids[i] = z.ID
	}
	return ids, nil
}

func (c *CloudflareProvider) syncDNSRecords(ctx context.Context, zoneID string) (*TableResult, error) {
	result := &TableResult{Name: "cloudflare_dns_records"}

	body, err := c.request(ctx, fmt.Sprintf("/zones/%s/dns_records?per_page=100", zoneID))
	if err != nil {
		return result, err
	}

	var response struct {
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Result))
	result.Inserted = result.Rows
	return result, nil
}

func (c *CloudflareProvider) syncFirewallRules(ctx context.Context, zoneID string) (*TableResult, error) {
	result := &TableResult{Name: "cloudflare_firewall_rules"}

	body, err := c.request(ctx, fmt.Sprintf("/zones/%s/firewall/rules?per_page=100", zoneID))
	if err != nil {
		return result, err
	}

	var response struct {
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Result))
	result.Inserted = result.Rows
	return result, nil
}
