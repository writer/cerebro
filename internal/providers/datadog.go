package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DatadogProvider syncs security and observability data from Datadog
type DatadogProvider struct {
	*BaseProvider
	apiKey  string
	appKey  string
	site    string
	baseURL string
	client  *http.Client
}

func NewDatadogProvider() *DatadogProvider {
	return &DatadogProvider{
		BaseProvider: NewBaseProvider("datadog", ProviderTypeSaaS),
		site:         "datadoghq.com",
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *DatadogProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := d.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	d.apiKey = d.GetConfigString("api_key")
	d.appKey = d.GetConfigString("app_key")
	if site := d.GetConfigString("site"); site != "" {
		d.site = site
	}
	d.baseURL = fmt.Sprintf("https://api.%s", d.site)

	return nil
}

func (d *DatadogProvider) Test(ctx context.Context) error {
	_, err := d.request(ctx, "/api/v1/validate")
	return err
}

func (d *DatadogProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "datadog_hosts",
			Description: "Datadog monitored hosts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "aliases", Type: "array"},
				{Name: "apps", Type: "array"},
				{Name: "aws_name", Type: "string"},
				{Name: "host_name", Type: "string"},
				{Name: "is_muted", Type: "boolean"},
				{Name: "last_reported_time", Type: "integer"},
				{Name: "meta", Type: "object"},
				{Name: "sources", Type: "array"},
				{Name: "tags_by_source", Type: "object"},
				{Name: "up", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "datadog_security_signals",
			Description: "Datadog Cloud SIEM security signals",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "title", Type: "string"},
				{Name: "message", Type: "string"},
				{Name: "rule_id", Type: "string"},
				{Name: "rule_name", Type: "string"},
				{Name: "timestamp", Type: "timestamp"},
				{Name: "attributes", Type: "object"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "datadog_security_rules",
			Description: "Datadog Cloud SIEM detection rules",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "is_enabled", Type: "boolean"},
				{Name: "is_default", Type: "boolean"},
				{Name: "message", Type: "string"},
				{Name: "tags", Type: "array"},
				{Name: "queries", Type: "array"},
				{Name: "cases", Type: "array"},
				{Name: "filters", Type: "array"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "datadog_cspm_findings",
			Description: "Datadog Cloud Security Posture Management findings",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "rule_id", Type: "string"},
				{Name: "rule_name", Type: "string"},
				{Name: "resource_type", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "framework", Type: "string"},
				{Name: "evaluation_timestamp", Type: "timestamp"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "datadog_monitors",
			Description: "Datadog monitors",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "query", Type: "string"},
				{Name: "message", Type: "string"},
				{Name: "overall_state", Type: "string"},
				{Name: "priority", Type: "integer"},
				{Name: "tags", Type: "array"},
				{Name: "created", Type: "timestamp"},
				{Name: "modified", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "datadog_dashboards",
			Description: "Datadog dashboards",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "title", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "layout_type", Type: "string"},
				{Name: "is_read_only", Type: "boolean"},
				{Name: "author_handle", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "modified_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (d *DatadogProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  d.Name(),
		StartedAt: start,
	}

	// Sync hosts
	hosts, err := d.syncHosts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "hosts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *hosts)
		result.TotalRows += hosts.Rows
	}

	// Sync security signals
	signals, err := d.syncSecuritySignals(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "security_signals: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *signals)
		result.TotalRows += signals.Rows
	}

	// Sync security rules
	rules, err := d.syncSecurityRules(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "security_rules: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *rules)
		result.TotalRows += rules.Rows
	}

	// Sync monitors
	monitors, err := d.syncMonitors(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "monitors: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *monitors)
		result.TotalRows += monitors.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (d *DatadogProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := d.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("DD-API-KEY", d.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", d.appKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("datadog API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (d *DatadogProvider) syncHosts(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "datadog_hosts"}

	body, err := d.request(ctx, "/api/v1/hosts")
	if err != nil {
		return result, err
	}

	var response struct {
		HostList []map[string]interface{} `json:"host_list"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.HostList))
	result.Inserted = result.Rows
	return result, nil
}

func (d *DatadogProvider) syncSecuritySignals(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "datadog_security_signals"}

	// Get signals from the last 24 hours
	now := time.Now()
	from := now.Add(-24*time.Hour).Unix() * 1000
	to := now.Unix() * 1000

	path := fmt.Sprintf("/api/v2/security_monitoring/signals?filter[from]=%d&filter[to]=%d&page[limit]=100", from, to)
	body, err := d.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (d *DatadogProvider) syncSecurityRules(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "datadog_security_rules"}

	body, err := d.request(ctx, "/api/v2/security_monitoring/rules?page[size]=100")
	if err != nil {
		return result, err
	}

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (d *DatadogProvider) syncMonitors(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "datadog_monitors"}

	body, err := d.request(ctx, "/api/v1/monitor")
	if err != nil {
		return result, err
	}

	var monitors []map[string]interface{}
	if err := json.Unmarshal(body, &monitors); err != nil {
		return result, err
	}

	result.Rows = int64(len(monitors))
	result.Inserted = result.Rows
	return result, nil
}
