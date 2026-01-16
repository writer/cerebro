package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TenableProvider syncs vulnerability data from Tenable.io
type TenableProvider struct {
	*BaseProvider
	accessKey string
	secretKey string
	baseURL   string
	client    *http.Client
}

func NewTenableProvider() *TenableProvider {
	return &TenableProvider{
		BaseProvider: NewBaseProvider("tenable", ProviderTypeSaaS),
		baseURL:      "https://cloud.tenable.com",
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (t *TenableProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := t.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	t.accessKey = t.GetConfigString("access_key")
	t.secretKey = t.GetConfigString("secret_key")
	if baseURL := t.GetConfigString("base_url"); baseURL != "" {
		t.baseURL = baseURL
	}

	return nil
}

func (t *TenableProvider) Test(ctx context.Context) error {
	_, err := t.request(ctx, "/server/properties")
	return err
}

func (t *TenableProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "tenable_assets",
			Description: "Tenable discovered assets",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "fqdn", Type: "array"},
				{Name: "hostname", Type: "array"},
				{Name: "ipv4", Type: "array"},
				{Name: "ipv6", Type: "array"},
				{Name: "mac_address", Type: "array"},
				{Name: "netbios_name", Type: "array"},
				{Name: "operating_system", Type: "array"},
				{Name: "system_type", Type: "array"},
				{Name: "agent_uuid", Type: "string"},
				{Name: "aws_ec2_instance_id", Type: "string"},
				{Name: "aws_vpc_id", Type: "string"},
				{Name: "azure_vm_id", Type: "string"},
				{Name: "gcp_instance_id", Type: "string"},
				{Name: "has_agent", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "first_seen", Type: "timestamp"},
				{Name: "last_seen", Type: "timestamp"},
				{Name: "last_authenticated_scan_date", Type: "timestamp"},
				{Name: "last_licensed_scan_date", Type: "timestamp"},
				{Name: "sources", Type: "array"},
				{Name: "tags", Type: "array"},
				{Name: "acr_score", Type: "integer"},
				{Name: "exposure_score", Type: "integer"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "tenable_vulnerabilities",
			Description: "Tenable vulnerability findings",
			Columns: []ColumnSchema{
				{Name: "asset_id", Type: "string", Required: true},
				{Name: "plugin_id", Type: "integer", Required: true},
				{Name: "plugin_name", Type: "string"},
				{Name: "plugin_family", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "severity_id", Type: "integer"},
				{Name: "cve", Type: "array"},
				{Name: "cvss_base_score", Type: "float"},
				{Name: "cvss3_base_score", Type: "float"},
				{Name: "vpr_score", Type: "float"},
				{Name: "exploit_available", Type: "boolean"},
				{Name: "exploitability_ease", Type: "string"},
				{Name: "exploit_code_maturity", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "protocol", Type: "string"},
				{Name: "port", Type: "integer"},
				{Name: "first_found", Type: "timestamp"},
				{Name: "last_found", Type: "timestamp"},
				{Name: "output", Type: "string"},
				{Name: "solution", Type: "string"},
			},
			PrimaryKey: []string{"asset_id", "plugin_id"},
		},
		{
			Name:        "tenable_plugins",
			Description: "Tenable vulnerability plugins",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "name", Type: "string"},
				{Name: "family_name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "synopsis", Type: "string"},
				{Name: "solution", Type: "string"},
				{Name: "risk_factor", Type: "string"},
				{Name: "cvss_base_score", Type: "float"},
				{Name: "cvss3_base_score", Type: "float"},
				{Name: "vpr_score", Type: "float"},
				{Name: "cve", Type: "array"},
				{Name: "cwe", Type: "array"},
				{Name: "xref", Type: "array"},
				{Name: "publication_date", Type: "timestamp"},
				{Name: "modification_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "tenable_scans",
			Description: "Tenable scan configurations and history",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "uuid", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "policy_id", Type: "integer"},
				{Name: "scanner_id", Type: "integer"},
				{Name: "folder_id", Type: "integer"},
				{Name: "owner", Type: "string"},
				{Name: "enabled", Type: "boolean"},
				{Name: "creation_date", Type: "timestamp"},
				{Name: "last_modification_date", Type: "timestamp"},
				{Name: "start_time", Type: "timestamp"},
				{Name: "end_time", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "tenable_agents",
			Description: "Tenable Nessus agents",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "uuid", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "distro", Type: "string"},
				{Name: "ip", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "core_version", Type: "string"},
				{Name: "last_scanned", Type: "timestamp"},
				{Name: "last_connect", Type: "timestamp"},
				{Name: "linked_on", Type: "timestamp"},
				{Name: "groups", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (t *TenableProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  t.Name(),
		StartedAt: start,
	}

	// Sync assets
	assets, err := t.syncAssets(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "assets: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *assets)
		result.TotalRows += assets.Rows
	}

	// Sync vulnerabilities (export)
	vulns, err := t.syncVulnerabilities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "vulnerabilities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vulns)
		result.TotalRows += vulns.Rows
	}

	// Sync scans
	scans, err := t.syncScans(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "scans: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *scans)
		result.TotalRows += scans.Rows
	}

	// Sync agents
	agents, err := t.syncAgents(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "agents: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *agents)
		result.TotalRows += agents.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (t *TenableProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", t.accessKey, t.secretKey))
	req.Header.Set("Accept", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tenable API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (t *TenableProvider) syncAssets(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tenable_assets"}

	// Use assets export for large datasets
	body, err := t.request(ctx, "/assets")
	if err != nil {
		return result, err
	}

	var response struct {
		Assets []map[string]interface{} `json:"assets"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Assets))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TenableProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tenable_vulnerabilities"}

	// Request vulnerability export
	// Note: In production, this would use the async export API
	body, err := t.request(ctx, "/workbenches/vulnerabilities?date_range=30")
	if err != nil {
		return result, err
	}

	var response struct {
		Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Vulnerabilities))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TenableProvider) syncScans(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tenable_scans"}

	body, err := t.request(ctx, "/scans")
	if err != nil {
		return result, err
	}

	var response struct {
		Scans []map[string]interface{} `json:"scans"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Scans))
	result.Inserted = result.Rows
	return result, nil
}

func (t *TenableProvider) syncAgents(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "tenable_agents"}

	body, err := t.request(ctx, "/scanners/1/agents?limit=5000")
	if err != nil {
		return result, err
	}

	var response struct {
		Agents []map[string]interface{} `json:"agents"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Agents))
	result.Inserted = result.Rows
	return result, nil
}
