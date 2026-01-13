package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SentinelOneProvider syncs endpoint security data from SentinelOne
type SentinelOneProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewSentinelOneProvider() *SentinelOneProvider {
	return &SentinelOneProvider{
		BaseProvider: NewBaseProvider("sentinelone", ProviderTypeEndpoint),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SentinelOneProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiToken = s.GetConfigString("api_token")
	s.baseURL = s.GetConfigString("base_url") // e.g., https://usea1-partners.sentinelone.net

	return nil
}

func (s *SentinelOneProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/web/api/v2.1/system/info")
	return err
}

func (s *SentinelOneProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "sentinelone_agents",
			Description: "SentinelOne endpoint agents",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "uuid", Type: "string"},
				{Name: "computer_name", Type: "string"},
				{Name: "external_ip", Type: "string"},
				{Name: "internal_ip", Type: "string"},
				{Name: "os_name", Type: "string"},
				{Name: "os_type", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "is_active", Type: "boolean"},
				{Name: "is_infected", Type: "boolean"},
				{Name: "is_up_to_date", Type: "boolean"},
				{Name: "network_status", Type: "string"},
				{Name: "scan_status", Type: "string"},
				{Name: "threat_reboot_required", Type: "boolean"},
				{Name: "last_active_date", Type: "timestamp"},
				{Name: "registered_at", Type: "timestamp"},
				{Name: "site_id", Type: "string"},
				{Name: "site_name", Type: "string"},
				{Name: "group_id", Type: "string"},
				{Name: "group_name", Type: "string"},
				{Name: "machine_type", Type: "string"},
				{Name: "domain", Type: "string"},
				{Name: "encrypted_applications", Type: "boolean"},
				{Name: "firewall_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_threats",
			Description: "SentinelOne threat detections",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "agent_id", Type: "string"},
				{Name: "agent_computer_name", Type: "string"},
				{Name: "threat_name", Type: "string"},
				{Name: "classification", Type: "string"},
				{Name: "classification_source", Type: "string"},
				{Name: "confidence_level", Type: "string"},
				{Name: "analyst_verdict", Type: "string"},
				{Name: "incident_status", Type: "string"},
				{Name: "mitigation_status", Type: "string"},
				{Name: "initiated_by", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "file_sha256", Type: "string"},
				{Name: "file_sha1", Type: "string"},
				{Name: "file_md5", Type: "string"},
				{Name: "mitre_tactics", Type: "array"},
				{Name: "mitre_techniques", Type: "array"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_activities",
			Description: "SentinelOne activity log",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "activity_type", Type: "integer"},
				{Name: "activity_description", Type: "string"},
				{Name: "primary_description", Type: "string"},
				{Name: "secondary_description", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "site_id", Type: "string"},
				{Name: "threat_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_sites",
			Description: "SentinelOne sites/accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "account_id", Type: "string"},
				{Name: "account_name", Type: "string"},
				{Name: "license_type", Type: "string"},
				{Name: "total_licenses", Type: "integer"},
				{Name: "active_licenses", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_applications",
			Description: "Applications installed on endpoints",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "agent_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "publisher", Type: "string"},
				{Name: "size", Type: "integer"},
				{Name: "installed_date", Type: "timestamp"},
				{Name: "type", Type: "string"},
				{Name: "risk_level", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_vulnerabilities",
			Description: "Vulnerabilities detected on endpoints",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "application_name", Type: "string"},
				{Name: "application_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "exploited_in_wild", Type: "boolean"},
				{Name: "days_since_detection", Type: "integer"},
				{Name: "remediation_action", Type: "string"},
				{Name: "detected_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SentinelOneProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	// Sync sites
	sites, err := s.syncSites(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "sites: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *sites)
		result.TotalRows += sites.Rows
	}

	// Sync agents
	agents, err := s.syncAgents(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "agents: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *agents)
		result.TotalRows += agents.Rows
	}

	// Sync threats
	threats, err := s.syncThreats(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "threats: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *threats)
		result.TotalRows += threats.Rows
	}

	// Sync activities
	activities, err := s.syncActivities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "activities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *activities)
		result.TotalRows += activities.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (s *SentinelOneProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := s.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "APIToken "+s.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sentinelone API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (s *SentinelOneProvider) syncSites(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "sentinelone_sites"}

	body, err := s.request(ctx, "/web/api/v2.1/sites?limit=100")
	if err != nil {
		return result, err
	}

	var response struct {
		Data struct {
			Sites []map[string]interface{} `json:"sites"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Data.Sites))
	result.Inserted = result.Rows
	return result, nil
}

func (s *SentinelOneProvider) syncAgents(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "sentinelone_agents"}

	body, err := s.request(ctx, "/web/api/v2.1/agents?limit=1000")
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

func (s *SentinelOneProvider) syncThreats(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "sentinelone_threats"}

	// Get threats from last 30 days
	createdAfter := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	path := fmt.Sprintf("/web/api/v2.1/threats?limit=1000&createdAt__gt=%s", createdAfter)

	body, err := s.request(ctx, path)
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

func (s *SentinelOneProvider) syncActivities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "sentinelone_activities"}

	// Get activities from last 7 days
	createdAfter := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	path := fmt.Sprintf("/web/api/v2.1/activities?limit=1000&createdAt__gt=%s", createdAfter)

	body, err := s.request(ctx, path)
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
