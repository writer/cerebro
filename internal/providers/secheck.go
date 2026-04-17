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

type SeCheckProvider struct {
	*BaseProvider
	apiURL   string
	apiToken string
	client   *http.Client
}

func NewSeCheckProvider() *SeCheckProvider {
	return &SeCheckProvider{
		BaseProvider: NewBaseProvider("secheck", ProviderTypeEndpoint),
		client:       newProviderHTTPClient(60 * time.Second),
	}
}

func (s *SeCheckProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiURL = s.GetConfigString("api_url")
	if s.apiURL == "" {
		return fmt.Errorf("secheck api_url required")
	}

	s.apiToken = s.GetConfigString("api_token")
	if s.apiToken == "" {
		return fmt.Errorf("secheck api_token required")
	}

	return nil
}

func (s *SeCheckProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/health")
	return err
}

func (s *SeCheckProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "secheck_devices",
			Description: "SeCheck enrolled endpoint devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "hostname", Type: "string"},
				{Name: "os_type", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "org_id", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "last_heartbeat", Type: "timestamp"},
				{Name: "enrolled_at", Type: "timestamp"},
				{Name: "status", Type: "string"},
			},
			PrimaryKey: []string{"device_id"},
		},
		{
			Name:        "secheck_findings",
			Description: "SeCheck verified vulnerability findings per device",
			Columns: []ColumnSchema{
				{Name: "finding_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "package_name", Type: "string"},
				{Name: "installed_version", Type: "string"},
				{Name: "fixed_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "ecosystem", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "verified_at", Type: "timestamp"},
				{Name: "remediated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"finding_id"},
		},
		{
			Name:        "secheck_remediations",
			Description: "SeCheck remediation attestation records",
			Columns: []ColumnSchema{
				{Name: "attestation_id", Type: "string", Required: true},
				{Name: "finding_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string", Required: true},
				{Name: "method", Type: "string"},
				{Name: "old_version", Type: "string"},
				{Name: "new_version", Type: "string"},
				{Name: "manager", Type: "string"},
				{Name: "success", Type: "boolean"},
				{Name: "completed_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"attestation_id"},
		},
	}
}

func (s *SeCheckProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	startedAt := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: startedAt,
	}

	tables := opts.Tables
	if len(tables) == 0 {
		for _, schema := range s.Schema() {
			tables = append(tables, schema.Name)
		}
	}

	for _, table := range tables {
		tableResult, err := s.syncTable(ctx, table, opts)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", table, err))
			result.Tables = append(result.Tables, TableResult{Name: table, Error: err.Error()})
			continue
		}
		result.Tables = append(result.Tables, *tableResult)
		result.TotalRows += tableResult.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startedAt)
	return result, nil
}

func (s *SeCheckProvider) syncTable(ctx context.Context, table string, opts SyncOptions) (*TableResult, error) {
	endpoint := tableEndpoint(table)
	if endpoint == "" {
		return nil, fmt.Errorf("unknown table %q", table)
	}

	if opts.Since != nil {
		endpoint += fmt.Sprintf("?since=%s", opts.Since.Format(time.RFC3339))
	}

	data, err := s.request(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var records []map[string]interface{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode %s: %w", table, err)
	}

	return &TableResult{
		Name:     table,
		Rows:     int64(len(records)),
		Inserted: int64(len(records)),
	}, nil
}

func (s *SeCheckProvider) request(ctx context.Context, path string) ([]byte, error) {
	reqURL := strings.TrimRight(s.apiURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secheck request %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("secheck read response %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("secheck %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

func tableEndpoint(table string) string {
	switch table {
	case "secheck_devices":
		return "/api/v1/devices"
	case "secheck_findings":
		return "/api/v1/findings"
	case "secheck_remediations":
		return "/api/v1/remediations"
	default:
		return ""
	}
}
