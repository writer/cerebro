package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// KandjiProvider syncs device data from Kandji MDM
type KandjiProvider struct {
	*BaseProvider
	apiURL   string
	apiToken string
	client   *http.Client
}

func NewKandjiProvider() *KandjiProvider {
	return &KandjiProvider{
		BaseProvider: NewBaseProvider("kandji", ProviderTypeEndpoint),
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (k *KandjiProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := k.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	k.apiURL = k.GetConfigString("api_url")
	if k.apiURL == "" {
		k.apiURL = "https://api.kandji.io/api/v1"
	}

	k.apiToken = k.GetConfigString("api_token")
	if k.apiToken == "" {
		return fmt.Errorf("kandji api_token required")
	}

	return nil
}

func (k *KandjiProvider) Test(ctx context.Context) error {
	_, err := k.request(ctx, "/devices?limit=1")
	return err
}

func (k *KandjiProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "kandji_devices",
			Description: "Kandji managed devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "device_name", Type: "string"},
				{Name: "serial_number", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "last_check_in", Type: "timestamp"},
				{Name: "user_name", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "asset_tag", Type: "string"},
				{Name: "blueprint_name", Type: "string"},
				{Name: "mdm_enabled", Type: "boolean"},
				{Name: "agent_installed", Type: "boolean"},
				{Name: "is_supervised", Type: "boolean"},
				{Name: "filevault_enabled", Type: "boolean"},
				{Name: "firewall_enabled", Type: "boolean"},
				{Name: "remote_desktop_enabled", Type: "boolean"},
				{Name: "screen_sharing_enabled", Type: "boolean"},
				{Name: "gatekeeper_enabled", Type: "boolean"},
				{Name: "sip_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"device_id"},
		},
		{
			Name:        "kandji_device_apps",
			Description: "Applications installed on Kandji devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "app_name", Type: "string", Required: true},
				{Name: "bundle_id", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "path", Type: "string"},
			},
			PrimaryKey: []string{"device_id", "app_name"},
		},
		{
			Name:        "kandji_device_profiles",
			Description: "Configuration profiles on Kandji devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "profile_id", Type: "string", Required: true},
				{Name: "profile_name", Type: "string"},
				{Name: "profile_uuid", Type: "string"},
				{Name: "installed", Type: "boolean"},
			},
			PrimaryKey: []string{"device_id", "profile_id"},
		},
		{
			Name:        "kandji_users",
			Description: "Kandji users",
			Columns: []ColumnSchema{
				{Name: "user_id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "is_active", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"user_id"},
		},
		{
			Name:        "kandji_vulnerabilities",
			Description: "Kandji vulnerability detections",
			Columns: []ColumnSchema{
				{Name: "cve_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string"},
				{Name: "device_name", Type: "string"},
				{Name: "device_serial_number", Type: "string"},
				{Name: "software_name", Type: "string"},
				{Name: "software_version", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "cvss_severity", Type: "string"},
				{Name: "first_detection_date", Type: "timestamp"},
				{Name: "latest_detection_date", Type: "timestamp"},
				{Name: "cve_link", Type: "string"},
			},
			PrimaryKey: []string{"cve_id", "device_id"},
		},
		{
			Name:        "kandji_audit_events",
			Description: "Kandji audit log events",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "action", Type: "string"},
				{Name: "actor_id", Type: "string"},
				{Name: "actor_type", Type: "string"},
				{Name: "target_id", Type: "string"},
				{Name: "target_type", Type: "string"},
				{Name: "occurred_at", Type: "timestamp"},
				{Name: "new_state", Type: "json"},
				{Name: "metadata", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (k *KandjiProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  k.Name(),
		StartedAt: start,
	}

	// Sync devices
	devices, err := k.syncDevices(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "devices: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *devices)
		result.TotalRows += devices.Rows
	}

	// Sync users
	users, err := k.syncUsers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "users: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *users)
		result.TotalRows += users.Rows
	}

	// Sync vulnerabilities (if available)
	vulns, err := k.syncVulnerabilities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "vulnerabilities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vulns)
		result.TotalRows += vulns.Rows
	}

	// Sync audit events
	auditEvents, err := k.syncAuditEvents(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "audit_events: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *auditEvents)
		result.TotalRows += auditEvents.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (k *KandjiProvider) syncDevices(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "kandji_devices"}

	devices, err := k.listAllDevices(ctx)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(devices))
	result.Inserted = result.Rows
	return result, nil
}

func (k *KandjiProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "kandji_users"}

	body, err := k.request(ctx, "/users")
	if err != nil {
		return result, err
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(body, &users); err != nil {
		return result, err
	}

	result.Rows = int64(len(users))
	result.Inserted = result.Rows
	return result, nil
}

func (k *KandjiProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "kandji_vulnerabilities"}

	body, err := k.request(ctx, "/vulnerability-management/detections?size=300")
	if err != nil {
		// Vulnerability management may not be enabled
		return result, nil
	}

	var resp struct {
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, nil
	}

	result.Rows = int64(len(resp.Results))
	result.Inserted = result.Rows
	return result, nil
}

func (k *KandjiProvider) syncAuditEvents(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "kandji_audit_events"}

	body, err := k.request(ctx, "/audit/events?limit=500&sort_by=-occurred_at")
	if err != nil {
		return result, err
	}

	var resp struct {
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	result.Rows = int64(len(resp.Results))
	result.Inserted = result.Rows
	return result, nil
}

func (k *KandjiProvider) listAllDevices(ctx context.Context) ([]map[string]interface{}, error) {
	var allDevices []map[string]interface{}
	offset := 0
	limit := 300

	for {
		body, err := k.request(ctx, fmt.Sprintf("/devices?limit=%d&offset=%d", limit, offset))
		if err != nil {
			return nil, err
		}

		var devices []map[string]interface{}
		if err := json.Unmarshal(body, &devices); err != nil {
			return nil, err
		}

		allDevices = append(allDevices, devices...)

		if len(devices) < limit {
			break
		}
		offset += limit
	}

	return allDevices, nil
}

func (k *KandjiProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := k.apiURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+k.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kandji API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// DeviceCompliance returns compliance information for a device
func (k *KandjiProvider) DeviceCompliance(device map[string]interface{}) map[string]bool {
	return map[string]bool{
		"filevault_enabled":  getBool(device, "filevault_enabled"),
		"firewall_enabled":   getBool(device, "firewall_enabled"),
		"gatekeeper_enabled": getBool(device, "gatekeeper_enabled"),
		"sip_enabled":        getBool(device, "sip_enabled"),
		"mdm_enabled":        getBool(device, "mdm_enabled"),
		"agent_installed":    getBool(device, "agent_installed"),
	}
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}
