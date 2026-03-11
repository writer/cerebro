package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IntuneProvider syncs device management data from Microsoft Intune
type IntuneProvider struct {
	*BaseProvider
	tenantID     string
	clientID     string
	clientSecret string
	accessToken  string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewIntuneProvider() *IntuneProvider {
	return &IntuneProvider{
		BaseProvider: NewBaseProvider("intune", ProviderTypeEndpoint),
		client:       newProviderHTTPClient(60 * time.Second),
	}
}

func (i *IntuneProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := i.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	i.tenantID = i.GetConfigString("tenant_id")
	if i.tenantID == "" {
		return fmt.Errorf("intune tenant_id required")
	}

	i.clientID = i.GetConfigString("client_id")
	i.clientSecret = i.GetConfigString("client_secret")

	if i.clientID == "" || i.clientSecret == "" {
		return fmt.Errorf("intune client_id and client_secret required")
	}

	return nil
}

func (i *IntuneProvider) Test(ctx context.Context) error {
	if err := i.ensureToken(ctx); err != nil {
		return err
	}
	_, err := i.request(ctx, "/v1.0/deviceManagement")
	return err
}

func (i *IntuneProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "intune_managed_devices",
			Description: "Intune managed devices",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "device_name", Type: "string"},
				{Name: "managed_device_owner_type", Type: "string"},
				{Name: "enrolled_datetime", Type: "timestamp"},
				{Name: "last_sync_datetime", Type: "timestamp"},
				{Name: "operating_system", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "compliance_state", Type: "string"},
				{Name: "jail_broken", Type: "string"},
				{Name: "management_agent", Type: "string"},
				{Name: "azure_ad_registered", Type: "boolean"},
				{Name: "azure_ad_device_id", Type: "string"},
				{Name: "user_principal_name", Type: "string"},
				{Name: "email_address", Type: "string"},
				{Name: "model", Type: "string"},
				{Name: "manufacturer", Type: "string"},
				{Name: "serial_number", Type: "string"},
				{Name: "is_encrypted", Type: "boolean"},
				{Name: "is_supervised", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "intune_device_compliance_policies",
			Description: "Intune device compliance policies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "last_modified_datetime", Type: "timestamp"},
				{Name: "platform", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "intune_device_configurations",
			Description: "Intune device configuration profiles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created_datetime", Type: "timestamp"},
				{Name: "last_modified_datetime", Type: "timestamp"},
				{Name: "platform", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "intune_detected_apps",
			Description: "Applications detected on managed devices",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "size_in_byte", Type: "integer"},
				{Name: "device_count", Type: "integer"},
				{Name: "platform", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "intune_compliance_policy_device_states",
			Description: "Device compliance status per policy",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "device_id", Type: "string"},
				{Name: "policy_id", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "last_reported_datetime", Type: "timestamp"},
				{Name: "user_principal_name", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "intune_windows_autopilot_devices",
			Description: "Windows Autopilot device identities",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "serial_number", Type: "string"},
				{Name: "product_key", Type: "string"},
				{Name: "model", Type: "string"},
				{Name: "manufacturer", Type: "string"},
				{Name: "group_tag", Type: "string"},
				{Name: "purchase_order_identifier", Type: "string"},
				{Name: "enrollment_state", Type: "string"},
				{Name: "last_contacted_datetime", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (i *IntuneProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  i.Name(),
		StartedAt: start,
	}

	if err := i.ensureToken(ctx); err != nil {
		result.Errors = append(result.Errors, "auth: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, err
	}

	// Sync managed devices
	devices, err := i.syncManagedDevices(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "managed_devices: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *devices)
		result.TotalRows += devices.Rows
	}

	// Sync compliance policies
	compliancePolicies, err := i.syncCompliancePolicies(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "compliance_policies: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *compliancePolicies)
		result.TotalRows += compliancePolicies.Rows
	}

	// Sync device configurations
	configurations, err := i.syncDeviceConfigurations(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "device_configurations: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *configurations)
		result.TotalRows += configurations.Rows
	}

	// Sync detected apps
	apps, err := i.syncDetectedApps(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "detected_apps: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *apps)
		result.TotalRows += apps.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (i *IntuneProvider) ensureToken(ctx context.Context) error {
	if i.accessToken != "" && time.Now().Before(i.tokenExpiry) {
		return nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", i.tenantID)

	data := url.Values{}
	data.Set("client_id", i.clientID)
	data.Set("client_secret", i.clientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("intune auth error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	i.accessToken = tokenResp.AccessToken
	i.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
}

func (i *IntuneProvider) syncManagedDevices(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "intune_managed_devices"}

	devices, err := i.listAll(ctx, "/v1.0/deviceManagement/managedDevices")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(devices))
	result.Inserted = result.Rows
	return result, nil
}

func (i *IntuneProvider) syncCompliancePolicies(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "intune_device_compliance_policies"}

	policies, err := i.listAll(ctx, "/v1.0/deviceManagement/deviceCompliancePolicies")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(policies))
	result.Inserted = result.Rows
	return result, nil
}

func (i *IntuneProvider) syncDeviceConfigurations(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "intune_device_configurations"}

	configs, err := i.listAll(ctx, "/v1.0/deviceManagement/deviceConfigurations")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(configs))
	result.Inserted = result.Rows
	return result, nil
}

func (i *IntuneProvider) syncDetectedApps(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "intune_detected_apps"}

	apps, err := i.listAll(ctx, "/v1.0/deviceManagement/detectedApps")
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(apps))
	result.Inserted = result.Rows
	return result, nil
}

func (i *IntuneProvider) listAll(ctx context.Context, path string) ([]map[string]interface{}, error) {
	var allItems []map[string]interface{}
	nextLink := path

	for nextLink != "" {
		body, err := i.request(ctx, nextLink)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Value    []map[string]interface{} `json:"value"`
			NextLink string                   `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allItems = append(allItems, resp.Value...)

		if resp.NextLink != "" {
			nextLink = strings.TrimPrefix(resp.NextLink, "https://graph.microsoft.com")
		} else {
			nextLink = ""
		}
	}

	return allItems, nil
}

func (i *IntuneProvider) request(ctx context.Context, path string) ([]byte, error) {
	if err := i.ensureToken(ctx); err != nil {
		return nil, err
	}

	urlStr := "https://graph.microsoft.com" + path
	if strings.HasPrefix(path, "https://") {
		urlStr = path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+i.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("intune API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetNonCompliantDevices returns devices that are not compliant
func (i *IntuneProvider) GetNonCompliantDevices(devices []map[string]interface{}) []map[string]interface{} {
	var nonCompliant []map[string]interface{}

	for _, device := range devices {
		state, _ := device["complianceState"].(string)
		if state == "noncompliant" || state == "unknown" {
			nonCompliant = append(nonCompliant, device)
		}
	}

	return nonCompliant
}

// GetUnencryptedDevices returns devices without encryption
func (i *IntuneProvider) GetUnencryptedDevices(devices []map[string]interface{}) []map[string]interface{} {
	var unencrypted []map[string]interface{}

	for _, device := range devices {
		encrypted, _ := device["isEncrypted"].(bool)
		if !encrypted {
			unencrypted = append(unencrypted, device)
		}
	}

	return unencrypted
}

// GetStaleDevices returns devices that haven't synced recently
func (i *IntuneProvider) GetStaleDevices(devices []map[string]interface{}, staleDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, -staleDays)
	var stale []map[string]interface{}

	for _, device := range devices {
		lastSync, _ := device["lastSyncDateTime"].(string)
		if lastSync == "" {
			stale = append(stale, device)
			continue
		}

		t, err := time.Parse(time.RFC3339, lastSync)
		if err == nil && t.Before(cutoff) {
			stale = append(stale, device)
		}
	}

	return stale
}
