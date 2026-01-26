package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// JamfProvider syncs device data from Jamf Pro MDM
type JamfProvider struct {
	*BaseProvider
	baseURL      string
	clientID     string
	clientSecret string
	accessToken  string
	tokenExpiry  time.Time
	client       *http.Client
}

func NewJamfProvider() *JamfProvider {
	return &JamfProvider{
		BaseProvider: NewBaseProvider("jamf", ProviderTypeEndpoint),
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (j *JamfProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := j.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	j.baseURL = j.GetConfigString("base_url")
	if j.baseURL == "" {
		return fmt.Errorf("jamf base_url required (e.g., https://yourorg.jamfcloud.com)")
	}

	j.clientID = j.GetConfigString("client_id")
	j.clientSecret = j.GetConfigString("client_secret")

	if j.clientID == "" || j.clientSecret == "" {
		return fmt.Errorf("jamf client_id and client_secret required")
	}

	return nil
}

func (j *JamfProvider) Test(ctx context.Context) error {
	if err := j.ensureToken(ctx); err != nil {
		return err
	}
	_, err := j.request(ctx, "/api/v1/jamf-pro-version")
	return err
}

func (j *JamfProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "jamf_computers",
			Description: "Jamf managed macOS computers",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "udid", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "serial_number", Type: "string"},
				{Name: "managed", Type: "boolean"},
				{Name: "supervised", Type: "boolean"},
				{Name: "mdm_capable", Type: "boolean"},
				{Name: "report_date", Type: "timestamp"},
				{Name: "last_contact_time", Type: "timestamp"},
				{Name: "last_enrolled_date", Type: "timestamp"},
				{Name: "os_name", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "os_build", Type: "string"},
				{Name: "model", Type: "string"},
				{Name: "model_identifier", Type: "string"},
				{Name: "username", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "building", Type: "string"},
				{Name: "room", Type: "string"},
				{Name: "filevault_enabled", Type: "boolean"},
				{Name: "firewall_enabled", Type: "boolean"},
				{Name: "gatekeeper_status", Type: "string"},
				{Name: "sip_status", Type: "string"},
				{Name: "remote_desktop_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jamf_mobile_devices",
			Description: "Jamf managed iOS/iPadOS devices",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "udid", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "serial_number", Type: "string"},
				{Name: "managed", Type: "boolean"},
				{Name: "supervised", Type: "boolean"},
				{Name: "last_inventory_update", Type: "timestamp"},
				{Name: "os_type", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "os_build", Type: "string"},
				{Name: "model", Type: "string"},
				{Name: "model_identifier", Type: "string"},
				{Name: "username", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "department", Type: "string"},
				{Name: "passcode_present", Type: "boolean"},
				{Name: "passcode_compliant", Type: "boolean"},
				{Name: "data_protection", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jamf_policies",
			Description: "Jamf configuration policies",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "enabled", Type: "boolean"},
				{Name: "trigger", Type: "string"},
				{Name: "frequency", Type: "string"},
				{Name: "category", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jamf_configuration_profiles",
			Description: "Jamf configuration profiles",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "scope", Type: "string"},
				{Name: "level", Type: "string"},
				{Name: "redeploy_on_update", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "jamf_users",
			Description: "Jamf user accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "email", Type: "string"},
				{Name: "enabled", Type: "boolean"},
				{Name: "privilege_set", Type: "string"},
				{Name: "directory_user", Type: "boolean"},
				{Name: "force_password_change", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (j *JamfProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  j.Name(),
		StartedAt: start,
	}

	if err := j.ensureToken(ctx); err != nil {
		result.Errors = append(result.Errors, "auth: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(start)
		return result, err
	}

	// Sync computers
	computers, err := j.syncComputers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "computers: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *computers)
		result.TotalRows += computers.Rows
	}

	// Sync mobile devices
	mobileDevices, err := j.syncMobileDevices(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "mobile_devices: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *mobileDevices)
		result.TotalRows += mobileDevices.Rows
	}

	// Sync policies
	policies, err := j.syncPolicies(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "policies: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *policies)
		result.TotalRows += policies.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (j *JamfProvider) ensureToken(ctx context.Context) error {
	if j.accessToken != "" && time.Now().Before(j.tokenExpiry) {
		return nil
	}

	url := j.baseURL + "/api/oauth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(j.clientID, j.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	q := req.URL.Query()
	q.Add("grant_type", "client_credentials")
	req.URL.RawQuery = q.Encode()

	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("jamf auth error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	j.accessToken = tokenResp.AccessToken
	j.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
}

func (j *JamfProvider) syncComputers(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "jamf_computers"}

	computers, err := j.listAllComputers(ctx)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(computers))
	result.Inserted = result.Rows
	return result, nil
}

func (j *JamfProvider) syncMobileDevices(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "jamf_mobile_devices"}

	devices, err := j.listAllMobileDevices(ctx)
	if err != nil {
		return result, err
	}

	result.Rows = int64(len(devices))
	result.Inserted = result.Rows
	return result, nil
}

func (j *JamfProvider) syncPolicies(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "jamf_policies"}

	body, err := j.request(ctx, "/api/v1/policies")
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

func (j *JamfProvider) listAllComputers(ctx context.Context) ([]map[string]interface{}, error) {
	var allComputers []map[string]interface{}
	page := 0
	pageSize := 100

	for {
		path := fmt.Sprintf("/api/v1/computers-inventory?page=%d&page-size=%d", page, pageSize)
		body, err := j.request(ctx, path)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Results    []map[string]interface{} `json:"results"`
			TotalCount int                      `json:"totalCount"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allComputers = append(allComputers, resp.Results...)

		if len(allComputers) >= resp.TotalCount {
			break
		}
		page++
	}

	return allComputers, nil
}

func (j *JamfProvider) listAllMobileDevices(ctx context.Context) ([]map[string]interface{}, error) {
	var allDevices []map[string]interface{}
	page := 0
	pageSize := 100

	for {
		path := fmt.Sprintf("/api/v2/mobile-devices?page=%d&page-size=%d", page, pageSize)
		body, err := j.request(ctx, path)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Results    []map[string]interface{} `json:"results"`
			TotalCount int                      `json:"totalCount"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allDevices = append(allDevices, resp.Results...)

		if len(allDevices) >= resp.TotalCount {
			break
		}
		page++
	}

	return allDevices, nil
}

func (j *JamfProvider) request(ctx context.Context, path string) ([]byte, error) {
	if err := j.ensureToken(ctx); err != nil {
		return nil, err
	}

	url := j.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+j.accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("jamf API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetNonCompliantComputers returns computers that don't meet security requirements
func (j *JamfProvider) GetNonCompliantComputers(computers []map[string]interface{}) []map[string]interface{} {
	var nonCompliant []map[string]interface{}

	for _, computer := range computers {
		security, _ := computer["security"].(map[string]interface{})
		if security == nil {
			continue
		}

		filevaultEnabled, _ := security["fileVault2Enabled"].(bool)
		firewallEnabled, _ := security["firewallEnabled"].(bool)
		sipEnabled := security["systemIntegrityProtectionEnabled"]

		if !filevaultEnabled || !firewallEnabled || sipEnabled == false {
			nonCompliant = append(nonCompliant, computer)
		}
	}

	return nonCompliant
}
