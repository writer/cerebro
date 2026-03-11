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

// AzureProvider syncs cloud resources from Azure subscriptions
type AzureProvider struct {
	*BaseProvider
	tenantID       string
	clientID       string
	clientSecret   string
	subscriptionID string
	token          string
	tokenExpiry    time.Time
	client         *http.Client
}

func NewAzureProvider() *AzureProvider {
	return &AzureProvider{
		BaseProvider: NewBaseProvider("azure", ProviderTypeCloud),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (a *AzureProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := a.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	a.tenantID = a.GetConfigString("tenant_id")
	a.clientID = a.GetConfigString("client_id")
	a.clientSecret = a.GetConfigString("client_secret")
	a.subscriptionID = a.GetConfigString("subscription_id")

	return nil
}

func (a *AzureProvider) Test(ctx context.Context) error {
	_, err := a.authenticate(ctx)
	return err
}

func (a *AzureProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "azure_subscriptions",
			Description: "Azure subscriptions",
			Columns: []ColumnSchema{
				{Name: "subscription_id", Type: "string", Required: true},
				{Name: "display_name", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "tenant_id", Type: "string"},
			},
			PrimaryKey: []string{"subscription_id"},
		},
		{
			Name:        "azure_resource_groups",
			Description: "Azure resource groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "subscription_id", Type: "string"},
				{Name: "tags", Type: "object"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_virtual_machines",
			Description: "Azure virtual machines",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "vm_size", Type: "string"},
				{Name: "os_type", Type: "string"},
				{Name: "provisioning_state", Type: "string"},
				{Name: "resource_group", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_storage_accounts",
			Description: "Azure storage accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "sku_name", Type: "string"},
				{Name: "kind", Type: "string"},
				{Name: "enable_https_traffic_only", Type: "boolean"},
				{Name: "allow_blob_public_access", Type: "boolean"},
				{Name: "minimum_tls_version", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_network_security_groups",
			Description: "Azure network security groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "resource_group", Type: "string"},
				{Name: "security_rules", Type: "array"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_sql_servers",
			Description: "Azure SQL servers",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "public_network_access", Type: "string"},
				{Name: "minimal_tls_version", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_key_vaults",
			Description: "Azure Key Vaults",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "location", Type: "string"},
				{Name: "sku_name", Type: "string"},
				{Name: "enable_soft_delete", Type: "boolean"},
				{Name: "enable_purge_protection", Type: "boolean"},
				{Name: "enabled_for_deployment", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "azure_activity_logs",
			Description: "Azure Activity Log events",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "operation_name", Type: "string"},
				{Name: "category", Type: "string"},
				{Name: "level", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "caller", Type: "string"},
				{Name: "resource_id", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (a *AzureProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  a.Name(),
		StartedAt: start,
	}

	token, err := a.authenticate(ctx)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	a.token = token

	// Sync resource groups
	rgs, err := a.syncResourceGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "resource_groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *rgs)
		result.TotalRows += rgs.Rows
	}

	// Sync virtual machines
	vms, err := a.syncVirtualMachines(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "virtual_machines: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vms)
		result.TotalRows += vms.Rows
	}

	// Sync storage accounts
	storage, err := a.syncStorageAccounts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "storage_accounts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *storage)
		result.TotalRows += storage.Rows
	}

	// Sync NSGs
	nsgs, err := a.syncNetworkSecurityGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "nsgs: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *nsgs)
		result.TotalRows += nsgs.Rows
	}

	// Sync Key Vaults
	kvs, err := a.syncKeyVaults(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "key_vaults: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *kvs)
		result.TotalRows += kvs.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (a *AzureProvider) authenticate(ctx context.Context) (string, error) {
	if a.token != "" && time.Now().Before(a.tokenExpiry) {
		return a.token, nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", a.tenantID)

	data := url.Values{}
	data.Set("client_id", a.clientID)
	data.Set("client_secret", a.clientSecret)
	data.Set("scope", "https://management.azure.com/.default")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
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

	a.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, nil
}

func (a *AzureProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("https://management.azure.com%s", path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("azure API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (a *AzureProvider) syncResourceGroups(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "azure_resource_groups"}

	path := fmt.Sprintf("/subscriptions/%s/resourcegroups?api-version=2021-04-01", a.subscriptionID)
	body, err := a.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Value))
	result.Inserted = result.Rows
	return result, nil
}

func (a *AzureProvider) syncVirtualMachines(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "azure_virtual_machines"}

	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01", a.subscriptionID)
	body, err := a.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Value))
	result.Inserted = result.Rows
	return result, nil
}

func (a *AzureProvider) syncStorageAccounts(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "azure_storage_accounts"}

	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", a.subscriptionID)
	body, err := a.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Value))
	result.Inserted = result.Rows
	return result, nil
}

func (a *AzureProvider) syncNetworkSecurityGroups(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "azure_network_security_groups"}

	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", a.subscriptionID)
	body, err := a.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Value))
	result.Inserted = result.Rows
	return result, nil
}

func (a *AzureProvider) syncKeyVaults(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "azure_key_vaults"}

	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", a.subscriptionID)
	body, err := a.request(ctx, path)
	if err != nil {
		return result, err
	}

	var response struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Value))
	result.Inserted = result.Rows
	return result, nil
}
