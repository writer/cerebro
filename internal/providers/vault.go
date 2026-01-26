package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VaultProvider syncs secret metadata from HashiCorp Vault
type VaultProvider struct {
	*BaseProvider
	address   string
	token     string
	namespace string
	client    *http.Client
}

func NewVaultProvider() *VaultProvider {
	return &VaultProvider{
		BaseProvider: NewBaseProvider("vault", ProviderTypeSaaS),
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (v *VaultProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := v.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	v.address = v.GetConfigString("address")
	if v.address == "" {
		return fmt.Errorf("vault address required")
	}

	v.token = v.GetConfigString("token")
	if v.token == "" {
		return fmt.Errorf("vault token required")
	}

	v.namespace = v.GetConfigString("namespace")

	return nil
}

func (v *VaultProvider) Test(ctx context.Context) error {
	_, err := v.request(ctx, "/v1/sys/health")
	return err
}

func (v *VaultProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "vault_secrets",
			Description: "Vault secret metadata (not values)",
			Columns: []ColumnSchema{
				{Name: "path", Type: "string", Required: true},
				{Name: "mount", Type: "string"},
				{Name: "version", Type: "integer"},
				{Name: "created_time", Type: "timestamp"},
				{Name: "deletion_time", Type: "timestamp"},
				{Name: "destroyed", Type: "boolean"},
				{Name: "custom_metadata", Type: "json"},
			},
			PrimaryKey: []string{"path"},
		},
		{
			Name:        "vault_auth_methods",
			Description: "Vault authentication methods",
			Columns: []ColumnSchema{
				{Name: "path", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "accessor", Type: "string"},
				{Name: "local", Type: "boolean"},
				{Name: "seal_wrap", Type: "boolean"},
			},
			PrimaryKey: []string{"path"},
		},
		{
			Name:        "vault_policies",
			Description: "Vault access policies",
			Columns: []ColumnSchema{
				{Name: "name", Type: "string", Required: true},
				{Name: "policy", Type: "string"},
			},
			PrimaryKey: []string{"name"},
		},
		{
			Name:        "vault_mounts",
			Description: "Vault secret engine mounts",
			Columns: []ColumnSchema{
				{Name: "path", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "accessor", Type: "string"},
				{Name: "local", Type: "boolean"},
				{Name: "seal_wrap", Type: "boolean"},
				{Name: "options", Type: "json"},
			},
			PrimaryKey: []string{"path"},
		},
		{
			Name:        "vault_tokens",
			Description: "Vault token accessors",
			Columns: []ColumnSchema{
				{Name: "accessor", Type: "string", Required: true},
				{Name: "creation_time", Type: "timestamp"},
				{Name: "creation_ttl", Type: "integer"},
				{Name: "display_name", Type: "string"},
				{Name: "expire_time", Type: "timestamp"},
				{Name: "orphan", Type: "boolean"},
				{Name: "path", Type: "string"},
				{Name: "policies", Type: "array"},
				{Name: "renewable", Type: "boolean"},
				{Name: "type", Type: "string"},
			},
			PrimaryKey: []string{"accessor"},
		},
		{
			Name:        "vault_audit_devices",
			Description: "Vault audit logging devices",
			Columns: []ColumnSchema{
				{Name: "path", Type: "string", Required: true},
				{Name: "type", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "options", Type: "json"},
				{Name: "local", Type: "boolean"},
			},
			PrimaryKey: []string{"path"},
		},
		{
			Name:        "vault_leases",
			Description: "Vault active leases",
			Columns: []ColumnSchema{
				{Name: "lease_id", Type: "string", Required: true},
				{Name: "issue_time", Type: "timestamp"},
				{Name: "expire_time", Type: "timestamp"},
				{Name: "last_renewal", Type: "timestamp"},
				{Name: "renewable", Type: "boolean"},
				{Name: "ttl", Type: "integer"},
			},
			PrimaryKey: []string{"lease_id"},
		},
		{
			Name:        "vault_entities",
			Description: "Vault identity entities",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "policies", Type: "array"},
				{Name: "disabled", Type: "boolean"},
				{Name: "creation_time", Type: "timestamp"},
				{Name: "last_update_time", Type: "timestamp"},
				{Name: "metadata", Type: "json"},
				{Name: "aliases", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "vault_groups",
			Description: "Vault identity groups",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "type", Type: "string"},
				{Name: "policies", Type: "array"},
				{Name: "member_entity_ids", Type: "array"},
				{Name: "member_group_ids", Type: "array"},
				{Name: "creation_time", Type: "timestamp"},
				{Name: "last_update_time", Type: "timestamp"},
				{Name: "metadata", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (v *VaultProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  v.Name(),
		StartedAt: start,
	}

	// Sync auth methods
	authMethods, err := v.syncAuthMethods(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "auth_methods: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *authMethods)
		result.TotalRows += authMethods.Rows
	}

	// Sync policies
	policies, err := v.syncPolicies(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "policies: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *policies)
		result.TotalRows += policies.Rows
	}

	// Sync mounts
	mounts, err := v.syncMounts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "mounts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *mounts)
		result.TotalRows += mounts.Rows
	}

	// Sync audit devices
	auditDevices, err := v.syncAuditDevices(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "audit_devices: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *auditDevices)
		result.TotalRows += auditDevices.Rows
	}

	// Sync identity entities
	entities, err := v.syncEntities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "entities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *entities)
		result.TotalRows += entities.Rows
	}

	// Sync identity groups
	groups, err := v.syncGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "groups: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *groups)
		result.TotalRows += groups.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (v *VaultProvider) syncAuthMethods(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_auth_methods"}

	body, err := v.request(ctx, "/v1/sys/auth")
	if err != nil {
		return result, err
	}

	var resp struct {
		Data map[string]map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try alternate response format
		var altResp map[string]map[string]interface{}
		if err := json.Unmarshal(body, &altResp); err != nil {
			return result, fmt.Errorf("parse auth methods: %w", err)
		}
		resp.Data = altResp
	}

	result.Rows = int64(len(resp.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) syncPolicies(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_policies"}

	body, err := v.request(ctx, "/v1/sys/policies/acl")
	if err != nil {
		return result, err
	}

	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, err
	}

	result.Rows = int64(len(resp.Data.Keys))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) syncMounts(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_mounts"}

	body, err := v.request(ctx, "/v1/sys/mounts")
	if err != nil {
		return result, err
	}

	var resp struct {
		Data map[string]map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try alternate response format
		var altResp map[string]map[string]interface{}
		if err := json.Unmarshal(body, &altResp); err != nil {
			return result, fmt.Errorf("parse mounts: %w", err)
		}
		resp.Data = altResp
	}

	result.Rows = int64(len(resp.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) syncAuditDevices(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_audit_devices"}

	body, err := v.request(ctx, "/v1/sys/audit")
	if err != nil {
		return result, err
	}

	var resp struct {
		Data map[string]map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try alternate response format
		var altResp map[string]map[string]interface{}
		if err := json.Unmarshal(body, &altResp); err != nil {
			return result, fmt.Errorf("parse audit devices: %w", err)
		}
		resp.Data = altResp
	}

	result.Rows = int64(len(resp.Data))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) syncEntities(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_entities"}

	body, err := v.request(ctx, "/v1/identity/entity/id?list=true")
	if err != nil {
		// Identity may not be enabled
		return result, nil
	}

	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, nil
	}

	result.Rows = int64(len(resp.Data.Keys))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) syncGroups(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "vault_groups"}

	body, err := v.request(ctx, "/v1/identity/group/id?list=true")
	if err != nil {
		// Identity may not be enabled
		return result, nil
	}

	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, nil
	}

	result.Rows = int64(len(resp.Data.Keys))
	result.Inserted = result.Rows
	return result, nil
}

func (v *VaultProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := v.address + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", v.token)
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("vault API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// HasAuditEnabled checks if Vault has at least one audit device enabled
func (v *VaultProvider) HasAuditEnabled(auditDevices map[string]map[string]interface{}) bool {
	return len(auditDevices) > 0
}

// GetExpiredTokens returns token accessors that are expired or expiring soon
func (v *VaultProvider) GetExpiredTokens(tokens []map[string]interface{}, expiringInDays int) []map[string]interface{} {
	cutoff := time.Now().AddDate(0, 0, expiringInDays)
	var expiring []map[string]interface{}

	for _, token := range tokens {
		expireTime, ok := token["expire_time"].(string)
		if !ok || expireTime == "" {
			continue
		}

		t, err := time.Parse(time.RFC3339, expireTime)
		if err != nil {
			continue
		}

		if t.Before(cutoff) {
			expiring = append(expiring, token)
		}
	}

	return expiring
}
