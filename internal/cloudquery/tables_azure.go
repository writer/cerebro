package cloudquery

// Azure Table Schemas for Snowflake
// These match CloudQuery's official Azure source plugin table schemas
// Reference: https://hub.cloudquery.io/plugins/source/cloudquery/azure

// Azure Compute Tables
var AzureComputeTables = map[string]TableDefinition{
	"azure_compute_virtual_machines": {
		Name:        "azure_compute_virtual_machines",
		Description: "Azure Virtual Machines",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "vm_id", Type: "VARCHAR"},
			{Name: "hardware_profile", Type: "VARIANT"},
			{Name: "storage_profile", Type: "VARIANT"},
			{Name: "os_profile", Type: "VARIANT"},
			{Name: "network_profile", Type: "VARIANT"},
			{Name: "diagnostics_profile", Type: "VARIANT"},
			{Name: "security_profile", Type: "VARIANT"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"azure_compute_disks": {
		Name:        "azure_compute_disks",
		Description: "Azure Managed Disks",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "sku", Type: "VARIANT"},
			{Name: "disk_size_gb", Type: "NUMBER"},
			{Name: "disk_state", Type: "VARCHAR"},
			{Name: "encryption", Type: "VARIANT"},
			{Name: "encryption_settings_collection", Type: "VARIANT"},
			{Name: "network_access_policy", Type: "VARCHAR"},
			{Name: "os_type", Type: "VARCHAR"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// Azure Network Tables
var AzureNetworkTables = map[string]TableDefinition{
	"azure_network_security_groups": {
		Name:        "azure_network_security_groups",
		Description: "Azure Network Security Groups",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "security_rules", Type: "VARIANT"},
			{Name: "default_security_rules", Type: "VARIANT"},
			{Name: "network_interfaces", Type: "VARIANT"},
			{Name: "subnets", Type: "VARIANT"},
			{Name: "flow_logs", Type: "VARIANT"},
			{Name: "resource_guid", Type: "VARCHAR"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"azure_network_virtual_networks": {
		Name:        "azure_network_virtual_networks",
		Description: "Azure Virtual Networks",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "address_space", Type: "VARIANT"},
			{Name: "dhcp_options", Type: "VARIANT"},
			{Name: "subnets", Type: "VARIANT"},
			{Name: "virtual_network_peerings", Type: "VARIANT"},
			{Name: "enable_ddos_protection", Type: "BOOLEAN"},
			{Name: "enable_vm_protection", Type: "BOOLEAN"},
			{Name: "flow_timeout_in_minutes", Type: "NUMBER"},
			{Name: "resource_guid", Type: "VARCHAR"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// Azure Storage Tables
var AzureStorageTables = map[string]TableDefinition{
	"azure_storage_accounts": {
		Name:        "azure_storage_accounts",
		Description: "Azure Storage Accounts",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "sku", Type: "VARIANT"},
			{Name: "kind", Type: "VARCHAR"},
			{Name: "access_tier", Type: "VARCHAR"},
			{Name: "allow_blob_public_access", Type: "BOOLEAN"},
			{Name: "enable_https_traffic_only", Type: "BOOLEAN"},
			{Name: "encryption", Type: "VARIANT"},
			{Name: "network_rule_set", Type: "VARIANT"},
			{Name: "minimum_tls_version", Type: "VARCHAR"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
		Relations: []string{"azure_storage_containers"},
	},
	"azure_storage_containers": {
		Name:        "azure_storage_containers",
		Description: "Azure Storage Blob Containers",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "public_access", Type: "VARCHAR"},
			{Name: "has_immutability_policy", Type: "BOOLEAN"},
			{Name: "has_legal_hold", Type: "BOOLEAN"},
			{Name: "deleted", Type: "BOOLEAN"},
			{Name: "version", Type: "VARCHAR"},
		},
	},
}

// Azure SQL Tables
var AzureSQLTables = map[string]TableDefinition{
	"azure_sql_servers": {
		Name:        "azure_sql_servers",
		Description: "Azure SQL Servers",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "kind", Type: "VARCHAR"},
			{Name: "administrator_login", Type: "VARCHAR"},
			{Name: "version", Type: "VARCHAR"},
			{Name: "state", Type: "VARCHAR"},
			{Name: "fully_qualified_domain_name", Type: "VARCHAR"},
			{Name: "minimal_tls_version", Type: "VARCHAR"},
			{Name: "public_network_access", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
		Relations: []string{"azure_sql_databases"},
	},
	"azure_sql_databases": {
		Name:        "azure_sql_databases",
		Description: "Azure SQL Databases",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "sku", Type: "VARIANT"},
			{Name: "kind", Type: "VARCHAR"},
			{Name: "collation", Type: "VARCHAR"},
			{Name: "status", Type: "VARCHAR"},
			{Name: "current_service_objective_name", Type: "VARCHAR"},
			{Name: "zone_redundant", Type: "BOOLEAN"},
			{Name: "transparent_data_encryption", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// Azure Key Vault Tables
var AzureKeyVaultTables = map[string]TableDefinition{
	"azure_keyvault_vaults": {
		Name:        "azure_keyvault_vaults",
		Description: "Azure Key Vaults",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "vault_uri", Type: "VARCHAR"},
			{Name: "tenant_id", Type: "VARCHAR"},
			{Name: "sku", Type: "VARIANT"},
			{Name: "access_policies", Type: "VARIANT"},
			{Name: "enable_rbac_authorization", Type: "BOOLEAN"},
			{Name: "enable_soft_delete", Type: "BOOLEAN"},
			{Name: "soft_delete_retention_in_days", Type: "NUMBER"},
			{Name: "enable_purge_protection", Type: "BOOLEAN"},
			{Name: "network_acls", Type: "VARIANT"},
			{Name: "provisioning_state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"azure_keyvault_keys": {
		Name:        "azure_keyvault_keys",
		Description: "Azure Key Vault Keys",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "vault_url", Type: "VARCHAR"},
			{Name: "kid", Type: "VARCHAR"},
			{Name: "attributes", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
			{Name: "managed", Type: "BOOLEAN"},
		},
	},
}

// Azure Monitor Tables
var AzureMonitorTables = map[string]TableDefinition{
	"azure_monitor_activity_log_alerts": {
		Name:        "azure_monitor_activity_log_alerts",
		Description: "Azure Monitor Activity Log Alerts",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "scopes", Type: "VARIANT"},
			{Name: "condition", Type: "VARIANT"},
			{Name: "actions", Type: "VARIANT"},
			{Name: "enabled", Type: "BOOLEAN"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"azure_monitor_diagnostic_settings": {
		Name:        "azure_monitor_diagnostic_settings",
		Description: "Azure Monitor Diagnostic Settings",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "storage_account_id", Type: "VARCHAR"},
			{Name: "event_hub_authorization_rule_id", Type: "VARCHAR"},
			{Name: "event_hub_name", Type: "VARCHAR"},
			{Name: "workspace_id", Type: "VARCHAR"},
			{Name: "logs", Type: "VARIANT"},
			{Name: "metrics", Type: "VARIANT"},
		},
	},
}

// Azure Security Tables
var AzureSecurityTables = map[string]TableDefinition{
	"azure_security_assessments": {
		Name:        "azure_security_assessments",
		Description: "Azure Security Center Assessments",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "display_name", Type: "VARCHAR"},
			{Name: "status", Type: "VARIANT"},
			{Name: "resource_details", Type: "VARIANT"},
			{Name: "additional_data", Type: "VARIANT"},
		},
	},
	"azure_security_pricings": {
		Name:        "azure_security_pricings",
		Description: "Azure Defender Pricing Plans",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "subscription_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "pricing_tier", Type: "VARCHAR"},
			{Name: "free_trial_remaining_time", Type: "VARCHAR"},
		},
	},
}

// GetAllAzureTableDefinitions returns all Azure CloudQuery table definitions
func GetAllAzureTableDefinitions() map[string]TableDefinition {
	all := make(map[string]TableDefinition)

	for k, v := range AzureComputeTables {
		all[k] = v
	}
	for k, v := range AzureNetworkTables {
		all[k] = v
	}
	for k, v := range AzureStorageTables {
		all[k] = v
	}
	for k, v := range AzureSQLTables {
		all[k] = v
	}
	for k, v := range AzureKeyVaultTables {
		all[k] = v
	}
	for k, v := range AzureMonitorTables {
		all[k] = v
	}
	for k, v := range AzureSecurityTables {
		all[k] = v
	}

	return all
}
