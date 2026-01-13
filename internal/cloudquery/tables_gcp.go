package cloudquery

// GCP Table Schemas for Snowflake
// These match CloudQuery's official GCP source plugin table schemas
// Reference: https://hub.cloudquery.io/plugins/source/cloudquery/gcp

// GCP IAM Tables
var GCPIAMTables = map[string]TableDefinition{
	"gcp_iam_service_accounts": {
		Name:        "gcp_iam_service_accounts",
		Description: "GCP IAM Service Accounts",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "unique_id", Type: "VARCHAR"},
			{Name: "email", Type: "VARCHAR"},
			{Name: "display_name", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "disabled", Type: "BOOLEAN"},
			{Name: "oauth2_client_id", Type: "VARCHAR"},
		},
		Relations: []string{"gcp_iam_service_account_keys"},
	},
	"gcp_iam_service_account_keys": {
		Name:        "gcp_iam_service_account_keys",
		Description: "GCP IAM Service Account Keys",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "key_algorithm", Type: "VARCHAR"},
			{Name: "key_origin", Type: "VARCHAR"},
			{Name: "key_type", Type: "VARCHAR"},
			{Name: "valid_after_time", Type: "TIMESTAMP_NTZ"},
			{Name: "valid_before_time", Type: "TIMESTAMP_NTZ"},
			{Name: "disabled", Type: "BOOLEAN"},
		},
	},
	"gcp_iam_roles": {
		Name:        "gcp_iam_roles",
		Description: "GCP IAM Roles",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "title", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "included_permissions", Type: "VARIANT"},
			{Name: "stage", Type: "VARCHAR"},
			{Name: "deleted", Type: "BOOLEAN"},
		},
	},
}

// GCP Compute Tables
var GCPComputeTables = map[string]TableDefinition{
	"gcp_compute_instances": {
		Name:        "gcp_compute_instances",
		Description: "GCP Compute Engine Instances",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "NUMBER"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "zone", Type: "VARCHAR"},
			{Name: "machine_type", Type: "VARCHAR"},
			{Name: "status", Type: "VARCHAR"},
			{Name: "can_ip_forward", Type: "BOOLEAN"},
			{Name: "deletion_protection", Type: "BOOLEAN"},
			{Name: "shielded_instance_config", Type: "VARIANT"},
			{Name: "network_interfaces", Type: "VARIANT"},
			{Name: "service_accounts", Type: "VARIANT"},
			{Name: "metadata", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
			{Name: "labels", Type: "VARIANT"},
			{Name: "creation_timestamp", Type: "VARCHAR"},
		},
	},
	"gcp_compute_firewalls": {
		Name:        "gcp_compute_firewalls",
		Description: "GCP Compute Engine Firewall Rules",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "NUMBER"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "network", Type: "VARCHAR"},
			{Name: "direction", Type: "VARCHAR"},
			{Name: "priority", Type: "NUMBER"},
			{Name: "source_ranges", Type: "VARIANT"},
			{Name: "destination_ranges", Type: "VARIANT"},
			{Name: "source_tags", Type: "VARIANT"},
			{Name: "target_tags", Type: "VARIANT"},
			{Name: "allowed", Type: "VARIANT"},
			{Name: "denied", Type: "VARIANT"},
			{Name: "disabled", Type: "BOOLEAN"},
			{Name: "log_config", Type: "VARIANT"},
		},
	},
	"gcp_compute_networks": {
		Name:        "gcp_compute_networks",
		Description: "GCP VPC Networks",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "NUMBER"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "auto_create_subnetworks", Type: "BOOLEAN"},
			{Name: "routing_config", Type: "VARIANT"},
			{Name: "subnetworks", Type: "VARIANT"},
		},
	},
	"gcp_compute_disks": {
		Name:        "gcp_compute_disks",
		Description: "GCP Compute Engine Disks",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "NUMBER"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "zone", Type: "VARCHAR"},
			{Name: "type", Type: "VARCHAR"},
			{Name: "size_gb", Type: "NUMBER"},
			{Name: "status", Type: "VARCHAR"},
			{Name: "source_image", Type: "VARCHAR"},
			{Name: "disk_encryption_key", Type: "VARIANT"},
			{Name: "labels", Type: "VARIANT"},
		},
	},
}

// GCP Storage Tables
var GCPStorageTables = map[string]TableDefinition{
	"gcp_storage_buckets": {
		Name:        "gcp_storage_buckets",
		Description: "GCP Cloud Storage Buckets",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "location_type", Type: "VARCHAR"},
			{Name: "storage_class", Type: "VARCHAR"},
			{Name: "versioning", Type: "VARIANT"},
			{Name: "logging", Type: "VARIANT"},
			{Name: "encryption", Type: "VARIANT"},
			{Name: "iam_configuration", Type: "VARIANT"},
			{Name: "public_access_prevention", Type: "VARCHAR"},
			{Name: "labels", Type: "VARIANT"},
			{Name: "time_created", Type: "TIMESTAMP_NTZ"},
		},
	},
}

// GCP SQL Tables
var GCPSQLTables = map[string]TableDefinition{
	"gcp_sql_instances": {
		Name:        "gcp_sql_instances",
		Description: "GCP Cloud SQL Instances",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "database_version", Type: "VARCHAR"},
			{Name: "instance_type", Type: "VARCHAR"},
			{Name: "state", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "gce_zone", Type: "VARCHAR"},
			{Name: "ip_addresses", Type: "VARIANT"},
			{Name: "settings", Type: "VARIANT"},
			{Name: "server_ca_cert", Type: "VARIANT"},
			{Name: "backend_type", Type: "VARCHAR"},
		},
	},
}

// GCP BigQuery Tables
var GCPBigQueryTables = map[string]TableDefinition{
	"gcp_bigquery_datasets": {
		Name:        "gcp_bigquery_datasets",
		Description: "GCP BigQuery Datasets",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "self_link", Type: "VARCHAR"},
			{Name: "friendly_name", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "default_encryption_configuration", Type: "VARIANT"},
			{Name: "access", Type: "VARIANT"},
			{Name: "labels", Type: "VARIANT"},
			{Name: "creation_time", Type: "NUMBER"},
			{Name: "last_modified_time", Type: "NUMBER"},
		},
	},
}

// GCP KMS Tables
var GCPKMSTables = map[string]TableDefinition{
	"gcp_kms_crypto_keys": {
		Name:        "gcp_kms_crypto_keys",
		Description: "GCP Cloud KMS Crypto Keys",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "purpose", Type: "VARCHAR"},
			{Name: "create_time", Type: "TIMESTAMP_NTZ"},
			{Name: "rotation_period", Type: "VARCHAR"},
			{Name: "next_rotation_time", Type: "TIMESTAMP_NTZ"},
			{Name: "version_template", Type: "VARIANT"},
			{Name: "labels", Type: "VARIANT"},
			{Name: "primary", Type: "VARIANT"},
		},
	},
	"gcp_kms_keyrings": {
		Name:        "gcp_kms_keyrings",
		Description: "GCP Cloud KMS Key Rings",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "location", Type: "VARCHAR"},
			{Name: "create_time", Type: "TIMESTAMP_NTZ"},
		},
	},
}

// GCP Logging Tables
var GCPLoggingTables = map[string]TableDefinition{
	"gcp_logging_sinks": {
		Name:        "gcp_logging_sinks",
		Description: "GCP Cloud Logging Sinks",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "destination", Type: "VARCHAR"},
			{Name: "filter", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "disabled", Type: "BOOLEAN"},
			{Name: "output_version_format", Type: "VARCHAR"},
			{Name: "writer_identity", Type: "VARCHAR"},
			{Name: "create_time", Type: "TIMESTAMP_NTZ"},
			{Name: "update_time", Type: "TIMESTAMP_NTZ"},
		},
	},
	"gcp_logging_metrics": {
		Name:        "gcp_logging_metrics",
		Description: "GCP Cloud Logging Metrics",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "project_id", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "filter", Type: "VARCHAR"},
			{Name: "metric_descriptor", Type: "VARIANT"},
			{Name: "value_extractor", Type: "VARCHAR"},
			{Name: "label_extractors", Type: "VARIANT"},
			{Name: "create_time", Type: "TIMESTAMP_NTZ"},
			{Name: "update_time", Type: "TIMESTAMP_NTZ"},
		},
	},
}

// GetAllGCPTableDefinitions returns all GCP CloudQuery table definitions
func GetAllGCPTableDefinitions() map[string]TableDefinition {
	all := make(map[string]TableDefinition)

	for k, v := range GCPIAMTables {
		all[k] = v
	}
	for k, v := range GCPComputeTables {
		all[k] = v
	}
	for k, v := range GCPStorageTables {
		all[k] = v
	}
	for k, v := range GCPSQLTables {
		all[k] = v
	}
	for k, v := range GCPBigQueryTables {
		all[k] = v
	}
	for k, v := range GCPKMSTables {
		all[k] = v
	}
	for k, v := range GCPLoggingTables {
		all[k] = v
	}

	return all
}
