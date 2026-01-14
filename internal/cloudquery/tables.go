package cloudquery

// CloudQuery Table Schemas for Snowflake
// These match CloudQuery's official AWS source plugin table schemas
// Reference: https://hub.cloudquery.io/plugins/source/cloudquery/aws

// TableDefinition represents a CloudQuery table schema
type TableDefinition struct {
	Name        string
	Description string
	Columns     []Column
	Relations   []string
}

// Column represents a column in a CloudQuery table
type Column struct {
	Name        string
	Type        string // VARCHAR, NUMBER, BOOLEAN, TIMESTAMP_NTZ, VARIANT
	Description string
	PrimaryKey  bool
}

// AWS IAM Tables
var AWSIAMTables = map[string]TableDefinition{
	"aws_iam_accounts": {
		Name:        "aws_iam_accounts",
		Description: "AWS IAM Account summary",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "users", Type: "NUMBER"},
			{Name: "groups", Type: "NUMBER"},
			{Name: "roles", Type: "NUMBER"},
			{Name: "policies", Type: "NUMBER"},
		},
	},
	"aws_iam_credential_reports": {
		Name:        "aws_iam_credential_reports",
		Description: "AWS IAM credential report entries",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "user", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "user_creation_time", Type: "TIMESTAMP_NTZ"},
			{Name: "password_enabled", Type: "BOOLEAN"},
			{Name: "password_last_used", Type: "TIMESTAMP_NTZ"},
			{Name: "password_last_changed", Type: "TIMESTAMP_NTZ"},
			{Name: "password_next_rotation", Type: "TIMESTAMP_NTZ"},
			{Name: "mfa_active", Type: "BOOLEAN"},
			{Name: "access_key_1_active", Type: "BOOLEAN"},
			{Name: "access_key_1_last_rotated", Type: "TIMESTAMP_NTZ"},
			{Name: "access_key_1_last_used_date", Type: "TIMESTAMP_NTZ"},
			{Name: "access_key_1_last_used_region", Type: "VARCHAR"},
			{Name: "access_key_1_last_used_service", Type: "VARCHAR"},
			{Name: "access_key_2_active", Type: "BOOLEAN"},
			{Name: "access_key_2_last_rotated", Type: "TIMESTAMP_NTZ"},
			{Name: "access_key_2_last_used_date", Type: "TIMESTAMP_NTZ"},
			{Name: "access_key_2_last_used_region", Type: "VARCHAR"},
			{Name: "access_key_2_last_used_service", Type: "VARCHAR"},
			{Name: "cert_1_active", Type: "BOOLEAN"},
			{Name: "cert_1_last_rotated", Type: "TIMESTAMP_NTZ"},
			{Name: "cert_2_active", Type: "BOOLEAN"},
			{Name: "cert_2_last_rotated", Type: "TIMESTAMP_NTZ"},
			{Name: "account_access_keys_present", Type: "NUMBER"},
			{Name: "account_mfa_active", Type: "BOOLEAN"},
		},
	},
	"aws_iam_policies": {
		Name:        "aws_iam_policies",
		Description: "AWS IAM policies",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "path", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "document", Type: "VARIANT"},
			{Name: "attachment_count", Type: "NUMBER"},
			{Name: "is_attachable", Type: "BOOLEAN"},
			{Name: "create_date", Type: "TIMESTAMP_NTZ"},
			{Name: "update_date", Type: "TIMESTAMP_NTZ"},
			{Name: "default_version_id", Type: "VARCHAR"},
		},
		Relations: []string{"aws_iam_policy_default_versions"},
	},
	"aws_iam_policy_default_versions": {
		Name:        "aws_iam_policy_default_versions",
		Description: "AWS IAM policy default versions with document",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "document", Type: "VARCHAR"},
			{Name: "document_json", Type: "VARIANT"},
			{Name: "is_default_version", Type: "BOOLEAN"},
			{Name: "version_id", Type: "VARCHAR"},
		},
	},
	"aws_iam_users": {
		Name:        "aws_iam_users",
		Description: "AWS IAM users",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "user_id", Type: "VARCHAR"},
			{Name: "user_name", Type: "VARCHAR"},
			{Name: "path", Type: "VARCHAR"},
			{Name: "create_date", Type: "TIMESTAMP_NTZ"},
			{Name: "password_last_used", Type: "TIMESTAMP_NTZ"},
			{Name: "permissions_boundary", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"aws_iam_roles": {
		Name:        "aws_iam_roles",
		Description: "AWS IAM roles",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "role_id", Type: "VARCHAR"},
			{Name: "role_name", Type: "VARCHAR"},
			{Name: "path", Type: "VARCHAR"},
			{Name: "assume_role_policy_document", Type: "VARIANT"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "create_date", Type: "TIMESTAMP_NTZ"},
			{Name: "max_session_duration", Type: "NUMBER"},
			{Name: "permissions_boundary", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"aws_iam_user_attached_policies": {
		Name:        "aws_iam_user_attached_policies",
		Description: "AWS IAM policies attached to users",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "user_arn", Type: "VARCHAR"},
			{Name: "policy_arn", Type: "VARCHAR"},
			{Name: "policy_name", Type: "VARCHAR"},
		},
	},
	"aws_iam_role_attached_policies": {
		Name:        "aws_iam_role_attached_policies",
		Description: "AWS IAM policies attached to roles",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "role_arn", Type: "VARCHAR"},
			{Name: "policy_arn", Type: "VARCHAR"},
			{Name: "policy_name", Type: "VARCHAR"},
		},
	},
	"aws_iam_user_policies": {
		Name:        "aws_iam_user_policies",
		Description: "AWS IAM inline policies for users",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "user_arn", Type: "VARCHAR"},
			{Name: "user_name", Type: "VARCHAR"},
			{Name: "policy_name", Type: "VARCHAR"},
			{Name: "policy_document", Type: "VARIANT"},
		},
	},
	"aws_iam_role_policies": {
		Name:        "aws_iam_role_policies",
		Description: "AWS IAM inline policies for roles",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "role_arn", Type: "VARCHAR"},
			{Name: "role_name", Type: "VARCHAR"},
			{Name: "policy_name", Type: "VARCHAR"},
			{Name: "policy_document", Type: "VARIANT"},
		},
	},
	"aws_iam_groups": {
		Name:        "aws_iam_groups",
		Description: "AWS IAM groups",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "group_id", Type: "VARCHAR"},
			{Name: "group_name", Type: "VARCHAR"},
			{Name: "path", Type: "VARCHAR"},
			{Name: "create_date", Type: "TIMESTAMP_NTZ"},
		},
	},
	"aws_iam_group_policies": {
		Name:        "aws_iam_group_policies",
		Description: "AWS IAM inline policies for groups",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "group_arn", Type: "VARCHAR"},
			{Name: "group_name", Type: "VARCHAR"},
			{Name: "policy_name", Type: "VARCHAR"},
			{Name: "policy_document", Type: "VARIANT"},
		},
	},
	"aws_iam_user_groups": {
		Name:        "aws_iam_user_groups",
		Description: "AWS IAM user group memberships",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "user_arn", Type: "VARCHAR"},
			{Name: "group_arn", Type: "VARCHAR"},
			{Name: "group_name", Type: "VARCHAR"},
		},
	},
}

// AWS S3 Tables
var AWSS3Tables = map[string]TableDefinition{
	"aws_s3_buckets": {
		Name:        "aws_s3_buckets",
		Description: "AWS S3 buckets",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "creation_date", Type: "TIMESTAMP_NTZ"},
			{Name: "versioning_status", Type: "VARCHAR"},
			{Name: "versioning_mfa_delete", Type: "VARCHAR"},
			{Name: "logging_target_bucket", Type: "VARCHAR"},
			{Name: "logging_target_prefix", Type: "VARCHAR"},
			{Name: "block_public_acls", Type: "BOOLEAN"},
			{Name: "block_public_policy", Type: "BOOLEAN"},
			{Name: "ignore_public_acls", Type: "BOOLEAN"},
			{Name: "restrict_public_buckets", Type: "BOOLEAN"},
			{Name: "tags", Type: "VARIANT"},
		},
		Relations: []string{"aws_s3_bucket_policies", "aws_s3_bucket_encryption_rules"},
	},
	"aws_s3_bucket_policies": {
		Name:        "aws_s3_bucket_policies",
		Description: "AWS S3 bucket policies",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "policy", Type: "VARIANT"},
		},
	},
	"aws_s3_accounts": {
		Name:        "aws_s3_accounts",
		Description: "AWS S3 account-level public access settings",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "config_exists", Type: "BOOLEAN"},
			{Name: "block_public_acls", Type: "BOOLEAN"},
			{Name: "block_public_policy", Type: "BOOLEAN"},
			{Name: "ignore_public_acls", Type: "BOOLEAN"},
			{Name: "restrict_public_buckets", Type: "BOOLEAN"},
		},
	},
}

// AWS EC2 Tables
var AWSEC2Tables = map[string]TableDefinition{
	"aws_ec2_instances": {
		Name:        "aws_ec2_instances",
		Description: "AWS EC2 instances",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "instance_id", Type: "VARCHAR"},
			{Name: "instance_type", Type: "VARCHAR"},
			{Name: "image_id", Type: "VARCHAR"},
			{Name: "state", Type: "VARIANT"},
			{Name: "public_ip_address", Type: "VARCHAR"},
			{Name: "private_ip_address", Type: "VARCHAR"},
			{Name: "vpc_id", Type: "VARCHAR"},
			{Name: "subnet_id", Type: "VARCHAR"},
			{Name: "security_groups", Type: "VARIANT"},
			{Name: "iam_instance_profile", Type: "VARIANT"},
			{Name: "metadata_options", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
			{Name: "launch_time", Type: "TIMESTAMP_NTZ"},
		},
	},
	"aws_ec2_security_groups": {
		Name:        "aws_ec2_security_groups",
		Description: "AWS EC2 security groups",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "group_id", Type: "VARCHAR"},
			{Name: "group_name", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "vpc_id", Type: "VARCHAR"},
			{Name: "owner_id", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
		Relations: []string{"aws_ec2_security_group_ip_permissions"},
	},
	"aws_ec2_security_group_ip_permissions": {
		Name:        "aws_ec2_security_group_ip_permissions",
		Description: "AWS EC2 security group ingress rules",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "ip_protocol", Type: "VARCHAR"},
			{Name: "from_port", Type: "NUMBER"},
			{Name: "to_port", Type: "NUMBER"},
		},
		Relations: []string{"aws_ec2_security_group_ip_ranges"},
	},
	"aws_ec2_security_group_ip_ranges": {
		Name:        "aws_ec2_security_group_ip_ranges",
		Description: "AWS EC2 security group IP ranges",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "_cq_parent_id", Type: "VARCHAR"},
			{Name: "cidr_ip", Type: "VARCHAR"},
			{Name: "description", Type: "VARCHAR"},
		},
	},
	"aws_ec2_vpcs": {
		Name:        "aws_ec2_vpcs",
		Description: "AWS EC2 VPCs",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "id", Type: "VARCHAR"},
			{Name: "cidr_block", Type: "VARCHAR"},
			{Name: "is_default", Type: "BOOLEAN"},
			{Name: "state", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"aws_ec2_flow_logs": {
		Name:        "aws_ec2_flow_logs",
		Description: "AWS EC2 VPC flow logs",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "flow_log_id", Type: "VARCHAR"},
			{Name: "resource_id", Type: "VARCHAR"},
			{Name: "traffic_type", Type: "VARCHAR"},
			{Name: "log_destination_type", Type: "VARCHAR"},
			{Name: "log_destination", Type: "VARCHAR"},
			{Name: "log_group_name", Type: "VARCHAR"},
			{Name: "creation_time", Type: "TIMESTAMP_NTZ"},
		},
	},
	"aws_ec2_ebs_volumes": {
		Name:        "aws_ec2_ebs_volumes",
		Description: "AWS EC2 EBS volumes",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "volume_id", Type: "VARCHAR"},
			{Name: "volume_type", Type: "VARCHAR"},
			{Name: "size", Type: "NUMBER"},
			{Name: "encrypted", Type: "BOOLEAN"},
			{Name: "kms_key_id", Type: "VARCHAR"},
			{Name: "state", Type: "VARCHAR"},
			{Name: "availability_zone", Type: "VARCHAR"},
			{Name: "create_time", Type: "TIMESTAMP_NTZ"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// AWS RDS Tables
var AWSRDSTables = map[string]TableDefinition{
	"aws_rds_instances": {
		Name:        "aws_rds_instances",
		Description: "AWS RDS database instances",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "db_instance_identifier", Type: "VARCHAR"},
			{Name: "db_instance_class", Type: "VARCHAR"},
			{Name: "engine", Type: "VARCHAR"},
			{Name: "engine_version", Type: "VARCHAR"},
			{Name: "publicly_accessible", Type: "BOOLEAN"},
			{Name: "storage_encrypted", Type: "BOOLEAN"},
			{Name: "kms_key_id", Type: "VARCHAR"},
			{Name: "multi_az", Type: "BOOLEAN"},
			{Name: "deletion_protection", Type: "BOOLEAN"},
			{Name: "db_instance_status", Type: "VARCHAR"},
			{Name: "endpoint", Type: "VARIANT"},
			{Name: "vpc_security_groups", Type: "VARIANT"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
	"aws_rds_clusters": {
		Name:        "aws_rds_clusters",
		Description: "AWS RDS clusters",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "db_cluster_identifier", Type: "VARCHAR"},
			{Name: "engine", Type: "VARCHAR"},
			{Name: "storage_encrypted", Type: "BOOLEAN"},
			{Name: "deletion_protection", Type: "BOOLEAN"},
			{Name: "status", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// AWS CloudTrail Tables
var AWSCloudTrailTables = map[string]TableDefinition{
	"aws_cloudtrail_trails": {
		Name:        "aws_cloudtrail_trails",
		Description: "AWS CloudTrail trails",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "name", Type: "VARCHAR"},
			{Name: "s3_bucket_name", Type: "VARCHAR"},
			{Name: "is_multi_region_trail", Type: "BOOLEAN"},
			{Name: "is_organization_trail", Type: "BOOLEAN"},
			{Name: "include_global_service_events", Type: "BOOLEAN"},
			{Name: "is_logging", Type: "BOOLEAN"},
			{Name: "log_file_validation_enabled", Type: "BOOLEAN"},
			{Name: "kms_key_id", Type: "VARCHAR"},
			{Name: "cloud_watch_logs_log_group_arn", Type: "VARCHAR"},
			{Name: "status", Type: "VARIANT"},
		},
	},
}

// AWS KMS Tables
var AWSKMSTables = map[string]TableDefinition{
	"aws_kms_keys": {
		Name:        "aws_kms_keys",
		Description: "AWS KMS keys",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "key_id", Type: "VARCHAR"},
			{Name: "key_state", Type: "VARCHAR"},
			{Name: "key_usage", Type: "VARCHAR"},
			{Name: "key_manager", Type: "VARCHAR"},
			{Name: "key_rotation_enabled", Type: "BOOLEAN"},
			{Name: "creation_date", Type: "TIMESTAMP_NTZ"},
			{Name: "description", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// AWS Lambda Tables
var AWSLambdaTables = map[string]TableDefinition{
	"aws_lambda_functions": {
		Name:        "aws_lambda_functions",
		Description: "AWS Lambda functions",
		Columns: []Column{
			{Name: "_cq_id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "account_id", Type: "VARCHAR"},
			{Name: "region", Type: "VARCHAR"},
			{Name: "arn", Type: "VARCHAR"},
			{Name: "function_name", Type: "VARCHAR"},
			{Name: "runtime", Type: "VARCHAR"},
			{Name: "role", Type: "VARCHAR"},
			{Name: "handler", Type: "VARCHAR"},
			{Name: "code_size", Type: "NUMBER"},
			{Name: "memory_size", Type: "NUMBER"},
			{Name: "timeout", Type: "NUMBER"},
			{Name: "environment", Type: "VARIANT"},
			{Name: "vpc_config", Type: "VARIANT"},
			{Name: "last_modified", Type: "VARCHAR"},
			{Name: "tags", Type: "VARIANT"},
		},
	},
}

// GetAllTableDefinitions returns all CloudQuery table definitions
func GetAllTableDefinitions() map[string]TableDefinition {
	all := make(map[string]TableDefinition)

	for k, v := range AWSIAMTables {
		all[k] = v
	}
	for k, v := range AWSS3Tables {
		all[k] = v
	}
	for k, v := range AWSEC2Tables {
		all[k] = v
	}
	for k, v := range AWSRDSTables {
		all[k] = v
	}
	for k, v := range AWSCloudTrailTables {
		all[k] = v
	}
	for k, v := range AWSKMSTables {
		all[k] = v
	}
	for k, v := range AWSLambdaTables {
		all[k] = v
	}

	return all
}

// GenerateCreateTableSQL generates Snowflake CREATE TABLE statement
func GenerateCreateTableSQL(table TableDefinition) string {
	cols := make([]string, 0, len(table.Columns)+1) // +1 for _cq_sync_time
	var pks []string

	for _, col := range table.Columns {
		colDef := col.Name + " " + col.Type
		cols = append(cols, colDef)
		if col.PrimaryKey {
			pks = append(pks, col.Name)
		}
	}

	// Add standard CloudQuery columns
	cols = append(cols, "_cq_sync_time TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()")

	sql := "CREATE TABLE IF NOT EXISTS " + table.Name + " (\n  "
	sql += joinStrings(cols, ",\n  ")
	if len(pks) > 0 {
		sql += ",\n  PRIMARY KEY (" + joinStrings(pks, ", ") + ")"
	}
	sql += "\n)"

	return sql
}

func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// GetAllTables returns all table definitions as a slice
func GetAllTables() []TableDefinition {
	all := GetAllTableDefinitions()
	tables := make([]TableDefinition, 0, len(all))
	for _, t := range all {
		tables = append(tables, t)
	}
	return tables
}

// GetTableByName returns a table definition by name
func GetTableByName(name string) (TableDefinition, bool) {
	all := GetAllTableDefinitions()
	t, ok := all[name]
	return t, ok
}
