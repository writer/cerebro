package policy

import (
	"strings"
)

// ResourceToTableMapping maps Cedar resource types to asset table names
// This enables validation that required tables exist before policy evaluation
var ResourceToTableMapping = map[string][]string{
	// S3
	"aws::s3::bucket":              {"aws_s3_buckets"},
	"aws::s3::bucket_policy":       {"aws_s3_bucket_policies"},
	"aws::s3::bucket_acl":          {"aws_s3_bucket_grants"},
	"aws::s3::bucket_encryption":   {"aws_s3_bucket_encryption_rules"},
	"aws::s3::bucket_versioning":   {"aws_s3_bucket_versionings"},
	"aws::s3::bucket_logging":      {"aws_s3_bucket_loggings"},
	"aws::s3::public_access_block": {"aws_s3_bucket_public_access_blocks"},
	"aws::s3::object":              {"aws_s3_objects"},

	// EC2 - Compute
	"aws::ec2::instance":       {"aws_ec2_instances"},
	"aws::ec2::security_group": {"aws_ec2_security_groups"},
	"aws::ec2::vpc":            {"aws_ec2_vpcs"},
	"aws::ec2::ebs_volume":     {"aws_ec2_ebs_volumes"},
	"aws::ec2::ebs_snapshot":   {"aws_ec2_ebs_snapshots"},
	"aws::ec2::ami":            {"aws_ec2_images"},
	"aws::ec2::image":          {"aws_ec2_images"},
	"aws::ec2::flow_log":       {"aws_ec2_flow_logs"},

	// EC2 - Network
	"aws::ec2::eip":                    {"aws_ec2_eips"},
	"aws::ec2::key_pair":               {"aws_ec2_key_pairs"},
	"aws::ec2::launch_template":        {"aws_ec2_launch_templates"},
	"aws::ec2::network_interface":      {"aws_ec2_network_interfaces"},
	"aws::ec2::vpc_endpoint":           {"aws_ec2_vpc_endpoints"},
	"aws::ec2::vpc_peering_connection": {"aws_ec2_vpc_peering_connections"},
	"aws::ec2::transit_gateway":        {"aws_ec2_transit_gateways"},
	"aws::ec2::customer_gateway":       {"aws_ec2_customer_gateways"},
	"aws::ec2::vpn_gateway":            {"aws_ec2_vpn_gateways"},
	"aws::ec2::vpn_connection":         {"aws_ec2_vpn_connections"},
	"aws::ec2::reserved_instance":      {"aws_ec2_reserved_instances"},
	"aws::ec2::capacity_reservation":   {"aws_ec2_capacity_reservations"},
	"aws::ec2::spot_instance_request":  {"aws_ec2_spot_instance_requests"},

	// IAM - Core
	"aws::iam::user":            {"aws_iam_users", "aws_iam_credential_reports"},
	"aws::iam::role":            {"aws_iam_roles"},
	"aws::iam::policy":          {"aws_iam_policies"},
	"aws::iam::group":           {"aws_iam_groups"},
	"aws::iam::account":         {"aws_iam_accounts"},
	"aws::iam::password_policy": {"aws_iam_password_policies"},

	// IAM - Extended
	"aws::iam::access_key":                {"aws_iam_user_access_keys"},
	"aws::iam::account_password_policy":   {"aws_iam_password_policies"},
	"aws_iam_account_password_policy":     {"aws_iam_password_policies"},
	"aws::iam::account_summary":           {"aws_iam_accounts"},
	"aws::iam::credential_report":         {"aws_iam_credential_reports"},
	"aws::iam::saml_provider":             {"aws_iam_saml_identity_providers"},
	"aws::iam::oidc_provider":             {"aws_iam_openid_connect_identity_providers"},
	"aws::iam::instance_profile":          {"aws_iam_instance_profiles"},
	"aws::iam::server_certificate":        {"aws_iam_server_certificates"},
	"aws::iam::mfa_device":                {"aws_iam_mfa_devices"},
	"aws::iam::role_policy":               {"aws_iam_role_policies"},
	"aws::iam::user_policy":               {"aws_iam_user_policies"},
	"aws::iam::group_policy":              {"aws_iam_group_policies"},
	"aws::identitycenter::permission_set": {"aws_identitycenter_permission_set_permission_usage"},

	// Lambda
	"aws::lambda::function": {"aws_lambda_functions"},

	// ELB
	"aws::elbv2::load_balancer": {"aws_elbv2_load_balancers"},
	"aws::elbv2::target_group":  {"aws_elbv2_target_groups"},
	"aws::elbv2::listener":      {"aws_lb_listeners"},

	// KMS
	"aws::kms::key": {"aws_kms_keys"},

	// CloudTrail
	"aws::cloudtrail::trail": {"aws_cloudtrail_trails"},

	// CloudWatch
	"aws::cloudwatch::alarm":     {"aws_cloudwatch_alarms"},
	"aws::cloudwatch::log_group": {"aws_cloudwatch_log_groups"},

	// Config
	"aws::config::recorder":               {"aws_config_configuration_recorders"},
	"aws::config::configuration_recorder": {"aws_config_configuration_recorders"},
	"aws::config::rule":                   {"aws_config_rules"},
	"aws::config::delivery_channel":       {"aws_config_delivery_channels"},
	"aws::config::conformance_pack":       {"aws_config_conformance_packs"},

	// GuardDuty
	"aws::guardduty::detector": {"aws_guardduty_detectors"},
	"aws::guardduty::finding":  {"aws_guardduty_findings"},

	// SecurityHub
	"aws::securityhub::hub":      {"aws_securityhub_hubs"},
	"aws::securityhub::finding":  {"aws_securityhub_findings"},
	"aws::securityhub::standard": {"aws_securityhub_standards"},

	// EKS
	"aws::eks::cluster":         {"aws_eks_clusters"},
	"aws::eks::nodegroup":       {"aws_eks_node_groups"},
	"aws::eks::fargate_profile": {"aws_eks_fargate_profiles"},

	// SageMaker
	"aws::sagemaker::notebook":            {"aws_sagemaker_notebook_instances"},
	"aws::sagemaker::model":               {"aws_sagemaker_models"},
	"aws::sagemaker::endpoint":            {"aws_sagemaker_endpoints"},
	"aws::sagemaker::model_package_group": {"aws_sagemaker_model_package_groups"},

	// VPC / Networking
	"aws::ec2::nacl":             {"aws_ec2_network_acls"},
	"aws::ec2::network_acl":      {"aws_ec2_network_acls"},
	"aws::ec2::subnet":           {"aws_ec2_subnets"},
	"aws::ec2::route_table":      {"aws_ec2_route_tables"},
	"aws::ec2::internet_gateway": {"aws_ec2_internet_gateways"},
	"aws::ec2::nat_gateway":      {"aws_ec2_nat_gateways"},

	// ECR
	"aws::ecr::repository":        {"aws_ecr_repositories"},
	"aws::ecr_public::repository": {"aws_ecr_public_repositories"},

	// API Gateway
	"aws::apigateway::rest_api": {"aws_apigateway_rest_apis"},
	"aws::apigateway::stage":    {"aws_apigateway_stages"},
	"aws::apigateway::method":   {"aws_apigateway_rest_api_methods"},
	"aws::apigatewayv2::api":    {"aws_apigatewayv2_apis"},

	// AppSync
	"aws::appsync::graphql_api": {"aws_appsync_graphql_apis"},

	// EFS
	"aws::efs::file_system":  {"aws_efs_file_systems"},
	"aws::efs::mount_target": {"aws_efs_mount_targets"},

	// Bedrock
	"aws::bedrock::custom_model":                 {"aws_bedrock_custom_models"},
	"aws::bedrock::provisioned_model_throughput": {"aws_bedrock_provisioned_model_throughputs"},

	// CloudFront
	"aws::cloudfront::distribution": {"aws_cloudfront_distributions"},

	// CodeBuild
	"aws::codebuild::project":           {"aws_codebuild_projects"},
	"aws::codebuild::source_credential": {"aws_codebuild_source_credentials"},

	// RDS (consolidated)
	"aws::rds::instance":    {"aws_rds_instances"},
	"aws::rds::db_instance": {"aws_rds_instances"},
	"aws::rds::cluster":     {"aws_rds_db_clusters"},
	"aws::rds::db_snapshot": {"aws_rds_db_snapshots"},
	"aws::rds::db_cluster":  {"aws_rds_db_clusters"},

	// EBS
	"aws::ec2::ebs_encryption_by_default": {"aws_ec2_regional_configs"},

	// CloudWatch Logs
	"aws::logs::log_group": {"aws_cloudwatch_log_groups"},

	// WAF
	"aws::wafv2::web_acl":           {"aws_wafv2_web_acls"},
	"aws::wafv2::ip_set":            {"aws_wafv2_ipsets"},
	"aws::wafv2::rule_group":        {"aws_wafv2_rule_groups"},
	"aws::wafv2::regex_pattern_set": {"aws_wafv2_regex_pattern_sets"},

	// Secrets Manager
	"aws::secretsmanager::secret": {"aws_secretsmanager_secrets"},

	// SNS/SQS
	"aws::sns::topic": {"aws_sns_topics"},
	"aws::sqs::queue": {"aws_sqs_queues"},

	// DynamoDB
	"aws::dynamodb::table": {"aws_dynamodb_tables"},

	// Redshift
	"aws::redshift::cluster": {"aws_redshift_clusters"},

	// ElastiCache
	"aws::elasticache::cluster": {"aws_elasticache_clusters"},

	// OpenSearch
	"aws::opensearch::domain": {"aws_opensearch_domains"},

	// ECS
	"aws::ecs::cluster":         {"aws_ecs_clusters"},
	"aws::ecs::task_definition": {"aws_ecs_task_definitions"},

	// ACM (Certificates)
	"aws::acm::certificate": {"aws_acm_certificates"},

	// Route53
	"aws::route53::hosted_zone":  {"aws_route53_hosted_zones"},
	"aws::route53::record_set":   {"aws_route53_record_sets"},
	"aws::route53::health_check": {"aws_route53_health_checks"},

	// SSM (Systems Manager)
	"aws::ssm::parameter":        {"aws_ssm_parameters"},
	"aws::ssm::managed_instance": {"aws_ssm_managed_instances"},
	"aws::ssm::patch_compliance": {"aws_ssm_patch_compliance"},
	"aws::ssm::document":         {"aws_ssm_documents"},

	// Inspector
	"aws::inspector2::finding":  {"aws_inspector2_findings"},
	"aws::inspector2::coverage": {"aws_inspector2_coverage"},

	// Access Analyzer
	"aws::accessanalyzer::analyzer": {"aws_accessanalyzer_analyzers"},
	"aws::accessanalyzer::finding":  {"aws_accessanalyzer_findings"},

	// Backup
	"aws::backup::vault":              {"aws_backup_vaults"},
	"aws::backup::plan":               {"aws_backup_plans"},
	"aws::backup::protected_resource": {"aws_backup_protected_resources"},
	"aws::backup::recovery_point":     {"aws_backup_recovery_points"},

	// Auto Scaling
	"aws::autoscaling::group":            {"aws_autoscaling_groups"},
	"aws::autoscaling::launch_config":    {"aws_autoscaling_launch_configurations"},
	"aws::autoscaling::policy":           {"aws_autoscaling_policies"},
	"aws::autoscaling::scheduled_action": {"aws_autoscaling_scheduled_actions"},
	"aws::autoscaling::lifecycle_hook":   {"aws_autoscaling_lifecycle_hooks"},

	// CloudWatch Extended
	"aws::cloudwatch::dashboard":     {"aws_cloudwatch_dashboards"},
	"aws::cloudwatch::metric_stream": {"aws_cloudwatch_metric_streams"},

	// EventBridge
	"aws::events::event_bus":       {"aws_eventbridge_event_buses"},
	"aws::events::rule":            {"aws_eventbridge_rules"},
	"aws::events::target":          {"aws_eventbridge_targets"},
	"aws::events::archive":         {"aws_eventbridge_archives"},
	"aws::events::api_destination": {"aws_eventbridge_api_destinations"},

	// Kinesis & Firehose
	"aws::kinesis::stream":           {"aws_kinesis_streams"},
	"aws::firehose::delivery_stream": {"aws_firehose_delivery_streams"},

	// Organizations
	"aws::organizations::account":      {"aws_organizations_accounts"},
	"aws::organizations::organization": {"aws_organizations_organization"},
	"aws::organizations::policy":       {"aws_organizations_policies"},
	"aws::organizations::ou":           {"aws_organizations_organizational_units"},

	// CloudFormation
	"aws::cloudformation::stack":          {"aws_cloudformation_stacks"},
	"aws::cloudformation::stack_resource": {"aws_cloudformation_stack_resources"},

	// Step Functions
	"aws::sfn::state_machine": {"aws_sfn_state_machines"},
	"aws::sfn::activity":      {"aws_sfn_activities"},

	// Cognito
	"aws::cognito::user_pool":         {"aws_cognito_user_pools"},
	"aws::cognito::user_pool_client":  {"aws_cognito_user_pool_clients"},
	"aws::cognito::identity_provider": {"aws_cognito_identity_providers"},

	// SES
	"aws::ses::identity":          {"aws_ses_identities"},
	"aws::ses::configuration_set": {"aws_ses_configuration_sets"},

	// MSK (Kafka)
	"aws::msk::cluster":       {"aws_msk_clusters"},
	"aws::msk::configuration": {"aws_msk_configurations"},

	// Transfer Family
	"aws::transfer::server": {"aws_transfer_servers"},
	"aws::transfer::user":   {"aws_transfer_users"},

	// FSx
	"aws::fsx::file_system": {"aws_fsx_file_systems"},
	"aws::fsx::volume":      {"aws_fsx_volumes"},
	"aws::fsx::backup":      {"aws_fsx_backups"},

	// DocumentDB
	"aws::docdb::cluster":  {"aws_docdb_clusters"},
	"aws::docdb::instance": {"aws_docdb_instances"},

	// Neptune
	"aws::neptune::cluster":  {"aws_neptune_clusters"},
	"aws::neptune::instance": {"aws_neptune_instances"},

	// MWAA (Airflow)
	"aws::mwaa::environment": {"aws_mwaa_environments"},

	// GCP
	"gcp::compute::instance":             {"gcp_compute_instances"},
	"gcp::compute::firewall":             {"gcp_compute_firewalls"},
	"gcp::iam::service_account":          {"gcp_iam_service_accounts"},
	"gcp::iam::service_account_key":      {"gcp_iam_service_account_keys"},
	"gcp::storage::bucket":               {"gcp_storage_buckets"},
	"gcp::storage::object":               {"gcp_storage_objects"},
	"gcp::iam::policy":                   {"gcp_iam_policies"},
	"gcp::iam::group_permission_usage":   {"gcp_iam_group_permission_usage"},
	"gcp::sql::database_instance":        {"gcp_sql_instances"},
	"gcp::sql::instance":                 {"gcp_sql_instances"},
	"gcp::container::cluster":            {"gcp_container_clusters"},
	"gcp::container::node_pool":          {"gcp_container_node_pools"},
	"gcp::dns::managed_zone":             {"gcp_dns_zones"},
	"gcp::kms::crypto_key":               {"gcp_kms_keys"},
	"gcp::run::service":                  {"gcp_cloudrun_services"},
	"gcp::cloudrun::service":             {"gcp_cloudrun_services"},
	"gcp::cloudrun::revision":            {"gcp_cloudrun_revisions"},
	"gcp::cloudfunctions::function":      {"gcp_cloudfunctions_functions"},
	"gcp::logging::sink":                 {"gcp_logging_sinks"},
	"gcp::logging::project_sink":         {"gcp_logging_project_sinks"},
	"gcp::ids::endpoint":                 {"gcp_ids_endpoints"},
	"gcp::resourcemanager::project":      {"gcp_iam_policies"},
	"gcp::artifact_registry::repository": {"gcp_artifact_registry_repositories"},
	"gcp::artifactregistry::repository":  {"gcp_artifact_registry_repositories"},
	"gcp::container_registry::registry":  {"gcp_artifact_registry_repositories"},
	"gcp_logging_sink":                   {"gcp_logging_sinks"},

	// Azure
	"azure::compute::virtual_machine": {"azure_compute_virtual_machines"},
	"azure::compute::vm":              {"azure_compute_virtual_machines"},
	"azure::functionapp::function":    {"azure_functions_apps"},
	"azure::web::function":            {"azure_functions_apps"},
	"azure::storage::account":         {"azure_storage_accounts"},
	"azure::storage::container":       {"azure_storage_containers"},
	"azure::storage::blob":            {"azure_storage_blobs"},
	"azure::sql::server":              {"azure_sql_servers"},
	"azure::network::security_group":  {"azure_network_security_groups"},
	"azure::keyvault::key":            {"azure_keyvault_keys"},
	"azure::ad::user":                 {"entra_users"},
	"azure::ad::service_principal":    {"entra_service_principals"},
	"azure::ad::authorization_policy": {"entra_authorization_policies"},

	// Entra ID (legacy resource_type values)
	"entra_user":                      {"entra_users"},
	"entra_service_principal":         {"entra_service_principals"},
	"entra_conditional_access_policy": {"entra_conditional_access_policies"},
	"entra_risky_user":                {"entra_risky_users"},
	"entra_role_assignment":           {"entra_role_assignments"},
	"entra_app_role_assignment":       {"entra_app_role_assignments"},
	"entra_sign_in":                   {"entra_sign_ins"},

	// AWS legacy resource_type values
	"aws_iam_policy":           {"aws_iam_policies"},
	"aws_dynamodb_table":       {"aws_dynamodb_tables"},
	"aws_lb_listener":          {"aws_lb_listeners"},
	"aws_cloudwatch_log_group": {"aws_cloudwatch_log_groups"},

	// GitHub
	"github::repository":                  {"github_repositories"},
	"github::repository_dependabot_alert": {"github_dependabot_alerts"},
	"github::code_scanning_alert":         {"github_code_scanning_alerts"},
	"github::secret_scanning_alert":       {"github_secret_scanning_alerts"},
	"github::actions_workflow":            {"github_actions_workflows"},
	"github::workflow":                    {"github_actions_workflows"},
	"github::user":                        {"github_organization_members"},
	"github_branch_protection":            {"github_branch_protections"},
	"github_user":                         {"github_organization_members"},

	// Okta
	"okta::user":             {"okta_users"},
	"okta::group":            {"okta_groups"},
	"okta::group_membership": {"okta_group_memberships"},
	"okta::application":      {"okta_applications"},
	"okta::app_assignment":   {"okta_app_assignments"},
	"okta::admin_role":       {"okta_admin_roles"},
	"okta::system_log":       {"okta_system_logs"},

	// SentinelOne
	"sentinelone::threat": {"sentinelone_threats"},

	// GitLab
	"gitlab::runner": {"gitlab_runners"},

	// Tailscale
	"tailscale_user":   {"tailscale_users"},
	"tailscale_device": {"tailscale_devices"},

	// Terraform
	"terraform::workspace": {"terraform_workspaces"},

	// Kubernetes
	"k8s::cluster_role":               {"k8s_rbac_cluster_roles"},
	"k8s::cluster_role_binding":       {"k8s_rbac_cluster_role_bindings"},
	"k8s::role":                       {"k8s_rbac_roles"},
	"k8s::role_binding":               {"k8s_rbac_role_bindings"},
	"k8s::namespace":                  {"k8s_core_namespaces"},
	"k8s::core::pod":                  {"k8s_core_pods"},
	"k8s::core::namespace":            {"k8s_core_namespaces"},
	"k8s::core::service":              {"k8s_core_services"},
	"k8s::core::node":                 {"k8s_core_nodes"},
	"k8s::cluster::inventory":         {"k8s_cluster_inventory"},
	"k8s::networking::ingress":        {"k8s_networking_ingresses"},
	"k8s::rbac::cluster_role":         {"k8s_rbac_cluster_roles"},
	"k8s::rbac::cluster_role_binding": {"k8s_rbac_cluster_role_bindings"},
	"k8s::rbac::role_binding":         {"k8s_rbac_role_bindings"},
	"k8s::rbac::risky_binding":        {"k8s_rbac_risky_bindings"},
	"kubernetes::pod":                 {"k8s_core_pods"},
	"kubernetes::service": {
		"k8s_core_services",
	},
	"kubernetes::cluster::inventory":   {"k8s_cluster_inventory"},
	"kubernetes::networking::ingress":  {"k8s_networking_ingresses"},
	"kubernetes::deployment":           {"k8s_apps_deployments"},
	"kubernetes::role_binding":         {"k8s_rbac_role_bindings"},
	"kubernetes::cluster_role_binding": {"k8s_rbac_cluster_role_bindings"},
	"kubernetes::rbac::risky_binding":  {"k8s_rbac_risky_bindings"},
	"kubernetes::audit_event":          {"k8s_audit_events"},

	// GKE (maps to Kubernetes RBAC tables)
	"gcp::gke::cluster_role":         {"k8s_rbac_cluster_roles"},
	"gcp::gke::role":                 {"k8s_rbac_roles"},
	"gcp::gke::role_binding":         {"k8s_rbac_role_bindings"},
	"gcp::gke::cluster_role_binding": {"k8s_rbac_cluster_role_bindings"},

	// Operational/compliance resources
	"backup":                {"backups"},
	"certificate":           {"certificates"},
	"container":             {"containers"},
	"container_image":       {"container_images"},
	"database":              {"databases"},
	"dns_zone":              {"dns_zones"},
	"employee":              {"employees"},
	"endpoint":              {"endpoints"},
	"firewall":              {"firewalls"},
	"firewall_rule":         {"firewall_rules"},
	"intune_managed_device": {"intune_managed_devices"},
	"jamf_computer":         {"jamf_computers"},
	"jamf_mobile_device":    {"jamf_mobile_devices"},
	"kandji_device":         {"kandji_devices"},
	"log_retention":         {"log_retention_policies"},
	"network_endpoint":      {"network_endpoints"},
	"network_segment":       {"network_segments"},
	"password_policy":       {"password_policies"},
	"penetration_test":      {"penetration_tests"},
	"policy_document":       {"policy_documents"},
	"secret":                {"secrets"},
	"sentinelone_agent":     {"sentinelone_agents"},
	"server":                {"servers"},
	"slack_user":            {"slack_users"},
	"system":                {"systems"},
	"tls_endpoint":          {"tls_endpoints"},
	"user_account":          {"user_accounts"},
	"vendor":                {"vendors"},
	"vulnerability":         {"vulnerabilities"},
	"vulnerability_scan":    {"vulnerability_scans"},

	// Cross-provider resources
	"compute::instance":       {"aws_ec2_instances", "gcp_compute_instances", "azure_compute_virtual_machines"},
	"compute::ssh_key":        {"aws_ec2_key_pairs"},
	"serverless::function":    {"aws_lambda_functions", "gcp_cloudfunctions_functions", "azure_functions_apps"},
	"storage::bucket":         {"aws_s3_buckets", "gcp_storage_buckets"},
	"storage::blob_container": {"azure_storage_containers"},
	"database::instance":      {"aws_rds_instances", "gcp_sql_instances", "azure_sql_servers"},
	"database::cluster":       {"aws_rds_db_clusters"},
	"iam::user":               {"aws_iam_users", "aws_iam_credential_reports"},
	"iam::service_account":    {"gcp_iam_service_accounts"},
	"iam::role":               {"aws_iam_roles", "gcp_iam_roles"},
	"iam::group":              {"aws_iam_groups"},
	"network::vpc_peering":    {"aws_ec2_vpc_peering_connections"},
	"network::vnet_peering":   {"azure_network_virtual_networks"},
	"container::pod":          {"k8s_core_pods"},
	"container::deployment":   {"k8s_apps_deployments"},
	"container::image":        {"snyk_container_images", "gcp_artifact_registry_images"},
	"ai::model":               {"ai_models"},
	"ai::endpoint":            {"ai_models"},
	"vendors":                 {"vendors"},
}

// GetRequiredTables returns the asset tables needed to evaluate a policy
func (p *Policy) GetRequiredTables() []string {
	return resourceToTables(p.Resource)
}

func resourceToTables(resource string) []string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return nil
	}
	if resource == "*" {
		return []string{"*"}
	}

	parts := strings.Split(resource, "|")
	seen := make(map[string]bool)
	var tables []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for _, table := range resourceToTablesForType(part) {
			if !seen[table] {
				seen[table] = true
				tables = append(tables, table)
			}
		}
	}

	if len(tables) == 0 {
		return nil
	}
	return tables
}

func hasWildcardTable(tables []string) bool {
	for _, table := range tables {
		if table == "*" {
			return true
		}
	}
	return false
}

func resourceToTablesForType(resource string) []string {
	if tables, ok := GlobalMappingRegistry().Get(resource); ok {
		return tables
	}

	if table := resourceToTable(resource); table != "" {
		return []string{table}
	}

	return nil
}

func resourceToTable(resource string) string {
	parts := strings.Split(resource, "::")
	if len(parts) >= 3 {
		tableName := parts[0] + "_" + parts[1] + "_" + pluralize(parts[2])
		return strings.ToLower(tableName)
	}
	if len(parts) == 2 {
		prefix := strings.ToLower(strings.TrimSpace(parts[0]))
		if shouldFallbackTwoPart(prefix) {
			tableName := prefix + "_" + pluralize(parts[1])
			return strings.ToLower(tableName)
		}
	}

	if strings.Contains(resource, "_") && !strings.Contains(resource, "::") && !strings.Contains(resource, "|") {
		return strings.ToLower(resource)
	}

	return ""
}

func shouldFallbackTwoPart(prefix string) bool {
	switch prefix {
	case "aws", "gcp", "azure", "github", "gitlab", "okta", "sentinelone", "terraform",
		"k8s", "kubernetes", "ai", "ml", "network", "vulnerability", "cross_provider":
		return true
	default:
		return false
	}
}

func pluralize(s string) string {
	if s == "" {
		return s
	}
	if strings.HasSuffix(s, "s") {
		return s
	}
	if strings.HasSuffix(s, "y") && len(s) > 1 {
		c := s[len(s)-2]
		if c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u' {
			return s[:len(s)-1] + "ies"
		}
	}
	return s + "s"
}

// GetAllRequiredTables returns all unique asset tables needed for a set of policies
func GetAllRequiredTables(policies []*Policy) []string {
	tableSet := make(map[string]bool)
	for _, p := range policies {
		for _, t := range p.GetRequiredTables() {
			tableSet[t] = true
		}
	}

	tables := make([]string, 0, len(tableSet))
	for t := range tableSet {
		tables = append(tables, t)
	}
	return tables
}

// ValidateTableCoverage checks which policies can't be evaluated due to missing tables
func (e *Engine) ValidateTableCoverage(availableTables []string) []PolicyCoverageGap {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tableSet := make(map[string]bool)
	for _, t := range availableTables {
		tableSet[t] = true
	}

	var gaps []PolicyCoverageGap
	for _, p := range e.policies {
		required := p.GetRequiredTables()
		if len(required) == 0 {
			continue // Unknown resource type
		}
		if hasWildcardTable(required) {
			continue
		}

		var missing []string
		for _, t := range required {
			if !tableSet[t] {
				missing = append(missing, t)
			}
		}

		if len(missing) > 0 {
			gaps = append(gaps, PolicyCoverageGap{
				PolicyID:      p.ID,
				PolicyName:    p.Name,
				Resource:      p.Resource,
				MissingTables: missing,
			})
		}
	}

	return gaps
}

// PolicyCoverageGap represents a policy that can't be evaluated due to missing tables
type PolicyCoverageGap struct {
	PolicyID      string   `json:"policy_id"`
	PolicyName    string   `json:"policy_name"`
	Resource      string   `json:"resource"`
	MissingTables []string `json:"missing_tables"`
}
