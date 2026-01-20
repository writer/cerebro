package policy

import (
	"strings"
)

// ResourceToTableMapping maps Cedar resource types to CloudQuery table names
// This enables validation that required tables exist before policy evaluation
var ResourceToTableMapping = map[string][]string{
	// S3
	"aws::s3::bucket": {"aws_s3_buckets"},

	// EC2
	"aws::ec2::instance":       {"aws_ec2_instances"},
	"aws::ec2::security_group": {"aws_ec2_security_groups"},
	"aws::ec2::vpc":            {"aws_ec2_vpcs"},
	"aws::ec2::ebs_volume":     {"aws_ec2_ebs_volumes"},
	"aws::ec2::ebs_snapshot":   {"aws_ec2_ebs_snapshots"},
	"aws::ec2::ami":            {"aws_ec2_amis"},
	"aws::ec2::flow_log":       {"aws_ec2_flow_logs"},

	// IAM
	"aws::iam::user":            {"aws_iam_users", "aws_iam_credential_reports"},
	"aws::iam::role":            {"aws_iam_roles"},
	"aws::iam::policy":          {"aws_iam_policies"},
	"aws::iam::group":           {"aws_iam_groups"},
	"aws::iam::account":         {"aws_iam_accounts"},
	"aws::iam::password_policy": {"aws_iam_password_policies"},

	// RDS
	"aws::rds::instance": {"aws_rds_db_instances"},
	"aws::rds::cluster":  {"aws_rds_db_clusters"},

	// Lambda
	"aws::lambda::function": {"aws_lambda_functions"},

	// ELB
	"aws::elbv2::load_balancer": {"aws_elbv2_load_balancers"},
	"aws::elbv2::target_group":  {"aws_elbv2_target_groups"},

	// KMS
	"aws::kms::key": {"aws_kms_keys"},

	// CloudTrail
	"aws::cloudtrail::trail": {"aws_cloudtrail_trails"},

	// CloudWatch
	"aws::cloudwatch::alarm":     {"aws_cloudwatch_alarms"},
	"aws::cloudwatch::log_group": {"aws_cloudwatch_log_groups"},

	// Config
	"aws::config::recorder": {"aws_config_configuration_recorders"},

	// GuardDuty
	"aws::guardduty::detector": {"aws_guardduty_detectors"},

	// EKS
	"aws::eks::cluster": {"aws_eks_clusters"},

	// ECR
	"aws::ecr::repository": {"aws_ecr_repositories"},

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

	// API Gateway
	"aws::apigateway::rest_api": {"aws_apigateway_rest_apis"},

	// CloudFront
	"aws::cloudfront::distribution": {"aws_cloudfront_distributions"},

	// CodeBuild
	"aws::codebuild::project": {"aws_codebuild_projects"},

	// ECS
	"aws::ecs::cluster":         {"aws_ecs_clusters"},
	"aws::ecs::task_definition": {"aws_ecs_task_definitions"},

	// GCP
	"gcp::compute::instance":      {"gcp_compute_instances"},
	"gcp::compute::firewall":      {"gcp_compute_firewalls"},
	"gcp::iam::service_account":   {"gcp_iam_service_accounts"},
	"gcp::storage::bucket":        {"gcp_storage_buckets"},
	"gcp::sql::instance":          {"gcp_sql_instances"},
	"gcp::container::cluster":     {"gcp_container_clusters"},
	"gcp::cloudrun::service":      {"gcp_cloudrun_services"},
	"gcp::cloudrun::revision":     {"gcp_cloudrun_revisions"},
	"gcp::cloudfunctions::function": {"gcp_cloudfunctions_functions"},

	// Azure
	"azure::compute::virtual_machine": {"azure_compute_virtual_machines"},
	"azure::storage::account":         {"azure_storage_accounts"},
	"azure::storage::container":       {"azure_storage_containers"},
	"azure::sql::server":              {"azure_sql_servers"},
	"azure::network::security_group":  {"azure_network_security_groups"},
	"azure::ad::user":                 {"azure_ad_users"},
	"azure::ad::service_principal":    {"azure_ad_service_principals"},
}

// GetRequiredTables returns the CloudQuery tables needed to evaluate a policy
func (p *Policy) GetRequiredTables() []string {
	if tables, ok := ResourceToTableMapping[p.Resource]; ok {
		return tables
	}

	// Fallback: If it contains an underscore, treat it as a direct table name
	// This supports policies that reference tables directly (e.g. "aws_s3_buckets")
	if strings.Contains(p.Resource, "_") {
		return []string{p.Resource}
	}

	return nil
}

// GetAllRequiredTables returns all unique CloudQuery tables needed for a set of policies
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
