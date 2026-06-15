package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

type cloudCoverageAlias struct {
	SourceID    string
	DimensionID string
}

var cloudPolicyCoverageAliases = map[string]cloudCoverageAlias{
	"aws::apigateway::method":                    {SourceID: "aws", DimensionID: "apigateway_method"},
	"aws::apigateway::rest_api":                  {SourceID: "aws", DimensionID: "apigateway_rest_api"},
	"aws::appsync::graphql_api":                  {SourceID: "aws", DimensionID: "appsync_graphql_api"},
	"aws::bedrock::custom_model":                 {SourceID: "aws", DimensionID: "bedrock_custom_model"},
	"aws::bedrock::provisioned_model_throughput": {SourceID: "aws", DimensionID: "bedrock_provisioned_model_throughput"},
	"aws::cloudfront::distribution":              {SourceID: "aws", DimensionID: "cloudfront_distribution"},
	"aws::cloudtrail::trail":                     {SourceID: "aws", DimensionID: "cloudtrail"},
	"aws::codebuild::project":                    {SourceID: "aws", DimensionID: "codebuild_project"},
	"aws::codebuild::source_credential":          {SourceID: "aws", DimensionID: "codebuild_source_credential"},
	"aws::config::configuration_recorder":        {SourceID: "aws", DimensionID: "config_recorder"},
	"aws::dynamodb::table":                       {SourceID: "aws", DimensionID: "dynamodb_table"},
	"aws::ec2::ami":                              {SourceID: "aws", DimensionID: "ec2_ami"},
	"aws::ec2::ebs_encryption_by_default":        {SourceID: "aws", DimensionID: "ec2_ebs_encryption_by_default"},
	"aws::ec2::ebs_snapshot":                     {SourceID: "aws", DimensionID: "ebs_snapshot"},
	"aws::ec2::ebs_volume":                       {SourceID: "aws", DimensionID: "ebs_volume"},
	"aws::ec2::instance":                         {SourceID: "aws", DimensionID: "ec2_instance"},
	"aws::ec2::security_group":                   {SourceID: "aws", DimensionID: "security_group"},
	"aws::ec2::vpc":                              {SourceID: "aws", DimensionID: "vpc"},
	"aws::ecr::repository":                       {SourceID: "aws", DimensionID: "ecr_repository"},
	"aws::ecr_public::repository":                {SourceID: "aws", DimensionID: "ecr_public_repository"},
	"aws::ecs::task_definition":                  {SourceID: "aws", DimensionID: "ecs_task_definition"},
	"aws::efs::mount_target":                     {SourceID: "aws", DimensionID: "efs_mount_target"},
	"aws::eks::cluster":                          {SourceID: "aws", DimensionID: "eks_cluster"},
	"aws::elasticache::cluster":                  {SourceID: "aws", DimensionID: "elasticache_cluster"},
	"aws::elbv2::listener":                       {SourceID: "aws", DimensionID: "elbv2_listener"},
	"aws::elbv2::load_balancer":                  {SourceID: "aws", DimensionID: "elbv2_load_balancer"},
	"aws::elbv2::target_group":                   {SourceID: "aws", DimensionID: "elbv2_target_group"},
	"aws::guardduty::detector":                   {SourceID: "aws", DimensionID: "guardduty_detector"},
	"aws::guardduty::finding":                    {SourceID: "aws", DimensionID: "guardduty_finding"},
	"aws::iam::access_key":                       {SourceID: "aws", DimensionID: "access_key"},
	"aws::iam::account_password_policy":          {SourceID: "aws", DimensionID: "iam_account_password_policy"},
	"aws::iam::account_summary":                  {SourceID: "aws", DimensionID: "iam_account_summary"},
	"aws::iam::credential_report":                {SourceID: "aws", DimensionID: "iam_credential_report"},
	"aws::iam::policy":                           {SourceID: "aws", DimensionID: "iam_policy"},
	"aws::iam::role":                             {SourceID: "aws", DimensionID: "iam_role"},
	"aws::iam::saml_provider":                    {SourceID: "aws", DimensionID: "iam_saml_provider"},
	"aws::iam::user":                             {SourceID: "aws", DimensionID: "iam_user"},
	"aws::kms::key":                              {SourceID: "aws", DimensionID: "kms_key"},
	"aws::lambda::function":                      {SourceID: "aws", DimensionID: "lambda_function"},
	"aws::logs::log_group":                       {SourceID: "aws", DimensionID: "cloudwatch_log_group"},
	"aws::opensearch::domain":                    {SourceID: "aws", DimensionID: "opensearch_domain"},
	"aws::rds::db_instance":                      {SourceID: "aws", DimensionID: "rds_instance"},
	"aws::rds::db_snapshot":                      {SourceID: "aws", DimensionID: "rds_db_snapshot"},
	"aws::rds::instance":                         {SourceID: "aws", DimensionID: "rds_instance"},
	"aws::redshift::cluster":                     {SourceID: "aws", DimensionID: "redshift_cluster"},
	"aws::s3::bucket":                            {SourceID: "aws", DimensionID: "s3_bucket"},
	"aws::s3::object":                            {SourceID: "aws", DimensionID: "s3_object"},
	"aws::sagemaker::endpoint_configuration":     {SourceID: "aws", DimensionID: "sagemaker_endpoint_configuration"},
	"aws::sagemaker::model":                      {SourceID: "aws", DimensionID: "sagemaker_model"},
	"aws::sagemaker::model_package_group":        {SourceID: "aws", DimensionID: "sagemaker_model_package_group"},
	"aws::sagemaker::notebook_instance":          {SourceID: "aws", DimensionID: "sagemaker_notebook_instance"},
	"aws::sagemaker::training_job":               {SourceID: "aws", DimensionID: "sagemaker_training_job"},
	"aws::secretsmanager::secret":                {SourceID: "aws", DimensionID: "secret"},
	"aws::sns::topic":                            {SourceID: "aws", DimensionID: "sns_topic"},
	"aws::sqs::queue":                            {SourceID: "aws", DimensionID: "sqs_queue"},
	"azure::ad::authorization_policy":            {SourceID: "azure", DimensionID: "ad_authorization_policy"},
	"azure::ad::service_principal":               {SourceID: "azure", DimensionID: "service_principal"},
	"azure::ad::user":                            {SourceID: "azure", DimensionID: "user"},
	"azure::app_service::web_app":                {SourceID: "azure", DimensionID: "app_service"},
	"azure::cognitive_services::account":         {SourceID: "azure", DimensionID: "cognitive_services_account"},
	"azure::compute::virtual_machine":            {SourceID: "azure", DimensionID: "virtual_machine"},
	"azure::compute::virtual_machine_extension":  {SourceID: "azure", DimensionID: "virtual_machine_extension"},
	"azure::containerservice::managed_cluster":   {SourceID: "azure", DimensionID: "aks_cluster"},
	"azure::cosmosdb::account":                   {SourceID: "azure", DimensionID: "cosmos_account"},
	"azure::cosmosdb::database_account":          {SourceID: "azure", DimensionID: "cosmos_account"},
	"azure::functionapp::function":               {SourceID: "azure", DimensionID: "function_app"},
	"azure::keyvault::key":                       {SourceID: "azure", DimensionID: "key_vault_key"},
	"azure::keyvault::vault":                     {SourceID: "azure", DimensionID: "key_vault"},
	"azure::machine_learning::workspace":         {SourceID: "azure", DimensionID: "machine_learning_workspace"},
	"azure::network::security_group":             {SourceID: "azure", DimensionID: "network_security_group"},
	"azure::postgresql::server":                  {SourceID: "azure", DimensionID: "postgresql_server"},
	"azure::sql::database":                       {SourceID: "azure", DimensionID: "sql_database"},
	"azure::sql::server":                         {SourceID: "azure", DimensionID: "sql_server"},
	"azure::storage::account":                    {SourceID: "azure", DimensionID: "storage_account"},
	"azure::storage::blob":                       {SourceID: "azure", DimensionID: "storage_blob"},
	"azure::storage::container":                  {SourceID: "azure", DimensionID: "storage_container"},
	"azure::web::function":                       {SourceID: "azure", DimensionID: "function_app"},
	"gcp::aiplatform::dataset":                   {SourceID: "gcp", DimensionID: "aiplatform_dataset"},
	"gcp::aiplatform::endpoint":                  {SourceID: "gcp", DimensionID: "aiplatform_endpoint"},
	"gcp::artifact_registry::repository":         {SourceID: "gcp", DimensionID: "artifact_registry_repository"},
	"gcp::bigquery::dataset":                     {SourceID: "gcp", DimensionID: "bigquery_dataset"},
	"gcp::cloudfunctions::function":              {SourceID: "gcp", DimensionID: "cloud_function"},
	"gcp::cloudrun::revision":                    {SourceID: "gcp", DimensionID: "cloud_run_revision"},
	"gcp::cloudrun::service":                     {SourceID: "gcp", DimensionID: "cloud_run_service"},
	"gcp::compute::backend_service":              {SourceID: "gcp", DimensionID: "compute_backend_service"},
	"gcp::compute::firewall":                     {SourceID: "gcp", DimensionID: "compute_firewall"},
	"gcp::compute::forwarding_rule":              {SourceID: "gcp", DimensionID: "compute_forwarding_rule"},
	"gcp::compute::instance":                     {SourceID: "gcp", DimensionID: "compute_instance"},
	"gcp::compute::security_policy":              {SourceID: "gcp", DimensionID: "compute_security_policy"},
	"gcp::container::cluster":                    {SourceID: "gcp", DimensionID: "gke_cluster"},
	"gcp::container::node_pool":                  {SourceID: "gcp", DimensionID: "gke_node_pool"},
	"gcp::container_registry::registry":          {SourceID: "gcp", DimensionID: "container_registry"},
	"gcp::dns::managed_zone":                     {SourceID: "gcp", DimensionID: "dns_managed_zone"},
	"gcp::gke::cluster_role":                     {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"gcp::gke::cluster_role_binding":             {SourceID: "kubernetes", DimensionID: "rbac_bindings"},
	"gcp::gke::role":                             {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"gcp::iam::member":                           {SourceID: "gcp", DimensionID: "iam_role_assignment"},
	"gcp::iam::policy":                           {SourceID: "gcp", DimensionID: "iam_role_assignment"},
	"gcp::iam::service_account":                  {SourceID: "gcp", DimensionID: "service_account"},
	"gcp::iam::service_account_key":              {SourceID: "gcp", DimensionID: "service_account_key"},
	"gcp::kms::crypto_key":                       {SourceID: "gcp", DimensionID: "kms_key"},
	"gcp::logging::project_sink":                 {SourceID: "gcp", DimensionID: "logging_project_sink"},
	"gcp::resourcemanager::project":              {SourceID: "gcp", DimensionID: "resourcemanager_project"},
	"gcp::run::service":                          {SourceID: "gcp", DimensionID: "cloud_run_service"},
	"gcp::sql::database_instance":                {SourceID: "gcp", DimensionID: "cloud_sql_instance"},
	"gcp::storage::bucket":                       {SourceID: "gcp", DimensionID: "gcs_bucket"},
	"gcp::storage::object":                       {SourceID: "gcp", DimensionID: "gcs_object"},
	"gcp_container_clusters":                     {SourceID: "gcp", DimensionID: "gke_cluster"},
	"gcp_container_node_pools":                   {SourceID: "gcp", DimensionID: "gke_node_pool"},
	"gcp_container_vulnerabilities":              {SourceID: "gcp", DimensionID: "container_vulnerability"},
	"gcp_ids_endpoints":                          {SourceID: "gcp", DimensionID: "cloud_ids_endpoint"},
	"k8s::cluster_role":                          {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"k8s::cluster::inventory":                    {SourceID: "kubernetes", DimensionID: "clusters"},
	"k8s::core::namespace":                       {SourceID: "kubernetes", DimensionID: "namespaces"},
	"k8s::core::node":                            {SourceID: "kubernetes", DimensionID: "nodes"},
	"k8s::core::pod":                             {SourceID: "kubernetes", DimensionID: "pods"},
	"k8s::core::service":                         {SourceID: "kubernetes", DimensionID: "services"},
	"k8s::namespace":                             {SourceID: "kubernetes", DimensionID: "namespaces"},
	"k8s::networking::ingress":                   {SourceID: "kubernetes", DimensionID: "ingresses"},
	"k8s::rbac::risky_binding":                   {SourceID: "kubernetes", DimensionID: "rbac_bindings"},
	"k8s::rbac::cluster_role":                    {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"k8s::role":                                  {SourceID: "kubernetes", DimensionID: "rbac_roles"},
}

var minimumCloudCoverageDimensions = map[string][]string{
	"aws": {
		"access_analyzer",
		"access_key",
		"acm_certificate",
		"backup_vault",
		"cloudtrail",
		"cloudwatch_alarm",
		"cloudwatch_log_group",
		"config_recorder",
		"container_vulnerability",
		"docdb_cluster",
		"dynamodb_table",
		"ebs_snapshot",
		"ebs_volume",
		"ec2_ami",
		"ec2_ebs_encryption_by_default",
		"ec2_instance",
		"ecr_public_repository",
		"ecr_repository",
		"ecs_service",
		"ecs_task",
		"ecs_task_definition",
		"efs_file_system",
		"efs_mount_target",
		"eks_cluster",
		"eks_node",
		"eks_nodegroup",
		"elbv2_listener",
		"elbv2_load_balancer",
		"elbv2_target_group",
		"fargate_service",
		"guardduty_detector",
		"guardduty_finding",
		"iam_account_password_policy",
		"iam_account_summary",
		"iam_credential_report",
		"iam_group",
		"iam_group_membership",
		"iam_policy",
		"iam_role",
		"iam_role_assignment",
		"iam_user",
		"identity_center_account_assignment",
		"identitystore_user",
		"inspector2_finding",
		"kms_key",
		"lambda_function",
		"network_acl",
		"rds_db_snapshot",
		"rds_instance",
		"route_table",
		"s3_bucket",
		"s3_object",
		"security_group",
		"securityhub_finding",
		"sns_topic",
		"sqs_queue",
		"subnet",
		"support_role",
		"vpc",
		"vpc_flow_log",
	},
	"azure": {
		"activity_log_alert",
		"ad_authorization_policy",
		"aks_cluster",
		"aks_node",
		"app_service",
		"application_container",
		"application_gateway",
		"application_insight",
		"container_repository",
		"container_vulnerability",
		"cosmos_account",
		"cosmos_postgresql",
		"database",
		"databricks_workspace",
		"defender_config",
		"diagnostic_setting",
		"foundry_model_deployment",
		"function_app",
		"iam_role_assignment",
		"key_vault",
		"key_vault_key",
		"key_vault_secret",
		"load_balancer",
		"log_alert",
		"metric_alert_rule",
		"network_security_group",
		"queue",
		"role",
		"route_table",
		"scale_set_virtual_machine",
		"security_contact",
		"server_vulnerability",
		"sql_database",
		"sql_managed_instance",
		"sql_server_on_virtual_machine",
		"storage_account",
		"subnet",
		"subscription",
		"synapse_warehouse",
		"virtual_machine",
		"virtual_machine_scale_set",
		"virtual_network",
	},
	"gcp": {
		"aiplatform_dataset",
		"aiplatform_endpoint",
		"artifact_registry_image",
		"artifact_registry_repository",
		"audit",
		"bigquery_dataset",
		"cloud_function",
		"cloud_ids_endpoint",
		"cloud_run_revision",
		"cloud_run_service",
		"cloud_sql_instance",
		"compute_backend_service",
		"compute_disk",
		"compute_firewall",
		"compute_forwarding_rule",
		"compute_instance",
		"compute_network",
		"compute_route",
		"compute_security_policy",
		"compute_subnetwork",
		"container_registry",
		"container_vulnerability",
		"dns_managed_zone",
		"gcs_bucket",
		"gcs_object",
		"gke_cluster",
		"gke_node_pool",
		"group",
		"group_membership",
		"iam_role_assignment",
		"kms_key",
		"logging_project_sink",
		"resourcemanager_project",
		"resource_exposure",
		"secret_manager_secret",
		"service_account",
		"service_account_impersonation",
		"service_account_key",
	},
}

func checkCloudPolicyCoverage(root string) ([]issue, error) {
	dimensions, err := loadCoverageDimensions(root)
	if err != nil {
		return nil, err
	}
	issues := checkRequiredCloudCoverageDimensions(dimensions)
	policiesRoot := filepath.Join(root, "policies")
	err = filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rel := slashRel(root, path)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(content, &raw); err != nil {
			return nil
		}
		for _, resource := range splitPolicyResources(stringField(raw, "resource")) {
			if !isCloudPolicyResource(resource) {
				continue
			}
			alias, ok := cloudPolicyCoverageAliases[resource]
			if !ok {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("cloud policy resource %q has no source coverage mapping", resource)})
				continue
			}
			sourceDimensions := dimensions[alias.SourceID]
			if len(sourceDimensions) == 0 {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("cloud policy resource %q maps to source %q with no coverage_contract", resource, alias.SourceID)})
				continue
			}
			if _, ok := sourceDimensions[alias.DimensionID]; !ok {
				issues = append(issues, issue{path: rel, message: fmt.Sprintf("cloud policy resource %q maps to missing %s coverage dimension %q", resource, alias.SourceID, alias.DimensionID)})
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("policies directory not found")
		}
		return nil, err
	}
	return issues, nil
}

func checkRequiredCloudCoverageDimensions(dimensions map[string]map[string]sourcecdk.CoverageDimension) []issue {
	var issues []issue
	for sourceID, requiredDimensions := range minimumCloudCoverageDimensions {
		sourceDimensions, ok := dimensions[sourceID]
		if !ok {
			continue
		}
		for _, dimensionID := range requiredDimensions {
			dimension, ok := sourceDimensions[dimensionID]
			if !ok {
				issues = append(issues, issue{path: fmt.Sprintf("sources/%s/catalog.yaml", sourceID), message: fmt.Sprintf("minimum cloud coverage dimension %q is missing", dimensionID)})
				continue
			}
			switch dimension.Support {
			case sourcecdk.CoverageSupportSupported, sourcecdk.CoverageSupportPartial:
			default:
				issues = append(issues, issue{path: fmt.Sprintf("sources/%s/catalog.yaml", sourceID), message: fmt.Sprintf("minimum cloud coverage dimension %q must be supported or partial, got %q", dimensionID, dimension.Support)})
			}
		}
	}
	return issues
}

func loadCoverageDimensions(root string) (map[string]map[string]sourcecdk.CoverageDimension, error) {
	sourcesRoot := filepath.Join(root, "sources")
	dimensions := map[string]map[string]sourcecdk.CoverageDimension{}
	err := filepath.WalkDir(sourcesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Base(path) != "catalog.yaml" {
			return nil
		}
		rel := slashRel(root, path)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(content)
		if err != nil {
			return nil
		}
		if catalog.CoverageContract == nil {
			return nil
		}
		byID := map[string]sourcecdk.CoverageDimension{}
		for _, dimension := range catalog.CoverageContract.Dimensions {
			byID[dimension.ID] = dimension
		}
		dimensions[catalog.Spec.GetId()] = byID
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("sources directory not found")
		}
		return nil, err
	}
	return dimensions, nil
}

func splitPolicyResources(value string) []string {
	seen := map[string]struct{}{}
	var resources []string
	for _, part := range strings.Split(value, "|") {
		resource := strings.TrimSpace(part)
		if resource == "" {
			continue
		}
		if _, ok := seen[resource]; ok {
			continue
		}
		seen[resource] = struct{}{}
		resources = append(resources, resource)
	}
	sort.Strings(resources)
	return resources
}

func isCloudPolicyResource(resource string) bool {
	switch {
	case strings.HasPrefix(resource, "aws::"):
		return true
	case strings.HasPrefix(resource, "azure::"):
		return true
	case strings.HasPrefix(resource, "gcp::"):
		return true
	case strings.HasPrefix(resource, "gcp_"):
		return true
	case strings.HasPrefix(resource, "k8s::"):
		return true
	default:
		return false
	}
}
