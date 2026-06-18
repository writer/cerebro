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
	"gopkg.in/yaml.v3"
)

type cloudCoverageAlias struct {
	SourceID    string
	DimensionID string
}

var cloudPolicyCoverageAliases = map[string]cloudCoverageAlias{
	"aws::apigateway::method":                         {SourceID: "aws", DimensionID: "apigateway_method"},
	"aws::apigateway::rest_api":                       {SourceID: "aws", DimensionID: "apigateway_rest_api"},
	"aws::appsync::graphql_api":                       {SourceID: "aws", DimensionID: "appsync_graphql_api"},
	"aws::bedrock::custom_model":                      {SourceID: "aws", DimensionID: "bedrock_custom_model"},
	"aws::bedrock::provisioned_model_throughput":      {SourceID: "aws", DimensionID: "bedrock_provisioned_model_throughput"},
	"aws::cloudfront::distribution":                   {SourceID: "aws", DimensionID: "cloudfront_distribution"},
	"aws::cloudtrail::trail":                          {SourceID: "aws", DimensionID: "cloudtrail"},
	"aws::codebuild::project":                         {SourceID: "aws", DimensionID: "codebuild_project"},
	"aws::codebuild::source_credential":               {SourceID: "aws", DimensionID: "codebuild_source_credential"},
	"aws::config::configuration_recorder":             {SourceID: "aws", DimensionID: "config_recorder"},
	"aws::dynamodb::table":                            {SourceID: "aws", DimensionID: "dynamodb_table"},
	"aws::ec2::ami":                                   {SourceID: "aws", DimensionID: "ec2_ami"},
	"aws::ec2::ebs_encryption_by_default":             {SourceID: "aws", DimensionID: "ec2_ebs_encryption_by_default"},
	"aws::ec2::ebs_snapshot":                          {SourceID: "aws", DimensionID: "ebs_snapshot"},
	"aws::ec2::ebs_volume":                            {SourceID: "aws", DimensionID: "ebs_volume"},
	"aws::ec2::instance":                              {SourceID: "aws", DimensionID: "ec2_instance"},
	"aws::ec2::network_acl":                           {SourceID: "aws", DimensionID: "network_acl"},
	"aws::ec2::security_group":                        {SourceID: "aws", DimensionID: "security_group"},
	"aws::ec2::vpc":                                   {SourceID: "aws", DimensionID: "vpc"},
	"aws::ec2::vpc_flow_log":                          {SourceID: "aws", DimensionID: "vpc_flow_log"},
	"aws::ecr::repository":                            {SourceID: "aws", DimensionID: "ecr_repository"},
	"aws::ecr_public::repository":                     {SourceID: "aws", DimensionID: "ecr_public_repository"},
	"aws::ecs::task_definition":                       {SourceID: "aws", DimensionID: "ecs_task_definition"},
	"aws::efs::mount_target":                          {SourceID: "aws", DimensionID: "efs_mount_target"},
	"aws::eks::cluster":                               {SourceID: "aws", DimensionID: "eks_cluster"},
	"aws::elasticache::cluster":                       {SourceID: "aws", DimensionID: "elasticache_cluster"},
	"aws::elbv2::listener":                            {SourceID: "aws", DimensionID: "elbv2_listener"},
	"aws::elbv2::load_balancer":                       {SourceID: "aws", DimensionID: "elbv2_load_balancer"},
	"aws::elbv2::target_group":                        {SourceID: "aws", DimensionID: "elbv2_target_group"},
	"aws::guardduty::detector":                        {SourceID: "aws", DimensionID: "guardduty_detector"},
	"aws::guardduty::finding":                         {SourceID: "aws", DimensionID: "guardduty_finding"},
	"aws::iam::access_key":                            {SourceID: "aws", DimensionID: "access_key"},
	"aws::iam::account_password_policy":               {SourceID: "aws", DimensionID: "iam_account_password_policy"},
	"aws::iam::account_summary":                       {SourceID: "aws", DimensionID: "iam_account_summary"},
	"aws::iam::credential_report":                     {SourceID: "aws", DimensionID: "iam_credential_report"},
	"aws::iam::policy":                                {SourceID: "aws", DimensionID: "iam_policy"},
	"aws::iam::role":                                  {SourceID: "aws", DimensionID: "iam_role"},
	"aws::iam::saml_provider":                         {SourceID: "aws", DimensionID: "iam_saml_provider"},
	"aws::iam::user":                                  {SourceID: "aws", DimensionID: "iam_user"},
	"aws::kms::key":                                   {SourceID: "aws", DimensionID: "kms_key"},
	"aws::lambda::function":                           {SourceID: "aws", DimensionID: "lambda_function"},
	"aws::logs::log_group":                            {SourceID: "aws", DimensionID: "cloudwatch_log_group"},
	"aws::opensearch::domain":                         {SourceID: "aws", DimensionID: "opensearch_domain"},
	"aws::rds::db_instance":                           {SourceID: "aws", DimensionID: "rds_instance"},
	"aws::rds::db_snapshot":                           {SourceID: "aws", DimensionID: "rds_db_snapshot"},
	"aws::rds::instance":                              {SourceID: "aws", DimensionID: "rds_instance"},
	"aws::redshift::cluster":                          {SourceID: "aws", DimensionID: "redshift_cluster"},
	"aws::s3::bucket":                                 {SourceID: "aws", DimensionID: "s3_bucket"},
	"aws::s3::object":                                 {SourceID: "aws", DimensionID: "s3_object"},
	"aws::sagemaker::endpoint_configuration":          {SourceID: "aws", DimensionID: "sagemaker_endpoint_configuration"},
	"aws::sagemaker::model":                           {SourceID: "aws", DimensionID: "sagemaker_model"},
	"aws::sagemaker::model_package_group":             {SourceID: "aws", DimensionID: "sagemaker_model_package_group"},
	"aws::sagemaker::notebook_instance":               {SourceID: "aws", DimensionID: "sagemaker_notebook_instance"},
	"aws::sagemaker::training_job":                    {SourceID: "aws", DimensionID: "sagemaker_training_job"},
	"aws::secretsmanager::secret":                     {SourceID: "aws", DimensionID: "secret"},
	"aws::sns::topic":                                 {SourceID: "aws", DimensionID: "sns_topic"},
	"aws::sqs::queue":                                 {SourceID: "aws", DimensionID: "sqs_queue"},
	"azure::ad::authorization_policy":                 {SourceID: "azure", DimensionID: "ad_authorization_policy"},
	"azure::ad::service_principal":                    {SourceID: "azure", DimensionID: "service_principal"},
	"azure::ad::user":                                 {SourceID: "azure", DimensionID: "user"},
	"azure::app_service::web_app":                     {SourceID: "azure", DimensionID: "app_service"},
	"azure::cognitive_services::account":              {SourceID: "azure", DimensionID: "cognitive_services_account"},
	"azure::compute::virtual_machine":                 {SourceID: "azure", DimensionID: "virtual_machine"},
	"azure::compute::virtual_machine_extension":       {SourceID: "azure", DimensionID: "virtual_machine_extension"},
	"azure::containerservice::managed_cluster":        {SourceID: "azure", DimensionID: "aks_cluster"},
	"azure::cosmosdb::account":                        {SourceID: "azure", DimensionID: "cosmos_account"},
	"azure::cosmosdb::database_account":               {SourceID: "azure", DimensionID: "cosmos_account"},
	"azure::functionapp::function":                    {SourceID: "azure", DimensionID: "function_app"},
	"azure::keyvault::key":                            {SourceID: "azure", DimensionID: "key_vault_key"},
	"azure::keyvault::vault":                          {SourceID: "azure", DimensionID: "key_vault"},
	"azure::machine_learning::workspace":              {SourceID: "azure", DimensionID: "machine_learning_workspace"},
	"azure::network::security_group":                  {SourceID: "azure", DimensionID: "network_security_group"},
	"azure::postgresql::server":                       {SourceID: "azure", DimensionID: "postgresql_server"},
	"azure::sql::database":                            {SourceID: "azure", DimensionID: "sql_database"},
	"azure::sql::server":                              {SourceID: "azure", DimensionID: "sql_server"},
	"azure::storage::account":                         {SourceID: "azure", DimensionID: "storage_account"},
	"azure::storage::blob":                            {SourceID: "azure", DimensionID: "storage_blob"},
	"azure::storage::container":                       {SourceID: "azure", DimensionID: "storage_container"},
	"azure::web::function":                            {SourceID: "azure", DimensionID: "function_app"},
	"cloudflare::access::application":                 {SourceID: "cloudflare", DimensionID: "access_applications"},
	"cloudflare::access::group":                       {SourceID: "cloudflare", DimensionID: "access_groups"},
	"cloudflare::account":                             {SourceID: "cloudflare", DimensionID: "accounts"},
	"cloudflare::account::member":                     {SourceID: "cloudflare", DimensionID: "members"},
	"cloudflare::account::role":                       {SourceID: "cloudflare", DimensionID: "roles"},
	"cloudflare::audit_log":                           {SourceID: "cloudflare", DimensionID: "audit_logs"},
	"cloudflare::dns::record":                         {SourceID: "cloudflare", DimensionID: "dns_records"},
	"cloudflare::gateway::rule":                       {SourceID: "cloudflare", DimensionID: "gateway_rules"},
	"cloudflare::load_balancer":                       {SourceID: "cloudflare", DimensionID: "load_balancers"},
	"cloudflare::load_balancer::pool":                 {SourceID: "cloudflare", DimensionID: "load_balancer_pools"},
	"cloudflare::ruleset::account":                    {SourceID: "cloudflare", DimensionID: "account_rulesets"},
	"cloudflare::ruleset::zone":                       {SourceID: "cloudflare", DimensionID: "zone_rulesets"},
	"cloudflare::worker::script":                      {SourceID: "cloudflare", DimensionID: "worker_scripts"},
	"cloudflare::zone":                                {SourceID: "cloudflare", DimensionID: "zones"},
	"gcp::aiplatform::dataset":                        {SourceID: "gcp", DimensionID: "aiplatform_dataset"},
	"gcp::aiplatform::endpoint":                       {SourceID: "gcp", DimensionID: "aiplatform_endpoint"},
	"gcp::artifact_registry::repository":              {SourceID: "gcp", DimensionID: "artifact_registry_repository"},
	"gcp::asset::data_sensitivity":                    {SourceID: "gcp", DimensionID: "asset_metadata"},
	"gcp::asset::metadata":                            {SourceID: "gcp", DimensionID: "asset_metadata"},
	"gcp::bigquery::dataset":                          {SourceID: "gcp", DimensionID: "bigquery_dataset"},
	"gcp::bigquery::table":                            {SourceID: "gcp", DimensionID: "bigquery_table"},
	"gcp::bigtable::instance":                         {SourceID: "gcp", DimensionID: "bigtable_instance"},
	"gcp::bigtable::table":                            {SourceID: "gcp", DimensionID: "bigtable_table"},
	"gcp::certificate_manager::certificate":           {SourceID: "gcp", DimensionID: "certificate_manager_certificate"},
	"gcp::certificate_manager::certificate_map":       {SourceID: "gcp", DimensionID: "certificate_manager_certificate_map"},
	"gcp::certificate_manager::certificate_map_entry": {SourceID: "gcp", DimensionID: "certificate_manager_certificate_map_entry"},
	"gcp::certificate_manager::dns_authorization":     {SourceID: "gcp", DimensionID: "certificate_manager_dns_authorization"},
	"gcp::certificatemanager::certificate":            {SourceID: "gcp", DimensionID: "certificate_manager_certificate"},
	"gcp::certificatemanager::certificate_map":        {SourceID: "gcp", DimensionID: "certificate_manager_certificate_map"},
	"gcp::certificatemanager::certificate_map_entry":  {SourceID: "gcp", DimensionID: "certificate_manager_certificate_map_entry"},
	"gcp::certificatemanager::dns_authorization":      {SourceID: "gcp", DimensionID: "certificate_manager_dns_authorization"},
	"gcp::cloud_scheduler::job":                       {SourceID: "gcp", DimensionID: "cloud_scheduler_job"},
	"gcp::cloudfunctions::function":                   {SourceID: "gcp", DimensionID: "cloud_function"},
	"gcp::cloudscheduler::job":                        {SourceID: "gcp", DimensionID: "cloud_scheduler_job"},
	"gcp::cloudrun::revision":                         {SourceID: "gcp", DimensionID: "cloud_run_revision"},
	"gcp::cloudrun::service":                          {SourceID: "gcp", DimensionID: "cloud_run_service"},
	"gcp::compute::address":                           {SourceID: "gcp", DimensionID: "compute_address"},
	"gcp::compute::backend_bucket":                    {SourceID: "gcp", DimensionID: "compute_backend_bucket"},
	"gcp::compute::backend_service":                   {SourceID: "gcp", DimensionID: "compute_backend_service"},
	"gcp::compute::external_vpn_gateway":              {SourceID: "gcp", DimensionID: "compute_external_vpn_gateway"},
	"gcp::compute::firewall":                          {SourceID: "gcp", DimensionID: "compute_firewall"},
	"gcp::compute::forwarding_rule":                   {SourceID: "gcp", DimensionID: "compute_forwarding_rule"},
	"gcp::compute::health_check":                      {SourceID: "gcp", DimensionID: "compute_health_check"},
	"gcp::compute::instance":                          {SourceID: "gcp", DimensionID: "compute_instance"},
	"gcp::compute::instance_group":                    {SourceID: "gcp", DimensionID: "compute_instance_group"},
	"gcp::compute::instance_group_manager":            {SourceID: "gcp", DimensionID: "compute_instance_group_manager"},
	"gcp::compute::instance_template":                 {SourceID: "gcp", DimensionID: "compute_instance_template"},
	"gcp::compute::interconnect":                      {SourceID: "gcp", DimensionID: "compute_interconnect"},
	"gcp::compute::interconnect_attachment":           {SourceID: "gcp", DimensionID: "compute_interconnect_attachment"},
	"gcp::compute::network_firewall_policy":           {SourceID: "gcp", DimensionID: "compute_network_firewall_policy"},
	"gcp::compute::network_endpoint_group":            {SourceID: "gcp", DimensionID: "compute_network_endpoint_group"},
	"gcp::compute::packet_mirroring":                  {SourceID: "gcp", DimensionID: "compute_packet_mirroring"},
	"gcp::compute::router":                            {SourceID: "gcp", DimensionID: "compute_router"},
	"gcp::compute::security_policy":                   {SourceID: "gcp", DimensionID: "compute_security_policy"},
	"gcp::compute::ssl_certificate":                   {SourceID: "gcp", DimensionID: "compute_ssl_certificate"},
	"gcp::compute::ssl_policy":                        {SourceID: "gcp", DimensionID: "compute_ssl_policy"},
	"gcp::compute::target_grpc_proxy":                 {SourceID: "gcp", DimensionID: "compute_target_grpc_proxy"},
	"gcp::compute::target_http_proxy":                 {SourceID: "gcp", DimensionID: "compute_target_http_proxy"},
	"gcp::compute::target_https_proxy":                {SourceID: "gcp", DimensionID: "compute_target_https_proxy"},
	"gcp::compute::target_ssl_proxy":                  {SourceID: "gcp", DimensionID: "compute_target_ssl_proxy"},
	"gcp::compute::target_tcp_proxy":                  {SourceID: "gcp", DimensionID: "compute_target_tcp_proxy"},
	"gcp::compute::target_vpn_gateway":                {SourceID: "gcp", DimensionID: "compute_target_vpn_gateway"},
	"gcp::compute::url_map":                           {SourceID: "gcp", DimensionID: "compute_url_map"},
	"gcp::compute::vpn_gateway":                       {SourceID: "gcp", DimensionID: "compute_vpn_gateway"},
	"gcp::compute::vpn_tunnel":                        {SourceID: "gcp", DimensionID: "compute_vpn_tunnel"},
	"gcp::container::cluster":                         {SourceID: "gcp", DimensionID: "gke_cluster"},
	"gcp::container::node_pool":                       {SourceID: "gcp", DimensionID: "gke_node_pool"},
	"gcp::container_registry::registry":               {SourceID: "gcp", DimensionID: "container_registry"},
	"gcp::dns::managed_zone":                          {SourceID: "gcp", DimensionID: "dns_managed_zone"},
	"gcp::dns::record_set":                            {SourceID: "gcp", DimensionID: "dns_record_set"},
	"gcp::gke::cluster_role":                          {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"gcp::gke::cluster_role_binding":                  {SourceID: "kubernetes", DimensionID: "rbac_bindings"},
	"gcp::gke::role":                                  {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"gcp::iam::effective_permission":                  {SourceID: "gcp", DimensionID: "effective_permission"},
	"gcp::iam::member":                                {SourceID: "gcp", DimensionID: "iam_role_assignment"},
	"gcp::iam::policy":                                {SourceID: "gcp", DimensionID: "iam_role_assignment"},
	"gcp::iam::service_account":                       {SourceID: "gcp", DimensionID: "service_account"},
	"gcp::iam::service_account_key":                   {SourceID: "gcp", DimensionID: "service_account_key"},
	"gcp::kms::crypto_key":                            {SourceID: "gcp", DimensionID: "kms_key"},
	"gcp::logging::metric":                            {SourceID: "gcp", DimensionID: "logging_metric"},
	"gcp::logging::project_sink":                      {SourceID: "gcp", DimensionID: "logging_project_sink"},
	"gcp::monitoring::alert_policy":                   {SourceID: "gcp", DimensionID: "monitoring_alert_policy"},
	"gcp::monitoring::notification_channel":           {SourceID: "gcp", DimensionID: "monitoring_notification_channel"},
	"gcp::org_policy::policy":                         {SourceID: "gcp", DimensionID: "org_policy"},
	"gcp::orgpolicy::policy":                          {SourceID: "gcp", DimensionID: "org_policy"},
	"gcp::pubsub::subscription":                       {SourceID: "gcp", DimensionID: "pubsub_subscription"},
	"gcp::pubsub::topic":                              {SourceID: "gcp", DimensionID: "pubsub_topic"},
	"gcp::resourcemanager::project":                   {SourceID: "gcp", DimensionID: "resourcemanager_project"},
	"gcp::run::service":                               {SourceID: "gcp", DimensionID: "cloud_run_service"},
	"gcp::secretmanager::secret_version":              {SourceID: "gcp", DimensionID: "secret_manager_version"},
	"gcp::secret_manager::secret_version":             {SourceID: "gcp", DimensionID: "secret_manager_version"},
	"gcp::service_usage::service":                     {SourceID: "gcp", DimensionID: "service_usage_service"},
	"gcp::serviceusage::service":                      {SourceID: "gcp", DimensionID: "service_usage_service"},
	"gcp::spanner::database":                          {SourceID: "gcp", DimensionID: "spanner_database"},
	"gcp::spanner::instance":                          {SourceID: "gcp", DimensionID: "spanner_instance"},
	"gcp::sql::database":                              {SourceID: "gcp", DimensionID: "cloud_sql_database"},
	"gcp::sql::database_instance":                     {SourceID: "gcp", DimensionID: "cloud_sql_instance"},
	"gcp::sql::user":                                  {SourceID: "gcp", DimensionID: "cloud_sql_user"},
	"gcp::storage::bucket":                            {SourceID: "gcp", DimensionID: "gcs_bucket"},
	"gcp::storage::object":                            {SourceID: "gcp", DimensionID: "gcs_object"},
	"gcp::vpcaccess::connector":                       {SourceID: "gcp", DimensionID: "vpc_access_connector"},
	"gcp_container_clusters":                          {SourceID: "gcp", DimensionID: "gke_cluster"},
	"gcp_container_node_pools":                        {SourceID: "gcp", DimensionID: "gke_node_pool"},
	"gcp_container_vulnerabilities":                   {SourceID: "gcp", DimensionID: "container_vulnerability"},
	"gcp_ids_endpoints":                               {SourceID: "gcp", DimensionID: "cloud_ids_endpoint"},
	"k8s::cluster_role":                               {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"k8s::cluster::inventory":                         {SourceID: "kubernetes", DimensionID: "clusters"},
	"k8s::core::namespace":                            {SourceID: "kubernetes", DimensionID: "namespaces"},
	"k8s::core::node":                                 {SourceID: "kubernetes", DimensionID: "nodes"},
	"k8s::core::pod":                                  {SourceID: "kubernetes", DimensionID: "pods"},
	"k8s::core::service":                              {SourceID: "kubernetes", DimensionID: "services"},
	"k8s::namespace":                                  {SourceID: "kubernetes", DimensionID: "namespaces"},
	"k8s::networking::ingress":                        {SourceID: "kubernetes", DimensionID: "ingresses"},
	"k8s::rbac::risky_binding":                        {SourceID: "kubernetes", DimensionID: "rbac_bindings"},
	"k8s::rbac::cluster_role":                         {SourceID: "kubernetes", DimensionID: "rbac_roles"},
	"k8s::role":                                       {SourceID: "kubernetes", DimensionID: "rbac_roles"},
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
	"cloudflare": {
		"access_applications",
		"access_groups",
		"account_rulesets",
		"accounts",
		"audit_logs",
		"dns_records",
		"gateway_rules",
		"load_balancer_pools",
		"load_balancers",
		"members",
		"roles",
		"worker_scripts",
		"zone_rulesets",
		"zones",
	},
	"gcp": {
		"aiplatform_dataset",
		"aiplatform_endpoint",
		"artifact_registry_image",
		"artifact_registry_repository",
		"asset_metadata",
		"audit",
		"bigquery_dataset",
		"bigquery_table",
		"bigtable_instance",
		"bigtable_table",
		"certificate_manager_certificate",
		"certificate_manager_certificate_map",
		"certificate_manager_certificate_map_entry",
		"certificate_manager_dns_authorization",
		"cloud_function",
		"cloud_ids_endpoint",
		"cloud_run_revision",
		"cloud_run_service",
		"cloud_scheduler_job",
		"cloud_sql_database",
		"cloud_sql_instance",
		"cloud_sql_user",
		"compute_address",
		"compute_backend_bucket",
		"compute_backend_service",
		"compute_disk",
		"compute_external_vpn_gateway",
		"compute_firewall",
		"compute_forwarding_rule",
		"compute_health_check",
		"compute_instance",
		"compute_instance_group",
		"compute_instance_group_manager",
		"compute_instance_template",
		"compute_interconnect",
		"compute_interconnect_attachment",
		"compute_network_endpoint_group",
		"compute_network_firewall_policy",
		"compute_network",
		"compute_packet_mirroring",
		"compute_route",
		"compute_router",
		"compute_security_policy",
		"compute_ssl_certificate",
		"compute_ssl_policy",
		"compute_subnetwork",
		"compute_target_grpc_proxy",
		"compute_target_http_proxy",
		"compute_target_https_proxy",
		"compute_target_ssl_proxy",
		"compute_target_tcp_proxy",
		"compute_target_vpn_gateway",
		"compute_url_map",
		"compute_vpn_gateway",
		"compute_vpn_tunnel",
		"container_registry",
		"container_vulnerability",
		"dns_managed_zone",
		"dns_record_set",
		"effective_permission",
		"gcs_bucket",
		"gcs_object",
		"gke_cluster",
		"gke_node_pool",
		"group",
		"group_membership",
		"iam_role_assignment",
		"kms_key",
		"logging_metric",
		"logging_project_sink",
		"monitoring_alert_policy",
		"monitoring_notification_channel",
		"org_policy",
		"pubsub_subscription",
		"pubsub_topic",
		"resourcemanager_project",
		"resource_exposure",
		"secret_manager_secret",
		"secret_manager_version",
		"service_account",
		"service_account_impersonation",
		"service_account_key",
		"service_usage_service",
		"spanner_database",
		"spanner_instance",
		"vpc_access_connector",
	},
}

func checkCloudPolicyCoverage(root string) ([]issue, error) {
	dimensions, err := loadCoverageDimensions(root)
	if err != nil {
		return nil, err
	}
	issues := checkRequiredCloudCoverageDimensions(dimensions)
	issues = append(issues, checkStrictDeployRuntimeCoverage(root, dimensions)...)
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

func checkStrictDeployRuntimeCoverage(root string, dimensions map[string]map[string]sourcecdk.CoverageDimension) []issue {
	var issues []issue
	for sourceID, sourceDimensions := range dimensions {
		sourceDir := filepath.Join(root, "sources", sourceID)
		hasDeployManifest, err := hasSourceDeployManifest(sourceDir)
		if err != nil {
			issues = append(issues, issue{path: fmt.Sprintf("sources/%s/catalog.yaml", sourceID), message: err.Error()})
			continue
		}
		if !hasDeployManifest {
			continue
		}
		deployFamilies, err := loadDeployRuntimeFamilies(filepath.Join(sourceDir, "deploy.yaml"))
		if err != nil {
			issues = append(issues, issue{path: fmt.Sprintf("sources/%s/deploy.yaml", sourceID), message: err.Error()})
			continue
		}
		coveredFamilies := coverageFamilies(sourceDimensions)
		missing := sortedStringSetDifference(deployFamilies, coveredFamilies)
		if len(missing) > 0 {
			issues = append(issues, issue{
				path:    fmt.Sprintf("sources/%s/catalog.yaml", sourceID),
				message: fmt.Sprintf("coverage_contract does not cover deploy runtime families: %s", strings.Join(missing, ", ")),
			})
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

type sourceDeployManifest struct {
	Runtimes []struct {
		Config map[string]string `yaml:"config"`
	} `yaml:"runtimes"`
}

func loadDeployRuntimeFamilies(path string) (map[string]struct{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deploy.yaml: %w", err)
	}
	var manifest sourceDeployManifest
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		return nil, fmt.Errorf("decode deploy.yaml: %w", err)
	}
	families := map[string]struct{}{}
	for _, runtime := range manifest.Runtimes {
		family := strings.TrimSpace(runtime.Config["family"])
		if family == "" {
			continue
		}
		families[family] = struct{}{}
	}
	return families, nil
}

func coverageFamilies(dimensions map[string]sourcecdk.CoverageDimension) map[string]struct{} {
	families := map[string]struct{}{}
	for _, dimension := range dimensions {
		switch dimension.Support {
		case sourcecdk.CoverageSupportSupported, sourcecdk.CoverageSupportPartial:
		default:
			continue
		}
		for _, family := range dimension.Families {
			family = strings.TrimSpace(family)
			if family != "" {
				families[family] = struct{}{}
			}
		}
	}
	return families
}

func sortedStringSetDifference(left map[string]struct{}, right map[string]struct{}) []string {
	out := make([]string, 0)
	for value := range left {
		if _, ok := right[value]; !ok {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
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
	case strings.HasPrefix(resource, "cloudflare::"):
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
