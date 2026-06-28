package sourceprojection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/attestedcompute"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

// ProjectionHandler processes events for a specific source type or event kind.
type ProjectionHandler interface {
	// Handles reports which event kind prefixes this handler processes.
	Handles() []string
}

// ProjectFunc converts one source event into graph projection records.
type ProjectFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

// EventProjector binds one event kind to one projector.
type EventProjector struct {
	Kind    string
	Project ProjectFunc
}

// Registry indexes projectors by event kind.
type Registry struct {
	mu                              sync.RWMutex
	projectors                      map[string]ProjectFunc
	handlers                        map[string]ProjectionHandler
	connectorDefinitionFingerprints map[string]string
	connectorDefinitionKinds        map[string]map[string]struct{}
	connectorDefinitionBases        map[string]ProjectFunc
	connectorDefinitionProjectors   map[string]map[string]ProjectFunc
}

// NewRegistry constructs an event projection registry.
func NewRegistry(projectors ...EventProjector) (*Registry, error) {
	registry := &Registry{
		projectors:                      make(map[string]ProjectFunc, len(projectors)),
		handlers:                        make(map[string]ProjectionHandler),
		connectorDefinitionFingerprints: map[string]string{},
		connectorDefinitionKinds:        map[string]map[string]struct{}{},
		connectorDefinitionBases:        map[string]ProjectFunc{},
		connectorDefinitionProjectors:   map[string]map[string]ProjectFunc{},
	}
	for _, projector := range projectors {
		kind := strings.TrimSpace(projector.Kind)
		if kind == "" {
			return nil, fmt.Errorf("projector kind is required")
		}
		if projector.Project == nil {
			return nil, fmt.Errorf("projector %q function is required", kind)
		}
		if _, ok := registry.projectors[kind]; ok {
			return nil, fmt.Errorf("duplicate projector kind %q", kind)
		}
		registry.projectors[kind] = projector.Project
	}
	return registry, nil
}

// RegisterConnectorDefinitions adds declarative runtime connector projectors to the registry.
func (r *Registry) RegisterConnectorDefinitions(definitions ...connectordefinitions.Definition) {
	if r == nil || len(definitions) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureConnectorDefinitionState()
	for _, definition := range definitions {
		normalized, err := connectordefinitions.Normalize(definition)
		if err != nil {
			continue
		}
		definition = normalized
		sourceID := strings.TrimSpace(definition.SourceID)
		if sourceID == "" || definition.Validation.Status == connectordefinitions.ValidationBlocked {
			continue
		}
		fingerprint := connectorDefinitionProjectorFingerprint(definition)
		if r.connectorDefinitionFingerprints[sourceID] == fingerprint {
			continue
		}
		r.unregisterConnectorDefinitionProjectors(sourceID)
		sourceProjectors := catalogRuntimeDefinitionProjectors(definition)
		if len(sourceProjectors) == 0 {
			continue
		}
		kinds := make([]string, 0, len(sourceProjectors))
		for kind, projector := range sourceProjectors {
			if _, ok := r.connectorDefinitionProjectors[kind]; !ok {
				r.connectorDefinitionBases[kind] = r.projectors[kind]
				r.connectorDefinitionProjectors[kind] = map[string]ProjectFunc{}
			}
			r.connectorDefinitionProjectors[kind][sourceID] = projector
			r.projectors[kind] = connectorDefinitionDispatchProjector(r.connectorDefinitionBases[kind], r.connectorDefinitionProjectors[kind])
			kinds = append(kinds, kind)
		}
		r.connectorDefinitionFingerprints[sourceID] = fingerprint
		r.connectorDefinitionKinds[sourceID] = kindSet(kinds)
	}
}

func (r *Registry) ensureConnectorDefinitionState() {
	if r.connectorDefinitionFingerprints == nil {
		r.connectorDefinitionFingerprints = map[string]string{}
	}
	if r.connectorDefinitionKinds == nil {
		r.connectorDefinitionKinds = map[string]map[string]struct{}{}
	}
	if r.connectorDefinitionBases == nil {
		r.connectorDefinitionBases = map[string]ProjectFunc{}
	}
	if r.connectorDefinitionProjectors == nil {
		r.connectorDefinitionProjectors = map[string]map[string]ProjectFunc{}
	}
}

func (r *Registry) unregisterConnectorDefinitionProjectors(sourceID string) {
	kinds := r.connectorDefinitionKinds[sourceID]
	for kind := range kinds {
		sourceProjectors := r.connectorDefinitionProjectors[kind]
		if sourceProjectors != nil {
			delete(sourceProjectors, sourceID)
			if len(sourceProjectors) > 0 {
				r.projectors[kind] = connectorDefinitionDispatchProjector(r.connectorDefinitionBases[kind], sourceProjectors)
				continue
			}
		}
		base, ok := r.connectorDefinitionBases[kind]
		if ok && base != nil {
			r.projectors[kind] = base
		} else {
			delete(r.projectors, kind)
		}
		delete(r.connectorDefinitionBases, kind)
		delete(r.connectorDefinitionProjectors, kind)
	}
	delete(r.connectorDefinitionKinds, sourceID)
	delete(r.connectorDefinitionFingerprints, sourceID)
}

func connectorDefinitionDispatchProjector(base ProjectFunc, sourceProjectors map[string]ProjectFunc) ProjectFunc {
	projectors := make(map[string]ProjectFunc, len(sourceProjectors))
	for sourceID, projector := range sourceProjectors {
		if projector != nil {
			projectors[sourceID] = projector
		}
	}
	return func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		if event != nil {
			if projector := projectors[strings.TrimSpace(event.GetSourceId())]; projector != nil {
				return projector(event)
			}
		}
		if base != nil {
			return base(event)
		}
		return nil, nil, nil
	}
}

func connectorDefinitionProjectorFingerprint(definition connectordefinitions.Definition) string {
	body, err := json.Marshal(struct {
		SourceID         string                                `json:"source_id"`
		ResourceFamilies []connectordefinitions.ResourceFamily `json:"resource_families"`
	}{SourceID: strings.TrimSpace(definition.SourceID), ResourceFamilies: definition.ResourceFamilies})
	if err != nil {
		return strings.TrimSpace(definition.SourceID)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func kindSet(kinds []string) map[string]struct{} {
	out := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		out[kind] = struct{}{}
	}
	return out
}

var builtinRegistry = &Registry{projectors: map[string]ProjectFunc{
	attestedcompute.EventKindGraphDelta:             attestedComputeGraphDeltaProjections,
	"backstage.component":                           backstageComponentProjections,
	"auth0.audit_events":                            auth0AuditEventsProjections,
	"auth0.roles":                                   auth0RolesProjections,
	"auth0.users":                                   auth0UsersProjections,
	"archetype.scan":                                archetypeScanProjections,
	"archetype.vulnerability":                       archetypeVulnerabilityProjections,
	"archetype.library_note":                        archetypeLibraryNoteProjections,
	"aurelius.catalog_promotion":                    aureliusCatalogPromotionProjections,
	"aurelius.finding":                              aureliusFindingProjections,
	"aurelius.image_scan":                           aureliusImageScanProjections,
	"aurelius.policy_exception":                     aureliusPolicyExceptionProjections,
	"cerebro.api_access":                            cerebroAPIAccessProjections,
	"aurelius.verdict":                              aureliusVerdictProjections,
	"github.pull_request":                           githubPullRequestProjections,
	"github.audit":                                  githubAuditProjections,
	"github.code.repository":                        githubCodeRepositoryProjections,
	"github.dependabot_alert":                       githubDependabotAlertProjections,
	"github.secret_scanning_alert":                  githubSecretScanningAlertProjections,
	"github.org_member":                             githubOrgMemberProjections,
	"github.org_installation":                       githubOrgInstallationProjections,
	"asset.crown_jewel":                             assetCrownJewelProjections,
	"asset.data_sensitivity":                        assetDataSensitivityProjections,
	"aws.access_key":                                awsAccessKeyProjections,
	"aws.access_analyzer":                           awsCloudResourceProjections,
	"aws.acm_certificate":                           awsCloudResourceProjections,
	"aws.apprunner_service":                         awsCloudResourceProjections,
	"aws.app_runner_service":                        awsCloudResourceProjections,
	"aws.appsync_graphql_api":                       awsCloudResourceProjections,
	"aws.asset_metadata":                            awsCloudResourceProjections,
	"aws.batch_compute_environment":                 awsCloudResourceProjections,
	"aws.batch_job_queue":                           awsCloudResourceProjections,
	"aws.backup_vault":                              awsBackupVaultProjections,
	"aws.backup_plan":                               awsBackupPlanProjections,
	"aws.backup_protected_resource":                 awsBackupProtectedResourceProjections,
	"aws.backup_recovery_point":                     awsBackupRecoveryPointProjections,
	"aws.bedrock_custom_model":                      awsCloudResourceProjections,
	"aws.bedrock_provisioned_model_throughput":      awsCloudResourceProjections,
	"aws.codebuild_project":                         awsCloudResourceProjections,
	"aws.codebuild_source_credential":               awsCloudResourceProjections,
	"aws.cloudtrail":                                awsCloudTrailProjections,
	"aws.config_recorder":                           awsCloudResourceProjections,
	"aws.docdb_cluster":                             awsCloudResourceProjections,
	"aws.docdb_instance":                            awsDatabaseInstanceProjections,
	"aws.dynamodb_backup":                           awsCloudResourceProjections,
	"aws.dynamodb_stream":                           awsCloudResourceProjections,
	"aws.dynamodb_table":                            awsCloudResourceProjections,
	"aws.datasync_location":                         awsCloudResourceProjections,
	"aws.datasync_task":                             awsCloudResourceProjections,
	"aws.ebs_snapshot":                              awsCloudResourceProjections,
	"aws.ebs_volume":                                awsCloudResourceProjections,
	"aws.ec2_ebs_encryption_by_default":             awsCloudResourceProjections,
	"aws.ec2_ami":                                   awsCloudResourceProjections,
	"aws.athena_data_catalog":                       awsCloudResourceProjections,
	"aws.athena_workgroup":                          awsCloudResourceProjections,
	"aws.cloudwatch_alarm":                          awsCloudResourceProjections,
	"aws.cloudwatch_log_group":                      awsCloudResourceProjections,
	"aws.ec2_instance":                              awsEC2InstanceProjections,
	"aws.vpc":                                       awsVPCProjections,
	"aws.subnet":                                    awsSubnetProjections,
	"aws.security_group":                            awsSecurityGroupProjections,
	"aws.route_table":                               awsRouteTableProjections,
	"aws.network_acl":                               awsNetworkACLProjections,
	"aws.internet_gateway":                          awsInternetGatewayProjections,
	"aws.nat_gateway":                               awsNATGatewayProjections,
	"aws.vpc_flow_log":                              awsVPCFlowLogProjections,
	"aws.vpc_endpoint":                              awsVPCEndpointProjections,
	"aws.ecr_public_repository":                     awsCloudResourceProjections,
	"aws.ecr_repository":                            awsCloudResourceProjections,
	"aws.ecs_service":                               awsECSServiceProjections,
	"aws.ecs_task":                                  awsECSTaskProjections,
	"aws.ecs_task_definition":                       awsECSTaskDefinitionProjections,
	"aws.efs_access_point":                          awsCloudResourceProjections,
	"aws.efs_file_system":                           awsCloudResourceProjections,
	"aws.efs_mount_target":                          awsDataResourceProjections,
	"aws.eks_cluster":                               awsEKSClusterProjections,
	"aws.eks_nodegroup":                             awsEKSNodegroupProjections,
	"aws.eks_fargate_profile":                       awsEKSFargateProfileProjections,
	"aws.eks_pod_identity_association":              awsEKSPodIdentityAssociationProjections,
	"aws.elasticache_cluster":                       awsDataResourceProjections,
	"aws.elasticache_replication_group":             awsDataResourceProjections,
	"aws.elasticache_subnet_group":                  awsDataResourceProjections,
	"aws.globalaccelerator_accelerator":             awsGlobalAcceleratorAcceleratorProjections,
	"aws.global_accelerator_accelerator":            awsGlobalAcceleratorAcceleratorProjections,
	"aws.globalaccelerator_listener":                awsGlobalAcceleratorListenerProjections,
	"aws.global_accelerator_listener":               awsGlobalAcceleratorListenerProjections,
	"aws.globalaccelerator_endpoint_group":          awsGlobalAcceleratorEndpointGroupProjections,
	"aws.global_accelerator_endpoint_group":         awsGlobalAcceleratorEndpointGroupProjections,
	"aws.vpclattice_service":                        awsVPCLatticeServiceProjections,
	"aws.vpclattice_listener":                       awsVPCLatticeListenerProjections,
	"aws.vpclattice_target_group":                   awsVPCLatticeTargetGroupProjections,
	"aws.elbv2_load_balancer":                       awsCloudResourceProjections,
	"aws.elbv2_listener":                            awsCloudResourceProjections,
	"aws.elbv2_target_group":                        awsCloudResourceProjections,
	"aws.apigateway_rest_api":                       awsCloudResourceProjections,
	"aws.apigateway_method":                         awsCloudResourceProjections,
	"aws.apigateway_stage":                          awsCloudResourceProjections,
	"aws.apigateway_route":                          awsCloudResourceProjections,
	"aws.apigateway_integration":                    awsCloudResourceProjections,
	"aws.cloudfront_distribution":                   awsCloudResourceProjections,
	"aws.cloudfront_origin_access_control":          awsCloudResourceProjections,
	"aws.cloudfront_key_group":                      awsCloudResourceProjections,
	"aws.cloudfront_public_key":                     awsCloudResourceProjections,
	"aws.cloudfront_response_headers_policy":        awsCloudResourceProjections,
	"aws.effective_permission":                      awsEffectivePermissionProjections,
	"aws.guardduty_detector":                        awsCloudResourceProjections,
	"aws.guardduty_finding":                         awsCloudResourceProjections,
	"aws.eventbridge_archive":                       awsCloudResourceProjections,
	"aws.eventbridge_event_bus":                     awsCloudResourceProjections,
	"aws.eventbridge_pipe":                          awsCloudResourceProjections,
	"aws.eventbridge_rule":                          awsCloudResourceProjections,
	"aws.firehose_delivery_stream":                  awsCloudResourceProjections,
	"aws.glue_crawler":                              awsCloudResourceProjections,
	"aws.glue_database":                             awsCloudResourceProjections,
	"aws.glue_job":                                  awsCloudResourceProjections,
	"aws.glue_table":                                awsCloudResourceProjections,
	"aws.iam_account_password_policy":               awsCloudResourceProjections,
	"aws.iam_account_summary":                       awsCloudResourceProjections,
	"aws.iam_credential_report":                     awsCloudResourceProjections,
	"aws.iam_group":                                 awsIAMGroupProjections,
	"aws.iam_group_membership":                      awsIAMGroupMembershipProjections,
	"aws.iam_policy":                                awsCloudResourceProjections,
	"aws.iam_role":                                  awsIAMRoleProjections,
	"aws.iam_role_assignment":                       awsIAMRoleAssignmentProjections,
	"aws.iam_role_trust":                            awsIAMRoleTrustProjections,
	"aws.iam_saml_provider":                         awsCloudResourceProjections,
	"aws.iam_user":                                  awsIAMUserProjections,
	"aws.inspector2_finding":                        awsInspector2FindingProjections,
	"aws.fsx_file_system":                           awsDataResourceProjections,
	"aws.kinesis_stream":                            awsCloudResourceProjections,
	"aws.identity_center_account_assignment":        awsIdentityCenterAccountAssignmentProjections,
	"aws.identity_center_permission_set":            awsIdentityCenterPermissionSetProjections,
	"aws.identitystore_group":                       awsIAMGroupProjections,
	"aws.identity_store_group":                      awsIAMGroupProjections,
	"aws.identitystore_group_membership":            awsIAMGroupMembershipProjections,
	"aws.identity_store_group_membership":           awsIAMGroupMembershipProjections,
	"aws.identitystore_user":                        awsIAMUserProjections,
	"aws.identity_store_user":                       awsIAMUserProjections,
	"aws.kms_key":                                   awsCloudResourceProjections,
	"aws.lakeformation_lf_tag":                      awsCloudResourceProjections,
	"aws.lakeformation_permission":                  awsCloudResourceProjections,
	"aws.lakeformation_resource":                    awsCloudResourceProjections,
	"aws.lambda_function":                           awsLambdaFunctionProjections,
	"aws.macie2_finding":                            awsCloudResourceProjections,
	"aws.network_firewall":                          awsCloudResourceProjections,
	"aws.neptune_cluster":                           awsCloudResourceProjections,
	"aws.neptune_instance":                          awsDatabaseInstanceProjections,
	"aws.msk_cluster":                               awsCloudResourceProjections,
	"aws.organizations_account":                     awsOrganizationsAccountProjections,
	"aws.organizations_organizational_unit":         awsOrganizationsOrganizationalUnitProjections,
	"aws.organizations_policy":                      awsOrganizationsPolicyProjections,
	"aws.organizations_root":                        awsOrganizationsRootProjections,
	"aws.opensearch_domain":                         awsDataResourceProjections,
	"aws.opensearch_serverless_collection":          awsCloudResourceProjections,
	"aws.opensearch_serverless_security_policy":     awsCloudResourceProjections,
	"aws.public_endpoint":                           awsPublicEndpointProjections,
	"aws.rds_db_snapshot":                           awsCloudResourceProjections,
	"aws.rds_instance":                              awsCloudResourceProjections,
	"aws.redshift_cluster":                          awsCloudResourceProjections,
	"aws.resource_exposure":                         awsResourceExposureProjections,
	"aws.route53_resolver_endpoint":                 awsCloudResourceProjections,
	"aws.route53_resolver_rule":                     awsCloudResourceProjections,
	"aws.s3_access_point":                           awsCloudResourceProjections,
	"aws.s3_bucket":                                 awsCloudResourceProjections,
	"aws.s3_multi_region_access_point":              awsCloudResourceProjections,
	"aws.sagemaker_endpoint_configuration":          awsCloudResourceProjections,
	"aws.sagemaker_model":                           awsCloudResourceProjections,
	"aws.sagemaker_model_package_group":             awsCloudResourceProjections,
	"aws.sagemaker_notebook_instance":               awsCloudResourceProjections,
	"aws.sagemaker_training_job":                    awsCloudResourceProjections,
	"aws.scheduler_schedule":                        awsCloudResourceProjections,
	"aws.scheduler_schedule_group":                  awsCloudResourceProjections,
	"aws.secret":                                    awsCloudResourceProjections,
	"aws.securityhub_finding":                       awsCloudResourceProjections,
	"aws.sns_topic":                                 awsCloudResourceProjections,
	"aws.sqs_queue":                                 awsCloudResourceProjections,
	"aws.wafv2_web_acl":                             awsCloudResourceProjections,
	"aws.ssm_association":                           awsCloudResourceProjections,
	"aws.ssm_document":                              awsCloudResourceProjections,
	"aws.ssm_managed_instance":                      awsCloudResourceProjections,
	"aws.ssm_parameter":                             awsCloudResourceProjections,
	"aws.stepfunctions_activity":                    awsCloudResourceProjections,
	"aws.stepfunctions_state_machine":               awsCloudResourceProjections,
	"aws.sso_account_assignment":                    awsSSOAccountAssignmentProjections,
	"aws.sso_instance":                              awsCloudResourceProjections,
	"aws.sso_permission_set":                        awsCloudResourceProjections,
	"azure.activity_log":                            azureAuditProjections,
	"azure.activity_log_alert":                      azureCloudResourceProjections,
	"azure.app_role_assignment":                     azureAppRoleAssignmentProjections,
	"azure.aks_cluster":                             azureCloudResourceProjections,
	"azure.aks_node_pool":                           azureCloudResourceProjections,
	"azure.app_service":                             azureCloudResourceProjections,
	"azure.application":                             azureApplicationProjections,
	"azure.application_container":                   azureCloudResourceProjections,
	"azure.application_gateway":                     azureCloudResourceProjections,
	"azure.application_insight":                     azureCloudResourceProjections,
	"azure.asset_metadata":                          azureCloudResourceProjections,
	"azure.authorization_policy":                    azureCloudResourceProjections,
	"azure.cognitive_services_account":              azureCloudResourceProjections,
	"azure.cognitive_services_deployment":           azureCloudResourceProjections,
	"azure.container_registry":                      azureCloudResourceProjections,
	"azure.cosmos_account":                          azureCloudResourceProjections,
	"azure.cosmos_postgresql":                       azureCloudResourceProjections,
	"azure.cosmos_postgresql_firewall_rule":         azureCloudResourceProjections,
	"azure.databricks_workspace":                    azureCloudResourceProjections,
	"azure.defender_config":                         azureCloudResourceProjections,
	"azure.diagnostic_setting":                      azureCloudResourceProjections,
	"azure.diagnostic_setting_resource":             azureCloudResourceProjections,
	"azure.credential":                              azureCredentialProjections,
	"azure.directory_audit":                         azureAuditProjections,
	"azure.directory_role_assignment":               azureRoleAssignmentProjections,
	"azure.effective_permission":                    azureEffectivePermissionProjections,
	"azure.function_app":                            azureCloudResourceProjections,
	"azure.group":                                   azureGroupProjections,
	"azure.group_membership":                        azureGroupMembershipProjections,
	"azure.iam_role_assignment":                     azureRoleAssignmentProjections,
	"azure.key_vault":                               azureCloudResourceProjections,
	"azure.key_vault_key":                           azureCloudResourceProjections,
	"azure.key_vault_secret":                        azureCloudResourceProjections,
	"azure.load_balancer":                           azureCloudResourceProjections,
	"azure.log_alert":                               azureCloudResourceProjections,
	"azure.machine_learning_compute":                azureCloudResourceProjections,
	"azure.machine_learning_workspace":              azureCloudResourceProjections,
	"azure.managed_disk":                            azureCloudResourceProjections,
	"azure.metric_alert_rule":                       azureCloudResourceProjections,
	"azure.mysql_server":                            azureCloudResourceProjections,
	"azure.network_security_group":                  azureCloudResourceProjections,
	"azure.policy_assignment":                       azureCloudResourceProjections,
	"azure.postgresql_firewall_rule":                azureCloudResourceProjections,
	"azure.postgresql_server":                       azureCloudResourceProjections,
	"azure.public_ip_address":                       azureCloudResourceProjections,
	"azure.resource_exposure":                       azureResourceExposureProjections,
	"azure.role":                                    azureCloudResourceProjections,
	"azure.route_table":                             azureCloudResourceProjections,
	"azure.security_contact":                        azureCloudResourceProjections,
	"azure.security_setting":                        azureCloudResourceProjections,
	"azure.server_vulnerability":                    azureCloudResourceProjections,
	"azure.server_vulnerability_subassessment":      azureCloudResourceProjections,
	"azure.service_principal":                       azureServicePrincipalProjections,
	"azure.sql_database":                            azureCloudResourceProjections,
	"azure.sql_managed_instance":                    azureCloudResourceProjections,
	"azure.sql_managed_instance_tde":                azureCloudResourceProjections,
	"azure.sql_server":                              azureCloudResourceProjections,
	"azure.sql_server_on_virtual_machine":           azureCloudResourceProjections,
	"azure.storage_account":                         azureCloudResourceProjections,
	"azure.storage_container":                       azureCloudResourceProjections,
	"azure.storage_queue":                           azureCloudResourceProjections,
	"azure.subnet":                                  azureSubnetProjections,
	"azure.synapse_sql_pool":                        azureCloudResourceProjections,
	"azure.user":                                    azureUserProjections,
	"azure.virtual_machine":                         azureCloudResourceProjections,
	"azure.virtual_machine_extension":               azureCloudResourceProjections,
	"azure.virtual_machine_scale_set":               azureCloudResourceProjections,
	"azure.virtual_machine_scale_set_instance":      azureCloudResourceProjections,
	"azure.virtual_network":                         azureCloudResourceProjections,
	"gcp.artifact_registry_image":                   gcpCloudResourceProjections,
	"gcp.artifact_registry_repository":              gcpCloudResourceProjections,
	"gcp.asset_metadata":                            gcpCloudResourceProjections,
	"gcp.aiplatform_dataset":                        gcpCloudResourceProjections,
	"gcp.aiplatform_endpoint":                       gcpCloudResourceProjections,
	"gcp.audit":                                     gcpAuditProjections,
	"gcp.binary_authorization_attestor":             gcpCloudResourceProjections,
	"gcp.binary_authorization_policy":               gcpCloudResourceProjections,
	"gcp.bigquery_dataset":                          gcpCloudResourceProjections,
	"gcp.bigquery_table":                            gcpCloudResourceProjections,
	"gcp.bigtable_instance":                         gcpCloudResourceProjections,
	"gcp.bigtable_table":                            gcpCloudResourceProjections,
	"gcp.certificate_manager_certificate":           gcpCloudResourceProjections,
	"gcp.certificate_manager_certificate_map":       gcpCloudResourceProjections,
	"gcp.certificate_manager_certificate_map_entry": gcpCloudResourceProjections,
	"gcp.certificate_manager_dns_authorization":     gcpCloudResourceProjections,
	"gcp.cloud_function":                            gcpCloudResourceProjections,
	"gcp.cloud_ids_endpoint":                        gcpCloudResourceProjections,
	"gcp.cloud_scheduler_job":                       gcpCloudResourceProjections,
	"gcp.cloud_run_revision":                        gcpCloudResourceProjections,
	"gcp.cloud_run_service":                         gcpCloudResourceProjections,
	"gcp.cloud_sql_database":                        gcpCloudResourceProjections,
	"gcp.cloud_sql_instance":                        gcpCloudResourceProjections,
	"gcp.cloud_sql_user":                            gcpCloudResourceProjections,
	"gcp.container_registry":                        gcpCloudResourceProjections,
	"gcp.compute_address":                           gcpCloudResourceProjections,
	"gcp.compute_backend_bucket":                    gcpCloudResourceProjections,
	"gcp.compute_backend_service":                   gcpCloudResourceProjections,
	"gcp.compute_disk":                              gcpCloudResourceProjections,
	"gcp.compute_external_vpn_gateway":              gcpCloudResourceProjections,
	"gcp.compute_firewall":                          gcpCloudResourceProjections,
	"gcp.compute_forwarding_rule":                   gcpCloudResourceProjections,
	"gcp.compute_health_check":                      gcpCloudResourceProjections,
	"gcp.compute_instance":                          gcpCloudResourceProjections,
	"gcp.compute_instance_group":                    gcpCloudResourceProjections,
	"gcp.compute_instance_group_manager":            gcpCloudResourceProjections,
	"gcp.compute_instance_template":                 gcpCloudResourceProjections,
	"gcp.compute_interconnect":                      gcpCloudResourceProjections,
	"gcp.compute_interconnect_attachment":           gcpCloudResourceProjections,
	"gcp.compute_network_endpoint_group":            gcpCloudResourceProjections,
	"gcp.compute_network_firewall_policy":           gcpCloudResourceProjections,
	"gcp.compute_network":                           gcpCloudResourceProjections,
	"gcp.compute_packet_mirroring":                  gcpCloudResourceProjections,
	"gcp.compute_route":                             gcpCloudResourceProjections,
	"gcp.compute_router":                            gcpCloudResourceProjections,
	"gcp.compute_security_policy":                   gcpCloudResourceProjections,
	"gcp.compute_ssl_certificate":                   gcpCloudResourceProjections,
	"gcp.compute_ssl_policy":                        gcpCloudResourceProjections,
	"gcp.compute_subnetwork":                        gcpCloudResourceProjections,
	"gcp.compute_target_grpc_proxy":                 gcpCloudResourceProjections,
	"gcp.compute_target_http_proxy":                 gcpCloudResourceProjections,
	"gcp.compute_target_https_proxy":                gcpCloudResourceProjections,
	"gcp.compute_target_ssl_proxy":                  gcpCloudResourceProjections,
	"gcp.compute_target_tcp_proxy":                  gcpCloudResourceProjections,
	"gcp.compute_target_vpn_gateway":                gcpCloudResourceProjections,
	"gcp.compute_url_map":                           gcpCloudResourceProjections,
	"gcp.compute_vpn_gateway":                       gcpCloudResourceProjections,
	"gcp.compute_vpn_tunnel":                        gcpCloudResourceProjections,
	"gcp.dns_managed_zone":                          gcpCloudResourceProjections,
	"gcp.dns_record_set":                            gcpCloudResourceProjections,
	"gcp.effective_permission":                      gcpEffectivePermissionProjections,
	"gcp.gcs_bucket":                                gcpCloudResourceProjections,
	"gcp.gcs_object":                                gcpCloudResourceProjections,
	"gcp.gke_cluster":                               gcpCloudResourceProjections,
	"gcp.gke_node_pool":                             gcpCloudResourceProjections,
	"gcp.group":                                     gcpGroupProjections,
	"gcp.group_membership":                          gcpGroupMembershipProjections,
	"gcp.iam_role_assignment":                       gcpIAMRoleAssignmentProjections,
	"gcp.kms_key":                                   gcpCloudResourceProjections,
	"gcp.logging_metric":                            gcpCloudResourceProjections,
	"gcp.logging_project_sink":                      gcpCloudResourceProjections,
	"gcp.monitoring_alert_policy":                   gcpCloudResourceProjections,
	"gcp.monitoring_notification_channel":           gcpCloudResourceProjections,
	"gcp.org_policy":                                gcpCloudResourceProjections,
	"gcp.pubsub_subscription":                       gcpCloudResourceProjections,
	"gcp.pubsub_topic":                              gcpCloudResourceProjections,
	"gcp.resourcemanager_project":                   gcpCloudResourceProjections,
	"gcp.resource_exposure":                         gcpResourceExposureProjections,
	"gcp.secret_manager_secret":                     gcpCloudResourceProjections,
	"gcp.secret_manager_version":                    gcpCloudResourceProjections,
	"gcp.security_center_finding":                   gcpCloudResourceProjections,
	"gcp.service_account":                           gcpServiceAccountProjections,
	"gcp.service_account_impersonation":             gcpServiceAccountImpersonationProjections,
	"gcp.service_account_key":                       gcpServiceAccountKeyProjections,
	"gcp.service_usage_service":                     gcpCloudResourceProjections,
	"gcp.spanner_database":                          gcpCloudResourceProjections,
	"gcp.spanner_instance":                          gcpCloudResourceProjections,
	"gcp.vpc_access_connector":                      gcpCloudResourceProjections,
	"gcp.workload_identity_pool":                    gcpCloudResourceProjections,
	"gcp.workload_identity_provider":                gcpCloudResourceProjections,
	"gcp.container_analysis_vulnerability":          gcpContainerVulnerabilityProjections,
	"gcp.container_vulnerability":                   gcpContainerVulnerabilityProjections,
	"cosmo.session":                                 cosmoSessionProjections,
	"cosmo.fact":                                    cosmoFactProjections,
	"cosmo.message":                                 cosmoMessageProjections,
	"cosmo.survey_feedback":                         cosmoSurveyFeedbackProjections,
	"kolide.check":                                  kolideCheckProjections,
	"kolide.device":                                 kolideDeviceProjections,
	"kolide.issue":                                  kolideIssueProjections,
	"kolide.software":                               kolideSoftwareProjections,
	"kolide.user_device":                            kolideUserDeviceProjections,
	"kolide.vulnerability":                          kolideVulnerabilityProjections,
	"kandji.application":                            kandjiApplicationProjections,
	"kandji.device":                                 kandjiDeviceProjections,
	"kandji.vulnerability":                          kandjiVulnerabilityProjections,
	"okta.user":                                     oktaUserProjections,
	"okta.group":                                    oktaGroupProjections,
	"okta.group_membership":                         oktaGroupMembershipProjections,
	"okta.api_token":                                oktaAPITokenProjections,
	"okta.authorization_server":                     oktaAuthorizationServerProjections,
	"okta.brand":                                    oktaBrandProjections,
	"okta.device_assurance":                         oktaDeviceAssuranceProjections,
	"okta.event_hook":                               oktaEventHookProjections,
	"okta.identity_provider":                        oktaIdentityProviderProjections,
	"okta.inline_hook":                              oktaInlineHookProjections,
	"okta.log_stream":                               oktaLogStreamProjections,
	"okta.network_zone":                             oktaNetworkZoneProjections,
	"okta.application":                              oktaApplicationProjections,
	"okta.app_assignment":                           oktaAppAssignmentProjections,
	"okta.policy_rule":                              oktaPolicyRuleProjections,
	"okta.admin_role":                               oktaAdminRoleProjections,
	"okta.audit":                                    oktaAuditProjections,
	"okta.authenticator":                            oktaAuthenticatorProjections,
	"okta.threat_insight":                           oktaThreatInsightProjections,
	"okta.trusted_origin":                           oktaTrustedOriginProjections,
	"panopticon.alert":                              panopticonAlertProjections,
	"panopticon.case":                               panopticonCaseProjections,
	"panopticon.ioc":                                panopticonIOCProjections,
	"google_workspace.user":                         googleWorkspaceUserProjections,
	"google_workspace.group":                        googleWorkspaceGroupProjections,
	"google_workspace.group_member":                 googleWorkspaceGroupMemberProjections,
	"google_workspace.role_assignment":              googleWorkspaceRoleAssignmentProjections,
	"google_workspace.audit":                        googleWorkspaceAuditProjections,
	"grc.framework":                                 grcFrameworkProjections,
	"grc.control":                                   grcControlProjections,
	"grc.control_test":                              grcControlTestProjections,
	"grc.policy":                                    grcPolicyProjections,
	"grc.policy_template":                           grcPolicyTemplateProjections,
	"grc.policy_version":                            grcPolicyVersionProjections,
	"grc.policy_approval":                           grcPolicyApprovalProjections,
	"grc.policy_acceptance":                         grcPolicyAcceptanceProjections,
	"grc.policy_review":                             grcPolicyReviewProjections,
	"grc.policy_exception":                          grcPolicyExceptionProjections,
	"grc.policy_reminder":                           grcPolicyReminderProjections,
	"grc.document":                                  grcDocumentProjections,
	"grc.contract":                                  grcContractProjections,
	"grc.security_review":                           grcSecurityReviewProjections,
	"grc.security_questionnaire":                    grcSecurityQuestionnaireProjections,
	"grc.penetration_test":                          grcPenetrationTestProjections,
	"grc.assurance_document":                        grcAssuranceDocumentProjections,
	"grc.regulatory_notification":                   grcRegulatoryNotificationProjections,
	"grc.recovery_objective":                        grcRecoveryObjectiveProjections,
	"grc.authorization_package":                     grcAuthorizationPackageProjections,
	"grc.poam_item":                                 grcPOAMItemProjections,
	"grc.training_attestation":                      grcTrainingAttestationProjections,
	"grc.discovered_vendor":                         grcDiscoveredVendorProjections,
	"grc.event_log":                                 grcEventLogProjections,
	"grc.group":                                     grcGroupProjections,
	"grc.vendor_risk_attribute":                     grcVendorRiskAttributeProjections,
	"grc.vendor":                                    grcVendorProjections,
	"grc.vulnerability":                             grcVulnerabilityProjections,
	"grc.vulnerability_remediation":                 grcVulnerabilityRemediationProjections,
	"grc.vulnerable_asset":                          grcVulnerableAssetProjections,
	"grc.monitored_computer":                        grcMonitoredComputerProjections,
	"grc.risk_scenario":                             grcRiskScenarioProjections,
	"grc.person":                                    grcPersonProjections,
	"grc.user":                                      grcUserProjections,
	"grc.integration":                               grcIntegrationProjections,
	"kubernetes.ingress":                            kubernetesIngressProjections,
	"kubernetes.node":                               kubernetesNodeProjections,
	"kubernetes.service":                            kubernetesServiceProjections,
	"kubernetes.service_account":                    kubernetesServiceAccountProjections,
	"kubernetes.rbac_binding":                       kubernetesRBACBindingProjections,
	"kubernetes.rbac_role":                          kubernetesRBACRoleProjections,
	"kubernetes.workload":                           kubernetesWorkloadProjections,
	"kubernetes.workload_identity_binding":          kubernetesWorkloadIdentityBindingProjections,
	"anthropic.api_key":                             anthropicCredentialProjections,
	"anthropic.analytics_cost":                      anthropicUsageMetricProjections,
	"anthropic.compliance_activity":                 anthropicComplianceActivityProjections,
	"anthropic.compliance_group":                    anthropicComplianceGroupProjections,
	"anthropic.compliance_group_member":             anthropicComplianceGroupMemberProjections,
	"anthropic.compliance_organization":             anthropicOrganizationProjections,
	"anthropic.compliance_organization_setting":     anthropicGovernanceControlProjections,
	"anthropic.compliance_organization_user":        anthropicUserProjections,
	"anthropic.compliance_project":                  anthropicProjectProjections,
	"anthropic.compliance_project_collaborator":     anthropicProjectCollaboratorProjections,
	"anthropic.compliance_role":                     anthropicComplianceRoleProjections,
	"anthropic.compliance_role_permission":          anthropicComplianceRolePermissionProjections,
	"anthropic.cost_report":                         anthropicUsageMetricProjections,
	"anthropic.external_key":                        anthropicCredentialProjections,
	"anthropic.federation_issuer":                   anthropicFederationIssuerProjections,
	"anthropic.federation_rule":                     anthropicFederationRuleProjections,
	"anthropic.invite":                              anthropicInviteProjections,
	"anthropic.organization":                        anthropicOrganizationProjections,
	"anthropic.rate_limit":                          anthropicGovernanceControlProjections,
	"anthropic.service_account":                     anthropicServiceAccountProjections,
	"anthropic.spend_limit":                         anthropicGovernanceControlProjections,
	"anthropic.spend_limit_increase_request":        anthropicGovernanceControlProjections,
	"anthropic.usage_report_claude_code":            anthropicUsageMetricProjections,
	"anthropic.usage_report_message":                anthropicUsageMetricProjections,
	"anthropic.user":                                anthropicUserProjections,
	"anthropic.workspace":                           anthropicWorkspaceProjections,
	"anthropic.workspace_member":                    anthropicWorkspaceMemberProjections,
	"anthropic.workspace_rate_limit":                anthropicGovernanceControlProjections,
	"cloudflare.access_application":                 cloudflareAccountScopedInventoryProjections,
	"cloudflare.access_group":                       cloudflareAccountScopedInventoryProjections,
	"cloudflare.account":                            cloudflareAccountProjections,
	"cloudflare.account_ruleset":                    cloudflareAccountScopedInventoryProjections,
	"cloudflare.audit_log":                          genericInventoryProjections,
	"cloudflare.dns_record":                         cloudflareDNSRecordProjections,
	"cloudflare.gateway_rule":                       cloudflareAccountScopedInventoryProjections,
	"cloudflare.load_balancer":                      cloudflareLoadBalancerProjections,
	"cloudflare.load_balancer_pool":                 cloudflareAccountScopedInventoryProjections,
	"cloudflare.member":                             cloudflareMemberProjections,
	"cloudflare.role":                               cloudflareRoleProjections,
	"cloudflare.worker_script":                      cloudflareAccountScopedInventoryProjections,
	"cloudflare.zone":                               cloudflareZoneProjections,
	"cloudflare.zone_access_application":            cloudflareZoneScopedInventoryProjections,
	"cloudflare.zone_access_group":                  cloudflareZoneScopedInventoryProjections,
	"cloudflare.zone_ruleset":                       cloudflareZoneScopedInventoryProjections,
	"duo.endpoint":                                  duoEndpointProjections,
	"duo.group":                                     duoGroupProjections,
	"duo.phone":                                     duoPhoneProjections,
	"duo.token":                                     duoTokenProjections,
	"duo.user":                                      duoUserProjections,
	"duo.web_authn_credential":                      duoWebAuthnCredentialProjections,
	"email_domain_health.health":                    emailDomainHealthProjections,
	"kubernetes.cluster":                            genericInventoryProjections,
	"kubernetes.container":                          kubernetesContainerProjections,
	"kubernetes.namespace":                          genericInventoryProjections,
	"kubernetes.pod":                                kubernetesPodProjections,
	"langchain.api_key":                             langChainCredentialProjections,
	"langchain.audit_log":                           langChainAuditProjections,
	"langchain.dataset":                             genericInventoryProjections,
	"langchain.feedback":                            genericInventoryProjections,
	"langchain.organization":                        langChainOrganizationProjections,
	"langchain.organization_member":                 langChainOrganizationMemberProjections,
	"langchain.project":                             langChainProjectProjections,
	"langchain.role":                                langChainRoleProjections,
	"langchain.run":                                 langChainUsageMetricProjections,
	"langchain.service_account":                     langChainServiceAccountProjections,
	"langchain.usage_limit":                         langChainGovernanceControlProjections,
	"langchain.workspace":                           langChainWorkspaceProjections,
	"langchain.workspace_member":                    langChainWorkspaceMemberProjections,
	"langfuse.annotation_queue":                     genericInventoryProjections,
	"langfuse.api_key":                              langfuseCredentialProjections,
	"langfuse.metric":                               langfuseUsageMetricProjections,
	"langfuse.observation":                          langfuseUsageMetricProjections,
	"langfuse.project":                              langfuseProjectProjections,
	"langfuse.project_member":                       langfuseProjectMemberProjections,
	"langfuse.prompt":                               genericInventoryProjections,
	"langfuse.score":                                genericInventoryProjections,
	"langfuse.session":                              genericInventoryProjections,
	"langfuse.trace":                                langfuseUsageMetricProjections,
	"openai.admin_api_key":                          openAIAPIKeyProjections,
	"openai.api_key":                                openAIAPIKeyProjections,
	"openai.audit_log":                              openAIAuditProjections,
	"openai.certificate":                            openAIGovernanceControlProjections,
	"openai.cost":                                   openAIUsageMetricProjections,
	"openai.data_retention":                         openAIGovernanceControlProjections,
	"openai.group":                                  openAIGroupProjections,
	"openai.group_role":                             openAIGroupRoleProjections,
	"openai.group_user":                             openAIGroupUserProjections,
	"openai.invite":                                 openAIInviteProjections,
	"openai.project":                                openAIProjectProjections,
	"openai.project_api_key":                        openAIAPIKeyProjections,
	"openai.project_certificate":                    openAIGovernanceControlProjections,
	"openai.project_data_retention":                 openAIGovernanceControlProjections,
	"openai.project_group":                          openAIProjectGroupProjections,
	"openai.project_group_role":                     openAIProjectGroupRoleProjections,
	"openai.project_hosted_tool_permission":         openAIProjectEntitlementProjections,
	"openai.project_model_permission":               openAIProjectEntitlementProjections,
	"openai.project_rate_limit":                     openAIGovernanceControlProjections,
	"openai.project_role":                           openAIRoleProjections,
	"openai.project_service_account":                openAIServiceAccountProjections,
	"openai.project_spend_alert":                    openAIGovernanceControlProjections,
	"openai.project_user":                           openAIProjectUserProjections,
	"openai.project_user_role":                      openAIProjectUserRoleProjections,
	"openai.role":                                   openAIRoleProjections,
	"openai.service_account":                        openAIServiceAccountProjections,
	"openai.spend_alert":                            openAIGovernanceControlProjections,
	"openai.usage_audio_speech":                     openAIUsageMetricProjections,
	"openai.usage_audio_transcription":              openAIUsageMetricProjections,
	"openai.usage_code_interpreter_session":         openAIUsageMetricProjections,
	"openai.usage_completion":                       openAIUsageMetricProjections,
	"openai.usage_embedding":                        openAIUsageMetricProjections,
	"openai.usage_file_search_call":                 openAIUsageMetricProjections,
	"openai.usage_image":                            openAIUsageMetricProjections,
	"openai.usage_moderation":                       openAIUsageMetricProjections,
	"openai.usage_vector_store":                     openAIUsageMetricProjections,
	"openai.usage_web_search_call":                  openAIUsageMetricProjections,
	"openai.user":                                   openAIUserProjections,
	"openai.user_role":                              openAIUserRoleProjections,
	"meraki.accesspolicy":                           merakiAccesspolicyProjections,
	"meraki.eventtype":                              merakiEventtypeProjections,
	"meraki.merakiauthuser":                         merakiMerakiauthuserProjections,
	"meraki.organization":                           merakiOrganizationProjections,
	"writer.application":                            genericInventoryProjections,
	"writer.application_graph":                      genericInventoryProjections,
	"writer.application_job":                        genericInventoryProjections,
	"writer.file":                                   genericInventoryProjections,
	"writer.graph":                                  genericInventoryProjections,
	"writer.model":                                  genericInventoryProjections,
	"pagerduty.escalation_policy":                   pagerDutyEscalationPolicyProjections,
	"pagerduty.integration":                         pagerDutyIntegrationProjections,
	"pagerduty.schedule":                            genericInventoryProjections,
	"pagerduty.service":                             pagerDutyServiceProjections,
	"pagerduty.team":                                genericInventoryProjections,
	"pagerduty.user":                                pagerDutyUserProjections,
	"pagerduty.vendor":                              genericInventoryProjections,
	"probely.event":                                 probelyEventProjections,
	"probely.framework":                             probelyFrameworkProjections,
	"probely.needs_attention_top":                   probelyNeedsAttentionTopProjections,
	"probely.user":                                  probelyUserProjections,
	"slack.channel":                                 slackTeamScopedProjections,
	"slack.team":                                    slackTeamProjections,
	"slack.user":                                    slackUserProjections,
	"slack.user_group":                              slackTeamScopedProjections,
	"tailscale.device":                              tailscaleDeviceProjections,
	"tailscale.grant":                               tailscaleGrantProjections,
	"tailscale.group":                               tailscaleGroupProjections,
	"tailscale.service":                             tailscaleServiceProjections,
	"tailscale.tag":                                 tailscaleTagProjections,
	"tailscale.tailnet":                             tailscaleTailnetProjections,
	"tailscale.user":                                tailscaleUserProjections,
	"trivy.fix":                                     trivyFixProjections,
	"trivy.image_package":                           trivyImagePackageProjections,
	"trivy.image_scan":                              trivyImageScanProjections,
	"trivy.image_vulnerability":                     trivyImageVulnerabilityProjections,
	"evidence_cas.object":                           runtimeEvidenceProjections,
	"runtime.evidence":                              runtimeEvidenceProjections,
	"sdk.integration_posture":                       sdkIntegrationPostureProjections,
	"security_tooling_map.control_mapping":          securityToolingMapControlMappingProjections,
	"security_tooling_map.tool":                     securityToolingMapToolProjections,
	"sentinelone.activity":                          sentinelOneActivityProjections,
	"sentinelone.agent":                             sentinelOneAgentProjections,
	"sentinelone.application_inventory":             sentinelOneApplicationInventoryProjections,
	"sentinelone.exclusion":                         sentinelOneExclusionProjections,
	"sentinelone.group":                             sentinelOneGroupProjections,
	"sentinelone.site":                              sentinelOneSiteProjections,
	"sentinelone.threat":                            sentinelOneThreatProjections,
	"sentinelone.vulnerability":                     sentinelOneVulnerabilityProjections,
	"trusted_endpoint.action_outcome":               trustedEndpointProjections,
	"trusted_endpoint.agent_identity":               trustedEndpointProjections,
	"trusted_endpoint.ai_session_summary":           trustedEndpointProjections,
	"trusted_endpoint.ai_workflow_risk":             trustedEndpointProjections,
	"trusted_endpoint.grc_evidence":                 trustedEndpointProjections,
	"trusted_endpoint.host_posture":                 trustedEndpointProjections,
	"trusted_endpoint.repo_worktree_context":        trustedEndpointProjections,
	"trusted_endpoint.security_finding":             trustedEndpointProjections,
	"trusted_endpoint.trust_gate_decision":          trustedEndpointProjections,
	"vulnview.asset":                                vulnViewAssetProjections,
	"vulnview.dns_alert":                            vulnViewDNSAlertProjections,
	"vulnview.scan":                                 vulnViewScanProjections,
	"vulnview.site":                                 vulnViewSiteProjections,
	"vulnview.vulnerability":                        vulnViewVulnerabilityProjections,
	// hashicorp_vault generated projectors (sourcegen promotion)
	"hashicorp_vault.users":        hashicorpVaultUsersProjections,
	"hashicorp_vault.secrets":      hashicorpVaultSecretsProjections,
	"hashicorp_vault.audit_events": hashicorpVaultAuditEventsProjections,
	// doppler generated projectors (sourcegen promotion)
	"doppler.secrets":      dopplerSecretsProjections,
	"doppler.projects":     dopplerProjectsProjections,
	"doppler.audit_events": dopplerAuditEventsProjections,
	// akeyless generated projectors (sourcegen promotion)
	"akeyless.items":        akeylessItemsProjections,
	"akeyless.auth_methods": akeylessAuthMethodsProjections,
	"akeyless.roles":        akeylessRolesProjections,
	"akeyless.audit_events": akeylessAuditEventsProjections,
	// conjur generated projectors (sourcegen promotion)
	"conjur.authenticator": conjurAuthenticatorProjections,
	"conjur.resource":      conjurResourceProjections,
	"conjur.resource_2":    conjurResource2Projections,
	"conjur.resource_3":    conjurResource3Projections,

	// box generated projectors (sourcegen promotion)
	"box.audit_events":   boxAuditEventsProjections,
	"box.content_assets": boxContentAssetsProjections,
	"box.users":          boxUsersProjections,

	// asana generated projectors (sourcegen promotion)
	"asana.audit_events": asanaAuditEventsProjections,
	"asana.projects":     asanaProjectsProjections,
	"asana.users":        asanaUsersProjections,

	// twilio generated projectors (sourcegen promotion)
	"twilio.accounts":     twilioAccountsProjections,
	"twilio.audit_events": twilioAuditEventsProjections,
	"twilio.keys":         twilioKeysProjections,

	// linode generated projectors (sourcegen promotion)
	"linode.credential": linodeCredentialProjections,
	"linode.event":      linodeEventProjections,
	"linode.issue":      linodeIssueProjections,
	"linode.user":       linodeUserProjections,

	// discord generated projectors (sourcegen promotion)
	"discord.audit_log":  discordAuditLogProjections,
	"discord.member":     discordMemberProjections,
	"discord.permission": discordPermissionProjections,
	"discord.role":       discordRoleProjections,

	// awscollectorgen:projector (insert new kind projectors above this line)
}}

func init() {
	registerCatalogRuntimeProjectors(builtinRegistry.projectors)
}

// BuiltinRegistry returns the default source event projector registry.
func BuiltinRegistry() *Registry {
	return builtinRegistry
}

// Register adds a handler for the kind prefixes it declares via Handles.
func (r *Registry) Register(h ProjectionHandler) {
	if r == nil || h == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handlers == nil {
		r.handlers = make(map[string]ProjectionHandler)
	}
	for _, prefix := range h.Handles() {
		r.handlers[prefix] = h
	}
}

// Lookup finds the handler for a given event kind by trying progressively
// shorter prefixes until a match is found.
func (r *Registry) Lookup(kind string) (ProjectionHandler, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.handlers == nil {
		return nil, false
	}
	for i := len(kind); i > 0; i-- {
		if h, ok := r.handlers[kind[:i]]; ok {
			return h, true
		}
	}
	return nil, false
}

// Kinds returns sorted registered event kinds.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	kinds := make([]string, 0, len(r.projectors))
	for kind := range r.projectors {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// Project applies the registered projector for an event.
func (r *Registry) Project(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if r == nil {
		return nil, nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	project, ok := r.projectors[strings.TrimSpace(event.GetKind())]
	if !ok {
		return nil, nil, nil
	}
	entities, links, err := project(event)
	if err != nil {
		return nil, nil, err
	}
	if err := ports.ValidateProjectedTenantScopes(entities, links); err != nil {
		return nil, nil, err
	}
	return entities, links, nil
}

// ProjectEvent projects one event through the built-in registry without stores.
func ProjectEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return BuiltinRegistry().Project(event)
}
