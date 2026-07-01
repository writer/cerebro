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
	"auth0.client_grants":                           auth0ClientGrantsProjections,
	"auth0.clients":                                 auth0ClientsProjections,
	"auth0.connections":                             auth0ConnectionsProjections,
	"auth0.grants":                                  auth0GrantsProjections,
	"auth0.guardian_factors":                        auth0GuardianFactorsProjections,
	"auth0.organization_members":                    auth0OrganizationMembersProjections,
	"auth0.organizations":                           auth0OrganizationsProjections,
	"auth0.resource_servers":                        auth0ResourceServersProjections,
	"auth0.roles":                                   auth0RolesProjections,
	"auth0.user_authentication_methods":             auth0UserAuthenticationMethodsProjections,
	"auth0.user_roles":                              auth0UserRolesProjections,
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
	"datadog.audit_events":                          datadogAuditEventProjections,
	"datadog.dashboards":                            datadogTaggedResourceProjections,
	"datadog.incidents":                             datadogIncidentProjections,
	"datadog.monitors":                              datadogTaggedResourceProjections,
	"datadog.roles":                                 genericInventoryProjections,
	"datadog.slos":                                  datadogTaggedResourceProjections,
	"datadog.teams":                                 genericInventoryProjections,
	"datadog.users":                                 datadogUserProjections,
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
	"aws.account_contact":                           awsAccountContactProjections,
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
	"aws.cloudformation_stack":                      awsCloudResourceProjections,
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
	"azure.authentication_methods_policy":           azureCloudResourceProjections,
	"azure.asset_metadata":                          azureCloudResourceProjections,
	"azure.authorization_policy":                    azureCloudResourceProjections,
	"azure.cognitive_services_account":              azureCloudResourceProjections,
	"azure.cognitive_services_deployment":           azureCloudResourceProjections,
	"azure.conditional_access_policy":               azurePolicyRuleProjections,
	"azure.container_registry":                      azureCloudResourceProjections,
	"azure.cosmos_account":                          azureCloudResourceProjections,
	"azure.cosmos_postgresql":                       azureCloudResourceProjections,
	"azure.cosmos_postgresql_firewall_rule":         azureCloudResourceProjections,
	"azure.databricks_workspace":                    azureCloudResourceProjections,
	"azure.defender_alert":                          azureCloudResourceProjections,
	"azure.defender_config":                         azureCloudResourceProjections,
	"azure.defender_incident":                       azureCloudResourceProjections,
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
	"azure.identity_risk_detection":                 azureCloudResourceProjections,
	"azure.identity_risky_user":                     azureUserProjections,
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
	"azure.purview_account":                         azureCloudResourceProjections,
	"azure.purview_private_endpoint_connection":     azureCloudResourceProjections,
	"azure.purview_retention_label":                 azureCloudResourceProjections,
	"azure.purview_sensitivity_label":               azureCloudResourceProjections,
	"azure.resource_exposure":                       azureResourceExposureProjections,
	"azure.role":                                    azureCloudResourceProjections,
	"azure.route_table":                             azureCloudResourceProjections,
	"azure.secure_score":                            azureCloudResourceProjections,
	"azure.secure_score_control":                    azureCloudResourceProjections,
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
	"grc.policy_lifecycle_event":                    grcPolicyLifecycleEventProjections,
	"grc.policy_evidence_snippet":                   grcPolicyEvidenceSnippetProjections,
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

	// abnormal_security generated projectors (sourcegen promotion)
	"abnormal_security.assets":          abnormalSecurityAssetsProjections,
	"abnormal_security.audit_events":    abnormalSecurityAuditEventsProjections,
	"abnormal_security.findings":        abnormalSecurityFindingsProjections,
	"abnormal_security.policies":        abnormalSecurityPoliciesProjections,
	"abnormal_security.vulnerabilities": abnormalSecurityVulnerabilitiesProjections,

	// abuseipdb generated projectors (sourcegen promotion)
	"abuseipdb.audit_events": abuseipdbAuditEventsProjections,
	"abuseipdb.ip_addresses": abuseipdbIpAddressesProjections,
	"abuseipdb.reports":      abuseipdbReportsProjections,

	// activecampaign generated projectors (sourcegen promotion)
	"activecampaign.accounts":     activecampaignAccountsProjections,
	"activecampaign.audit_events": activecampaignAuditEventsProjections,
	"activecampaign.policies":     activecampaignPoliciesProjections,
	"activecampaign.records":      activecampaignRecordsProjections,
	"activecampaign.users":        activecampaignUsersProjections,

	// activtrak generated projectors (sourcegen promotion)
	"activtrak.accounts":     activtrakAccountsProjections,
	"activtrak.audit_events": activtrakAuditEventsProjections,
	"activtrak.policies":     activtrakPoliciesProjections,
	"activtrak.records":      activtrakRecordsProjections,
	"activtrak.users":        activtrakUsersProjections,

	// acunetix generated projectors (sourcegen promotion)
	"acunetix.assets":          acunetixAssetsProjections,
	"acunetix.audit_events":    acunetixAuditEventsProjections,
	"acunetix.findings":        acunetixFindingsProjections,
	"acunetix.policies":        acunetixPoliciesProjections,
	"acunetix.vulnerabilities": acunetixVulnerabilitiesProjections,

	// ada_support generated projectors (sourcegen promotion)
	"ada_support.accounts":     adaSupportAccountsProjections,
	"ada_support.audit_events": adaSupportAuditEventsProjections,
	"ada_support.policies":     adaSupportPoliciesProjections,
	"ada_support.records":      adaSupportRecordsProjections,
	"ada_support.users":        adaSupportUsersProjections,

	// addigy generated projectors (sourcegen promotion)
	"addigy.applications": addigyApplicationsProjections,
	"addigy.audit_events": addigyAuditEventsProjections,
	"addigy.groups":       addigyGroupsProjections,
	"addigy.roles":        addigyRolesProjections,
	"addigy.users":        addigyUsersProjections,

	// adobe_workfront generated projectors (sourcegen promotion)
	"adobe_workfront.audit_events": adobeWorkfrontAuditEventsProjections,
	"adobe_workfront.documents":    adobeWorkfrontDocumentsProjections,
	"adobe_workfront.groups":       adobeWorkfrontGroupsProjections,
	"adobe_workfront.users":        adobeWorkfrontUsersProjections,
	"adobe_workfront.workspaces":   adobeWorkfrontWorkspacesProjections,

	// adp_workforce_now generated projectors (sourcegen promotion)
	"adp_workforce_now.accounts":     adpWorkforceNowAccountsProjections,
	"adp_workforce_now.audit_events": adpWorkforceNowAuditEventsProjections,
	"adp_workforce_now.policies":     adpWorkforceNowPoliciesProjections,
	"adp_workforce_now.records":      adpWorkforceNowRecordsProjections,
	"adp_workforce_now.users":        adpWorkforceNowUsersProjections,

	// agiloft generated projectors (sourcegen promotion)
	"agiloft.accounts":     agiloftAccountsProjections,
	"agiloft.audit_events": agiloftAuditEventsProjections,
	"agiloft.policies":     agiloftPoliciesProjections,
	"agiloft.records":      agiloftRecordsProjections,
	"agiloft.users":        agiloftUsersProjections,

	// aha generated projectors (sourcegen promotion)
	"aha.audit_events": ahaAuditEventsProjections,
	"aha.deployments":  ahaDeploymentsProjections,
	"aha.projects":     ahaProjectsProjections,
	"aha.repositories": ahaRepositoriesProjections,
	"aha.users":        ahaUsersProjections,

	// airbase generated projectors (sourcegen promotion)
	"airbase.accounts":     airbaseAccountsProjections,
	"airbase.audit_events": airbaseAuditEventsProjections,
	"airbase.policies":     airbasePoliciesProjections,
	"airbase.records":      airbaseRecordsProjections,
	"airbase.users":        airbaseUsersProjections,

	// airbrake generated projectors (sourcegen promotion)
	"airbrake.alerts":       airbrakeAlertsProjections,
	"airbrake.audit_events": airbrakeAuditEventsProjections,
	"airbrake.dashboards":   airbrakeDashboardsProjections,
	"airbrake.incidents":    airbrakeIncidentsProjections,
	"airbrake.monitors":     airbrakeMonitorsProjections,

	// airbyte_cloud generated projectors (sourcegen promotion)
	"airbyte_cloud.accounts":     airbyteCloudAccountsProjections,
	"airbyte_cloud.audit_events": airbyteCloudAuditEventsProjections,
	"airbyte_cloud.policies":     airbyteCloudPoliciesProjections,
	"airbyte_cloud.records":      airbyteCloudRecordsProjections,
	"airbyte_cloud.users":        airbyteCloudUsersProjections,

	// aircall generated projectors (sourcegen promotion)
	"aircall.audit_events": aircallAuditEventsProjections,
	"aircall.documents":    aircallDocumentsProjections,
	"aircall.groups":       aircallGroupsProjections,
	"aircall.users":        aircallUsersProjections,
	"aircall.workspaces":   aircallWorkspacesProjections,

	// airfocus generated projectors (sourcegen promotion)
	"airfocus.audit_events": airfocusAuditEventsProjections,
	"airfocus.deployments":  airfocusDeploymentsProjections,
	"airfocus.projects":     airfocusProjectsProjections,
	"airfocus.repositories": airfocusRepositoriesProjections,
	"airfocus.users":        airfocusUsersProjections,

	// airtable generated projectors (sourcegen promotion)
	"airtable.audit_events": airtableAuditEventsProjections,
	"airtable.projects":     airtableProjectsProjections,
	"airtable.users":        airtableUsersProjections,

	// akeneo generated projectors (sourcegen promotion)
	"akeneo.asset":                        akeneoAssetProjections,
	"akeneo.asset_families_attribute":     akeneoAssetFamiliesAttributeProjections,
	"akeneo.asset_family":                 akeneoAssetFamilyProjections,
	"akeneo.attribute":                    akeneoAttributeProjections,
	"akeneo.attribute_group":              akeneoAttributeGroupProjections,
	"akeneo.attributes_option":            akeneoAttributesOptionProjections,
	"akeneo.draft":                        akeneoDraftProjections,
	"akeneo.option":                       akeneoOptionProjections,
	"akeneo.products_draft":               akeneoProductsDraftProjections,
	"akeneo.products_uuid_draft":          akeneoProductsUuidDraftProjections,
	"akeneo.reference_entities_attribute": akeneoReferenceEntitiesAttributeProjections,
	"akeneo.v1_attribute":                 akeneoV1AttributeProjections,

	// alation generated projectors (sourcegen promotion)
	"alation.accounts":     alationAccountsProjections,
	"alation.audit_events": alationAuditEventsProjections,
	"alation.policies":     alationPoliciesProjections,
	"alation.records":      alationRecordsProjections,
	"alation.users":        alationUsersProjections,

	// alchemer generated projectors (sourcegen promotion)
	"alchemer.accounts":     alchemerAccountsProjections,
	"alchemer.audit_events": alchemerAuditEventsProjections,
	"alchemer.policies":     alchemerPoliciesProjections,
	"alchemer.records":      alchemerRecordsProjections,
	"alchemer.users":        alchemerUsersProjections,

	// alteryx generated projectors (sourcegen promotion)
	"alteryx.accounts":     alteryxAccountsProjections,
	"alteryx.audit_events": alteryxAuditEventsProjections,
	"alteryx.policies":     alteryxPoliciesProjections,
	"alteryx.records":      alteryxRecordsProjections,
	"alteryx.users":        alteryxUsersProjections,

	// amplitude generated projectors (sourcegen promotion)
	"amplitude.accounts":     amplitudeAccountsProjections,
	"amplitude.audit_events": amplitudeAuditEventsProjections,
	"amplitude.policies":     amplitudePoliciesProjections,
	"amplitude.records":      amplitudeRecordsProjections,
	"amplitude.users":        amplitudeUsersProjections,

	// anchore generated projectors (sourcegen promotion)
	"anchore.assets":          anchoreAssetsProjections,
	"anchore.findings":        anchoreFindingsProjections,
	"anchore.vulnerabilities": anchoreVulnerabilitiesProjections,

	// anecdotes generated projectors (sourcegen promotion)
	"anecdotes.assets":          anecdotesAssetsProjections,
	"anecdotes.audit_events":    anecdotesAuditEventsProjections,
	"anecdotes.findings":        anecdotesFindingsProjections,
	"anecdotes.policies":        anecdotesPoliciesProjections,
	"anecdotes.vulnerabilities": anecdotesVulnerabilitiesProjections,

	// anomali_threatstream generated projectors (sourcegen promotion)
	"anomali_threatstream.assets":          anomaliThreatstreamAssetsProjections,
	"anomali_threatstream.audit_events":    anomaliThreatstreamAuditEventsProjections,
	"anomali_threatstream.findings":        anomaliThreatstreamFindingsProjections,
	"anomali_threatstream.policies":        anomaliThreatstreamPoliciesProjections,
	"anomali_threatstream.vulnerabilities": anomaliThreatstreamVulnerabilitiesProjections,

	// anomalo generated projectors (sourcegen promotion)
	"anomalo.accounts":     anomaloAccountsProjections,
	"anomalo.audit_events": anomaloAuditEventsProjections,
	"anomalo.policies":     anomaloPoliciesProjections,
	"anomalo.records":      anomaloRecordsProjections,
	"anomalo.users":        anomaloUsersProjections,

	// apache generated projectors (sourcegen promotion)
	"apache.eventlog":   apacheEventlogProjections,
	"apache.permission": apachePermissionProjections,
	"apache.role":       apacheRoleProjections,
	"apache.user":       apacheUserProjections,

	// apacta generated projectors (sourcegen promotion)
	"apacta.activity":                    apactaActivityProjections,
	"apacta.changelog":                   apactaChangelogProjections,
	"apacta.city":                        apactaCityProjections,
	"apacta.contact_person":              apactaContactPersonProjections,
	"apacta.event":                       apactaEventProjections,
	"apacta.mass_messages_user":          apactaMassMessagesUserProjections,
	"apacta.projects_user":               apactaProjectsUserProjections,
	"apacta.role":                        apactaRoleProjections,
	"apacta.time_entry_rule_group":       apactaTimeEntryRuleGroupProjections,
	"apacta.user":                        apactaUserProjections,
	"apacta.user_custom_field_attribute": apactaUserCustomFieldAttributeProjections,
	"apacta.user_custom_field_value":     apactaUserCustomFieldValueProjections,

	// api2cart generated projectors (sourcegen promotion)
	"api2cart.attribute_attributeset_list_json": api2cartAttributeAttributesetListJsonProjections,
	"api2cart.attribute_group_list_json":        api2cartAttributeGroupListJsonProjections,

	// apideck generated projectors (sourcegen promotion)
	"apideck.bill":           apideckBillProjections,
	"apideck.credit_note":    apideckCreditNoteProjections,
	"apideck.customer":       apideckCustomerProjections,
	"apideck.ledger_account": apideckLedgerAccountProjections,

	// apigee generated projectors (sourcegen promotion)
	"apigee.audit_events": apigeeAuditEventsProjections,
	"apigee.deployments":  apigeeDeploymentsProjections,
	"apigee.projects":     apigeeProjectsProjections,
	"apigee.repositories": apigeeRepositoriesProjections,
	"apigee.users":        apigeeUsersProjections,

	// apiiro generated projectors (sourcegen promotion)
	"apiiro.assets":          apiiroAssetsProjections,
	"apiiro.audit_events":    apiiroAuditEventsProjections,
	"apiiro.findings":        apiiroFindingsProjections,
	"apiiro.policies":        apiiroPoliciesProjections,
	"apiiro.vulnerabilities": apiiroVulnerabilitiesProjections,

	// apollo generated projectors (sourcegen promotion)
	"apollo.accounts":     apolloAccountsProjections,
	"apollo.audit_events": apolloAuditEventsProjections,
	"apollo.policies":     apolloPoliciesProjections,
	"apollo.records":      apolloRecordsProjections,
	"apollo.users":        apolloUsersProjections,

	// appcircle generated projectors (sourcegen promotion)
	"appcircle.audit_events": appcircleAuditEventsProjections,
	"appcircle.deployments":  appcircleDeploymentsProjections,
	"appcircle.projects":     appcircleProjectsProjections,
	"appcircle.repositories": appcircleRepositoriesProjections,
	"appcircle.users":        appcircleUsersProjections,

	// appdynamics generated projectors (sourcegen promotion)
	"appdynamics.alerts":       appdynamicsAlertsProjections,
	"appdynamics.audit_events": appdynamicsAuditEventsProjections,
	"appdynamics.dashboards":   appdynamicsDashboardsProjections,
	"appdynamics.incidents":    appdynamicsIncidentsProjections,
	"appdynamics.monitors":     appdynamicsMonitorsProjections,

	// appfolio generated projectors (sourcegen promotion)
	"appfolio.accounts":     appfolioAccountsProjections,
	"appfolio.audit_events": appfolioAuditEventsProjections,
	"appfolio.policies":     appfolioPoliciesProjections,
	"appfolio.records":      appfolioRecordsProjections,
	"appfolio.users":        appfolioUsersProjections,

	// appgate generated projectors (sourcegen promotion)
	"appgate.applications": appgateApplicationsProjections,
	"appgate.audit_events": appgateAuditEventsProjections,
	"appgate.groups":       appgateGroupsProjections,
	"appgate.roles":        appgateRolesProjections,
	"appgate.users":        appgateUsersProjections,

	// applitools generated projectors (sourcegen promotion)
	"applitools.audit_events": applitoolsAuditEventsProjections,
	"applitools.deployments":  applitoolsDeploymentsProjections,
	"applitools.projects":     applitoolsProjectsProjections,
	"applitools.repositories": applitoolsRepositoriesProjections,
	"applitools.users":        applitoolsUsersProjections,

	// appomni generated projectors (sourcegen promotion)
	"appomni.assets":          appomniAssetsProjections,
	"appomni.audit_events":    appomniAuditEventsProjections,
	"appomni.findings":        appomniFindingsProjections,
	"appomni.policies":        appomniPoliciesProjections,
	"appomni.vulnerabilities": appomniVulnerabilitiesProjections,

	// appveyor generated projectors (sourcegen promotion)
	"appveyor.artifact":     appveyorArtifactProjections,
	"appveyor.collaborator": appveyorCollaboratorProjections,
	"appveyor.role":         appveyorRoleProjections,
	"appveyor.user":         appveyorUserProjections,

	// appwrite generated projectors (sourcegen promotion)
	"appwrite.continent":  appwriteContinentProjections,
	"appwrite.log":        appwriteLogProjections,
	"appwrite.membership": appwriteMembershipProjections,
	"appwrite.team":       appwriteTeamProjections,

	// aqua_security generated projectors (sourcegen promotion)
	"aqua_security.assets":          aquaSecurityAssetsProjections,
	"aqua_security.findings":        aquaSecurityFindingsProjections,
	"aqua_security.vulnerabilities": aquaSecurityVulnerabilitiesProjections,

	// arctic_wolf generated projectors (sourcegen promotion)
	"arctic_wolf.assets":          arcticWolfAssetsProjections,
	"arctic_wolf.audit_events":    arcticWolfAuditEventsProjections,
	"arctic_wolf.findings":        arcticWolfFindingsProjections,
	"arctic_wolf.policies":        arcticWolfPoliciesProjections,
	"arctic_wolf.vulnerabilities": arcticWolfVulnerabilitiesProjections,

	// argo_cd generated projectors (sourcegen promotion)
	"argo_cd.audit_events": argoCdAuditEventsProjections,
	"argo_cd.findings":     argoCdFindingsProjections,
	"argo_cd.pipelines":    argoCdPipelinesProjections,

	// armis generated projectors (sourcegen promotion)
	"armis.assets":          armisAssetsProjections,
	"armis.audit_events":    armisAuditEventsProjections,
	"armis.findings":        armisFindingsProjections,
	"armis.policies":        armisPoliciesProjections,
	"armis.vulnerabilities": armisVulnerabilitiesProjections,

	// armo_platform generated projectors (sourcegen promotion)
	"armo_platform.assets":          armoPlatformAssetsProjections,
	"armo_platform.audit_events":    armoPlatformAuditEventsProjections,
	"armo_platform.findings":        armoPlatformFindingsProjections,
	"armo_platform.policies":        armoPlatformPoliciesProjections,
	"armo_platform.vulnerabilities": armoPlatformVulnerabilitiesProjections,

	// armorcode generated projectors (sourcegen promotion)
	"armorcode.assets":          armorcodeAssetsProjections,
	"armorcode.audit_events":    armorcodeAuditEventsProjections,
	"armorcode.findings":        armorcodeFindingsProjections,
	"armorcode.policies":        armorcodePoliciesProjections,
	"armorcode.vulnerabilities": armorcodeVulnerabilitiesProjections,

	// arnica_security generated projectors (sourcegen promotion)
	"arnica_security.assets":          arnicaSecurityAssetsProjections,
	"arnica_security.audit_events":    arnicaSecurityAuditEventsProjections,
	"arnica_security.findings":        arnicaSecurityFindingsProjections,
	"arnica_security.policies":        arnicaSecurityPoliciesProjections,
	"arnica_security.vulnerabilities": arnicaSecurityVulnerabilitiesProjections,

	// ashby generated projectors (sourcegen promotion)
	"ashby.accounts":     ashbyAccountsProjections,
	"ashby.audit_events": ashbyAuditEventsProjections,
	"ashby.policies":     ashbyPoliciesProjections,
	"ashby.records":      ashbyRecordsProjections,
	"ashby.users":        ashbyUsersProjections,

	// astrix_security generated projectors (sourcegen promotion)
	"astrix_security.assets":          astrixSecurityAssetsProjections,
	"astrix_security.audit_events":    astrixSecurityAuditEventsProjections,
	"astrix_security.findings":        astrixSecurityFindingsProjections,
	"astrix_security.policies":        astrixSecurityPoliciesProjections,
	"astrix_security.vulnerabilities": astrixSecurityVulnerabilitiesProjections,

	// atlan generated projectors (sourcegen promotion)
	"atlan.accounts":     atlanAccountsProjections,
	"atlan.audit_events": atlanAuditEventsProjections,
	"atlan.policies":     atlanPoliciesProjections,
	"atlan.records":      atlanRecordsProjections,
	"atlan.users":        atlanUsersProjections,

	// attackiq generated projectors (sourcegen promotion)
	"attackiq.assets":          attackiqAssetsProjections,
	"attackiq.audit_events":    attackiqAuditEventsProjections,
	"attackiq.findings":        attackiqFindingsProjections,
	"attackiq.policies":        attackiqPoliciesProjections,
	"attackiq.vulnerabilities": attackiqVulnerabilitiesProjections,

	// auditboard generated projectors (sourcegen promotion)
	"auditboard.controls": auditboardControlsProjections,
	"auditboard.findings": auditboardFindingsProjections,
	"auditboard.users":    auditboardUsersProjections,

	// authentik_cloud generated projectors (sourcegen promotion)
	"authentik_cloud.applications": authentikCloudApplicationsProjections,
	"authentik_cloud.audit_events": authentikCloudAuditEventsProjections,
	"authentik_cloud.groups":       authentikCloudGroupsProjections,
	"authentik_cloud.roles":        authentikCloudRolesProjections,
	"authentik_cloud.users":        authentikCloudUsersProjections,

	// autotask generated projectors (sourcegen promotion)
	"autotask.entityinformation_field": autotaskEntityinformationFieldProjections,
	"autotask.excludedrole":            autotaskExcludedroleProjections,
	"autotask.field":                   autotaskFieldProjections,
	"autotask.userdefinedfield":        autotaskUserdefinedfieldProjections,

	// avature generated projectors (sourcegen promotion)
	"avature.accounts":     avatureAccountsProjections,
	"avature.audit_events": avatureAuditEventsProjections,
	"avature.policies":     avaturePoliciesProjections,
	"avature.records":      avatureRecordsProjections,
	"avature.users":        avatureUsersProjections,

	// avaza generated projectors (sourcegen promotion)
	"avaza.bill":          avazaBillProjections,
	"avaza.billpayment":   avazaBillpaymentProjections,
	"avaza.company":       avazaCompanyProjections,
	"avaza.contact":       avazaContactProjections,
	"avaza.creditnote":    avazaCreditnoteProjections,
	"avaza.currency":      avazaCurrencyProjections,
	"avaza.estimate":      avazaEstimateProjections,
	"avaza.expense":       avazaExpenseProjections,
	"avaza.lookup":        avazaLookupProjections,
	"avaza.projectmember": avazaProjectmemberProjections,
	"avaza.userprofile":   avazaUserprofileProjections,
	"avaza.webhook":       avazaWebhookProjections,

	// aws_bedrock generated projectors (sourcegen promotion)
	"aws_bedrock.custom_models":                 awsBedrockCustomModelsProjections,
	"aws_bedrock.foundation_models":             awsBedrockFoundationModelsProjections,
	"aws_bedrock.guardrails":                    awsBedrockGuardrailsProjections,
	"aws_bedrock.model_customization_jobs":      awsBedrockModelCustomizationJobsProjections,
	"aws_bedrock.provisioned_model_throughputs": awsBedrockProvisionedModelThroughputsProjections,

	// axiom generated projectors (sourcegen promotion)
	"axiom.alerts":       axiomAlertsProjections,
	"axiom.audit_events": axiomAuditEventsProjections,
	"axiom.dashboards":   axiomDashboardsProjections,
	"axiom.incidents":    axiomIncidentsProjections,
	"axiom.monitors":     axiomMonitorsProjections,

	// axonius generated projectors (sourcegen promotion)
	"axonius.assets":          axoniusAssetsProjections,
	"axonius.audit_events":    axoniusAuditEventsProjections,
	"axonius.findings":        axoniusFindingsProjections,
	"axonius.policies":        axoniusPoliciesProjections,
	"axonius.vulnerabilities": axoniusVulnerabilitiesProjections,

	// azure_devops generated projectors (sourcegen promotion)
	"azure_devops.audit_events": azureDevopsAuditEventsProjections,
	"azure_devops.repositories": azureDevopsRepositoriesProjections,
	"azure_devops.users":        azureDevopsUsersProjections,

	// azure_openai generated projectors (sourcegen promotion)
	"azure_openai.deployments":                  azureOpenaiDeploymentsProjections,
	"azure_openai.model_catalog":                azureOpenaiModelCatalogProjections,
	"azure_openai.private_endpoint_connections": azureOpenaiPrivateEndpointConnectionsProjections,
	"azure_openai.rai_blocklists":               azureOpenaiRaiBlocklistsProjections,
	"azure_openai.rai_policies":                 azureOpenaiRaiPoliciesProjections,

	// bamboohr generated projectors (sourcegen promotion)
	"bamboohr.audit_events": bamboohrAuditEventsProjections,
	"bamboohr.groups":       bamboohrGroupsProjections,
	"bamboohr.users":        bamboohrUsersProjections,

	// basecamp generated projectors (sourcegen promotion)
	"basecamp.audit_events": basecampAuditEventsProjections,
	"basecamp.documents":    basecampDocumentsProjections,
	"basecamp.groups":       basecampGroupsProjections,
	"basecamp.users":        basecampUsersProjections,
	"basecamp.workspaces":   basecampWorkspacesProjections,

	// baselime generated projectors (sourcegen promotion)
	"baselime.alerts":       baselimeAlertsProjections,
	"baselime.audit_events": baselimeAuditEventsProjections,
	"baselime.dashboards":   baselimeDashboardsProjections,
	"baselime.incidents":    baselimeIncidentsProjections,
	"baselime.monitors":     baselimeMonitorsProjections,

	// bazaarvoice generated projectors (sourcegen promotion)
	"bazaarvoice.accounts":     bazaarvoiceAccountsProjections,
	"bazaarvoice.audit_events": bazaarvoiceAuditEventsProjections,
	"bazaarvoice.policies":     bazaarvoicePoliciesProjections,
	"bazaarvoice.records":      bazaarvoiceRecordsProjections,
	"bazaarvoice.users":        bazaarvoiceUsersProjections,

	// beeline generated projectors (sourcegen promotion)
	"beeline.accounts":     beelineAccountsProjections,
	"beeline.audit_events": beelineAuditEventsProjections,
	"beeline.policies":     beelinePoliciesProjections,
	"beeline.records":      beelineRecordsProjections,
	"beeline.users":        beelineUsersProjections,

	// beezup generated projectors (sourcegen promotion)
	"beezup.alert":          beezupAlertProjections,
	"beezup.autoimport":     beezupAutoimportProjections,
	"beezup.beezupcolumn":   beezupBeezupcolumnProjections,
	"beezup.catalogcolumn":  beezupCatalogcolumnProjections,
	"beezup.category":       beezupCategoryProjections,
	"beezup.channelcatalog": beezupChannelcatalogProjections,
	"beezup.customcolumn":   beezupCustomcolumnProjections,
	"beezup.filter":         beezupFilterProjections,
	"beezup.filteroperator": beezupFilteroperatorProjections,
	"beezup.offer":          beezupOfferProjections,
	"beezup.random":         beezupRandomProjections,
	"beezup.rule":           beezupRuleProjections,

	// better_stack generated projectors (sourcegen promotion)
	"better_stack.alerts":       betterStackAlertsProjections,
	"better_stack.audit_events": betterStackAuditEventsProjections,
	"better_stack.dashboards":   betterStackDashboardsProjections,
	"better_stack.incidents":    betterStackIncidentsProjections,
	"better_stack.monitors":     betterStackMonitorsProjections,

	// bettercloud generated projectors (sourcegen promotion)
	"bettercloud.applications": bettercloudApplicationsProjections,
	"bettercloud.audit_events": bettercloudAuditEventsProjections,
	"bettercloud.groups":       bettercloudGroupsProjections,
	"bettercloud.roles":        bettercloudRolesProjections,
	"bettercloud.users":        bettercloudUsersProjections,

	// beyondtrust generated projectors (sourcegen promotion)
	"beyondtrust.audit_events": beyondtrustAuditEventsProjections,
	"beyondtrust.secrets":      beyondtrustSecretsProjections,
	"beyondtrust.users":        beyondtrustUsersProjections,

	// biapi generated projectors (sourcegen promotion)
	"biapi.account":     biapiAccountProjections,
	"biapi.add_to_data": biapiAddToDataProjections,
	"biapi.alert":       biapiAlertProjections,
	"biapi.logo":        biapiLogoProjections,

	// bigfix generated projectors (sourcegen promotion)
	"bigfix.analyses":  bigfixAnalysesProjections,
	"bigfix.computers": bigfixComputersProjections,
	"bigfix.sites":     bigfixSitesProjections,

	// bigid generated projectors (sourcegen promotion)
	"bigid.assets":          bigidAssetsProjections,
	"bigid.audit_events":    bigidAuditEventsProjections,
	"bigid.findings":        bigidFindingsProjections,
	"bigid.policies":        bigidPoliciesProjections,
	"bigid.vulnerabilities": bigidVulnerabilitiesProjections,

	// bigpanda generated projectors (sourcegen promotion)
	"bigpanda.alerts":       bigpandaAlertsProjections,
	"bigpanda.audit_events": bigpandaAuditEventsProjections,
	"bigpanda.dashboards":   bigpandaDashboardsProjections,
	"bigpanda.incidents":    bigpandaIncidentsProjections,
	"bigpanda.monitors":     bigpandaMonitorsProjections,

	// bigredcloud generated projectors (sourcegen promotion)
	"bigredcloud.account":          bigredcloudAccountProjections,
	"bigredcloud.analysiscategory": bigredcloudAnalysiscategoryProjections,
	"bigredcloud.bankaccount":      bigredcloudBankaccountProjections,
	"bigredcloud.ownertypegroup":   bigredcloudOwnertypegroupProjections,

	// bill_com generated projectors (sourcegen promotion)
	"bill_com.accounts":     billComAccountsProjections,
	"bill_com.audit_events": billComAuditEventsProjections,
	"bill_com.policies":     billComPoliciesProjections,
	"bill_com.records":      billComRecordsProjections,
	"bill_com.users":        billComUsersProjections,

	// billbee generated projectors (sourcegen promotion)
	"billbee.addresses":          billbeeAddressesProjections,
	"billbee.cloudstorage":       billbeeCloudstorageProjections,
	"billbee.custom_field":       billbeeCustomFieldProjections,
	"billbee.customer":           billbeeCustomerProjections,
	"billbee.customer_addresses": billbeeCustomerAddressesProjections,
	"billbee.image":              billbeeImageProjections,
	"billbee.layout":             billbeeLayoutProjections,
	"billbee.order":              billbeeOrderProjections,
	"billbee.product":            billbeeProductProjections,
	"billbee.shipment":           billbeeShipmentProjections,
	"billbee.stock":              billbeeStockProjections,
	"billbee.webhook":            billbeeWebhookProjections,

	// billingo generated projectors (sourcegen promotion)
	"billingo.bank_account":   billingoBankAccountProjections,
	"billingo.document":       billingoDocumentProjections,
	"billingo.document_block": billingoDocumentBlockProjections,
	"billingo.partner":        billingoPartnerProjections,

	// bitbucket_cloud generated projectors (sourcegen promotion)
	"bitbucket_cloud.audit_events": bitbucketCloudAuditEventsProjections,
	"bitbucket_cloud.repositories": bitbucketCloudRepositoriesProjections,
	"bitbucket_cloud.users":        bitbucketCloudUsersProjections,

	// bitrise generated projectors (sourcegen promotion)
	"bitrise.audit_events": bitriseAuditEventsProjections,
	"bitrise.deployments":  bitriseDeploymentsProjections,
	"bitrise.projects":     bitriseProjectsProjections,
	"bitrise.repositories": bitriseRepositoriesProjections,
	"bitrise.users":        bitriseUsersProjections,

	// bitsight generated projectors (sourcegen promotion)
	"bitsight.assets":          bitsightAssetsProjections,
	"bitsight.audit_events":    bitsightAuditEventsProjections,
	"bitsight.findings":        bitsightFindingsProjections,
	"bitsight.policies":        bitsightPoliciesProjections,
	"bitsight.vulnerabilities": bitsightVulnerabilitiesProjections,

	// bitwarden generated projectors (sourcegen promotion)
	"bitwarden.applications": bitwardenApplicationsProjections,
	"bitwarden.audit_events": bitwardenAuditEventsProjections,
	"bitwarden.groups":       bitwardenGroupsProjections,
	"bitwarden.roles":        bitwardenRolesProjections,
	"bitwarden.users":        bitwardenUsersProjections,

	// bitwarden_enterprise generated projectors (sourcegen promotion)
	"bitwarden_enterprise.audit_events": bitwardenEnterpriseAuditEventsProjections,
	"bitwarden_enterprise.secrets":      bitwardenEnterpriseSecretsProjections,
	"bitwarden_enterprise.users":        bitwardenEnterpriseUsersProjections,

	// black_kite generated projectors (sourcegen promotion)
	"black_kite.assets":          blackKiteAssetsProjections,
	"black_kite.audit_events":    blackKiteAuditEventsProjections,
	"black_kite.findings":        blackKiteFindingsProjections,
	"black_kite.policies":        blackKitePoliciesProjections,
	"black_kite.vulnerabilities": blackKiteVulnerabilitiesProjections,

	// blackduck generated projectors (sourcegen promotion)
	"blackduck.assets":          blackduckAssetsProjections,
	"blackduck.audit_events":    blackduckAuditEventsProjections,
	"blackduck.findings":        blackduckFindingsProjections,
	"blackduck.policies":        blackduckPoliciesProjections,
	"blackduck.vulnerabilities": blackduckVulnerabilitiesProjections,

	// bluejeans generated projectors (sourcegen promotion)
	"bluejeans.audit_events": bluejeansAuditEventsProjections,
	"bluejeans.documents":    bluejeansDocumentsProjections,
	"bluejeans.groups":       bluejeansGroupsProjections,
	"bluejeans.users":        bluejeansUsersProjections,
	"bluejeans.workspaces":   bluejeansWorkspacesProjections,

	// boomi generated projectors (sourcegen promotion)
	"boomi.audit_events": boomiAuditEventsProjections,
	"boomi.deployments":  boomiDeploymentsProjections,
	"boomi.projects":     boomiProjectsProjections,
	"boomi.repositories": boomiRepositoriesProjections,
	"boomi.users":        boomiUsersProjections,

	// botify generated projectors (sourcegen promotion)
	"botify.analyses":      botifyAnalysesProjections,
	"botify.datamodel":     botifyDatamodelProjections,
	"botify.domain":        botifyDomainProjections,
	"botify.export":        botifyExportProjections,
	"botify.filter":        botifyFilterProjections,
	"botify.orphan_url":    botifyOrphanUrlProjections,
	"botify.out_of_config": botifyOutOfConfigProjections,
	"botify.percentile":    botifyPercentileProjections,
	"botify.project":       botifyProjectProjections,
	"botify.report":        botifyReportProjections,
	"botify.sitemap_only":  botifySitemapOnlyProjections,
	"botify.url":           botifyUrlProjections,

	// braintree generated projectors (sourcegen promotion)
	"braintree.audit_events": braintreeAuditEventsProjections,
	"braintree.customers":    braintreeCustomersProjections,
	"braintree.transactions": braintreeTransactionsProjections,

	// braze generated projectors (sourcegen promotion)
	"braze.accounts":     brazeAccountsProjections,
	"braze.audit_events": brazeAuditEventsProjections,
	"braze.policies":     brazePoliciesProjections,
	"braze.records":      brazeRecordsProjections,
	"braze.users":        brazeUsersProjections,

	// brex generated projectors (sourcegen promotion)
	"brex.audit_events": brexAuditEventsProjections,
	"brex.cards":        brexCardsProjections,
	"brex.users":        brexUsersProjections,

	// brightflag generated projectors (sourcegen promotion)
	"brightflag.accounts":     brightflagAccountsProjections,
	"brightflag.audit_events": brightflagAuditEventsProjections,
	"brightflag.policies":     brightflagPoliciesProjections,
	"brightflag.records":      brightflagRecordsProjections,
	"brightflag.users":        brightflagUsersProjections,

	// brinqa generated projectors (sourcegen promotion)
	"brinqa.assets":          brinqaAssetsProjections,
	"brinqa.audit_events":    brinqaAuditEventsProjections,
	"brinqa.findings":        brinqaFindingsProjections,
	"brinqa.policies":        brinqaPoliciesProjections,
	"brinqa.vulnerabilities": brinqaVulnerabilitiesProjections,

	// britive generated projectors (sourcegen promotion)
	"britive.applications": britiveApplicationsProjections,
	"britive.audit_events": britiveAuditEventsProjections,
	"britive.groups":       britiveGroupsProjections,
	"britive.roles":        britiveRolesProjections,
	"britive.users":        britiveUsersProjections,

	// browserstack generated projectors (sourcegen promotion)
	"browserstack.audit_events": browserstackAuditEventsProjections,
	"browserstack.deployments":  browserstackDeploymentsProjections,
	"browserstack.projects":     browserstackProjectsProjections,
	"browserstack.repositories": browserstackRepositoriesProjections,
	"browserstack.users":        browserstackUsersProjections,

	// buddy_ci generated projectors (sourcegen promotion)
	"buddy_ci.audit_events": buddyCiAuditEventsProjections,
	"buddy_ci.deployments":  buddyCiDeploymentsProjections,
	"buddy_ci.projects":     buddyCiProjectsProjections,
	"buddy_ci.repositories": buddyCiRepositoriesProjections,
	"buddy_ci.users":        buddyCiUsersProjections,

	// bugcrowd generated projectors (sourcegen promotion)
	"bugcrowd.assets":          bugcrowdAssetsProjections,
	"bugcrowd.audit_events":    bugcrowdAuditEventsProjections,
	"bugcrowd.findings":        bugcrowdFindingsProjections,
	"bugcrowd.policies":        bugcrowdPoliciesProjections,
	"bugcrowd.vulnerabilities": bugcrowdVulnerabilitiesProjections,

	// bugsnag generated projectors (sourcegen promotion)
	"bugsnag.audit_events": bugsnagAuditEventsProjections,
	"bugsnag.errors":       bugsnagErrorsProjections,
	"bugsnag.projects":     bugsnagProjectsProjections,

	// buildkite generated projectors (sourcegen promotion)
	"buildkite.audit_events": buildkiteAuditEventsProjections,
	"buildkite.findings":     buildkiteFindingsProjections,
	"buildkite.pipelines":    buildkitePipelinesProjections,

	// bulksms generated projectors (sourcegen promotion)
	"bulksms.message":                bulksmsMessageProjections,
	"bulksms.relatedreceivedmessage": bulksmsRelatedreceivedmessageProjections,
	"bulksms.send":                   bulksmsSendProjections,
	"bulksms.webhook":                bulksmsWebhookProjections,

	// bunq generated projectors (sourcegen promotion)
	"bunq.credential_password_ip":   bunqCredentialPasswordIpProjections,
	"bunq.event":                    bunqEventProjections,
	"bunq.notification_filter_push": bunqNotificationFilterPushProjections,
	"bunq.user":                     bunqUserProjections,

	// burp_suite_enterprise generated projectors (sourcegen promotion)
	"burp_suite_enterprise.assets":          burpSuiteEnterpriseAssetsProjections,
	"burp_suite_enterprise.audit_events":    burpSuiteEnterpriseAuditEventsProjections,
	"burp_suite_enterprise.findings":        burpSuiteEnterpriseFindingsProjections,
	"burp_suite_enterprise.policies":        burpSuiteEnterprisePoliciesProjections,
	"burp_suite_enterprise.vulnerabilities": burpSuiteEnterpriseVulnerabilitiesProjections,

	// calcom generated projectors (sourcegen promotion)
	"calcom.audit_events": calcomAuditEventsProjections,
	"calcom.bookings":     calcomBookingsProjections,
	"calcom.users":        calcomUsersProjections,

	// calendly generated projectors (sourcegen promotion)
	"calendly.audit_events": calendlyAuditEventsProjections,
	"calendly.documents":    calendlyDocumentsProjections,
	"calendly.groups":       calendlyGroupsProjections,
	"calendly.users":        calendlyUsersProjections,
	"calendly.workspaces":   calendlyWorkspacesProjections,

	// callfire generated projectors (sourcegen promotion)
	"callfire.account":    callfireAccountProjections,
	"callfire.broadcast":  callfireBroadcastProjections,
	"callfire.call":       callfireCallProjections,
	"callfire.credential": callfireCredentialProjections,

	// fire generated projectors (sourcegen promotion)
	"fire.account": fireAccountProjections,
	"fire.aspsp":   fireAspspProjections,
	"fire.batche":  fireBatcheProjections,
	"fire.user":    fireUserProjections,

	// front generated projectors (sourcegen promotion)
	"front.audit_events": frontAuditEventsProjections,
	"front.documents":    frontDocumentsProjections,
	"front.groups":       frontGroupsProjections,
	"front.users":        frontUsersProjections,
	"front.workspaces":   frontWorkspacesProjections,

	// workfront generated projectors (sourcegen promotion)
	"workfront.audit_events": workfrontAuditEventsProjections,
	"workfront.documents":    workfrontDocumentsProjections,
	"workfront.groups":       workfrontGroupsProjections,
	"workfront.users":        workfrontUsersProjections,
	"workfront.workspaces":   workfrontWorkspacesProjections,

	// callrail generated projectors (sourcegen promotion)
	"callrail.accounts":     callrailAccountsProjections,
	"callrail.audit_events": callrailAuditEventsProjections,
	"callrail.policies":     callrailPoliciesProjections,
	"callrail.records":      callrailRecordsProjections,
	"callrail.users":        callrailUsersProjections,

	// campaign_monitor generated projectors (sourcegen promotion)
	"campaign_monitor.accounts":     campaignMonitorAccountsProjections,
	"campaign_monitor.audit_events": campaignMonitorAuditEventsProjections,
	"campaign_monitor.policies":     campaignMonitorPoliciesProjections,
	"campaign_monitor.records":      campaignMonitorRecordsProjections,
	"campaign_monitor.users":        campaignMonitorUsersProjections,

	// canva_enterprise generated projectors (sourcegen promotion)
	"canva_enterprise.audit_events": canvaEnterpriseAuditEventsProjections,
	"canva_enterprise.documents":    canvaEnterpriseDocumentsProjections,
	"canva_enterprise.groups":       canvaEnterpriseGroupsProjections,
	"canva_enterprise.users":        canvaEnterpriseUsersProjections,
	"canva_enterprise.workspaces":   canvaEnterpriseWorkspacesProjections,

	// carbon_black_cloud generated projectors (sourcegen promotion)
	"carbon_black_cloud.assets":          carbonBlackCloudAssetsProjections,
	"carbon_black_cloud.audit_events":    carbonBlackCloudAuditEventsProjections,
	"carbon_black_cloud.findings":        carbonBlackCloudFindingsProjections,
	"carbon_black_cloud.policies":        carbonBlackCloudPoliciesProjections,
	"carbon_black_cloud.vulnerabilities": carbonBlackCloudVulnerabilitiesProjections,

	// caspio generated projectors (sourcegen promotion)
	"caspio.accounts":     caspioAccountsProjections,
	"caspio.audit_events": caspioAuditEventsProjections,
	"caspio.policies":     caspioPoliciesProjections,
	"caspio.records":      caspioRecordsProjections,
	"caspio.users":        caspioUsersProjections,

	// cast_ai generated projectors (sourcegen promotion)
	"cast_ai.alerts":       castAiAlertsProjections,
	"cast_ai.audit_events": castAiAuditEventsProjections,
	"cast_ai.dashboards":   castAiDashboardsProjections,
	"cast_ai.incidents":    castAiIncidentsProjections,
	"cast_ai.monitors":     castAiMonitorsProjections,

	// catalyst generated projectors (sourcegen promotion)
	"catalyst.accounts":     catalystAccountsProjections,
	"catalyst.audit_events": catalystAuditEventsProjections,
	"catalyst.policies":     catalystPoliciesProjections,
	"catalyst.records":      catalystRecordsProjections,
	"catalyst.users":        catalystUsersProjections,

	// catchpoint generated projectors (sourcegen promotion)
	"catchpoint.alerts":       catchpointAlertsProjections,
	"catchpoint.audit_events": catchpointAuditEventsProjections,
	"catchpoint.dashboards":   catchpointDashboardsProjections,
	"catchpoint.incidents":    catchpointIncidentsProjections,
	"catchpoint.monitors":     catchpointMonitorsProjections,

	// cato_networks generated projectors (sourcegen promotion)
	"cato_networks.assets":          catoNetworksAssetsProjections,
	"cato_networks.audit_events":    catoNetworksAuditEventsProjections,
	"cato_networks.findings":        catoNetworksFindingsProjections,
	"cato_networks.policies":        catoNetworksPoliciesProjections,
	"cato_networks.vulnerabilities": catoNetworksVulnerabilitiesProjections,

	// cenit generated projectors (sourcegen promotion)
	"cenit.connection":            cenitConnectionProjections,
	"cenit.connection_role":       cenitConnectionRoleProjections,
	"cenit.data_type":             cenitDataTypeProjections,
	"cenit.flow":                  cenitFlowProjections,
	"cenit.namespace":             cenitNamespaceProjections,
	"cenit.observer":              cenitObserverProjections,
	"cenit.scheduler":             cenitSchedulerProjections,
	"cenit.schema":                cenitSchemaProjections,
	"cenit.setup_connection_role": cenitSetupConnectionRoleProjections,
	"cenit.setup_webhook":         cenitSetupWebhookProjections,
	"cenit.translator":            cenitTranslatorProjections,
	"cenit.webhook":               cenitWebhookProjections,

	// census generated projectors (sourcegen promotion)
	"census.accounts":     censusAccountsProjections,
	"census.audit_events": censusAuditEventsProjections,
	"census.policies":     censusPoliciesProjections,
	"census.records":      censusRecordsProjections,
	"census.users":        censusUsersProjections,

	// censys_asm generated projectors (sourcegen promotion)
	"censys_asm.assets":          censysAsmAssetsProjections,
	"censys_asm.findings":        censysAsmFindingsProjections,
	"censys_asm.vulnerabilities": censysAsmVulnerabilitiesProjections,

	// cerbos_cloud generated projectors (sourcegen promotion)
	"cerbos_cloud.applications": cerbosCloudApplicationsProjections,
	"cerbos_cloud.audit_events": cerbosCloudAuditEventsProjections,
	"cerbos_cloud.groups":       cerbosCloudGroupsProjections,
	"cerbos_cloud.roles":        cerbosCloudRolesProjections,
	"cerbos_cloud.users":        cerbosCloudUsersProjections,

	// cerby generated projectors (sourcegen promotion)
	"cerby.applications": cerbyApplicationsProjections,
	"cerby.audit_events": cerbyAuditEventsProjections,
	"cerby.groups":       cerbyGroupsProjections,
	"cerby.roles":        cerbyRolesProjections,
	"cerby.users":        cerbyUsersProjections,

	// cerebras generated projectors (sourcegen promotion)
	"cerebras.api_keys":          cerebrasApiKeysProjections,
	"cerebras.model_deployments": cerebrasModelDeploymentsProjections,
	"cerebras.projects":          cerebrasProjectsProjections,
	"cerebras.usage_reports":     cerebrasUsageReportsProjections,

	// ceridian_dayforce generated projectors (sourcegen promotion)
	"ceridian_dayforce.accounts":     ceridianDayforceAccountsProjections,
	"ceridian_dayforce.audit_events": ceridianDayforceAuditEventsProjections,
	"ceridian_dayforce.policies":     ceridianDayforcePoliciesProjections,
	"ceridian_dayforce.records":      ceridianDayforceRecordsProjections,
	"ceridian_dayforce.users":        ceridianDayforceUsersProjections,

	// chargebee generated projectors (sourcegen promotion)
	"chargebee.audit_events":  chargebeeAuditEventsProjections,
	"chargebee.customers":     chargebeeCustomersProjections,
	"chargebee.subscriptions": chargebeeSubscriptionsProjections,

	// chargify generated projectors (sourcegen promotion)
	"chargify.accounts":     chargifyAccountsProjections,
	"chargify.audit_events": chargifyAuditEventsProjections,
	"chargify.policies":     chargifyPoliciesProjections,
	"chargify.records":      chargifyRecordsProjections,
	"chargify.users":        chargifyUsersProjections,

	// charthop generated projectors (sourcegen promotion)
	"charthop.accounts":     charthopAccountsProjections,
	"charthop.audit_events": charthopAuditEventsProjections,
	"charthop.policies":     charthopPoliciesProjections,
	"charthop.records":      charthopRecordsProjections,
	"charthop.users":        charthopUsersProjections,

	// checkly generated projectors (sourcegen promotion)
	"checkly.alerts":       checklyAlertsProjections,
	"checkly.audit_events": checklyAuditEventsProjections,
	"checkly.dashboards":   checklyDashboardsProjections,
	"checkly.incidents":    checklyIncidentsProjections,
	"checkly.monitors":     checklyMonitorsProjections,

	// checkmarx_one generated projectors (sourcegen promotion)
	"checkmarx_one.assets":          checkmarxOneAssetsProjections,
	"checkmarx_one.findings":        checkmarxOneFindingsProjections,
	"checkmarx_one.vulnerabilities": checkmarxOneVulnerabilitiesProjections,

	// checkout_com generated projectors (sourcegen promotion)
	"checkout_com.accounts":     checkoutComAccountsProjections,
	"checkout_com.audit_events": checkoutComAuditEventsProjections,
	"checkout_com.policies":     checkoutComPoliciesProjections,
	"checkout_com.records":      checkoutComRecordsProjections,
	"checkout_com.users":        checkoutComUsersProjections,

	// checkr generated projectors (sourcegen promotion)
	"checkr.background_checks": checkrBackgroundChecksProjections,
	"checkr.candidates":        checkrCandidatesProjections,
	"checkr.users":             checkrUsersProjections,

	// chili_piper generated projectors (sourcegen promotion)
	"chili_piper.audit_events": chiliPiperAuditEventsProjections,
	"chili_piper.documents":    chiliPiperDocumentsProjections,
	"chili_piper.groups":       chiliPiperGroupsProjections,
	"chili_piper.users":        chiliPiperUsersProjections,
	"chili_piper.workspaces":   chiliPiperWorkspacesProjections,

	// chorus generated projectors (sourcegen promotion)
	"chorus.accounts":     chorusAccountsProjections,
	"chorus.audit_events": chorusAuditEventsProjections,
	"chorus.policies":     chorusPoliciesProjections,
	"chorus.records":      chorusRecordsProjections,
	"chorus.users":        chorusUsersProjections,

	// chronosphere generated projectors (sourcegen promotion)
	"chronosphere.alerts":       chronosphereAlertsProjections,
	"chronosphere.audit_events": chronosphereAuditEventsProjections,
	"chronosphere.dashboards":   chronosphereDashboardsProjections,
	"chronosphere.incidents":    chronosphereIncidentsProjections,
	"chronosphere.monitors":     chronosphereMonitorsProjections,

	// churnzero generated projectors (sourcegen promotion)
	"churnzero.accounts":     churnzeroAccountsProjections,
	"churnzero.audit_events": churnzeroAuditEventsProjections,
	"churnzero.policies":     churnzeroPoliciesProjections,
	"churnzero.records":      churnzeroRecordsProjections,
	"churnzero.users":        churnzeroUsersProjections,

	// circleci generated projectors (sourcegen promotion)
	"circleci.audit_events": circleciAuditEventsProjections,
	"circleci.findings":     circleciFindingsProjections,
	"circleci.pipelines":    circleciPipelinesProjections,

	// cisco_umbrella generated projectors (sourcegen promotion)
	"cisco_umbrella.assets":          ciscoUmbrellaAssetsProjections,
	"cisco_umbrella.audit_events":    ciscoUmbrellaAuditEventsProjections,
	"cisco_umbrella.findings":        ciscoUmbrellaFindingsProjections,
	"cisco_umbrella.policies":        ciscoUmbrellaPoliciesProjections,
	"cisco_umbrella.vulnerabilities": ciscoUmbrellaVulnerabilitiesProjections,

	// clari generated projectors (sourcegen promotion)
	"clari.accounts":     clariAccountsProjections,
	"clari.audit_events": clariAuditEventsProjections,
	"clari.policies":     clariPoliciesProjections,
	"clari.records":      clariRecordsProjections,
	"clari.users":        clariUsersProjections,

	// claroty generated projectors (sourcegen promotion)
	"claroty.assets":          clarotyAssetsProjections,
	"claroty.audit_events":    clarotyAuditEventsProjections,
	"claroty.findings":        clarotyFindingsProjections,
	"claroty.policies":        clarotyPoliciesProjections,
	"claroty.vulnerabilities": clarotyVulnerabilitiesProjections,

	// clearblade generated projectors (sourcegen promotion)
	"clearblade.admin_audit":     clearbladeAdminAuditProjections,
	"clearblade.audit":           clearbladeAuditProjections,
	"clearblade.connection":      clearbladeConnectionProjections,
	"clearblade.deployment":      clearbladeDeploymentProjections,
	"clearblade.listindexe":      clearbladeListindexeProjections,
	"clearblade.platform_system": clearbladePlatformSystemProjections,
	"clearblade.session_user":    clearbladeSessionUserProjections,
	"clearblade.system":          clearbladeSystemProjections,
	"clearblade.timer":           clearbladeTimerProjections,
	"clearblade.topic":           clearbladeTopicProjections,
	"clearblade.trigger":         clearbladeTriggerProjections,
	"clearblade.user":            clearbladeUserProjections,

	// clever_cloud generated projectors (sourcegen promotion)
	"clever_cloud.deployment":   cleverCloudDeploymentProjections,
	"clever_cloud.email":        cleverCloudEmailProjections,
	"clever_cloud.networkgroup": cleverCloudNetworkgroupProjections,
	"clever_cloud.token":        cleverCloudTokenProjections,

	// clickmeter generated projectors (sourcegen promotion)
	"clickmeter.aggregated_list": clickmeterAggregatedListProjections,
	"clickmeter.clickstream":     clickmeterClickstreamProjections,
	"clickmeter.conversions_hit": clickmeterConversionsHitProjections,
	"clickmeter.datapoint":       clickmeterDatapointProjections,
	"clickmeter.datapoints_hit":  clickmeterDatapointsHitProjections,
	"clickmeter.group":           clickmeterGroupProjections,
	"clickmeter.groups_hit":      clickmeterGroupsHitProjections,
	"clickmeter.hit":             clickmeterHitProjections,
	"clickmeter.ipblacklist":     clickmeterIpblacklistProjections,
	"clickmeter.list":            clickmeterListProjections,
	"clickmeter.summary_group":   clickmeterSummaryGroupProjections,
	"clickmeter.tags_group":      clickmeterTagsGroupProjections,

	// clicksend generated projectors (sourcegen promotion)
	"clicksend.audit_events": clicksendAuditEventsProjections,
	"clicksend.documents":    clicksendDocumentsProjections,
	"clicksend.groups":       clicksendGroupsProjections,
	"clicksend.users":        clicksendUsersProjections,
	"clicksend.workspaces":   clicksendWorkspacesProjections,

	// clickup generated projectors (sourcegen promotion)
	"clickup.audit_events": clickupAuditEventsProjections,
	"clickup.projects":     clickupProjectsProjections,
	"clickup.users":        clickupUsersProjections,

	// close_crm generated projectors (sourcegen promotion)
	"close_crm.accounts":     closeCrmAccountsProjections,
	"close_crm.audit_events": closeCrmAuditEventsProjections,
	"close_crm.policies":     closeCrmPoliciesProjections,
	"close_crm.records":      closeCrmRecordsProjections,
	"close_crm.users":        closeCrmUsersProjections,

	// cloudbees_ci generated projectors (sourcegen promotion)
	"cloudbees_ci.audit_events": cloudbeesCiAuditEventsProjections,
	"cloudbees_ci.deployments":  cloudbeesCiDeploymentsProjections,
	"cloudbees_ci.projects":     cloudbeesCiProjectsProjections,
	"cloudbees_ci.repositories": cloudbeesCiRepositoriesProjections,
	"cloudbees_ci.users":        cloudbeesCiUsersProjections,

	// cloudflare_workers_ai generated projectors (sourcegen promotion)
	"cloudflare_workers_ai.ai_gateways":              cloudflareWorkersAiAiGatewaysProjections,
	"cloudflare_workers_ai.gateway_evaluations":      cloudflareWorkersAiGatewayEvaluationsProjections,
	"cloudflare_workers_ai.gateway_logs":             cloudflareWorkersAiGatewayLogsProjections,
	"cloudflare_workers_ai.gateway_provider_configs": cloudflareWorkersAiGatewayProviderConfigsProjections,
	"cloudflare_workers_ai.model_catalog":            cloudflareWorkersAiModelCatalogProjections,
	"cloudflare_workers_ai.vectorize_indexes":        cloudflareWorkersAiVectorizeIndexesProjections,

	// cloudflare_zero_trust generated projectors (sourcegen promotion)
	"cloudflare_zero_trust.applications": cloudflareZeroTrustApplicationsProjections,
	"cloudflare_zero_trust.audit_events": cloudflareZeroTrustAuditEventsProjections,
	"cloudflare_zero_trust.groups":       cloudflareZeroTrustGroupsProjections,
	"cloudflare_zero_trust.roles":        cloudflareZeroTrustRolesProjections,
	"cloudflare_zero_trust.users":        cloudflareZeroTrustUsersProjections,

	// cloudsmith generated projectors (sourcegen promotion)
	"cloudsmith.audit_events": cloudsmithAuditEventsProjections,
	"cloudsmith.deployments":  cloudsmithDeploymentsProjections,
	"cloudsmith.projects":     cloudsmithProjectsProjections,
	"cloudsmith.repositories": cloudsmithRepositoriesProjections,
	"cloudsmith.users":        cloudsmithUsersProjections,

	// cloudtalk generated projectors (sourcegen promotion)
	"cloudtalk.accounts":     cloudtalkAccountsProjections,
	"cloudtalk.audit_events": cloudtalkAuditEventsProjections,
	"cloudtalk.policies":     cloudtalkPoliciesProjections,
	"cloudtalk.records":      cloudtalkRecordsProjections,
	"cloudtalk.users":        cloudtalkUsersProjections,

	// coalesce_data generated projectors (sourcegen promotion)
	"coalesce_data.accounts":     coalesceDataAccountsProjections,
	"coalesce_data.audit_events": coalesceDataAuditEventsProjections,
	"coalesce_data.policies":     coalesceDataPoliciesProjections,
	"coalesce_data.records":      coalesceDataRecordsProjections,
	"coalesce_data.users":        coalesceDataUsersProjections,

	// cobalt generated projectors (sourcegen promotion)
	"cobalt.assets":          cobaltAssetsProjections,
	"cobalt.audit_events":    cobaltAuditEventsProjections,
	"cobalt.findings":        cobaltFindingsProjections,
	"cobalt.policies":        cobaltPoliciesProjections,
	"cobalt.vulnerabilities": cobaltVulnerabilitiesProjections,

	// cockroachdb_cloud generated projectors (sourcegen promotion)
	"cockroachdb_cloud.assets":          cockroachdbCloudAssetsProjections,
	"cockroachdb_cloud.audit_events":    cockroachdbCloudAuditEventsProjections,
	"cockroachdb_cloud.vulnerabilities": cockroachdbCloudVulnerabilitiesProjections,

	// coda generated projectors (sourcegen promotion)
	"coda.audit_events": codaAuditEventsProjections,
	"coda.documents":    codaDocumentsProjections,
	"coda.groups":       codaGroupsProjections,
	"coda.users":        codaUsersProjections,
	"coda.workspaces":   codaWorkspacesProjections,

	// codacy generated projectors (sourcegen promotion)
	"codacy.audit_events": codacyAuditEventsProjections,
	"codacy.deployments":  codacyDeploymentsProjections,
	"codacy.projects":     codacyProjectsProjections,
	"codacy.repositories": codacyRepositoriesProjections,
	"codacy.users":        codacyUsersProjections,

	// codecov generated projectors (sourcegen promotion)
	"codecov.audit_events": codecovAuditEventsProjections,
	"codecov.deployments":  codecovDeploymentsProjections,
	"codecov.projects":     codecovProjectsProjections,
	"codecov.repositories": codecovRepositoriesProjections,
	"codecov.users":        codecovUsersProjections,

	// codefresh generated projectors (sourcegen promotion)
	"codefresh.audit_events": codefreshAuditEventsProjections,
	"codefresh.builds":       codefreshBuildsProjections,
	"codefresh.projects":     codefreshProjectsProjections,

	// codemagic generated projectors (sourcegen promotion)
	"codemagic.audit_events": codemagicAuditEventsProjections,
	"codemagic.deployments":  codemagicDeploymentsProjections,
	"codemagic.projects":     codemagicProjectsProjections,
	"codemagic.repositories": codemagicRepositoriesProjections,
	"codemagic.users":        codemagicUsersProjections,

	// coder_cloud generated projectors (sourcegen promotion)
	"coder_cloud.audit_events": coderCloudAuditEventsProjections,
	"coder_cloud.deployments":  coderCloudDeploymentsProjections,
	"coder_cloud.projects":     coderCloudProjectsProjections,
	"coder_cloud.repositories": coderCloudRepositoriesProjections,
	"coder_cloud.users":        coderCloudUsersProjections,

	// cofense generated projectors (sourcegen promotion)
	"cofense.assets":          cofenseAssetsProjections,
	"cofense.audit_events":    cofenseAuditEventsProjections,
	"cofense.findings":        cofenseFindingsProjections,
	"cofense.policies":        cofensePoliciesProjections,
	"cofense.vulnerabilities": cofenseVulnerabilitiesProjections,

	// cohere generated projectors (sourcegen promotion)
	"cohere.connectors":        cohereConnectorsProjections,
	"cohere.datasets":          cohereDatasetsProjections,
	"cohere.fine_tuned_models": cohereFineTunedModelsProjections,
	"cohere.model_catalog":     cohereModelCatalogProjections,

	// collibra generated projectors (sourcegen promotion)
	"collibra.accounts":     collibraAccountsProjections,
	"collibra.audit_events": collibraAuditEventsProjections,
	"collibra.policies":     collibraPoliciesProjections,
	"collibra.records":      collibraRecordsProjections,
	"collibra.users":        collibraUsersProjections,

	// combell generated projectors (sourcegen promotion)
	"combell.account":   combellAccountProjections,
	"combell.account_2": combellAccount2Projections,
	"combell.ssh":       combellSshProjections,
	"combell.user":      combellUserProjections,

	// concur generated projectors (sourcegen promotion)
	"concur.accounts":     concurAccountsProjections,
	"concur.audit_events": concurAuditEventsProjections,
	"concur.policies":     concurPoliciesProjections,
	"concur.records":      concurRecordsProjections,
	"concur.users":        concurUsersProjections,

	// configcat generated projectors (sourcegen promotion)
	"configcat.auditlog":     configcatAuditlogProjections,
	"configcat.member":       configcatMemberProjections,
	"configcat.organization": configcatOrganizationProjections,
	"configcat.permission":   configcatPermissionProjections,

	// confluence generated projectors (sourcegen promotion)
	"confluence.audit_events": confluenceAuditEventsProjections,
	"confluence.projects":     confluenceProjectsProjections,
	"confluence.users":        confluenceUsersProjections,

	// conga generated projectors (sourcegen promotion)
	"conga.accounts":     congaAccountsProjections,
	"conga.audit_events": congaAuditEventsProjections,
	"conga.policies":     congaPoliciesProjections,
	"conga.records":      congaRecordsProjections,
	"conga.users":        congaUsersProjections,

	// contentful generated projectors (sourcegen promotion)
	"contentful.audit_events": contentfulAuditEventsProjections,
	"contentful.documents":    contentfulDocumentsProjections,
	"contentful.groups":       contentfulGroupsProjections,
	"contentful.users":        contentfulUsersProjections,
	"contentful.workspaces":   contentfulWorkspacesProjections,

	// contractbook generated projectors (sourcegen promotion)
	"contractbook.accounts":     contractbookAccountsProjections,
	"contractbook.audit_events": contractbookAuditEventsProjections,
	"contractbook.policies":     contractbookPoliciesProjections,
	"contractbook.records":      contractbookRecordsProjections,
	"contractbook.users":        contractbookUsersProjections,

	// contrast_security generated projectors (sourcegen promotion)
	"contrast_security.assets":          contrastSecurityAssetsProjections,
	"contrast_security.audit_events":    contrastSecurityAuditEventsProjections,
	"contrast_security.findings":        contrastSecurityFindingsProjections,
	"contrast_security.policies":        contrastSecurityPoliciesProjections,
	"contrast_security.vulnerabilities": contrastSecurityVulnerabilitiesProjections,

	// copper_crm generated projectors (sourcegen promotion)
	"copper_crm.accounts":     copperCrmAccountsProjections,
	"copper_crm.audit_events": copperCrmAuditEventsProjections,
	"copper_crm.policies":     copperCrmPoliciesProjections,
	"copper_crm.records":      copperCrmRecordsProjections,
	"copper_crm.users":        copperCrmUsersProjections,

	// coralogix generated projectors (sourcegen promotion)
	"coralogix.alerts":       coralogixAlertsProjections,
	"coralogix.audit_events": coralogixAuditEventsProjections,
	"coralogix.dashboards":   coralogixDashboardsProjections,
	"coralogix.incidents":    coralogixIncidentsProjections,
	"coralogix.monitors":     coralogixMonitorsProjections,

	// cornerstone_ondemand generated projectors (sourcegen promotion)
	"cornerstone_ondemand.accounts":     cornerstoneOndemandAccountsProjections,
	"cornerstone_ondemand.audit_events": cornerstoneOndemandAuditEventsProjections,
	"cornerstone_ondemand.policies":     cornerstoneOndemandPoliciesProjections,
	"cornerstone_ondemand.records":      cornerstoneOndemandRecordsProjections,
	"cornerstone_ondemand.users":        cornerstoneOndemandUsersProjections,

	// cortex_xdr generated projectors (sourcegen promotion)
	"cortex_xdr.assets":          cortexXdrAssetsProjections,
	"cortex_xdr.findings":        cortexXdrFindingsProjections,
	"cortex_xdr.vulnerabilities": cortexXdrVulnerabilitiesProjections,

	// cortex_xsoar generated projectors (sourcegen promotion)
	"cortex_xsoar.assets":       cortexXsoarAssetsProjections,
	"cortex_xsoar.audit_events": cortexXsoarAuditEventsProjections,
	"cortex_xsoar.findings":     cortexXsoarFindingsProjections,

	// coupa generated projectors (sourcegen promotion)
	"coupa.accounts":     coupaAccountsProjections,
	"coupa.audit_events": coupaAuditEventsProjections,
	"coupa.policies":     coupaPoliciesProjections,
	"coupa.records":      coupaRecordsProjections,
	"coupa.users":        coupaUsersProjections,

	// crashlytics generated projectors (sourcegen promotion)
	"crashlytics.alerts":       crashlyticsAlertsProjections,
	"crashlytics.audit_events": crashlyticsAuditEventsProjections,
	"crashlytics.dashboards":   crashlyticsDashboardsProjections,
	"crashlytics.incidents":    crashlyticsIncidentsProjections,
	"crashlytics.monitors":     crashlyticsMonitorsProjections,

	// creately generated projectors (sourcegen promotion)
	"creately.audit_events": createlyAuditEventsProjections,
	"creately.documents":    createlyDocumentsProjections,
	"creately.groups":       createlyGroupsProjections,
	"creately.users":        createlyUsersProjections,
	"creately.workspaces":   createlyWorkspacesProjections,

	// cribl_cloud generated projectors (sourcegen promotion)
	"cribl_cloud.alerts":       criblCloudAlertsProjections,
	"cribl_cloud.audit_events": criblCloudAuditEventsProjections,
	"cribl_cloud.dashboards":   criblCloudDashboardsProjections,
	"cribl_cloud.incidents":    criblCloudIncidentsProjections,
	"cribl_cloud.monitors":     criblCloudMonitorsProjections,

	// crowdstrike_falcon generated projectors (sourcegen promotion)
	"crowdstrike_falcon.endpoint_devices": crowdstrikeFalconEndpointDevicesProjections,
	"crowdstrike_falcon.findings":         crowdstrikeFalconFindingsProjections,
	"crowdstrike_falcon.vulnerabilities":  crowdstrikeFalconVulnerabilitiesProjections,

	// crowdstrike_identity generated projectors (sourcegen promotion)
	"crowdstrike_identity.assets":          crowdstrikeIdentityAssetsProjections,
	"crowdstrike_identity.audit_events":    crowdstrikeIdentityAuditEventsProjections,
	"crowdstrike_identity.findings":        crowdstrikeIdentityFindingsProjections,
	"crowdstrike_identity.policies":        crowdstrikeIdentityPoliciesProjections,
	"crowdstrike_identity.vulnerabilities": crowdstrikeIdentityVulnerabilitiesProjections,

	// culture_amp generated projectors (sourcegen promotion)
	"culture_amp.accounts":     cultureAmpAccountsProjections,
	"culture_amp.audit_events": cultureAmpAuditEventsProjections,
	"culture_amp.policies":     cultureAmpPoliciesProjections,
	"culture_amp.records":      cultureAmpRecordsProjections,
	"culture_amp.users":        cultureAmpUsersProjections,

	// customer_io generated projectors (sourcegen promotion)
	"customer_io.accounts":     customerIoAccountsProjections,
	"customer_io.audit_events": customerIoAuditEventsProjections,
	"customer_io.policies":     customerIoPoliciesProjections,
	"customer_io.records":      customerIoRecordsProjections,
	"customer_io.users":        customerIoUsersProjections,

	// cyberark_identity generated projectors (sourcegen promotion)
	"cyberark_identity.audit_events": cyberarkIdentityAuditEventsProjections,
	"cyberark_identity.groups":       cyberarkIdentityGroupsProjections,
	"cyberark_identity.users":        cyberarkIdentityUsersProjections,

	// cyberark_pam generated projectors (sourcegen promotion)
	"cyberark_pam.audit_events": cyberarkPamAuditEventsProjections,
	"cyberark_pam.secrets":      cyberarkPamSecretsProjections,
	"cyberark_pam.users":        cyberarkPamUsersProjections,

	// cycode generated projectors (sourcegen promotion)
	"cycode.assets":          cycodeAssetsProjections,
	"cycode.audit_events":    cycodeAuditEventsProjections,
	"cycode.findings":        cycodeFindingsProjections,
	"cycode.policies":        cycodePoliciesProjections,
	"cycode.vulnerabilities": cycodeVulnerabilitiesProjections,

	// cyera generated projectors (sourcegen promotion)
	"cyera.assets":          cyeraAssetsProjections,
	"cyera.audit_events":    cyeraAuditEventsProjections,
	"cyera.findings":        cyeraFindingsProjections,
	"cyera.policies":        cyeraPoliciesProjections,
	"cyera.vulnerabilities": cyeraVulnerabilitiesProjections,

	// cyolo generated projectors (sourcegen promotion)
	"cyolo.applications": cyoloApplicationsProjections,
	"cyolo.audit_events": cyoloAuditEventsProjections,
	"cyolo.groups":       cyoloGroupsProjections,
	"cyolo.roles":        cyoloRolesProjections,
	"cyolo.users":        cyoloUsersProjections,

	// dashlane_business generated projectors (sourcegen promotion)
	"dashlane_business.applications": dashlaneBusinessApplicationsProjections,
	"dashlane_business.audit_events": dashlaneBusinessAuditEventsProjections,
	"dashlane_business.groups":       dashlaneBusinessGroupsProjections,
	"dashlane_business.roles":        dashlaneBusinessRolesProjections,
	"dashlane_business.users":        dashlaneBusinessUsersProjections,

	// databricks generated projectors (sourcegen promotion)
	"databricks.assets":                  databricksAssetsProjections,
	"databricks.audit_events":            databricksAuditEventsProjections,
	"databricks.model_serving_endpoints": databricksModelServingEndpointsProjections,
	"databricks.vulnerabilities":         databricksVulnerabilitiesProjections,

	// datafold generated projectors (sourcegen promotion)
	"datafold.accounts":     datafoldAccountsProjections,
	"datafold.audit_events": datafoldAuditEventsProjections,
	"datafold.policies":     datafoldPoliciesProjections,
	"datafold.records":      datafoldRecordsProjections,
	"datafold.users":        datafoldUsersProjections,

	// dbt_cloud generated projectors (sourcegen promotion)
	"dbt_cloud.accounts":     dbtCloudAccountsProjections,
	"dbt_cloud.audit_events": dbtCloudAuditEventsProjections,
	"dbt_cloud.policies":     dbtCloudPoliciesProjections,
	"dbt_cloud.records":      dbtCloudRecordsProjections,
	"dbt_cloud.users":        dbtCloudUsersProjections,

	// dealhub generated projectors (sourcegen promotion)
	"dealhub.accounts":     dealhubAccountsProjections,
	"dealhub.audit_events": dealhubAuditEventsProjections,
	"dealhub.policies":     dealhubPoliciesProjections,
	"dealhub.records":      dealhubRecordsProjections,
	"dealhub.users":        dealhubUsersProjections,

	// deel generated projectors (sourcegen promotion)
	"deel.accounts":     deelAccountsProjections,
	"deel.audit_events": deelAuditEventsProjections,
	"deel.policies":     deelPoliciesProjections,
	"deel.records":      deelRecordsProjections,
	"deel.users":        deelUsersProjections,

	// deepseek generated projectors (sourcegen promotion)
	"deepseek.account_balances": deepseekAccountBalancesProjections,
	"deepseek.model_catalog":    deepseekModelCatalogProjections,

	// defectdojo_cloud generated projectors (sourcegen promotion)
	"defectdojo_cloud.assets":          defectdojoCloudAssetsProjections,
	"defectdojo_cloud.audit_events":    defectdojoCloudAuditEventsProjections,
	"defectdojo_cloud.findings":        defectdojoCloudFindingsProjections,
	"defectdojo_cloud.policies":        defectdojoCloudPoliciesProjections,
	"defectdojo_cloud.vulnerabilities": defectdojoCloudVulnerabilitiesProjections,

	// degreed generated projectors (sourcegen promotion)
	"degreed.accounts":     degreedAccountsProjections,
	"degreed.audit_events": degreedAuditEventsProjections,
	"degreed.policies":     degreedPoliciesProjections,
	"degreed.records":      degreedRecordsProjections,
	"degreed.users":        degreedUsersProjections,

	// delinea generated projectors (sourcegen promotion)
	"delinea.applications": delineaApplicationsProjections,
	"delinea.audit_events": delineaAuditEventsProjections,
	"delinea.groups":       delineaGroupsProjections,
	"delinea.roles":        delineaRolesProjections,
	"delinea.users":        delineaUsersProjections,

	// demandbase generated projectors (sourcegen promotion)
	"demandbase.accounts":     demandbaseAccountsProjections,
	"demandbase.audit_events": demandbaseAuditEventsProjections,
	"demandbase.policies":     demandbasePoliciesProjections,
	"demandbase.records":      demandbaseRecordsProjections,
	"demandbase.users":        demandbaseUsersProjections,

	// depot generated projectors (sourcegen promotion)
	"depot.audit_events": depotAuditEventsProjections,
	"depot.deployments":  depotDeploymentsProjections,
	"depot.projects":     depotProjectsProjections,
	"depot.repositories": depotRepositoriesProjections,
	"depot.users":        depotUsersProjections,

	// descope generated projectors (sourcegen promotion)
	"descope.applications": descopeApplicationsProjections,
	"descope.audit_events": descopeAuditEventsProjections,
	"descope.groups":       descopeGroupsProjections,
	"descope.roles":        descopeRolesProjections,
	"descope.users":        descopeUsersProjections,

	// detectify generated projectors (sourcegen promotion)
	"detectify.assets":        detectifyAssetsProjections,
	"detectify.findings":      detectifyFindingsProjections,
	"detectify.scan_profiles": detectifyScanProfilesProjections,

	// devcycle generated projectors (sourcegen promotion)
	"devcycle.audit_events": devcycleAuditEventsProjections,
	"devcycle.deployments":  devcycleDeploymentsProjections,
	"devcycle.projects":     devcycleProjectsProjections,
	"devcycle.repositories": devcycleRepositoriesProjections,
	"devcycle.users":        devcycleUsersProjections,

	// device42 generated projectors (sourcegen promotion)
	"device42.applications": device42ApplicationsProjections,
	"device42.audit_events": device42AuditEventsProjections,
	"device42.groups":       device42GroupsProjections,
	"device42.roles":        device42RolesProjections,
	"device42.users":        device42UsersProjections,

	// devtron generated projectors (sourcegen promotion)
	"devtron.audit_events": devtronAuditEventsProjections,
	"devtron.deployments":  devtronDeploymentsProjections,
	"devtron.projects":     devtronProjectsProjections,
	"devtron.repositories": devtronRepositoriesProjections,
	"devtron.users":        devtronUsersProjections,

	// dialpad generated projectors (sourcegen promotion)
	"dialpad.audit_events": dialpadAuditEventsProjections,
	"dialpad.documents":    dialpadDocumentsProjections,
	"dialpad.groups":       dialpadGroupsProjections,
	"dialpad.users":        dialpadUsersProjections,
	"dialpad.workspaces":   dialpadWorkspacesProjections,

	// dig_security generated projectors (sourcegen promotion)
	"dig_security.assets":          digSecurityAssetsProjections,
	"dig_security.audit_events":    digSecurityAuditEventsProjections,
	"dig_security.findings":        digSecurityFindingsProjections,
	"dig_security.policies":        digSecurityPoliciesProjections,
	"dig_security.vulnerabilities": digSecurityVulnerabilitiesProjections,

	// digitalocean generated projectors (sourcegen promotion)
	"digitalocean.audit_events": digitaloceanAuditEventsProjections,
	"digitalocean.droplets":     digitaloceanDropletsProjections,
	"digitalocean.teams":        digitaloceanTeamsProjections,

	// discourse generated projectors (sourcegen promotion)
	"discourse.backups_json":       discourseBackupsJsonProjections,
	"discourse.groups_json":        discourseGroupsJsonProjections,
	"discourse.notifications_json": discourseNotificationsJsonProjections,
	"discourse.user_actions_json":  discourseUserActionsJsonProjections,

	// divvy generated projectors (sourcegen promotion)
	"divvy.accounts":     divvyAccountsProjections,
	"divvy.audit_events": divvyAuditEventsProjections,
	"divvy.policies":     divvyPoliciesProjections,
	"divvy.records":      divvyRecordsProjections,
	"divvy.users":        divvyUsersProjections,

	// dixa generated projectors (sourcegen promotion)
	"dixa.accounts":     dixaAccountsProjections,
	"dixa.audit_events": dixaAuditEventsProjections,
	"dixa.policies":     dixaPoliciesProjections,
	"dixa.records":      dixaRecordsProjections,
	"dixa.users":        dixaUsersProjections,

	// docebo generated projectors (sourcegen promotion)
	"docebo.accounts":     doceboAccountsProjections,
	"docebo.audit_events": doceboAuditEventsProjections,
	"docebo.policies":     doceboPoliciesProjections,
	"docebo.records":      doceboRecordsProjections,
	"docebo.users":        doceboUsersProjections,

	// docker_hub generated projectors (sourcegen promotion)
	"docker_hub.audit_events": dockerHubAuditEventsProjections,
	"docker_hub.repositories": dockerHubRepositoriesProjections,
	"docker_hub.users":        dockerHubUsersProjections,

	// document360 generated projectors (sourcegen promotion)
	"document360.audit_events": document360AuditEventsProjections,
	"document360.documents":    document360DocumentsProjections,
	"document360.groups":       document360GroupsProjections,
	"document360.users":        document360UsersProjections,
	"document360.workspaces":   document360WorkspacesProjections,

	// docusign generated projectors (sourcegen promotion)
	"docusign.bcc_email_archive":  docusignBccEmailArchiveProjections,
	"docusign.permission_profile": docusignPermissionProfileProjections,
	"docusign.request_log":        docusignRequestLogProjections,
	"docusign.signing_group":      docusignSigningGroupProjections,

	// domo generated projectors (sourcegen promotion)
	"domo.accounts":     domoAccountsProjections,
	"domo.audit_events": domoAuditEventsProjections,
	"domo.policies":     domoPoliciesProjections,
	"domo.records":      domoRecordsProjections,
	"domo.users":        domoUsersProjections,

	// dracoon generated projectors (sourcegen promotion)
	"dracoon.channel":    dracoonChannelProjections,
	"dracoon.event_type": dracoonEventTypeProjections,
	"dracoon.group":      dracoonGroupProjections,
	"dracoon.user":       dracoonUserProjections,

	// dragos_worldview generated projectors (sourcegen promotion)
	"dragos_worldview.assets":          dragosWorldviewAssetsProjections,
	"dragos_worldview.audit_events":    dragosWorldviewAuditEventsProjections,
	"dragos_worldview.findings":        dragosWorldviewFindingsProjections,
	"dragos_worldview.policies":        dragosWorldviewPoliciesProjections,
	"dragos_worldview.vulnerabilities": dragosWorldviewVulnerabilitiesProjections,

	// drata generated projectors (sourcegen promotion)
	"drata.controls": drataControlsProjections,
	"drata.findings": drataFindingsProjections,
	"drata.users":    drataUsersProjections,

	// drchrono generated projectors (sourcegen promotion)
	"drchrono.allergy":                 drchronoAllergyProjections,
	"drchrono.amendment":               drchronoAmendmentProjections,
	"drchrono.appointment":             drchronoAppointmentProjections,
	"drchrono.appointment_profile":     drchronoAppointmentProfileProjections,
	"drchrono.appointment_template":    drchronoAppointmentTemplateProjections,
	"drchrono.care_team_member":        drchronoCareTeamMemberProjections,
	"drchrono.comm_log":                drchronoCommLogProjections,
	"drchrono.implantable_device":      drchronoImplantableDeviceProjections,
	"drchrono.patient_payment_log":     drchronoPatientPaymentLogProjections,
	"drchrono.patient_risk_assessment": drchronoPatientRiskAssessmentProjections,
	"drchrono.user":                    drchronoUserProjections,
	"drchrono.user_group":              drchronoUserGroupProjections,

	// drift generated projectors (sourcegen promotion)
	"drift.audit_events": driftAuditEventsProjections,
	"drift.documents":    driftDocumentsProjections,
	"drift.groups":       driftGroupsProjections,
	"drift.users":        driftUsersProjections,
	"drift.workspaces":   driftWorkspacesProjections,

	// drone_cloud generated projectors (sourcegen promotion)
	"drone_cloud.audit_events": droneCloudAuditEventsProjections,
	"drone_cloud.deployments":  droneCloudDeploymentsProjections,
	"drone_cloud.projects":     droneCloudProjectsProjections,
	"drone_cloud.repositories": droneCloudRepositoriesProjections,
	"drone_cloud.users":        droneCloudUsersProjections,

	// dropbox_business generated projectors (sourcegen promotion)
	"dropbox_business.audit_events":   dropboxBusinessAuditEventsProjections,
	"dropbox_business.content_assets": dropboxBusinessContentAssetsProjections,
	"dropbox_business.users":          dropboxBusinessUsersProjections,

	// dropbox_sign generated projectors (sourcegen promotion)
	"dropbox_sign.audit_events": dropboxSignAuditEventsProjections,
	"dropbox_sign.documents":    dropboxSignDocumentsProjections,
	"dropbox_sign.groups":       dropboxSignGroupsProjections,
	"dropbox_sign.users":        dropboxSignUsersProjections,
	"dropbox_sign.workspaces":   dropboxSignWorkspacesProjections,

	// duo_security generated projectors (sourcegen promotion)
	"duo_security.applications": duoSecurityApplicationsProjections,
	"duo_security.audit_events": duoSecurityAuditEventsProjections,
	"duo_security.groups":       duoSecurityGroupsProjections,
	"duo_security.roles":        duoSecurityRolesProjections,
	"duo_security.users":        duoSecurityUsersProjections,

	// dynamics_365_sales generated projectors (sourcegen promotion)
	"dynamics_365_sales.accounts":     dynamics365SalesAccountsProjections,
	"dynamics_365_sales.audit_events": dynamics365SalesAuditEventsProjections,
	"dynamics_365_sales.policies":     dynamics365SalesPoliciesProjections,
	"dynamics_365_sales.records":      dynamics365SalesRecordsProjections,
	"dynamics_365_sales.users":        dynamics365SalesUsersProjections,

	// dynatrace generated projectors (sourcegen promotion)
	"dynatrace.alerts":       dynatraceAlertsProjections,
	"dynatrace.audit_events": dynatraceAuditEventsProjections,
	"dynatrace.dashboards":   dynatraceDashboardsProjections,
	"dynatrace.incidents":    dynatraceIncidentsProjections,
	"dynatrace.monitors":     dynatraceMonitorsProjections,

	// easyllama generated projectors (sourcegen promotion)
	"easyllama.accounts":     easyllamaAccountsProjections,
	"easyllama.audit_events": easyllamaAuditEventsProjections,
	"easyllama.policies":     easyllamaPoliciesProjections,
	"easyllama.records":      easyllamaRecordsProjections,
	"easyllama.users":        easyllamaUsersProjections,

	// eclypsium generated projectors (sourcegen promotion)
	"eclypsium.assets":          eclypsiumAssetsProjections,
	"eclypsium.audit_events":    eclypsiumAuditEventsProjections,
	"eclypsium.findings":        eclypsiumFindingsProjections,
	"eclypsium.policies":        eclypsiumPoliciesProjections,
	"eclypsium.vulnerabilities": eclypsiumVulnerabilitiesProjections,

	// egnyte generated projectors (sourcegen promotion)
	"egnyte.audit_events": egnyteAuditEventsProjections,
	"egnyte.documents":    egnyteDocumentsProjections,
	"egnyte.groups":       egnyteGroupsProjections,
	"egnyte.users":        egnyteUsersProjections,
	"egnyte.workspaces":   egnyteWorkspacesProjections,

	// elastic_cloud generated projectors (sourcegen promotion)
	"elastic_cloud.alerts":       elasticCloudAlertsProjections,
	"elastic_cloud.audit_events": elasticCloudAuditEventsProjections,
	"elastic_cloud.dashboards":   elasticCloudDashboardsProjections,
	"elastic_cloud.incidents":    elasticCloudIncidentsProjections,
	"elastic_cloud.monitors":     elasticCloudMonitorsProjections,

	// elastic_security generated projectors (sourcegen promotion)
	"elastic_security.assets":       elasticSecurityAssetsProjections,
	"elastic_security.audit_events": elasticSecurityAuditEventsProjections,
	"elastic_security.findings":     elasticSecurityFindingsProjections,

	// elevenlabs generated projectors (sourcegen promotion)
	"elevenlabs.auth_connections":         elevenlabsAuthConnectionsProjections,
	"elevenlabs.model_catalog":            elevenlabsModelCatalogProjections,
	"elevenlabs.service_account_api_keys": elevenlabsServiceAccountApiKeysProjections,
	"elevenlabs.service_accounts":         elevenlabsServiceAccountsProjections,
	"elevenlabs.voices":                   elevenlabsVoicesProjections,
	"elevenlabs.webhooks":                 elevenlabsWebhooksProjections,

	// elmah generated projectors (sourcegen promotion)
	"elmah.deployment":  elmahDeploymentProjections,
	"elmah.log":         elmahLogProjections,
	"elmah.message":     elmahMessageProjections,
	"elmah.uptimecheck": elmahUptimecheckProjections,

	// endor_labs generated projectors (sourcegen promotion)
	"endor_labs.assets":          endorLabsAssetsProjections,
	"endor_labs.audit_events":    endorLabsAuditEventsProjections,
	"endor_labs.findings":        endorLabsFindingsProjections,
	"endor_labs.policies":        endorLabsPoliciesProjections,
	"endor_labs.vulnerabilities": endorLabsVulnerabilitiesProjections,

	// env0 generated projectors (sourcegen promotion)
	"env0.audit_events": env0AuditEventsProjections,
	"env0.deployments":  env0DeploymentsProjections,
	"env0.projects":     env0ProjectsProjections,
	"env0.repositories": env0RepositoriesProjections,
	"env0.users":        env0UsersProjections,

	// envkey generated projectors (sourcegen promotion)
	"envkey.applications": envkeyApplicationsProjections,
	"envkey.audit_events": envkeyAuditEventsProjections,
	"envkey.groups":       envkeyGroupsProjections,
	"envkey.roles":        envkeyRolesProjections,
	"envkey.users":        envkeyUsersProjections,

	// envoy generated projectors (sourcegen promotion)
	"envoy.audit_events": envoyAuditEventsProjections,
	"envoy.documents":    envoyDocumentsProjections,
	"envoy.groups":       envoyGroupsProjections,
	"envoy.users":        envoyUsersProjections,
	"envoy.workspaces":   envoyWorkspacesProjections,

	// envoy_visitors generated projectors (sourcegen promotion)
	"envoy_visitors.accounts":     envoyVisitorsAccountsProjections,
	"envoy_visitors.audit_events": envoyVisitorsAuditEventsProjections,
	"envoy_visitors.policies":     envoyVisitorsPoliciesProjections,
	"envoy_visitors.records":      envoyVisitorsRecordsProjections,
	"envoy_visitors.users":        envoyVisitorsUsersProjections,

	// ethena generated projectors (sourcegen promotion)
	"ethena.course_assignments": ethenaCourseAssignmentsProjections,
	"ethena.training_statuses":  ethenaTrainingStatusesProjections,
	"ethena.users":              ethenaUsersProjections,

	// everlaw generated projectors (sourcegen promotion)
	"everlaw.accounts":     everlawAccountsProjections,
	"everlaw.audit_events": everlawAuditEventsProjections,
	"everlaw.policies":     everlawPoliciesProjections,
	"everlaw.records":      everlawRecordsProjections,
	"everlaw.users":        everlawUsersProjections,

	// evernote_teams generated projectors (sourcegen promotion)
	"evernote_teams.audit_events": evernoteTeamsAuditEventsProjections,
	"evernote_teams.documents":    evernoteTeamsDocumentsProjections,
	"evernote_teams.groups":       evernoteTeamsGroupsProjections,
	"evernote_teams.users":        evernoteTeamsUsersProjections,
	"evernote_teams.workspaces":   evernoteTeamsWorkspacesProjections,

	// evisort generated projectors (sourcegen promotion)
	"evisort.accounts":     evisortAccountsProjections,
	"evisort.audit_events": evisortAuditEventsProjections,
	"evisort.policies":     evisortPoliciesProjections,
	"evisort.records":      evisortRecordsProjections,
	"evisort.users":        evisortUsersProjections,

	// exavault generated projectors (sourcegen promotion)
	"exavault.email_list":   exavaultEmailListProjections,
	"exavault.notification": exavaultNotificationProjections,
	"exavault.session":      exavaultSessionProjections,
	"exavault.ssh_key":      exavaultSshKeyProjections,

	// expel generated projectors (sourcegen promotion)
	"expel.assets":          expelAssetsProjections,
	"expel.audit_events":    expelAuditEventsProjections,
	"expel.findings":        expelFindingsProjections,
	"expel.policies":        expelPoliciesProjections,
	"expel.vulnerabilities": expelVulnerabilitiesProjections,

	// expensify generated projectors (sourcegen promotion)
	"expensify.accounts":     expensifyAccountsProjections,
	"expensify.audit_events": expensifyAuditEventsProjections,
	"expensify.policies":     expensifyPoliciesProjections,
	"expensify.records":      expensifyRecordsProjections,
	"expensify.users":        expensifyUsersProjections,

	// fairmarkit generated projectors (sourcegen promotion)
	"fairmarkit.accounts":     fairmarkitAccountsProjections,
	"fairmarkit.audit_events": fairmarkitAuditEventsProjections,
	"fairmarkit.policies":     fairmarkitPoliciesProjections,
	"fairmarkit.records":      fairmarkitRecordsProjections,
	"fairmarkit.users":        fairmarkitUsersProjections,

	// faros_ai generated projectors (sourcegen promotion)
	"faros_ai.assets":          farosAiAssetsProjections,
	"faros_ai.audit_events":    farosAiAuditEventsProjections,
	"faros_ai.findings":        farosAiFindingsProjections,
	"faros_ai.policies":        farosAiPoliciesProjections,
	"faros_ai.vulnerabilities": farosAiVulnerabilitiesProjections,

	// fastly generated projectors (sourcegen promotion)
	"fastly.acl_entries":  fastlyAclEntriesProjections,
	"fastly.audit_events": fastlyAuditEventsProjections,
	"fastly.services":     fastlyServicesProjections,

	// fathom_video generated projectors (sourcegen promotion)
	"fathom_video.audit_events": fathomVideoAuditEventsProjections,
	"fathom_video.documents":    fathomVideoDocumentsProjections,
	"fathom_video.groups":       fathomVideoGroupsProjections,
	"fathom_video.users":        fathomVideoUsersProjections,
	"fathom_video.workspaces":   fathomVideoWorkspacesProjections,

	// featurebase generated projectors (sourcegen promotion)
	"featurebase.audit_events": featurebaseAuditEventsProjections,
	"featurebase.deployments":  featurebaseDeploymentsProjections,
	"featurebase.projects":     featurebaseProjectsProjections,
	"featurebase.repositories": featurebaseRepositoriesProjections,
	"featurebase.users":        featurebaseUsersProjections,

	// fifteenfive generated projectors (sourcegen promotion)
	"fifteenfive.accounts":     fifteenfiveAccountsProjections,
	"fifteenfive.audit_events": fifteenfiveAuditEventsProjections,
	"fifteenfive.policies":     fifteenfivePoliciesProjections,
	"fifteenfive.records":      fifteenfiveRecordsProjections,
	"fifteenfive.users":        fifteenfiveUsersProjections,

	// figma generated projectors (sourcegen promotion)
	"figma.audit_events": figmaAuditEventsProjections,
	"figma.projects":     figmaProjectsProjections,
	"figma.users":        figmaUsersProjections,

	// files_com generated projectors (sourcegen promotion)
	"files_com.action_notification_export_result": filesComActionNotificationExportResultProjections,
	"files_com.api_key":                           filesComApiKeyProjections,
	"files_com.exavault_reserved":                 filesComExavaultReservedProjections,
	"files_com.external_event":                    filesComExternalEventProjections,
	"files_com.group":                             filesComGroupProjections,
	"files_com.group_user":                        filesComGroupUserProjections,
	"files_com.login":                             filesComLoginProjections,
	"files_com.permission":                        filesComPermissionProjections,
	"files_com.site_api_key":                      filesComSiteApiKeyProjections,
	"files_com.user":                              filesComUserProjections,
	"files_com.user_api_key":                      filesComUserApiKeyProjections,
	"files_com.user_group":                        filesComUserGroupProjections,

	// fireflies_ai generated projectors (sourcegen promotion)
	"fireflies_ai.audit_events": firefliesAiAuditEventsProjections,
	"fireflies_ai.documents":    firefliesAiDocumentsProjections,
	"fireflies_ai.groups":       firefliesAiGroupsProjections,
	"fireflies_ai.users":        firefliesAiUsersProjections,
	"fireflies_ai.workspaces":   firefliesAiWorkspacesProjections,

	// firefly generated projectors (sourcegen promotion)
	"firefly.audit_events": fireflyAuditEventsProjections,
	"firefly.deployments":  fireflyDeploymentsProjections,
	"firefly.projects":     fireflyProjectsProjections,
	"firefly.repositories": fireflyRepositoriesProjections,
	"firefly.users":        fireflyUsersProjections,

	// firehydrant generated projectors (sourcegen promotion)
	"firehydrant.alerts":       firehydrantAlertsProjections,
	"firehydrant.audit_events": firehydrantAuditEventsProjections,
	"firehydrant.dashboards":   firehydrantDashboardsProjections,
	"firehydrant.incidents":    firehydrantIncidentsProjections,
	"firehydrant.monitors":     firehydrantMonitorsProjections,

	// fireworks_ai generated projectors (sourcegen promotion)
	"fireworks_ai.audit_logs":        fireworksAiAuditLogsProjections,
	"fireworks_ai.billing_metrics":   fireworksAiBillingMetricsProjections,
	"fireworks_ai.model_deployments": fireworksAiModelDeploymentsProjections,
	"fireworks_ai.service_accounts":  fireworksAiServiceAccountsProjections,

	// firmalyzer generated projectors (sourcegen promotion)
	"firmalyzer.account":      firmalyzerAccountProjections,
	"firmalyzer.config_issue": firmalyzerConfigIssueProjections,
	"firmalyzer.private_key":  firmalyzerPrivateKeyProjections,
	"firmalyzer.risk":         firmalyzerRiskProjections,

	// five9 generated projectors (sourcegen promotion)
	"five9.accounts":     five9AccountsProjections,
	"five9.audit_events": five9AuditEventsProjections,
	"five9.policies":     five9PoliciesProjections,
	"five9.records":      five9RecordsProjections,
	"five9.users":        five9UsersProjections,

	// fivetran generated projectors (sourcegen promotion)
	"fivetran.accounts":     fivetranAccountsProjections,
	"fivetran.audit_events": fivetranAuditEventsProjections,
	"fivetran.policies":     fivetranPoliciesProjections,
	"fivetran.records":      fivetranRecordsProjections,
	"fivetran.users":        fivetranUsersProjections,

	// flagsmith_cloud generated projectors (sourcegen promotion)
	"flagsmith_cloud.audit_events": flagsmithCloudAuditEventsProjections,
	"flagsmith_cloud.deployments":  flagsmithCloudDeploymentsProjections,
	"flagsmith_cloud.projects":     flagsmithCloudProjectsProjections,
	"flagsmith_cloud.repositories": flagsmithCloudRepositoriesProjections,
	"flagsmith_cloud.users":        flagsmithCloudUsersProjections,

	// fleetdm generated projectors (sourcegen promotion)
	"fleetdm.audit_activities": fleetdmAuditActivitiesProjections,
	"fleetdm.hosts":            fleetdmHostsProjections,
	"fleetdm.policies":         fleetdmPoliciesProjections,

	// forethought generated projectors (sourcegen promotion)
	"forethought.accounts":     forethoughtAccountsProjections,
	"forethought.audit_events": forethoughtAuditEventsProjections,
	"forethought.policies":     forethoughtPoliciesProjections,
	"forethought.records":      forethoughtRecordsProjections,
	"forethought.users":        forethoughtUsersProjections,

	// formstack generated projectors (sourcegen promotion)
	"formstack.accounts":     formstackAccountsProjections,
	"formstack.audit_events": formstackAuditEventsProjections,
	"formstack.policies":     formstackPoliciesProjections,
	"formstack.records":      formstackRecordsProjections,
	"formstack.users":        formstackUsersProjections,

	// foxpass generated projectors (sourcegen promotion)
	"foxpass.applications": foxpassApplicationsProjections,
	"foxpass.audit_events": foxpassAuditEventsProjections,
	"foxpass.groups":       foxpassGroupsProjections,
	"foxpass.roles":        foxpassRolesProjections,
	"foxpass.users":        foxpassUsersProjections,

	// freshbooks generated projectors (sourcegen promotion)
	"freshbooks.accounts":     freshbooksAccountsProjections,
	"freshbooks.audit_events": freshbooksAuditEventsProjections,
	"freshbooks.policies":     freshbooksPoliciesProjections,
	"freshbooks.records":      freshbooksRecordsProjections,
	"freshbooks.users":        freshbooksUsersProjections,

	// freshdesk generated projectors (sourcegen promotion)
	"freshdesk.audit_events": freshdeskAuditEventsProjections,
	"freshdesk.documents":    freshdeskDocumentsProjections,
	"freshdesk.groups":       freshdeskGroupsProjections,
	"freshdesk.users":        freshdeskUsersProjections,
	"freshdesk.workspaces":   freshdeskWorkspacesProjections,

	// freshsales generated projectors (sourcegen promotion)
	"freshsales.accounts":     freshsalesAccountsProjections,
	"freshsales.audit_events": freshsalesAuditEventsProjections,
	"freshsales.policies":     freshsalesPoliciesProjections,
	"freshsales.records":      freshsalesRecordsProjections,
	"freshsales.users":        freshsalesUsersProjections,

	// freshservice generated projectors (sourcegen promotion)
	"freshservice.audit_events": freshserviceAuditEventsProjections,
	"freshservice.tickets":      freshserviceTicketsProjections,
	"freshservice.users":        freshserviceUsersProjections,

	// frontegg generated projectors (sourcegen promotion)
	"frontegg.applications": fronteggApplicationsProjections,
	"frontegg.audit_events": fronteggAuditEventsProjections,
	"frontegg.groups":       fronteggGroupsProjections,
	"frontegg.roles":        fronteggRolesProjections,
	"frontegg.users":        fronteggUsersProjections,

	// frontify generated projectors (sourcegen promotion)
	"frontify.audit_events": frontifyAuditEventsProjections,
	"frontify.documents":    frontifyDocumentsProjections,
	"frontify.groups":       frontifyGroupsProjections,
	"frontify.users":        frontifyUsersProjections,
	"frontify.workspaces":   frontifyWorkspacesProjections,

	// fulfillment_com generated projectors (sourcegen promotion)
	"fulfillment_com.accounting": fulfillmentComAccountingProjections,
	"fulfillment_com.inventory":  fulfillmentComInventoryProjections,
	"fulfillment_com.return":     fulfillmentComReturnProjections,
	"fulfillment_com.track":      fulfillmentComTrackProjections,

	// fullstory generated projectors (sourcegen promotion)
	"fullstory.alerts":       fullstoryAlertsProjections,
	"fullstory.audit_events": fullstoryAuditEventsProjections,
	"fullstory.dashboards":   fullstoryDashboardsProjections,
	"fullstory.incidents":    fullstoryIncidentsProjections,
	"fullstory.monitors":     fullstoryMonitorsProjections,

	// fusionauth generated projectors (sourcegen promotion)
	"fusionauth.applications": fusionauthApplicationsProjections,
	"fusionauth.audit_events": fusionauthAuditEventsProjections,
	"fusionauth.groups":       fusionauthGroupsProjections,
	"fusionauth.roles":        fusionauthRolesProjections,
	"fusionauth.users":        fusionauthUsersProjections,

	// gainsight generated projectors (sourcegen promotion)
	"gainsight.accounts":     gainsightAccountsProjections,
	"gainsight.audit_events": gainsightAuditEventsProjections,
	"gainsight.policies":     gainsightPoliciesProjections,
	"gainsight.records":      gainsightRecordsProjections,
	"gainsight.users":        gainsightUsersProjections,

	// gem generated projectors (sourcegen promotion)
	"gem.accounts":     gemAccountsProjections,
	"gem.audit_events": gemAuditEventsProjections,
	"gem.policies":     gemPoliciesProjections,
	"gem.records":      gemRecordsProjections,
	"gem.users":        gemUsersProjections,

	// genesys_cloud generated projectors (sourcegen promotion)
	"genesys_cloud.accounts":     genesysCloudAccountsProjections,
	"genesys_cloud.audit_events": genesysCloudAuditEventsProjections,
	"genesys_cloud.policies":     genesysCloudPoliciesProjections,
	"genesys_cloud.records":      genesysCloudRecordsProjections,
	"genesys_cloud.users":        genesysCloudUsersProjections,

	// gitbook generated projectors (sourcegen promotion)
	"gitbook.audit_events": gitbookAuditEventsProjections,
	"gitbook.documents":    gitbookDocumentsProjections,
	"gitbook.groups":       gitbookGroupsProjections,
	"gitbook.users":        gitbookUsersProjections,
	"gitbook.workspaces":   gitbookWorkspacesProjections,

	// gitea generated projectors (sourcegen promotion)
	"gitea.email":    giteaEmailProjections,
	"gitea.search":   giteaSearchProjections,
	"gitea.team":     giteaTeamProjections,
	"gitea.timeline": giteaTimelineProjections,

	// gitguardian generated projectors (sourcegen promotion)
	"gitguardian.audit_events": gitguardianAuditEventsProjections,
	"gitguardian.incidents":    gitguardianIncidentsProjections,
	"gitguardian.members":      gitguardianMembersProjections,

	// gitguardian_secrets generated projectors (sourcegen promotion)
	"gitguardian_secrets.audit_events": gitguardianSecretsAuditEventsProjections,
	"gitguardian_secrets.secrets":      gitguardianSecretsSecretsProjections,
	"gitguardian_secrets.sources":      gitguardianSecretsSourcesProjections,

	// gitlab generated projectors (sourcegen promotion)
	"gitlab.audit_events": gitlabAuditEventsProjections,
	"gitlab.repositories": gitlabRepositoriesProjections,
	"gitlab.users":        gitlabUsersProjections,

	// gitpod generated projectors (sourcegen promotion)
	"gitpod.audit_events": gitpodAuditEventsProjections,
	"gitpod.deployments":  gitpodDeploymentsProjections,
	"gitpod.projects":     gitpodProjectsProjections,
	"gitpod.repositories": gitpodRepositoriesProjections,
	"gitpod.users":        gitpodUsersProjections,

	// gladly generated projectors (sourcegen promotion)
	"gladly.audit_events": gladlyAuditEventsProjections,
	"gladly.documents":    gladlyDocumentsProjections,
	"gladly.groups":       gladlyGroupsProjections,
	"gladly.users":        gladlyUsersProjections,
	"gladly.workspaces":   gladlyWorkspacesProjections,

	// gocd generated projectors (sourcegen promotion)
	"gocd.audit_events": gocdAuditEventsProjections,
	"gocd.deployments":  gocdDeploymentsProjections,
	"gocd.projects":     gocdProjectsProjections,
	"gocd.repositories": gocdRepositoriesProjections,
	"gocd.users":        gocdUsersProjections,

	// godaddy generated projectors (sourcegen promotion)
	"godaddy.domain":      godaddyDomainProjections,
	"godaddy.maintenance": godaddyMaintenanceProjections,
	"godaddy.optin":       godaddyOptinProjections,
	"godaddy.tld":         godaddyTldProjections,

	// gong generated projectors (sourcegen promotion)
	"gong.accounts":     gongAccountsProjections,
	"gong.audit_events": gongAuditEventsProjections,
	"gong.policies":     gongPoliciesProjections,
	"gong.records":      gongRecordsProjections,
	"gong.users":        gongUsersProjections,

	// google_analytics_360 generated projectors (sourcegen promotion)
	"google_analytics_360.accounts":     googleAnalytics360AccountsProjections,
	"google_analytics_360.audit_events": googleAnalytics360AuditEventsProjections,
	"google_analytics_360.policies":     googleAnalytics360PoliciesProjections,
	"google_analytics_360.records":      googleAnalytics360RecordsProjections,
	"google_analytics_360.users":        googleAnalytics360UsersProjections,

	// google_drive generated projectors (sourcegen promotion)
	"google_drive.changes":       googleDriveChangesProjections,
	"google_drive.files":         googleDriveFilesProjections,
	"google_drive.shared_drives": googleDriveSharedDrivesProjections,

	// google_gemini generated projectors (sourcegen promotion)
	"google_gemini.batch_jobs":      googleGeminiBatchJobsProjections,
	"google_gemini.cached_contents": googleGeminiCachedContentsProjections,
	"google_gemini.files":           googleGeminiFilesProjections,
	"google_gemini.model_catalog":   googleGeminiModelCatalogProjections,
	"google_gemini.tuned_models":    googleGeminiTunedModelsProjections,

	// google_play_console generated projectors (sourcegen promotion)
	"google_play_console.audit_events": googlePlayConsoleAuditEventsProjections,
	"google_play_console.deployments":  googlePlayConsoleDeploymentsProjections,
	"google_play_console.projects":     googlePlayConsoleProjectsProjections,
	"google_play_console.repositories": googlePlayConsoleRepositoriesProjections,
	"google_play_console.users":        googlePlayConsoleUsersProjections,

	// google_secops_chronicle generated projectors (sourcegen promotion)
	"google_secops_chronicle.assets":       googleSecopsChronicleAssetsProjections,
	"google_secops_chronicle.audit_events": googleSecopsChronicleAuditEventsProjections,
	"google_secops_chronicle.findings":     googleSecopsChronicleFindingsProjections,

	// google_vertex_ai generated projectors (sourcegen promotion)
	"google_vertex_ai.batch_prediction_jobs": googleVertexAiBatchPredictionJobsProjections,
	"google_vertex_ai.custom_jobs":           googleVertexAiCustomJobsProjections,
	"google_vertex_ai.endpoints":             googleVertexAiEndpointsProjections,
	"google_vertex_ai.indexes":               googleVertexAiIndexesProjections,
	"google_vertex_ai.models":                googleVertexAiModelsProjections,
	"google_vertex_ai.reasoning_engines":     googleVertexAiReasoningEnginesProjections,

	// gorgias generated projectors (sourcegen promotion)
	"gorgias.audit_events": gorgiasAuditEventsProjections,
	"gorgias.documents":    gorgiasDocumentsProjections,
	"gorgias.groups":       gorgiasGroupsProjections,
	"gorgias.users":        gorgiasUsersProjections,
	"gorgias.workspaces":   gorgiasWorkspacesProjections,

	// grafana_cloud generated projectors (sourcegen promotion)
	"grafana_cloud.assets":       grafanaCloudAssetsProjections,
	"grafana_cloud.audit_events": grafanaCloudAuditEventsProjections,
	"grafana_cloud.findings":     grafanaCloudFindingsProjections,

	// grain generated projectors (sourcegen promotion)
	"grain.audit_events": grainAuditEventsProjections,
	"grain.documents":    grainDocumentsProjections,
	"grain.groups":       grainGroupsProjections,
	"grain.users":        grainUsersProjections,
	"grain.workspaces":   grainWorkspacesProjections,

	// grammarly_business generated projectors (sourcegen promotion)
	"grammarly_business.audit_events": grammarlyBusinessAuditEventsProjections,
	"grammarly_business.documents":    grammarlyBusinessDocumentsProjections,
	"grammarly_business.groups":       grammarlyBusinessGroupsProjections,
	"grammarly_business.users":        grammarlyBusinessUsersProjections,
	"grammarly_business.workspaces":   grammarlyBusinessWorkspacesProjections,

	// gravitee_cloud generated projectors (sourcegen promotion)
	"gravitee_cloud.audit_events": graviteeCloudAuditEventsProjections,
	"gravitee_cloud.deployments":  graviteeCloudDeploymentsProjections,
	"gravitee_cloud.projects":     graviteeCloudProjectsProjections,
	"gravitee_cloud.repositories": graviteeCloudRepositoriesProjections,
	"gravitee_cloud.users":        graviteeCloudUsersProjections,

	// greenhouse generated projectors (sourcegen promotion)
	"greenhouse.accounts":     greenhouseAccountsProjections,
	"greenhouse.audit_events": greenhouseAuditEventsProjections,
	"greenhouse.policies":     greenhousePoliciesProjections,
	"greenhouse.records":      greenhouseRecordsProjections,
	"greenhouse.users":        greenhouseUsersProjections,

	// greythr generated projectors (sourcegen promotion)
	"greythr.accounts":     greythrAccountsProjections,
	"greythr.audit_events": greythrAuditEventsProjections,
	"greythr.policies":     greythrPoliciesProjections,
	"greythr.records":      greythrRecordsProjections,
	"greythr.users":        greythrUsersProjections,

	// grip_security generated projectors (sourcegen promotion)
	"grip_security.applications": gripSecurityApplicationsProjections,
	"grip_security.audit_events": gripSecurityAuditEventsProjections,
	"grip_security.groups":       gripSecurityGroupsProjections,
	"grip_security.roles":        gripSecurityRolesProjections,
	"grip_security.users":        gripSecurityUsersProjections,

	// groq generated projectors (sourcegen promotion)
	"groq.batch_jobs":       groqBatchJobsProjections,
	"groq.files":            groqFilesProjections,
	"groq.fine_tuning_jobs": groqFineTuningJobsProjections,
	"groq.model_catalog":    groqModelCatalogProjections,

	// groundcover generated projectors (sourcegen promotion)
	"groundcover.alerts":       groundcoverAlertsProjections,
	"groundcover.audit_events": groundcoverAuditEventsProjections,
	"groundcover.dashboards":   groundcoverDashboardsProjections,
	"groundcover.incidents":    groundcoverIncidentsProjections,
	"groundcover.monitors":     groundcoverMonitorsProjections,

	// gsmtasks generated projectors (sourcegen promotion)
	"gsmtasks.account":               gsmtasksAccountProjections,
	"gsmtasks.account_role":          gsmtasksAccountRoleProjections,
	"gsmtasks.client_role":           gsmtasksClientRoleProjections,
	"gsmtasks.device":                gsmtasksDeviceProjections,
	"gsmtasks.email":                 gsmtasksEmailProjections,
	"gsmtasks.formrule":              gsmtasksFormruleProjections,
	"gsmtasks.notification":          gsmtasksNotificationProjections,
	"gsmtasks.notification_template": gsmtasksNotificationTemplateProjections,
	"gsmtasks.task_event":            gsmtasksTaskEventProjections,
	"gsmtasks.task_event_track":      gsmtasksTaskEventTrackProjections,
	"gsmtasks.user":                  gsmtasksUserProjections,
	"gsmtasks.users_on_duty_log":     gsmtasksUsersOnDutyLogProjections,

	// guru generated projectors (sourcegen promotion)
	"guru.audit_events": guruAuditEventsProjections,
	"guru.documents":    guruDocumentsProjections,
	"guru.groups":       guruGroupsProjections,
	"guru.users":        guruUsersProjections,
	"guru.workspaces":   guruWorkspacesProjections,

	// gusto generated projectors (sourcegen promotion)
	"gusto.accounts":     gustoAccountsProjections,
	"gusto.audit_events": gustoAuditEventsProjections,
	"gusto.policies":     gustoPoliciesProjections,
	"gusto.records":      gustoRecordsProjections,
	"gusto.users":        gustoUsersProjections,

	// hackerone generated projectors (sourcegen promotion)
	"hackerone.assets":          hackeroneAssetsProjections,
	"hackerone.audit_events":    hackeroneAuditEventsProjections,
	"hackerone.findings":        hackeroneFindingsProjections,
	"hackerone.policies":        hackeronePoliciesProjections,
	"hackerone.vulnerabilities": hackeroneVulnerabilitiesProjections,

	// hadrian_security generated projectors (sourcegen promotion)
	"hadrian_security.assets":          hadrianSecurityAssetsProjections,
	"hadrian_security.audit_events":    hadrianSecurityAuditEventsProjections,
	"hadrian_security.findings":        hadrianSecurityFindingsProjections,
	"hadrian_security.policies":        hadrianSecurityPoliciesProjections,
	"hadrian_security.vulnerabilities": hadrianSecurityVulnerabilitiesProjections,

	// harness generated projectors (sourcegen promotion)
	"harness.audit_events": harnessAuditEventsProjections,
	"harness.findings":     harnessFindingsProjections,
	"harness.pipelines":    harnessPipelinesProjections,

	// harness_platform generated projectors (sourcegen promotion)
	"harness_platform.audit_events": harnessPlatformAuditEventsProjections,
	"harness_platform.deployments":  harnessPlatformDeploymentsProjections,
	"harness_platform.projects":     harnessPlatformProjectsProjections,
	"harness_platform.repositories": harnessPlatformRepositoriesProjections,
	"harness_platform.users":        harnessPlatformUsersProjections,

	// haveibeenpwned generated projectors (sourcegen promotion)
	"haveibeenpwned.affected_accounts": haveibeenpwnedAffectedAccountsProjections,
	"haveibeenpwned.audit_events":      haveibeenpwnedAuditEventsProjections,
	"haveibeenpwned.breaches":          haveibeenpwnedBreachesProjections,

	// healthchecks generated projectors (sourcegen promotion)
	"healthchecks.alerts":       healthchecksAlertsProjections,
	"healthchecks.audit_events": healthchecksAuditEventsProjections,
	"healthchecks.dashboards":   healthchecksDashboardsProjections,
	"healthchecks.incidents":    healthchecksIncidentsProjections,
	"healthchecks.monitors":     healthchecksMonitorsProjections,

	// heap generated projectors (sourcegen promotion)
	"heap.accounts":     heapAccountsProjections,
	"heap.audit_events": heapAuditEventsProjections,
	"heap.policies":     heapPoliciesProjections,
	"heap.records":      heapRecordsProjections,
	"heap.users":        heapUsersProjections,

	// helpscout generated projectors (sourcegen promotion)
	"helpscout.audit_events": helpscoutAuditEventsProjections,
	"helpscout.documents":    helpscoutDocumentsProjections,
	"helpscout.groups":       helpscoutGroupsProjections,
	"helpscout.users":        helpscoutUsersProjections,
	"helpscout.workspaces":   helpscoutWorkspacesProjections,

	// heroku generated projectors (sourcegen promotion)
	"heroku.apps":          herokuAppsProjections,
	"heroku.audit_events":  herokuAuditEventsProjections,
	"heroku.collaborators": herokuCollaboratorsProjections,

	// hetzner generated projectors (sourcegen promotion)
	"hetzner.certificate":     hetznerCertificateProjections,
	"hetzner.firewall":        hetznerFirewallProjections,
	"hetzner.placement_group": hetznerPlacementGroupProjections,
	"hetzner.ssh_key":         hetznerSshKeyProjections,

	// hevo_data generated projectors (sourcegen promotion)
	"hevo_data.accounts":     hevoDataAccountsProjections,
	"hevo_data.audit_events": hevoDataAuditEventsProjections,
	"hevo_data.policies":     hevoDataPoliciesProjections,
	"hevo_data.records":      hevoDataRecordsProjections,
	"hevo_data.users":        hevoDataUsersProjections,

	// hexnode generated projectors (sourcegen promotion)
	"hexnode.applications": hexnodeApplicationsProjections,
	"hexnode.audit_events": hexnodeAuditEventsProjections,
	"hexnode.groups":       hexnodeGroupsProjections,
	"hexnode.roles":        hexnodeRolesProjections,
	"hexnode.users":        hexnodeUsersProjections,

	// hibob generated projectors (sourcegen promotion)
	"hibob.accounts":     hibobAccountsProjections,
	"hibob.audit_events": hibobAuditEventsProjections,
	"hibob.policies":     hibobPoliciesProjections,
	"hibob.records":      hibobRecordsProjections,
	"hibob.users":        hibobUsersProjections,

	// hid_workforce_identity generated projectors (sourcegen promotion)
	"hid_workforce_identity.applications": hidWorkforceIdentityApplicationsProjections,
	"hid_workforce_identity.audit_events": hidWorkforceIdentityAuditEventsProjections,
	"hid_workforce_identity.groups":       hidWorkforceIdentityGroupsProjections,
	"hid_workforce_identity.roles":        hidWorkforceIdentityRolesProjections,
	"hid_workforce_identity.users":        hidWorkforceIdentityUsersProjections,

	// highlight generated projectors (sourcegen promotion)
	"highlight.alerts":       highlightAlertsProjections,
	"highlight.audit_events": highlightAuditEventsProjections,
	"highlight.dashboards":   highlightDashboardsProjections,
	"highlight.incidents":    highlightIncidentsProjections,
	"highlight.monitors":     highlightMonitorsProjections,

	// highspot generated projectors (sourcegen promotion)
	"highspot.accounts":     highspotAccountsProjections,
	"highspot.audit_events": highspotAuditEventsProjections,
	"highspot.policies":     highspotPoliciesProjections,
	"highspot.records":      highspotRecordsProjections,
	"highspot.users":        highspotUsersProjections,

	// hightail generated projectors (sourcegen promotion)
	"hightail.audit_events": hightailAuditEventsProjections,
	"hightail.documents":    hightailDocumentsProjections,
	"hightail.groups":       hightailGroupsProjections,
	"hightail.users":        hightailUsersProjections,
	"hightail.workspaces":   hightailWorkspacesProjections,

	// hightouch generated projectors (sourcegen promotion)
	"hightouch.accounts":     hightouchAccountsProjections,
	"hightouch.audit_events": hightouchAuditEventsProjections,
	"hightouch.policies":     hightouchPoliciesProjections,
	"hightouch.records":      hightouchRecordsProjections,
	"hightouch.users":        hightouchUsersProjections,

	// hitrust_mycsf generated projectors (sourcegen promotion)
	"hitrust_mycsf.assessments": hitrustMycsfAssessmentsProjections,
	"hitrust_mycsf.controls":    hitrustMycsfControlsProjections,
	"hitrust_mycsf.evidence":    hitrustMycsfEvidenceProjections,

	// hive generated projectors (sourcegen promotion)
	"hive.audit_events": hiveAuditEventsProjections,
	"hive.documents":    hiveDocumentsProjections,
	"hive.groups":       hiveGroupsProjections,
	"hive.users":        hiveUsersProjections,
	"hive.workspaces":   hiveWorkspacesProjections,

	// holm_security generated projectors (sourcegen promotion)
	"holm_security.assets":          holmSecurityAssetsProjections,
	"holm_security.audit_events":    holmSecurityAuditEventsProjections,
	"holm_security.findings":        holmSecurityFindingsProjections,
	"holm_security.policies":        holmSecurityPoliciesProjections,
	"holm_security.vulnerabilities": holmSecurityVulnerabilitiesProjections,

	// honeybadger generated projectors (sourcegen promotion)
	"honeybadger.alerts":       honeybadgerAlertsProjections,
	"honeybadger.audit_events": honeybadgerAuditEventsProjections,
	"honeybadger.dashboards":   honeybadgerDashboardsProjections,
	"honeybadger.incidents":    honeybadgerIncidentsProjections,
	"honeybadger.monitors":     honeybadgerMonitorsProjections,

	// honeycomb generated projectors (sourcegen promotion)
	"honeycomb.alerts":       honeycombAlertsProjections,
	"honeycomb.audit_events": honeycombAuditEventsProjections,
	"honeycomb.dashboards":   honeycombDashboardsProjections,
	"honeycomb.incidents":    honeycombIncidentsProjections,
	"honeycomb.monitors":     honeycombMonitorsProjections,

	// hotjar generated projectors (sourcegen promotion)
	"hotjar.accounts":     hotjarAccountsProjections,
	"hotjar.audit_events": hotjarAuditEventsProjections,
	"hotjar.policies":     hotjarPoliciesProjections,
	"hotjar.records":      hotjarRecordsProjections,
	"hotjar.users":        hotjarUsersProjections,

	// hubspot generated projectors (sourcegen promotion)
	"hubspot.assets":       hubspotAssetsProjections,
	"hubspot.audit_events": hubspotAuditEventsProjections,
	"hubspot.users":        hubspotUsersProjections,

	// hudsonrock generated projectors (sourcegen promotion)
	"hudsonrock.audit_events": hudsonrockAuditEventsProjections,
	"hudsonrock.domains":      hudsonrockDomainsProjections,
	"hudsonrock.infostealers": hudsonrockInfostealersProjections,

	// huggingface generated projectors (sourcegen promotion)
	"huggingface.audit_logs":           huggingfaceAuditLogsProjections,
	"huggingface.organization_members": huggingfaceOrganizationMembersProjections,
	"huggingface.repositories":         huggingfaceRepositoriesProjections,
	"huggingface.resource_groups":      huggingfaceResourceGroupsProjections,

	// huntr generated projectors (sourcegen promotion)
	"huntr.assets":          huntrAssetsProjections,
	"huntr.audit_events":    huntrAuditEventsProjections,
	"huntr.findings":        huntrFindingsProjections,
	"huntr.policies":        huntrPoliciesProjections,
	"huntr.vulnerabilities": huntrVulnerabilitiesProjections,

	// hyperdx generated projectors (sourcegen promotion)
	"hyperdx.alerts":       hyperdxAlertsProjections,
	"hyperdx.audit_events": hyperdxAuditEventsProjections,
	"hyperdx.dashboards":   hyperdxDashboardsProjections,
	"hyperdx.incidents":    hyperdxIncidentsProjections,
	"hyperdx.monitors":     hyperdxMonitorsProjections,

	// hyperproof generated projectors (sourcegen promotion)
	"hyperproof.assets":          hyperproofAssetsProjections,
	"hyperproof.audit_events":    hyperproofAuditEventsProjections,
	"hyperproof.findings":        hyperproofFindingsProjections,
	"hyperproof.policies":        hyperproofPoliciesProjections,
	"hyperproof.vulnerabilities": hyperproofVulnerabilitiesProjections,

	// ibm_randori generated projectors (sourcegen promotion)
	"ibm_randori.assets":          ibmRandoriAssetsProjections,
	"ibm_randori.audit_events":    ibmRandoriAuditEventsProjections,
	"ibm_randori.findings":        ibmRandoriFindingsProjections,
	"ibm_randori.policies":        ibmRandoriPoliciesProjections,
	"ibm_randori.vulnerabilities": ibmRandoriVulnerabilitiesProjections,

	// ibm_watsonx_ai generated projectors (sourcegen promotion)
	"ibm_watsonx_ai.custom_models":          ibmWatsonxAiCustomModelsProjections,
	"ibm_watsonx_ai.deployments":            ibmWatsonxAiDeploymentsProjections,
	"ibm_watsonx_ai.foundation_model_specs": ibmWatsonxAiFoundationModelSpecsProjections,
	"ibm_watsonx_ai.foundation_model_tasks": ibmWatsonxAiFoundationModelTasksProjections,
	"ibm_watsonx_ai.training_jobs":          ibmWatsonxAiTrainingJobsProjections,

	// icertis generated projectors (sourcegen promotion)
	"icertis.accounts":     icertisAccountsProjections,
	"icertis.audit_events": icertisAuditEventsProjections,
	"icertis.policies":     icertisPoliciesProjections,
	"icertis.records":      icertisRecordsProjections,
	"icertis.users":        icertisUsersProjections,

	// icims generated projectors (sourcegen promotion)
	"icims.accounts":     icimsAccountsProjections,
	"icims.audit_events": icimsAuditEventsProjections,
	"icims.policies":     icimsPoliciesProjections,
	"icims.records":      icimsRecordsProjections,
	"icims.users":        icimsUsersProjections,

	// ilert generated projectors (sourcegen promotion)
	"ilert.alerts":       ilertAlertsProjections,
	"ilert.audit_events": ilertAuditEventsProjections,
	"ilert.dashboards":   ilertDashboardsProjections,
	"ilert.incidents":    ilertIncidentsProjections,
	"ilert.monitors":     ilertMonitorsProjections,

	// illumidesk generated projectors (sourcegen promotion)
	"illumidesk.application":  illumideskApplicationProjections,
	"illumidesk.card":         illumideskCardProjections,
	"illumidesk.deployment":   illumideskDeploymentProjections,
	"illumidesk.email":        illumideskEmailProjections,
	"illumidesk.entity":       illumideskEntityProjections,
	"illumidesk.group":        illumideskGroupProjections,
	"illumidesk.invoice":      illumideskInvoiceProjections,
	"illumidesk.notification": illumideskNotificationProjections,
	"illumidesk.profile":      illumideskProfileProjections,
	"illumidesk.server_size":  illumideskServerSizeProjections,
	"illumidesk.setting":      illumideskSettingProjections,
	"illumidesk.team":         illumideskTeamProjections,

	// imanage_cloud generated projectors (sourcegen promotion)
	"imanage_cloud.accounts":     imanageCloudAccountsProjections,
	"imanage_cloud.audit_events": imanageCloudAuditEventsProjections,
	"imanage_cloud.policies":     imanageCloudPoliciesProjections,
	"imanage_cloud.records":      imanageCloudRecordsProjections,
	"imanage_cloud.users":        imanageCloudUsersProjections,

	// immuta generated projectors (sourcegen promotion)
	"immuta.accounts":     immutaAccountsProjections,
	"immuta.audit_events": immutaAuditEventsProjections,
	"immuta.policies":     immutaPoliciesProjections,
	"immuta.records":      immutaRecordsProjections,
	"immuta.users":        immutaUsersProjections,

	// imprivata generated projectors (sourcegen promotion)
	"imprivata.applications": imprivataApplicationsProjections,
	"imprivata.audit_events": imprivataAuditEventsProjections,
	"imprivata.groups":       imprivataGroupsProjections,
	"imprivata.roles":        imprivataRolesProjections,
	"imprivata.users":        imprivataUsersProjections,

	// incident_io generated projectors (sourcegen promotion)
	"incident_io.alerts":       incidentIoAlertsProjections,
	"incident_io.audit_events": incidentIoAuditEventsProjections,
	"incident_io.dashboards":   incidentIoDashboardsProjections,
	"incident_io.incidents":    incidentIoIncidentsProjections,
	"incident_io.monitors":     incidentIoMonitorsProjections,

	// increase generated projectors (sourcegen promotion)
	"increase.account":              increaseAccountProjections,
	"increase.account_number":       increaseAccountNumberProjections,
	"increase.account_statement":    increaseAccountStatementProjections,
	"increase.account_transfer":     increaseAccountTransferProjections,
	"increase.ach_prenotification":  increaseAchPrenotificationProjections,
	"increase.ach_transfer":         increaseAchTransferProjections,
	"increase.card":                 increaseCardProjections,
	"increase.digital_wallet_token": increaseDigitalWalletTokenProjections,
	"increase.event":                increaseEventProjections,
	"increase.event_subscription":   increaseEventSubscriptionProjections,
	"increase.external_account":     increaseExternalAccountProjections,
	"increase.oauth_connection":     increaseOauthConnectionProjections,

	// infisical generated projectors (sourcegen promotion)
	"infisical.audit_events": infisicalAuditEventsProjections,
	"infisical.deployments":  infisicalDeploymentsProjections,
	"infisical.projects":     infisicalProjectsProjections,
	"infisical.repositories": infisicalRepositoriesProjections,
	"infisical.users":        infisicalUsersProjections,

	// influxdata generated projectors (sourcegen promotion)
	"influxdata.dbrp":   influxdataDbrpProjections,
	"influxdata.log":    influxdataLogProjections,
	"influxdata.secret": influxdataSecretProjections,
	"influxdata.user":   influxdataUserProjections,

	// insomnia_cloud generated projectors (sourcegen promotion)
	"insomnia_cloud.audit_events": insomniaCloudAuditEventsProjections,
	"insomnia_cloud.deployments":  insomniaCloudDeploymentsProjections,
	"insomnia_cloud.projects":     insomniaCloudProjectsProjections,
	"insomnia_cloud.repositories": insomniaCloudRepositoriesProjections,
	"insomnia_cloud.users":        insomniaCloudUsersProjections,

	// intercom generated projectors (sourcegen promotion)
	"intercom.audit_events": intercomAuditEventsProjections,
	"intercom.documents":    intercomDocumentsProjections,
	"intercom.groups":       intercomGroupsProjections,
	"intercom.users":        intercomUsersProjections,
	"intercom.workspaces":   intercomWorkspacesProjections,

	// intruder generated projectors (sourcegen promotion)
	"intruder.assets":          intruderAssetsProjections,
	"intruder.audit_events":    intruderAuditEventsProjections,
	"intruder.findings":        intruderFindingsProjections,
	"intruder.policies":        intruderPoliciesProjections,
	"intruder.vulnerabilities": intruderVulnerabilitiesProjections,

	// invicti generated projectors (sourcegen promotion)
	"invicti.assets":          invictiAssetsProjections,
	"invicti.audit_events":    invictiAuditEventsProjections,
	"invicti.findings":        invictiFindingsProjections,
	"invicti.policies":        invictiPoliciesProjections,
	"invicti.vulnerabilities": invictiVulnerabilitiesProjections,

	// iqualify generated projectors (sourcegen promotion)
	"iqualify.courses":           iqualifyCoursesProjections,
	"iqualify.current":           iqualifyCurrentProjections,
	"iqualify.future":            iqualifyFutureProjections,
	"iqualify.group":             iqualifyGroupProjections,
	"iqualify.learner":           iqualifyLearnerProjections,
	"iqualify.learners_progress": iqualifyLearnersProgressProjections,
	"iqualify.progress":          iqualifyProgressProjections,
	"iqualify.pulses":            iqualifyPulsesProjections,
	"iqualify.responses":         iqualifyResponsesProjections,
	"iqualify.social_note":       iqualifySocialNoteProjections,
	"iqualify.unit_reaction":     iqualifyUnitReactionProjections,
	"iqualify.user":              iqualifyUserProjections,

	// ironclad generated projectors (sourcegen promotion)
	"ironclad.accounts":     ironcladAccountsProjections,
	"ironclad.audit_events": ironcladAuditEventsProjections,
	"ironclad.policies":     ironcladPoliciesProjections,
	"ironclad.records":      ironcladRecordsProjections,
	"ironclad.users":        ironcladUsersProjections,

	// island generated projectors (sourcegen promotion)
	"island.applications": islandApplicationsProjections,
	"island.audit_events": islandAuditEventsProjections,
	"island.groups":       islandGroupsProjections,
	"island.roles":        islandRolesProjections,
	"island.users":        islandUsersProjections,

	// iterable generated projectors (sourcegen promotion)
	"iterable.accounts":     iterableAccountsProjections,
	"iterable.audit_events": iterableAuditEventsProjections,
	"iterable.policies":     iterablePoliciesProjections,
	"iterable.records":      iterableRecordsProjections,
	"iterable.users":        iterableUsersProjections,

	// jamf_pro generated projectors (sourcegen promotion)
	"jamf_pro.applications": jamfProApplicationsProjections,
	"jamf_pro.audit_events": jamfProAuditEventsProjections,
	"jamf_pro.groups":       jamfProGroupsProjections,
	"jamf_pro.roles":        jamfProRolesProjections,
	"jamf_pro.users":        jamfProUsersProjections,

	// jamf_protect generated projectors (sourcegen promotion)
	"jamf_protect.applications": jamfProtectApplicationsProjections,
	"jamf_protect.audit_events": jamfProtectAuditEventsProjections,
	"jamf_protect.groups":       jamfProtectGroupsProjections,
	"jamf_protect.roles":        jamfProtectRolesProjections,
	"jamf_protect.users":        jamfProtectUsersProjections,

	// jenkins generated projectors (sourcegen promotion)
	"jenkins.audit_events": jenkinsAuditEventsProjections,
	"jenkins.findings":     jenkinsFindingsProjections,
	"jenkins.pipelines":    jenkinsPipelinesProjections,

	// jetbrains_space generated projectors (sourcegen promotion)
	"jetbrains_space.audit_events": jetbrainsSpaceAuditEventsProjections,
	"jetbrains_space.deployments":  jetbrainsSpaceDeploymentsProjections,
	"jetbrains_space.projects":     jetbrainsSpaceProjectsProjections,
	"jetbrains_space.repositories": jetbrainsSpaceRepositoriesProjections,
	"jetbrains_space.users":        jetbrainsSpaceUsersProjections,

	// jfrog_artifactory generated projectors (sourcegen promotion)
	"jfrog_artifactory.audit_events": jfrogArtifactoryAuditEventsProjections,
	"jfrog_artifactory.deployments":  jfrogArtifactoryDeploymentsProjections,
	"jfrog_artifactory.projects":     jfrogArtifactoryProjectsProjections,
	"jfrog_artifactory.repositories": jfrogArtifactoryRepositoriesProjections,
	"jfrog_artifactory.users":        jfrogArtifactoryUsersProjections,

	// jfrog_artifactory_xray generated projectors (sourcegen promotion)
	"jfrog_artifactory_xray.assets":          jfrogArtifactoryXrayAssetsProjections,
	"jfrog_artifactory_xray.findings":        jfrogArtifactoryXrayFindingsProjections,
	"jfrog_artifactory_xray.vulnerabilities": jfrogArtifactoryXrayVulnerabilitiesProjections,

	// jfrog_xray generated projectors (sourcegen promotion)
	"jfrog_xray.audit_events": jfrogXrayAuditEventsProjections,
	"jfrog_xray.deployments":  jfrogXrayDeploymentsProjections,
	"jfrog_xray.projects":     jfrogXrayProjectsProjections,
	"jfrog_xray.repositories": jfrogXrayRepositoriesProjections,
	"jfrog_xray.users":        jfrogXrayUsersProjections,

	// jira generated projectors (sourcegen promotion)
	"jira.audit_events":       jiraAuditEventsProjections,
	"jira.group_members":      jiraGroupMembersProjections,
	"jira.groups":             jiraGroupsProjections,
	"jira.permission_schemes": jiraPermissionSchemesProjections,
	"jira.project_roles":      jiraProjectRolesProjections,
	"jira.projects":           jiraProjectsProjections,
	"jira.users":              jiraUsersProjections,

	// journy_io generated projectors (sourcegen promotion)
	"journy_io.account":          journyIoAccountProjections,
	"journy_io.event":            journyIoEventProjections,
	"journy_io.segments_account": journyIoSegmentsAccountProjections,
	"journy_io.segments_user":    journyIoSegmentsUserProjections,
	"journy_io.user":             journyIoUserProjections,

	// jumpcloud generated projectors (sourcegen promotion)
	"jumpcloud.audit_events": jumpcloudAuditEventsProjections,
	"jumpcloud.groups":       jumpcloudGroupsProjections,
	"jumpcloud.users":        jumpcloudUsersProjections,

	// jumpseller generated projectors (sourcegen promotion)
	"jumpseller.checkout_custom_fields_json": jumpsellerCheckoutCustomFieldsJsonProjections,
	"jumpseller.countries_json":              jumpsellerCountriesJsonProjections,
	"jumpseller.custom_fields_json":          jumpsellerCustomFieldsJsonProjections,
	"jumpseller.customer_categories_json":    jumpsellerCustomerCategoriesJsonProjections,
	"jumpseller.customers_json":              jumpsellerCustomersJsonProjections,
	"jumpseller.fulfillments_json":           jumpsellerFulfillmentsJsonProjections,
	"jumpseller.hooks_json":                  jumpsellerHooksJsonProjections,
	"jumpseller.jsapps_json":                 jumpsellerJsappsJsonProjections,
	"jumpseller.orders_json":                 jumpsellerOrdersJsonProjections,
	"jumpseller.pages_json":                  jumpsellerPagesJsonProjections,
	"jumpseller.payment_methods_json":        jumpsellerPaymentMethodsJsonProjections,
	"jumpseller.products_json":               jumpsellerProductsJsonProjections,

	// justworks generated projectors (sourcegen promotion)
	"justworks.accounts":     justworksAccountsProjections,
	"justworks.audit_events": justworksAuditEventsProjections,
	"justworks.policies":     justworksPoliciesProjections,
	"justworks.records":      justworksRecordsProjections,
	"justworks.users":        justworksUsersProjections,

	// k6_cloud generated projectors (sourcegen promotion)
	"k6_cloud.audit_events": k6CloudAuditEventsProjections,
	"k6_cloud.deployments":  k6CloudDeploymentsProjections,
	"k6_cloud.projects":     k6CloudProjectsProjections,
	"k6_cloud.repositories": k6CloudRepositoriesProjections,
	"k6_cloud.users":        k6CloudUsersProjections,

	// keeper generated projectors (sourcegen promotion)
	"keeper.audit_events": keeperAuditEventsProjections,
	"keeper.secrets":      keeperSecretsProjections,
	"keeper.users":        keeperUsersProjections,

	// keeper_security generated projectors (sourcegen promotion)
	"keeper_security.applications": keeperSecurityApplicationsProjections,
	"keeper_security.audit_events": keeperSecurityAuditEventsProjections,
	"keeper_security.groups":       keeperSecurityGroupsProjections,
	"keeper_security.roles":        keeperSecurityRolesProjections,
	"keeper_security.users":        keeperSecurityUsersProjections,

	// kenna_security generated projectors (sourcegen promotion)
	"kenna_security.assets":          kennaSecurityAssetsProjections,
	"kenna_security.audit_events":    kennaSecurityAuditEventsProjections,
	"kenna_security.findings":        kennaSecurityFindingsProjections,
	"kenna_security.policies":        kennaSecurityPoliciesProjections,
	"kenna_security.vulnerabilities": kennaSecurityVulnerabilitiesProjections,

	// kentik generated projectors (sourcegen promotion)
	"kentik.alerts":       kentikAlertsProjections,
	"kentik.audit_events": kentikAuditEventsProjections,
	"kentik.dashboards":   kentikDashboardsProjections,
	"kentik.incidents":    kentikIncidentsProjections,
	"kentik.monitors":     kentikMonitorsProjections,

	// keycloak generated projectors (sourcegen promotion)
	"keycloak.audit_events": keycloakAuditEventsProjections,
	"keycloak.groups":       keycloakGroupsProjections,
	"keycloak.users":        keycloakUsersProjections,

	// klaviyo generated projectors (sourcegen promotion)
	"klaviyo.accounts":     klaviyoAccountsProjections,
	"klaviyo.audit_events": klaviyoAuditEventsProjections,
	"klaviyo.policies":     klaviyoPoliciesProjections,
	"klaviyo.records":      klaviyoRecordsProjections,
	"klaviyo.users":        klaviyoUsersProjections,

	// knowbe4 generated projectors (sourcegen promotion)
	"knowbe4.groups":               knowbe4GroupsProjections,
	"knowbe4.phishing_campaigns":   knowbe4PhishingCampaignsProjections,
	"knowbe4.training_enrollments": knowbe4TrainingEnrollmentsProjections,
	"knowbe4.users":                knowbe4UsersProjections,

	// kong_konnect generated projectors (sourcegen promotion)
	"kong_konnect.audit_events": kongKonnectAuditEventsProjections,
	"kong_konnect.deployments":  kongKonnectDeploymentsProjections,
	"kong_konnect.projects":     kongKonnectProjectsProjections,
	"kong_konnect.repositories": kongKonnectRepositoriesProjections,
	"kong_konnect.users":        kongKonnectUsersProjections,

	// kustomer generated projectors (sourcegen promotion)
	"kustomer.audit_events": kustomerAuditEventsProjections,
	"kustomer.documents":    kustomerDocumentsProjections,
	"kustomer.groups":       kustomerGroupsProjections,
	"kustomer.users":        kustomerUsersProjections,
	"kustomer.workspaces":   kustomerWorkspacesProjections,

	// lacework generated projectors (sourcegen promotion)
	"lacework.assets":          laceworkAssetsProjections,
	"lacework.findings":        laceworkFindingsProjections,
	"lacework.vulnerabilities": laceworkVulnerabilitiesProjections,

	// lambdatest generated projectors (sourcegen promotion)
	"lambdatest.location":   lambdatestLocationProjections,
	"lambdatest.profile":    lambdatestProfileProjections,
	"lambdatest.resolution": lambdatestResolutionProjections,
	"lambdatest.resource":   lambdatestResourceProjections,

	// laminar_security generated projectors (sourcegen promotion)
	"laminar_security.assets":          laminarSecurityAssetsProjections,
	"laminar_security.audit_events":    laminarSecurityAuditEventsProjections,
	"laminar_security.findings":        laminarSecurityFindingsProjections,
	"laminar_security.policies":        laminarSecurityPoliciesProjections,
	"laminar_security.vulnerabilities": laminarSecurityVulnerabilitiesProjections,

	// last9 generated projectors (sourcegen promotion)
	"last9.alerts":       last9AlertsProjections,
	"last9.audit_events": last9AuditEventsProjections,
	"last9.dashboards":   last9DashboardsProjections,
	"last9.incidents":    last9IncidentsProjections,
	"last9.monitors":     last9MonitorsProjections,

	// lastpass_business generated projectors (sourcegen promotion)
	"lastpass_business.audit_events": lastpassBusinessAuditEventsProjections,
	"lastpass_business.secrets":      lastpassBusinessSecretsProjections,
	"lastpass_business.users":        lastpassBusinessUsersProjections,

	// lattice generated projectors (sourcegen promotion)
	"lattice.accounts":     latticeAccountsProjections,
	"lattice.audit_events": latticeAuditEventsProjections,
	"lattice.policies":     latticePoliciesProjections,
	"lattice.records":      latticeRecordsProjections,
	"lattice.users":        latticeUsersProjections,

	// launchdarkly generated projectors (sourcegen promotion)
	"launchdarkly.audit_events": launchdarklyAuditEventsProjections,
	"launchdarkly.repositories": launchdarklyRepositoriesProjections,
	"launchdarkly.users":        launchdarklyUsersProjections,

	// leapsome generated projectors (sourcegen promotion)
	"leapsome.accounts":     leapsomeAccountsProjections,
	"leapsome.audit_events": leapsomeAuditEventsProjections,
	"leapsome.policies":     leapsomePoliciesProjections,
	"leapsome.records":      leapsomeRecordsProjections,
	"leapsome.users":        leapsomeUsersProjections,

	// learnifier generated projectors (sourcegen promotion)
	"learnifier.coursedesign":       learnifierCoursedesignProjections,
	"learnifier.globalusergroup":    learnifierGlobalusergroupProjections,
	"learnifier.member":             learnifierMemberProjections,
	"learnifier.orgunit":            learnifierOrgunitProjections,
	"learnifier.orgunits_usergroup": learnifierOrgunitsUsergroupProjections,
	"learnifier.participant":        learnifierParticipantProjections,
	"learnifier.project":            learnifierProjectProjections,
	"learnifier.teammember":         learnifierTeammemberProjections,
	"learnifier.user":               learnifierUserProjections,
	"learnifier.usergroup":          learnifierUsergroupProjections,
	"learnifier.usergroups_member":  learnifierUsergroupsMemberProjections,

	// legit_security generated projectors (sourcegen promotion)
	"legit_security.assets":          legitSecurityAssetsProjections,
	"legit_security.audit_events":    legitSecurityAuditEventsProjections,
	"legit_security.findings":        legitSecurityFindingsProjections,
	"legit_security.policies":        legitSecurityPoliciesProjections,
	"legit_security.vulnerabilities": legitSecurityVulnerabilitiesProjections,

	// lessonly generated projectors (sourcegen promotion)
	"lessonly.accounts":     lessonlyAccountsProjections,
	"lessonly.audit_events": lessonlyAuditEventsProjections,
	"lessonly.policies":     lessonlyPoliciesProjections,
	"lessonly.records":      lessonlyRecordsProjections,
	"lessonly.users":        lessonlyUsersProjections,

	// lever generated projectors (sourcegen promotion)
	"lever.accounts":     leverAccountsProjections,
	"lever.audit_events": leverAuditEventsProjections,
	"lever.policies":     leverPoliciesProjections,
	"lever.records":      leverRecordsProjections,
	"lever.users":        leverUsersProjections,

	// lightstep generated projectors (sourcegen promotion)
	"lightstep.alerts":       lightstepAlertsProjections,
	"lightstep.audit_events": lightstepAuditEventsProjections,
	"lightstep.dashboards":   lightstepDashboardsProjections,
	"lightstep.incidents":    lightstepIncidentsProjections,
	"lightstep.monitors":     lightstepMonitorsProjections,

	// linear generated projectors (sourcegen promotion)
	"linear.audit_events": linearAuditEventsProjections,
	"linear.projects":     linearProjectsProjections,
	"linear.users":        linearUsersProjections,

	// linksquares generated projectors (sourcegen promotion)
	"linksquares.accounts":     linksquaresAccountsProjections,
	"linksquares.audit_events": linksquaresAuditEventsProjections,
	"linksquares.policies":     linksquaresPoliciesProjections,
	"linksquares.records":      linksquaresRecordsProjections,
	"linksquares.users":        linksquaresUsersProjections,

	// livestorm generated projectors (sourcegen promotion)
	"livestorm.audit_events": livestormAuditEventsProjections,
	"livestorm.documents":    livestormDocumentsProjections,
	"livestorm.groups":       livestormGroupsProjections,
	"livestorm.users":        livestormUsersProjections,
	"livestorm.workspaces":   livestormWorkspacesProjections,

	// logicgate generated projectors (sourcegen promotion)
	"logicgate.assets":          logicgateAssetsProjections,
	"logicgate.audit_events":    logicgateAuditEventsProjections,
	"logicgate.findings":        logicgateFindingsProjections,
	"logicgate.policies":        logicgatePoliciesProjections,
	"logicgate.vulnerabilities": logicgateVulnerabilitiesProjections,

	// logicmonitor generated projectors (sourcegen promotion)
	"logicmonitor.alerts":       logicmonitorAlertsProjections,
	"logicmonitor.audit_events": logicmonitorAuditEventsProjections,
	"logicmonitor.dashboards":   logicmonitorDashboardsProjections,
	"logicmonitor.incidents":    logicmonitorIncidentsProjections,
	"logicmonitor.monitors":     logicmonitorMonitorsProjections,

	// logrocket generated projectors (sourcegen promotion)
	"logrocket.alerts":       logrocketAlertsProjections,
	"logrocket.audit_events": logrocketAuditEventsProjections,
	"logrocket.dashboards":   logrocketDashboardsProjections,
	"logrocket.incidents":    logrocketIncidentsProjections,
	"logrocket.monitors":     logrocketMonitorsProjections,

	// logz_io generated projectors (sourcegen promotion)
	"logz_io.alerts":       logzIoAlertsProjections,
	"logz_io.audit_events": logzIoAuditEventsProjections,
	"logz_io.dashboards":   logzIoDashboardsProjections,
	"logz_io.incidents":    logzIoIncidentsProjections,
	"logz_io.monitors":     logzIoMonitorsProjections,

	// loket generated projectors (sourcegen promotion)
	"loket.actualorganizationalentity": loketActualorganizationalentityProjections,
	"loket.customnotification":         loketCustomnotificationProjections,
	"loket.emailidentity":              loketEmailidentityProjections,
	"loket.integration":                loketIntegrationProjections,

	// looker generated projectors (sourcegen promotion)
	"looker.accounts":     lookerAccountsProjections,
	"looker.audit_events": lookerAuditEventsProjections,
	"looker.policies":     lookerPoliciesProjections,
	"looker.records":      lookerRecordsProjections,
	"looker.users":        lookerUsersProjections,

	// loom generated projectors (sourcegen promotion)
	"loom.audit_events": loomAuditEventsProjections,
	"loom.documents":    loomDocumentsProjections,
	"loom.groups":       loomGroupsProjections,
	"loom.users":        loomUsersProjections,
	"loom.workspaces":   loomWorkspacesProjections,

	// lucidchart generated projectors (sourcegen promotion)
	"lucidchart.audit_events": lucidchartAuditEventsProjections,
	"lucidchart.documents":    lucidchartDocumentsProjections,
	"lucidchart.groups":       lucidchartGroupsProjections,
	"lucidchart.users":        lucidchartUsersProjections,
	"lucidchart.workspaces":   lucidchartWorkspacesProjections,

	// lucidscale generated projectors (sourcegen promotion)
	"lucidscale.audit_events": lucidscaleAuditEventsProjections,
	"lucidscale.documents":    lucidscaleDocumentsProjections,
	"lucidscale.groups":       lucidscaleGroupsProjections,
	"lucidscale.users":        lucidscaleUsersProjections,
	"lucidscale.workspaces":   lucidscaleWorkspacesProjections,

	// lumos_identity generated projectors (sourcegen promotion)
	"lumos_identity.applications": lumosIdentityApplicationsProjections,
	"lumos_identity.audit_events": lumosIdentityAuditEventsProjections,
	"lumos_identity.groups":       lumosIdentityGroupsProjections,
	"lumos_identity.roles":        lumosIdentityRolesProjections,
	"lumos_identity.users":        lumosIdentityUsersProjections,

	// mabl generated projectors (sourcegen promotion)
	"mabl.audit_events": mablAuditEventsProjections,
	"mabl.deployments":  mablDeploymentsProjections,
	"mabl.projects":     mablProjectsProjections,
	"mabl.repositories": mablRepositoriesProjections,
	"mabl.users":        mablUsersProjections,

	// magento generated projectors (sourcegen promotion)
	"magento.attribute":      magentoAttributeProjections,
	"magento.coupons_search": magentoCouponsSearchProjections,
	"magento.role":           magentoRoleProjections,
	"magento.search":         magentoSearchProjections,

	// mailchimp generated projectors (sourcegen promotion)
	"mailchimp.audit_events": mailchimpAuditEventsProjections,
	"mailchimp.lists":        mailchimpListsProjections,
	"mailchimp.members":      mailchimpMembersProjections,

	// mailscript generated projectors (sourcegen promotion)
	"mailscript.action":       mailscriptActionProjections,
	"mailscript.addresses":    mailscriptAddressesProjections,
	"mailscript.domain":       mailscriptDomainProjections,
	"mailscript.input":        mailscriptInputProjections,
	"mailscript.integration":  mailscriptIntegrationProjections,
	"mailscript.key":          mailscriptKeyProjections,
	"mailscript.trigger":      mailscriptTriggerProjections,
	"mailscript.verification": mailscriptVerificationProjections,
	"mailscript.verify":       mailscriptVerifyProjections,
	"mailscript.workflow":     mailscriptWorkflowProjections,
	"mailscript.workspace":    mailscriptWorkspaceProjections,

	// manageengine_endpoint_central generated projectors (sourcegen promotion)
	"manageengine_endpoint_central.applications": manageengineEndpointCentralApplicationsProjections,
	"manageengine_endpoint_central.audit_events": manageengineEndpointCentralAuditEventsProjections,
	"manageengine_endpoint_central.groups":       manageengineEndpointCentralGroupsProjections,
	"manageengine_endpoint_central.roles":        manageengineEndpointCentralRolesProjections,
	"manageengine_endpoint_central.users":        manageengineEndpointCentralUsersProjections,

	// mandiant_advantage generated projectors (sourcegen promotion)
	"mandiant_advantage.assets":          mandiantAdvantageAssetsProjections,
	"mandiant_advantage.audit_events":    mandiantAdvantageAuditEventsProjections,
	"mandiant_advantage.findings":        mandiantAdvantageFindingsProjections,
	"mandiant_advantage.policies":        mandiantAdvantagePoliciesProjections,
	"mandiant_advantage.vulnerabilities": mandiantAdvantageVulnerabilitiesProjections,

	// marketo generated projectors (sourcegen promotion)
	"marketo.accounts":     marketoAccountsProjections,
	"marketo.audit_events": marketoAuditEventsProjections,
	"marketo.policies":     marketoPoliciesProjections,
	"marketo.records":      marketoRecordsProjections,
	"marketo.users":        marketoUsersProjections,

	// mastodon generated projectors (sourcegen promotion)
	"mastodon.account":           mastodonAccountProjections,
	"mastodon.activity":          mastodonActivityProjections,
	"mastodon.notification":      mastodonNotificationProjections,
	"mastodon.verify_credential": mastodonVerifyCredentialProjections,

	// material_security generated projectors (sourcegen promotion)
	"material_security.assets":          materialSecurityAssetsProjections,
	"material_security.audit_events":    materialSecurityAuditEventsProjections,
	"material_security.findings":        materialSecurityFindingsProjections,
	"material_security.policies":        materialSecurityPoliciesProjections,
	"material_security.vulnerabilities": materialSecurityVulnerabilitiesProjections,

	// matillion generated projectors (sourcegen promotion)
	"matillion.accounts":     matillionAccountsProjections,
	"matillion.audit_events": matillionAuditEventsProjections,
	"matillion.policies":     matillionPoliciesProjections,
	"matillion.records":      matillionRecordsProjections,
	"matillion.users":        matillionUsersProjections,

	// maxio generated projectors (sourcegen promotion)
	"maxio.accounts":     maxioAccountsProjections,
	"maxio.audit_events": maxioAuditEventsProjections,
	"maxio.policies":     maxioPoliciesProjections,
	"maxio.records":      maxioRecordsProjections,
	"maxio.users":        maxioUsersProjections,

	// meistertask generated projectors (sourcegen promotion)
	"meistertask.audit_events": meistertaskAuditEventsProjections,
	"meistertask.documents":    meistertaskDocumentsProjections,
	"meistertask.groups":       meistertaskGroupsProjections,
	"meistertask.users":        meistertaskUsersProjections,
	"meistertask.workspaces":   meistertaskWorkspacesProjections,

	// mend_io generated projectors (sourcegen promotion)
	"mend_io.assets":          mendIoAssetsProjections,
	"mend_io.findings":        mendIoFindingsProjections,
	"mend_io.vulnerabilities": mendIoVulnerabilitiesProjections,

	// mentimeter generated projectors (sourcegen promotion)
	"mentimeter.audit_events": mentimeterAuditEventsProjections,
	"mentimeter.documents":    mentimeterDocumentsProjections,
	"mentimeter.groups":       mentimeterGroupsProjections,
	"mentimeter.users":        mentimeterUsersProjections,
	"mentimeter.workspaces":   mentimeterWorkspacesProjections,

	// mercury generated projectors (sourcegen promotion)
	"mercury.accounts":     mercuryAccountsProjections,
	"mercury.transactions": mercuryTransactionsProjections,
	"mercury.users":        mercuryUsersProjections,

	// mesh_payments generated projectors (sourcegen promotion)
	"mesh_payments.accounts":     meshPaymentsAccountsProjections,
	"mesh_payments.audit_events": meshPaymentsAuditEventsProjections,
	"mesh_payments.policies":     meshPaymentsPoliciesProjections,
	"mesh_payments.records":      meshPaymentsRecordsProjections,
	"mesh_payments.users":        meshPaymentsUsersProjections,

	// metaplane generated projectors (sourcegen promotion)
	"metaplane.accounts":     metaplaneAccountsProjections,
	"metaplane.audit_events": metaplaneAuditEventsProjections,
	"metaplane.policies":     metaplanePoliciesProjections,
	"metaplane.records":      metaplaneRecordsProjections,
	"metaplane.users":        metaplaneUsersProjections,

	// mezmo generated projectors (sourcegen promotion)
	"mezmo.alerts":       mezmoAlertsProjections,
	"mezmo.audit_events": mezmoAuditEventsProjections,
	"mezmo.dashboards":   mezmoDashboardsProjections,
	"mezmo.incidents":    mezmoIncidentsProjections,
	"mezmo.monitors":     mezmoMonitorsProjections,

	// microsoft_365 generated projectors (sourcegen promotion)
	"microsoft_365.audit_events":   microsoft365AuditEventsProjections,
	"microsoft_365.content_assets": microsoft365ContentAssetsProjections,
	"microsoft_365.users":          microsoft365UsersProjections,

	// microsoft_defender_for_cloud generated projectors (sourcegen promotion)
	"microsoft_defender_for_cloud.assets":          microsoftDefenderForCloudAssetsProjections,
	"microsoft_defender_for_cloud.findings":        microsoftDefenderForCloudFindingsProjections,
	"microsoft_defender_for_cloud.vulnerabilities": microsoftDefenderForCloudVulnerabilitiesProjections,

	// microsoft_defender_for_cloud_apps generated projectors (sourcegen promotion)
	"microsoft_defender_for_cloud_apps.assets":          microsoftDefenderForCloudAppsAssetsProjections,
	"microsoft_defender_for_cloud_apps.findings":        microsoftDefenderForCloudAppsFindingsProjections,
	"microsoft_defender_for_cloud_apps.vulnerabilities": microsoftDefenderForCloudAppsVulnerabilitiesProjections,

	// microsoft_defender_for_endpoint generated projectors (sourcegen promotion)
	"microsoft_defender_for_endpoint.endpoint_devices": microsoftDefenderForEndpointEndpointDevicesProjections,
	"microsoft_defender_for_endpoint.findings":         microsoftDefenderForEndpointFindingsProjections,
	"microsoft_defender_for_endpoint.vulnerabilities":  microsoftDefenderForEndpointVulnerabilitiesProjections,

	// microsoft_entra_id generated projectors (sourcegen promotion)
	"microsoft_entra_id.audit_events": microsoftEntraIdAuditEventsProjections,
	"microsoft_entra_id.groups":       microsoftEntraIdGroupsProjections,
	"microsoft_entra_id.users":        microsoftEntraIdUsersProjections,

	// microsoft_foundry generated projectors (sourcegen promotion)
	"microsoft_foundry.agents":      microsoftFoundryAgentsProjections,
	"microsoft_foundry.connections": microsoftFoundryConnectionsProjections,
	"microsoft_foundry.datasets":    microsoftFoundryDatasetsProjections,
	"microsoft_foundry.evaluations": microsoftFoundryEvaluationsProjections,
	"microsoft_foundry.indexes":     microsoftFoundryIndexesProjections,

	// microsoft_sentinel generated projectors (sourcegen promotion)
	"microsoft_sentinel.assets":       microsoftSentinelAssetsProjections,
	"microsoft_sentinel.audit_events": microsoftSentinelAuditEventsProjections,
	"microsoft_sentinel.findings":     microsoftSentinelFindingsProjections,

	// microsoft_teams generated projectors (sourcegen promotion)
	"microsoft_teams.audit_events":   microsoftTeamsAuditEventsProjections,
	"microsoft_teams.content_assets": microsoftTeamsContentAssetsProjections,
	"microsoft_teams.users":          microsoftTeamsUsersProjections,

	// mimecast generated projectors (sourcegen promotion)
	"mimecast.assets":          mimecastAssetsProjections,
	"mimecast.audit_events":    mimecastAuditEventsProjections,
	"mimecast.findings":        mimecastFindingsProjections,
	"mimecast.policies":        mimecastPoliciesProjections,
	"mimecast.vulnerabilities": mimecastVulnerabilitiesProjections,

	// miradore generated projectors (sourcegen promotion)
	"miradore.applications": miradoreApplicationsProjections,
	"miradore.audit_events": miradoreAuditEventsProjections,
	"miradore.groups":       miradoreGroupsProjections,
	"miradore.roles":        miradoreRolesProjections,
	"miradore.users":        miradoreUsersProjections,

	// miro generated projectors (sourcegen promotion)
	"miro.audit_events": miroAuditEventsProjections,
	"miro.projects":     miroProjectsProjections,
	"miro.users":        miroUsersProjections,

	// mist generated projectors (sourcegen promotion)
	"mist.alarmtemplate": mistAlarmtemplateProjections,
	"mist.call_event":    mistCallEventProjections,
	"mist.secpolicy":     mistSecpolicyProjections,
	"mist.sitegroup":     mistSitegroupProjections,

	// mistral generated projectors (sourcegen promotion)
	"mistral.api_keys":      mistralApiKeysProjections,
	"mistral.audit_logs":    mistralAuditLogsProjections,
	"mistral.usage_reports": mistralUsageReportsProjections,
	"mistral.workspaces":    mistralWorkspacesProjections,

	// mobileiron generated projectors (sourcegen promotion)
	"mobileiron.applications": mobileironApplicationsProjections,
	"mobileiron.audit_events": mobileironAuditEventsProjections,
	"mobileiron.groups":       mobileironGroupsProjections,
	"mobileiron.roles":        mobileironRolesProjections,
	"mobileiron.users":        mobileironUsersProjections,

	// mode_analytics generated projectors (sourcegen promotion)
	"mode_analytics.accounts":     modeAnalyticsAccountsProjections,
	"mode_analytics.audit_events": modeAnalyticsAuditEventsProjections,
	"mode_analytics.policies":     modeAnalyticsPoliciesProjections,
	"mode_analytics.records":      modeAnalyticsRecordsProjections,
	"mode_analytics.users":        modeAnalyticsUsersProjections,

	// monday_com generated projectors (sourcegen promotion)
	"monday_com.audit_events": mondayComAuditEventsProjections,
	"monday_com.projects":     mondayComProjectsProjections,
	"monday_com.users":        mondayComUsersProjections,

	// mongodb_atlas generated projectors (sourcegen promotion)
	"mongodb_atlas.assets":          mongodbAtlasAssetsProjections,
	"mongodb_atlas.audit_events":    mongodbAtlasAuditEventsProjections,
	"mongodb_atlas.vulnerabilities": mongodbAtlasVulnerabilitiesProjections,

	// monte_carlo_data generated projectors (sourcegen promotion)
	"monte_carlo_data.accounts":     monteCarloDataAccountsProjections,
	"monte_carlo_data.audit_events": monteCarloDataAuditEventsProjections,
	"monte_carlo_data.policies":     monteCarloDataPoliciesProjections,
	"monte_carlo_data.records":      monteCarloDataRecordsProjections,
	"monte_carlo_data.users":        monteCarloDataUsersProjections,

	// moogsoft generated projectors (sourcegen promotion)
	"moogsoft.alerts":       moogsoftAlertsProjections,
	"moogsoft.audit_events": moogsoftAuditEventsProjections,
	"moogsoft.dashboards":   moogsoftDashboardsProjections,
	"moogsoft.incidents":    moogsoftIncidentsProjections,
	"moogsoft.monitors":     moogsoftMonitorsProjections,

	// mosyle generated projectors (sourcegen promotion)
	"mosyle.applications": mosyleApplicationsProjections,
	"mosyle.audit_events": mosyleAuditEventsProjections,
	"mosyle.groups":       mosyleGroupsProjections,
	"mosyle.roles":        mosyleRolesProjections,
	"mosyle.users":        mosyleUsersProjections,

	// motaword generated projectors (sourcegen promotion)
	"motaword.activities_comment":   motawordActivitiesCommentProjections,
	"motaword.activity":             motawordActivityProjections,
	"motaword.blog":                 motawordBlogProjections,
	"motaword.comment":              motawordCommentProjections,
	"motaword.corporate_user":       motawordCorporateUserProjections,
	"motaword.corporate_user_group": motawordCorporateUserGroupProjections,
	"motaword.corporates_user":      motawordCorporatesUserProjections,
	"motaword.permission":           motawordPermissionProjections,
	"motaword.projects_activity":    motawordProjectsActivityProjections,
	"motaword.user":                 motawordUserProjections,
	"motaword.user_group":           motawordUserGroupProjections,
	"motaword.user_group_2":         motawordUserGroup2Projections,

	// mparticle generated projectors (sourcegen promotion)
	"mparticle.accounts":     mparticleAccountsProjections,
	"mparticle.audit_events": mparticleAuditEventsProjections,
	"mparticle.policies":     mparticlePoliciesProjections,
	"mparticle.records":      mparticleRecordsProjections,
	"mparticle.users":        mparticleUsersProjections,

	// mulesoft_anypoint generated projectors (sourcegen promotion)
	"mulesoft_anypoint.audit_events": mulesoftAnypointAuditEventsProjections,
	"mulesoft_anypoint.deployments":  mulesoftAnypointDeploymentsProjections,
	"mulesoft_anypoint.projects":     mulesoftAnypointProjectsProjections,
	"mulesoft_anypoint.repositories": mulesoftAnypointRepositoriesProjections,
	"mulesoft_anypoint.users":        mulesoftAnypointUsersProjections,

	// multiplier generated projectors (sourcegen promotion)
	"multiplier.accounts":     multiplierAccountsProjections,
	"multiplier.audit_events": multiplierAuditEventsProjections,
	"multiplier.policies":     multiplierPoliciesProjections,
	"multiplier.records":      multiplierRecordsProjections,
	"multiplier.users":        multiplierUsersProjections,

	// mural generated projectors (sourcegen promotion)
	"mural.audit_events": muralAuditEventsProjections,
	"mural.documents":    muralDocumentsProjections,
	"mural.groups":       muralGroupsProjections,
	"mural.users":        muralUsersProjections,
	"mural.workspaces":   muralWorkspacesProjections,

	// n_auth generated projectors (sourcegen promotion)
	"n_auth.account":    nAuthAccountProjections,
	"n_auth.apikey":     nAuthApikeyProjections,
	"n_auth.permission": nAuthPermissionProjections,
	"n_auth.user":       nAuthUserProjections,

	// namely generated projectors (sourcegen promotion)
	"namely.accounts":     namelyAccountsProjections,
	"namely.audit_events": namelyAuditEventsProjections,
	"namely.policies":     namelyPoliciesProjections,
	"namely.records":      namelyRecordsProjections,
	"namely.users":        namelyUsersProjections,

	// navan generated projectors (sourcegen promotion)
	"navan.accounts":     navanAccountsProjections,
	"navan.audit_events": navanAuditEventsProjections,
	"navan.policies":     navanPoliciesProjections,
	"navan.records":      navanRecordsProjections,
	"navan.users":        navanUsersProjections,

	// netboxdemo generated projectors (sourcegen promotion)
	"netboxdemo.cluster_group":    netboxdemoClusterGroupProjections,
	"netboxdemo.connected_device": netboxdemoConnectedDeviceProjections,
	"netboxdemo.device_role":      netboxdemoDeviceRoleProjections,
	"netboxdemo.secret":           netboxdemoSecretProjections,

	// netdocuments generated projectors (sourcegen promotion)
	"netdocuments.accounts":     netdocumentsAccountsProjections,
	"netdocuments.audit_events": netdocumentsAuditEventsProjections,
	"netdocuments.policies":     netdocumentsPoliciesProjections,
	"netdocuments.records":      netdocumentsRecordsProjections,
	"netdocuments.users":        netdocumentsUsersProjections,

	// netlicensing generated projectors (sourcegen promotion)
	"netlicensing.license":         netlicensingLicenseProjections,
	"netlicensing.licensee":        netlicensingLicenseeProjections,
	"netlicensing.licensetemplate": netlicensingLicensetemplateProjections,
	"netlicensing.token":           netlicensingTokenProjections,

	// netlify generated projectors (sourcegen promotion)
	"netlify.audit_events": netlifyAuditEventsProjections,
	"netlify.deployments":  netlifyDeploymentsProjections,
	"netlify.projects":     netlifyProjectsProjections,
	"netlify.repositories": netlifyRepositoriesProjections,
	"netlify.users":        netlifyUsersProjections,

	// netskope generated projectors (sourcegen promotion)
	"netskope.assets":          netskopeAssetsProjections,
	"netskope.audit_events":    netskopeAuditEventsProjections,
	"netskope.findings":        netskopeFindingsProjections,
	"netskope.policies":        netskopePoliciesProjections,
	"netskope.vulnerabilities": netskopeVulnerabilitiesProjections,

	// netspi_platform generated projectors (sourcegen promotion)
	"netspi_platform.assets":          netspiPlatformAssetsProjections,
	"netspi_platform.audit_events":    netspiPlatformAuditEventsProjections,
	"netspi_platform.findings":        netspiPlatformFindingsProjections,
	"netspi_platform.policies":        netspiPlatformPoliciesProjections,
	"netspi_platform.vulnerabilities": netspiPlatformVulnerabilitiesProjections,

	// netsuite generated projectors (sourcegen promotion)
	"netsuite.assets":       netsuiteAssetsProjections,
	"netsuite.audit_events": netsuiteAuditEventsProjections,
	"netsuite.users":        netsuiteUsersProjections,

	// neutrinoapi generated projectors (sourcegen promotion)
	"neutrinoapi.bin_lookup":      neutrinoapiBinLookupProjections,
	"neutrinoapi.geocode_address": neutrinoapiGeocodeAddressProjections,
	"neutrinoapi.host_reputation": neutrinoapiHostReputationProjections,
	"neutrinoapi.ip_blocklist":    neutrinoapiIpBlocklistProjections,

	// new_relic generated projectors (sourcegen promotion)
	"new_relic.assets":       newRelicAssetsProjections,
	"new_relic.audit_events": newRelicAuditEventsProjections,
	"new_relic.findings":     newRelicFindingsProjections,

	// nice_cxone generated projectors (sourcegen promotion)
	"nice_cxone.accounts":     niceCxoneAccountsProjections,
	"nice_cxone.audit_events": niceCxoneAuditEventsProjections,
	"nice_cxone.policies":     niceCxonePoliciesProjections,
	"nice_cxone.records":      niceCxoneRecordsProjections,
	"nice_cxone.users":        niceCxoneUsersProjections,

	// noetic_cyber generated projectors (sourcegen promotion)
	"noetic_cyber.assets":          noeticCyberAssetsProjections,
	"noetic_cyber.audit_events":    noeticCyberAuditEventsProjections,
	"noetic_cyber.findings":        noeticCyberFindingsProjections,
	"noetic_cyber.policies":        noeticCyberPoliciesProjections,
	"noetic_cyber.vulnerabilities": noeticCyberVulnerabilitiesProjections,

	// noname_security generated projectors (sourcegen promotion)
	"noname_security.assets":          nonameSecurityAssetsProjections,
	"noname_security.audit_events":    nonameSecurityAuditEventsProjections,
	"noname_security.findings":        nonameSecurityFindingsProjections,
	"noname_security.policies":        nonameSecurityPoliciesProjections,
	"noname_security.vulnerabilities": nonameSecurityVulnerabilitiesProjections,

	// noosh generated projectors (sourcegen promotion)
	"noosh.automaticinvitation":                   nooshAutomaticinvitationProjections,
	"noosh.billingrecipient":                      nooshBillingrecipientProjections,
	"noosh.clientworkgroup":                       nooshClientworkgroupProjections,
	"noosh.clientworkgroups_projecthomeuserfield": nooshClientworkgroupsProjecthomeuserfieldProjections,
	"noosh.memberrole":                            nooshMemberroleProjections,
	"noosh.projecthomeuserfield":                  nooshProjecthomeuserfieldProjections,
	"noosh.supplierworkgroup":                     nooshSupplierworkgroupProjections,
	"noosh.teammember":                            nooshTeammemberProjections,
	"noosh.teammembersofclientproject":            nooshTeammembersofclientprojectProjections,
	"noosh.teamtemplate":                          nooshTeamtemplateProjections,
	"noosh.workgroup":                             nooshWorkgroupProjections,
	"noosh.workgroupmember":                       nooshWorkgroupmemberProjections,

	// nordigen generated projectors (sourcegen promotion)
	"nordigen.account":     nordigenAccountProjections,
	"nordigen.creditor":    nordigenCreditorProjections,
	"nordigen.enduser":     nordigenEnduserProjections,
	"nordigen.institution": nordigenInstitutionProjections,

	// nordlayer generated projectors (sourcegen promotion)
	"nordlayer.applications": nordlayerApplicationsProjections,
	"nordlayer.audit_events": nordlayerAuditEventsProjections,
	"nordlayer.groups":       nordlayerGroupsProjections,
	"nordlayer.roles":        nordlayerRolesProjections,
	"nordlayer.users":        nordlayerUsersProjections,

	// normalyze generated projectors (sourcegen promotion)
	"normalyze.assets":          normalyzeAssetsProjections,
	"normalyze.audit_events":    normalyzeAuditEventsProjections,
	"normalyze.findings":        normalyzeFindingsProjections,
	"normalyze.policies":        normalyzePoliciesProjections,
	"normalyze.vulnerabilities": normalyzeVulnerabilitiesProjections,

	// notion generated projectors (sourcegen promotion)
	"notion.audit_events": notionAuditEventsProjections,
	"notion.projects":     notionProjectsProjections,
	"notion.users":        notionUsersProjections,

	// nucleus_security generated projectors (sourcegen promotion)
	"nucleus_security.assets":          nucleusSecurityAssetsProjections,
	"nucleus_security.audit_events":    nucleusSecurityAuditEventsProjections,
	"nucleus_security.findings":        nucleusSecurityFindingsProjections,
	"nucleus_security.policies":        nucleusSecurityPoliciesProjections,
	"nucleus_security.vulnerabilities": nucleusSecurityVulnerabilitiesProjections,

	// nuclino generated projectors (sourcegen promotion)
	"nuclino.audit_events": nuclinoAuditEventsProjections,
	"nuclino.documents":    nuclinoDocumentsProjections,
	"nuclino.groups":       nuclinoGroupsProjections,
	"nuclino.users":        nuclinoUsersProjections,
	"nuclino.workspaces":   nuclinoWorkspacesProjections,

	// nudge_security generated projectors (sourcegen promotion)
	"nudge_security.applications": nudgeSecurityApplicationsProjections,
	"nudge_security.audit_events": nudgeSecurityAuditEventsProjections,
	"nudge_security.groups":       nudgeSecurityGroupsProjections,
	"nudge_security.roles":        nudgeSecurityRolesProjections,
	"nudge_security.users":        nudgeSecurityUsersProjections,

	// observe_platform generated projectors (sourcegen promotion)
	"observe_platform.alerts":       observePlatformAlertsProjections,
	"observe_platform.audit_events": observePlatformAuditEventsProjections,
	"observe_platform.dashboards":   observePlatformDashboardsProjections,
	"observe_platform.incidents":    observePlatformIncidentsProjections,
	"observe_platform.monitors":     observePlatformMonitorsProjections,

	// obsidian_security generated projectors (sourcegen promotion)
	"obsidian_security.assets":          obsidianSecurityAssetsProjections,
	"obsidian_security.audit_events":    obsidianSecurityAuditEventsProjections,
	"obsidian_security.findings":        obsidianSecurityFindingsProjections,
	"obsidian_security.policies":        obsidianSecurityPoliciesProjections,
	"obsidian_security.vulnerabilities": obsidianSecurityVulnerabilitiesProjections,

	// octopus_deploy generated projectors (sourcegen promotion)
	"octopus_deploy.audit_events": octopusDeployAuditEventsProjections,
	"octopus_deploy.deployments":  octopusDeployDeploymentsProjections,
	"octopus_deploy.projects":     octopusDeployProjectsProjections,
	"octopus_deploy.repositories": octopusDeployRepositoriesProjections,
	"octopus_deploy.users":        octopusDeployUsersProjections,

	// office_space generated projectors (sourcegen promotion)
	"office_space.audit_events": officeSpaceAuditEventsProjections,
	"office_space.documents":    officeSpaceDocumentsProjections,
	"office_space.groups":       officeSpaceGroupsProjections,
	"office_space.users":        officeSpaceUsersProjections,
	"office_space.workspaces":   officeSpaceWorkspacesProjections,

	// omada_identity generated projectors (sourcegen promotion)
	"omada_identity.applications": omadaIdentityApplicationsProjections,
	"omada_identity.audit_events": omadaIdentityAuditEventsProjections,
	"omada_identity.groups":       omadaIdentityGroupsProjections,
	"omada_identity.roles":        omadaIdentityRolesProjections,
	"omada_identity.users":        omadaIdentityUsersProjections,

	// omni_analytics generated projectors (sourcegen promotion)
	"omni_analytics.accounts":     omniAnalyticsAccountsProjections,
	"omni_analytics.audit_events": omniAnalyticsAuditEventsProjections,
	"omni_analytics.policies":     omniAnalyticsPoliciesProjections,
	"omni_analytics.records":      omniAnalyticsRecordsProjections,
	"omni_analytics.users":        omniAnalyticsUsersProjections,

	// onelogin generated projectors (sourcegen promotion)
	"onelogin.audit_events": oneloginAuditEventsProjections,
	"onelogin.groups":       oneloginGroupsProjections,
	"onelogin.users":        oneloginUsersProjections,

	// onepassword_business generated projectors (sourcegen promotion)
	"onepassword_business.audit_events": onepasswordBusinessAuditEventsProjections,
	"onepassword_business.secrets":      onepasswordBusinessSecretsProjections,
	"onepassword_business.users":        onepasswordBusinessUsersProjections,

	// onetrust generated projectors (sourcegen promotion)
	"onetrust.controls": onetrustControlsProjections,
	"onetrust.findings": onetrustFindingsProjections,
	"onetrust.users":    onetrustUsersProjections,

	// opal_security generated projectors (sourcegen promotion)
	"opal_security.applications": opalSecurityApplicationsProjections,
	"opal_security.audit_events": opalSecurityAuditEventsProjections,
	"opal_security.groups":       opalSecurityGroupsProjections,
	"opal_security.roles":        opalSecurityRolesProjections,
	"opal_security.users":        opalSecurityUsersProjections,

	// opendatasoft generated projectors (sourcegen promotion)
	"opendatasoft.aggregate":          opendatasoftAggregateProjections,
	"opendatasoft.attachment":         opendatasoftAttachmentProjections,
	"opendatasoft.dataset":            opendatasoftDatasetProjections,
	"opendatasoft.datasets_aggregate": opendatasoftDatasetsAggregateProjections,
	"opendatasoft.datasets_facet":     opendatasoftDatasetsFacetProjections,
	"opendatasoft.facet":              opendatasoftFacetProjections,
	"opendatasoft.metadata_template":  opendatasoftMetadataTemplateProjections,
	"opendatasoft.page":               opendatasoftPageProjections,
	"opendatasoft.record":             opendatasoftRecordProjections,
	"opendatasoft.resource":           opendatasoftResourceProjections,
	"opendatasoft.resource_2":         opendatasoftResource2Projections,
	"opendatasoft.reuses":             opendatasoftReusesProjections,

	// openfintech generated projectors (sourcegen promotion)
	"openfintech.bank":         openfintechBankProjections,
	"openfintech.country":      openfintechCountryProjections,
	"openfintech.currency":     openfintechCurrencyProjections,
	"openfintech.organization": openfintechOrganizationProjections,

	// openpolicy generated projectors (sourcegen promotion)
	"openpolicy.data":      openpolicyDataProjections,
	"openpolicy.policy":    openpolicyPolicyProjections,
	"openpolicy.query":     openpolicyQueryProjections,
	"openpolicy.v1_policy": openpolicyV1PolicyProjections,

	// openrouter generated projectors (sourcegen promotion)
	"openrouter.api_keys":             openrouterApiKeysProjections,
	"openrouter.organization_members": openrouterOrganizationMembersProjections,
	"openrouter.provider_keys":        openrouterProviderKeysProjections,
	"openrouter.usage_reports":        openrouterUsageReportsProjections,

	// opsgenie generated projectors (sourcegen promotion)
	"opsgenie.audit_events": opsgenieAuditEventsProjections,
	"opsgenie.tickets":      opsgenieTicketsProjections,
	"opsgenie.users":        opsgenieUsersProjections,

	// opslevel generated projectors (sourcegen promotion)
	"opslevel.audit_events": opslevelAuditEventsProjections,
	"opslevel.deployments":  opslevelDeploymentsProjections,
	"opslevel.projects":     opslevelProjectsProjections,
	"opslevel.repositories": opslevelRepositoriesProjections,
	"opslevel.users":        opslevelUsersProjections,

	// optimizely_feature_experimentation generated projectors (sourcegen promotion)
	"optimizely_feature_experimentation.audit_events": optimizelyFeatureExperimentationAuditEventsProjections,
	"optimizely_feature_experimentation.deployments":  optimizelyFeatureExperimentationDeploymentsProjections,
	"optimizely_feature_experimentation.projects":     optimizelyFeatureExperimentationProjectsProjections,
	"optimizely_feature_experimentation.repositories": optimizelyFeatureExperimentationRepositoriesProjections,
	"optimizely_feature_experimentation.users":        optimizelyFeatureExperimentationUsersProjections,

	// oracle_hcm generated projectors (sourcegen promotion)
	"oracle_hcm.accounts":     oracleHcmAccountsProjections,
	"oracle_hcm.audit_events": oracleHcmAuditEventsProjections,
	"oracle_hcm.policies":     oracleHcmPoliciesProjections,
	"oracle_hcm.records":      oracleHcmRecordsProjections,
	"oracle_hcm.users":        oracleHcmUsersProjections,

	// orca generated projectors (sourcegen promotion)
	"orca.assets":          orcaAssetsProjections,
	"orca.findings":        orcaFindingsProjections,
	"orca.vulnerabilities": orcaVulnerabilitiesProjections,

	// orca_security generated projectors (sourcegen promotion)
	"orca_security.assets":          orcaSecurityAssetsProjections,
	"orca_security.audit_events":    orcaSecurityAuditEventsProjections,
	"orca_security.findings":        orcaSecurityFindingsProjections,
	"orca_security.policies":        orcaSecurityPoliciesProjections,
	"orca_security.vulnerabilities": orcaSecurityVulnerabilitiesProjections,

	// ordway generated projectors (sourcegen promotion)
	"ordway.accounts":     ordwayAccountsProjections,
	"ordway.audit_events": ordwayAuditEventsProjections,
	"ordway.policies":     ordwayPoliciesProjections,
	"ordway.records":      ordwayRecordsProjections,
	"ordway.users":        ordwayUsersProjections,

	// osisoft generated projectors (sourcegen promotion)
	"osisoft.analysisruleplugin":                  osisoftAnalysisrulepluginProjections,
	"osisoft.assetserver":                         osisoftAssetserverProjections,
	"osisoft.baseelementtemplate":                 osisoftBaseelementtemplateProjections,
	"osisoft.elements_eventframe":                 osisoftElementsEventframeProjections,
	"osisoft.elementtemplate":                     osisoftElementtemplateProjections,
	"osisoft.eventframe":                          osisoftEventframeProjections,
	"osisoft.eventframeattribute":                 osisoftEventframeattributeProjections,
	"osisoft.eventframes_eventframe":              osisoftEventframesEventframeProjections,
	"osisoft.eventframes_eventframeattribute":     osisoftEventframesEventframeattributeProjections,
	"osisoft.notificationcontacttemplates_search": osisoftNotificationcontacttemplatesSearchProjections,
	"osisoft.search":                              osisoftSearchProjections,
	"osisoft.securityidentity":                    osisoftSecurityidentityProjections,

	// otter_ai generated projectors (sourcegen promotion)
	"otter_ai.audit_events": otterAiAuditEventsProjections,
	"otter_ai.documents":    otterAiDocumentsProjections,
	"otter_ai.groups":       otterAiGroupsProjections,
	"otter_ai.users":        otterAiUsersProjections,
	"otter_ai.workspaces":   otterAiWorkspacesProjections,

	// outreach generated projectors (sourcegen promotion)
	"outreach.accounts":     outreachAccountsProjections,
	"outreach.audit_events": outreachAuditEventsProjections,
	"outreach.policies":     outreachPoliciesProjections,
	"outreach.records":      outreachRecordsProjections,
	"outreach.users":        outreachUsersProjections,

	// oyster_hr generated projectors (sourcegen promotion)
	"oyster_hr.accounts":     oysterHrAccountsProjections,
	"oyster_hr.audit_events": oysterHrAuditEventsProjections,
	"oyster_hr.policies":     oysterHrPoliciesProjections,
	"oyster_hr.records":      oysterHrRecordsProjections,
	"oyster_hr.users":        oysterHrUsersProjections,

	// paddle generated projectors (sourcegen promotion)
	"paddle.accounts":     paddleAccountsProjections,
	"paddle.audit_events": paddleAuditEventsProjections,
	"paddle.policies":     paddlePoliciesProjections,
	"paddle.records":      paddleRecordsProjections,
	"paddle.users":        paddleUsersProjections,

	// pandadoc generated projectors (sourcegen promotion)
	"pandadoc.accounts":     pandadocAccountsProjections,
	"pandadoc.audit_events": pandadocAuditEventsProjections,
	"pandadoc.policies":     pandadocPoliciesProjections,
	"pandadoc.records":      pandadocRecordsProjections,
	"pandadoc.users":        pandadocUsersProjections,

	// panther generated projectors (sourcegen promotion)
	"panther.assets":       pantherAssetsProjections,
	"panther.audit_events": pantherAuditEventsProjections,
	"panther.findings":     pantherFindingsProjections,

	// pathlock generated projectors (sourcegen promotion)
	"pathlock.applications": pathlockApplicationsProjections,
	"pathlock.audit_events": pathlockAuditEventsProjections,
	"pathlock.groups":       pathlockGroupsProjections,
	"pathlock.roles":        pathlockRolesProjections,
	"pathlock.users":        pathlockUsersProjections,

	// paychex_flex generated projectors (sourcegen promotion)
	"paychex_flex.accounts":     paychexFlexAccountsProjections,
	"paychex_flex.audit_events": paychexFlexAuditEventsProjections,
	"paychex_flex.policies":     paychexFlexPoliciesProjections,
	"paychex_flex.records":      paychexFlexRecordsProjections,
	"paychex_flex.users":        paychexFlexUsersProjections,

	// paycom generated projectors (sourcegen promotion)
	"paycom.accounts":     paycomAccountsProjections,
	"paycom.audit_events": paycomAuditEventsProjections,
	"paycom.policies":     paycomPoliciesProjections,
	"paycom.records":      paycomRecordsProjections,
	"paycom.users":        paycomUsersProjections,

	// paylocity generated projectors (sourcegen promotion)
	"paylocity.accounts":     paylocityAccountsProjections,
	"paylocity.audit_events": paylocityAuditEventsProjections,
	"paylocity.policies":     paylocityPoliciesProjections,
	"paylocity.records":      paylocityRecordsProjections,
	"paylocity.users":        paylocityUsersProjections,

	// paylocity_time generated projectors (sourcegen promotion)
	"paylocity_time.accounts":     paylocityTimeAccountsProjections,
	"paylocity_time.audit_events": paylocityTimeAuditEventsProjections,
	"paylocity_time.policies":     paylocityTimePoliciesProjections,
	"paylocity_time.records":      paylocityTimeRecordsProjections,
	"paylocity_time.users":        paylocityTimeUsersProjections,

	// pendo generated projectors (sourcegen promotion)
	"pendo.account": pendoAccountProjections,
	"pendo.feature": pendoFeatureProjections,
	"pendo.search":  pendoSearchProjections,
	"pendo.user":    pendoUserProjections,

	// perfecto generated projectors (sourcegen promotion)
	"perfecto.audit_events": perfectoAuditEventsProjections,
	"perfecto.deployments":  perfectoDeploymentsProjections,
	"perfecto.projects":     perfectoProjectsProjections,
	"perfecto.repositories": perfectoRepositoriesProjections,
	"perfecto.users":        perfectoUsersProjections,

	// perforce_helix_cloud generated projectors (sourcegen promotion)
	"perforce_helix_cloud.audit_events": perforceHelixCloudAuditEventsProjections,
	"perforce_helix_cloud.deployments":  perforceHelixCloudDeploymentsProjections,
	"perforce_helix_cloud.projects":     perforceHelixCloudProjectsProjections,
	"perforce_helix_cloud.repositories": perforceHelixCloudRepositoriesProjections,
	"perforce_helix_cloud.users":        perforceHelixCloudUsersProjections,

	// performyard generated projectors (sourcegen promotion)
	"performyard.accounts":     performyardAccountsProjections,
	"performyard.audit_events": performyardAuditEventsProjections,
	"performyard.policies":     performyardPoliciesProjections,
	"performyard.records":      performyardRecordsProjections,
	"performyard.users":        performyardUsersProjections,

	// perimeter81 generated projectors (sourcegen promotion)
	"perimeter81.applications": perimeter81ApplicationsProjections,
	"perimeter81.audit_events": perimeter81AuditEventsProjections,
	"perimeter81.groups":       perimeter81GroupsProjections,
	"perimeter81.roles":        perimeter81RolesProjections,
	"perimeter81.users":        perimeter81UsersProjections,

	// permit_io generated projectors (sourcegen promotion)
	"permit_io.applications": permitIoApplicationsProjections,
	"permit_io.audit_events": permitIoAuditEventsProjections,
	"permit_io.groups":       permitIoGroupsProjections,
	"permit_io.roles":        permitIoRolesProjections,
	"permit_io.users":        permitIoUsersProjections,

	// perplexity generated projectors (sourcegen promotion)
	"perplexity.api_groups":    perplexityApiGroupsProjections,
	"perplexity.api_keys":      perplexityApiKeysProjections,
	"perplexity.team_members":  perplexityTeamMembersProjections,
	"perplexity.usage_reports": perplexityUsageReportsProjections,

	// personio generated projectors (sourcegen promotion)
	"personio.accounts":     personioAccountsProjections,
	"personio.audit_events": personioAuditEventsProjections,
	"personio.policies":     personioPoliciesProjections,
	"personio.records":      personioRecordsProjections,
	"personio.users":        personioUsersProjections,

	// pinecone generated projectors (sourcegen promotion)
	"pinecone.backups":      pineconeBackupsProjections,
	"pinecone.collections":  pineconeCollectionsProjections,
	"pinecone.indexes":      pineconeIndexesProjections,
	"pinecone.restore_jobs": pineconeRestoreJobsProjections,

	// pingdom generated projectors (sourcegen promotion)
	"pingdom.alerts":       pingdomAlertsProjections,
	"pingdom.audit_events": pingdomAuditEventsProjections,
	"pingdom.dashboards":   pingdomDashboardsProjections,
	"pingdom.incidents":    pingdomIncidentsProjections,
	"pingdom.monitors":     pingdomMonitorsProjections,

	// pingone generated projectors (sourcegen promotion)
	"pingone.audit_events": pingoneAuditEventsProjections,
	"pingone.groups":       pingoneGroupsProjections,
	"pingone.users":        pingoneUsersProjections,

	// pipedrive generated projectors (sourcegen promotion)
	"pipedrive.accounts":     pipedriveAccountsProjections,
	"pipedrive.audit_events": pipedriveAuditEventsProjections,
	"pipedrive.policies":     pipedrivePoliciesProjections,
	"pipedrive.records":      pipedriveRecordsProjections,
	"pipedrive.users":        pipedriveUsersProjections,

	// pitch generated projectors (sourcegen promotion)
	"pitch.audit_events": pitchAuditEventsProjections,
	"pitch.documents":    pitchDocumentsProjections,
	"pitch.groups":       pitchGroupsProjections,
	"pitch.users":        pitchUsersProjections,
	"pitch.workspaces":   pitchWorkspacesProjections,

	// planview_adaptivework generated projectors (sourcegen promotion)
	"planview_adaptivework.audit_events": planviewAdaptiveworkAuditEventsProjections,
	"planview_adaptivework.documents":    planviewAdaptiveworkDocumentsProjections,
	"planview_adaptivework.groups":       planviewAdaptiveworkGroupsProjections,
	"planview_adaptivework.users":        planviewAdaptiveworkUsersProjections,
	"planview_adaptivework.workspaces":   planviewAdaptiveworkWorkspacesProjections,

	// platform_sh generated projectors (sourcegen promotion)
	"platform_sh.audit_events": platformShAuditEventsProjections,
	"platform_sh.deployments":  platformShDeploymentsProjections,
	"platform_sh.projects":     platformShProjectsProjections,
	"platform_sh.repositories": platformShRepositoriesProjections,
	"platform_sh.users":        platformShUsersProjections,

	// plextrac generated projectors (sourcegen promotion)
	"plextrac.assets":          plextracAssetsProjections,
	"plextrac.audit_events":    plextracAuditEventsProjections,
	"plextrac.findings":        plextracFindingsProjections,
	"plextrac.policies":        plextracPoliciesProjections,
	"plextrac.vulnerabilities": plextracVulnerabilitiesProjections,

	// portable generated projectors (sourcegen promotion)
	"portable.accounts":     portableAccountsProjections,
	"portable.audit_events": portableAuditEventsProjections,
	"portable.policies":     portablePoliciesProjections,
	"portable.records":      portableRecordsProjections,
	"portable.users":        portableUsersProjections,

	// portainer_cloud generated projectors (sourcegen promotion)
	"portainer_cloud.audit_events": portainerCloudAuditEventsProjections,
	"portainer_cloud.deployments":  portainerCloudDeploymentsProjections,
	"portainer_cloud.projects":     portainerCloudProjectsProjections,
	"portainer_cloud.repositories": portainerCloudRepositoriesProjections,
	"portainer_cloud.users":        portainerCloudUsersProjections,

	// portswigger_enterprise generated projectors (sourcegen promotion)
	"portswigger_enterprise.assets":          portswiggerEnterpriseAssetsProjections,
	"portswigger_enterprise.audit_events":    portswiggerEnterpriseAuditEventsProjections,
	"portswigger_enterprise.findings":        portswiggerEnterpriseFindingsProjections,
	"portswigger_enterprise.policies":        portswiggerEnterprisePoliciesProjections,
	"portswigger_enterprise.vulnerabilities": portswiggerEnterpriseVulnerabilitiesProjections,

	// postman generated projectors (sourcegen promotion)
	"postman.audit_events": postmanAuditEventsProjections,
	"postman.collections":  postmanCollectionsProjections,
	"postman.environments": postmanEnvironmentsProjections,

	// postmark generated projectors (sourcegen promotion)
	"postmark.audit_events": postmarkAuditEventsProjections,
	"postmark.domains":      postmarkDomainsProjections,
	"postmark.servers":      postmarkServersProjections,

	// power_bi generated projectors (sourcegen promotion)
	"power_bi.accounts":     powerBiAccountsProjections,
	"power_bi.audit_events": powerBiAuditEventsProjections,
	"power_bi.policies":     powerBiPoliciesProjections,
	"power_bi.records":      powerBiRecordsProjections,
	"power_bi.users":        powerBiUsersProjections,

	// prisma_cloud generated projectors (sourcegen promotion)
	"prisma_cloud.assets":          prismaCloudAssetsProjections,
	"prisma_cloud.findings":        prismaCloudFindingsProjections,
	"prisma_cloud.vulnerabilities": prismaCloudVulnerabilitiesProjections,

	// privacera generated projectors (sourcegen promotion)
	"privacera.assets":          privaceraAssetsProjections,
	"privacera.audit_events":    privaceraAuditEventsProjections,
	"privacera.findings":        privaceraFindingsProjections,
	"privacera.policies":        privaceraPoliciesProjections,
	"privacera.vulnerabilities": privaceraVulnerabilitiesProjections,

	// procurify generated projectors (sourcegen promotion)
	"procurify.accounts":     procurifyAccountsProjections,
	"procurify.audit_events": procurifyAuditEventsProjections,
	"procurify.policies":     procurifyPoliciesProjections,
	"procurify.records":      procurifyRecordsProjections,
	"procurify.users":        procurifyUsersProjections,

	// productboard generated projectors (sourcegen promotion)
	"productboard.audit_events": productboardAuditEventsProjections,
	"productboard.deployments":  productboardDeploymentsProjections,
	"productboard.projects":     productboardProjectsProjections,
	"productboard.repositories": productboardRepositoriesProjections,
	"productboard.users":        productboardUsersProjections,

	// productiv generated projectors (sourcegen promotion)
	"productiv.applications": productivApplicationsProjections,
	"productiv.audit_events": productivAuditEventsProjections,
	"productiv.groups":       productivGroupsProjections,
	"productiv.roles":        productivRolesProjections,
	"productiv.users":        productivUsersProjections,

	// proofpoint generated projectors (sourcegen promotion)
	"proofpoint.assets":          proofpointAssetsProjections,
	"proofpoint.audit_events":    proofpointAuditEventsProjections,
	"proofpoint.findings":        proofpointFindingsProjections,
	"proofpoint.policies":        proofpointPoliciesProjections,
	"proofpoint.vulnerabilities": proofpointVulnerabilitiesProjections,

	// proposify generated projectors (sourcegen promotion)
	"proposify.accounts":     proposifyAccountsProjections,
	"proposify.audit_events": proposifyAuditEventsProjections,
	"proposify.policies":     proposifyPoliciesProjections,
	"proposify.records":      proposifyRecordsProjections,
	"proposify.users":        proposifyUsersProjections,

	// pulumi_cloud generated projectors (sourcegen promotion)
	"pulumi_cloud.audit_events": pulumiCloudAuditEventsProjections,
	"pulumi_cloud.repositories": pulumiCloudRepositoriesProjections,
	"pulumi_cloud.users":        pulumiCloudUsersProjections,

	// push_security generated projectors (sourcegen promotion)
	"push_security.applications": pushSecurityApplicationsProjections,
	"push_security.audit_events": pushSecurityAuditEventsProjections,
	"push_security.groups":       pushSecurityGroupsProjections,
	"push_security.roles":        pushSecurityRolesProjections,
	"push_security.users":        pushSecurityUsersProjections,

	// qdrant_cloud generated projectors (sourcegen promotion)
	"qdrant_cloud.account_members":   qdrantCloudAccountMembersProjections,
	"qdrant_cloud.accounts":          qdrantCloudAccountsProjections,
	"qdrant_cloud.backup_restores":   qdrantCloudBackupRestoresProjections,
	"qdrant_cloud.backup_schedules":  qdrantCloudBackupSchedulesProjections,
	"qdrant_cloud.backups":           qdrantCloudBackupsProjections,
	"qdrant_cloud.clusters":          qdrantCloudClustersProjections,
	"qdrant_cloud.database_api_keys": qdrantCloudDatabaseApiKeysProjections,
	"qdrant_cloud.roles":             qdrantCloudRolesProjections,

	// qodo generated projectors (sourcegen promotion)
	"qodo.audit_events": qodoAuditEventsProjections,
	"qodo.deployments":  qodoDeploymentsProjections,
	"qodo.projects":     qodoProjectsProjections,
	"qodo.repositories": qodoRepositoriesProjections,
	"qodo.users":        qodoUsersProjections,

	// qualtrics generated projectors (sourcegen promotion)
	"qualtrics.accounts":     qualtricsAccountsProjections,
	"qualtrics.audit_events": qualtricsAuditEventsProjections,
	"qualtrics.policies":     qualtricsPoliciesProjections,
	"qualtrics.records":      qualtricsRecordsProjections,
	"qualtrics.users":        qualtricsUsersProjections,

	// qualys_vm generated projectors (sourcegen promotion)
	"qualys_vm.assets":          qualysVmAssetsProjections,
	"qualys_vm.audit_events":    qualysVmAuditEventsProjections,
	"qualys_vm.findings":        qualysVmFindingsProjections,
	"qualys_vm.policies":        qualysVmPoliciesProjections,
	"qualys_vm.vulnerabilities": qualysVmVulnerabilitiesProjections,

	// qualys_vmdr generated projectors (sourcegen promotion)
	"qualys_vmdr.assets":          qualysVmdrAssetsProjections,
	"qualys_vmdr.findings":        qualysVmdrFindingsProjections,
	"qualys_vmdr.vulnerabilities": qualysVmdrVulnerabilitiesProjections,

	// quay generated projectors (sourcegen promotion)
	"quay.audit_events": quayAuditEventsProjections,
	"quay.deployments":  quayDeploymentsProjections,
	"quay.projects":     quayProjectsProjections,
	"quay.repositories": quayRepositoriesProjections,
	"quay.users":        quayUsersProjections,

	// quickbase generated projectors (sourcegen promotion)
	"quickbase.accounts":     quickbaseAccountsProjections,
	"quickbase.audit_events": quickbaseAuditEventsProjections,
	"quickbase.policies":     quickbasePoliciesProjections,
	"quickbase.records":      quickbaseRecordsProjections,
	"quickbase.users":        quickbaseUsersProjections,

	// quickbooks_online generated projectors (sourcegen promotion)
	"quickbooks_online.accounts":     quickbooksOnlineAccountsProjections,
	"quickbooks_online.audit_events": quickbooksOnlineAuditEventsProjections,
	"quickbooks_online.policies":     quickbooksOnlinePoliciesProjections,
	"quickbooks_online.records":      quickbooksOnlineRecordsProjections,
	"quickbooks_online.users":        quickbooksOnlineUsersProjections,

	// quip generated projectors (sourcegen promotion)
	"quip.audit_events": quipAuditEventsProjections,
	"quip.documents":    quipDocumentsProjections,
	"quip.groups":       quipGroupsProjections,
	"quip.users":        quipUsersProjections,
	"quip.workspaces":   quipWorkspacesProjections,

	// rally generated projectors (sourcegen promotion)
	"rally.audit_events": rallyAuditEventsProjections,
	"rally.deployments":  rallyDeploymentsProjections,
	"rally.projects":     rallyProjectsProjections,
	"rally.repositories": rallyRepositoriesProjections,
	"rally.users":        rallyUsersProjections,

	// ramp generated projectors (sourcegen promotion)
	"ramp.cards":        rampCardsProjections,
	"ramp.transactions": rampTransactionsProjections,
	"ramp.users":        rampUsersProjections,

	// rapid7_insightidr generated projectors (sourcegen promotion)
	"rapid7_insightidr.assets":          rapid7InsightidrAssetsProjections,
	"rapid7_insightidr.audit_events":    rapid7InsightidrAuditEventsProjections,
	"rapid7_insightidr.findings":        rapid7InsightidrFindingsProjections,
	"rapid7_insightidr.policies":        rapid7InsightidrPoliciesProjections,
	"rapid7_insightidr.vulnerabilities": rapid7InsightidrVulnerabilitiesProjections,

	// rapid7_insightvm generated projectors (sourcegen promotion)
	"rapid7_insightvm.assets":          rapid7InsightvmAssetsProjections,
	"rapid7_insightvm.findings":        rapid7InsightvmFindingsProjections,
	"rapid7_insightvm.vulnerabilities": rapid7InsightvmVulnerabilitiesProjections,

	// raygun generated projectors (sourcegen promotion)
	"raygun.audit_events": raygunAuditEventsProjections,
	"raygun.deployments":  raygunDeploymentsProjections,
	"raygun.projects":     raygunProjectsProjections,
	"raygun.repositories": raygunRepositoriesProjections,
	"raygun.users":        raygunUsersProjections,

	// readme generated projectors (sourcegen promotion)
	"readme.audit_events": readmeAuditEventsProjections,
	"readme.deployments":  readmeDeploymentsProjections,
	"readme.projects":     readmeProjectsProjections,
	"readme.repositories": readmeRepositoriesProjections,
	"readme.users":        readmeUsersProjections,

	// rebilly generated projectors (sourcegen promotion)
	"rebilly.aml":                            rebillyAmlProjections,
	"rebilly.authentication_token":           rebillyAuthenticationTokenProjections,
	"rebilly.bank_account":                   rebillyBankAccountProjections,
	"rebilly.customer_timeline_custom_event": rebillyCustomerTimelineCustomEventProjections,

	// recharge generated projectors (sourcegen promotion)
	"recharge.accounts":     rechargeAccountsProjections,
	"recharge.audit_events": rechargeAuditEventsProjections,
	"recharge.policies":     rechargePoliciesProjections,
	"recharge.records":      rechargeRecordsProjections,
	"recharge.users":        rechargeUsersProjections,

	// reco_security generated projectors (sourcegen promotion)
	"reco_security.assets":          recoSecurityAssetsProjections,
	"reco_security.audit_events":    recoSecurityAuditEventsProjections,
	"reco_security.findings":        recoSecurityFindingsProjections,
	"reco_security.policies":        recoSecurityPoliciesProjections,
	"reco_security.vulnerabilities": recoSecurityVulnerabilitiesProjections,

	// recorded_future generated projectors (sourcegen promotion)
	"recorded_future.assets":          recordedFutureAssetsProjections,
	"recorded_future.findings":        recordedFutureFindingsProjections,
	"recorded_future.vulnerabilities": recordedFutureVulnerabilitiesProjections,

	// recurly generated projectors (sourcegen promotion)
	"recurly.accounts":     recurlyAccountsProjections,
	"recurly.audit_events": recurlyAuditEventsProjections,
	"recurly.policies":     recurlyPoliciesProjections,
	"recurly.records":      recurlyRecordsProjections,
	"recurly.users":        recurlyUsersProjections,

	// red_canary generated projectors (sourcegen promotion)
	"red_canary.assets":          redCanaryAssetsProjections,
	"red_canary.audit_events":    redCanaryAuditEventsProjections,
	"red_canary.findings":        redCanaryFindingsProjections,
	"red_canary.policies":        redCanaryPoliciesProjections,
	"red_canary.vulnerabilities": redCanaryVulnerabilitiesProjections,

	// redhat generated projectors (sourcegen promotion)
	"redhat.advisory":         redhatAdvisoryProjections,
	"redhat.package":          redhatPackageProjections,
	"redhat.systems_advisory": redhatSystemsAdvisoryProjections,
	"redhat.v1_package":       redhatV1PackageProjections,

	// redirection_io generated projectors (sourcegen promotion)
	"redirection_io.agent_rule":          redirectionIoAgentRuleProjections,
	"redirection_io.agent_rule_complexe": redirectionIoAgentRuleComplexeProjections,
	"redirection_io.agent_rule_straight": redirectionIoAgentRuleStraightProjections,
	"redirection_io.aggregate_log":       redirectionIoAggregateLogProjections,
	"redirection_io.export_rule":         redirectionIoExportRuleProjections,
	"redirection_io.log":                 redirectionIoLogProjections,
	"redirection_io.notification":        redirectionIoNotificationProjections,
	"redirection_io.rule":                redirectionIoRuleProjections,
	"redirection_io.rule_change":         redirectionIoRuleChangeProjections,
	"redirection_io.rule_set_version":    redirectionIoRuleSetVersionProjections,
	"redirection_io.smart_list":          redirectionIoSmartListProjections,
	"redirection_io.user":                redirectionIoUserProjections,

	// relativity_one generated projectors (sourcegen promotion)
	"relativity_one.accounts":     relativityOneAccountsProjections,
	"relativity_one.audit_events": relativityOneAuditEventsProjections,
	"relativity_one.policies":     relativityOnePoliciesProjections,
	"relativity_one.records":      relativityOneRecordsProjections,
	"relativity_one.users":        relativityOneUsersProjections,

	// remote_com generated projectors (sourcegen promotion)
	"remote_com.accounts":     remoteComAccountsProjections,
	"remote_com.audit_events": remoteComAuditEventsProjections,
	"remote_com.policies":     remoteComPoliciesProjections,
	"remote_com.records":      remoteComRecordsProjections,
	"remote_com.users":        remoteComUsersProjections,

	// render_cloud generated projectors (sourcegen promotion)
	"render_cloud.audit_events": renderCloudAuditEventsProjections,
	"render_cloud.deployments":  renderCloudDeploymentsProjections,
	"render_cloud.projects":     renderCloudProjectsProjections,
	"render_cloud.repositories": renderCloudRepositoriesProjections,
	"render_cloud.users":        renderCloudUsersProjections,

	// replicate generated projectors (sourcegen promotion)
	"replicate.collections": replicateCollectionsProjections,
	"replicate.deployments": replicateDeploymentsProjections,
	"replicate.models":      replicateModelsProjections,
	"replicate.predictions": replicatePredictionsProjections,

	// replicated generated projectors (sourcegen promotion)
	"replicated.audit_events": replicatedAuditEventsProjections,
	"replicated.deployments":  replicatedDeploymentsProjections,
	"replicated.projects":     replicatedProjectsProjections,
	"replicated.repositories": replicatedRepositoriesProjections,
	"replicated.users":        replicatedUsersProjections,

	// resend generated projectors (sourcegen promotion)
	"resend.api_keys":     resendApiKeysProjections,
	"resend.audit_events": resendAuditEventsProjections,
	"resend.domains":      resendDomainsProjections,

	// retool generated projectors (sourcegen promotion)
	"retool.audit_events": retoolAuditEventsProjections,
	"retool.deployments":  retoolDeploymentsProjections,
	"retool.projects":     retoolProjectsProjections,
	"retool.repositories": retoolRepositoriesProjections,
	"retool.users":        retoolUsersProjections,

	// revenuecat generated projectors (sourcegen promotion)
	"revenuecat.accounts":     revenuecatAccountsProjections,
	"revenuecat.audit_events": revenuecatAuditEventsProjections,
	"revenuecat.policies":     revenuecatPoliciesProjections,
	"revenuecat.records":      revenuecatRecordsProjections,
	"revenuecat.users":        revenuecatUsersProjections,

	// ringcentral generated projectors (sourcegen promotion)
	"ringcentral.audit_events": ringcentralAuditEventsProjections,
	"ringcentral.documents":    ringcentralDocumentsProjections,
	"ringcentral.groups":       ringcentralGroupsProjections,
	"ringcentral.users":        ringcentralUsersProjections,
	"ringcentral.workspaces":   ringcentralWorkspacesProjections,

	// rippling generated projectors (sourcegen promotion)
	"rippling.background_checks": ripplingBackgroundChecksProjections,
	"rippling.devices":           ripplingDevicesProjections,
	"rippling.users":             ripplingUsersProjections,

	// riskiq generated projectors (sourcegen promotion)
	"riskiq.assets":          riskiqAssetsProjections,
	"riskiq.audit_events":    riskiqAuditEventsProjections,
	"riskiq.findings":        riskiqFindingsProjections,
	"riskiq.policies":        riskiqPoliciesProjections,
	"riskiq.vulnerabilities": riskiqVulnerabilitiesProjections,

	// riskonnect generated projectors (sourcegen promotion)
	"riskonnect.assets":          riskonnectAssetsProjections,
	"riskonnect.audit_events":    riskonnectAuditEventsProjections,
	"riskonnect.findings":        riskonnectFindingsProjections,
	"riskonnect.policies":        riskonnectPoliciesProjections,
	"riskonnect.vulnerabilities": riskonnectVulnerabilitiesProjections,

	// rivery generated projectors (sourcegen promotion)
	"rivery.accounts":     riveryAccountsProjections,
	"rivery.audit_events": riveryAuditEventsProjections,
	"rivery.policies":     riveryPoliciesProjections,
	"rivery.records":      riveryRecordsProjections,
	"rivery.users":        riveryUsersProjections,

	// robin generated projectors (sourcegen promotion)
	"robin.audit_events": robinAuditEventsProjections,
	"robin.documents":    robinDocumentsProjections,
	"robin.groups":       robinGroupsProjections,
	"robin.users":        robinUsersProjections,
	"robin.workspaces":   robinWorkspacesProjections,

	// rollbar generated projectors (sourcegen promotion)
	"rollbar.alerts":       rollbarAlertsProjections,
	"rollbar.audit_events": rollbarAuditEventsProjections,
	"rollbar.dashboards":   rollbarDashboardsProjections,
	"rollbar.incidents":    rollbarIncidentsProjections,
	"rollbar.monitors":     rollbarMonitorsProjections,

	// rootly generated projectors (sourcegen promotion)
	"rootly.alerts":       rootlyAlertsProjections,
	"rootly.audit_events": rootlyAuditEventsProjections,
	"rootly.dashboards":   rootlyDashboardsProjections,
	"rootly.incidents":    rootlyIncidentsProjections,
	"rootly.monitors":     rootlyMonitorsProjections,

	// rudderstack generated projectors (sourcegen promotion)
	"rudderstack.accounts":     rudderstackAccountsProjections,
	"rudderstack.audit_events": rudderstackAuditEventsProjections,
	"rudderstack.policies":     rudderstackPoliciesProjections,
	"rudderstack.records":      rudderstackRecordsProjections,
	"rudderstack.users":        rudderstackUsersProjections,

	// runscope generated projectors (sourcegen promotion)
	"runscope.agent":        runscopeAgentProjections,
	"runscope.bucket":       runscopeBucketProjections,
	"runscope.buckets_test": runscopeBucketsTestProjections,
	"runscope.environment":  runscopeEnvironmentProjections,
	"runscope.integration":  runscopeIntegrationProjections,
	"runscope.metric":       runscopeMetricProjections,
	"runscope.people":       runscopePeopleProjections,
	"runscope.test":         runscopeTestProjections,

	// runzero generated projectors (sourcegen promotion)
	"runzero.assets":          runzeroAssetsProjections,
	"runzero.audit_events":    runzeroAuditEventsProjections,
	"runzero.findings":        runzeroFindingsProjections,
	"runzero.policies":        runzeroPoliciesProjections,
	"runzero.vulnerabilities": runzeroVulnerabilitiesProjections,

	// safe_base generated projectors (sourcegen promotion)
	"safe_base.assets":          safeBaseAssetsProjections,
	"safe_base.audit_events":    safeBaseAuditEventsProjections,
	"safe_base.findings":        safeBaseFindingsProjections,
	"safe_base.policies":        safeBasePoliciesProjections,
	"safe_base.vulnerabilities": safeBaseVulnerabilitiesProjections,

	// sage_intacct generated projectors (sourcegen promotion)
	"sage_intacct.accounts":     sageIntacctAccountsProjections,
	"sage_intacct.audit_events": sageIntacctAuditEventsProjections,
	"sage_intacct.policies":     sageIntacctPoliciesProjections,
	"sage_intacct.records":      sageIntacctRecordsProjections,
	"sage_intacct.users":        sageIntacctUsersProjections,

	// sailpoint_identitynow generated projectors (sourcegen promotion)
	"sailpoint_identitynow.applications": sailpointIdentitynowApplicationsProjections,
	"sailpoint_identitynow.audit_events": sailpointIdentitynowAuditEventsProjections,
	"sailpoint_identitynow.groups":       sailpointIdentitynowGroupsProjections,
	"sailpoint_identitynow.roles":        sailpointIdentitynowRolesProjections,
	"sailpoint_identitynow.users":        sailpointIdentitynowUsersProjections,

	// sakari generated projectors (sourcegen promotion)
	"sakari.campaign":     sakariCampaignProjections,
	"sakari.contact":      sakariContactProjections,
	"sakari.conversation": sakariConversationProjections,
	"sakari.webhook":      sakariWebhookProjections,

	// salesforce generated projectors (sourcegen promotion)
	"salesforce.assets":       salesforceAssetsProjections,
	"salesforce.audit_events": salesforceAuditEventsProjections,
	"salesforce.users":        salesforceUsersProjections,

	// salesforce_cpq generated projectors (sourcegen promotion)
	"salesforce_cpq.accounts":     salesforceCpqAccountsProjections,
	"salesforce_cpq.audit_events": salesforceCpqAuditEventsProjections,
	"salesforce_cpq.policies":     salesforceCpqPoliciesProjections,
	"salesforce_cpq.records":      salesforceCpqRecordsProjections,
	"salesforce_cpq.users":        salesforceCpqUsersProjections,

	// saleshood generated projectors (sourcegen promotion)
	"saleshood.accounts":     saleshoodAccountsProjections,
	"saleshood.audit_events": saleshoodAuditEventsProjections,
	"saleshood.policies":     saleshoodPoliciesProjections,
	"saleshood.records":      saleshoodRecordsProjections,
	"saleshood.users":        saleshoodUsersProjections,

	// salesloft generated projectors (sourcegen promotion)
	"salesloft.account_stages_json":      salesloftAccountStagesJsonProjections,
	"salesloft.cadence_memberships_json": salesloftCadenceMembershipsJsonProjections,
	"salesloft.crm_activity_fields_json": salesloftCrmActivityFieldsJsonProjections,
	"salesloft.groups_json":              salesloftGroupsJsonProjections,

	// salt_security generated projectors (sourcegen promotion)
	"salt_security.assets":          saltSecurityAssetsProjections,
	"salt_security.audit_events":    saltSecurityAuditEventsProjections,
	"salt_security.findings":        saltSecurityFindingsProjections,
	"salt_security.policies":        saltSecurityPoliciesProjections,
	"salt_security.vulnerabilities": saltSecurityVulnerabilitiesProjections,

	// sauce_labs generated projectors (sourcegen promotion)
	"sauce_labs.audit_events": sauceLabsAuditEventsProjections,
	"sauce_labs.deployments":  sauceLabsDeploymentsProjections,
	"sauce_labs.projects":     sauceLabsProjectsProjections,
	"sauce_labs.repositories": sauceLabsRepositoriesProjections,
	"sauce_labs.users":        sauceLabsUsersProjections,

	// saviynt generated projectors (sourcegen promotion)
	"saviynt.applications": saviyntApplicationsProjections,
	"saviynt.audit_events": saviyntAuditEventsProjections,
	"saviynt.groups":       saviyntGroupsProjections,
	"saviynt.roles":        saviyntRolesProjections,
	"saviynt.users":        saviyntUsersProjections,

	// scalefusion generated projectors (sourcegen promotion)
	"scalefusion.applications": scalefusionApplicationsProjections,
	"scalefusion.audit_events": scalefusionAuditEventsProjections,
	"scalefusion.groups":       scalefusionGroupsProjections,
	"scalefusion.roles":        scalefusionRolesProjections,
	"scalefusion.users":        scalefusionUsersProjections,

	// scalr generated projectors (sourcegen promotion)
	"scalr.audit_events": scalrAuditEventsProjections,
	"scalr.deployments":  scalrDeploymentsProjections,
	"scalr.projects":     scalrProjectsProjections,
	"scalr.repositories": scalrRepositoriesProjections,
	"scalr.users":        scalrUsersProjections,

	// secureframe generated projectors (sourcegen promotion)
	"secureframe.controls": secureframeControlsProjections,
	"secureframe.findings": secureframeFindingsProjections,
	"secureframe.users":    secureframeUsersProjections,

	// securiti generated projectors (sourcegen promotion)
	"securiti.assets":          securitiAssetsProjections,
	"securiti.audit_events":    securitiAuditEventsProjections,
	"securiti.findings":        securitiFindingsProjections,
	"securiti.policies":        securitiPoliciesProjections,
	"securiti.vulnerabilities": securitiVulnerabilitiesProjections,

	// securityscorecard generated projectors (sourcegen promotion)
	"securityscorecard.assets":          securityscorecardAssetsProjections,
	"securityscorecard.audit_events":    securityscorecardAuditEventsProjections,
	"securityscorecard.findings":        securityscorecardFindingsProjections,
	"securityscorecard.policies":        securityscorecardPoliciesProjections,
	"securityscorecard.vulnerabilities": securityscorecardVulnerabilitiesProjections,

	// securonix generated projectors (sourcegen promotion)
	"securonix.assets":          securonixAssetsProjections,
	"securonix.audit_events":    securonixAuditEventsProjections,
	"securonix.findings":        securonixFindingsProjections,
	"securonix.policies":        securonixPoliciesProjections,
	"securonix.vulnerabilities": securonixVulnerabilitiesProjections,

	// segment generated projectors (sourcegen promotion)
	"segment.sources":    segmentSourcesProjections,
	"segment.users":      segmentUsersProjections,
	"segment.workspaces": segmentWorkspacesProjections,

	// seismic generated projectors (sourcegen promotion)
	"seismic.accounts":     seismicAccountsProjections,
	"seismic.audit_events": seismicAuditEventsProjections,
	"seismic.policies":     seismicPoliciesProjections,
	"seismic.records":      seismicRecordsProjections,
	"seismic.users":        seismicUsersProjections,

	// semaphore_ci generated projectors (sourcegen promotion)
	"semaphore_ci.audit_events": semaphoreCiAuditEventsProjections,
	"semaphore_ci.deployments":  semaphoreCiDeploymentsProjections,
	"semaphore_ci.projects":     semaphoreCiProjectsProjections,
	"semaphore_ci.repositories": semaphoreCiRepositoriesProjections,
	"semaphore_ci.users":        semaphoreCiUsersProjections,

	// semgrep generated projectors (sourcegen promotion)
	"semgrep.assets":          semgrepAssetsProjections,
	"semgrep.audit_events":    semgrepAuditEventsProjections,
	"semgrep.findings":        semgrepFindingsProjections,
	"semgrep.policies":        semgrepPoliciesProjections,
	"semgrep.vulnerabilities": semgrepVulnerabilitiesProjections,

	// sendgrid generated projectors (sourcegen promotion)
	"sendgrid.activity":      sendgridActivityProjections,
	"sendgrid.api_key":       sendgridApiKeyProjections,
	"sendgrid.group":         sendgridGroupProjections,
	"sendgrid.invalid_email": sendgridInvalidEmailProjections,

	// sendoso generated projectors (sourcegen promotion)
	"sendoso.accounts":     sendosoAccountsProjections,
	"sendoso.audit_events": sendosoAuditEventsProjections,
	"sendoso.policies":     sendosoPoliciesProjections,
	"sendoso.records":      sendosoRecordsProjections,
	"sendoso.users":        sendosoUsersProjections,

	// sentra generated projectors (sourcegen promotion)
	"sentra.assets":          sentraAssetsProjections,
	"sentra.audit_events":    sentraAuditEventsProjections,
	"sentra.findings":        sentraFindingsProjections,
	"sentra.policies":        sentraPoliciesProjections,
	"sentra.vulnerabilities": sentraVulnerabilitiesProjections,

	// sentry generated projectors (sourcegen promotion)
	"sentry.assets":          sentryAssetsProjections,
	"sentry.findings":        sentryFindingsProjections,
	"sentry.vulnerabilities": sentryVulnerabilitiesProjections,

	// servicenow generated projectors (sourcegen promotion)
	"servicenow.audit_events": servicenowAuditEventsProjections,
	"servicenow.tickets":      servicenowTicketsProjections,
	"servicenow.users":        servicenowUsersProjections,

	// servicenow_grc generated projectors (sourcegen promotion)
	"servicenow_grc.assets":          servicenowGrcAssetsProjections,
	"servicenow_grc.audit_events":    servicenowGrcAuditEventsProjections,
	"servicenow_grc.findings":        servicenowGrcFindingsProjections,
	"servicenow_grc.policies":        servicenowGrcPoliciesProjections,
	"servicenow_grc.vulnerabilities": servicenowGrcVulnerabilitiesProjections,

	// sevenrooms generated projectors (sourcegen promotion)
	"sevenrooms.accounts":     sevenroomsAccountsProjections,
	"sevenrooms.audit_events": sevenroomsAuditEventsProjections,
	"sevenrooms.policies":     sevenroomsPoliciesProjections,
	"sevenrooms.records":      sevenroomsRecordsProjections,
	"sevenrooms.users":        sevenroomsUsersProjections,

	// sharefile generated projectors (sourcegen promotion)
	"sharefile.audit_events": sharefileAuditEventsProjections,
	"sharefile.documents":    sharefileDocumentsProjections,
	"sharefile.groups":       sharefileGroupsProjections,
	"sharefile.users":        sharefileUsersProjections,
	"sharefile.workspaces":   sharefileWorkspacesProjections,

	// shipengine generated projectors (sourcegen promotion)
	"shipengine.package":  shipenginePackageProjections,
	"shipengine.track":    shipengineTrackProjections,
	"shipengine.tracking": shipengineTrackingProjections,
	"shipengine.webhook":  shipengineWebhookProjections,

	// shorebird generated projectors (sourcegen promotion)
	"shorebird.audit_events": shorebirdAuditEventsProjections,
	"shorebird.deployments":  shorebirdDeploymentsProjections,
	"shorebird.projects":     shorebirdProjectsProjections,
	"shorebird.repositories": shorebirdRepositoriesProjections,
	"shorebird.users":        shorebirdUsersProjections,

	// shortcut generated projectors (sourcegen promotion)
	"shortcut.audit_events": shortcutAuditEventsProjections,
	"shortcut.deployments":  shortcutDeploymentsProjections,
	"shortcut.projects":     shortcutProjectsProjections,
	"shortcut.repositories": shortcutRepositoriesProjections,
	"shortcut.users":        shortcutUsersProjections,

	// showpad generated projectors (sourcegen promotion)
	"showpad.accounts":     showpadAccountsProjections,
	"showpad.audit_events": showpadAuditEventsProjections,
	"showpad.policies":     showpadPoliciesProjections,
	"showpad.records":      showpadRecordsProjections,
	"showpad.users":        showpadUsersProjections,

	// sigma_computing generated projectors (sourcegen promotion)
	"sigma_computing.accounts":     sigmaComputingAccountsProjections,
	"sigma_computing.audit_events": sigmaComputingAuditEventsProjections,
	"sigma_computing.policies":     sigmaComputingPoliciesProjections,
	"sigma_computing.records":      sigmaComputingRecordsProjections,
	"sigma_computing.users":        sigmaComputingUsersProjections,

	// signl4 generated projectors (sourcegen promotion)
	"signl4.image":      signl4ImageProjections,
	"signl4.membership": signl4MembershipProjections,
	"signl4.team":       signl4TeamProjections,
	"signl4.user":       signl4UserProjections,

	// silverfort generated projectors (sourcegen promotion)
	"silverfort.applications": silverfortApplicationsProjections,
	"silverfort.audit_events": silverfortAuditEventsProjections,
	"silverfort.groups":       silverfortGroupsProjections,
	"silverfort.roles":        silverfortRolesProjections,
	"silverfort.users":        silverfortUsersProjections,

	// simplemdm generated projectors (sourcegen promotion)
	"simplemdm.applications": simplemdmApplicationsProjections,
	"simplemdm.audit_events": simplemdmAuditEventsProjections,
	"simplemdm.groups":       simplemdmGroupsProjections,
	"simplemdm.roles":        simplemdmRolesProjections,
	"simplemdm.users":        simplemdmUsersProjections,

	// sinao generated projectors (sourcegen promotion)
	"sinao.access":            sinaoAccessProjections,
	"sinao.account":           sinaoAccountProjections,
	"sinao.accountcategory":   sinaoAccountcategoryProjections,
	"sinao.accounting_entry":  sinaoAccountingEntryProjections,
	"sinao.apps_organization": sinaoAppsOrganizationProjections,
	"sinao.invite":            sinaoInviteProjections,
	"sinao.organization":      sinaoOrganizationProjections,
	"sinao.person":            sinaoPersonProjections,
	"sinao.product":           sinaoProductProjections,
	"sinao.productcategory":   sinaoProductcategoryProjections,
	"sinao.productstock":      sinaoProductstockProjections,
	"sinao.rule":              sinaoRuleProjections,

	// sirionlabs generated projectors (sourcegen promotion)
	"sirionlabs.accounts":     sirionlabsAccountsProjections,
	"sirionlabs.audit_events": sirionlabsAuditEventsProjections,
	"sirionlabs.policies":     sirionlabsPoliciesProjections,
	"sirionlabs.records":      sirionlabsRecordsProjections,
	"sirionlabs.users":        sirionlabsUsersProjections,

	// sisense generated projectors (sourcegen promotion)
	"sisense.accounts":     sisenseAccountsProjections,
	"sisense.audit_events": sisenseAuditEventsProjections,
	"sisense.policies":     sisensePoliciesProjections,
	"sisense.records":      sisenseRecordsProjections,
	"sisense.users":        sisenseUsersProjections,

	// sixsense generated projectors (sourcegen promotion)
	"sixsense.accounts":     sixsenseAccountsProjections,
	"sixsense.audit_events": sixsenseAuditEventsProjections,
	"sixsense.policies":     sixsensePoliciesProjections,
	"sixsense.records":      sixsenseRecordsProjections,
	"sixsense.users":        sixsenseUsersProjections,

	// skedda generated projectors (sourcegen promotion)
	"skedda.audit_events": skeddaAuditEventsProjections,
	"skedda.documents":    skeddaDocumentsProjections,
	"skedda.groups":       skeddaGroupsProjections,
	"skedda.users":        skeddaUsersProjections,
	"skedda.workspaces":   skeddaWorkspacesProjections,

	// skillsoft_percipio generated projectors (sourcegen promotion)
	"skillsoft_percipio.accounts":     skillsoftPercipioAccountsProjections,
	"skillsoft_percipio.audit_events": skillsoftPercipioAuditEventsProjections,
	"skillsoft_percipio.policies":     skillsoftPercipioPoliciesProjections,
	"skillsoft_percipio.records":      skillsoftPercipioRecordsProjections,
	"skillsoft_percipio.users":        skillsoftPercipioUsersProjections,

	// slab generated projectors (sourcegen promotion)
	"slab.audit_events": slabAuditEventsProjections,
	"slab.documents":    slabDocumentsProjections,
	"slab.groups":       slabGroupsProjections,
	"slab.users":        slabUsersProjections,
	"slab.workspaces":   slabWorkspacesProjections,

	// slideroom generated projectors (sourcegen promotion)
	"slideroom.attributes_name": slideroomAttributesNameProjections,
	"slideroom.export":          slideroomExportProjections,
	"slideroom.name":            slideroomNameProjections,

	// slite generated projectors (sourcegen promotion)
	"slite.audit_events": sliteAuditEventsProjections,
	"slite.documents":    sliteDocumentsProjections,
	"slite.groups":       sliteGroupsProjections,
	"slite.users":        sliteUsersProjections,
	"slite.workspaces":   sliteWorkspacesProjections,

	// smartrecruiters generated projectors (sourcegen promotion)
	"smartrecruiters.accounts":     smartrecruitersAccountsProjections,
	"smartrecruiters.audit_events": smartrecruitersAuditEventsProjections,
	"smartrecruiters.policies":     smartrecruitersPoliciesProjections,
	"smartrecruiters.records":      smartrecruitersRecordsProjections,
	"smartrecruiters.users":        smartrecruitersUsersProjections,

	// smartsheet generated projectors (sourcegen promotion)
	"smartsheet.audit_events": smartsheetAuditEventsProjections,
	"smartsheet.documents":    smartsheetDocumentsProjections,
	"smartsheet.groups":       smartsheetGroupsProjections,
	"smartsheet.users":        smartsheetUsersProjections,
	"smartsheet.workspaces":   smartsheetWorkspacesProjections,

	// smartsuite generated projectors (sourcegen promotion)
	"smartsuite.accounts":     smartsuiteAccountsProjections,
	"smartsuite.audit_events": smartsuiteAuditEventsProjections,
	"smartsuite.policies":     smartsuitePoliciesProjections,
	"smartsuite.records":      smartsuiteRecordsProjections,
	"smartsuite.users":        smartsuiteUsersProjections,

	// snowflake generated projectors (sourcegen promotion)
	"snowflake.assets":                 snowflakeAssetsProjections,
	"snowflake.audit_events":           snowflakeAuditEventsProjections,
	"snowflake.cortex_search_services": snowflakeCortexSearchServicesProjections,
	"snowflake.vulnerabilities":        snowflakeVulnerabilitiesProjections,

	// snyk generated projectors (sourcegen promotion)
	"snyk.assets":          snykAssetsProjections,
	"snyk.findings":        snykFindingsProjections,
	"snyk.vulnerabilities": snykVulnerabilitiesProjections,

	// soda_cloud generated projectors (sourcegen promotion)
	"soda_cloud.accounts":     sodaCloudAccountsProjections,
	"soda_cloud.audit_events": sodaCloudAuditEventsProjections,
	"soda_cloud.policies":     sodaCloudPoliciesProjections,
	"soda_cloud.records":      sodaCloudRecordsProjections,
	"soda_cloud.users":        sodaCloudUsersProjections,

	// sonarcloud generated projectors (sourcegen promotion)
	"sonarcloud.assets":          sonarcloudAssetsProjections,
	"sonarcloud.findings":        sonarcloudFindingsProjections,
	"sonarcloud.vulnerabilities": sonarcloudVulnerabilitiesProjections,

	// sonatype_lifecycle generated projectors (sourcegen promotion)
	"sonatype_lifecycle.assets":          sonatypeLifecycleAssetsProjections,
	"sonatype_lifecycle.audit_events":    sonatypeLifecycleAuditEventsProjections,
	"sonatype_lifecycle.findings":        sonatypeLifecycleFindingsProjections,
	"sonatype_lifecycle.policies":        sonatypeLifecyclePoliciesProjections,
	"sonatype_lifecycle.vulnerabilities": sonatypeLifecycleVulnerabilitiesProjections,

	// sonrai_security generated projectors (sourcegen promotion)
	"sonrai_security.applications": sonraiSecurityApplicationsProjections,
	"sonrai_security.audit_events": sonraiSecurityAuditEventsProjections,
	"sonrai_security.groups":       sonraiSecurityGroupsProjections,
	"sonrai_security.roles":        sonraiSecurityRolesProjections,
	"sonrai_security.users":        sonraiSecurityUsersProjections,

	// sophos_central generated projectors (sourcegen promotion)
	"sophos_central.assets":          sophosCentralAssetsProjections,
	"sophos_central.audit_events":    sophosCentralAuditEventsProjections,
	"sophos_central.findings":        sophosCentralFindingsProjections,
	"sophos_central.policies":        sophosCentralPoliciesProjections,
	"sophos_central.vulnerabilities": sophosCentralVulnerabilitiesProjections,

	// soti_mobicontrol generated projectors (sourcegen promotion)
	"soti_mobicontrol.applications": sotiMobicontrolApplicationsProjections,
	"soti_mobicontrol.audit_events": sotiMobicontrolAuditEventsProjections,
	"soti_mobicontrol.groups":       sotiMobicontrolGroupsProjections,
	"soti_mobicontrol.roles":        sotiMobicontrolRolesProjections,
	"soti_mobicontrol.users":        sotiMobicontrolUsersProjections,

	// sourcegraph generated projectors (sourcegen promotion)
	"sourcegraph.audit_events": sourcegraphAuditEventsProjections,
	"sourcegraph.deployments":  sourcegraphDeploymentsProjections,
	"sourcegraph.projects":     sourcegraphProjectsProjections,
	"sourcegraph.repositories": sourcegraphRepositoriesProjections,
	"sourcegraph.users":        sourcegraphUsersProjections,

	// sourcewhale generated projectors (sourcegen promotion)
	"sourcewhale.accounts":     sourcewhaleAccountsProjections,
	"sourcewhale.audit_events": sourcewhaleAuditEventsProjections,
	"sourcewhale.policies":     sourcewhalePoliciesProjections,
	"sourcewhale.records":      sourcewhaleRecordsProjections,
	"sourcewhale.users":        sourcewhaleUsersProjections,

	// spacelift generated projectors (sourcegen promotion)
	"spacelift.audit_events": spaceliftAuditEventsProjections,
	"spacelift.deployments":  spaceliftDeploymentsProjections,
	"spacelift.projects":     spaceliftProjectsProjections,
	"spacelift.repositories": spaceliftRepositoriesProjections,
	"spacelift.users":        spaceliftUsersProjections,

	// spendesk generated projectors (sourcegen promotion)
	"spendesk.accounts":     spendeskAccountsProjections,
	"spendesk.audit_events": spendeskAuditEventsProjections,
	"spendesk.policies":     spendeskPoliciesProjections,
	"spendesk.records":      spendeskRecordsProjections,
	"spendesk.users":        spendeskUsersProjections,

	// split_io generated projectors (sourcegen promotion)
	"split_io.audit_events": splitIoAuditEventsProjections,
	"split_io.deployments":  splitIoDeploymentsProjections,
	"split_io.projects":     splitIoProjectsProjections,
	"split_io.repositories": splitIoRepositoriesProjections,
	"split_io.users":        splitIoUsersProjections,

	// splunk_cloud generated projectors (sourcegen promotion)
	"splunk_cloud.assets":       splunkCloudAssetsProjections,
	"splunk_cloud.audit_events": splunkCloudAuditEventsProjections,
	"splunk_cloud.findings":     splunkCloudFindingsProjections,

	// splunk_observability generated projectors (sourcegen promotion)
	"splunk_observability.alerts":       splunkObservabilityAlertsProjections,
	"splunk_observability.audit_events": splunkObservabilityAuditEventsProjections,
	"splunk_observability.dashboards":   splunkObservabilityDashboardsProjections,
	"splunk_observability.incidents":    splunkObservabilityIncidentsProjections,
	"splunk_observability.monitors":     splunkObservabilityMonitorsProjections,

	// springhealth generated projectors (sourcegen promotion)
	"springhealth.accounts":     springhealthAccountsProjections,
	"springhealth.audit_events": springhealthAuditEventsProjections,
	"springhealth.policies":     springhealthPoliciesProjections,
	"springhealth.records":      springhealthRecordsProjections,
	"springhealth.users":        springhealthUsersProjections,

	// sprinklr generated projectors (sourcegen promotion)
	"sprinklr.accounts":     sprinklrAccountsProjections,
	"sprinklr.audit_events": sprinklrAuditEventsProjections,
	"sprinklr.policies":     sprinklrPoliciesProjections,
	"sprinklr.records":      sprinklrRecordsProjections,
	"sprinklr.users":        sprinklrUsersProjections,

	// sprinto generated projectors (sourcegen promotion)
	"sprinto.assets":          sprintoAssetsProjections,
	"sprinto.audit_events":    sprintoAuditEventsProjections,
	"sprinto.findings":        sprintoFindingsProjections,
	"sprinto.policies":        sprintoPoliciesProjections,
	"sprinto.vulnerabilities": sprintoVulnerabilitiesProjections,

	// sprout_social generated projectors (sourcegen promotion)
	"sprout_social.audit_events": sproutSocialAuditEventsProjections,
	"sprout_social.documents":    sproutSocialDocumentsProjections,
	"sprout_social.groups":       sproutSocialGroupsProjections,
	"sprout_social.users":        sproutSocialUsersProjections,
	"sprout_social.workspaces":   sproutSocialWorkspacesProjections,

	// squadcast generated projectors (sourcegen promotion)
	"squadcast.alerts":       squadcastAlertsProjections,
	"squadcast.audit_events": squadcastAuditEventsProjections,
	"squadcast.dashboards":   squadcastDashboardsProjections,
	"squadcast.incidents":    squadcastIncidentsProjections,
	"squadcast.monitors":     squadcastMonitorsProjections,

	// square generated projectors (sourcegen promotion)
	"square.activity":                    squareActivityProjections,
	"square.bank_account":                squareBankAccountProjections,
	"square.group":                       squareGroupProjections,
	"square.team_member_booking_profile": squareTeamMemberBookingProfileProjections,

	// stability_ai generated projectors (sourcegen promotion)
	"stability_ai.account":         stabilityAiAccountProjections,
	"stability_ai.account_balance": stabilityAiAccountBalanceProjections,
	"stability_ai.engines":         stabilityAiEnginesProjections,

	// stackblitz generated projectors (sourcegen promotion)
	"stackblitz.audit_events": stackblitzAuditEventsProjections,
	"stackblitz.deployments":  stackblitzDeploymentsProjections,
	"stackblitz.projects":     stackblitzProjectsProjections,
	"stackblitz.repositories": stackblitzRepositoriesProjections,
	"stackblitz.users":        stackblitzUsersProjections,

	// stackhawk generated projectors (sourcegen promotion)
	"stackhawk.assets":          stackhawkAssetsProjections,
	"stackhawk.audit_events":    stackhawkAuditEventsProjections,
	"stackhawk.findings":        stackhawkFindingsProjections,
	"stackhawk.policies":        stackhawkPoliciesProjections,
	"stackhawk.vulnerabilities": stackhawkVulnerabilitiesProjections,

	// statsig generated projectors (sourcegen promotion)
	"statsig.audit_events": statsigAuditEventsProjections,
	"statsig.deployments":  statsigDeploymentsProjections,
	"statsig.projects":     statsigProjectsProjections,
	"statsig.repositories": statsigRepositoriesProjections,
	"statsig.users":        statsigUsersProjections,

	// statuscake generated projectors (sourcegen promotion)
	"statuscake.alerts":       statuscakeAlertsProjections,
	"statuscake.audit_events": statuscakeAuditEventsProjections,
	"statuscake.dashboards":   statuscakeDashboardsProjections,
	"statuscake.incidents":    statuscakeIncidentsProjections,
	"statuscake.monitors":     statuscakeMonitorsProjections,

	// statuspage generated projectors (sourcegen promotion)
	"statuspage.audit_events": statuspageAuditEventsProjections,
	"statuspage.tickets":      statuspageTicketsProjections,
	"statuspage.users":        statuspageUsersProjections,

	// stigg generated projectors (sourcegen promotion)
	"stigg.alerts":       stiggAlertsProjections,
	"stigg.audit_events": stiggAuditEventsProjections,
	"stigg.dashboards":   stiggDashboardsProjections,
	"stigg.incidents":    stiggIncidentsProjections,
	"stigg.monitors":     stiggMonitorsProjections,

	// stitch generated projectors (sourcegen promotion)
	"stitch.accounts":     stitchAccountsProjections,
	"stitch.audit_events": stitchAuditEventsProjections,
	"stitch.policies":     stitchPoliciesProjections,
	"stitch.records":      stitchRecordsProjections,
	"stitch.users":        stitchUsersProjections,

	// stoplight generated projectors (sourcegen promotion)
	"stoplight.audit_events": stoplightAuditEventsProjections,
	"stoplight.deployments":  stoplightDeploymentsProjections,
	"stoplight.projects":     stoplightProjectsProjections,
	"stoplight.repositories": stoplightRepositoriesProjections,
	"stoplight.users":        stoplightUsersProjections,

	// stream_io_api generated projectors (sourcegen promotion)
	"stream_io_api.device":            streamIoApiDeviceProjections,
	"stream_io_api.member":            streamIoApiMemberProjections,
	"stream_io_api.query_banned_user": streamIoApiQueryBannedUserProjections,
	"stream_io_api.role":              streamIoApiRoleProjections,

	// stripe generated projectors (sourcegen promotion)
	"stripe.assets":       stripeAssetsProjections,
	"stripe.audit_events": stripeAuditEventsProjections,
	"stripe.users":        stripeUsersProjections,

	// strongdm generated projectors (sourcegen promotion)
	"strongdm.audit_events": strongdmAuditEventsProjections,
	"strongdm.groups":       strongdmGroupsProjections,
	"strongdm.users":        strongdmUsersProjections,

	// stytch generated projectors (sourcegen promotion)
	"stytch.applications": stytchApplicationsProjections,
	"stytch.audit_events": stytchAuditEventsProjections,
	"stytch.groups":       stytchGroupsProjections,
	"stytch.roles":        stytchRolesProjections,
	"stytch.users":        stytchUsersProjections,

	// successfactors generated projectors (sourcegen promotion)
	"successfactors.accounts":     successfactorsAccountsProjections,
	"successfactors.audit_events": successfactorsAuditEventsProjections,
	"successfactors.policies":     successfactorsPoliciesProjections,
	"successfactors.records":      successfactorsRecordsProjections,
	"successfactors.users":        successfactorsUsersProjections,

	// sumo_logic generated projectors (sourcegen promotion)
	"sumo_logic.assets":       sumoLogicAssetsProjections,
	"sumo_logic.audit_events": sumoLogicAuditEventsProjections,
	"sumo_logic.findings":     sumoLogicFindingsProjections,

	// surveymonkey generated projectors (sourcegen promotion)
	"surveymonkey.accounts":     surveymonkeyAccountsProjections,
	"surveymonkey.audit_events": surveymonkeyAuditEventsProjections,
	"surveymonkey.policies":     surveymonkeyPoliciesProjections,
	"surveymonkey.records":      surveymonkeyRecordsProjections,
	"surveymonkey.users":        surveymonkeyUsersProjections,

	// svix generated projectors (sourcegen promotion)
	"svix.endpoint":     svixEndpointProjections,
	"svix.event_type":   svixEventTypeProjections,
	"svix.msg":          svixMsgProjections,
	"svix.msg_endpoint": svixMsgEndpointProjections,

	// swaggerhub generated projectors (sourcegen promotion)
	"swaggerhub.audit_events": swaggerhubAuditEventsProjections,
	"swaggerhub.deployments":  swaggerhubDeploymentsProjections,
	"swaggerhub.projects":     swaggerhubProjectsProjections,
	"swaggerhub.repositories": swaggerhubRepositoriesProjections,
	"swaggerhub.users":        swaggerhubUsersProjections,

	// swif_ai generated projectors (sourcegen promotion)
	"swif_ai.device_compliance": swifAiDeviceComplianceProjections,
	"swif_ai.devices":           swifAiDevicesProjections,
	"swif_ai.users":             swifAiUsersProjections,

	// synack generated projectors (sourcegen promotion)
	"synack.assets":          synackAssetsProjections,
	"synack.audit_events":    synackAuditEventsProjections,
	"synack.findings":        synackFindingsProjections,
	"synack.policies":        synackPoliciesProjections,
	"synack.vulnerabilities": synackVulnerabilitiesProjections,

	// sync_com generated projectors (sourcegen promotion)
	"sync_com.audit_events": syncComAuditEventsProjections,
	"sync_com.documents":    syncComDocumentsProjections,
	"sync_com.groups":       syncComGroupsProjections,
	"sync_com.users":        syncComUsersProjections,
	"sync_com.workspaces":   syncComWorkspacesProjections,

	// sysdig_secure generated projectors (sourcegen promotion)
	"sysdig_secure.assets":          sysdigSecureAssetsProjections,
	"sysdig_secure.findings":        sysdigSecureFindingsProjections,
	"sysdig_secure.vulnerabilities": sysdigSecureVulnerabilitiesProjections,

	// tableau_cloud generated projectors (sourcegen promotion)
	"tableau_cloud.accounts":     tableauCloudAccountsProjections,
	"tableau_cloud.audit_events": tableauCloudAuditEventsProjections,
	"tableau_cloud.policies":     tableauCloudPoliciesProjections,
	"tableau_cloud.records":      tableauCloudRecordsProjections,
	"tableau_cloud.users":        tableauCloudUsersProjections,

	// talkdesk generated projectors (sourcegen promotion)
	"talkdesk.audit_events": talkdeskAuditEventsProjections,
	"talkdesk.documents":    talkdeskDocumentsProjections,
	"talkdesk.groups":       talkdeskGroupsProjections,
	"talkdesk.users":        talkdeskUsersProjections,
	"talkdesk.workspaces":   talkdeskWorkspacesProjections,

	// tallyfy generated projectors (sourcegen promotion)
	"tallyfy.accounts":     tallyfyAccountsProjections,
	"tallyfy.audit_events": tallyfyAuditEventsProjections,
	"tallyfy.policies":     tallyfyPoliciesProjections,
	"tallyfy.records":      tallyfyRecordsProjections,
	"tallyfy.users":        tallyfyUsersProjections,

	// tanium_cloud generated projectors (sourcegen promotion)
	"tanium_cloud.assets":          taniumCloudAssetsProjections,
	"tanium_cloud.audit_events":    taniumCloudAuditEventsProjections,
	"tanium_cloud.findings":        taniumCloudFindingsProjections,
	"tanium_cloud.policies":        taniumCloudPoliciesProjections,
	"tanium_cloud.vulnerabilities": taniumCloudVulnerabilitiesProjections,

	// taxamo generated projectors (sourcegen promotion)
	"taxamo.payment":     taxamoPaymentProjections,
	"taxamo.refund":      taxamoRefundProjections,
	"taxamo.transaction": taxamoTransactionProjections,
	"taxamo.vy":          taxamoVyProjections,

	// teamcity_cloud generated projectors (sourcegen promotion)
	"teamcity_cloud.audit_events": teamcityCloudAuditEventsProjections,
	"teamcity_cloud.deployments":  teamcityCloudDeploymentsProjections,
	"teamcity_cloud.projects":     teamcityCloudProjectsProjections,
	"teamcity_cloud.repositories": teamcityCloudRepositoriesProjections,
	"teamcity_cloud.users":        teamcityCloudUsersProjections,

	// teampay generated projectors (sourcegen promotion)
	"teampay.accounts":     teampayAccountsProjections,
	"teampay.audit_events": teampayAuditEventsProjections,
	"teampay.policies":     teampayPoliciesProjections,
	"teampay.records":      teampayRecordsProjections,
	"teampay.users":        teampayUsersProjections,

	// teamwork generated projectors (sourcegen promotion)
	"teamwork.audit_events": teamworkAuditEventsProjections,
	"teamwork.documents":    teamworkDocumentsProjections,
	"teamwork.groups":       teamworkGroupsProjections,
	"teamwork.users":        teamworkUsersProjections,
	"teamwork.workspaces":   teamworkWorkspacesProjections,

	// teamwork_projects generated projectors (sourcegen promotion)
	"teamwork_projects.audit_events": teamworkProjectsAuditEventsProjections,
	"teamwork_projects.documents":    teamworkProjectsDocumentsProjections,
	"teamwork_projects.groups":       teamworkProjectsGroupsProjections,
	"teamwork_projects.users":        teamworkProjectsUsersProjections,
	"teamwork_projects.workspaces":   teamworkProjectsWorkspacesProjections,

	// telemetryhub generated projectors (sourcegen promotion)
	"telemetryhub.alerts":       telemetryhubAlertsProjections,
	"telemetryhub.audit_events": telemetryhubAuditEventsProjections,
	"telemetryhub.dashboards":   telemetryhubDashboardsProjections,
	"telemetryhub.incidents":    telemetryhubIncidentsProjections,
	"telemetryhub.monitors":     telemetryhubMonitorsProjections,

	// teleport generated projectors (sourcegen promotion)
	"teleport.audit_events": teleportAuditEventsProjections,
	"teleport.groups":       teleportGroupsProjections,
	"teleport.users":        teleportUsersProjections,

	// telnyx generated projectors (sourcegen promotion)
	"telnyx.billing_group":                telnyxBillingGroupProjections,
	"telnyx.call_control_application":     telnyxCallControlApplicationProjections,
	"telnyx.call_event":                   telnyxCallEventProjections,
	"telnyx.credential_connection":        telnyxCredentialConnectionProjections,
	"telnyx.detail_records_report":        telnyxDetailRecordsReportProjections,
	"telnyx.managed_account":              telnyxManagedAccountProjections,
	"telnyx.notification_channel":         telnyxNotificationChannelProjections,
	"telnyx.notification_event":           telnyxNotificationEventProjections,
	"telnyx.notification_event_condition": telnyxNotificationEventConditionProjections,
	"telnyx.sim_card_group":               telnyxSimCardGroupProjections,
	"telnyx.sim_card_group_action":        telnyxSimCardGroupActionProjections,
	"telnyx.wireless_connectivity_log":    telnyxWirelessConnectivityLogProjections,

	// tenable_io generated projectors (sourcegen promotion)
	"tenable_io.assets":          tenableIoAssetsProjections,
	"tenable_io.findings":        tenableIoFindingsProjections,
	"tenable_io.vulnerabilities": tenableIoVulnerabilitiesProjections,

	// terraform_cloud generated projectors (sourcegen promotion)
	"terraform_cloud.audit_events": terraformCloudAuditEventsProjections,
	"terraform_cloud.repositories": terraformCloudRepositoriesProjections,
	"terraform_cloud.users":        terraformCloudUsersProjections,

	// testim generated projectors (sourcegen promotion)
	"testim.audit_events": testimAuditEventsProjections,
	"testim.deployments":  testimDeploymentsProjections,
	"testim.projects":     testimProjectsProjections,
	"testim.repositories": testimRepositoriesProjections,
	"testim.users":        testimUsersProjections,

	// tettra generated projectors (sourcegen promotion)
	"tettra.audit_events": tettraAuditEventsProjections,
	"tettra.documents":    tettraDocumentsProjections,
	"tettra.groups":       tettraGroupsProjections,
	"tettra.users":        tettraUsersProjections,
	"tettra.workspaces":   tettraWorkspacesProjections,

	// thoropass generated projectors (sourcegen promotion)
	"thoropass.assets":          thoropassAssetsProjections,
	"thoropass.audit_events":    thoropassAuditEventsProjections,
	"thoropass.findings":        thoropassFindingsProjections,
	"thoropass.policies":        thoropassPoliciesProjections,
	"thoropass.vulnerabilities": thoropassVulnerabilitiesProjections,

	// thoughtspot generated projectors (sourcegen promotion)
	"thoughtspot.accounts":     thoughtspotAccountsProjections,
	"thoughtspot.audit_events": thoughtspotAuditEventsProjections,
	"thoughtspot.policies":     thoughtspotPoliciesProjections,
	"thoughtspot.records":      thoughtspotRecordsProjections,
	"thoughtspot.users":        thoughtspotUsersProjections,

	// thousandeyes generated projectors (sourcegen promotion)
	"thousandeyes.alerts":       thousandeyesAlertsProjections,
	"thousandeyes.audit_events": thousandeyesAuditEventsProjections,
	"thousandeyes.dashboards":   thousandeyesDashboardsProjections,
	"thousandeyes.incidents":    thousandeyesIncidentsProjections,
	"thousandeyes.monitors":     thousandeyesMonitorsProjections,

	// threatjammer generated projectors (sourcegen promotion)
	"threatjammer.activity":    threatjammerActivityProjections,
	"threatjammer.all":         threatjammerAllProjections,
	"threatjammer.ip":          threatjammerIpProjections,
	"threatjammer.reported_ip": threatjammerReportedIpProjections,

	// three_sixty_learning generated projectors (sourcegen promotion)
	"three_sixty_learning.accounts":     threeSixtyLearningAccountsProjections,
	"three_sixty_learning.audit_events": threeSixtyLearningAuditEventsProjections,
	"three_sixty_learning.policies":     threeSixtyLearningPoliciesProjections,
	"three_sixty_learning.records":      threeSixtyLearningRecordsProjections,
	"three_sixty_learning.users":        threeSixtyLearningUsersProjections,

	// tines generated projectors (sourcegen promotion)
	"tines.assets":       tinesAssetsProjections,
	"tines.audit_events": tinesAuditEventsProjections,
	"tines.findings":     tinesFindingsProjections,

	// together_ai generated projectors (sourcegen promotion)
	"together_ai.api_keys":         togetherAiApiKeysProjections,
	"together_ai.fine_tuning_jobs": togetherAiFineTuningJobsProjections,
	"together_ai.projects":         togetherAiProjectsProjections,
	"together_ai.usage_reports":    togetherAiUsageReportsProjections,

	// torii generated projectors (sourcegen promotion)
	"torii.applications": toriiApplicationsProjections,
	"torii.audit_events": toriiAuditEventsProjections,
	"torii.groups":       toriiGroupsProjections,
	"torii.roles":        toriiRolesProjections,
	"torii.users":        toriiUsersProjections,

	// torq generated projectors (sourcegen promotion)
	"torq.assets":       torqAssetsProjections,
	"torq.audit_events": torqAuditEventsProjections,
	"torq.findings":     torqFindingsProjections,

	// traceable_ai generated projectors (sourcegen promotion)
	"traceable_ai.assets":          traceableAiAssetsProjections,
	"traceable_ai.audit_events":    traceableAiAuditEventsProjections,
	"traceable_ai.findings":        traceableAiFindingsProjections,
	"traceable_ai.policies":        traceableAiPoliciesProjections,
	"traceable_ai.vulnerabilities": traceableAiVulnerabilitiesProjections,

	// travis_ci generated projectors (sourcegen promotion)
	"travis_ci.audit_events": travisCiAuditEventsProjections,
	"travis_ci.deployments":  travisCiDeploymentsProjections,
	"travis_ci.projects":     travisCiProjectsProjections,
	"travis_ci.repositories": travisCiRepositoriesProjections,
	"travis_ci.users":        travisCiUsersProjections,

	// tray_io generated projectors (sourcegen promotion)
	"tray_io.audit_events": trayIoAuditEventsProjections,
	"tray_io.deployments":  trayIoDeploymentsProjections,
	"tray_io.projects":     trayIoProjectsProjections,
	"tray_io.repositories": trayIoRepositoriesProjections,
	"tray_io.users":        trayIoUsersProjections,

	// trello generated projectors (sourcegen promotion)
	"trello.audit_events": trelloAuditEventsProjections,
	"trello.documents":    trelloDocumentsProjections,
	"trello.groups":       trelloGroupsProjections,
	"trello.users":        trelloUsersProjections,
	"trello.workspaces":   trelloWorkspacesProjections,

	// tresorit generated projectors (sourcegen promotion)
	"tresorit.audit_events": tresoritAuditEventsProjections,
	"tresorit.documents":    tresoritDocumentsProjections,
	"tresorit.groups":       tresoritGroupsProjections,
	"tresorit.users":        tresoritUsersProjections,
	"tresorit.workspaces":   tresoritWorkspacesProjections,

	// trufflehog_enterprise generated projectors (sourcegen promotion)
	"trufflehog_enterprise.assets":          trufflehogEnterpriseAssetsProjections,
	"trufflehog_enterprise.audit_events":    trufflehogEnterpriseAuditEventsProjections,
	"trufflehog_enterprise.findings":        trufflehogEnterpriseFindingsProjections,
	"trufflehog_enterprise.policies":        trufflehogEnterprisePoliciesProjections,
	"trufflehog_enterprise.vulnerabilities": trufflehogEnterpriseVulnerabilitiesProjections,

	// truora generated projectors (sourcegen promotion)
	"truora.check":  truoraCheckProjections,
	"truora.config": truoraConfigProjections,
	"truora.hook":   truoraHookProjections,
	"truora.report": truoraReportProjections,

	// trustarc generated projectors (sourcegen promotion)
	"trustarc.assets":          trustarcAssetsProjections,
	"trustarc.audit_events":    trustarcAuditEventsProjections,
	"trustarc.findings":        trustarcFindingsProjections,
	"trustarc.policies":        trustarcPoliciesProjections,
	"trustarc.vulnerabilities": trustarcVulnerabilitiesProjections,

	// trustpilot generated projectors (sourcegen promotion)
	"trustpilot.accounts":     trustpilotAccountsProjections,
	"trustpilot.audit_events": trustpilotAuditEventsProjections,
	"trustpilot.policies":     trustpilotPoliciesProjections,
	"trustpilot.records":      trustpilotRecordsProjections,
	"trustpilot.users":        trustpilotUsersProjections,

	// tugboat_logic generated projectors (sourcegen promotion)
	"tugboat_logic.assets":          tugboatLogicAssetsProjections,
	"tugboat_logic.audit_events":    tugboatLogicAuditEventsProjections,
	"tugboat_logic.findings":        tugboatLogicFindingsProjections,
	"tugboat_logic.policies":        tugboatLogicPoliciesProjections,
	"tugboat_logic.vulnerabilities": tugboatLogicVulnerabilitiesProjections,

	// twitter generated projectors (sourcegen promotion)
	"twitter.dm_event":        twitterDmEventProjections,
	"twitter.job":             twitterJobProjections,
	"twitter.list_membership": twitterListMembershipProjections,
	"twitter.member":          twitterMemberProjections,

	// tyk generated projectors (sourcegen promotion)
	"tyk.api":    tykApiProjections,
	"tyk.client": tykClientProjections,
	"tyk.key":    tykKeyProjections,

	// typeform generated projectors (sourcegen promotion)
	"typeform.accounts":     typeformAccountsProjections,
	"typeform.audit_events": typeformAuditEventsProjections,
	"typeform.policies":     typeformPoliciesProjections,
	"typeform.records":      typeformRecordsProjections,
	"typeform.users":        typeformUsersProjections,

	// typefully generated projectors (sourcegen promotion)
	"typefully.audit_events": typefullyAuditEventsProjections,
	"typefully.documents":    typefullyDocumentsProjections,
	"typefully.groups":       typefullyGroupsProjections,
	"typefully.users":        typefullyUsersProjections,
	"typefully.workspaces":   typefullyWorkspacesProjections,

	// udemy_business generated projectors (sourcegen promotion)
	"udemy_business.accounts":     udemyBusinessAccountsProjections,
	"udemy_business.audit_events": udemyBusinessAuditEventsProjections,
	"udemy_business.policies":     udemyBusinessPoliciesProjections,
	"udemy_business.records":      udemyBusinessRecordsProjections,
	"udemy_business.users":        udemyBusinessUsersProjections,

	// ujet generated projectors (sourcegen promotion)
	"ujet.accounts":     ujetAccountsProjections,
	"ujet.audit_events": ujetAuditEventsProjections,
	"ujet.policies":     ujetPoliciesProjections,
	"ujet.records":      ujetRecordsProjections,
	"ujet.users":        ujetUsersProjections,

	// ukg_pro generated projectors (sourcegen promotion)
	"ukg_pro.accounts":     ukgProAccountsProjections,
	"ukg_pro.audit_events": ukgProAuditEventsProjections,
	"ukg_pro.policies":     ukgProPoliciesProjections,
	"ukg_pro.records":      ukgProRecordsProjections,
	"ukg_pro.users":        ukgProUsersProjections,

	// unleash_cloud generated projectors (sourcegen promotion)
	"unleash_cloud.audit_events": unleashCloudAuditEventsProjections,
	"unleash_cloud.deployments":  unleashCloudDeploymentsProjections,
	"unleash_cloud.projects":     unleashCloudProjectsProjections,
	"unleash_cloud.repositories": unleashCloudRepositoriesProjections,
	"unleash_cloud.users":        unleashCloudUsersProjections,

	// upguard generated projectors (sourcegen promotion)
	"upguard.assets":          upguardAssetsProjections,
	"upguard.audit_events":    upguardAuditEventsProjections,
	"upguard.findings":        upguardFindingsProjections,
	"upguard.policies":        upguardPoliciesProjections,
	"upguard.vulnerabilities": upguardVulnerabilitiesProjections,

	// uptime_com generated projectors (sourcegen promotion)
	"uptime_com.alerts":       uptimeComAlertsProjections,
	"uptime_com.audit_events": uptimeComAuditEventsProjections,
	"uptime_com.dashboards":   uptimeComDashboardsProjections,
	"uptime_com.incidents":    uptimeComIncidentsProjections,
	"uptime_com.monitors":     uptimeComMonitorsProjections,

	// uptimerobot generated projectors (sourcegen promotion)
	"uptimerobot.alert_contacts": uptimerobotAlertContactsProjections,
	"uptimerobot.audit_events":   uptimerobotAuditEventsProjections,
	"uptimerobot.monitors":       uptimerobotMonitorsProjections,

	// uptrace generated projectors (sourcegen promotion)
	"uptrace.alerts":       uptraceAlertsProjections,
	"uptrace.audit_events": uptraceAuditEventsProjections,
	"uptrace.dashboards":   uptraceDashboardsProjections,
	"uptrace.incidents":    uptraceIncidentsProjections,
	"uptrace.monitors":     uptraceMonitorsProjections,

	// userpilot generated projectors (sourcegen promotion)
	"userpilot.accounts":     userpilotAccountsProjections,
	"userpilot.audit_events": userpilotAuditEventsProjections,
	"userpilot.policies":     userpilotPoliciesProjections,
	"userpilot.records":      userpilotRecordsProjections,
	"userpilot.users":        userpilotUsersProjections,

	// uservoice generated projectors (sourcegen promotion)
	"uservoice.audit_events": uservoiceAuditEventsProjections,
	"uservoice.documents":    uservoiceDocumentsProjections,
	"uservoice.groups":       uservoiceGroupsProjections,
	"uservoice.users":        uservoiceUsersProjections,
	"uservoice.workspaces":   uservoiceWorkspacesProjections,

	// valence_security generated projectors (sourcegen promotion)
	"valence_security.assets":          valenceSecurityAssetsProjections,
	"valence_security.audit_events":    valenceSecurityAuditEventsProjections,
	"valence_security.findings":        valenceSecurityFindingsProjections,
	"valence_security.policies":        valenceSecurityPoliciesProjections,
	"valence_security.vulnerabilities": valenceSecurityVulnerabilitiesProjections,

	// vanta generated projectors (sourcegen promotion)
	"vanta.controls": vantaControlsProjections,
	"vanta.findings": vantaFindingsProjections,
	"vanta.users":    vantaUsersProjections,

	// varicent generated projectors (sourcegen promotion)
	"varicent.accounts":     varicentAccountsProjections,
	"varicent.audit_events": varicentAuditEventsProjections,
	"varicent.policies":     varicentPoliciesProjections,
	"varicent.records":      varicentRecordsProjections,
	"varicent.users":        varicentUsersProjections,

	// velopayments generated projectors (sourcegen promotion)
	"velopayments.delta":              velopaymentsDeltaProjections,
	"velopayments.paymentchannelrule": velopaymentsPaymentchannelruleProjections,
	"velopayments.sourceaccount":      velopaymentsSourceaccountProjections,
	"velopayments.webhook":            velopaymentsWebhookProjections,

	// veracode generated projectors (sourcegen promotion)
	"veracode.assets":          veracodeAssetsProjections,
	"veracode.findings":        veracodeFindingsProjections,
	"veracode.vulnerabilities": veracodeVulnerabilitiesProjections,

	// vercel generated projectors (sourcegen promotion)
	"vercel.audit_events": vercelAuditEventsProjections,
	"vercel.deployments":  vercelDeploymentsProjections,
	"vercel.projects":     vercelProjectsProjections,

	// victoriametrics_cloud generated projectors (sourcegen promotion)
	"victoriametrics_cloud.accounts":     victoriametricsCloudAccountsProjections,
	"victoriametrics_cloud.audit_events": victoriametricsCloudAuditEventsProjections,
	"victoriametrics_cloud.policies":     victoriametricsCloudPoliciesProjections,
	"victoriametrics_cloud.records":      victoriametricsCloudRecordsProjections,
	"victoriametrics_cloud.users":        victoriametricsCloudUsersProjections,

	// victorops generated projectors (sourcegen promotion)
	"victorops.incident": victoropsIncidentProjections,
	"victorops.log":      victoropsLogProjections,
	"victorops.team":     victoropsTeamProjections,
	"victorops.user":     victoropsUserProjections,

	// vidyard generated projectors (sourcegen promotion)
	"vidyard.audit_events": vidyardAuditEventsProjections,
	"vidyard.documents":    vidyardDocumentsProjections,
	"vidyard.groups":       vidyardGroupsProjections,
	"vidyard.users":        vidyardUsersProjections,
	"vidyard.workspaces":   vidyardWorkspacesProjections,

	// virustotal generated projectors (sourcegen promotion)
	"virustotal.assets":          virustotalAssetsProjections,
	"virustotal.findings":        virustotalFindingsProjections,
	"virustotal.vulnerabilities": virustotalVulnerabilitiesProjections,

	// visiblethread generated projectors (sourcegen promotion)
	"visiblethread.document":   visiblethreadDocumentProjections,
	"visiblethread.document_2": visiblethreadDocument2Projections,
	"visiblethread.webscan":    visiblethreadWebscanProjections,
	"visiblethread.weburl":     visiblethreadWeburlProjections,

	// vitally generated projectors (sourcegen promotion)
	"vitally.accounts":     vitallyAccountsProjections,
	"vitally.audit_events": vitallyAuditEventsProjections,
	"vitally.policies":     vitallyPoliciesProjections,
	"vitally.records":      vitallyRecordsProjections,
	"vitally.users":        vitallyUsersProjections,

	// vulncheck generated projectors (sourcegen promotion)
	"vulncheck.assets":          vulncheckAssetsProjections,
	"vulncheck.audit_events":    vulncheckAuditEventsProjections,
	"vulncheck.findings":        vulncheckFindingsProjections,
	"vulncheck.policies":        vulncheckPoliciesProjections,
	"vulncheck.vulnerabilities": vulncheckVulnerabilitiesProjections,

	// webex generated projectors (sourcegen promotion)
	"webex.audit_events": webexAuditEventsProjections,
	"webex.documents":    webexDocumentsProjections,
	"webex.groups":       webexGroupsProjections,
	"webex.users":        webexUsersProjections,
	"webex.workspaces":   webexWorkspacesProjections,

	// whatsapp generated projectors (sourcegen promotion)
	"whatsapp.group":   whatsappGroupProjections,
	"whatsapp.group_2": whatsappGroup2Projections,
	"whatsapp.invite":  whatsappInviteProjections,
	"whatsapp.user":    whatsappUserProjections,

	// whereby generated projectors (sourcegen promotion)
	"whereby.audit_events": wherebyAuditEventsProjections,
	"whereby.documents":    wherebyDocumentsProjections,
	"whereby.groups":       wherebyGroupsProjections,
	"whereby.users":        wherebyUsersProjections,
	"whereby.workspaces":   wherebyWorkspacesProjections,

	// whistic generated projectors (sourcegen promotion)
	"whistic.assets":          whisticAssetsProjections,
	"whistic.audit_events":    whisticAuditEventsProjections,
	"whistic.findings":        whisticFindingsProjections,
	"whistic.policies":        whisticPoliciesProjections,
	"whistic.vulnerabilities": whisticVulnerabilitiesProjections,

	// wing_security generated projectors (sourcegen promotion)
	"wing_security.assets":          wingSecurityAssetsProjections,
	"wing_security.audit_events":    wingSecurityAuditEventsProjections,
	"wing_security.findings":        wingSecurityFindingsProjections,
	"wing_security.policies":        wingSecurityPoliciesProjections,
	"wing_security.vulnerabilities": wingSecurityVulnerabilitiesProjections,

	// winsms generated projectors (sourcegen promotion)
	"winsms.incoming":     winsmsIncomingProjections,
	"winsms.optout":       winsmsOptoutProjections,
	"winsms.sms_incoming": winsmsSmsIncomingProjections,
	"winsms.subaccount":   winsmsSubaccountProjections,

	// wistia generated projectors (sourcegen promotion)
	"wistia.audit_events": wistiaAuditEventsProjections,
	"wistia.documents":    wistiaDocumentsProjections,
	"wistia.groups":       wistiaGroupsProjections,
	"wistia.users":        wistiaUsersProjections,
	"wistia.workspaces":   wistiaWorkspacesProjections,

	// wiz generated projectors (sourcegen promotion)
	"wiz.assets":          wizAssetsProjections,
	"wiz.findings":        wizFindingsProjections,
	"wiz.vulnerabilities": wizVulnerabilitiesProjections,

	// workable generated projectors (sourcegen promotion)
	"workable.accounts":     workableAccountsProjections,
	"workable.audit_events": workableAuditEventsProjections,
	"workable.policies":     workablePoliciesProjections,
	"workable.records":      workableRecordsProjections,
	"workable.users":        workableUsersProjections,

	// workato generated projectors (sourcegen promotion)
	"workato.audit_events": workatoAuditEventsProjections,
	"workato.deployments":  workatoDeploymentsProjections,
	"workato.projects":     workatoProjectsProjections,
	"workato.repositories": workatoRepositoriesProjections,
	"workato.users":        workatoUsersProjections,

	// workday generated projectors (sourcegen promotion)
	"workday.audit_events": workdayAuditEventsProjections,
	"workday.groups":       workdayGroupsProjections,
	"workday.users":        workdayUsersProjections,

	// workos generated projectors (sourcegen promotion)
	"workos.audit_events": workosAuditEventsProjections,
	"workos.groups":       workosGroupsProjections,
	"workos.users":        workosUsersProjections,

	// workplace_from_meta generated projectors (sourcegen promotion)
	"workplace_from_meta.audit_events": workplaceFromMetaAuditEventsProjections,
	"workplace_from_meta.documents":    workplaceFromMetaDocumentsProjections,
	"workplace_from_meta.groups":       workplaceFromMetaGroupsProjections,
	"workplace_from_meta.users":        workplaceFromMetaUsersProjections,
	"workplace_from_meta.workspaces":   workplaceFromMetaWorkspacesProjections,

	// wrike generated projectors (sourcegen promotion)
	"wrike.audit_events": wrikeAuditEventsProjections,
	"wrike.documents":    wrikeDocumentsProjections,
	"wrike.groups":       wrikeGroupsProjections,
	"wrike.users":        wrikeUsersProjections,
	"wrike.workspaces":   wrikeWorkspacesProjections,

	// xai generated projectors (sourcegen promotion)
	"xai.api_keys":      xaiApiKeysProjections,
	"xai.audit_logs":    xaiAuditLogsProjections,
	"xai.model_access":  xaiModelAccessProjections,
	"xai.usage_reports": xaiUsageReportsProjections,

	// xero generated projectors (sourcegen promotion)
	"xero.accounts":     xeroAccountsProjections,
	"xero.audit_events": xeroAuditEventsProjections,
	"xero.policies":     xeroPoliciesProjections,
	"xero.records":      xeroRecordsProjections,
	"xero.users":        xeroUsersProjections,

	// xmatters generated projectors (sourcegen promotion)
	"xmatters.alerts":       xmattersAlertsProjections,
	"xmatters.audit_events": xmattersAuditEventsProjections,
	"xmatters.dashboards":   xmattersDashboardsProjections,
	"xmatters.incidents":    xmattersIncidentsProjections,
	"xmatters.monitors":     xmattersMonitorsProjections,

	// xtrf_eu generated projectors (sourcegen promotion)
	"xtrf_eu.active":       xtrfEuActiveProjections,
	"xtrf_eu.all":          xtrfEuAllProjections,
	"xtrf_eu.customer":     xtrfEuCustomerProjections,
	"xtrf_eu.customers_id": xtrfEuCustomersIdProjections,
	"xtrf_eu.id":           xtrfEuIdProjections,
	"xtrf_eu.id_2":         xtrfEuId2Projections,
	"xtrf_eu.invoices_id":  xtrfEuInvoicesIdProjections,
	"xtrf_eu.persons_id":   xtrfEuPersonsIdProjections,
	"xtrf_eu.projects_id":  xtrfEuProjectsIdProjections,
	"xtrf_eu.providers_id": xtrfEuProvidersIdProjections,
	"xtrf_eu.quotes_id":    xtrfEuQuotesIdProjections,
	"xtrf_eu.user":         xtrfEuUserProjections,

	// yardi_voyager generated projectors (sourcegen promotion)
	"yardi_voyager.accounts":     yardiVoyagerAccountsProjections,
	"yardi_voyager.audit_events": yardiVoyagerAuditEventsProjections,
	"yardi_voyager.policies":     yardiVoyagerPoliciesProjections,
	"yardi_voyager.records":      yardiVoyagerRecordsProjections,
	"yardi_voyager.users":        yardiVoyagerUsersProjections,

	// zapier_enterprise generated projectors (sourcegen promotion)
	"zapier_enterprise.audit_events": zapierEnterpriseAuditEventsProjections,
	"zapier_enterprise.deployments":  zapierEnterpriseDeploymentsProjections,
	"zapier_enterprise.projects":     zapierEnterpriseProjectsProjections,
	"zapier_enterprise.repositories": zapierEnterpriseRepositoriesProjections,
	"zapier_enterprise.users":        zapierEnterpriseUsersProjections,

	// zeet generated projectors (sourcegen promotion)
	"zeet.audit_events": zeetAuditEventsProjections,
	"zeet.deployments":  zeetDeploymentsProjections,
	"zeet.projects":     zeetProjectsProjections,
	"zeet.repositories": zeetRepositoriesProjections,
	"zeet.users":        zeetUsersProjections,

	// zendesk generated projectors (sourcegen promotion)
	"zendesk.audit_events": zendeskAuditEventsProjections,
	"zendesk.tickets":      zendeskTicketsProjections,
	"zendesk.users":        zendeskUsersProjections,

	// zendesk_sell generated projectors (sourcegen promotion)
	"zendesk_sell.accounts":     zendeskSellAccountsProjections,
	"zendesk_sell.audit_events": zendeskSellAuditEventsProjections,
	"zendesk_sell.policies":     zendeskSellPoliciesProjections,
	"zendesk_sell.records":      zendeskSellRecordsProjections,
	"zendesk_sell.users":        zendeskSellUsersProjections,

	// zenefits generated projectors (sourcegen promotion)
	"zenefits.accounts":     zenefitsAccountsProjections,
	"zenefits.audit_events": zenefitsAuditEventsProjections,
	"zenefits.policies":     zenefitsPoliciesProjections,
	"zenefits.records":      zenefitsRecordsProjections,
	"zenefits.users":        zenefitsUsersProjections,

	// zerofox generated projectors (sourcegen promotion)
	"zerofox.assets":          zerofoxAssetsProjections,
	"zerofox.audit_events":    zerofoxAuditEventsProjections,
	"zerofox.findings":        zerofoxFindingsProjections,
	"zerofox.policies":        zerofoxPoliciesProjections,
	"zerofox.vulnerabilities": zerofoxVulnerabilitiesProjections,

	// zilla_security generated projectors (sourcegen promotion)
	"zilla_security.applications": zillaSecurityApplicationsProjections,
	"zilla_security.audit_events": zillaSecurityAuditEventsProjections,
	"zilla_security.groups":       zillaSecurityGroupsProjections,
	"zilla_security.roles":        zillaSecurityRolesProjections,
	"zilla_security.users":        zillaSecurityUsersProjections,

	// ziphq generated projectors (sourcegen promotion)
	"ziphq.accounts":     ziphqAccountsProjections,
	"ziphq.audit_events": ziphqAuditEventsProjections,
	"ziphq.policies":     ziphqPoliciesProjections,
	"ziphq.records":      ziphqRecordsProjections,
	"ziphq.users":        ziphqUsersProjections,

	// zoho_books generated projectors (sourcegen promotion)
	"zoho_books.accounts":     zohoBooksAccountsProjections,
	"zoho_books.audit_events": zohoBooksAuditEventsProjections,
	"zoho_books.policies":     zohoBooksPoliciesProjections,
	"zoho_books.records":      zohoBooksRecordsProjections,
	"zoho_books.users":        zohoBooksUsersProjections,

	// zoho_crm generated projectors (sourcegen promotion)
	"zoho_crm.accounts":     zohoCrmAccountsProjections,
	"zoho_crm.audit_events": zohoCrmAuditEventsProjections,
	"zoho_crm.policies":     zohoCrmPoliciesProjections,
	"zoho_crm.records":      zohoCrmRecordsProjections,
	"zoho_crm.users":        zohoCrmUsersProjections,

	// zoho_mail generated projectors (sourcegen promotion)
	"zoho_mail.audit_events": zohoMailAuditEventsProjections,
	"zoho_mail.documents":    zohoMailDocumentsProjections,
	"zoho_mail.groups":       zohoMailGroupsProjections,
	"zoho_mail.users":        zohoMailUsersProjections,
	"zoho_mail.workspaces":   zohoMailWorkspacesProjections,

	// zoho_projects generated projectors (sourcegen promotion)
	"zoho_projects.audit_events": zohoProjectsAuditEventsProjections,
	"zoho_projects.documents":    zohoProjectsDocumentsProjections,
	"zoho_projects.groups":       zohoProjectsGroupsProjections,
	"zoho_projects.users":        zohoProjectsUsersProjections,
	"zoho_projects.workspaces":   zohoProjectsWorkspacesProjections,

	// zoho_sprints generated projectors (sourcegen promotion)
	"zoho_sprints.audit_events": zohoSprintsAuditEventsProjections,
	"zoho_sprints.documents":    zohoSprintsDocumentsProjections,
	"zoho_sprints.groups":       zohoSprintsGroupsProjections,
	"zoho_sprints.users":        zohoSprintsUsersProjections,
	"zoho_sprints.workspaces":   zohoSprintsWorkspacesProjections,

	// zoho_workdrive generated projectors (sourcegen promotion)
	"zoho_workdrive.audit_events": zohoWorkdriveAuditEventsProjections,
	"zoho_workdrive.documents":    zohoWorkdriveDocumentsProjections,
	"zoho_workdrive.groups":       zohoWorkdriveGroupsProjections,
	"zoho_workdrive.users":        zohoWorkdriveUsersProjections,
	"zoho_workdrive.workspaces":   zohoWorkdriveWorkspacesProjections,

	// zoom generated projectors (sourcegen promotion)
	"zoom.audit_events":   zoomAuditEventsProjections,
	"zoom.content_assets": zoomContentAssetsProjections,
	"zoom.users":          zoomUsersProjections,

	// zoom_phone generated projectors (sourcegen promotion)
	"zoom_phone.audit_events": zoomPhoneAuditEventsProjections,
	"zoom_phone.documents":    zoomPhoneDocumentsProjections,
	"zoom_phone.groups":       zoomPhoneGroupsProjections,
	"zoom_phone.users":        zoomPhoneUsersProjections,
	"zoom_phone.workspaces":   zoomPhoneWorkspacesProjections,

	// zoominfo generated projectors (sourcegen promotion)
	"zoominfo.accounts":     zoominfoAccountsProjections,
	"zoominfo.audit_events": zoominfoAuditEventsProjections,
	"zoominfo.policies":     zoominfoPoliciesProjections,
	"zoominfo.records":      zoominfoRecordsProjections,
	"zoominfo.users":        zoominfoUsersProjections,

	// zscaler_internet_access generated projectors (sourcegen promotion)
	"zscaler_internet_access.applications": zscalerInternetAccessApplicationsProjections,
	"zscaler_internet_access.audit_events": zscalerInternetAccessAuditEventsProjections,
	"zscaler_internet_access.groups":       zscalerInternetAccessGroupsProjections,
	"zscaler_internet_access.roles":        zscalerInternetAccessRolesProjections,
	"zscaler_internet_access.users":        zscalerInternetAccessUsersProjections,

	// zscaler_private_access generated projectors (sourcegen promotion)
	"zscaler_private_access.applications": zscalerPrivateAccessApplicationsProjections,
	"zscaler_private_access.audit_events": zscalerPrivateAccessAuditEventsProjections,
	"zscaler_private_access.groups":       zscalerPrivateAccessGroupsProjections,
	"zscaler_private_access.roles":        zscalerPrivateAccessRolesProjections,
	"zscaler_private_access.users":        zscalerPrivateAccessUsersProjections,

	// zuora generated projectors (sourcegen promotion)
	"zuora.account":                 zuoraAccountProjections,
	"zuora.accounting_code":         zuoraAccountingCodeProjections,
	"zuora.accounting_period":       zuoraAccountingPeriodProjections,
	"zuora.callout":                 zuoraCalloutProjections,
	"zuora.email":                   zuoraEmailProjections,
	"zuora.email_template":          zuoraEmailTemplateProjections,
	"zuora.event_trigger":           zuoraEventTriggerProjections,
	"zuora.hostedpage":              zuoraHostedpageProjections,
	"zuora.notification_definition": zuoraNotificationDefinitionProjections,
	"zuora.product":                 zuoraProductProjections,
	"zuora.revenue_event":           zuoraRevenueEventProjections,
	"zuora.revenue_schedule":        zuoraRevenueScheduleProjections,

	// zylo generated projectors (sourcegen promotion)
	"zylo.applications": zyloApplicationsProjections,
	"zylo.audit_events": zyloAuditEventsProjections,
	"zylo.groups":       zyloGroupsProjections,
	"zylo.roles":        zyloRolesProjections,
	"zylo.users":        zyloUsersProjections,

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
