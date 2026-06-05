package sourceprojection

import (
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// ProjectFunc converts one source event into graph projection records.
type ProjectFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

// EventProjector binds one event kind to one projector.
type EventProjector struct {
	Kind    string
	Project ProjectFunc
}

// Registry indexes projectors by event kind.
type Registry struct {
	projectors map[string]ProjectFunc
}

// NewRegistry constructs an event projection registry.
func NewRegistry(projectors ...EventProjector) (*Registry, error) {
	registry := &Registry{projectors: make(map[string]ProjectFunc, len(projectors))}
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

var builtinRegistry = &Registry{projectors: map[string]ProjectFunc{
	"backstage.component":                    backstageComponentProjections,
	"aurelius.catalog_promotion":             aureliusCatalogPromotionProjections,
	"aurelius.finding":                       aureliusFindingProjections,
	"aurelius.image_scan":                    aureliusImageScanProjections,
	"aurelius.policy_exception":              aureliusPolicyExceptionProjections,
	"aurelius.verdict":                       aureliusVerdictProjections,
	"github.pull_request":                    githubPullRequestProjections,
	"github.audit":                           githubAuditProjections,
	"github.code.repository":                 githubCodeRepositoryProjections,
	"github.dependabot_alert":                githubDependabotAlertProjections,
	"github.secret_scanning_alert":           githubSecretScanningAlertProjections,
	"github.org_member":                      githubOrgMemberProjections,
	"github.org_installation":                githubOrgInstallationProjections,
	"asset.crown_jewel":                      assetCrownJewelProjections,
	"asset.data_sensitivity":                 assetDataSensitivityProjections,
	"aws.access_key":                         awsAccessKeyProjections,
	"aws.athena_data_catalog":                awsCloudResourceProjections,
	"aws.athena_workgroup":                   awsCloudResourceProjections,
	"aws.asset_metadata":                     awsCloudResourceProjections,
	"aws.cloudtrail":                         awsCloudTrailProjections,
	"aws.ec2_instance":                       awsEC2InstanceProjections,
	"aws.ecr_repository":                     awsCloudResourceProjections,
	"aws.ecs_service":                        awsECSServiceProjections,
	"aws.ecs_task":                           awsECSTaskProjections,
	"aws.ecs_task_definition":                awsECSTaskDefinitionProjections,
	"aws.eks_cluster":                        awsEKSClusterProjections,
	"aws.eks_nodegroup":                      awsEKSNodegroupProjections,
	"aws.eks_fargate_profile":                awsEKSFargateProfileProjections,
	"aws.eks_pod_identity_association":       awsEKSPodIdentityAssociationProjections,
	"aws.effective_permission":               awsEffectivePermissionProjections,
	"aws.glue_crawler":                       awsCloudResourceProjections,
	"aws.glue_database":                      awsCloudResourceProjections,
	"aws.glue_job":                           awsCloudResourceProjections,
	"aws.glue_table":                         awsCloudResourceProjections,
	"aws.iam_group":                          awsIAMGroupProjections,
	"aws.iam_group_membership":               awsIAMGroupMembershipProjections,
	"aws.iam_role":                           awsIAMRoleProjections,
	"aws.iam_role_assignment":                awsIAMRoleAssignmentProjections,
	"aws.iam_role_trust":                     awsIAMRoleTrustProjections,
	"aws.iam_user":                           awsIAMUserProjections,
	"aws.kms_key":                            awsCloudResourceProjections,
	"aws.lakeformation_resource":             awsCloudResourceProjections,
	"aws.lambda_function":                    awsLambdaFunctionProjections,
	"aws.public_endpoint":                    awsPublicEndpointProjections,
	"aws.rds_instance":                       awsCloudResourceProjections,
	"aws.resource_exposure":                  awsResourceExposureProjections,
	"aws.s3_bucket":                          awsCloudResourceProjections,
	"aws.secret":                             awsCloudResourceProjections,
	"aws.sns_topic":                          awsCloudResourceProjections,
	"aws.sqs_queue":                          awsCloudResourceProjections,
	"azure.activity_log":                     azureAuditProjections,
	"azure.app_role_assignment":              azureAppRoleAssignmentProjections,
	"azure.aks_cluster":                      azureCloudResourceProjections,
	"azure.app_service":                      azureCloudResourceProjections,
	"azure.application":                      azureApplicationProjections,
	"azure.asset_metadata":                   azureCloudResourceProjections,
	"azure.container_registry":               azureCloudResourceProjections,
	"azure.cosmos_account":                   azureCloudResourceProjections,
	"azure.credential":                       azureCredentialProjections,
	"azure.directory_audit":                  azureAuditProjections,
	"azure.directory_role_assignment":        azureRoleAssignmentProjections,
	"azure.effective_permission":             azureEffectivePermissionProjections,
	"azure.function_app":                     azureCloudResourceProjections,
	"azure.group":                            azureGroupProjections,
	"azure.group_membership":                 azureGroupMembershipProjections,
	"azure.iam_role_assignment":              azureRoleAssignmentProjections,
	"azure.key_vault":                        azureCloudResourceProjections,
	"azure.key_vault_key":                    azureCloudResourceProjections,
	"azure.key_vault_secret":                 azureCloudResourceProjections,
	"azure.resource_exposure":                azureResourceExposureProjections,
	"azure.service_principal":                azureServicePrincipalProjections,
	"azure.sql_database":                     azureCloudResourceProjections,
	"azure.sql_server":                       azureCloudResourceProjections,
	"azure.storage_account":                  azureCloudResourceProjections,
	"azure.user":                             azureUserProjections,
	"azure.virtual_machine":                  azureCloudResourceProjections,
	"gcp.artifact_registry_image":            gcpCloudResourceProjections,
	"gcp.artifact_registry_repository":       gcpCloudResourceProjections,
	"gcp.asset_metadata":                     gcpCloudResourceProjections,
	"gcp.audit":                              gcpAuditProjections,
	"gcp.cloud_function":                     gcpCloudResourceProjections,
	"gcp.cloud_run_service":                  gcpCloudResourceProjections,
	"gcp.cloud_sql_instance":                 gcpCloudResourceProjections,
	"gcp.compute_instance":                   gcpCloudResourceProjections,
	"gcp.effective_permission":               gcpEffectivePermissionProjections,
	"gcp.gcs_bucket":                         gcpCloudResourceProjections,
	"gcp.gke_cluster":                        gcpCloudResourceProjections,
	"gcp.group":                              gcpGroupProjections,
	"gcp.group_membership":                   gcpGroupMembershipProjections,
	"gcp.iam_role_assignment":                gcpIAMRoleAssignmentProjections,
	"gcp.kms_key":                            gcpCloudResourceProjections,
	"gcp.resource_exposure":                  gcpResourceExposureProjections,
	"gcp.secret_manager_secret":              gcpCloudResourceProjections,
	"gcp.service_account":                    gcpServiceAccountProjections,
	"gcp.service_account_impersonation":      gcpServiceAccountImpersonationProjections,
	"gcp.service_account_key":                gcpServiceAccountKeyProjections,
	"gcp.container_analysis_vulnerability":   gcpContainerVulnerabilityProjections,
	"gcp.container_vulnerability":            gcpContainerVulnerabilityProjections,
	"cosmo.session":                          cosmoSessionProjections,
	"cosmo.fact":                             cosmoFactProjections,
	"cosmo.message":                          cosmoMessageProjections,
	"cosmo.survey_feedback":                  cosmoSurveyFeedbackProjections,
	"kolide.check":                           kolideCheckProjections,
	"kolide.device":                          kolideDeviceProjections,
	"kolide.software":                        kolideSoftwareProjections,
	"kolide.user_device":                     kolideUserDeviceProjections,
	"kolide.vulnerability":                   kolideVulnerabilityProjections,
	"kandji.application":                     kandjiApplicationProjections,
	"kandji.device":                          kandjiDeviceProjections,
	"kandji.vulnerability":                   kandjiVulnerabilityProjections,
	"okta.user":                              oktaUserProjections,
	"okta.group":                             oktaGroupProjections,
	"okta.group_membership":                  oktaGroupMembershipProjections,
	"okta.application":                       oktaApplicationProjections,
	"okta.app_assignment":                    oktaAppAssignmentProjections,
	"okta.policy_rule":                       oktaPolicyRuleProjections,
	"okta.admin_role":                        oktaAdminRoleProjections,
	"okta.audit":                             oktaAuditProjections,
	"okta.authenticator":                     oktaAuthenticatorProjections,
	"okta.threat_insight":                    oktaThreatInsightProjections,
	"google_workspace.user":                  googleWorkspaceUserProjections,
	"google_workspace.group":                 googleWorkspaceGroupProjections,
	"google_workspace.group_member":          googleWorkspaceGroupMemberProjections,
	"google_workspace.role_assignment":       googleWorkspaceRoleAssignmentProjections,
	"google_workspace.audit":                 googleWorkspaceAuditProjections,
	"grc.framework":                          grcFrameworkProjections,
	"grc.control":                            grcControlProjections,
	"grc.control_test":                       grcControlTestProjections,
	"grc.policy":                             grcPolicyProjections,
	"grc.document":                           grcDocumentProjections,
	"grc.vendor":                             grcVendorProjections,
	"grc.vulnerability":                      grcVulnerabilityProjections,
	"grc.vulnerable_asset":                   grcVulnerableAssetProjections,
	"grc.risk_scenario":                      grcRiskScenarioProjections,
	"grc.person":                             grcPersonProjections,
	"grc.user":                               grcUserProjections,
	"grc.integration":                        grcIntegrationProjections,
	"kubernetes.service_account":             kubernetesServiceAccountProjections,
	"kubernetes.workload":                    kubernetesWorkloadProjections,
	"kubernetes.workload_identity_binding":   kubernetesWorkloadIdentityBindingProjections,
	"runtime.evidence":                       runtimeEvidenceProjections,
	"security_tooling_map.control_mapping":   securityToolingMapControlMappingProjections,
	"security_tooling_map.tool":              securityToolingMapToolProjections,
	"sentinelone.activity":                   sentinelOneActivityProjections,
	"sentinelone.agent":                      sentinelOneAgentProjections,
	"sentinelone.application_inventory":      sentinelOneApplicationInventoryProjections,
	"sentinelone.exclusion":                  sentinelOneExclusionProjections,
	"sentinelone.group":                      sentinelOneGroupProjections,
	"sentinelone.site":                       sentinelOneSiteProjections,
	"sentinelone.threat":                     sentinelOneThreatProjections,
	"sentinelone.vulnerability":              sentinelOneVulnerabilityProjections,
	"trusted_endpoint.action_outcome":        trustedEndpointProjections,
	"trusted_endpoint.agent_identity":        trustedEndpointProjections,
	"trusted_endpoint.ai_session_summary":    trustedEndpointProjections,
	"trusted_endpoint.ai_workflow_risk":      trustedEndpointProjections,
	"trusted_endpoint.grc_evidence":          trustedEndpointProjections,
	"trusted_endpoint.host_posture":          trustedEndpointProjections,
	"trusted_endpoint.repo_worktree_context": trustedEndpointProjections,
	"trusted_endpoint.security_finding":      trustedEndpointProjections,
	"trusted_endpoint.trust_gate_decision":   trustedEndpointProjections,
	"vulnview.asset":                         vulnViewAssetProjections,
	"vulnview.dns_alert":                     vulnViewDNSAlertProjections,
	"vulnview.scan":                          vulnViewScanProjections,
	"vulnview.site":                          vulnViewSiteProjections,
	"vulnview.vulnerability":                 vulnViewVulnerabilityProjections,
}}

// BuiltinRegistry returns the default source event projector registry.
func BuiltinRegistry() *Registry {
	return builtinRegistry
}

// Kinds returns sorted registered event kinds.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
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
	project, ok := r.projectors[strings.TrimSpace(event.GetKind())]
	if !ok {
		return nil, nil, nil
	}
	return project(event)
}

// ProjectEvent projects one event through the built-in registry without stores.
func ProjectEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return BuiltinRegistry().Project(event)
}
