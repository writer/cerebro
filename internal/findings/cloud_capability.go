package findings

import (
	"sort"
	"strings"
)

type cloudCapability string

const (
	cloudCapabilityEffectivePermission cloudCapability = "effective_permission"
	cloudCapabilityPrivilegePath       cloudCapability = "privilege_path"
	cloudCapabilityResourceExposure    cloudCapability = "resource_exposure"
)

type cloudEventCapability struct {
	SourceID   string
	Kind       string
	Capability cloudCapability
}

type cloudCapabilityRegistry struct {
	events []cloudEventCapability
}

var builtinCloudCapabilities = newCloudCapabilityRegistry()

func newCloudCapabilityRegistry() cloudCapabilityRegistry {
	return cloudCapabilityRegistry{events: []cloudEventCapability{
		{SourceID: "aws", Kind: "aws.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "aws", Kind: "asset.data_sensitivity", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.asset_metadata", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.iam_role_trust", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "aws", Kind: "aws.ec2_instance", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.ecs_service", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.ecs_task", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.ecs_task_definition", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.eks_cluster", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.eks_nodegroup", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.eks_fargate_profile", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.eks_pod_identity_association", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.ecr_repository", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.iam_role_assignment", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "aws", Kind: "aws.kms_key", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.lambda_function", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.public_endpoint", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.rds_instance", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.s3_bucket", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.secret", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.sns_topic", Capability: cloudCapabilityResourceExposure},
		{SourceID: "aws", Kind: "aws.sqs_queue", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.app_role_assignment", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "azure", Kind: "asset.data_sensitivity", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.aks_cluster", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.app_service", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.asset_metadata", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.container_registry", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.cosmos_account", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "azure", Kind: "azure.function_app", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.iam_role_assignment", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "azure", Kind: "azure.key_vault", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.key_vault_key", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.key_vault_secret", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.sql_database", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.sql_server", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.storage_account", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.virtual_machine", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "asset.data_sensitivity", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.artifact_registry_image", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.artifact_registry_repository", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.asset_metadata", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.cloud_function", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.cloud_run_service", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.cloud_sql_instance", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.compute_instance", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "gcp", Kind: "gcp.gcs_bucket", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.gke_cluster", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.iam_role_assignment", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "gcp", Kind: "gcp.kms_key", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.secret_manager_secret", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.service_account_impersonation", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "kubernetes", Kind: "kubernetes.workload_identity_binding", Capability: cloudCapabilityPrivilegePath},
	}}
}

func (r cloudCapabilityRegistry) SourceIDs() []string {
	values := map[string]struct{}{}
	for _, event := range r.events {
		if sourceID := strings.TrimSpace(event.SourceID); sourceID != "" {
			values[sourceID] = struct{}{}
		}
	}
	return sortedCloudKeys(values)
}

func (r cloudCapabilityRegistry) EventKinds(capabilities ...cloudCapability) []string {
	allowed := map[cloudCapability]struct{}{}
	for _, capability := range capabilities {
		allowed[capability] = struct{}{}
	}
	values := map[string]struct{}{}
	for _, event := range r.events {
		if _, ok := allowed[event.Capability]; !ok {
			continue
		}
		if kind := strings.TrimSpace(event.Kind); kind != "" {
			values[kind] = struct{}{}
		}
	}
	return sortedCloudKeys(values)
}

func sortedCloudKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
