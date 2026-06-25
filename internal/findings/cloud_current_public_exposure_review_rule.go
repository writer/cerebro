package findings

const cloudCurrentPublicExposureReviewRuleID = "cloud-current-public-exposure-review-needed"

func newCloudPublicResourceExposureGraphRule() Rule {
	definition := cloudRuleDefinition(
		cloudCurrentPublicExposureReviewRuleID,
		"Cloud Current Public Exposure Needs Review",
		"Detect current cloud resources with public internet exposure from the projected graph when no open exposure finding already anchors the resource.",
		"HIGH",
		"finding.cloud_current_public_exposure_review_needed",
		[]string{"cloud", "exposure", "public", "attack.t1190", "graph-rule"},
		[]string{"exposed_resource_urn"},
	)
	definition.EventKinds = builtinCloudCapabilities.EventKinds(cloudCapabilityResourceExposure)
	return newCoordinationGraphRule(definition, map[string][]string{
		"aws": {
			"asset_metadata",
			"ec2_instance",
			"ecs_service",
			"ecs_task",
			"ecs_task_definition",
			"eks_cluster",
			"eks_nodegroup",
			"eks_fargate_profile",
			"eks_pod_identity_association",
			"lambda_function",
			"public_endpoint",
			"resource_exposure",
		},
		"azure": {
			"aks_cluster",
			"app_service",
			"asset_metadata",
			"container_registry",
			"cosmos_account",
			"function_app",
			"key_vault",
			"key_vault_key",
			"key_vault_secret",
			"resource_exposure",
			"sql_database",
			"sql_server",
			"storage_account",
			"virtual_machine",
		},
		"gcp": {
			"artifact_registry_image",
			"artifact_registry_repository",
			"asset_metadata",
			"cloud_function",
			"cloud_run_service",
			"cloud_sql_instance",
			"compute_instance",
			"gcs_bucket",
			"gke_cluster",
			"kms_key",
			"resource_exposure",
			"secret_manager_secret",
		},
	}, `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(resource:Entity {tenant_id: $tenant_id})
WHERE public.entity_type IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal']
  AND resource.entity_type <> 'cloud.account'
  AND NOT resource.entity_type IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal']
  AND (
    coalesce(resource.attributes_json, '') CONTAINS '"internet_exposed":"true"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"external_exposure":"true"'
    OR coalesce(resource.attributes_json, '') CONTAINS '"public":"true"'
  )
  AND coalesce(reach.attributes_json, '') CONTAINS '"at":"'
  AND datetime(split(split(coalesce(reach.attributes_json, ''), '"at":"')[1], '"')[0]) >= datetime() - duration('P30D')
  AND NOT EXISTS {
    MATCH (resource)-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
    WHERE coalesce(finding.attributes_json, '') CONTAINS '"status":"open"'
      AND (
        coalesce(finding.attributes_json, '') CONTAINS '"rule_id":"cloud-public-resource-exposure"'
        OR coalesce(finding.attributes_json, '') CONTAINS '"rule_id":"cloud-public-exposure-privileged-principal"'
      )
  }
WITH DISTINCT resource
RETURN resource.urn AS primary_urn,
       resource.label AS primary_label,
       resource.entity_type AS primary_type,
       resource.urn AS fingerprint_key,
       CASE
         WHEN resource.entity_type IN ['aws.security.group', 'aws.application.load.balancer', 'aws.apigatewayv2.api', 'aws.cloudfront.distribution'] THEN 'HIGH'
         ELSE 'MEDIUM'
       END AS severity,
       'Cloud resource ' + coalesce(resource.label, resource.urn) + ' is publicly exposed' AS summary,
       'Review whether the public exposure is required; remove public ingress or document an approved exception' AS action,
       [resource.urn] AS resource_urns,
       [] AS evidence
ORDER BY resource.entity_type, resource.label, resource.urn
LIMIT $row_limit`, nil)
}
