package findings

const cloudPublicSensitiveResourceRuleID = "cloud-public-sensitive-resource"

func newCloudPublicSensitiveResourceGraphRule() Rule {
	definition := cloudRuleDefinition(
		cloudPublicSensitiveResourceRuleID,
		"Cloud Public Sensitive Resource",
		"Detect publicly reachable cloud data, secret, key, queue, or registry resources that carry sensitivity or crown-jewel context.",
		"CRITICAL",
		"finding.cloud_public_sensitive_resource",
		[]string{"cloud", "data", "exposure", "public", "crown-jewel", "attack-path", "attack.t1190"},
		[]string{"resource_urn", "sensitivity_urn"},
	)
	definition.EventKinds = builtinCloudCapabilities.EventKinds(cloudCapabilityResourceExposure)
	definition.FalsePositives = []string{
		"Approved public distribution or queue that only exposes non-sensitive data and is tagged conservatively.",
		"Temporary migration exposure where compensating access controls are enforced outside the modeled graph.",
	}
	definition.Runbook = "Remove public reachability first, then verify the data classification or crown-jewel tag. If exposure is intentional, link the exception to the owning team and expiration date."
	return newCoordinationGraphRule(definition, map[string][]string{
		"aws": {
			"asset_metadata",
			"ecr_repository",
			"kms_key",
			"public_endpoint",
			"rds_instance",
			"resource_exposure",
			"s3_bucket",
			"secret",
			"sns_topic",
			"sqs_queue",
		},
		"azure": {
			"asset_metadata",
			"container_registry",
			"cosmos_account",
			"key_vault",
			"key_vault_key",
			"key_vault_secret",
			"resource_exposure",
			"sql_database",
			"sql_server",
			"storage_account",
		},
		"gcp": {
			"artifact_registry_image",
			"artifact_registry_repository",
			"asset_metadata",
			"cloud_sql_instance",
			"gcs_bucket",
			"kms_key",
			"resource_exposure",
			"secret_manager_secret",
		},
	}, `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(resource:Entity {tenant_id: $tenant_id})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND resource.entity_type <> 'cloud.account'
  AND NOT resource.entity_type ENDS WITH '.public_principal'
  AND (resource.entity_type STARTS WITH 'aws.' OR resource.entity_type STARTS WITH 'azure.' OR resource.entity_type STARTS WITH 'gcp.')
  AND coalesce(reach.attributes_json, '') CONTAINS '"at":"'
  AND datetime(split(split(coalesce(reach.attributes_json, ''), '"at":"')[1], '"')[0]) >= datetime() - duration('P30D')
OPTIONAL MATCH (resource)-[:RELATION {relation: 'has_classification'}]->(classification:Entity {tenant_id: $tenant_id})
OPTIONAL MATCH (resource)-[:RELATION {relation: 'tagged_as'}]->(tag:Entity {tenant_id: $tenant_id})
WITH public, reach, resource, collect(DISTINCT classification)[0] AS classification, collect(DISTINCT tag)[0] AS tag
WHERE classification IS NOT NULL
   OR tag IS NOT NULL
   OR coalesce(resource.attributes_json, '') CONTAINS '"data_classification":"restricted"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"data_classification":"confidential"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"data_sensitivity":"restricted"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"data_sensitivity":"confidential"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"sensitivity":"restricted"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"sensitivity":"confidential"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"crown_jewel":"true"'
   OR coalesce(resource.attributes_json, '') CONTAINS '"pii":"true"'
RETURN resource.urn AS primary_urn,
       resource.label AS primary_label,
       resource.entity_type AS primary_type,
       resource.urn + '|' + coalesce(classification.urn, tag.urn, 'sensitive') AS fingerprint_key,
       CASE
         WHEN coalesce(tag.label, '') = 'crown_jewel' OR coalesce(resource.attributes_json, '') CONTAINS '"crown_jewel":"true"' THEN 'CRITICAL'
         WHEN coalesce(classification.label, '') IN ['restricted', 'confidential'] THEN 'CRITICAL'
         ELSE 'HIGH'
       END AS severity,
       'Publicly reachable sensitive cloud resource ' + coalesce(resource.label, resource.urn) AS summary,
       'Remove public reachability or document a time-bound approved exception with the resource owner' AS action,
       [resource.urn, public.urn] + CASE WHEN classification.urn IS NULL THEN [] ELSE [classification.urn] END + CASE WHEN tag.urn IS NULL THEN [] ELSE [tag.urn] END AS resource_urns,
       [{urn: public.urn, label: public.label, entity_type: public.entity_type, relation: 'can_reach', attributes_json: coalesce(reach.attributes_json, '')}]
         + CASE WHEN classification.urn IS NULL THEN [] ELSE [{urn: classification.urn, label: classification.label, entity_type: classification.entity_type, relation: 'has_classification', attributes_json: coalesce(classification.attributes_json, '')}] END
         + CASE WHEN tag.urn IS NULL THEN [] ELSE [{urn: tag.urn, label: tag.label, entity_type: tag.entity_type, relation: 'tagged_as', attributes_json: coalesce(tag.attributes_json, '')}] END AS evidence
ORDER BY severity, resource.entity_type, resource.label, resource.urn
LIMIT $row_limit`, nil)
}
