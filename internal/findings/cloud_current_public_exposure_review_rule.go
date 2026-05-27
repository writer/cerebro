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
	definition.EventKinds = []string{"aws.public_endpoint", "aws.resource_exposure", "azure.resource_exposure", "gcp.resource_exposure"}
	return newCoordinationGraphRule(definition, map[string][]string{
		"aws":   {"public_endpoint", "resource_exposure"},
		"azure": {"public_endpoint", "resource_exposure"},
		"gcp":   {"public_endpoint", "resource_exposure"},
	}, `MATCH (public:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'can_reach'}]->(resource:Entity {tenant_id: $tenant_id})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND resource.entity_type <> 'cloud.account'
  AND NOT resource.entity_type ENDS WITH '.public_principal'
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
