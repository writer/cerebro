package findings

import "github.com/writer/cerebro/internal/ports"

const graphAWSEC2ENILinkMissingRuleID = "graph-aws-ec2-eni-link-missing"

func newGraphAWSEC2ENILinkMissingRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          graphAWSEC2ENILinkMissingRuleID,
		Name:        "AWS EC2 ENI Link Missing",
		Description: "Detect AWS network interface public-endpoint nodes that name an EC2 instance but lack the graph link to that instance.",
		SourceID:    "graph",
		EventKinds:  []string{"aws.public_endpoint"},
		OutputKind:  "finding.graph_aws_ec2_eni_link_missing",
		Severity:    "LOW",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"graph", "aws", "ec2", "network-interface", "enrichment"},
		References:  []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html"},
		FalsePositives: []string{
			"The referenced EC2 instance may have been terminated between endpoint and instance inventory snapshots.",
		},
		Runbook:           "Backfill or fix the public endpoint projection so ENIs are linked to their attached or associated EC2 instance.",
		FingerprintFields: []string{"network_interface_urn", "instance_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.35"},
		},
	}, nil, `MATCH (eni:Entity {tenant_id: $tenant_id, entity_type: 'aws.network.interface'})
WITH eni,
     CASE
       WHEN coalesce(eni.attributes_json, '') CONTAINS '"attached_instance_id":"' THEN split(split(eni.attributes_json, '"attached_instance_id":"')[1], '"')[0]
       WHEN coalesce(eni.attributes_json, '') CONTAINS '"associated_instance_id":"' THEN split(split(eni.attributes_json, '"associated_instance_id":"')[1], '"')[0]
       ELSE ''
     END AS instance_id
WHERE instance_id <> ''
MATCH (ec2:Entity {tenant_id: $tenant_id})
WHERE ec2.entity_type IN ['aws.ec2.instance', 'aws.aws::ec2::instance']
  AND (ec2.urn ENDS WITH ':' + instance_id OR ec2.label = instance_id OR coalesce(ec2.attributes_json, '') CONTAINS '"instance_id":"' + instance_id + '"')
  AND NOT EXISTS { MATCH (eni)-[:RELATION {relation: 'attached_to'}]->(ec2) }
  AND NOT EXISTS { MATCH (eni)-[:RELATION {relation: 'associated_with'}]->(ec2) }
  AND NOT EXISTS { MATCH (eni)-[:RELATION {relation: 'belongs_to'}]->(ec2) }
RETURN eni.urn AS primary_urn,
       eni.label AS primary_label,
       eni.entity_type AS primary_type,
       eni.urn + '|' + ec2.urn AS fingerprint_key,
       'LOW' AS severity,
       'AWS network interface ' + coalesce(eni.label, eni.urn) + ' is missing its EC2 instance graph link' AS summary,
       'Create the ENI to EC2 relation during projection/backfill' AS action,
       [eni.urn, ec2.urn] AS resource_urns,
       [{urn: ec2.urn, label: ec2.label, entity_type: ec2.entity_type, relation: 'attached_to', attributes_json: coalesce(ec2.attributes_json, '')}] AS evidence
ORDER BY eni.urn, ec2.urn
LIMIT $row_limit`, nil)
}
