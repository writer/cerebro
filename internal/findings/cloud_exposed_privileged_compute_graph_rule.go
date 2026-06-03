package findings

const cloudExposedPrivilegedComputeRoleRuleID = "cloud-exposed-privileged-compute-role"

func newCloudExposedPrivilegedComputeRoleRule() Rule {
	definition := cloudRuleDefinition(
		cloudExposedPrivilegedComputeRoleRuleID,
		"Cloud Exposed Privileged Compute Role",
		"Detect publicly reachable AWS compute workloads that run as admin-equivalent or privilege-escalating roles.",
		"CRITICAL",
		"finding.cloud_exposed_privileged_compute_role",
		[]string{"cloud", "aws", "compute", "ecs", "lambda", "ec2", "attack-path", "public-exposure", "privilege-escalation", "attack.t1190", "attack.t1098"},
		[]string{"compute_workload_urn", "runtime_role_urn", "permission_urn"},
	)
	definition.EventKinds = []string{
		"aws.ec2_instance",
		"aws.lambda_function",
		"aws.ecs_service",
		"aws.ecs_task_definition",
		"aws.effective_permission",
		"aws.iam_role_assignment",
		"aws.iam_role_trust",
		"aws.public_endpoint",
		"aws.resource_exposure",
	}
	definition.FalsePositives = []string{
		"Approved public compute endpoint whose runtime role is intentionally broad and protected by compensating controls not yet modeled in the graph.",
		"Temporary deployment or break-glass role attachment during a documented maintenance window.",
	}
	definition.References = []string{
		"https://www.cisecurity.org/benchmark/amazon_web_services",
		"https://attack.mitre.org/techniques/T1190/",
		"https://attack.mitre.org/techniques/T1098/",
	}
	definition.Runbook = "Validate the public entry point, remove unnecessary public ingress, and reduce the EC2 instance profile, Lambda role, or ECS task role to least privilege. For ECS services, review the linked task definition role first."
	return newCoordinationGraphRule(definition, map[string][]string{
		"aws": {
			"ec2_instance",
			"lambda_function",
			"ecs_service",
			"ecs_task_definition",
			"effective_permission",
			"iam_role_assignment",
			"iam_role_trust",
			"public_endpoint",
			"resource_exposure",
		},
	}, `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(entry:Entity {tenant_id: $tenant_id})
MATCH (workload:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND workload.entity_type IN ['aws.ec2.instance', 'aws.lambda.function', 'aws.ecs.service']
  AND (
    entry = workload
    OR EXISTS {
      MATCH (entry)-[:RELATION {relation: 'attached_to'}]->(workload)
      WHERE entry.entity_type = 'aws.network.interface'
    }
    OR EXISTS {
      MATCH (workload)-[:RELATION {relation: 'member_of'}]->(entry)
      WHERE entry.entity_type = 'aws.security_group'
    }
  )
  AND coalesce(reach.attributes_json, '') CONTAINS '"at":"'
  AND datetime(split(split(coalesce(reach.attributes_json, ''), '"at":"')[1], '"')[0]) >= datetime() - duration('P30D')
OPTIONAL MATCH (workload)-[directRun:RELATION {relation: 'runs_as'}]->(directRole:Entity {tenant_id: $tenant_id, entity_type: 'aws.role'})
OPTIONAL MATCH (workload)-[taskLink:RELATION {relation: 'depends_on'}]->(taskDefinition:Entity {tenant_id: $tenant_id, entity_type: 'aws.ecs.task_definition'})-[taskRun:RELATION {relation: 'runs_as'}]->(taskRole:Entity {tenant_id: $tenant_id, entity_type: 'aws.role'})
WITH public, reach, entry, workload, account, taskDefinition, coalesce(directRole, taskRole) AS role, coalesce(directRun.attributes_json, taskRun.attributes_json, '') AS run_attributes_json, taskLink
WHERE role IS NOT NULL
  AND (workload.entity_type <> 'aws.ecs.service' OR taskDefinition IS NOT NULL)
MATCH (role)-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})
WHERE access.relation IN ['can_admin', 'can_assume', 'can_perform']
  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
  )
RETURN workload.urn AS primary_urn,
       workload.label AS primary_label,
       workload.entity_type AS primary_type,
       workload.urn + '|' + role.urn + '|' + permission.urn AS fingerprint_key,
       CASE WHEN access.relation = 'can_assume' THEN 'HIGH' ELSE 'CRITICAL' END AS severity,
       'Publicly reachable compute workload ' + coalesce(workload.label, workload.urn) + ' runs as privileged role ' + coalesce(role.label, role.urn) AS summary,
       'Remove unnecessary public reachability and reduce the compute runtime role privileges' AS action,
       CASE
         WHEN taskDefinition.urn IS NULL THEN [workload.urn, entry.urn, role.urn, permission.urn, account.urn]
         ELSE [workload.urn, entry.urn, taskDefinition.urn, role.urn, permission.urn, account.urn]
       END AS resource_urns,
       CASE
         WHEN taskDefinition.urn IS NULL THEN [
           {urn: public.urn, label: public.label, entity_type: public.entity_type, relation: 'can_reach', attributes_json: coalesce(reach.attributes_json, '')},
           {urn: entry.urn, label: entry.label, entity_type: entry.entity_type, relation: CASE WHEN entry = workload THEN 'can_reach' WHEN entry.entity_type = 'aws.network.interface' THEN 'attached_to' ELSE 'member_of' END, attributes_json: coalesce(reach.attributes_json, '')},
           {urn: role.urn, label: role.label, entity_type: role.entity_type, relation: 'runs_as', attributes_json: run_attributes_json},
           {urn: permission.urn, label: permission.label, entity_type: permission.entity_type, relation: access.relation, attributes_json: coalesce(access.attributes_json, '')},
           {urn: account.urn, label: account.label, entity_type: account.entity_type, relation: 'belongs_to', attributes_json: ''}
         ]
         ELSE [
           {urn: public.urn, label: public.label, entity_type: public.entity_type, relation: 'can_reach', attributes_json: coalesce(reach.attributes_json, '')},
           {urn: entry.urn, label: entry.label, entity_type: entry.entity_type, relation: CASE WHEN entry = workload THEN 'can_reach' WHEN entry.entity_type = 'aws.network.interface' THEN 'attached_to' ELSE 'member_of' END, attributes_json: coalesce(reach.attributes_json, '')},
           {urn: taskDefinition.urn, label: taskDefinition.label, entity_type: taskDefinition.entity_type, relation: 'depends_on', attributes_json: coalesce(taskLink.attributes_json, '')},
           {urn: role.urn, label: role.label, entity_type: role.entity_type, relation: 'runs_as', attributes_json: run_attributes_json},
           {urn: permission.urn, label: permission.label, entity_type: permission.entity_type, relation: access.relation, attributes_json: coalesce(access.attributes_json, '')},
           {urn: account.urn, label: account.label, entity_type: account.entity_type, relation: 'belongs_to', attributes_json: ''}
         ]
       END AS evidence
ORDER BY severity, workload.entity_type, workload.label, role.label, permission.label
LIMIT $row_limit`, nil)
}
