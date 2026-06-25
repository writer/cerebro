package findings

const cloudExposedPrivilegedComputeRoleRuleID = "cloud-exposed-privileged-compute-role"

func newCloudExposedPrivilegedComputeRoleRule() Rule {
	definition := cloudRuleDefinition(
		cloudExposedPrivilegedComputeRoleRuleID,
		"Cloud Exposed Privileged Compute Role",
		"Detect publicly reachable cloud compute workloads that run as admin-equivalent or privilege-escalating identities.",
		"CRITICAL",
		"finding.cloud_exposed_privileged_compute_role",
		[]string{"cloud", "aws", "gcp", "azure", "compute", "ecs", "eks", "gke", "serverless", "vm", "attack-path", "public-exposure", "privilege-escalation", "attack.t1190", "attack.t1098"},
		[]string{"compute_workload_urn", "runtime_identity_urn", "permission_urn"},
	)
	definition.EventKinds = []string{
		"asset.data_sensitivity",
		"aws.ec2_instance",
		"aws.lambda_function",
		"aws.ecs_service",
		"aws.ecs_task",
		"aws.ecs_task_definition",
		"aws.eks_cluster",
		"aws.eks_nodegroup",
		"aws.eks_fargate_profile",
		"aws.eks_pod_identity_association",
		"aws.effective_permission",
		"aws.iam_role_assignment",
		"aws.iam_role_trust",
		"aws.public_endpoint",
		"aws.resource_exposure",
		"azure.aks_cluster",
		"azure.app_service",
		"azure.effective_permission",
		"azure.function_app",
		"azure.resource_exposure",
		"azure.virtual_machine",
		"gcp.cloud_function",
		"gcp.cloud_run_service",
		"gcp.cloud_sql_instance",
		"gcp.compute_instance",
		"gcp.effective_permission",
		"gcp.gke_cluster",
		"gcp.resource_exposure",
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
	definition.Runbook = "Validate the public entry point, remove unnecessary public ingress, and reduce the AWS role, GCP service account, or Azure managed identity to least privilege. For ECS services and tasks, review the linked task definition role first."
	return newCoordinationGraphRule(definition, map[string][]string{
		"aws": {
			"asset_metadata",
			"ec2_instance",
			"lambda_function",
			"ecs_service",
			"ecs_task",
			"ecs_task_definition",
			"eks_cluster",
			"eks_nodegroup",
			"eks_fargate_profile",
			"eks_pod_identity_association",
			"effective_permission",
			"iam_role_assignment",
			"iam_role_trust",
			"public_endpoint",
			"resource_exposure",
		},
		"azure": {
			"aks_cluster",
			"app_service",
			"asset_metadata",
			"effective_permission",
			"function_app",
			"resource_exposure",
			"virtual_machine",
		},
		"gcp": {
			"asset_metadata",
			"cloud_function",
			"cloud_run_service",
			"cloud_sql_instance",
			"compute_instance",
			"effective_permission",
			"gke_cluster",
			"resource_exposure",
		},
	}, `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(entry:Entity {tenant_id: $tenant_id})
WHERE public.entity_type IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal']
  AND coalesce(reach.attributes_json, '') CONTAINS '"at":"'
  AND datetime(split(split(coalesce(reach.attributes_json, ''), '"at":"')[1], '"')[0]) >= datetime() - duration('P30D')
CALL {
  WITH entry
  MATCH (workload:Entity {tenant_id: $tenant_id})
  WHERE workload = entry
  RETURN workload
  UNION
  WITH entry
  MATCH (entry)-[:RELATION {relation: 'attached_to'}]->(workload:Entity {tenant_id: $tenant_id})
  WHERE entry.entity_type = 'aws.network.interface'
  RETURN workload
  UNION
  WITH entry
  MATCH (workload:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'member_of'}]->(entry)
  WHERE entry.entity_type = 'aws.security_group'
  RETURN workload
}
WITH public, reach, entry, workload
WHERE workload.entity_type IN ['aws.ec2.instance', 'aws.lambda.function', 'aws.ecs.service', 'aws.ecs.task', 'aws.eks.cluster', 'aws.eks.nodegroup', 'aws.eks.fargate_profile', 'aws.eks.pod_identity_association', 'gcp.compute.instance', 'gcp.gke.cluster', 'gcp.cloud.run.service', 'gcp.cloud.function', 'gcp.cloud.sql.instance', 'azure.virtual.machine', 'azure.aks.cluster', 'azure.app.service', 'azure.function.app']
MATCH (workload)-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
OPTIONAL MATCH (workload)-[directRun:RELATION {relation: 'runs_as'}]->(directRole:Entity {tenant_id: $tenant_id})
OPTIONAL MATCH (workload)-[taskLink:RELATION {relation: 'depends_on'}]->(taskDefinition:Entity {tenant_id: $tenant_id, entity_type: 'aws.ecs.task_definition'})-[taskRun:RELATION {relation: 'runs_as'}]->(taskRole:Entity {tenant_id: $tenant_id, entity_type: 'aws.role'})
WITH public, reach, entry, workload, account, taskDefinition, coalesce(directRole, taskRole) AS role, coalesce(directRun.attributes_json, taskRun.attributes_json, '') AS run_attributes_json, taskLink
WHERE role IS NOT NULL
  AND (NOT workload.entity_type IN ['aws.ecs.service', 'aws.ecs.task'] OR taskDefinition IS NOT NULL)
MATCH (role)-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})
WHERE access.relation IN ['can_admin', 'can_assume', 'can_impersonate', 'can_perform']
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
       CASE WHEN access.relation IN ['can_assume', 'can_impersonate'] THEN 'HIGH' ELSE 'CRITICAL' END AS severity,
       'Publicly reachable compute workload ' + coalesce(workload.label, workload.urn) + ' runs as privileged identity ' + coalesce(role.label, role.urn) AS summary,
       'Remove unnecessary public reachability and reduce the compute runtime identity privileges' AS action,
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
