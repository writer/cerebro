# Graph Ontology Auto-Generated Catalog

Generated from `graph.RegisteredNodeKinds()`, `graph.RegisteredEdgeKinds()`, and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_graph_ontology_docs/main.go`.

- Node kinds: **68**
- Edge kinds: **44**
- Mapping rules: **13**
- Source domains: **9**

## Node Kinds

| Kind | Categories | Required Properties | Relationships |
|---|---|---|---|
| `action` | business | `action_type`, `observed_at`, `status`, `valid_from` | `based_on`, `evaluates`, `interacted_with`, `targets` |
| `activity` | business | - | - |
| `any` | - | - | - |
| `application` | resource | - | - |
| `bucket` | resource | - | `configures`, `depends_on`, `exposed_to`, `managed_by`, `owns`, `targets` |
| `bucket_encryption_config` | resource | `bucket_id`, `encryption_config_id`, `observed_at`, `recorded_at`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `configures`, `refers` |
| `bucket_logging_config` | resource | `bucket_id`, `logging_config_id`, `observed_at`, `recorded_at`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `configures`, `targets` |
| `bucket_policy_statement` | resource | `bucket_id`, `effect`, `observed_at`, `recorded_at`, `statement_id`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `configures`, `targets` |
| `bucket_public_access_block` | resource | `bucket_id`, `observed_at`, `public_access_block_id`, `recorded_at`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `configures`, `targets` |
| `bucket_versioning_config` | resource | `bucket_id`, `observed_at`, `recorded_at`, `transaction_from`, `valid_from`, `versioning_config_id` | `asserted_by`, `based_on`, `configures` |
| `check_run` | business | `check_name`, `check_run_id`, `observed_at`, `repository`, `status`, `valid_from` | `based_on`, `caused_by`, `evaluates`, `targets` |
| `ci_workflow` | - | - | - |
| `claim` | business | `claim_type`, `observed_at`, `predicate`, `recorded_at`, `status`, `subject_id`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `contradicts`, `refers`, `refutes`, `supersedes`, `supports`, `targets` |
| `cluster_role` | kubernetes | - | - |
| `cluster_role_binding` | kubernetes | - | - |
| `communication_thread` | business | `channel_id`, `observed_at`, `thread_id`, `valid_from` | `based_on`, `interacted_with`, `targets` |
| `company` | business | - | - |
| `configmap` | kubernetes, resource | - | - |
| `contact` | business | - | - |
| `customer` | business | - | - |
| `database` | resource | - | - |
| `deal` | business | - | - |
| `decision` | business | `decision_type`, `made_at`, `observed_at`, `status`, `valid_from` | `based_on`, `executed_by`, `targets` |
| `department` | business | - | - |
| `deployment` | kubernetes, resource | - | - |
| `deployment_run` | business, resource | `deploy_id`, `environment`, `observed_at`, `service_id`, `status`, `valid_from` | `based_on`, `depends_on`, `targets`, `triggered_by` |
| `document` | business | `document_id`, `observed_at`, `title`, `valid_from` | `based_on`, `targets` |
| `evidence` | business | `evidence_type`, `observed_at`, `source_system`, `valid_from` | `based_on`, `targets` |
| `folder` | resource | `folder_id`, `resource_name` | `located_in` |
| `function` | resource | - | - |
| `group` | identity | - | - |
| `identity_alias` | identity | `external_id`, `observed_at`, `source_system`, `valid_from` | `alias_of` |
| `incident` | business | `incident_id`, `observed_at`, `status`, `valid_from` | `based_on`, `caused_by`, `evaluates`, `targets` |
| `instance` | resource | - | - |
| `internet` | - | - | - |
| `invoice` | business | - | - |
| `lead` | business | - | - |
| `location` | business | - | - |
| `meeting` | business | `ends_at`, `meeting_id`, `observed_at`, `starts_at`, `valid_from` | `assigned_to`, `based_on`, `targets` |
| `namespace` | kubernetes | - | - |
| `network` | resource | - | - |
| `observation` | business | `observation_type`, `observed_at`, `recorded_at`, `subject_id`, `transaction_from`, `valid_from` | `asserted_by`, `based_on`, `targets` |
| `opportunity` | business | - | - |
| `organization` | resource | `organization_id`, `resource_name` | - |
| `outcome` | business | `observed_at`, `outcome_type`, `valid_from`, `verdict` | `evaluates`, `targets` |
| `package` | resource | `ecosystem`, `observed_at`, `package_name`, `recorded_at`, `transaction_from`, `valid_from`, `version` | `affected_by`, `based_on` |
| `permission_boundary` | - | - | - |
| `persistent_volume` | kubernetes, resource | - | - |
| `person` | identity | - | - |
| `pipeline_run` | business, resource | `observed_at`, `pipeline_id`, `run_id`, `service_id`, `status`, `valid_from` | `based_on`, `executed_by`, `targets` |
| `pod` | kubernetes, resource | - | - |
| `project` | resource | `project_id`, `resource_name` | `located_in` |
| `pull_request` | business | `number`, `observed_at`, `repository`, `state`, `valid_from` | `based_on`, `targets` |
| `repository` | - | - | - |
| `role` | identity | - | - |
| `role_binding` | kubernetes | - | - |
| `scp` | - | - | - |
| `secret` | resource | - | - |
| `service` | business, resource | `observed_at`, `service_id`, `valid_from` | `depends_on`, `owns`, `runs`, `targets` |
| `service_account` | identity | - | - |
| `source` | business | `canonical_name`, `observed_at`, `recorded_at`, `source_type`, `transaction_from`, `valid_from` | - |
| `subscription` | business | - | - |
| `technology` | resource | `category`, `observed_at`, `recorded_at`, `technology_id`, `technology_name`, `transaction_from`, `valid_from` | `based_on` |
| `ticket` | business | - | - |
| `user` | identity | - | - |
| `vulnerability` | resource | `observed_at`, `recorded_at`, `severity`, `transaction_from`, `valid_from`, `vulnerability_id` | `based_on` |
| `workload` | resource | `observed_at`, `runtime`, `valid_from`, `workload_id` | `connects_to`, `depends_on`, `targets` |
| `workload_scan` | resource | `observed_at`, `recorded_at`, `scan_id`, `status`, `target_id`, `target_kind`, `transaction_from`, `valid_from` | `based_on`, `contains_package`, `found_vulnerability`, `has_scan`, `targets` |

## Node Metadata Profiles

| Kind | Required Metadata | Optional Metadata | Timestamp Keys | Enum Constraints |
|---|---|---|---|---|
| `action` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `bucket_encryption_config` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `bucket_logging_config` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `bucket_policy_statement` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `effect`=`allow`, `deny`<br>`principal_type`=`account`, `all_authenticated_users`, `all_users`, `anonymous`, `public`, `service`, `user` |
| `bucket_public_access_block` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `public_access_prevention`=`disabled`, `enabled`, `enforced`, `inherited`, `unspecified` |
| `bucket_versioning_config` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `versioning_status`=`disabled`, `enabled`, `off`, `on`, `suspended` |
| `check_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `conclusion`=`action_required`, `cancelled`, `failure`, `neutral`, `skipped`, `stale`, `startup_failure`, `success`, `timed_out`<br>`status`=`completed`, `in_progress`, `queued` |
| `claim` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `claim_type`=`attribute`, `classification`, `existence`, `relation`<br>`status`=`asserted`, `corrected`, `disputed`, `refuted`, `retracted`, `superseded` |
| `communication_thread` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `decision` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `status`=`approved`, `cancelled`, `completed`, `deferred`, `in_progress`, `proposed`, `rejected` |
| `deployment_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `environment`=`dev`, `prod`, `production`, `qa`, `sandbox`, `staging`, `test`<br>`status`=`cancelled`, `completed`, `error`, `failed`, `failure`, `in_progress`, `pending`, `queued`, `running`, `succeeded`, `success`, `successful` |
| `document` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `evidence` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `folder` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `group` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `identity_alias` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `alias_type`=`email`, `employee_id`, `github`, `slack`, `uid`, `upn`, `username` |
| `incident` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `severity`=`critical`, `high`, `low`, `medium`, `sev1`, `sev2`, `sev3`, `sev4`<br>`status`=`acknowledged`, `closed`, `investigating`, `monitoring`, `open`, `postmortem`, `resolved`, `triggered` |
| `meeting` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `observation` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `organization` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `outcome` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `verdict`=`mixed`, `negative`, `neutral`, `positive`, `unknown` |
| `package` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `person` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `pipeline_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `status`=`action_required`, `cancelled`, `completed`, `failed`, `failure`, `in_progress`, `neutral`, `passed`, `pending`, `queued`, `running`, `skipped`, `succeeded`, `success`, `successful`, `timed_out` |
| `project` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `pull_request` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `state`=`closed`, `draft`, `merged`, `open`, `opened`, `review_submitted` |
| `role` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `service` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `criticality`=`critical`, `high`, `low`, `medium`, `tier0`, `tier1`, `tier2`, `tier3` |
| `service_account` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `source` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `source_type`=`document`, `external_api`, `human`, `model`, `pipeline`, `sensor`, `system`<br>`trust_tier`=`authoritative`, `derived`, `unverified`, `verified` |
| `technology` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `user` | - | `confidence`, `observed_at`, `recorded_at`, `source_event_id`, `source_system`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | - |
| `vulnerability` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `severity`=`critical`, `high`, `low`, `medium`, `unknown` |
| `workload` | `observed_at`, `source_system`, `valid_from` | `confidence`, `recorded_at`, `source_event_id`, `transaction_from`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `environment`=`dev`, `prod`, `production`, `qa`, `sandbox`, `staging`, `test` |
| `workload_scan` | `observed_at`, `recorded_at`, `source_system`, `transaction_from`, `valid_from` | `confidence`, `source_event_id`, `transaction_to`, `valid_to` | `observed_at`, `recorded_at`, `transaction_from`, `transaction_to`, `valid_from`, `valid_to` | `status`=`failed`, `queued`, `running`, `succeeded` |

## Edge Kinds

| Kind | Description |
|---|---|
| `affected_by` | - |
| `alias_of` | - |
| `asserted_by` | - |
| `assigned_to` | - |
| `based_on` | - |
| `billed_by` | - |
| `can_admin` | - |
| `can_assume` | - |
| `can_delete` | - |
| `can_read` | - |
| `can_write` | - |
| `caused_by` | - |
| `configures` | - |
| `connects_to` | - |
| `contains_package` | - |
| `contradicts` | - |
| `depends_on` | - |
| `deployed_from` | - |
| `escalated_to` | - |
| `evaluates` | - |
| `executed_by` | - |
| `exposed_to` | - |
| `found_vulnerability` | - |
| `has_credential_for` | - |
| `has_scan` | - |
| `interacted_with` | - |
| `located_in` | - |
| `managed_by` | - |
| `member_of` | - |
| `originated_from` | - |
| `owns` | - |
| `provisioned_as` | - |
| `refers` | - |
| `refutes` | - |
| `renews` | - |
| `reports_to` | - |
| `resolves_to` | - |
| `runs` | - |
| `subscribed_to` | - |
| `supersedes` | - |
| `supports` | - |
| `targets` | - |
| `triggered_by` | - |
| `works_at` | - |

## Source Domain Coverage

| Domain | Source Patterns | Node Kinds |
|---|---|---|
| `calendar` | `ensemble.tap.calendar.meeting.recorded` | `meeting`, `service` |
| `ci` | `ensemble.tap.ci.deploy.completed`, `ensemble.tap.ci.pipeline.completed` | `ci_workflow`, `deployment_run`, `pipeline_run`, `service`, `workload` |
| `docs` | `ensemble.tap.docs.page.edited` | `document`, `evidence` |
| `github` | `ensemble.tap.github.check_run.completed`, `ensemble.tap.github.pull_request.merged`, `ensemble.tap.github.pull_request.opened`, `ensemble.tap.github.pull_request.review_submitted` | `check_run`, `ci_workflow`, `pull_request`, `repository`, `service` |
| `incident` | `ensemble.tap.incident.timeline.*` | `action`, `evidence`, `incident`, `service` |
| `jira` | `ensemble.tap.jira.issue.transitioned` | `action`, `ticket` |
| `sales` | `ensemble.tap.sales.call.logged` | `action`, `company`, `contact`, `deal`, `lead`, `opportunity` |
| `slack` | `ensemble.tap.slack.thread.message_posted` | `action`, `communication_thread` |
| `support` | `ensemble.tap.support.ticket.updated` | `action`, `company`, `customer`, `subscription`, `ticket` |

## Unmapped Built-in Node Kinds

Total unmapped kinds: **45**

- `activity`
- `application`
- `bucket`
- `bucket_encryption_config`
- `bucket_logging_config`
- `bucket_policy_statement`
- `bucket_public_access_block`
- `bucket_versioning_config`
- `claim`
- `cluster_role`
- `cluster_role_binding`
- `configmap`
- `database`
- `decision`
- `department`
- `deployment`
- `folder`
- `function`
- `group`
- `identity_alias`
- `instance`
- `internet`
- `invoice`
- `location`
- `namespace`
- `network`
- `observation`
- `organization`
- `outcome`
- `package`
- `permission_boundary`
- `persistent_volume`
- `person`
- `pod`
- `project`
- `role`
- `role_binding`
- `scp`
- `secret`
- `service_account`
- `source`
- `technology`
- `user`
- `vulnerability`
- `workload_scan`
