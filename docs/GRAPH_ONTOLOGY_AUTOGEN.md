# Graph Ontology Auto-Generated Catalog

Generated from `graph.RegisteredNodeKinds()`, `graph.RegisteredEdgeKinds()`, and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_graph_ontology_docs/main.go`.

- Node kinds: **52**
- Edge kinds: **31**
- Mapping rules: **13**
- Source domains: **9**

## Node Kinds

| Kind | Categories | Required Properties | Relationships |
|---|---|---|---|
| `action` | business | `action_type`, `observed_at`, `status`, `valid_from` | `based_on`, `evaluates`, `interacted_with`, `targets` |
| `activity` | business | - | - |
| `any` | - | - | - |
| `application` | resource | - | - |
| `bucket` | resource | - | - |
| `check_run` | business | `check_name`, `check_run_id`, `observed_at`, `repository`, `status`, `valid_from` | `based_on`, `evaluates`, `targets` |
| `ci_workflow` | - | - | - |
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
| `deployment_run` | business, resource | `deploy_id`, `environment`, `observed_at`, `service_id`, `status`, `valid_from` | `based_on`, `depends_on`, `targets` |
| `document` | business | `document_id`, `observed_at`, `title`, `valid_from` | `based_on`, `targets` |
| `evidence` | business | `evidence_type`, `observed_at`, `source_system`, `valid_from` | `based_on`, `targets` |
| `function` | resource | - | - |
| `group` | identity | - | - |
| `identity_alias` | identity | `external_id`, `observed_at`, `source_system`, `valid_from` | `alias_of` |
| `incident` | business | `incident_id`, `observed_at`, `status`, `valid_from` | `based_on`, `evaluates`, `targets` |
| `instance` | resource | - | - |
| `internet` | - | - | - |
| `invoice` | business | - | - |
| `lead` | business | - | - |
| `location` | business | - | - |
| `meeting` | business | `ends_at`, `meeting_id`, `observed_at`, `starts_at`, `valid_from` | `assigned_to`, `based_on`, `targets` |
| `namespace` | kubernetes | - | - |
| `network` | resource | - | - |
| `opportunity` | business | - | - |
| `outcome` | business | `observed_at`, `outcome_type`, `valid_from`, `verdict` | `evaluates`, `targets` |
| `permission_boundary` | - | - | - |
| `persistent_volume` | kubernetes, resource | - | - |
| `person` | identity | - | - |
| `pipeline_run` | business, resource | `observed_at`, `pipeline_id`, `run_id`, `service_id`, `status`, `valid_from` | `based_on`, `executed_by`, `targets` |
| `pod` | kubernetes, resource | - | - |
| `pull_request` | business | `number`, `observed_at`, `repository`, `state`, `valid_from` | `based_on`, `targets` |
| `repository` | - | - | - |
| `role` | identity | - | - |
| `scp` | - | - | - |
| `secret` | resource | - | - |
| `service` | business, resource | `observed_at`, `service_id`, `valid_from` | `depends_on`, `owns`, `runs`, `targets` |
| `service_account` | identity | - | - |
| `subscription` | business | - | - |
| `ticket` | business | - | - |
| `user` | identity | - | - |
| `workload` | resource | `observed_at`, `runtime`, `valid_from`, `workload_id` | `connects_to`, `depends_on`, `targets` |

## Node Metadata Profiles

| Kind | Required Metadata | Optional Metadata | Timestamp Keys | Enum Constraints |
|---|---|---|---|---|
| `action` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `check_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `conclusion`=`action_required`, `cancelled`, `failure`, `neutral`, `skipped`, `stale`, `startup_failure`, `success`, `timed_out`<br>`status`=`completed`, `in_progress`, `queued` |
| `communication_thread` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `decision` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `status`=`approved`, `cancelled`, `completed`, `deferred`, `in_progress`, `proposed`, `rejected` |
| `deployment_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `environment`=`dev`, `prod`, `production`, `qa`, `sandbox`, `staging`, `test`<br>`status`=`cancelled`, `completed`, `error`, `failed`, `failure`, `in_progress`, `pending`, `queued`, `running`, `succeeded`, `success`, `successful` |
| `document` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `evidence` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `group` | - | `confidence`, `observed_at`, `source_event_id`, `source_system`, `valid_from`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `identity_alias` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `alias_type`=`email`, `employee_id`, `github`, `slack`, `uid`, `upn`, `username` |
| `incident` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `severity`=`critical`, `high`, `low`, `medium`, `sev1`, `sev2`, `sev3`, `sev4`<br>`status`=`acknowledged`, `closed`, `investigating`, `monitoring`, `open`, `postmortem`, `resolved`, `triggered` |
| `meeting` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `outcome` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `verdict`=`mixed`, `negative`, `neutral`, `positive`, `unknown` |
| `person` | - | `confidence`, `observed_at`, `source_event_id`, `source_system`, `valid_from`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `pipeline_run` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `status`=`action_required`, `cancelled`, `completed`, `failed`, `failure`, `in_progress`, `neutral`, `passed`, `pending`, `queued`, `running`, `skipped`, `succeeded`, `success`, `successful`, `timed_out` |
| `pull_request` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `state`=`closed`, `draft`, `merged`, `open`, `opened`, `review_submitted` |
| `role` | - | `confidence`, `observed_at`, `source_event_id`, `source_system`, `valid_from`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `service` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `criticality`=`critical`, `high`, `low`, `medium`, `tier0`, `tier1`, `tier2`, `tier3` |
| `service_account` | - | `confidence`, `observed_at`, `source_event_id`, `source_system`, `valid_from`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `user` | - | `confidence`, `observed_at`, `source_event_id`, `source_system`, `valid_from`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | - |
| `workload` | `observed_at`, `source_system`, `valid_from` | `confidence`, `source_event_id`, `valid_to` | `observed_at`, `valid_from`, `valid_to` | `environment`=`dev`, `prod`, `production`, `qa`, `sandbox`, `staging`, `test` |

## Edge Kinds

| Kind | Description |
|---|---|
| `alias_of` | - |
| `assigned_to` | - |
| `based_on` | - |
| `billed_by` | - |
| `can_admin` | - |
| `can_assume` | - |
| `can_delete` | - |
| `can_read` | - |
| `can_write` | - |
| `connects_to` | - |
| `depends_on` | - |
| `deployed_from` | - |
| `escalated_to` | - |
| `evaluates` | - |
| `executed_by` | - |
| `exposed_to` | - |
| `interacted_with` | - |
| `located_in` | - |
| `managed_by` | - |
| `member_of` | - |
| `originated_from` | - |
| `owns` | - |
| `provisioned_as` | - |
| `refers` | - |
| `renews` | - |
| `reports_to` | - |
| `resolves_to` | - |
| `runs` | - |
| `subscribed_to` | - |
| `targets` | - |
| `works_at` | - |

## Source Domain Coverage

| Domain | Source Patterns | Node Kinds |
|---|---|---|
| `calendar` | `ensemble.tap.calendar.meeting.recorded` | `meeting`, `service` |
| `ci` | `ensemble.tap.ci.deploy.completed`, `ensemble.tap.ci.pipeline.completed` | `deployment_run`, `pipeline_run`, `service`, `workload` |
| `docs` | `ensemble.tap.docs.page.edited` | `document`, `evidence` |
| `github` | `ensemble.tap.github.check_run.completed`, `ensemble.tap.github.pull_request.merged`, `ensemble.tap.github.pull_request.opened`, `ensemble.tap.github.pull_request.review_submitted` | `check_run`, `pull_request`, `service` |
| `incident` | `ensemble.tap.incident.timeline.*` | `action`, `evidence`, `incident`, `service` |
| `jira` | `ensemble.tap.jira.issue.transitioned` | `action`, `ticket` |
| `sales` | `ensemble.tap.sales.call.logged` | `action`, `contact` |
| `slack` | `ensemble.tap.slack.thread.message_posted` | `action`, `communication_thread` |
| `support` | `ensemble.tap.support.ticket.updated` | `action`, `ticket` |

## Unmapped Built-in Node Kinds

Total unmapped kinds: **37**

- `activity`
- `application`
- `bucket`
- `ci_workflow`
- `cluster_role`
- `cluster_role_binding`
- `company`
- `configmap`
- `customer`
- `database`
- `deal`
- `decision`
- `department`
- `deployment`
- `function`
- `group`
- `identity_alias`
- `instance`
- `internet`
- `invoice`
- `lead`
- `location`
- `namespace`
- `network`
- `opportunity`
- `outcome`
- `permission_boundary`
- `persistent_volume`
- `person`
- `pod`
- `repository`
- `role`
- `scp`
- `secret`
- `service_account`
- `subscription`
- `user`
