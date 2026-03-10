# CloudEvents Auto-Generated Contract Catalog

Generated from `internal/events.CloudEvent` and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_cloudevents_docs/main.go`.

- Contract catalog API version: **cerebro.graph.contracts/v1alpha1**
- Contract catalog kind: **CloudEventMappingContractCatalog**
- CloudEvent envelope fields: **12**
- Platform lifecycle event contracts: **10**
- TAP mapping rules: **13**
- Wildcard event patterns: **1**
- Distinct required data keys across mappings: **29**
- Distinct optional data keys across mappings: **36**

## CloudEvent Envelope

| Field | Type | Required |
|---|---|---|
| `datacontenttype` | `string` | yes |
| `dataschema` | `string` | yes |
| `id` | `string` | yes |
| `schema_version` | `string` | yes |
| `source` | `string` | yes |
| `specversion` | `string` | yes |
| `tenant_id` | `string` | yes |
| `time` | `time.Time` | yes |
| `traceparent` | `string` | yes |
| `type` | `string` | yes |
| `data` | `map[string]interface {}` | no |
| `subject` | `string` | no |

## Platform Lifecycle Event Contracts

| Event Type | Summary | Schema URL | Required Data Keys | Optional Data Keys |
|---|---|---|---|---|
| `platform.action.recorded` | Action write recorded on the shared platform workflow layer. | `urn:cerebro:events/platform.action.recorded/v1` | `action_id`, `title`, `target_ids`, `source_system`, `source_event_id`, `observed_at`, `valid_from`, `auto_generated` | `decision_id`, `recommendation_id`, `insight_type`, `summary`, `status`, `tenant_id`, `traceparent` |
| `platform.claim.written` | Claim write recorded on the shared platform knowledge layer. | `urn:cerebro:events/platform.claim.written/v1` | `claim_id`, `subject_id`, `predicate`, `claim_type`, `status`, `source_system`, `source_event_id`, `observed_at`, `recorded_at`, `transaction_from` | `source_id`, `object_id`, `object_value`, `evidence_ids`, `supporting_claim_ids`, `refuting_claim_ids`, `tenant_id`, `traceparent` |
| `platform.decision.recorded` | Decision write recorded on the shared platform workflow layer. | `urn:cerebro:events/platform.decision.recorded/v1` | `decision_id`, `decision_type`, `status`, `target_ids`, `source_system`, `source_event_id`, `observed_at`, `valid_from` | `made_by`, `rationale`, `evidence_ids`, `action_ids`, `tenant_id`, `traceparent` |
| `platform.outcome.recorded` | Outcome write recorded on the shared platform workflow layer. | `urn:cerebro:events/platform.outcome.recorded/v1` | `outcome_id`, `decision_id`, `outcome_type`, `verdict`, `impact_score`, `source_system`, `source_event_id`, `observed_at`, `valid_from` | `target_ids`, `tenant_id`, `traceparent` |
| `platform.report_run.canceled` | Report execution canceled on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_run.canceled/v1` | `run_id`, `report_id`, `status`, `execution_mode`, `submitted_at`, `completed_at`, `status_url`, `cancel_reason` | `started_at`, `requested_by`, `cache_key`, `job_id`, `job_status_url`, `parameter_count`, `materialized_result`, `latest_attempt_id`, `attempt_count`, `event_count`, `trigger_surface`, `execution_surface`, `execution_host`, `attempt_classification`, `retry_of_attempt_id`, `retry_reason`, `retry_backoff_ms`, `scheduled_for`, `retry_max_attempts`, `retry_base_backoff_ms`, `retry_max_backoff_ms`, `storage_class`, `retention_tier`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `error`, `tenant_id`, `traceparent` |
| `platform.report_run.completed` | Report execution completed on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_run.completed/v1` | `run_id`, `report_id`, `status`, `execution_mode`, `submitted_at`, `completed_at`, `status_url`, `materialized_result` | `started_at`, `requested_by`, `cache_key`, `job_id`, `job_status_url`, `parameter_count`, `latest_attempt_id`, `attempt_count`, `event_count`, `trigger_surface`, `execution_surface`, `execution_host`, `attempt_classification`, `retry_of_attempt_id`, `retry_reason`, `retry_backoff_ms`, `scheduled_for`, `retry_max_attempts`, `retry_base_backoff_ms`, `retry_max_backoff_ms`, `storage_class`, `retention_tier`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `snapshot_id`, `result_schema`, `section_count`, `tenant_id`, `traceparent` |
| `platform.report_run.failed` | Report execution failed on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_run.failed/v1` | `run_id`, `report_id`, `status`, `execution_mode`, `submitted_at`, `completed_at`, `status_url`, `error` | `started_at`, `requested_by`, `cache_key`, `job_id`, `job_status_url`, `parameter_count`, `materialized_result`, `latest_attempt_id`, `attempt_count`, `event_count`, `trigger_surface`, `execution_surface`, `execution_host`, `attempt_classification`, `retry_of_attempt_id`, `retry_reason`, `retry_backoff_ms`, `scheduled_for`, `retry_max_attempts`, `retry_base_backoff_ms`, `retry_max_backoff_ms`, `storage_class`, `retention_tier`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `tenant_id`, `traceparent` |
| `platform.report_run.queued` | Report execution queued on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_run.queued/v1` | `run_id`, `report_id`, `status`, `execution_mode`, `submitted_at`, `status_url` | `requested_by`, `cache_key`, `job_id`, `job_status_url`, `parameter_count`, `materialized_result`, `latest_attempt_id`, `attempt_count`, `event_count`, `trigger_surface`, `execution_surface`, `execution_host`, `attempt_classification`, `retry_of_attempt_id`, `retry_reason`, `retry_backoff_ms`, `scheduled_for`, `retry_max_attempts`, `retry_base_backoff_ms`, `retry_max_backoff_ms`, `storage_class`, `retention_tier`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `tenant_id`, `traceparent` |
| `platform.report_run.started` | Report execution started on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_run.started/v1` | `run_id`, `report_id`, `status`, `execution_mode`, `submitted_at`, `started_at`, `status_url` | `requested_by`, `cache_key`, `job_id`, `job_status_url`, `parameter_count`, `materialized_result`, `latest_attempt_id`, `attempt_count`, `event_count`, `trigger_surface`, `execution_surface`, `execution_host`, `attempt_classification`, `retry_of_attempt_id`, `retry_reason`, `retry_backoff_ms`, `scheduled_for`, `retry_max_attempts`, `retry_base_backoff_ms`, `retry_max_backoff_ms`, `storage_class`, `retention_tier`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `tenant_id`, `traceparent` |
| `platform.report_snapshot.materialized` | Report snapshot materialized on the shared platform intelligence layer. | `urn:cerebro:events/platform.report_snapshot.materialized/v1` | `snapshot_id`, `run_id`, `report_id`, `result_schema`, `generated_at`, `recorded_at`, `content_hash`, `byte_size`, `section_count`, `retained`, `status_url` | `expires_at`, `cache_key`, `storage_class`, `retention_tier`, `materialized_result`, `result_truncated`, `graph_snapshot_id`, `graph_built_at`, `graph_schema_version`, `ontology_contract_version`, `report_definition_version`, `tenant_id`, `traceparent` |

## Mapping Contracts

| Mapping | Source Pattern | Domain | Wildcard | apiVersion | contractVersion | schemaURL | Node Kinds | Edge Kinds | Required Data Keys | Optional Data Keys | Resolve Keys |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `calendar_meeting_recorded` | `ensemble.tap.calendar.meeting.recorded` | `calendar` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `meeting`, `service` | `assigned_to`, `targets` | `meeting_id`, `organizer_email`, `service` | `ends_at`, `starts_at`, `title` | `organizer_email` |
| `ci_deploy_completed` | `ensemble.tap.ci.deploy.completed` | `ci` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `deployment_run`, `service`, `workload` | `based_on`, `interacted_with`, `runs`, `targets` | `actor_email`, `deploy_id`, `service` | `environment`, `release_version`, `status` | `actor_email` |
| `ci_pipeline_completed` | `ensemble.tap.ci.pipeline.completed` | `ci` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `pipeline_run`, `service` | `interacted_with`, `targets` | `actor_email`, `pipeline_id`, `run_id`, `service` | `branch`, `commit_sha`, `completed_at`, `pipeline_name`, `started_at`, `status` | `actor_email` |
| `docs_page_edited` | `ensemble.tap.docs.page.edited` | `docs` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `document`, `evidence` | `based_on`, `interacted_with` | `doc_id`, `editor_email`, `version` | `change_summary`, `title`, `url` | `editor_email` |
| `github_check_run_completed` | `ensemble.tap.github.check_run.completed` | `github` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `check_run`, `service` | `interacted_with`, `targets` | `actor_email`, `check_run_id`, `repository` | `check_name`, `commit_sha`, `conclusion`, `status`, `url` | `actor_email` |
| `github_pr_merged` | `ensemble.tap.github.pull_request.merged` | `github` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `pull_request`, `service` | `interacted_with`, `targets` | `merged_by_email`, `number`, `repository` | `merged_by`, `title` | `merged_by_email` |
| `github_pr_opened` | `ensemble.tap.github.pull_request.opened` | `github` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `pull_request`, `service` | `interacted_with`, `targets` | `author_email`, `number`, `repository` | `author`, `title` | `author_email` |
| `github_pr_review_submitted` | `ensemble.tap.github.pull_request.review_submitted` | `github` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `pull_request`, `service` | `interacted_with`, `targets` | `number`, `repository`, `reviewer_email` | `state` | `reviewer_email` |
| `incident_timeline_event` | `ensemble.tap.incident.timeline.*` | `incident` | yes | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `action`, `evidence`, `incident`, `service` | `based_on`, `targets` | `event_id`, `incident_id`, `service` | `actor_email`, `event_type`, `performed_at`, `severity`, `status`, `summary`, `title` | `actor_email` |
| `jira_issue_transition` | `ensemble.tap.jira.issue.transitioned` | `jira` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `action`, `ticket` | `assigned_to`, `targets` | `actor_email`, `issue_key`, `transition_id` | `from_status`, `issue_type`, `performed_at`, `project_key`, `summary`, `to_status` | `actor_email` |
| `sales_call_logged` | `ensemble.tap.sales.call.logged` | `sales` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `action`, `contact` | `interacted_with`, `targets` | `call_id`, `contact_id`, `rep_email` | `contact_email`, `contact_name`, `duration_minutes`, `logged_at`, `summary` | `rep_email` |
| `slack_thread_message` | `ensemble.tap.slack.thread.message_posted` | `slack` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `action`, `communication_thread` | `interacted_with`, `targets` | `author_email`, `channel_id`, `message_ts`, `thread_ts` | `channel_name`, `text` | `author_email` |
| `support_ticket_updated` | `ensemble.tap.support.ticket.updated` | `support` | no | `cerebro.graphingest/v1alpha1` | `1.0.0` | - | `action`, `ticket` | `assigned_to`, `targets` | `agent_email`, `ticket_id`, `update_id` | `priority`, `status`, `subject`, `update_type`, `updated_at` | `agent_email` |

## Shared Context Keys Used by Templates

No non-data context keys are referenced by mapper templates.

## Notes

- `Required Data Keys` are data paths used in structural template locations (node id/kind, edge source/target/kind).
- `Optional Data Keys` are data paths used in non-structural locations (names/properties/providers/effects).
- `Resolve Keys` are keys used in `{{resolve(...)}}` expressions for identity canonicalization.
- `docs/CLOUDEVENTS_CONTRACTS.json` is the machine-readable contract + data-schema artifact for automation and API surfaces.
- Additions or changes to `internal/graphingest/mappings.yaml` should be accompanied by regenerated contract artifacts.
