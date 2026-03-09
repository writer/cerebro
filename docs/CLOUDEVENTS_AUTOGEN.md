# CloudEvents Auto-Generated Contract Catalog

Generated from `internal/events.CloudEvent` and `internal/graphingest/mappings.yaml` via `go run ./scripts/generate_cloudevents_docs/main.go`.

- Contract catalog API version: **cerebro.graph.contracts/v1alpha1**
- Contract catalog kind: **CloudEventMappingContractCatalog**
- CloudEvent envelope fields: **12**
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
