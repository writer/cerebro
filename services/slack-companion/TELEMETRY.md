---
spec: ./TELEMETRY.spec.md
---

# Telemetry

## Goal

Use this map when a Slack answer, alert triage run, scheduled check, goal runner step, or runtime tool call failed or behaved unexpectedly.

The service emits structured JSON logs when `CEREBRO_TELEMETRY_ENABLED=true` and Prometheus-style metrics when `CEREBRO_METRICS_ENABLED=true`. Main spans use `event.dataset=cerebro_slack_companion.wide_events`; supporting spans and events use `event.dataset=cerebro_slack_companion.telemetry`.

## Where To Query

| Starting point | Query surface | Pivot | Answers | Next step |
| --- | --- | --- | --- | --- |
| Slack thread URL | Structured logs | `messaging.message.conversation_id` or `messaging.message.thread_ts` | Accepted, skipped, queued, answered, or failed | Run the conversation timeline recipe. |
| Slack timestamp | Structured logs | `messaging.message.id` | One message route | Check Slack event and work-loop spans. |
| Event name | Structured logs | `event.name` | Failure class and trace | Open matching `trace_id`. |
| Tool name | Structured logs | `tool.name` | Tool family, authority, target, and result | Check dependency and error fields. |
| Metrics alert | `/metrics` scrape | metric label set | Error cohort or volume change | Join to logs by operation name. |

## Investigation Pivots

| Pivot | Meaning | Found in | First query |
| --- | --- | --- | --- |
| `trace_id` | One request or worker execution trace | structured logs | `trace_id:"<trace_id>"` |
| `span_id` | One operation inside a trace | structured logs | `span_id:"<span_id>"` |
| `messaging.message.conversation_id` | Slack channel and thread identity | Slack event spans, assistant spans | `messaging.message.conversation_id:"<channel_id>:<thread_ts>"` |
| `messaging.message.id` | Slack message timestamp | Slack event spans | `messaging.message.id:"<ts>"` |
| `messaging.destination.name` | Slack channel id | Slack event spans | `messaging.destination.name:"<channel_id>"` |
| `tool.name` | Agent tool id | `assistant.tool.execute` spans | `tool.name:"<tool_name>"` |
| `operation.name` | Span operation | every span | `operation.name:"assistant.tool.execute"` |

## Query Recipes

Conversation timeline from a Slack thread:

```text
query='messaging.message.conversation_id:"<channel_id>:<thread_ts>"'
fields=timestamp,kind,name,trace_id,span_id,operation.name,operation.status,event.name,error_kind
sort=timestamp
```

Recent app mention failures:

```text
query='operation.name:"slack.event.app_mention" AND operation.status:"failed"'
fields=timestamp,trace_id,messaging.destination.name,messaging.message.id,error_kind
sort=-timestamp
```

Background assistant work failures:

```text
query='operation.name:"companion.work.slack_question" AND operation.status:"failed"'
fields=timestamp,trace_id,messaging.message.conversation_id,phase.last_name,dependency.last_system,error_kind
sort=-timestamp
```

Tool failure or blocked tool result:

```text
query='operation.name:"assistant.tool.execute" AND tool.name:"<tool_name>"'
fields=timestamp,trace_id,tool.name,tool.family,tool.authority,tool.target_source,operation.status,tool.result.error_present
sort=-timestamp
```

Code Mode termination or unknown write outcome:

```text
query='operation.name:"assistant.code.execute" AND assistant.code.outcome:("failed" OR "timed_out" OR "terminated" OR "outcome_unknown")'
fields=timestamp,trace_id,operation.status,assistant.code.outcome,assistant.code.termination_reason,assistant.code.child_exit_class,assistant.code.tool_call_count,assistant.code.side_effect_call_count
sort=-timestamp
```

Schedule runner failures:

```text
query='operation.name:"schedule.run" OR operation.name:"schedule.step.run"'
fields=timestamp,trace_id,operation.name,operation.status,phase.last_name,dependency.last_system,error_kind
sort=-timestamp
```

Metrics health check:

```text
GET /metrics
look for cerebro_slack_companion_operations_total{operation="<operation>",status="failed",...}
look for cerebro_slack_companion_assistant_eval_total{passed="false"}
look for cerebro_slack_companion_agent_run_tool_total{status="failed"}
look for cerebro_slack_companion_agent_run_completion_total{status!="complete"}
look for cerebro_slack_companion_assistant_feedback_total{vote="down"}
look for cerebro_slack_companion_assistant_feedback_context_total{included="true"}
look for cerebro_slack_companion_assistant_delivery_failures_total{partial="true"}
look for cerebro_slack_companion_autonomy_runner_blocked_total
look for cerebro_slack_companion_improvement_runs_total{status="queued"}
look for cerebro_slack_companion_improvement_jobs_total{outcome="completed"}
```

Runtime readiness check:

```text
GET /readyz
look for status=ready and ready=true
```

## Domains

### Slack Ingress

Slack event handling, dedupe, routing, and queue handoff.

Events: `slack.event.skipped`, `slack.event.app_mention.error`

Spans: `slack.event.app_mention`, `slack.event.message`

Attributes: `slack.event.claimed`, `slack.event.claim_reason`, `messaging.destination.name`, `messaging.message.id`, `messaging.message.thread_ts`

### Companion Work Loop

Background Slack question execution after an app mention is queued.

Spans: `companion.work.slack_question`, `assistant.pi.run`, `assistant.answer`

Events: `assistant.answer.delivered`, `assistant.answer.delivery_failed`

Attributes: `phase.last_name`, `phase.last_status`, `dependency.last_system`, `dependency.error.count`, `assistant.sender_kind`, `assistant.traffic_kind`, `assistant.delivery.planned_count`, `assistant.delivery.posted_count`, `assistant.delivery.complete`, `assistant.answer.execution_lane`, `assistant.answer.goal_captured`, `assistant.answer.commitment_count`, `assistant.answer.open_loop_count`, `assistant.answer.user_decision_required`, `assistant.goal.linked_count`, `assistant.goal.unbacked_count`, `assistant.goal.missing_count`, `assistant.goal.scope_mismatch_count`, `assistant.tool_pack.selected_count`, `assistant.research.claim_coverage`, `assistant.eval.score`, `assistant.eval.goal_understanding`, `assistant.eval.teammate_ownership`, `assistant.eval.burden_reduction`, `assistant.eval.communication_quality`, `assistant.eval.blocker_count`

Metrics: `cerebro_slack_companion_work_enqueued_total{kind,traffic}`, `cerebro_slack_companion_assistant_delivery_failures_total{traffic,partial}`

Use `assistant.traffic_kind=human_request` for product-quality and latency analysis. `machine_handoff` covers bot-authored digests and handoffs that still enter the Pi loop and may be suppressed there.

### Code Mode

One bounded JavaScript composition executed in a fresh child process. Nested tool calls keep their ordinary `assistant.tool.execute` spans; the outer executor span does not replace or duplicate those tool spans.

Events: `assistant.code.blocked`, `assistant.code.terminated`, `assistant.code.outcome_unknown`

Spans: `assistant.code.execute`

Attributes: `assistant.execution_style`, `assistant.code.outcome`, `assistant.code.termination_reason`, `assistant.code.child_exit_class`, `assistant.code.tool_call_count`, `assistant.code.side_effect_call_count`, `assistant.code.duration_ms`, `assistant.code.limit_class`, `assistant.code.output_truncated`

Allowed values are bounded. `assistant.code.outcome` is `completed`, `failed`, `blocked`, `timed_out`, `terminated`, or `outcome_unknown`. Termination and limit classes are fixed enums such as `deadline`, `policy`, `protocol`, `tool_limit`, `side_effect_limit`, `output_limit`, `memory_limit`, `guest_error`, and `child_exit`; they are not exception text.

Do not emit the program or its hash, tool arguments, tool results, IPC messages, child stdout or stderr, catalog contents, toolset digest, target identifiers, Slack text, evidence receipts, credentials, or exception messages. Use `trace_id` to join the outer execution to normal nested tool spans. Tool names appear only on those ordinary tool spans.

### Response Feedback

Structured ratings for delivered human-facing assistant answers.

Events: `assistant.feedback.recorded`, `assistant.feedback.context_built`, `assistant.feedback.index_backfill_completed`

Attributes: `assistant.feedback.vote`, `assistant.feedback.reason`, `assistant.feedback.changed`, `assistant.feedback.had_evidence`, `assistant.feedback.had_actions`, `assistant.feedback.had_goal`, `assistant.feedback.delivery_complete`, `assistant.feedback.model_version`, `assistant.feedback.preference_evidence_count`, `assistant.feedback.has_task_correction`, `assistant.answer.execution_lane`, `assistant.feedback.context.included`, `assistant.feedback.context.direct_count`, `assistant.feedback.context.topic_matched_count`, `assistant.feedback.context.team_guidance_count`, `assistant.feedback.context.rating_count`, `assistant.feedback.context.preference_count`, `assistant.feedback.context.correction_count`, `assistant.feedback.context.outcome_count`, `assistant.feedback.context.team_preference_count`, `assistant.feedback.context.user_read_mode`, `assistant.feedback.context.team_read_mode`, `assistant.feedback.context.oldest_selected_age`, `assistant.feedback.context.duration_ms`, `assistant.feedback.index.migrated_signal_count`, `assistant.feedback.index.migrated_user_record_count`, `assistant.feedback.index.skipped_signal_count`

Metrics: `cerebro_slack_companion_assistant_feedback_total{vote,reason}`, `cerebro_slack_companion_assistant_feedback_context_total{included,user_read_mode,team_read_mode}`, `cerebro_slack_companion_assistant_feedback_context_duration_seconds_sum`, `cerebro_slack_companion_assistant_feedback_context_duration_seconds_count`

Allowed dimensions are fixed enums and bounded states: vote, reason, model version, projection presence, inclusion, user/team read mode, counts, age bucket, and duration. Do not add preference keys, Slack user ids, display names, channel ids, questions, answers, or comments to feedback telemetry.

### Agent Tools

Tool execution, target ownership, authority, and failure state.

Events: `assistant.tool.error`

Spans: `assistant.tool.execute`

Attributes: `tool.name`, `tool.family`, `tool.authority`, `tool.target_source`, `tool.credential_scope`, `tool.side_effect`, `tool.retry`, `tool.result.error_present`

### Risk Subject Checks

Bounded person confirmation for one security risk.

Events: `slack.risk_attestation.sent`, `slack.risk_attestation.answered`, `slack.risk_attestation.delivery_failed`, `slack.risk_attestation.dm_refresh_failed`, `slack.risk_attestation.origin_notification_failed`

Attributes: `risk_attestation.request_id_hash`, `risk_attestation.status`, `risk_attestation.evidence_ref_count`, `risk_attestation.origin_notified`

Metrics: `cerebro_slack_companion_risk_attestations_total{event,status}`

Do not add Slack user ids, display names, channel ids, activity summaries, risk references, identity evidence, or evidence references to telemetry.

### Recursive Improvement

Durable human-feedback repair runs and the isolated candidate worker.

Events: `improvement.run.queued`, `improvement.control_plane.blocked`, `improvement.run.conflict`, `improvement.worker.started`, `improvement.worker.job_completed`, `improvement.worker.poll_failed`

Attributes: `improvement.run_id_hash`, `improvement.issue_kind`, `improvement.skill_id`, `improvement.signal_count`, `improvement.table_configured`, `improvement.bucket_configured`, `improvement.queue_configured`

Metrics: `cerebro_slack_companion_improvement_runs_total{status,source}`, `cerebro_slack_companion_improvement_jobs_total{kind,outcome}`

Query `event.name:"improvement.worker.poll_failed"` for queue or dependency failures. Inspect the DynamoDB run and immutable event rows by the operator-held run id. Do not add Slack text, answer text, comments, S3 object bodies, or signatures to telemetry.

### Schedules And Goals

Durable scheduled jobs and autonomy runner steps.

Events: `schedule.job.blocked`, `autonomy.runner.retry_scheduled`, `autonomy.runner.blocked`

Spans: `schedule.tick`, `schedule.run`, `schedule.step.run`, `autonomy.runner.tick`

Attributes: `phase.last_name`, `operation.status`, `dependency.last_system`, `error_kind`, `autonomy.failure.equivalent_count`, `autonomy.retry.delay_ms`, `autonomy.retry_at`

Metrics: `cerebro_slack_companion_agent_run_tool_total{tool,phase,status}`, `cerebro_slack_companion_agent_run_completion_total{status,verifier}`, `cerebro_slack_companion_autonomy_runner_failures_total{capability}`, `cerebro_slack_companion_autonomy_runner_blocked_total{capability}`

Two equivalent failures are rescheduled with exponential delay. The third moves the goal to `blocked`, clears its next wake, and emits one `autonomy.runner.blocked` event. Resume the goal only after the recorded cause is fixed.

Use `phase=execute` versus `phase=verify` to separate a failed action from a failed independent check. A `status=partial` completion means at least one acceptance criterion failed or remained pending.

### A2A Fleet

Concurrent Cerebro discovery, peer messages, and shutdown handoff.

Events: `companion.a2a.started`, `companion.a2a.message_sent`, `companion.a2a.message_acknowledged`, `companion.a2a.shutdown_handoff`, `companion.a2a.error`

Attributes: `a2a.instance_id`, `a2a.label`, `a2a.role`, `a2a.commit`, `a2a.message.kind`, `a2a.sender`, `a2a.recipient`, `a2a.handoff.state`, `a2a.handoff.peer`, `a2a.handoff.goal_count`

Query `event.name:"companion.a2a.shutdown_handoff" AND a2a.handoff.state:"timed_out"` for shutdowns that did not receive a peer acknowledgement. Instance labels, roles, commits, opaque instance ids, message kinds, and goal counts are allowed. Do not add A2A part bodies, goal objectives, Slack text, credentials, or source evidence to telemetry.

Query `event.name:"assistant.ensemble.completed"` to compare requested peers, completed peer reviews, arbitration use, and total ensemble duration. Query `event.name:"assistant.ensemble.error" OR event.name:"assistant.ensemble.peer_error" OR event.name:"assistant.ensemble.local_peer_error" OR event.name:"assistant.ensemble.chair_error"` for fail-open stages. Ensemble telemetry may include counts, duration, stable instance ids, and error kinds. It must not include questions, candidate answers, peer reviews, evidence, credentials, or source payloads.

Metrics: `cerebro_slack_companion_schedule_due_count`, `cerebro_slack_companion_schedule_oldest_due_age_seconds`, `cerebro_slack_companion_schedule_jobs`, `cerebro_slack_companion_autonomy_due_count`, `cerebro_slack_companion_autonomy_oldest_due_age_seconds`, `cerebro_slack_companion_autonomy_goals`, `cerebro_slack_companion_autonomy_stale_claims`

### External Dependencies

Cerebro, Slack, EvidenceCAS, Infisical, GitHub, Bedrock, DynamoDB, and ECS calls.

Spans: `cerebro.http.request`, `assistant.tool.execute`

Attributes: `dependency.last_system`, `dependency.last_operation`, `dependency.last_status`, `dependency.error.count`

### Runtime Lifecycle

Companion startup and shutdown timing.

Events: `companion.starting`, `companion.started`, `companion.shutdown_requested`, `companion.shutdown_completed`

Attributes: `startup.duration_ms`, `shutdown.duration_ms`, `shutdown.notice_duration_ms`, `shutdown.app_stop_duration_ms`, `shutdown.app_stop_status`, `shutdown.a2a_handoff_status`, `shutdown.a2a_handoff_goal_count`

### Runtime Readiness

Liveness, readiness, config audit, deploy fence state, and backlog gauges.

Routes: `/healthz`, `/readyz`, `/metrics`

Operator command: `/cerebro operator health`

Metrics: `cerebro_slack_companion_runtime_ready`, `cerebro_slack_companion_runtime_status`, `cerebro_slack_companion_runtime_check_status`

## Alerts

Use these as starting points for sec-dev monitors. Tune windows after one week of observed volume.

| Alert | Signal | Page | First action |
| --- | --- | --- | --- |
| Runtime not ready | `cerebro_slack_companion_runtime_ready == 0` for 5 minutes or `/readyz` returns non-200 | Yes | Run `/cerebro operator health`; check failing `check.*` lines. |
| Slack work backlog | `cerebro_slack_companion_work_oldest_queue_age_seconds > 300` | Yes during business hours | Check `companion.work.slack_question` failures and Slack API status. |
| Scheduled checks stuck | `cerebro_slack_companion_schedule_oldest_due_age_seconds > 600` or blocked jobs > 0 | Ticket, page if security monitor | Run `/cerebro schedules`; inspect `schedule.run` and blocked job notes. |
| Autonomy goals stuck | `cerebro_slack_companion_autonomy_oldest_due_age_seconds > 600` or stale claims > 0 | Ticket, page if incident goal | Run `/cerebro goals active`; inspect `autonomy.runner.retry_scheduled`. |
| Runner failure budget exhausted | `autonomy.runner.failure_budget_exhausted` event | Ticket | Open the goal, fix dependency or stored state, then resume. |
| Schedule failure budget exhausted | `schedule.job.blocked` event | Ticket | Open the scheduled check, fix prompt/dependency, then resume. |
| Cerebro dependency failures | `operation.name:"cerebro.http.request" AND operation.status:"failed"` burn over 10 minutes | Yes if widespread | Check Cerebro API status and route-level failure class. |
| Claim store unavailable | `slack.event.claim_reason:"claim_store_unavailable"` | Yes | Check DynamoDB table access and coordination config. |
| Stale deployment claiming events | `slack.event.claim_reason:"stale_deployment"` outside active deploy | Ticket | Check ECS service primary task definition and deploy fence cache. |

## Runbooks

Runtime not ready:

1. Run `/cerebro operator health`.
2. If `config.*` failed, fix the runtime secret, Pulumi config, or table setting and redeploy.
3. If `deployment.fence` failed, check ECS primary task definition and running task count.
4. If backlog is growing, inspect the matching domain spans before restarting tasks.

Scheduled check blocked:

1. Run `/cerebro schedules`.
2. Find jobs with `blocked` status and read the last run summary.
3. Fix the dependency, prompt, or channel target.
4. Run `/cerebro schedule resume <schedule-id>`.

Autonomy goal blocked by runner failures:

1. Run `/cerebro goals blocked`.
2. Open the goal card and read the latest blocker.
3. Check `autonomy.runner.retry_scheduled` and `autonomy.runner.failure_budget_exhausted` events by goal id.
4. Fix the dependency or stored goal state, then resume the goal.

## Configuration

| Setting | Controls | Default |
| --- | --- | --- |
| `CEREBRO_TELEMETRY_ENABLED` | Structured JSON logs and spans | `true` |
| `CEREBRO_METRICS_ENABLED` | Prometheus metrics registry | `true` |
| `CEREBRO_TELEMETRY_SERVICE_NAME` | Service name in telemetry resource attributes | `cerebro-slack-companion` |
| `CEREBRO_DEPLOYMENT_ENVIRONMENT` | Deployment environment label | `NODE_ENV` |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes | unset |

Sensitive fields are redacted by telemetry sanitization. Do not add raw Slack text, prompts, generated code, code hashes, tool arguments, tool results, IPC payloads, child output, target identifiers, toolset digests, evidence receipts, exception messages, secrets, tokens, cookies, or credentials to telemetry attributes.
