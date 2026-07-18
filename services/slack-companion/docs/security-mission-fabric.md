# Security Mission Fabric

## Runtime contract

Cerebro uses two execution paths:

- A Slack question stays in the Pi assistant loop and returns an answer from current thread and source context.
- Work that must resume, wait for a source, or cross an approval boundary becomes a durable agent run.

Mission compilation does not route or answer Slack questions. Pi calls `operator_mission_compile`, or an operator uses an explicit goal command, after durable execution is selected. The compiler returns a versioned plan. `operator_goal_create` stores the pack id, pack version, compiler version, objective digest, plan digest, resolved inputs, missing inputs, owner, service level, required evidence, action steps, plan, and acceptance checks.

The runner advances one ready step per lease. A step can be in one of four binding states:

- `bound`: an exact registered tool and validated arguments are present.
- `missing_input`: a required finding, identity, alert, rule, repository, runtime, pull request, or evidence reference is absent.
- `needs_tool`: the pack identifies the required family and authority, but no exact tool has been bound.
- `operator_decision`: the next state depends on an evidence-backed decision or reviewed approval.

The runner does not mark an unbound mission step complete. It records the missing input, tool, decision, or approval and waits. `operator_agent_run_step_bind` resumes a tool step after checking the registered tool name, family, authority, argument schema, acceptance checks, approval requirement, idempotency key, rollback, and independent verification. `operator_agent_run_step_decide` records a non-action decision with reopenable evidence. Slack approval actions remain the path for reviewed mission approvals.

## Mission runtime storage

Mission snapshots use one DynamoDB partition per mission. Sharded due, recent, status, and sparse work indexes keep recovery and operator reads bounded as mission volume grows. Every snapshot transition uses an optimistic revision and writes an immutable ledger event in the same transaction. A transition that leaves runnable work also writes a versioned outbox item in that transaction. The snapshot retains the latest 100 work-log entries; the ledger retains the complete transition history.

The outbox publisher claims due records with a short publication lease, sends a bounded envelope to the FIFO mission queue, and records the SQS message id. Queue groups preserve order per mission while allowing unrelated missions to run concurrently. A consumer must claim the exact snapshot revision named in the envelope before executing one step. It records the outcome on the outbox item before acknowledging the message. A stale revision is acknowledged without execution; a transient failure remains visible for retry and dead-letter redrive. Periodic due-index reconciliation recreates a missing outbox item after migration or an interrupted deployment.

The deployment reads legacy goals from the learning table during migration. The first successful transition promotes a legacy goal into the mission table. New missions are written only to the mission table. Remove `CEREBRO_AUTONOMY_GOALS_LEGACY_TABLE_NAME` after active legacy goals have been completed or promoted.

## Pack contract

Each pack defines:

- a stable id and version;
- supported objectives and event triggers;
- required and optional inputs;
- required evidence;
- allowed actions;
- owner, escalation path, and service level;
- dependency-ordered steps;
- tool selectors by exact name, prefix, family, and authority;
- action stage for every step;
- acceptance checks;
- per-action approval, verification, idempotency, and rollback requirements.

Pack steps use the host tool catalog and dispatcher. A pack grants no credential and cannot override a tool's authority, target boundary, or runtime policy.

## Initial packs

| Pack | Durable path | Write boundary | Completion state |
| --- | --- | --- | --- |
| `appsec.remediation` | Finding evidence → owner → bounded patch and pull request → exact-head checks → merge monitor → fresh source evaluation → finding read | Pull request creation stays reviewable. Source evaluation requires reviewed approval, idempotency, rollback, and an independent source-status read. | The fresh finding read reports `resolved`, and every acceptance check has evidence. |
| `identity.access-risk` | Lifecycle, IdP, SaaS access, and activity evidence → access-path correlation → optional self-attestation → revocation approval → one access change → access read | Self-attestation is not proof or approval. Revocation requires a registered `security_write` tool, reviewed approval, rollback, and an independent identity read. | The targeted access path is absent in the owning source and the verification evidence is attached. |
| `detection.response` | Provider state → alert enrichment → incident or noise decision → bounded rule change → backtest → canary → deployment approval → effectiveness read | Mutating Panther tools are classified as `security_write`; the dispatcher requires reviewed approval, idempotency, rollback, and independent read-only verification. | Post-deployment evidence shows the expected rule behavior without a blocking backtest or canary regression. |

The identity pack can investigate and checkpoint a revocation when no identity write connector is registered. It remains in `needs_tool` until an approved connector exposes a matching `security_write` action and read-only verification tool. The detection pack uses the same rule for Panther tools that are not enabled by runtime configuration.

## Operator state

`/cerebro goal show <goal-id>` and `operator_agent_run_status` return:

- pack id, version, status, owner, and plan receipt;
- current and waiting steps;
- missing inputs and blockers;
- pending approvals;
- bound tool count;
- source resources and evidence artifacts;
- acceptance checks and completion receipt;
- next wake time.

An operator can reopen the exact plan from the stored digest and see which action changed external state, who approved it, which read verified it, and which rollback applies.
