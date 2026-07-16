# Source Runtime Backfills

Use the `Source Runtime Backfill` workflow to repair missing source-sync or graph-ingest history. The workflow separates target selection, approval, execution, and recovery so recorded completed work is not restarted after a source-specific failure.

## Plan

Run the workflow with `mode=plan` and choose one target source:

- `latest-graph-health` reads missing runtime IDs from a recent successful `Graph Health Insight` run on `main` for the selected stack.
- `explicit` reads the runtime IDs supplied in the workflow form.

The plan artifact contains:

- every requested runtime and its declared state;
- one execution lane per source;
- page, event, retry, cooldown, and parallelism bounds;
- the exact repository commit and stack-file digest;
- the plan hash required by `dry-run` and `run`.

A quarantined, undeclared, source-filtered, unscheduled, multiply scheduled, or disabled-schedule runtime remains visible in plan mode. The workflow refuses to execute a plan containing one of those states.

## Inspect deployed targets

Run the same workflow at the same commit with `mode=dry-run`, unchanged bounds, and the plan hash. Dry-run jobs assume the selected stack role and inspect deployed runtime targets without starting ECS tasks.

## Run

Run the workflow at the same commit with `mode=run`, unchanged bounds, and the plan hash. The production stack also requires the `production` environment approval.

The executor applies these controls:

1. Recompute the plan hash from typed fields. Edited plans are rejected.
2. Verify the checked-out stack file and workflow commit still match the approved plan.
3. Run different sources up to `source_parallelism`.
4. Run runtimes from the same source sequentially.
5. Refuse a source lane larger than `max_targets_per_source`.
6. Reject policies whose worst-case attempts, exponential retry delays, and cooldowns exceed a 5.5-hour source lane budget.
7. Apply `source_cooldown_seconds` between successful runtimes from one source.
8. Retry retryable failures with exponential backoff up to `max_attempts`.
9. Retry lease contention instead of counting a skipped runtime as completed.
10. Stop the remaining source lane after shared authentication, authorization, source-configuration, or exhausted rate-limit failures.
11. Write a checkpoint after every target state change.

Each runtime attempt has explicit page, graph-page, event, wait, and attempt-duration bounds. Source jobs also have a six-hour runner timeout. The workflow has no unbounded production defaults.

## Resume

Set `resume_run_id` to the prior `Source Runtime Backfill` workflow run. The workflow downloads the checkpoint for each source lane. Completed runtimes are skipped; failed and blocked runtimes are eligible to run again.

Resume requires the same plan hash, execution mode, source, workflow commit, and stack-file digest. Create a new plan after any of those inputs change.

The executor writes its checkpoint file after each state change and the job uploads that file when the source lane exits. A hard runner termination before artifact upload can lose the newest checkpoint for that source lane; checkpoint artifacts from other completed source lanes remain reusable.

## Results

Each source lane uploads a checkpoint artifact even when that lane fails. The summary job combines those checkpoints into JSON and Markdown with counts for completed, failed, and blocked runtimes.

Failure classes map to operator actions:

| Failure class | Required action |
| --- | --- |
| `authentication` | Correct or rotate the source credential, then resume. |
| `authorization` | Restore source permissions, then resume. |
| `source_configuration` | Repair shared source configuration, then resume. |
| `rate_limited` | Wait for the provider window or reduce bounds, then resume. |
| `target_configuration` | Repair the runtime schedule or target, then create a new plan. |
| `transient` | Resume; completed runtimes will not run again. |
| `runtime_failure` | Inspect the runtime-specific logs, correct the failure, then resume. |

Do not paste credentials, secret names, or provider responses into runtime IDs, workflow inputs, commit messages, or pull request text.
