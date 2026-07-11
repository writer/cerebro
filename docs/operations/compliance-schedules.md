# Compliance Schedule Operations

## Monitor states

Each monitor points to one tenant, program, and immutable assessment-plan
revision. Operators should use these fields when deciding what action to take:

| Field | Operator meaning |
| --- | --- |
| `enabled` | New occurrences may be claimed. Disabling does not cancel a running job. |
| `next_run_at` | Logical occurrence time. It advances only after the job exists. |
| `claim_owner`, `claim_expires_at` | Scheduler claim. An expired claim is safe to reclaim. |
| plan run lease | Prevents overlapping runs for one tenant and plan revision. |
| `last_success_at` | Last terminal assessment recorded as successful. |
| `consecutive_failures` | Number of terminal failures since the last success. |

## Missed occurrence

1. Confirm the monitor is enabled and `next_run_at` is due.
2. Check whether the monitor claim is active. Do not clear an unexpired claim.
3. Check for a job with the monitor occurrence idempotency key.
4. If the job exists, let the scheduler acknowledge the occurrence on its next
   pass. Do not create another job manually.
5. If no job exists and the claim expired, release the claim or wait for the next
   scheduler pass.
6. Confirm `next_run_at` advanced only after the job record appeared.

## Change-triggered occurrence

Change monitors keep a tenant-scoped receipt for each monitor and source event.
Repeated delivery of one event does not increase the window count. New events
extend the monitor's debounce window and increment its version.

1. Confirm the monitor is enabled, uses the `change` trigger, and has a positive
   debounce window.
2. Check the change receipt by tenant, monitor, and event ID.
3. Check `ready_at`. A window is not missed while its debounce period is open.
4. If a claim exists, compare its version with the current window version. A
   newer version means another signal arrived while the older claim ran.
5. Confirm the assessment job exists before acknowledging the claimed version.
6. Leave a newer window in place. The plan run lease prevents it from starting
   until the current assessment reaches a terminal state.

## Stuck plan lease

1. Find the assessment job referenced by the occurrence.
2. If the job is running and its worker lease is current, keep the plan lease.
3. If the job lease expired, allow platform job recovery to resume it.
4. If the job is terminal but the plan lease remains, release the plan lease with
   the recorded owner.
5. If the plan lease expired while a job still runs, stop and investigate the job
   heartbeat before allowing another occurrence.

## Repeated failures

- Inspect the assessment run failure code. Do not use evidence text or attachment
  content in alerts.
- `collection_incomplete` requires a complete source scan before retry.
- `source_unavailable` requires source runtime recovery; unaffected objectives may
  still finish in a later run.
- `result_invalid` requires evaluator or conformance-fixture repair before retry.
- Disable the monitor when retries would repeat an unresolved contract failure.

## Safe cancellation

Cancel the platform job. The runner records a readable cancelled run and releases
the plan lease after its terminal event is durable. Do not delete the run, its
input receipts, or completed result chunks.
