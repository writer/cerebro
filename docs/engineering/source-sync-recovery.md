# Source Sync Recovery Contract

Source runtime sync is page-oriented. The current implementation intentionally
orders each page as append, project, then progress. It does not yet have a
transactional page ledger or outbox, so this ordering is the recovery contract
until that ledger exists.

## Current Commit Sequence

For each source page:

1. Read the next page from the Source CDK source.
2. Validate each emitted event envelope and source-specific event contract.
3. Append each accepted event to the append log.
4. Project each appended event through the configured source projector.
5. Persist runtime progress with `PutSourceRuntime` only after the page's
   accepted events have been appended and projected.
6. Emit `source_runtime.page_committed` after progress persistence succeeds.

Runtime progress includes cursor and checkpoint state. It must not advance ahead
of accepted event append and projection.

## Failure And Replay Rules

- If page read or event validation fails, no accepted event from that failure is
  committed.
- If append fails, projection and runtime progress must not run for that event.
- If projection fails after append, the sync fails before runtime progress is
  persisted. Repair should replay or re-project the appended event; Neo4j must
  not be treated as the source of truth.
- If runtime progress persistence fails after append and projection, the next
  sync may reread the same page. Append and projection paths must therefore be
  idempotent by stable event identity.
- Operators should use append-log replay or bounded source reread to repair
  projection gaps; checkpoint state alone is not a rebuild source.

## Target Ledger/Outbox Shape

The target hardening step is a source-sync ledger or outbox that records page
commit state with runtime ID, source ID, page attempt, accepted event IDs,
checkpoint hash, and projection/progress status. Runtime progress should advance
in the same durable transaction as the page commit marker, or recovery should
scan incomplete page commits and finish append-log replay/projection before
marking the page committed.

Until that exists, changes to source sync must preserve the append, project,
then progress ordering and keep `source_runtime.page_committed` as the last
successful page signal.

## Retry And Backoff

The orchestrator classifies each failed scheduled sync by typed error identity
(`sourceruntime.ClassifySyncFailure`) and stores the next allowed attempt in the
Postgres `source_runtime_sync_schedules` table. The table is scheduling
metadata only; it is never projected or replayed. A runtime whose next attempt
is in the future is skipped before lease acquisition with `sync=skipped` and
reason `backoff`. A successful sync deletes the row.

| Class | Policy |
| --- | --- |
| `unauthorized`, `permission_denied`, `invalid_config`, `decode_failed`, `cursor_invalid` | Hold 6h without growth; an operator change is required. |
| `rate_limited` | Wait the larger of the provider retry-after (capped at 15m) and 5m, plus up to 20% jitter. |
| `provider_unavailable`, `projection_unavailable`, `internal` | Full-jitter exponential backoff from 2m, doubling per consecutive failure, capped at 1h. At 8 consecutive failures the circuit opens and the runtime holds at 1h. |
| `budget_exhausted`, `cancelled` | No backoff. Cancelled syncs do not change the stored schedule. |

Runs that name runtimes explicitly (`runtime_id=` or `runtime_ids=`) bypass
backoff but still record the outcome. A hold also lifts immediately when the
runtime's source ID or operator-owned config (every key outside the
runtime-owned `__cerebro_` prefix) differs from the digest stored with the last
failure. If the schedule read fails, the sync runs
as if no backoff were stored; schedule write failures are reported as runtime
errors.
