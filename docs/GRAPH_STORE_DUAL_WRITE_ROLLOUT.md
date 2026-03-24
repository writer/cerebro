# Graph Store Dual-Write Rollout

This document describes the canary sequence for enabling graph-store
dual-write during a migration from the current primary backend to a Spanner
target.

## Components

The dual-write slice adds:

- `DualWriteGraphStore`
  - fans out graph mutations to a primary and secondary backend
  - keeps reads pinned to the primary backend
- reconciliation queue
  - persists failed secondary mutations to a local JSON queue
  - replays them in bounded batches on a background loop
- mutation outcome reporting
  - records primary/secondary success state
  - records retryability and enqueue status for secondary failures

## Configuration

Primary backend selection stays unchanged:

- `GRAPH_STORE_BACKEND`

Secondary fan-out is enabled with:

- `GRAPH_STORE_SECONDARY_BACKEND`
- `GRAPH_STORE_DUAL_WRITE_MODE`
- `GRAPH_STORE_DUAL_WRITE_RECONCILIATION_PATH`
- `GRAPH_STORE_DUAL_WRITE_REPLAY_ENABLED`
- `GRAPH_STORE_DUAL_WRITE_REPLAY_INTERVAL`
- `GRAPH_STORE_DUAL_WRITE_REPLAY_BATCH_SIZE`

Backend-specific secondary settings mirror the primary settings:

- Neptune:
  - `GRAPH_STORE_SECONDARY_NEPTUNE_*`
- Spanner:
  - `GRAPH_STORE_SECONDARY_SPANNER_*`

## Rollout sequence

1. Deploy with parity and shadow reads already enabled.
2. Configure `GRAPH_STORE_SECONDARY_BACKEND` and leave `GRAPH_STORE_DUAL_WRITE_MODE=primary_only`.
3. Confirm both backends initialize cleanly and no secondary open/bootstrap errors appear at startup.
4. Switch to `GRAPH_STORE_DUAL_WRITE_MODE=best_effort_dual_write`.
5. Watch reconciliation queue depth and warning logs for secondary write failures.
6. Leave replay enabled until the queue remains empty through sustained live traffic.
7. Use cutover parity probes and snapshot diffs to confirm structural parity while dual-write is live.
8. Move read-path cutover only after secondary writes stay clean and parity remains stable.
9. Reserve `strict_dual_write` for short canaries or pre-cutover validation windows because it couples request success to both backends.

## Failure policy guidance

- `primary_only`
  - validates secondary connectivity without affecting request success
- `best_effort_dual_write`
  - recommended default migration mode
  - primary remains authoritative
  - retryable secondary failures are queued for replay
- `strict_dual_write`
  - strongest parity guarantee
  - highest operational risk during rollout

## Operational expectations

- Reads remain primary-only until an explicit cutover phase.
- The reconciliation queue is durable across process restarts.
- Replay is idempotent because it reuses the graph-store mutation contract.
- Secondary failure handling is visible in structured logs via mutation outcome reports.
