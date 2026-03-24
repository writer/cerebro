# Graph Dual-Write Durable Replay

## Purpose

During graph-store cutover, `DualWriteGraphStore` can accept a successful primary write even when the secondary backend fails. Durable replay keeps those missed secondary mutations from being lost across process restarts.

## Queue Backends

- File path without a database extension: local-process JSON queue
- Path ending in `.db`, `.sqlite`, or `.sqlite3`, or prefixed with `sqlite://`: SQLite-backed durable queue

The SQLite backend adds durable enqueue, lease, ack, retry, and dead-letter semantics. It is the recommended backend for crash-safe replay.

## Replay Semantics

- `Enqueue`: persist the failed secondary mutation
- `Lease`: claim a bounded batch for one replay worker with a time-bound lease
- `Ack`: remove a successfully replayed mutation
- `Retry`: release the lease, increment retry metadata, and make the mutation visible again
- `Dead-letter`: isolate poison messages once retries are exhausted or the failure is non-retryable

Replay workers tolerate duplicate delivery by replaying idempotent graph mutations against the secondary store.

## Operator Signals

- Prometheus queue depth gauges:
  - `cerebro_graph_dual_write_reconciliation_queue_depth{state="pending"}`
  - `cerebro_graph_dual_write_reconciliation_queue_depth{state="leased"}`
  - `cerebro_graph_dual_write_reconciliation_queue_depth{state="dead_letter"}`
- Prometheus event counter:
  - `cerebro_graph_dual_write_reconciliation_events_total{result=...}`
- Health check:
  - `graph_dual_write_reconciliation`

Dead-lettered mutations degrade health so cutover operators can stop rollout before divergence grows silently.

## Rollout Guidance

1. Start in `best_effort_dual_write` with durable replay enabled.
2. Use a SQLite queue path for crash-safe replay during staging and early production cutover.
3. Watch pending depth, replay failures, and dead-letter count before increasing traffic.
4. Only move to `strict_dual_write` after replay stays empty and parity checks are stable.
5. Investigate every dead-lettered mutation before disabling the old backend.

