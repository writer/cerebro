# Spanner Graph Change Streams

## Purpose

`cerebro_world_model_changes` provides near-real-time propagation of world-model mutations from Spanner into downstream graph consumers. The change stream is scoped to the canonical world-model tables so downstream consumers can rebuild graph mutations without polling full snapshots.

## Covered Tables

- `entities`
- `entity_relationships`
- `sources`
- `evidence`
- `evidence_targets`
- `observations`
- `observation_targets`
- `claims`
- `claim_subjects`
- `claim_objects`
- `claim_sources`
- `claim_evidence`
- `claim_relationships`

## Default DDL

The default generator emits a single `CREATE CHANGE STREAM` statement with:

- `retention_period = '168h'`
- `value_capture_type = 'NEW_ROW_AND_OLD_VALUES'`
- inserts, updates, and deletes enabled
- `allow_txn_exclusion = true`

## Rollout Constraints

- Retention window: keep retention long enough to cover downstream outages plus replay lag. The default 7-day window is a starting point, not a hard guarantee.
- Backfill bootstrap: bootstrap downstream consumers from a known snapshot before tailing the change stream, or use dry-run parity to verify that the initial stream position matches the seeded state.
- Schema changes: any new canonical world-model table or link table must be added to the watched-table config and corresponding mutation-shaping tests before rollout.
- Replay and idempotency: downstream sinks must treat `transaction_id + mutation_sequence + identifier` as an idempotency key. Replays after consumer failure are expected.
- Delete handling: child/link-table cascading deletes can arrive independently; consumers must not assume parent records are still readable when delete envelopes are processed.

## Recommended Consumption Modes

- Pub/Sub fan-out for event-driven graph projections or external consumers.
- Queue handoff when replay durability and back-pressure control matter more than latency.
- In-process reconciler for local projection updates or parity validators.

## Verification

- Run `go test ./internal/graph -run TestSpannerWorldModelChangeStream -count=1`
- Confirm the watched-table set still matches the canonical schema before applying DDL.
