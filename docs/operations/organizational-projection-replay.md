# Organizational projection replay

The Rust organizational graph is a rebuildable projection. JetStream source
events remain the replay input, PostgreSQL stores the Rust current-state ledger
and projection receipts, and Neo4j stores the rebuildable graph.

Replay does not promote a source family from legacy write authority. The replay
and forward consumer materialize Rust shadow state so parity can be measured
before promotion.

## Required configuration

Both replay and forward consumption require:

- `CEREBRO_JETSTREAM_URL`
- `CEREBRO_JETSTREAM_STREAM_NAME`
- `CEREBRO_JETSTREAM_SUBJECT_PREFIX`
- `CEREBRO_POSTGRES_DSN`
- `CEREBRO_NEO4J_URI`
- `CEREBRO_NEO4J_USERNAME`
- `CEREBRO_NEO4J_PASSWORD`

Consumer names and run IDs contain only letters, digits, hyphens, and
underscores. A replay never uses the forward consumer name.

## Capture the fence

Run this from the same network and NATS account as the consumer:

```sh
cerebro-platform inspect-append-log
```

Save the emitted `cerebro.organizational-consumer-fence/v1` JSON. Its
`first_sequence` is the first retained stream sequence and `end_sequence` is
the immutable upper fence for this replay. Do not substitute a later stream
sequence after a replay run starts.

## Run bounded replay batches

Use one replay consumer name and run ID for every bounded invocation:

```sh
CEREBRO_ORGANIZATIONAL_CONSUMER_MODE=replay \
CEREBRO_ORGANIZATIONAL_CONSUMER_NAME=organizational-graph-replay-<change-id> \
CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID=<change-id> \
CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY=all \
CEREBRO_ORGANIZATIONAL_CONSUMER_END_SEQUENCE=<end_sequence> \
CEREBRO_ORGANIZATIONAL_CONSUMER_MAX_MESSAGES=100000 \
CEREBRO_ORGANIZATIONAL_CONSUMER_MAX_RUNTIME_SECONDS=3600 \
cerebro-platform consume-append-log
```

The first invocation persists the fence before it creates or reads the
consumer. Later invocations reuse the stored fence and durable checkpoint.
Message and projection counters remain cumulative. A safety-bound stop records
`stopped`, exits zero for trusted resume automation, and never emits
`completed`. Configuration, retention, rejected-message, and projection
failures exit nonzero.

SIGTERM or Ctrl-C records `stopped` before exit. Stopping the ECS task is the
rollback control; restarting the same task resumes from the durable checkpoint.
Do not delete the durable consumer or change the run ID during a replay.

Do not run the forward projector at the same time. Historical replay after a
newer forward event could regress current state; event-receipt idempotency does
not prove stale-event rejection.

If a replay has recorded any rejected message, retain that consumer run as
failed audit evidence. A later candidate cannot turn its cumulative rejected
counter back to zero. Retry the same immutable fence from its original
`first_sequence` with a new consumer name and run ID, for example
`organizational-graph-replay-sec-dev-cutover-v2` and `sec-dev-cutover-v2`.
Do not delete or reset the failed run or its durable.

Replay recognizes a bounded set of pre-canonical historical records as explicit
skips: the legacy `asset.data_sensitivity` kind, invalid historical observation
IDs for `gcp.iam_role_assignment`, `gcp.effective_permission`, and
`aws.public_endpoint`, the catalog-owned `cerebro.health.jetstream_canary`
without a source envelope, and the retired `okta.threat_insight` family. This
compatibility applies only in replay mode. The forward consumer continues to
reject every one of these shapes. Inspect the completed run and review the
per-source-family skipped counters as the durable evidence for these records.

## Start the forward durable after replay

After the replay receipt is `completed`, capture the stream state again. Fail
closed if the current `first_sequence` is greater than `end_sequence + 1`;
retention has removed part of the handoff range.

Then start the long-running service with a distinct durable consumer at
`end_sequence + 1`:

```sh
CEREBRO_ORGANIZATIONAL_CONSUMER_MODE=forward \
CEREBRO_ORGANIZATIONAL_CONSUMER_NAME=organizational-graph-forward-v1 \
CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID=forward-from-<end_sequence> \
CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY=by_start_sequence \
CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE=<end_sequence+1> \
cerebro-platform serve-neo4j-consumer
```

JetStream retains the forward checkpoint. Restart the service with the same
consumer name, run ID, and start sequence.

## Completion and authority prerequisite

The process emits `cerebro.organizational-consumer-run/v1` JSON and persists the
same progress in `organizational_consumer_runs`.

A replay is materialization-complete only when all of these are true:

- `status = 'completed'`;
- `covered_sequence = end_sequence`;
- `messages_projected > 0`;
- `messages_rejected = 0`;
- the forward run is `running`, uses a different consumer name, and has
  `start_sequence = end_sequence + 1`.
- the replay `completed_at` precedes the forward run `started_at`.

`messages_skipped` is explicit. It includes retained events outside the
portable organizational projection contract and must be reviewed before using
the replay as parity evidence. Service health, Neo4j connectivity, messages
seen, or a drained consumer alone are not authority-readiness signals.

Emit the inspection payload from the same candidate:

```sh
CEREBRO_ORGANIZATIONAL_CONSUMER_NAME=organizational-graph-replay-<change-id> \
CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID=<change-id> \
cerebro-platform inspect-consumer-run
```

The output includes the materialization receipt and its SHA-256 digest. Typed
read parity remains the semantic comparison; raw relation or assertion counts
are not interchangeable.

Use this query for the durable receipt:

```sql
SELECT consumer_name, run_id, mode, start_sequence, end_sequence,
       last_delivered_sequence, covered_sequence, messages_seen, messages_projected,
       messages_skipped, messages_rejected, status, updated_at, completed_at
FROM organizational_consumer_runs
WHERE (consumer_name, run_id) IN (
  ('organizational-graph-replay-<change-id>', '<change-id>'),
  ('organizational-graph-forward-v1', 'forward-from-<end_sequence>')
);
```

Do not promote read or write authority until this receipt, projection parity,
and the separate cutover gates all pass.
