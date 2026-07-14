# Append-Log Dead-Letter Data Policy

## Purpose

Append-log dead letters preserve one event after JetStream publication exhausts its retry budget. They exist so an operator can replay or discard that event without depending on the unavailable broker.

## Data Classification

| Field group | Classification | Operator list output | Telemetry |
| --- | --- | --- | --- |
| ID, status, event kind, subject, retry counts, payload size and hash | Operational | Allowed | Allowed with bounded dimensions |
| Tenant, source, runtime, and job identifiers | Internal | Allowed only through authenticated operator commands | Values excluded from metric dimensions |
| Error category and generated diagnostic | Operational | Category allowed | Category allowed |
| Replayable event envelope | Sensitive recovery data | Never returned | Never emitted |
| Replay claim token | Secret | Never returned | Never emitted |

The stored diagnostic is generated from the bounded retry category and attempt counts. Wrapped transport errors, authorization headers, credentials, request or response bodies, and provider URLs are not persisted in the diagnostic field.

The replayable envelope remains in Postgres. Production deployments must provide tenant isolation, encrypted storage, encrypted backups, and access logging for the database that owns the table.

## Retention

- Pending records are not deleted by a terminal-record retention job.
- Pending records older than 7 days require an operator alert and disposition.
- Replayed and discarded records have a default retention period of 30 days.
- Forced deletion of a pending record requires an authenticated actor, a concrete reason, and a durable audit record for every deleted ID.
- Cleanup runs operate in bounded batches of at most 500 rows and persist their cursor so interruption resumes after the last committed batch.

## Capacity Limits

- Emit backlog rows, estimated payload bytes, and oldest pending age without tenant IDs in metric dimensions.
- Warn at 10,000 rows or 1 GiB of replayable payloads.
- Reject creation above 100,000 rows or 10 GiB until an operator restores publication or performs an audited emergency purge.
- A hard-limit rejection records a bounded category and never logs the rejected event envelope.

These limits are defaults. A deployment may set lower limits. Raising a hard limit requires a recorded policy change and confirmed database headroom.

## Audited Actions

Replay, discard, forced pending purge, and retention-policy changes record the authenticated actor, action, reason, record ID or policy revision, and timestamp. Claim tokens and event envelopes are excluded from audit payloads.

## Recovery Procedure

1. Restore JetStream publication health.
2. List pending records and review subject, event kind, age, attempts, and claim state.
3. Replay one record at a time. Wait for an active ownership lease to expire before retrying an abandoned claim.
4. Discard only when the event must not be published, and provide the reason required by the command.
5. Use forced pending purge only when retention of the recovery payload creates a greater incident risk than event loss. Record the incident or change reference in the reason.
