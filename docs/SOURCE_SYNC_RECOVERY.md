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
