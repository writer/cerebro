# Durability Contract

This document records which Cerebro writes are event-backed today, which writes
are current-state backed, and how graph rebuilds should treat each path.

Use this with [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`NON_GOALS.md`](./NON_GOALS.md),
[`SOURCE_RUNTIME_GUIDE.md`](./SOURCE_RUNTIME_GUIDE.md), and
[`SOURCE_SYNC_RECOVERY.md`](./SOURCE_SYNC_RECOVERY.md).

## Current Write Classes

| Write class | Durable record | Projection path | Rebuild source |
| --- | --- | --- | --- |
| Source runtime sync | JetStream event envelopes plus runtime cursor state | Source event projector writes Postgres projection rows and Neo4j graph rows when configured | JetStream replay, or bounded source reread for dry-run previews |
| Workflow decisions, actions, and outcomes | JetStream `workflow.v1.*` event envelopes | Workflow projector writes graph rows after append succeeds | JetStream replay |
| SDK/runtime claims | Postgres claim rows | Claim service writes Postgres projection rows and Neo4j graph rows when configured | Postgres claim state until claim events exist |
| Finding current state | Postgres finding, evidence, candidate, and evaluation-run rows | Finding lifecycle methods may emit workflow events for timeline/graph context where configured | Postgres finding state plus workflow replay for workflow context |

The important boundary is that graph state must not become independently
authoritative. Neo4j remains a projection. Today most graph-affecting writes are
event-backed, but SDK/runtime claim writes are a documented current-state-backed
path until a claim event stream lands.

## Required Invariants

- Source runtime sync must append accepted source events before projecting them.
- Source runtime sync must not advance runtime progress before the page's
  accepted events have been appended and projected through the configured
  projector.
- Source runtime page recovery must follow [`SOURCE_SYNC_RECOVERY.md`](./SOURCE_SYNC_RECOVERY.md) until a transactional sync ledger or outbox exists.
- Workflow projection must happen after the corresponding workflow event append.
- SDK/runtime claim writes must persist claim rows before writing graph
  projections.
- Any new graph-affecting write path must declare whether it is event-backed or
  current-state backed in this document before it ships.
- Any new current-state-backed graph write must include a rebuild plan that does
  not require Neo4j to be authoritative.

## Target Direction

The preferred long-term shape is for SDK/runtime claim writes to become
event-backed through a stable `claim.v1.*` event family. Until that exists,
claim rows in Postgres are the rebuild source for claim-derived graph state.
This is an explicit transition state, not permission for additional
current-state-backed graph writers.

## Review Checklist

For any PR that touches graph-affecting writes, reviewers should be able to
answer:

1. What is the durable record?
2. Which projector writes graph rows?
3. What happens if append, projection, or current-state persistence fails after
   a partial write?
4. How can an operator rebuild or repair graph state without treating Neo4j as
   authoritative?
