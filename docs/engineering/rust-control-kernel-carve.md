# Native Rust Control Kernel Carve

## Decision

Cerebro will build its durable mandate and mission control plane as a native Rust kernel. The existing Go service remains the compatibility data plane for source runtimes, provider collection, graph projection, current findings and GRC APIs, and action adapters while callers migrate.

This is a service carve, not a package-by-package language translation. New mandate, mission, authority, scheduling, actor-coordination, decision, and verification behavior belongs to the Rust kernel. Existing Go capabilities are reached through versioned events and authenticated APIs.

## Customer Outcome

The kernel lets an operator establish a standing condition, such as removing production access after a person leaves, and lets Cerebro keep working until the condition is independently verified. A chat response, provider receipt, merged change, or completed job is not closure.

## Ownership

The Rust control kernel owns:

- mandate identity, immutable revisions, scope, desired conditions, and suspension;
- mission identity, state, hypotheses, plan revisions, commitments, and wake conditions;
- actor capability declarations, assignment, and exclusive work leases;
- scoped capability grants, decision requests, and immutable decision receipts;
- action proposals, expected effects, rollback references, and execution receipts;
- independent verification challenges, verification receipts, outcomes, and reopening;
- replayable mission events and projections used by agent-facing APIs.

The Go compatibility plane owns during migration:

- source runtimes and connector implementations;
- provider-specific collection and normalization entry points;
- existing finding evaluation and graph projection;
- existing action adapters and verified-action APIs;
- existing report and GRC compatibility routes.

The graph remains a rebuildable projection. It is not a mission store, scheduler, authority system, or closure record.

## Process Boundary

The control kernel runs as a native Linux process. It does not use CGO, in-process Go/Rust FFI, or embedded Wasm for orchestration. The current embedded Rust/Wasm modules remain bounded deterministic helpers. The kernel communicates with the compatibility plane through:

- versioned JetStream events for observed state and durable workflow facts;
- authenticated HTTP or Connect calls for existing reads and actions;
- idempotency keys, exact tenant and resource identifiers, source revisions, and receipts on every boundary.

## Storage Boundary

This carve preserves the existing storage contract:

- JetStream remains the log of record.
- Postgres remains the current state store and holds mission projections, leases, and queryable state.
- Neo4j remains a rebuildable graph projection.

The kernel does not introduce another database. Mission events are appended to JetStream before their Postgres projections become visible. A projection can be rebuilt from ordered events.

## Kernel Rules

The `cerebro-control-kernel` crate is pure domain code. It must not depend on network clients, databases, graph clients, provider SDKs, model clients, or transport frameworks.

The deterministic kernel owns:

- valid state transitions;
- optimistic revision checks;
- grant and approval requirements;
- actor separation rules;
- idempotency identities;
- closure and reopening conditions.

A model may propose hypotheses, plans, actor assignments, and explanations. Model output cannot advance mission state, manufacture authority, or mark verification successful.

## First Mandate

The first production mandate is:

> No terminated identity retains production access for more than 24 hours.

The vertical is complete only when Cerebro can:

1. consume a termination or active-access observation;
2. open or deduplicate a mission;
3. resolve identity, access path, owner, and source freshness;
4. prepare a typed remediation plan;
5. request the minimum required human decision;
6. invoke an existing approved action adapter;
7. wait for a newer source revision;
8. independently verify that the access path is gone;
9. close, block, or reopen the mission from evidence;
10. publish one reusable outcome and evidence receipt.

## Migration Stages

1. **Shadow:** consume real events and create missions without external writes.
2. **Recommend:** produce plans, action proposals, and decision requests.
3. **Governed execution:** invoke one allowlisted existing adapter under an exact capability grant.
4. **Default control plane:** agent-facing mission reads and decisions use the Rust kernel.
5. **Domain migration:** move deterministic domains only when the move removes a complete Go ownership boundary.
6. **Deletion:** retire duplicate Go orchestration and contract-only agent work surfaces.

## Release Gates

The Rust kernel cannot become authoritative until tests prove:

- replay produces the same mission state and digest;
- duplicate events do not duplicate missions or actions;
- worker crashes do not lose or repeat completed effects;
- stale leases cannot commit;
- revoked or expired grants block execution;
- missing or stale evidence cannot produce verified closure;
- provider success cannot produce verified closure;
- executor and verifier identities are distinct;
- cross-tenant references fail closed;
- mission history remains available when the graph is unavailable;
- the kernel can be rolled back without losing mission history.

## Delivery Discipline

- Keep no more than two dependent draft layers ahead of a mergeable foundation.
- Every draft has code, tests, an exact base, and an independently reviewable ownership boundary.
- Do not merge a child into a feature branch to simulate progress.
- Do not raise architecture budgets to hide misplaced behavior.
- Do not port connectors to increase the percentage of Rust.
- Do not create a generic workflow DSL before the first mandate proves the required execution shape.
