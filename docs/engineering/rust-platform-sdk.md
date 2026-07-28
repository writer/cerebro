# Rust Platform SDK

## Decision

Cerebro exposes one reusable, transport-neutral Rust SDK for platform
capabilities. The SDK composes the existing sealed organizational model,
bounded fact-query model, and control kernel. It does not copy their types or
reimplement their validation rules.

The SDK owns:

- validated platform capability identifiers and content digests;
- graph revision selectors and bounded temporal diff contracts;
- evidence quality and provenance explanation contracts;
- continuous assertion definitions and evaluations;
- counterfactual simulation requests and results;
- durable subscription filters, cursors, and event pages;
- materialized-view definitions and revision-bound snapshots;
- signed incident snapshot manifests;
- governed action proposals, operation state, and receipts;
- per-tenant resource budgets and operational diagnostics;
- disaster-recovery verification reports;
- first-party, zero-import deterministic analysis-plugin manifests; and
- one adapter trait implemented by in-process, Connect, HTTP, and test clients.

The SDK does not own transport, storage, graph mutation, provider access,
scheduling, deployment, or model execution.

## Reuse boundary

```text
cerebro-organizational-model
        |
cerebro-agent-context     cerebro-control-kernel
        |                         |
        +------ cerebro-platform-sdk ------+
                                             |
                      +----------------------+------------------+
                      |                      |                  |
                in-process adapter      Connect adapter    test adapter
                      |
          JetStream + Postgres + Neo4j authorities
```

`cerebro-platform-sdk` is the only handwritten semantic contract for these
capabilities. Generated Connect, Go, TypeScript, and Python clients adapt the
versioned wire contract to the SDK vocabulary. They do not independently
decide limits, lifecycle state, authority, evidence quality, or verification
semantics.

## Non-goal alignment

- JetStream remains the log of record, Postgres remains current state, and
  Neo4j remains a rebuildable projection. The SDK introduces no store.
- Temporal queries reconstruct bounded history from the ledger and log. They
  do not make Neo4j authoritative.
- Simulations are read-only. Mutations use governed Action contracts.
- An Action proposal binds the validated finding revision, action-definition
  revision, target, simulation, rollback, and verification plan. A worker can
  claim it only after an independent decision receipt approves that exact
  proposal digest.
- Provider completion is not verification. The verified transition requires a
  receipt bound to the operation, proposal, observed effect, and executor, with
  a different verifier, a fresh source revision, and evidence.
- Subscriptions use durable cursors and typed filters. They do not expose
  arbitrary Cypher.
- Analysis plugins remain first-party, release-provenanced, zero-import,
  deterministic Wasm modules with fixed limits. This is not a plugin
  marketplace.
- The mission surface composes the reviewed native control-kernel carve. It
  does not expand the Go action engine into a generic workflow runtime.

## Delivery order

1. SDK identities, revisions, digests, limits, contracts, and adapter trait.
2. Postgres temporal ledger reads and provenance assembly.
3. Pure continuous-assertion and counterfactual-simulation engines.
4. JetStream subscription adapter and Postgres materialized-view projection.
5. Incident snapshot packaging and verification.
6. Governed action and mission adapters over the existing durable workflows.
7. Diagnostics, tenant budgets, and disaster-recovery verification.
8. Fixed-ABI first-party analysis plugin adapter.
9. Generated Connect, Go, TypeScript, and Python clients plus conformance tests.

Each layer must retain the same SDK types and fail closed when its required
authority is unavailable.
