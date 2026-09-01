# Rust Platform SDK

## Decision

Cerebro exposes one reusable, transport-neutral Rust SDK for platform
capabilities. The SDK composes the existing sealed organizational model,
bounded fact-query model, and control kernel. It does not copy their types or
reimplement their validation rules.

The SDK owns:

- validated platform capability identifiers and content digests;
- graph revision selectors and bounded temporal diff contracts;
- immutable context bindings and verified invalidation outcomes;
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
- Context bindings content-address an exact graph revision, rendered context,
  and bounded dependency set. Later authoritative temporal diffs produce
  explicit unchanged, changed, or invalidated outcomes; missing, incomplete,
  or digest-mismatched evidence produces unknown. Bindings and evaluations are
  self-validating records and introduce no additional snapshot or store.
- Simulations are read-only. Mutations use governed Action contracts.
- An Action proposal binds the validated finding revision, action-definition
  revision, target, simulation, rollback, and verification plan. A worker can
  claim it only after an independent decision receipt approves that exact
  proposal digest. The SDK computes that versioned digest from every
  execution-relevant proposal field and rejects any record whose stored digest
  no longer matches.
- `cerebro-action-catalog` is the closed runtime registry for new proposals.
  Its reviewed source is `crates/action-catalog/action_catalog.yaml`; the
  generator assigns a
  content digest to every provider operation, and rejects unknown Action kinds,
  altered definition digests, mismatched effects, and effects aimed at a
  different target. Historical ledger rows keep their committed definition
  digest even after the active catalog changes.
- A new Action also requires an append-only Rust finding-validation receipt.
  The receipt binds the tenant, finding revision, graph revision, policy
  definition, evidence, decision, validator, and expiry. The ledger checks that
  receipt in the same PostgreSQL transaction that commits the Action and rejects
  rejected, expired, self-validated, missing, or mismatched receipts.
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
