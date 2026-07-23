# Rust Organizational Platform

## Decision

Cerebro's target runtime is a Rust-owned organizational data and agent platform. This is a replacement architecture, not a validation helper beside the Go projection path.

Rust owns:

- connector definition compilation and provider collection;
- collection scope, completeness, cursors, and observations;
- provider-object identity and canonical organizational identity;
- relationship assertion admission and retraction;
- current graph resolution and graph-store writes;
- bounded graph context for agents, Slack, and web;
- the public service process and generated client contracts.

The existing Go runtime is a migration oracle. It may provide fixtures, expected events, source parity results, and differential test cases while sources move. It is not an alternate graph writer in the target deployment.

## Crate ownership

```text
provider API
    |
cerebro-source-catalog --> cerebro-source-runtime-next
                                  |
                                  v
                      cerebro-organizational-model
                                  |
                                  v
                      cerebro-organizational-store
                         |                   |
                  Postgres ledger      Neo4j projection
                                             |
                                             v
                                  cerebro-agent-context
                                             |
                                    cerebro-platform
```

`cerebro-organizational-model` is pure domain code. Its validated types expose no public fields and do not implement `Deserialize`. Wire records must be converted through checked constructors.

`cerebro-organizational-graph` is the only crate that advances current organizational graph state. A commit takes a validated `GraphDelta`; there is no public entity/link mutation method.

`cerebro-source-catalog` compiles all 794 checked-in source definitions and 3,891 resource families into a closed runtime grammar. It joins those definitions to provider proof manifests. A definition without complete provider proof remains shadow-only even if it can be executed.

`cerebro-source-runtime-next` owns source collection, pagination, mapping, and graph commit sequencing. Provider redirects are disabled, pagination cannot change origin, pages are bounded, and resolved credentials never enter the graph model. A source cannot obtain a graph store or construct an unvalidated graph write.

`cerebro-organizational-store` commits raw observations, admitted entities, assertions, retractions, the tenant graph revision, and a projection outbox row in one PostgreSQL transaction. PostgreSQL is the durable authority. Neo4j is an idempotent, rebuildable current-state projection written in batches.

`cerebro-agent-context` exposes bounded search, lookup, expansion, path, and explanation operations. It does not expose Cypher or store mutation.

`cerebro-platform` serves the bounded agent graph API against Neo4j in production and the in-memory graph in local demos. Web and Slack use search, lookup, expansion, paths, and assertion explanation; neither receives Cypher or graph-write access.

## Enforced identity model

Provider identities and canonical identities are different Rust types.

```text
ProviderIdentity --REPRESENTS--> CanonicalIdentity
```

A provider identity contains the source runtime, provider kind, and provider ID. A canonical identity contains an opaque Cerebro identity ID. Neither can be constructed as the other.

Identity binding is a dedicated assertion. The general relationship constructor cannot create `REPRESENTS`. Confirmed bindings require an authoritative employee identifier, verified email, or human decision. An agent proposal cannot create a confirmed binding.

The graph engine enforces one current confirmed canonical binding per provider identity. Authoritative employee IDs and normalized verified emails are typed `IdentityClaim` values, and the canonical identity ID is derived from the tenant and claim. Independent providers therefore produce the same canonical identity before storage. PostgreSQL repeats both invariants with tenant-scoped primary keys, so a second process or human override cannot split one claim across two canonical identities. A conflicting delta fails atomically and does not advance the tenant graph revision.

## Enforced relationship model

Relations are a closed Rust enum. Each variant owns its accepted endpoint kinds. Invalid combinations cannot produce a `RelationshipAssertion`.

Every assertion requires one or more observations from one tenant, source runtime, and collection. The delta must match that tenant and runtime. Cross-tenant values fail before storage.

Incomplete and incremental collections cannot call `retract_missing`. That method exists only on `GraphDeltaBuilder<Authoritative>`, which can be created only from `CompleteCollection`.

## Production bypass prevention

Language-level constraints prevent accidental bypass inside Rust. Production authority prevents deliberate bypass across processes:

1. Only the Rust platform workload receives graph-write credentials.
2. Source collectors run inside the Rust source runtime and receive no graph handle.
3. Go deployments become read-only during shadow comparison, then lose graph credentials before Rust becomes authoritative.
4. The graph store accepts writes only from the Rust workload identity at the network and database authorization layers.
5. CI rejects dependencies from the replacement crates onto Go projection contracts.
6. PostgreSQL forces tenant row-level security on the ledger tables and uses a tenant-scoped unique key for confirmed identity bindings.
7. Neo4j writes are not public API operations. Agent, web, and Slack routes are read-only and hard-bound to six hops and 500 results.

Repository conventions and review are not the security boundary. Store credentials and workload identity are.

## Source coverage migration

Source migration is definition- and family-based, not package-by-package translation.

For every existing source family, the parity corpus records:

- provider request and pagination behavior;
- collection scope and completeness;
- emitted provider objects and stable IDs;
- normalized entities and relationship assertions;
- retractions after complete collections;
- graph paths produced from the fixture;
- provider failure and permission states.

Rust runs the same fixtures in shadow and compares complete graph deltas and deterministic digests. `CutoverGate` requires complete provider proof, at least three consecutive matching receipts, matching latest corpora, and projection lag within policy. A source family moves only after that decision allows it. The Go implementation remains available as a rollback oracle until the Rust family is authoritative, then its write path is removed.

The current checked-in catalog compiles to 794 sources and 3,891 families. Based on exact provider method-and-path proof and auth support present in this Rust runtime, 33 sources and 238 families are authoritative; the other 761 sources remain shadow-only. This preserves source coverage without converting catalog presence into a false production claim.

## Performance shape

- The reproducible Go/Rust comparison and current measurements are recorded in
  [Rust Organizational Platform Benchmarks](rust-organizational-platform-benchmarks.md).
- Deltas are tenant- and collection-scoped, deterministic, and batchable.
- The graph engine validates a complete candidate transaction before commit.
- Agent traversal is limited to six hops and 500 returned entities per request.
- Provider documents remain outside the current graph; assertions carry compact evidence references.
- Production graph adapters batch entity and relationship writes and publish one graph revision per accepted delta.
- PostgreSQL serializes revisions per tenant, not globally.
- The Neo4j outbox is tenant-scoped and replayable after projection failure.
- Provider pagination is bounded at 10,000 pages and page size is bounded at 1,000 records.
