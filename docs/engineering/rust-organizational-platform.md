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

`cerebro-source-catalog` compiles all 794 checked-in source definitions and 3,891 resource families into a closed runtime grammar. Every family is assigned one Rust-owned projection class: identity, access, resource, finding, activity, or bespoke. Connector YAML cannot declare another class. It joins those definitions to provider proof manifests. A definition without complete provider proof remains shadow-only even if it can be executed. Bespoke families also remain shadow-only until a native mapper is added.

`cerebro-source-runtime-next` owns source collection, pagination, mapping, and graph commit sequencing. Provider redirects are disabled, pagination cannot change origin, pages are bounded, and resolved credentials never enter the graph model. A source cannot obtain a graph store or construct an unvalidated graph write.

`cerebro-organizational-store` commits raw observations, admitted entities, assertions, retractions, the tenant graph revision, parity receipts, and a projection outbox row in one PostgreSQL transaction. PostgreSQL is the transactional authority for organizational current state. Neo4j is an idempotent, rebuildable current-state projection written in batches.

During migration, the Go source runtime may still collect legacy families and publish their events, but it cannot submit an event payload to the Rust projector. The Rust runtime consumes committed events directly from JetStream. Go asks Rust only for the persisted family authority: a legacy family returns to the Go projector and records a bounded compatibility delta, while a Rust-authoritative family returns no Go projection result and is committed only by the Rust consumer. Replay, refetch, device, CLI, and orchestrator paths use the same authority check, so an alternate Go entry point cannot restore a retired writer. The remaining projection HTTP routes accept legacy parity deltas, collection manifests, and authority reads; they do not provide a Rust-authoritative event write path.

`cerebro-agent-context` exposes bounded search, lookup, expansion, path, and explanation operations. It does not expose Cypher or store mutation.

`cerebro-platform` serves the bounded agent graph API against Neo4j in production and the in-memory graph in local demos. Web, Slack, MCP, reports, and the graph agent use this API as the authority for bounded neighborhood reads. One-hop requests, including batches of up to 100 roots, execute as one tenant-scoped Neo4j query. Go deployments can omit the graph store and every Neo4j credential once their callers use typed Rust operations. Any remaining raw Cypher caller then fails with `typed Rust graph operation required`; it cannot fall back to another graph reader. Raw Cypher is not exposed by the Rust API.

The Rust service also owns `GET /platform/graph/neighborhood`. It returns the
existing product JSON shape directly from the bounded Rust graph operation.
The boundary verifies the requested root, authenticated tenant, every returned
agent key, unique entity-to-key mapping, edge endpoints, labels, relation
metadata, and the 50-edge product limit before serializing a response.

## Enforced identity model

Provider identities and canonical identities are different Rust types.

```text
ProviderIdentity --REPRESENTS--> CanonicalIdentity
```

A provider identity contains the source runtime, provider kind, and provider ID. A canonical person contains an opaque Cerebro person ID. Neither can be constructed as the other.

Identity binding is a dedicated assertion. The general relationship constructor cannot create `REPRESENTS`. An Okta employee ID anchors the canonical person. The same workforce record may attach a normalized email claim to that person. GitHub can match the claim only when its email record says `verified=true`; Slack can match an existing workforce claim but cannot create one. Human decisions remain explicit assertions. An agent proposal cannot create a confirmed binding.

The canonical person ID is derived once from the tenant and authoritative employee ID. Verified email is a lookup key attached to that person, not another canonical-ID generator. This permits email renames without changing the person and prevents two claims for one employee from creating two canonical records.

The graph engine rebuilds the identity indexes from active assertions on every atomic admission. It enforces one current canonical person per provider identity, one canonical person per authoritative claim, an employee anchor before an email claim, and an existing authoritative claim before a GitHub or Slack match. PostgreSQL repeats those checks inside the commit transaction. A conflicting or unanchored delta fails without advancing the tenant graph revision.

Every entity also has one tenant-scoped `agent_key`. A valid source URN is
kept when it belongs to the entity's tenant. Otherwise Rust derives a stable
organizational-entity URN from the sealed tenant and entity ID. Neo4j indexes
that key, and every bounded API response returns it explicitly. Agents can use
any returned node as the root of the next request without learning internal
Neo4j IDs or inventing another identity layer.

## Enforced relationship model

Relations are a closed Rust enum. Each variant owns its accepted endpoint kinds. Invalid combinations cannot produce a `RelationshipAssertion`.

Every assertion requires one or more observations from one tenant, source runtime, and collection. The delta must match that tenant and runtime. Cross-tenant values fail before storage.

Incomplete and incremental collections cannot call `retract_missing`. That method exists only on `GraphDeltaBuilder<Authoritative>`, which can be created only from `CompleteCollection`.

## Compliance facts and agent queries

Compliance is part of the organizational graph, not a second graph-shaped
schema. Frameworks, programs, objectives, rules, controls, findings, evidence,
assessment runs, results, snapshots, remediations, verifications, and work
items use the same sealed `Entity` type, tenant identity, observation
provenance, revision, Postgres commit, and Neo4j projection as people,
resources, access, and ownership.

The relationship enum carries the compliance joins. For example, a finding can
be `mapped_to_control`, `affects` a resource, be `detected_by` a rule, and be
`addressed` by a remediation. Evidence can be linked with `evidence_for`;
assessment results can `evaluate` an objective and `cite` evidence. Rust
rejects invalid endpoint combinations before a delta can reach either store.

Agents query these facts through `QueryFacts`. A request contains node
variables, closed entity-kind filters, typed directed edges, optional
`NOT EXISTS` edge checks, stable entity or agent keys, and a result limit. It
cannot contain Cypher. Rust rejects unknown kinds and relations, incompatible
typed endpoints, disconnected positive patterns, more than eight nodes, more
than twelve joins, more than eight absence checks, more than 100 stable keys
per node, duplicate filters, and limits above 500.
Neo4j receives only a statement compiled from that validated structure, with
tenant, values, and the hard row limit passed as parameters. The result carries
the graph revision read in the same Neo4j query as every non-empty match.

The replacement proof commits a compliance snapshot through the Rust durable
store, restarts the Rust service, and executes this query through Connect:

```text
(finding)-[:mapped_to_control]->(control)
    |
    +--[:affects]->(resource)

NOT EXISTS (evidence)-[:evidence_for]->(finding)
```

The proof fails unless the unsupported finding is returned and the
evidence-backed finding is excluded both before and after restart.

## Production bypass prevention

Language-level constraints prevent accidental bypass inside Rust. Production authority prevents deliberate bypass across processes:

1. Only the Rust platform workload receives graph-write credentials.
2. Source collectors run inside the Rust source runtime and receive no graph handle.
3. Go deployments become read-only for each promoted family. A persisted `(tenant, source, family)` authority record selects one writer, including through replay and refetch entry points.
4. The graph store accepts writes only from the Rust workload identity at the network and database authorization layers.
5. CI rejects dependencies from the replacement crates onto Go projection contracts.
6. PostgreSQL forces tenant row-level security on the ledger tables and uses a tenant-scoped unique key for confirmed identity bindings.
7. Neo4j writes are not public API operations. Agent, web, and Slack routes are read-only and hard-bound to six hops and 500 results.
8. The replacement proof builds one Rust image without installing Go. The
   proof driver runs inside that image, rejects a Go server or toolchain,
   restarts the Rust service, and reads the recovered graph through both the
   generated agent RPC and the native product HTTP route.

Before a read family changes authority, the Go API may remain the temporary
read authority while a bounded sample is compared with Rust. That adapter must
return the Go result, tolerate Rust unavailability, emit only bounded comparison
labels, and must not receive graph-write credentials or project graph changes.
Shadow comparisons run outside the request path with the configured timeout
and a fixed 32-operation concurrency ceiling. Saturation records
`status=dropped`; it never queues unbounded work or delays the Go response.

Repository conventions and review are not the security boundary. Store credentials and workload identity are.

## Source coverage migration

Source migration is definition- and family-based, not package-by-package translation.

The append log remains the source-event log of record throughout migration.
Rust records every valid source event in a tenant-scoped, idempotent PostgreSQL
receipt projection before it evaluates family authority. An event from a
legacy or not-yet-cataloged family is retained and acknowledged as legacy; it
is not silently discarded. Reusing an event ID with different content fails
closed. The receipt contains event metadata and content digests, not a second
copy of the raw payload or secret material.

While a family remains legacy-authoritative, the shared Go projection boundary
also sends Rust the exact normalized entities, links, entity retractions, link
retractions, and scoped cleanup requests written for that event. These
compatibility records preserve existing source coverage for parity and replay;
they do not grant Rust graph-write authority and they are not another system of
record.

After each bounded source-runtime sync, the same boundary records a collection
manifest with expected and observed families, page and record counts,
projection counts, and deterministic incompleteness reasons. A completed sync
receipt is coverage evidence only. It does not become an authoritative
`CompleteCollection`, and therefore cannot enable missing-record retraction.

For every existing source family, the parity corpus records:

- provider request and pagination behavior;
- collection scope and completeness;
- emitted provider objects and stable IDs;
- normalized entities and relationship assertions;
- retractions after complete collections;
- graph paths produced from the fixture;
- provider failure and permission states.

`make projection-parity-test` sends the same provider records through the current Go projector and the Rust mapper. The temporary Go adapter emits only catalog-governed semantic facts. Rust validates and compares provider identity, canonical identity, entity, relationship, identity-binding, provenance-observation, and retraction facts. Serialized Go and Rust storage shapes are not compared.

Each receipt binds the tenant, runtime, source, family, collection, exact input digest, both projector revisions, both semantic digests, completeness, mismatch count and bounded mismatch sample, projection lag, runtime versions, and comparison time. PostgreSQL stores the full receipt under forced tenant row-level security.

`CutoverGate` requires complete provider proof, a native projection class, at least three consecutive matching receipts, matching latest corpora, and projection lag within policy. A source family moves only after the ledger evaluates its own stored receipts. Callers cannot submit an approval decision. Promotion records the evidence digest and is irreversible; a later attempt with changed evidence is rejected.

The runtime reads the same authority record before every projection. Legacy authority calls only Go. Rust authority calls only Rust, requires a commit receipt, and fails closed. The compatibility mapper remains available for parity comparison, but it is no longer a write fallback for a promoted family.

The current checked-in catalog compiles to 794 sources and 3,891 families:

| Projection class | Families | Rust meaning |
| --- | ---: | --- |
| Identity | 823 | people, provider identities, groups, memberships, credentials, and applications |
| Access | 371 | policies and application grants |
| Resource | 1,549 | assets, repositories, deployments, devices, cloud resources, and secrets |
| Finding | 407 | findings, vulnerabilities, and alerts |
| Activity | 738 | audit and operational events |
| Bespoke | 3 | retained for source coverage but barred from authority |

Based on exact provider method-and-path proof, resolvable runtime path and query parameters, bounded fanout scopes, and auth support present in this Rust runtime, 46 sources and 328 families are authoritative; the other 748 sources remain shadow-only. This preserves source coverage without converting catalog presence into a false production claim.

## Family cutover

The first cutover unit is one tenant, source, and family. It does not move a whole connector or a whole tenant.

```text
source event
    |
    v
append log commit
    |
    v
PostgreSQL authority lookup
    | legacy                     | rust
    v                            v
Go projector                Rust mapper
                                 |
                                 v
                       PostgreSQL transaction
                                 |
                                 v
                         Neo4j outbox apply
```

`cerebro-platform evaluate-family` evaluates stored parity receipts without changing authority. `cerebro-platform promote-family` repeats that evaluation and records Rust authority. `cerebro-platform show-authority` reads the effective record. These commands use `CEREBRO_POSTGRES_DSN` plus `CEREBRO_TENANT_ID`, `CEREBRO_SOURCE_ID`, and `CEREBRO_SOURCE_FAMILY`.

`cerebro-platform serve-neo4j-readonly` opens only the bounded Neo4j read plane. It does not connect to PostgreSQL, run store migrations, expose a projection runtime, or consume the append log. Use this process for pre-cutover shadow and read canaries. `serve-neo4j` adds the projection API, while `serve-neo4j-consumer` also starts append-log consumption.

Read promotion uses three explicit states. `shadow` always returns Go and
compares a stable sample with Rust. `canary` assigns each tenant to Rust or Go
with a stable hash; a Rust-tenant failure fails closed and never retries
against Go. `authority` returns Rust for every typed read. Raw Cypher is not
part of the canary surface and must be removed before the Go graph store can be
retired.

The canary percentage controls tenant allocation, not a random share of
requests. Monitor `cerebro.organizational_graph.canary.routes` by `authority`,
`status`, `operation`, and `configured_percent` to compare the configured
tenant cohort with actual Go and Rust request volume. These labels are bounded
and never contain tenant or graph identifiers.

During the first low-volume canary, set
`CEREBRO_ORGANIZATIONAL_GRAPH_CANARY_VERIFY_PERCENT=100`. Every selected
Rust-authority read remains Rust-authoritative and is also compared with Go.
The Go verification runs outside the request path under the same bounded
comparison ceiling. Mismatch, Go-oracle failure, or saturation changes only
the verification receipt; it does not delay, replace, or retry the Rust result
through Go. Monitor
`cerebro.organizational_graph.canary.verifications` for `match`, `mismatch`,
`legacy_error`, `comparison_error`, and `dropped`, and compare
`cerebro.organizational_graph.canary.duration` by authority before increasing
the Rust cohort. Reduce the verification percentage independently when the
duplicate Go load is no longer justified.

The append-log consumer defaults to new events. A rebuild uses
`CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY=all`, while a fenced handoff
uses `by_start_sequence` plus
`CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE`. Either replay mode requires
an explicit, separate `CEREBRO_ORGANIZATIONAL_CONSUMER_NAME`; it cannot reuse
the live forward-only durable identity.

Every server mode exposes Prometheus request counters and latency histograms on `/metrics`. Operation labels come from a fixed route vocabulary; tenant IDs, entity IDs, request paths, and evidence do not enter metric labels.

Generated Rust protobuf and Connect modules are wire contracts, not
compatibility authorities. Architecture scans enforce the forbidden legacy
contract rule against handwritten Rust; generated modules may contain unused
declarations from an imported protobuf package, while platform services expose
only explicitly registered Rust-owned methods.

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
