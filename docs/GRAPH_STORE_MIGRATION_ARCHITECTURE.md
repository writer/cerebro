# Graph Store Migration Architecture

This document captures the current migration path from Cerebro's hot in-memory graph toward durable graph storage that can scale with the world model.

It is intentionally narrower than the ontology and world-model docs. The goal here is to answer one question:

How do we move safely from the current graph runtime to durable Neptune and Spanner backends without corrupting the world model?

See also:

- [GRAPH_HORIZONTAL_SCALING_ARCHITECTURE.md](./GRAPH_HORIZONTAL_SCALING_ARCHITECTURE.md)
- [GRAPH_WORLD_MODEL_ARCHITECTURE.md](./GRAPH_WORLD_MODEL_ARCHITECTURE.md)
- [GRAPH_ONTOLOGY_ARCHITECTURE.md](./GRAPH_ONTOLOGY_ARCHITECTURE.md)
- [GRAPH_INTELLIGENCE_LAYER.md](./GRAPH_INTELLIGENCE_LAYER.md)
- [GRAPH_SPANNER_WORLD_MODEL_SCHEMA.md](./GRAPH_SPANNER_WORLD_MODEL_SCHEMA.md)

## Current Repo State

Cerebro already has a first-generation graph persistence seam:

- `graph.GraphStore` abstracts graph CRUD, snapshot, and traversal operations.
- `*graph.Graph` satisfies that contract for the current in-memory runtime.
- `*graph.NeptuneGraphStore` persists nodes and edges in Neptune through openCypher.
- `*graph.SpannerGraphStore` persists nodes and edges in Cloud Spanner.
- production config already defaults `GRAPH_STORE_BACKEND` to `spanner`

Important caveat:

- Neptune executes bounded graph queries natively.
- Spanner currently persists CRUD in Spanner, but traversal-heavy methods still materialize a snapshot-backed in-memory graph before answering.

That means the durable backend seam exists, but the migration is not done.

## Trade-Offs

### Neptune

What Neptune is good at:

- native property-graph storage
- openCypher and Gremlin support on the same property graph
- direct graph query profiling (`EXPLAIN`) for traversal tuning

What Neptune costs us:

- a separate graph-specialized operational surface
- separate AWS operational model, IAM path, networking path, and cost center
- less natural fit for world-model records that want strong relational structure around bitemporal claims, evidence, and correction history

### Spanner

What Spanner is good at:

- globally distributed, strongly consistent storage
- declarative mapping of relational tables into a property graph without data migration
- explicit schema design tools for interleaving, foreign keys, and change streams

What Spanner costs us:

- graph behavior must be designed over relational tables rather than accepted as the primary storage model
- traversal performance depends on good schema design and, for now, explicit migration away from snapshot materialization
- the current repo schema is still too generic for the full world model

## Why Spanner Is The Long-Term Target

The world model is not just a generic LPG. It needs:

- durable entities
- claims
- observations
- evidence
- support / contradiction / supersession history
- fact time and system time

That is a better fit for:

- relational ownership of canonical records
- explicit temporal columns
- graph projections over those tables for bounded traversal and intelligence queries

Neptune remains useful as:

- a native graph backend option
- a performance reference point for bounded traversal workloads
- a compatibility target while the Spanner world-model schema matures

But Spanner is the better convergence point for Cerebro's long-term intelligence substrate.

## Proposed Migration Phases

### Phase 1: Backend Driver Contract

Issue: `#667`

Goals:

- stop hard-coding backend initialization logic in app init
- codify backend open / bootstrap / probe / close behavior
- add parity tests for backend contract drift

This phase makes the migration seam explicit.

### Phase 2: World-Model-Native Spanner Schema

Issue: `#668`

Goals:

- move from flat `graph_nodes` / `graph_edges` tables toward canonical world-model tables
- carry bitemporal columns explicitly
- define the Spanner Graph projection over those canonical tables

This phase makes the storage model fit the world model instead of forcing the world model into generic JSON blobs.

### Phase 3: Native Spanner Traversal

Issue: `#669`

Goals:

- replace full snapshot materialization for bounded traversals with native Spanner graph queries where possible
- keep snapshot fallback explicit for unsupported paths
- benchmark parity and performance against the in-memory graph and Neptune

This phase removes the largest scaling compromise in the current Spanner backend.

### Phase 4: Cutover Safety

Issue: `#670`

Goals:

- backfill target stores from current graph snapshots
- add parity diff tooling
- add shadow reads and report/traversal comparison before cutover

This phase makes migration operationally safe.

## Safety Tests Required Before Any Cutover

The migration is not safe until Cerebro can prove:

1. Backend contract parity

- CRUD parity across memory, Neptune, and Spanner adapters
- snapshot parity on active/deleted records
- traversal parity for bounded graph routines

2. Temporal parity

- `observed_at` / `valid_from` / `valid_to` round-trip correctly
- `recorded_at` / `transaction_from` / `transaction_to` round-trip correctly
- claim timelines and contradiction grouping remain stable across stores

3. Report parity

- claim conflict reports
- entity summary reports
- evaluation lifecycle / temporal analysis reports
- playbook effectiveness reports

4. Migration parity

- source and target stores agree on counts
- source and target stores agree on representative traversals
- source and target stores agree on representative report outputs

## Spanner World-Model Shape

The target Spanner schema should stop treating world-model semantics as only generic node/edge payloads.

At minimum, Cerebro should move toward:

- `entities`
- `entity_relationships`
- `claims`
- `claim_sources`
- `claim_evidence`
- `observations`
- `evidence`

with explicit temporal columns on durable world-model records:

- `observed_at`
- `valid_from`
- `valid_to`
- `recorded_at`
- `transaction_from`
- `transaction_to`

The property graph exposed through Spanner Graph should be treated as a query projection over canonical tables, not as the only source of truth.

## Design Rules

1. Keep the durable storage model explicit and relational where the world model needs correctness.
2. Use graph projections for traversal and intelligence, not as an excuse to hide temporal semantics in blobs.
3. Treat Neptune as a supported backend and a parity reference, not the inevitable end state.
4. Do not cut over until parity can be measured, replayed, and audited.
