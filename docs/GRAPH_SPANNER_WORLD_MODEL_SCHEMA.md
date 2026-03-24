# Graph Spanner World-Model Schema

This document defines the first world-model-native Spanner target for Cerebro. It is the storage design that should eventually replace the flat `graph_nodes` / `graph_edges` projection when the Spanner backend becomes the primary durable substrate.

See also:

- [GRAPH_STORE_MIGRATION_ARCHITECTURE.md](./GRAPH_STORE_MIGRATION_ARCHITECTURE.md)
- [GRAPH_WORLD_MODEL_ARCHITECTURE.md](./GRAPH_WORLD_MODEL_ARCHITECTURE.md)
- [GRAPH_ONTOLOGY_ARCHITECTURE.md](./GRAPH_ONTOLOGY_ARCHITECTURE.md)

## Canonical Tables

The canonical Spanner ownership model is:

- `entities`: durable world entities and operational resources
- `entity_relationships`: generic entity-to-entity relationships that still behave like graph edges
- `sources`: first-class claim sources and provenance producers
- `evidence`: supporting artifacts
- `evidence_targets`: evidence-to-entity targeting links
- `observations`: raw lower-level observations
- `observation_targets`: observation-to-entity targeting links
- `claims`: first-class claims with explicit bitemporal columns
- `claim_subjects`: claim-to-subject entity links
- `claim_objects`: claim-to-object entity links when the object is another entity
- `claim_sources`: claim-to-source asserted-by links
- `claim_evidence`: claim-to-evidence based-on links
- `claim_relationships`: claim-to-claim support/refute/supersede/contradict links

## Bitemporal Rules

World-model tables carry the same normalized columns Cerebro already uses in graph writes:

- fact time: `observed_at`, `valid_from`, optional `valid_to`
- system time: `recorded_at`, `transaction_from`, optional `transaction_to`
- provenance: `source_system`, `source_event_id`, `confidence`

The point of the schema is to stop hiding these fields only inside JSON blobs. JSON columns remain for residual per-kind properties, but temporal and provenance columns are first-class.

## Property-Graph Projection

The Spanner Graph projection is exposed as `cerebro_world_model`.

Node tables:

- `entities`
- `sources`
- `evidence`
- `observations`
- `claims`

Edge tables:

- `entity_relationships`
- `evidence_targets`
- `observation_targets`
- `claim_subjects`
- `claim_objects`
- `claim_sources`
- `claim_evidence`
- `claim_relationships`

This keeps relational ownership explicit while still enabling bounded graph traversal over the same data.

The specialized link tables now carry explicit `edge_id` columns. That lets the canonical tables reconstruct the current graph-layer edge projection without inventing synthetic IDs during readback.

## Migration Mapping

Current `graph_nodes` / `graph_edges` records should map as follows:

- generic non-knowledge node kinds -> `entities`
- `source` nodes -> `sources`
- `evidence` nodes -> `evidence`
- `observation` nodes -> `observations`
- `claim` nodes -> `claims`
- generic entity-to-entity edges -> `entity_relationships`
- `claim --asserted_by--> source` -> `claim_sources`
- `claim --based_on/supports--> evidence|observation` -> `claim_evidence`
- `claim --supports/refutes/supersedes/contradicts--> claim` -> `claim_relationships`
- `observation --targets--> entity` -> `observation_targets`
- `evidence --targets--> entity` -> `evidence_targets`

For existing generic nodes that do not yet carry full metadata, the migration layer should backfill:

- `observed_at` from node metadata, then `updated_at`, then `created_at`
- `valid_from` from node metadata, then `observed_at`
- `recorded_at` from node metadata, then `updated_at`, then `observed_at`
- `transaction_from` from node metadata, then `recorded_at`
- `source_system` from node metadata, then `provider`, then `unknown`
- `source_event_id` from node metadata, then a deterministic synthetic ID based on node/edge ID plus `recorded_at`

That makes backfills deterministic while keeping the target schema strict.

## Rollout Coexistence

During rollout, flat graph storage and canonical world-model storage should coexist:

- `graph_nodes` / `graph_edges` remain the compatibility projection used by the current graph-store contract.
- canonical world-model tables become the durable ownership layer for entities, claims, observations, evidence, and typed relationships.
- migration and cutover flows should compare both representations from the same logical writes until parity is stable.
- specialized link tables preserve original graph edge IDs so shadow reads and parity reports can compare exact edge identities instead of only tuple keys.
