# Spanner Graph GQL Traversals

`#694` moves Cerebro's first bounded traversal family off Neptune/openCypher assumptions and onto the documented Spanner Graph model.

## Scope

- `BlastRadius`
- `ReverseAccess`
- `EffectiveAccess`
- `ExtractSubgraph`

`CascadingBlastRadius` intentionally stays on the explicit snapshot fallback for now because it still needs wider recursive fan-out semantics than the first bounded query builder exposes.

## Query Shape

The native path builds `GRAPH_TABLE(...)` statements over the `cerebro_graph_store` property graph defined in [spanner_graph_store.sql](../internal/graph/schema/spanner_graph_store.sql). The current builder emits fixed-length `MATCH TRAIL` unions instead of relying on Neptune-style openCypher compatibility assumptions.

That does two things:

1. It keeps Cerebro aligned with the documented Spanner Graph SQL/PGQ surface.
2. It preserves relationship-unique path semantics with `TRAIL`, which is the closest match to the current bounded traversal behavior.

## Semantic Gaps

- Spanner Graph is treated as a GQL/SQL `GRAPH_TABLE` surface here, not as a native openCypher endpoint.
- The builder expands bounded path lengths explicitly. That is more verbose than Neptune's quantified openCypher patterns, but it gives deterministic edge rows that map cleanly back into Cerebro's existing `Edge` records.
- Native graph queries are opt-in through `WithSpannerNativeTraversalQueries(true)`. The existing lookup-based traversal path remains the default fallback until production parity is proven on live Spanner datasets.

## Rollout

- Test and parity harnesses should enable the native path explicitly.
- Production wiring should stay on the fallback path until live Spanner validation and benchmark data from `#697` confirm the native query path is equivalent and worth enabling by default.
