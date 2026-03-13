# Graph Horizontal Scaling Architecture

Issue `#221` is the decision gate between the current single-process hot graph and the later high-availability / tenant-partitioned graph work in `#246` and `#247`.

## Why This Exists

The current graph model is intentionally simple:

- one in-memory hot graph
- copy-on-write clone/mutate/index/swap on writes
- snapshot/diff support for persistence and recovery
- a shared execution-store seam for durable execution state

That has been the right tradeoff while the graph substrate was still moving. It is no longer enough to say "SQLite won't scale" or "we need distributed graph persistence" without profiling the current graph path first.

`#221` exists to answer three concrete questions:

1. At what resource tier does the current hot graph become expensive enough that it should stop being the only authoritative runtime representation?
2. Which operation fails first: build/index, query latency, copy-on-write mutation, or snapshot/diff?
3. What should Cerebro build next: external graph DB, sharded in-memory graph, or a hybrid model with durable graph backing?

## Executable Profiling Surface

Cerebro now has an executable benchmark:

```bash
cerebro graph profile-scale --output table
cerebro graph profile-scale --output json --query-iterations 3
```

The profiler uses a deterministic synthetic estate with:

- accounts
- roles and assume/admin access edges
- services
- workloads, buckets, databases, and functions
- exposed resources and dependency chains

It measures, per tier:

- build time
- index build time
- search latency
- suggest latency
- cold and warm blast-radius latency
- snapshot compression size/time
- clone cost
- copy-on-write mutation cost
- snapshot diff cost
- heap allocation footprint

Default tiers:

- `1,000`
- `10,000`
- `50,000`
- `100,000`

## Research We Are Stealing From

Useful reference points pulled through `gh`:

- `dagster-io/dagster`
  - durable run/storage seams first, richer indexing second
- `temporalio/temporal`
  - execution coordination belongs in durable state, not process-local memory
- `OpenLineage/OpenLineage`
  - typed lineage/state contracts are easier to move across backends than implicit runtime glue
- `open-metadata/OpenMetadata`
  - broad metadata/query surfaces stay tractable only when the underlying persisted model is explicit
- `neo4j/neo4j` and `dgraph-io/dgraph`
  - useful warning and option set, but both imply a much larger programming-model shift than Cerebro currently needs

The local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces the same lesson from the product side:

- very broad query surfaces are manageable only when pagination, counts, and typed connection resources stay explicit
- the right next step for Cerebro is not "replace everything with a graph DB"
- the right next step is "keep the hot graph query surface small and typed, while making persistence and execution durable enough for horizontal scale"

## Current Read On The Breakpoint

Local baseline runs on this branch already show the breakpoint clearly enough to make the next decision.

Measured with:

```bash
cerebro graph profile-scale --output json --query-iterations 1 --tiers 1000
cerebro graph profile-scale --output json --query-iterations 1 --tiers 10000
```

Observed results:

- `1K` resources
  - elapsed: `8.5s`
  - heap alloc: `8.1 MiB`
  - index build: `39.9 ms`
  - search: `107.2 ms`
  - blast radius (cold): `4.6 ms`
  - copy-on-write: `43.6 ms`
  - recommendation: `single_node_with_replicated_snapshots`
- `10K` resources
  - elapsed: `15.5s`
  - heap alloc: `79.1 MiB`
  - index build: `506.7 ms`
  - search: `11331.6 ms`
  - blast radius (cold): `25.3 ms`
  - copy-on-write: `533.6 ms`
  - recommendation: `tenant_sharded_hot_graph`

Higher-tier attempts are already enough to show the boundary:

- the `50K` single-tier run exceeded `2.5m` elapsed and reached roughly `1.6 GiB` RSS before completion
- the aggregated `1K -> 10K -> 50K -> 100K` run exceeded `5m` elapsed and pushed roughly `1.7 GiB` RSS before completion

That is already enough to reject two bad instincts:

1. keep deepening single-process in-memory as the only graph runtime
2. jump straight to an external graph database before using the persistence seams Cerebro already has

## Recommended Path

The recommended scale path is:

### 1. Hybrid hot graph + durable graph backing

Keep a hot in-memory graph for low-latency read patterns:

- entity search
- typed facets
- knowledge reads
- attack-path / blast-radius style traversals

But stop treating that hot graph as the only durable runtime artifact.

The full graph state should move toward:

- durable snapshot manifests
- durable snapshot artifacts
- durable incremental mutation / CDC logs
- replayable graph rebuild inputs

### 2. Single writer, multi-reader before multi-writer

For `#246`, the first HA step should not be active-active graph mutation.

It should be:

- one leased graph writer / rebuilder
- replicated durable snapshots
- follower processes that hydrate read-only hot graphs from the latest durable snapshot
- shared execution records for rebuild/apply/projection jobs

That keeps correctness manageable while removing single-node durability risk.

### 3. Partition by tenant/account before considering graph-DB migration

For `#247`, tenant/account partitioning should happen on the current graph substrate before any radical database transition.

That means:

- tenant-scoped graph snapshots
- tenant/account-scoped hot graph hydration
- tenant-scoped query guards and audit
- explicit cross-tenant joins only through audited higher-level report/intelligence jobs

### 4. Do not jump to Neo4j/Dgraph yet

An external graph database remains an option, but it is not the next step.

Why not:

- it would force a programming-model rewrite across entity, knowledge, risk, and report surfaces
- it would not remove the need for durable execution state
- it would likely slow the current pace of graph-surface evolution more than it would help near-term customer scale

The hybrid path uses existing seams and keeps optionality open.

## What `#246` Should Actually Build

`#246` should implement:

- durable graph snapshot manifests and lineage
- replicated/object-backed graph snapshot storage
- graph hydration from durable snapshots into hot read graphs
- one writer lease / ownership model for graph rebuild and CDC apply
- health/readiness around snapshot freshness and hydration lag

It should not start by replacing the query engine.

## What `#246` Now Implements

The first concrete `#246` cut is now in the repo:

- a shared app-owned graph persistence store, parallel to the shared execution store
- automatic snapshot persistence on graph activation
- recovery from the latest persisted snapshot before the warehouse rebuild completes
- replica-aware fallback for graph snapshot APIs, temporal diff paths, and tool diff helpers
- pluggable replica backends for:
  - local filesystem mirrors (`file://` or plain path)
  - Amazon S3 (`s3://bucket/prefix`)
  - Google Cloud Storage (`gs://bucket/prefix`)
- persistence health reporting through the app health registry

That means Cerebro now has the first durable graph-runtime seam needed for:

- rolling deployments without throwing away the only durable graph artifact
- follower/read replica hydration in a later cut
- one-writer lease semantics in a later cut
- tenant/account partitioned hydration in `#247`

It still intentionally does **not** solve:

- lease election / writer fencing
- follower promotion logic
- replica lag metrics and automatic repair
- tenant/account graph partitioning

Those remain the next layers on top of the shared persistence substrate.

## What `#247` Should Actually Build

`#247` should implement:

- tenant-scoped graph IDs / partition keys
- tenant/account-scoped query APIs and graph hydration
- tenant-safe cache keys and execution keys
- audit trail for cross-tenant graph access

It should not be layered on top of an undefined persistence model.

## Exit Criteria For `#221`

This issue is done when Cerebro has:

- an executable profiling command
- measured tier outputs for `1K/10K/50K/100K`
- an explicit recommendation for the next persistence path
- a clear dependency chain into `#246` and `#247`

That is the bar this cut is meant to satisfy.
