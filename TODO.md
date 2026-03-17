# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-16 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

## Deep Review Cycle 162 - Streaming Snapshot Serialization Slice (2026-03-16)

### Review findings
- [x] Gap: issue `#386` is real because `SnapshotStore.SaveGraph()` still materialized a full in-memory `Snapshot` before gzip encoding, preserving the monolithic serialization spike on the main persistence path.
- [x] Gap: the lowest-risk first slice is the write path, not a full storage-format migration; the store can stream graph artifacts directly while the loader remains backward-compatible with legacy snapshot files.
- [x] Gap: the graph package had no regression coverage proving a persisted snapshot artifact could use a streaming format without breaking `LoadSnapshotFromFile`, and no benchmark comparing the new writer against the legacy monolithic encode path.

### Execution plan
- [x] Add a streaming compressed snapshot writer for live graphs with:
  - [x] explicit stream magic
  - [x] typed header/node/edge/footer records
  - [x] backward-compatible loader support for both legacy and streaming artifacts
- [x] Switch `SnapshotStore.SaveGraph()` to the streaming writer so the hot persistence path no longer depends on `CreateSnapshot()`.
- [x] Add TDD coverage for:
  - [x] legacy artifact compatibility
  - [x] streaming artifact persistence and load round-trip
  - [x] legacy-vs-streaming compressed write benchmark
- [ ] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 161 - Runtime Admission Policy Substrate (2026-03-16)

### Review findings
- [x] Gap: issue `#361` had no concrete admission-control substrate in the runtime package, so every caller would have to re-encode lag and memory thresholds ad hoc.
- [x] Gap: the current codebase already has normalized runtime observations and findings, which makes priority classification the lowest-risk first slice before any consumer or graph integration.
- [x] Gap: there was no regression coverage locking down the boundary behavior for green/yellow/red transitions or which priorities survive at each level.

### Execution plan
- [x] Add runtime admission levels and pressure inputs for:
  - [x] consumer lag
  - [x] memory utilization
- [x] Add priority classification helpers for:
  - [x] generic event types
  - [x] normalized runtime observations
  - [x] runtime findings
- [x] Add admit/drop helpers that enforce:
  - [x] green accepts all
  - [x] yellow sheds low-priority work
  - [x] red admits only critical work
- [x] Re-run focused runtime tests, lint, and changed-file validation.

## Deep Review Cycle 160 - Runtime Risk Signals In Workload Security Facet (2026-03-16)

### Review findings
- [x] Gap: issue `#370` had no graph-side substrate for runtime-aware workload risk; static scan facets could not distinguish a dark workload from one with active runtime findings.
- [x] Gap: runtimegraph already projects workload-targeted observations and finding evidence, so the cheapest first slice is a read-side signal summary instead of a new scoring engine.
- [x] Gap: the workload security facet had no regression coverage proving runtime darkness and active multi-technique findings change the facet assessment and exposed fields.

### Execution plan
- [x] Add a graph helper that summarizes workload runtime signals at a bitemporal slice:
  - [x] observation count
  - [x] runtime finding count
  - [x] distinct MITRE technique count
  - [x] dark-workload detection
  - [x] composite runtime multiplier
- [x] Surface runtime signal fields in the workload security facet.
- [x] Make the facet warn on dark workloads and fail on active runtime findings.
- [x] Add TDD coverage for:
  - [x] dark workload penalty
  - [x] active runtime finding escalation
  - [x] multi-technique multiplier
- [x] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 158 - Runtime Graph Materialization Coverage Expansion (2026-03-16)

### Review findings
- [x] Gap: runtimegraph had targeted tests for individual behaviors, but it still lacked one representative integration pass proving the main runtime observation kinds materialize into valid graph observation nodes and `targets` edges end to end.
- [x] Gap: the supported observation kinds now span workload-scoped and service-scoped subjects, so coverage needed to lock down both reverse-edge behavior for workload subjects and the absence of that reverse edge for service subjects.
- [x] Gap: future causal-link slices (`067`, `068`) build on these node and edge shapes, so representative materialization coverage is the cheapest place to catch summary, subject, or schema regressions before they fan out.

### Execution plan
- [x] Add a representative integration test matrix covering:
  - [x] file writes
  - [x] network flows
  - [x] DNS queries
  - [x] Kubernetes audit observations
  - [x] runtime alerts
  - [x] trace links
- [x] Validate for each case:
  - [x] observation node creation
  - [x] normalized summary/detail fields
  - [x] `targets` edge schema validity
  - [x] reverse workload-edge presence or absence as appropriate
- [x] Re-run focused runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 159 - Runtime Dedup Bloom Fast Path (2026-03-16)

### Review findings
- [x] Gap: issue `#351` is real on the runtime ingest hot path because every source event still paid a read-before-write SQLite round trip just to learn that a brand-new event key had never been seen.
- [x] Gap: the fast path still needs to preserve durable dedupe correctness for in-flight processing claims, so the optimization cannot simply skip persistence or trust a stale in-memory filter as authoritative.
- [x] Gap: there was no regression coverage proving startup bloom hydration avoids the extra duplicate-path fast-claim attempt, that unseen events take the optimized insert-only path, or that the filter stays within a defensible false-positive envelope.

### Execution plan
- [x] Add a lightweight in-memory bloom filter for runtime processed-event keys with rebuild support from the durable execution store.
- [x] Add an execution-store fast claim primitive that uses insert-or-ignore semantics so bloom misses avoid the expensive read-before-write query while still taking a durable claim.
- [x] Keep correctness conservative by falling back to the existing full claim path on conflicts and by leaving direct duplicate lookups backed by SQLite.
- [x] Add TDD coverage for:
  - [x] fast-claim insertion behavior
  - [x] active-key listing and expired-key pruning
  - [x] runtime ingest fast path for unseen events
  - [x] startup bloom hydration for existing duplicates
  - [x] bloom-filter false-positive envelope
- [x] Add a benchmark for new-event claim throughput with and without the bloom fast path.
- [x] Re-run focused runtime/executionstore tests, lint, changed-file validation, and the new benchmark.

## Deep Review Cycle 157 - Runtime Observation Causal Links To Kubernetes Audit Events (2026-03-16)

### Review findings
- [x] Gap: runtime observations can already project into graph `observation` nodes, but the graph still had no causal bridge back to the Kubernetes audit observations that often explain why a workload changed immediately before a runtime signal appeared.
- [x] Gap: this correlation also needs to stay conservative; if multiple recent audit observations touch the same subject, the projector should skip the causal edge instead of inventing provenance.
- [x] Gap: runtimegraph had no regression coverage proving audit-observation causal edges can be created, suppressed on ambiguity, and deduplicated across repeated materialization passes.

### Execution plan
- [x] Add a Kubernetes-audit matcher in runtimegraph that requires:
  - [x] one concrete shared subject ID
  - [x] exactly one recent prior `k8s_audit` observation node for that subject
  - [x] a bounded pre-observation time window
- [x] Materialize `observation -> based_on -> observation(k8s_audit)` edges with subject and time-gap metadata.
- [x] Add TDD coverage for:
  - [x] unique audit correlation
  - [x] ambiguity skip behavior
  - [x] idempotent repeated projection
- [x] Re-run focused runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 158 - Graph Operation Metrics (2026-03-16)

### Review findings
- [x] Gap: issue `#349` is real because the graph hot path still exposes no first-class metrics for mutation cost, index rebuild cost, search latency, snapshot duration, snapshot size, clone cost, or live node/edge counts.
- [x] Gap: the current graph code was triggering implicit index builds from entity search without any way to distinguish search-triggered rebuilds from explicit manual rebuilds in Prometheus.
- [x] Gap: there was no regression coverage proving the new graph metric helpers are registered, incremented on the real graph paths, and updated when the app swaps the active security graph.

### Execution plan
- [x] Add Prometheus metrics and helpers for:
  - [x] graph index build duration by trigger
  - [x] mutation latency by operation
  - [x] search latency by query type
  - [x] snapshot duration by operation
  - [x] snapshot size bytes
  - [x] live node and edge counts
  - [x] clone duration
- [x] Instrument graph mutation, search, index-build, snapshot, and clone paths with those helpers.
- [x] Publish active graph node and edge gauges from `setSecurityGraph()` so only the live security graph drives the exported counts.
- [x] Add TDD coverage for:
  - [x] metric helper registration and observation
  - [x] integrated graph metric emission across mutation/search/snapshot/clone flows
  - [x] app-layer live graph count publication and reset
- [x] Re-run focused graph/app/metrics tests, lint, and changed-file validation.

## Deep Review Cycle 156 - Runtime Observation Causal Links To Deployment Runs (2026-03-16)

### Review findings
- [x] Gap: runtime observation projection already materializes `observation` nodes, but there was still no causal link back to the one deployment run most likely to have introduced the observed behavior when service and time evidence are both strong.
- [x] Gap: this correlation needs to stay conservative; multiple recent deployments on the same service should suppress the edge rather than guessing a cause.
- [x] Gap: runtimegraph had no regression coverage proving deployment-run causal edges can be added for workload-scoped observations with service metadata, skipped on ambiguity, and deduplicated across repeated materialization passes.

### Execution plan
- [x] Add a deployment-run matcher in runtimegraph that requires:
  - [x] one derivable service ID for the observation
  - [x] exactly one recent `deployment_run` targeting that service
  - [x] a bounded pre-observation time window
- [x] Materialize `observation -> based_on -> deployment_run` edges with service and time-gap metadata.
- [x] Add TDD coverage for:
  - [x] unique deployment correlation
  - [x] ambiguity skip behavior
  - [x] idempotent repeated projection
- [x] Re-run focused runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 155 - Runtime Response Outcome Causal Links To Findings (2026-03-16)

### Review findings
- [x] Gap: runtime response executions already carry `finding_id` through remediation trigger data, but the normalized `response_outcome` observations were discarding that causal reference before graph materialization.
- [x] Gap: issue `#366` is only partially complete without a causal edge from response outcomes back to the promoted runtime finding evidence they are acting on.
- [x] Gap: the runtimegraph package had no regression coverage proving response outcomes add a `based_on` edge when evidence exists, skip it safely when evidence is absent, and remain idempotent on repeated materialization.

### Execution plan
- [x] Preserve `finding_id` in `observationFromResponseExecution`.
- [x] Add response-outcome `based_on` edges from observation nodes to runtime finding evidence nodes when the evidence node is already present.
- [x] Add TDD coverage for:
  - [x] `finding_id` preservation on response-outcome normalization
  - [x] response-outcome causal edge creation
  - [x] missing-evidence skip behavior
  - [x] idempotent repeated projection
- [x] Re-run focused runtime/runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 154 - Lazy Entity Suggest Index Construction (2026-03-16)

### Review findings
- [x] Gap: issue `#372` is only partially addressed in the current tree; runtime `observation` and `evidence` nodes are already excluded from entity search, but `BuildIndex()` still eagerly expands every search suggestion prefix for every searchable node on every rebuild.
- [x] Gap: the eager prefix expansion work is independent from token/trigram indexing, so it is wasted on callers that only need graph indexes, entity search, or runtimegraph finalization and never call entity suggestions.
- [x] Gap: the graph package had no regression coverage proving suggestion prefixes can be deferred until the first short-query search or explicit `SuggestEntities()` call.

### Execution plan
- [x] Keep `BuildIndex()` responsible for entity search documents plus token/trigram indexes only.
- [x] Add an on-demand suggestion-index builder shared by:
  - [x] short-query `SearchEntities`
  - [x] `SuggestEntities`
- [x] Add TDD coverage for:
  - [x] deferring suggestion-index construction after `BuildIndex()`
  - [x] preserving short-query search behavior after lazy construction
  - [x] existing exclusion of runtime artifacts from entity search
- [x] Add a graph benchmark covering repeated `BuildIndex()` on a large entity-search corpus.
- [x] Re-run focused graph/entity-search tests, lint, and changed-file validation.

## Deep Review Cycle 151 - SetNodeProperty PreviousProperties Narrowing (2026-03-16)

### Review findings
- [x] Gap: issue `#379` is real on the hot path because `SetNodeProperty()` was deep-cloning the entire node property map into `PreviousProperties` on every single-key update.
- [x] Gap: the existing temporal tests only required `PreviousProperties` to preserve the prior value for the changed key; they did not require a full snapshot of unrelated keys.
- [x] Gap: the graph package had no benchmark locking down `SetNodeProperty()` allocation behavior for a realistic runtime-observation-sized property map.

### Execution plan
- [x] Narrow `SetNodeProperty()` so `PreviousProperties` stores only the previous value for the touched key.
- [x] Reuse the small `PreviousProperties` map instead of re-allocating/cloning the whole property bag on each update.
- [x] Preserve deep-copy behavior for composite prior values so callers do not retain aliases into mutable old state.
- [x] Add regressions for:
  - [x] unchanged keys omitted from `PreviousProperties`
  - [x] composite previous-value cloning
- [x] Add a focused benchmark for `SetNodeProperty()` on a 20-property node.
- [x] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 150 - Runtime Observation Metadata Allocation Trim (2026-03-16)

### Review findings
- [x] Gap: issue `#374` is real on the current runtime observation materialization path because each observation still pays multiple metadata-map allocations even before the graph stores the node and edge.
- [x] Gap: `observationMetadata()` and `WriteMetadata.PropertyMap()` were both building small fixed-shape maps without any capacity hint, which causes avoidable growth churn across large observation batches.
- [x] Gap: `WriteMetadata.ApplyTo()` was allocating a full temporary metadata map just to copy the same fixed fields back into another map, and `WriteObservation()` was cloning a freshly allocated edge-property map before inserting it into the graph.
- [x] Gap: the runtimegraph package had no benchmark locking down observation-write allocation behavior after the deferred-finalization changes.

### Execution plan
- [x] Pre-size the fixed-shape observation metadata map in `internal/runtimegraph/materializer.go`.
- [x] Pre-size `WriteMetadata.PropertyMap()` and make `ApplyTo()` write fields directly without allocating an intermediate map.
- [x] Stop cloning the freshly allocated observation `targets` edge-property map in `internal/graph/knowledge_observations.go`.
- [x] Add allocation benchmarks for:
  - [x] `BuildObservationWriteRequest`
  - [x] `WriteObservation`
- [x] Re-run focused runtimegraph/graph tests, lint, and changed-file validation.

## Deep Review Cycle 144 - Runtime Response Outcome Target Edges (2026-03-16)

### Review findings
- [x] Gap: response executions were already normalized into `response_outcome` observations, but the graph `targets` edges still carried only generic observation timing/source metadata and dropped the response execution/action context that makes those target links actionable.
- [x] Gap: the runtimegraph package had no regression coverage proving response outcome observations preserve execution/policy/action metadata on the graph edge that links the outcome back to its target workload.
- [x] Gap: the graph package lacked a small, safe helper for enriching an existing edge in place by ID, which forced any runtimegraph response-edge enrichment to either duplicate lookup logic or mutate edge pointers ad hoc.

### Execution plan
- [x] Add a graph helper to merge properties onto an existing active edge by ID.
- [x] Enrich response-outcome `targets` edges with:
  - [x] `response_execution_id`
  - [x] `response_policy_id`
  - [x] `response_action_type`
  - [x] `response_action_status`
- [x] Apply the same response metadata to the reverse workload -> observation `targets` edge when present.
- [x] Add TDD coverage for:
  - [x] graph edge property merging
  - [x] response-outcome forward target-edge metadata
- [x] response-outcome reverse target-edge metadata
- [x] Re-run focused runtimegraph/graph tests and lint.

## Deep Review Cycle 148 - Deleted Node Tombstone Compaction (2026-03-16)

### Review findings
- [x] Gap: the graph already exposes `CompactDeletedEdges()`, but soft-deleted nodes remained in the backing `nodes` map indefinitely after `RemoveNode`, which matches issue `#377` and causes tombstone accumulation in long-lived graphs.
- [x] Gap: scans like `GetAllNodesIncludingDeleted()` and other map-wide maintenance paths still paid for deleted-node tombstones even when active-node counts were unchanged.
- [x] Gap: node compaction needed explicit index-invalidating behavior only when entries were actually removed, otherwise maintenance calls would create avoidable secondary-index churn.

### Execution plan
- [x] Add `CompactDeletedNodes()` to prune soft-deleted and nil node entries from the backing node map.
- [x] Keep compaction side effects cheap by invalidating indexes only when compaction removes at least one entry.
- [x] Add TDD coverage for:
  - [x] removing deleted-node tombstones from the backing map
  - [x] preserving active node counts across compaction
  - [x] leaving indexes current on no-op compaction and invalidating only on real removals
- [x] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 152 - Snapshot Restore Batch Rehydration (2026-03-16)

### Review findings
- [x] Gap: `RestoreFromSnapshot` still rebuilt graphs by calling `AddNode` and `AddEdge` for every serialized entry, which matches issue `#378` and turns large snapshot restores into avoidable repeated lock acquisition and mutation-wrapper overhead.
- [x] Gap: the graph package already has internal locked mutation helpers that preserve restore semantics, so snapshot rehydration can collapse into a single critical section without duplicating node or edge mutation logic.
- [x] Gap: the snapshot restore path lacked focused regression coverage for invalid-entry skipping and had no benchmark anchored on restore throughput for larger snapshots.

### Execution plan
- [x] Rework `RestoreFromSnapshot` to rebuild graphs inside one locked bulk pass via the existing internal mutation helpers.
- [x] Preserve current skip behavior for nil and structurally invalid nodes or edges during restore.
- [x] Add focused regression coverage for invalid-entry skipping and metadata preservation.
- [x] Add a restore benchmark for a multi-thousand-node snapshot.
- [x] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 153 - Blast Radius Cache Version-Only Invalidation (2026-03-16)

### Review findings
- [x] Gap: graph mutation already increments a blast-radius cache version, but `markGraphChangedLocked` was still doing a full `sync.Map.Range+Delete` sweep on every mutation, which matches issue `#380` and makes every write scale with the current cache size.
- [x] Gap: blast-radius cache entries already include a version stamp and are keyed by stable `(principalID, maxDepth)` tuples, so a version mismatch is sufficient to invalidate stale entries without eagerly deleting the whole map.
- [x] Gap: the graph tests covered cache correctness but did not prove that post-mutation invalidation preserves cache slots and recomputes by version instead of by full-map eviction.

### Execution plan
- [x] Remove eager `blastRadiusCache.Range+Delete` invalidation from graph mutations.
- [x] Keep invalidation correctness by relying on `blastRadiusVersion` mismatch during cache reads.
- [x] Add TDD coverage proving:
  - [x] cached blast-radius entries survive graph mutation structurally
  - [x] stale entries still force recomputation after mutation
  - [x] recomputation overwrites existing cache keys instead of growing the map
- [x] Re-run focused graph tests, lint, and changed-file validation.

## Deep Review Cycle 143 - Runtime Graph Deferred Index Finalization (2026-03-16)

### Review findings
- [x] Gap: runtime observation and evidence materializers were each calling `BuildIndex()` after every batch, which directly matches issue `#371` and makes batched runtime graph projection pay repeated full-index rebuild cost.
- [x] Gap: the eager index rebuilds were bundled together with graph metadata refresh, so callers had no way to defer expensive secondary-index work while still keeping node/edge counts and build timestamps current between batches.
- [x] Gap: the runtimegraph package had no explicit regression coverage proving that batched materialization can intentionally leave indexes stale until one caller-controlled finalization step.

### Execution plan
- [x] Split runtimegraph materialization finalization into:
  - [x] cheap metadata refresh after each batch
  - [x] explicit caller-controlled graph finalization for index rebuilds
- [x] Remove eager `BuildIndex()` calls from:
  - [x] observation materialization
  - [x] evidence materialization
- [x] Add `FinalizeMaterializedGraph` so callers can rebuild indexes once after multiple batches.
- [x] Add TDD coverage for:
  - [x] deferred index rebuild after observation projection
  - [x] deferred index rebuild after evidence projection
- [x] Add a benchmark covering repeated observation batches followed by one finalization pass.
- [x] Re-run focused runtimegraph/graph tests, lint, and changed-file validation.

## Deep Review Cycle 145 - Constant-Time Graph Node and Edge Counts (2026-03-16)

### Review findings
- [x] Gap: `NodeCount()` and `EdgeCount()` were still full-map/full-adjacency scans, which issue `#376` correctly called out as a hot-path tax on runtimegraph metadata refresh, health checks, snapshot creation, and multiple app/report paths.
- [x] Gap: graph mutation helpers already centralize the active/inactive transitions for nodes and edges, so the graph had a precise seam for exact counters without inventing approximate background recounts.
- [x] Gap: the existing tests asserted point counts in a few places but did not explicitly prove counter parity across mixed mutation, clear, and snapshot-restore flows.

### Execution plan
- [x] Add exact active node and edge counters to `Graph`.
- [x] Maintain those counters across:
  - [x] node add/upsert and revive paths
  - [x] edge add paths
  - [x] direct edge removal
  - [x] node removal and incident-edge deletion
  - [x] graph and edge clearing
- [x] Switch `NodeCount()` and `EdgeCount()` to constant-time reads.
- [x] Add TDD coverage for:
  - [x] mixed mutation parity against a full scan
  - [x] snapshot restore parity
- [x] Add microbenchmarks for large-graph `NodeCount()` and `EdgeCount()`.
- [x] Re-run focused graph tests and lint, then repo-wide tests.

## Deep Review Cycle 147 - Graph Property History TTL and Depth Controls (2026-03-16)

### Review findings
- [x] Gap: node `PropertyHistory` was still effectively unbounded for long-lived high-churn nodes because the only guardrail was a hardcoded per-property cap buried inside the graph package.
- [x] Gap: there was no write-path TTL trimming, so long-idle snapshots accumulated until an explicit compaction pass, which is the wrong place to enforce a hard memory bound.
- [x] Gap: operators had no metric or env-backed control surface for property-history retention, so graph memory growth from runtime-heavy workloads was not observable or tunable.
- [x] Gap: long-horizon graph tests that intentionally reason across multi-week temporal history needed explicit larger TTLs once the new default seven-day retention started applying on writes.

### Execution plan
- [x] Replace the hardcoded temporal history cap with per-graph retention config defaults:
  - [x] max entries default `50`
  - [x] TTL default `7d`
- [x] Trim expired and over-cap snapshots on every property-history write.
- [x] Reuse the same bounded trimming for temporal compaction output.
- [x] Add TDD coverage for:
  - [x] max-entry enforcement
  - [x] TTL trimming on the next write
  - [x] snapshot size shrink after TTL enforcement
- [x] Wire env-backed controls:
- [x] `GRAPH_PROPERTY_HISTORY_MAX_ENTRIES`
- [x] `GRAPH_PROPERTY_HISTORY_TTL`
- [x] Expose `cerebro_graph_property_history_depth`.
- [x] Update the affected long-horizon graph test to request an explicit larger TTL instead of depending on effectively infinite history.

## Deep Review Cycle 136 - Runtime Service Identity Binding (2026-03-16)

### Review findings
- [x] Gap: shared runtime observation normalization already bound cluster, namespace, workload, container, image, and principal identity, but service identity was still trapped inside source-specific adapters instead of being normalized once at the shared runtime layer.
- [x] Gap: legacy `RuntimeEvent` ingestion could carry `service_name`, `service_namespace`, `trace_id`, and `span_id` metadata without reconstructing a `TraceContext`, which meant service-scoped resource identity was silently lost on the compatibility path.
- [x] Gap: the service-binding seam needed explicit precedence coverage so workload and container identity continue to win when both stronger identities and service metadata are present on the same observation.
- [x] Gap: adapter-provided non-service `resource_id` values were incorrectly blocking service binding even when no higher-precedence workload or container identity existed.

### Execution plan
- [x] Reconstruct `TraceContext` from runtime metadata during `ObservationFromEvent`.
- [x] Bind service resource identity from shared normalized observation context when a service name is present and workload/container identity is absent.
- [x] Fall back namespace binding from `service_namespace` metadata when Kubernetes namespace is unavailable.
- [x] Keep service identity out of the workload-ref backfill path.
- [x] Add regressions for:
  - [x] direct normalization from `TraceContext` plus metadata
  - [x] legacy event reconstruction from metadata
  - [x] workload/container precedence over service identity
  - [x] adapter `resource_id` fallback to service identity

## Deep Review Cycle 137 - Runtime Identity Conflict and Partial Metadata Coverage (2026-03-16)

### Review findings
- [x] Gap: shared runtime identity binding still treated whitespace-only metadata as authoritative because `firstNonEmptyRuntime` returned raw strings instead of trimmed values.
- [x] Gap: that allowed partial metadata like `principal_id=\" \"` or `namespace=\" \"` to block stronger fallbacks from process actors, workload resource IDs, and container resource IDs.
- [x] Gap: the runtime visibility backlog explicitly calls for conflict and partial-metadata coverage before graph materialization builds on top of the normalized identity layer.

### Execution plan
- [x] Trim candidate values inside the shared `firstNonEmptyRuntime` helper so whitespace-only metadata no longer wins precedence checks.
- [x] Add regressions covering:
  - [x] whitespace-only metadata vs process-user principal fallback
  - [x] whitespace-only namespace metadata vs workload namespace backfill
  - [x] whitespace-only container metadata vs container resource-id backfill
- [x] Re-run focused runtime tests and lint on the shared normalization package.

## Deep Review Cycle 138 - Runtime Observation Graph Materializer Package (2026-03-16)

### Review findings
- [x] Gap: the graph layer already has a generic `WriteObservation` path, but the runtime subsystem still lacks a dedicated seam that turns normalized `RuntimeObservation` records into graph observation write requests.
- [x] Gap: without a runtime-specific materializer package, later graph projection slices would either duplicate runtime-to-graph field mapping in multiple places or push runtime-specific subject-selection logic into the generic graph package.
- [x] Gap: runtime observations need deterministic graph IDs, concrete subject selection, and compact summary/metadata shaping before they can be written safely as first-class graph observations.

### Execution plan
- [x] Add a dedicated `internal/runtimegraph` package for runtime observation graph materialization helpers.
- [x] Convert normalized runtime observations into `graph.ObservationWriteRequest` values with:
  - [x] deterministic observation IDs
  - [x] concrete subject selection
  - [x] normalized temporal metadata
  - [x] compact runtime-specific summary fields
- [x] Add TDD coverage for:
  - [x] workload-subject precedence
  - [x] service-resource fallback
  - [x] concrete control-plane resource handling
  - [x] rejection when no concrete graph subject exists
- [x] Re-run focused runtime/runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 139 - Runtime Observation Node Projection (2026-03-16)

### Review findings
- [x] Gap: the new runtime graph materializer seam can build `graph.ObservationWriteRequest` values, but nothing is using it yet to project normalized runtime observations into first-class graph `observation` nodes.
- [x] Gap: graph projection needs explicit skip semantics for observations that still have no concrete subject or that reference graph subjects not present in the current graph snapshot.
- [x] Gap: the runtime graph projection step should update graph indexes and metadata after bulk writes so downstream queries see consistent node/edge counts on the same pass.

### Execution plan
- [x] Add runtime observation projection helpers that materialize batches of normalized runtime observations into graph observation nodes.
- [x] Reuse the runtime-specific observation write-request seam instead of duplicating node-property shaping.
- [x] Add TDD coverage for:
  - [x] successful node + edge projection against an existing workload subject
  - [x] skip behavior when the graph subject is missing
  - [x] skip behavior when the observation still has no concrete subject
- [x] Rebuild graph indexes and metadata after projection.
- [x] Re-run focused runtimegraph tests and lint.

## Deep Review Cycle 140 - Runtime Evidence Node Projection (2026-03-16)

### Review findings
- [x] Gap: runtime graph projection can now materialize raw `observation` nodes, but promoted detection results still have no first-class `evidence` node representation in the graph.
- [x] Gap: evidence nodes should represent the detection-layer artifact, not duplicate raw sensor provenance; runtime-source details belong in metadata while `source_system` should remain the detection system.
- [x] Gap: promoted runtime evidence still needs deterministic node IDs and temporal fallbacks from the underlying observation/event when the finding timestamp is absent.

### Execution plan
- [x] Add runtime-finding-to-evidence node builders in `internal/runtimegraph`.
- [x] Materialize runtime findings into graph `evidence` nodes without introducing the later `based_on` edges yet.
- [x] Add TDD coverage for:
  - [x] detection provenance and metadata shaping
  - [x] observation timestamp fallback
  - [x] bulk evidence-node projection
  - [x] skip behavior when no temporal context exists
- [x] Rebuild graph indexes and metadata after evidence projection.
- [x] Re-run focused runtimegraph tests and lint.

## Deep Review Cycle 141 - Workload To Observation Target Edges (2026-03-16)

### Review findings
- [x] Gap: runtime observation projection already creates `observation -> targets -> subject`, but the runtime visibility design explicitly calls for the reverse workload-centric navigation edge `workload -> targets -> observation`.
- [x] Gap: that reverse edge should be limited to workload-class subjects rather than every observation target, otherwise service and other non-workload subjects would get noisy mirrored edges with no architectural justification.
- [x] Gap: the runtime observation materialization result needs to report how many workload-target edges were added so later graph-causal slices can measure the projection delta directly.

### Execution plan
- [x] Extend runtime observation materialization to add reverse `targets` edges from workload-class subjects to observation nodes.
- [x] Keep the new reverse edge scoped to workload-class node kinds only.
- [x] Add TDD coverage for:
  - [x] reverse edge creation for workload subjects
  - [x] no reverse edge for service subjects
- [x] result counter increments
- [x] Re-run focused runtimegraph tests and lint.

## Deep Review Cycle 142 - Runtime Evidence Based-On Edges (2026-03-16)

### Review findings
- [x] Gap: runtime findings now materialize as first-class `evidence` nodes, but they still float unconnected from the underlying `observation` that triggered promotion.
- [x] Gap: without a causal `based_on` edge, graph queries cannot walk from promoted detection evidence back to the raw runtime observation context.
- [x] Gap: repeated evidence materialization must stay idempotent, so the new `based_on` edge projection needs explicit deduplication and missing-target handling instead of raw `AddEdge` calls.

### Execution plan
- [x] Add runtime finding -> observation `based_on` edge construction in `internal/runtimegraph`.
- [x] Keep the edge conditional on a real materialized observation node rather than creating dangling graph links.
- [x] Reuse the runtimegraph dedupe helper so repeated materialization stays stable.
- [x] Add TDD coverage for:
  - [x] successful evidence -> observation linking
  - [x] skip behavior when the underlying observation node is missing
  - [x] idempotent repeated evidence projection
- [x] Re-run focused runtimegraph tests and lint.

## Deep Review Cycle 133 - Hubble Golden Payload Coverage (2026-03-15)

### Review findings
- [x] Gap: the Hubble adapter had edge-case unit coverage for egress, ingress, and DNS paths, but it still lacked repo-local fixtures that lock the normalized contract to representative payloads.
- [x] Gap: relying only on inline JSON literals makes it too easy for future refactors to drift away from realistic Hubble exporter payload structure without tripping a stable fixture-backed test.
- [x] Gap: the direction-neutral `primary_*` / `peer_*` metadata path added in cycle 132 needs fixture-backed coverage so ingress/egress anchoring changes do not silently break later graph and detection work.

### Execution plan
- [x] Add repo-local Hubble golden fixtures for representative:
  - [x] egress TCP L3/L4 flow
  - [x] ingress UDP L3/L4 flow
  - [x] DNS L7 flow
- [x] Add fixture-backed normalization coverage that asserts:
  - [x] observation kind
  - [x] resource/workload anchoring
  - [x] direction and network protocol
  - [x] direction-neutral identity metadata
  - [x] DNS query preservation

## Deep Review Cycle 135 - Runtime Observation Identity Binding (2026-03-16)

### Review findings
- [x] Gap: `NormalizeObservation` already derived identity from dedicated top-level fields, but it still failed to bind cluster/container/image/principal/workload context when adapters surfaced those values only through metadata or resource IDs.
- [x] Gap: workload and namespace identity were still one-way; observations with `resource_id=deployment:prod/api` or `workload_ref=statefulset:data/postgres` kept the raw identifier but did not backfill normalized namespace/workload context.
- [x] Gap: principal identity did not fall back to process or file actors when metadata lacked `principal_id`, which weakens runtime correlation for Falco- and file-oriented alerts.

### Execution plan
- [x] Bind cluster identity from normalized metadata fallbacks.
- [x] Bind namespace and workload identity from `resource_id` / `workload_ref` when possible.
- [x] Bind container and image identity from metadata fallbacks.
- [x] Bind principal identity from metadata and process/file actor fallbacks.
- [x] Add regression coverage for metadata-driven and resource-ref-driven identity binding.

## Deep Review Cycle 134 - Tetragon Security Signal Normalization (2026-03-16)

### Review findings
- [x] Gap: the Tetragon adapter already normalized `process_kprobe` file, network, and DNS telemetry, but it still rejected policy-driven security hooks like capability checks and credential changes as unsupported events.
- [x] Gap: upstream Tetragon emits high-value runtime security signals through `process_kprobe` payloads with typed args such as `capability_arg`, `user_ns_arg`, and `process_credentials_arg`, so continuing to drop them would leave privilege-escalation monitoring blind even with the source adapter in place.
- [x] Gap: generic security-policy `process_kprobe` events need to preserve enforcement metadata (`policy_name`, `action`, `return_action`, `return_code`) so downstream detection and graph correlation can distinguish observed signals from blocking/enforcement outcomes.

### Execution plan
- [x] Normalize security-oriented `process_kprobe` payloads into `ObservationKindRuntimeAlert`.
- [x] Preserve extracted capability and credential metadata:
  - [x] capability name/value
  - [x] user-namespace context
  - [x] credential UID/GID and capability-mask state
- [x] Preserve policy/action/return metadata on normalized runtime alerts.
- [x] Keep malformed bare `process_kprobe` payloads failing fast instead of silently normalizing junk input.

## Deep Review Cycle 132 - Hubble Verdict and Identity Metadata (2026-03-15)

### Review findings
- [x] Gap: the Hubble adapter preserved `source_*` and `destination_*` metadata, but downstream runtime intelligence still had to special-case traffic direction because there was no direction-neutral `primary_*` / `peer_*` identity surface.
- [x] Gap: Hubble endpoint IDs were still dropped entirely, which weakens future correlation against Cilium/Hubble endpoint-centric telemetry and any replay/debug workflows that need the original endpoint handle.
- [x] Gap: verdict and peer identity metadata need to stay normalized across ingress and egress flows so later graph materialization and detection logic do not duplicate branchy source-vs-destination interpretation.

### Execution plan
- [x] Preserve Hubble endpoint IDs in normalized metadata.
- [x] Add direction-neutral `primary_*` and `peer_*` identity metadata alongside the existing `source_*` / `destination_*` keys.
- [x] Preserve peer cluster and label context for downstream runtime intelligence.
- [x] Add regression tests for ingress and egress/DNS flows covering:
  - [x] peer identity
  - [x] primary identity
  - [x] endpoint IDs
  - [x] peer labels and cluster metadata

## Deep Review Cycle 130 - Tetragon DNS Observation Normalization (2026-03-15)

### Review findings
- [x] Gap: the Tetragon adapter could normalize connect/file/process telemetry, but it still discarded `process_kprobe` packet-hook payloads that carry DNS-server traffic through `skb_arg`.
- [x] Gap: upstream Tetragon exposes DNS-server enforcement/examples through `ip_output` packet hooks with `KprobeSkb` metadata, so continuing to ignore `skb_arg` would leave the Tetragon DNS slice unimplemented even though the source contract is already stable.
- [x] Gap: explicit `ObservationKindDNSQuery` observations without a populated `network.domain` would round-trip through the legacy `RuntimeEvent` compatibility path as generic `network_flow`, which would silently degrade this new Tetragon DNS seam.

### Execution plan
- [x] Parse Tetragon `process_kprobe` DNS packet payloads from `skb_arg` into `ObservationKindDNSQuery`.
- [x] Preserve DNS packet metadata:
  - [x] source/destination IPs and ports
  - [x] packet length as `network.bytes_sent`
  - [x] transport protocol / protocol number
  - [x] socket family
- [x] Keep DNS observations on IDs distinct from generic network-flow observations.
- [x] Preserve explicit observation kind through `RuntimeObservation <-> RuntimeEvent` compatibility even when DNS observations do not have a domain string.
- [x] Add regression and golden coverage for Tetragon DNS normalization plus the explicit-kind round-trip seam.

## Deep Review Cycle 131 - Runtime Source Payload Dedupe (2026-03-15)

### Review findings
- [x] Gap: runtime ingest runs now persist checkpoints and normalization outcomes, but they still treat repeated source payload IDs as fresh observations, which can inflate findings and response executions when collectors retry or replay.
- [x] Gap: dedupe needs payload-hash awareness instead of raw ID-only suppression, or legitimate upstream corrections using the same event ID will be dropped as duplicates.
- [x] Gap: duplicate runtime payloads should become explicit ingest events and counters rather than silently disappearing, or operators cannot distinguish successful suppression from ingest loss.

### Execution plan
- [x] Add processed-event dedupe for runtime source payload IDs through `internal/executionstore`.
- [x] Treat same source + event ID + payload hash as duplicates while allowing hash-mismatched replays through.
- [x] Record duplicate runtime payloads as `observation_duplicate` ingest events and expose duplicate counters in run checkpoints and API responses.
- [x] Add store and API regression coverage for:
  - [x] same-payload duplicate suppression
  - [x] hash mismatch pass-through
  - [x] duplicate telemetry counters and ingest events

## Deep Review Cycle 124 - Tetragon Network Observation Normalization (2026-03-15)

### Review findings
- [x] Gap: the runtime visibility substrate now normalizes process lifecycle and file telemetry, but it still drops Tetragon network observations even though outbound connection context is the next required seam for runtime causality.
- [x] Gap: Tetragon emits both first-class `process_connect` events and socket-oriented `process_kprobe` connect hooks, so handling only one shape would leave real deployments with partial network coverage.
- [x] Gap: network observations need IDs distinct from process/file telemetry while still preserving destination identity and observation timestamp so downstream dedupe does not collapse repeated connections.

### Execution plan
- [x] Normalize first-class Tetragon `process_connect` events into `ObservationKindNetworkFlow`.
- [x] Normalize socket-oriented `process_kprobe` connect hooks:
  - [x] `tcp_connect`
  - [x] `security_socket_connect`
- [x] Preserve Tetragon socket family, socket type, policy, action, and return-code metadata on normalized observations.
- [x] Add regression tests for first-class `process_connect`, `tcp_connect`, and `security_socket_connect` payloads.

## Deep Review Cycle 127 - Hubble DNS Flow Normalization (2026-03-15)

### Review findings
- [x] Gap: the first Hubble adapter cut deliberately rejected DNS/L7 payloads to avoid silently flattening them into generic network flows, but that still left one of the highest-value runtime visibility signals unmodeled.
- [x] Gap: Hubble’s DNS proto already exposes `query`, `ips`, `ttl`, `cnames`, `rcode`, `qtypes`, and `rrtypes`, so continuing to reject DNS would be an unnecessary blind spot rather than a data-model limitation.
- [x] Gap: DNS flows should become `ObservationKindDNSQuery` while non-DNS L7 payloads remain explicitly unsupported until a later slice adds HTTP/Kafka or generalized L7 semantics.

### Execution plan
- [x] Normalize Hubble DNS L7 payloads into `ObservationKindDNSQuery`.
- [x] Preserve DNS-specific metadata:
  - [x] query result IPs
  - [x] TTL
  - [x] CNAMEs
  - [x] observation source
  - [x] rcode
  - [x] qtypes
  - [x] rrtypes
- [x] Keep anchoring semantics consistent with the L3/L4 flow adapter cut.
- [x] Add regression tests for:
  - [x] DNS query normalization
  - [x] rejection of unsupported non-DNS L7 payloads

## Deep Review Cycle 126 - Hubble Adapter and L3/L4 Flow Normalization (2026-03-15)

### Review findings
- [x] Gap: the runtime visibility architecture explicitly calls for Hubble as the cluster-wide network flow substrate, but Cerebro still had no Hubble adapter package at all.
- [x] Gap: waiting for full DNS/L7 support should not block the lower-risk L3/L4 path, because exported Hubble flow payloads already provide stable IP, L4, verdict, endpoint, and traffic-direction context that maps cleanly onto `ObservationKindNetworkFlow`.
- [x] Gap: Hubble DNS/L7 payloads need a dedicated normalization slice instead of being silently downgraded to generic network flows, or Cerebro will erase query-specific semantics before slice `027` lands.

### Execution plan
- [x] Add `internal/runtime/adapters/hubble` with the shared adapter contract.
- [x] Normalize exported Hubble `GetFlowsResponse.flow` JSON payloads for L3/L4 flows into `ObservationKindNetworkFlow`.
- [x] Anchor egress flows to the source workload and ingress flows to the destination workload while preserving peer/service/verdict metadata.
- [x] Add regression tests for:
  - [x] dropped TCP egress flow normalization
  - [x] forwarded UDP ingress flow normalization
  - [x] explicit rejection of DNS/L7 payloads pending the dedicated DNS slice
  - [x] explicit rejection of unsupported wrapper-only events

## Deep Review Cycle 125 - Tetragon Adapter Golden Payload Coverage (2026-03-15)

### Review findings
- [x] Gap: the adapter had edge-case unit tests for individual payload shapes, but it still lacked fixture-backed golden coverage to catch contract drift against representative upstream Tetragon event payloads.
- [x] Gap: runtime visibility needs stable sample coverage for both first-class event envelopes and `process_kprobe`-backed telemetry, or future parser refactors can silently break one family while the inline tests keep passing.
- [x] Gap: relying only on inline JSON literals makes it harder to compare Cerebro’s normalized contract against the upstream Tetragon examples the adapter is meant to support.

### Execution plan
- [x] Add repo-local golden fixtures for representative Tetragon payload families:
  - [x] `process_exec`
  - [x] `process_exit`
  - [x] `process_connect`
  - [x] `security_file_permission`
  - [x] `tcp_connect`
- [x] Add fixture-backed normalization tests that assert the normalized observation kind and key process/file/network fields for each payload family.

## Deep Review Cycle 124 - Tetragon Network Observation Normalization (2026-03-15)

### Review findings
- [x] Gap: the runtime visibility substrate could normalize `process_exec` and `process_exit`, but it still dropped Tetragon `process_kprobe` file-access events entirely even though the architecture and slice plan explicitly call out file telemetry as the next source class.
- [x] Gap: the documented Tetragon filename-monitoring hooks span both legacy and newer kernels, so supporting only `security_path_truncate` would leave `security_file_truncate` blind on newer kernels.
- [x] Gap: file observations need stable IDs distinct from process lifecycle observations and from sibling file accesses in the same process, or downstream dedupe/finding correlation will collapse unrelated file events.

### Execution plan
- [x] Normalize Tetragon `process_kprobe` file events from the documented hooks:
  - [x] `security_file_permission`
  - [x] `security_mmap_file`
  - [x] `security_path_truncate`
  - [x] `security_file_truncate`
- [x] Map read vs modify semantics onto the existing `RuntimeObservation` / `FileEvent` contract.
- [x] Preserve Tetragon function name, policy, return code, and access mask metadata on normalized observations.
- [x] Add regression tests for write, read, truncate, kernel-6.2 file truncate, and file-observation ID uniqueness.

## Deep Review Cycle 122 - Runtime Visibility Architecture and Integration Plan (2026-03-15)

### Review findings
- [x] Gap: Cerebro already has runtime event ingest, detections, responses, and shared execution-state durability, but it still does not have a first-class runtime observation substrate that can safely absorb real process, file, network, and control-plane telemetry.
- [x] Gap: the current `internal/runtime.RuntimeEvent` shape is too narrow for production-grade runtime visibility, and treating it as the permanent canonical contract would force provider-specific drift and weak graph identity binding.
- [x] Gap: runtime response execution is now durable and action-engine-backed, but response outcomes still are not projected back into the same runtime causal graph as observations and findings.
- [x] Gap: the shared `internal/executionstore` seam is the right place for ingestion jobs, checkpoints, and response history, but not the right place to persist every raw runtime observation at production rates.
- [x] Gap: the right initial source mix is layered rather than monolithic:
  - [x] Kubernetes audit for control-plane causality
  - [x] Tetragon for process/file/runtime security telemetry
  - [x] Hubble for network flow visibility
  - [x] OpenTelemetry for service/trace/resource correlation

### Execution plan
- [x] Write and link a dedicated runtime visibility architecture doc in [docs/RUNTIME_VISIBILITY_ARCHITECTURE.md](./docs/RUNTIME_VISIBILITY_ARCHITECTURE.md).
- [x] Add a canonical normalized `RuntimeObservation` contract behind provider adapters while keeping `RuntimeEvent` as a compatibility path.
- [ ] Add provider adapter seams for:
  - [x] Tetragon
  - [x] Kubernetes audit
  - [ ] Hubble
  - [ ] OpenTelemetry
- [ ] Persist runtime-ingest runs, checkpoints, and replay/materialization jobs through `internal/executionstore` without routing every raw observation through the same store.
  - [x] Persist the existing `/api/v1/runtime/events` and `/api/v1/telemetry/ingest` HTTP ingest flows as execution-store-backed runtime ingest runs with checkpoints and `run_id` responses.
- [x] Close the normalization seam before more sources land:
  - [x] observations now pass through central validation and normalization instead of adapter-local cleanup
  - [x] invalid runtime observations are rejected before detection evaluation
  - [x] raw and provenance payloads are bounded so replay/state surfaces do not quietly balloon
  - [x] observations without stable source IDs still get deterministic generated IDs
  - [x] missing observation timestamps now fall back consistently from `recorded_at`
- [ ] Project promoted runtime observations and response outcomes into graph `observation` / `evidence` resources with causal edges to workload, deployment, incident, and response execution context.
- [ ] Make runtime response executions emit typed outcome observations so containment success/failure becomes part of graph intelligence instead of staying local to the response subsystem.
- [ ] Expose runtime visibility coverage and source health through platform intelligence endpoints once the substrate exists.

### Runtime visibility slice list
- [x] 001. Write the runtime visibility architecture document.
- [x] 002. Cross-link runtime visibility architecture from runtime response and graph intelligence docs.
- [x] 003. Add a canonical `RuntimeObservationKind` enum-like contract.
- [x] 004. Add a canonical `RuntimeObservation` struct in `internal/runtime`.
- [x] 005. Add control-plane and trace context fragments to the observation contract.
- [x] 006. Add compatibility conversion from `RuntimeEvent` to `RuntimeObservation`.
- [x] 007. Add compatibility conversion from `RuntimeObservation` back to `RuntimeEvent`.
- [x] 008. Add `DetectionEngine.ProcessObservation`.
- [x] 009. Preserve legacy finding `Event` payloads while attaching normalized observations.
- [x] 010. Add a runtime response outcome observation helper.
- [x] 011. Add a generic runtime adapter interface package.
- [x] 012. Add a first Kubernetes audit adapter package.
- [x] 013. Parse single Kubernetes audit events into normalized observations.
- [x] 014. Parse Kubernetes audit list payloads into normalized observations.
- [x] 015. Tag Kubernetes `exec` events explicitly.
- [x] 016. Add malformed Kubernetes audit payload tests.
- [x] 017. Add a Tetragon adapter package.
- [x] 018. Normalize Tetragon process exec events.
- [x] 019. Normalize Tetragon process exit events.
- [x] 020. Normalize Tetragon file events.
- [x] 021. Normalize Tetragon network events.
- [x] 022. Normalize Tetragon DNS events.
- [x] 023. Normalize Tetragon security signal payloads.
- [x] 024. Add Tetragon adapter golden payload tests.
- [x] 025. Add Hubble adapter package.
- [x] 026. Normalize Hubble L3/L4 flow events.
- [x] 027. Normalize Hubble DNS flow events.
- [x] 028. Normalize Hubble verdict and identity metadata.
- [x] 029. Add Hubble adapter golden payload tests.
- [x] 030. Add OpenTelemetry adapter package.
- [x] 031. Normalize OTLP log records into observation enrichments.
- [x] 032. Normalize OTLP trace/span identity into observation enrichments.
- [x] 033. Normalize OTel resource attributes into workload/service context.
- [x] 034. Add OTLP adapter tests.
- [x] 035. Add Falco adapter package.
- [x] 036. Normalize Falco JSON outputs into observation/finding inputs.
- [x] 037. Add Falco adapter tests.
- [x] 038. Add a runtime ingest namespace to the execution-store-backed control plane.
- [x] 039. Add a runtime ingest run record type.
- [x] 040. Add runtime ingest event/checkpoint records.
- [x] 041. Add runtime replay/materialization job records.
- [x] 042. Add checkpoint cursor persistence per source.
- [x] 043. Add processed-event dedupe for runtime source payload IDs.
- [x] 044. Add runtime ingest store tests.
- [x] 045. Add runtime observation validation and normalization helpers.
- [x] 046. Reject structurally invalid observations early.
- [x] 047. Add bounded raw/provenance payload trimming.
- [x] 048. Add observation ID generation when sources omit stable IDs.
- [x] 049. Add observation timestamp fallback rules.
- [x] 050. Add observation normalization tests.
- [x] 051. Bind observations to cluster identity.
- [x] 052. Bind observations to namespace identity.
- [x] 053. Bind observations to workload identity.
- [x] 054. Bind observations to container identity.
- [x] 055. Bind observations to image identity.
- [x] 056. Bind observations to principal identity.
- [x] 057. Bind observations to service identity from OTel/resource context.
- [ ] 058. Bind observations to deployment runs when temporal evidence is strong.
- [x] 059. Add identity-binding tests for conflicting or partial runtime metadata.
- [x] 060. Add a runtime observation graph materializer package.
- [x] 061. Project promoted runtime observations into graph `observation` nodes.
- [x] 062. Project promoted runtime evidence into graph `evidence` nodes.
- [x] 063. Add workload-to-observation edges.
- [x] 064. Add finding-to-evidence edges.
- [x] 065. Add response-to-target edges for runtime response outcomes.
- [x] 066. Add causal edges from response outcomes back to findings.
- [x] 067. Add causal edges from runtime observations to deployment runs where justified.
- [x] 068. Add causal edges from runtime observations to Kubernetes audit events where justified.
- [x] 069. Add graph materialization tests for runtime observations.
- [ ] 070. Add graph ontology/schema entries required for runtime evidence projection.
- [ ] 071. Add response-engine hooks to emit outcome observations on action completion.
- [ ] 072. Add response-engine hooks to emit outcome observations on action failure.
- [ ] 073. Add response-engine hooks to emit approval outcome observations.
- [ ] 074. Preserve actuator/provider metadata on response outcome observations.
- [ ] 075. Add response outcome observation tests.
- [ ] 076. Add runtime-source health reporting.
- [ ] 077. Add runtime-source coverage reporting.
- [ ] 078. Add runtime replay status reporting.
- [ ] 079. Add runtime visibility platform intelligence measures.
- [ ] 080. Add runtime visibility docs for operator configuration and source coverage.
- [ ] 081. Add a platform/runtime observations read surface.
- [ ] 082. Add a platform/runtime sources read surface.
- [ ] 083. Add a platform/runtime coverage read surface.
- [ ] 084. Add a platform/runtime replay/job surface.
- [ ] 085. Add API contract tests for runtime visibility endpoints.
- [ ] 086. Add RBAC mapping for runtime visibility platform endpoints.
- [ ] 087. Add Kubernetes audit ingestion endpoint or collector bridge.
- [ ] 088. Add Tetragon ingestion endpoint or collector bridge.
- [ ] 089. Add Hubble ingestion endpoint or collector bridge.
- [ ] 090. Add OTLP/OTel ingestion bridge for runtime enrichment.
- [ ] 091. Add performance tests for high-volume runtime normalization.
- [ ] 092. Add backpressure/drop strategy tests for bursty runtime sources.
- [ ] 093. Add raw telemetry retention and pruning controls.
- [ ] 094. Add source health alerting hooks.
- [ ] 095. Add runtime observation replay tooling for incident investigation.
- [ ] 096. Add runtime-vs-control-plane causality experiments and fixtures.
- [ ] 097. Add network-flow plus process-correlation experiments and fixtures.
- [ ] 098. Add vendor/package/image enrichment from runtime observations.
- [ ] 099. Add confidence/outcome feedback loops from runtime response results.
- [ ] 100. Document the production rollout sequence and default source recommendation.

## Deep Review Cycle 121 - Vendor Grant Monitoring Signals for Okta and Google Workspace (2026-03-15)

### Review findings
- [x] Gap: after `#319`, vendor nodes could score live OAuth grants, but they still had no lifecycle or recent-activity signal to distinguish dormant access from freshly changing integrations.
- [x] Gap: the first Google Workspace monitoring cut only enriched already-inventoried token applications, so apps that appeared only in audit activity would disappear from the graph entirely even though recent authorization/revocation activity is material vendor evidence.
- [x] Gap: the Google token activity parser assumed JSON-decoded `[]interface{}` shapes for events and parameters, which made direct normalized/provider-fed map slices easy to drop or panic on in tests and future ingestion paths.
- [x] Gap: Okta application grants already carry stable lifecycle fields (`status`, `source`, `created`, `lastUpdated`), but vendor nodes were not summarizing that lifecycle metadata on the application/vendor surface at all.

### Execution plan
- [x] Add Google Workspace provider coverage for recent token audit activity from Admin Reports `applications/token`.
- [x] Build Google Workspace application monitoring enrichment that persists recent activity counts and newest activity timestamp on application nodes.
- [x] Materialize audit-only Google Workspace OAuth applications into the graph so recent authorize/revoke events still project vendors even when there is no current token inventory row.
- [x] Add Okta application grant monitoring enrichment that summarizes active/admin/principal grant counts plus newest grant timestamp on application nodes.
- [x] Roll the new Okta/Google monitoring signals up onto vendor nodes:
  - [x] `active_grant_count`
  - [x] `admin_grant_count`
  - [x] `principal_grant_count`
  - [x] `recent_oauth_activity_count`
  - [x] `recent_oauth_authorize_event_count`
  - [x] `recent_oauth_revoke_event_count`
  - [x] `last_grant_updated_at`
  - [x] `last_oauth_activity_at`
- [x] Add TDD coverage for:
  - [x] malformed Google token activity event payloads being ignored safely
  - [x] audit-only Google OAuth apps still projecting application and vendor nodes
  - [x] newest Okta grant / Google activity timestamp aggregation
  - [x] recent authorize vs revoke event counting
- [x] Rerun focused provider/sync/builder validation, full `go test ./... -count=1`, and changed-package lint.

## Deep Review Cycle 112 - Explicit Vendor Ontology + Identity Integration Projection (2026-03-15)

### Review findings
- [x] Gap: issue `#255` still depended on overloaded `company` semantics even though the world-model architecture already called out `vendor` as a first-class ontology module.
- [x] Gap: identity-provider integrations with real access semantics existed in the graph, but there was no derived vendor inventory node to aggregate them.
- [x] Gap: incremental CDC rebuilds would leave any derived vendor inventory stale unless the projection was wired into both full-build and incremental rebuild paths.

### Execution plan
- [x] Add TDD coverage for builtin `vendor` registration and business-category behavior.
- [x] Add builder coverage for projecting vendor nodes from Okta applications and Entra service principals while excluding Azure managed identities.
- [x] Rebuild derived vendor nodes during both full graph builds and CDC edge rebuilds.
- [x] Aggregate initial vendor risk signals from managed integration nodes onto the vendor node itself.

## Deep Review Cycle 113 - Azure/Entra Service Principal Vendor Metadata Parity (2026-03-15)

- [x] Gap: the Azure/Entra service-principal parser now depends on `app_owner_organization_id`, `app_role_assignment_required`, and `publisher_name`, but the source queries had drifted and no longer selected that full field set consistently.
- [x] Gap: that drift meant vendor provenance/risk enrichment silently disappeared depending on whether the graph build came from `azure_graph_service_principals`, `entra_service_principals`, or CDC payload replay.
- [x] Keep the parser contract and repair the source layers instead of trimming the metadata back out, because those fields are the right substrate for explicit vendor nodes.

- [x] Extend the Azure Graph sync table and Microsoft Graph select list to include `app_role_assignment_required`.
- [x] Extend the native Entra provider schema/select list to include `app_owner_organization_id` and `publisher_name`.
- [x] Align builder identity queries with the parser contract for both Azure Graph and Entra fallback paths.
- [x] Add build-path and CDC-path regressions that assert the vendor-relevant service-principal metadata survives end to end.

## Deep Review Cycle 114 - Vendor Canonicalization and Provenance (2026-03-15)

- [x] Gap: explicit vendor nodes still fragmented on raw publisher/display strings, so `Slack` and `Slack Technologies, LLC` would project as separate vendors despite representing the same integration boundary.
- [x] Gap: vendor inventory still lacked first-class provenance and scope fields from issue `#255`, making the node kind present but not yet stable enough for downstream scoring.
- [x] Gap: vendor scope summaries were vulnerable to self-contamination from the new `managed_by` edges unless access aggregation stayed permission-edge-only.

- [x] Add deterministic vendor alias canonicalization using conservative token normalization and legal-suffix stripping.
- [x] Collapse vendor projections by owner-organization ID first, then by canonical alias/prefix match.
- [x] Persist explicit vendor aliases, owner organization IDs, assignment-required counts, permission level, accessible resource kinds, and sensitive resource counts on vendor nodes.
- [x] Add TDD coverage for canonical alias collapse and provenance/scope aggregation.
- [x] Fix the regression where derived `managed_by` edges polluted the vendor's own access-scope summary.
- [x] Regenerate ontology docs and rerun graph/builders validation plus lint.

## Deep Review Cycle 115 - Vendor Dependency Breadth and Graph-Derived Risk Score (2026-03-15)

- [x] Gap: issue `#255` explicitly called for scoring vendors by the number of users/resources depending on them, but vendor nodes still only summarized what the vendor could touch, not who depended on that integration.
- [x] Gap: direct group assignments undercount blast radius unless vendor dependency breadth expands transitive `member_of` edges to the actual impacted users and workload identities.
- [x] Gap: vendor nodes still lacked a graph-derived numeric score that combined permission depth, sensitive-resource reach, and dependency breadth into one stable signal for downstream ranking.

- [x] Add TDD coverage for vendor dependency breadth across direct user assignment, group assignment with transitive members, and service-principal assignment.
- [x] Aggregate dependent principal/user/group/service-account counts from inbound permission edges on vendor-managed integrations.
- [x] Add a deterministic `vendor_risk_score` that combines privilege depth, sensitive-resource reach, dependency breadth, and assignment-optional exposure.
- [x] Keep the coarse `Risk` level derived from the score bands so existing graph/report consumers continue to work.

## Deep Review Cycle 116 - Verified Publisher Trust Signals for Vendor Nodes (2026-03-15)

- [x] Gap: Microsoft Graph already exposes `verifiedPublisher` on service principals, but Cerebro was discarding it at both Entra sync and Azure Graph sync time, so vendor identity still depended on weaker raw publisher strings.
- [x] Gap: that meant verified-publisher IDs could not anchor cross-product vendor merges, and vendor nodes had no first-class trust/provenance signal distinguishing verified from unverified integrations.
- [x] Gap: CDC replay and fallback Entra builds also needed the same flattening so the trust signal survived regardless of ingestion path.

- [x] Flatten `verifiedPublisher.displayName`, `verifiedPublisherId`, and `addedDateTime` into both Entra and Azure Graph service-principal tables.
- [x] Thread the verified-publisher fields through builder queries and CDC replay for Azure/Entra service principals.
- [x] Prefer verified-publisher display name as the stronger vendor identity label and merge vendor projections by verified-publisher ID when present.
- [x] Persist verified/unverified integration counts plus verification status on vendor nodes.
- [x] Add TDD coverage for verified-publisher preservation and verified-publisher-based vendor projection merge behavior.

## Deep Review Cycle 117 - Entra Delegated OAuth Grants for Vendor Access Modeling (2026-03-15)

- [x] Gap: Entra app-role assignments only model app-only grants, but issue `#255` explicitly called out OAuth app authorizations and vendor access from identity providers.
- [x] Gap: Cerebro was not ingesting `oauth2PermissionGrant`, so delegated OAuth consents had no first-class graph representation and vendor dependency breadth missed user-consented SaaS apps entirely.
- [x] Gap: the right seam is the existing Entra provider + Azure relationship extractor, not a one-off vendor-specific path, so delegated grants become reusable graph substrate.

- [x] Add an `entra_oauth2_permission_grants` provider table for `client_id`, `consent_type`, `principal_id`, `resource_id`, `scope`, `start_time`, and `expiry_time`.
- [x] Sync delegated OAuth grants from Microsoft Graph with the official `oauth2PermissionGrants` endpoint.
- [x] Project delegated grant relationships into `resource_relationships` for both client-app-to-resource access and principal-to-client consent edges where applicable.
- [x] Add TDD coverage for delegated grant relationship extraction and vendor signal aggregation from delegated OAuth consents.
- [x] Rerun focused and broad graph/provider/sync validation plus lint.

## Deep Review Cycle 118 - Vendor Risk Signals for Delegated Admin Consent (2026-03-15)

- [x] Gap: delegated OAuth grants were now in the graph, but vendor nodes still collapsed tenant-wide admin consent into the same generic access summary as per-user delegated consent.
- [x] Gap: the graph builder stores raw relationship payloads under nested edge properties, and vendor aggregation was ignoring those nested grant fields entirely.
- [x] Gap: that left `AllPrincipals` delegated grants under-scored even though they materially widen vendor blast radius without requiring per-user assignment edges.

- [x] Add TDD coverage for tenant-wide delegated grants and principal-scoped delegated consent on vendor nodes.
- [x] Decode nested relationship grant payloads during vendor aggregation instead of relying on flattened edge fields that do not exist.
- [x] Persist delegated-grant counts, admin-consent counts, principal-consent counts, and unique delegated scopes on vendor nodes.
- [x] Lift vendor risk scoring when tenant-wide delegated admin consent and broad delegated scope sets are present.

## Deep Review Cycle 119 - Entra OAuth Grant v1.0 API Contract Fix (2026-03-15)

- [x] Gap: the new delegated-grant sync was requesting `startTime` and `expiryTime` from the Microsoft Graph v1.0 `oauth2PermissionGrants` endpoint even though those fields are beta-only.
- [x] Gap: leaving those fields in the stable v1.0 request would make delegated-grant ingestion fail at runtime with a `400`, which would invalidate the whole vendor OAuth modeling cut.
- [x] Gap: relationship payloads and schema metadata also needed to match the stable v1.0 contract instead of preserving unsupported columns that will never populate.

- [x] Add a provider regression test that asserts the v1.0 delegated-grant sync query only requests supported fields.
- [x] Remove beta-only grant timestamps from the Entra provider schema, request path, and relationship payload projection.
- [x] Rerun provider, sync, builder, lint, and full-repo validation on the corrected v1.0 contract.

## Deep Review Cycle 120 - Okta and Google Workspace OAuth Vendor Coverage (2026-03-15)

### Review findings
- [x] Gap: issue `#255` still had a major identity-provider blind spot. Vendor discovery and scoring now handled Entra delegated grants, but Okta application grants and Google Workspace third-party OAuth tokens were still invisible to the graph.
- [x] Gap: the first Okta cut only modeled app-to-scope access, which lost the difference between tenant-wide admin-approved grants and user-scoped consent. That undercounted both delegated grant inventory and affected principals.
- [x] Gap: Google Workspace token metadata exposes `anonymous` and `nativeApp`, but leaving those as inert provider fields wasted a concrete risk signal for unmanaged OAuth clients.
- [x] Gap: status-bearing Okta grants need active-state filtering at relationship extraction time. Otherwise stale or revoked grants can continue to project live vendor access.
- [x] Gap: the right Google Workspace seam is graph-native: sync tokens, project application + scope + user-consent edges, and let vendor nodes aggregate from those edges instead of adding a provider-specific side table.

### Execution plan
- [x] Add Okta and Google Workspace provider coverage:
  - [x] sync `okta_app_grants` from `/api/v1/apps/{appId}/grants`
  - [x] sync `google_workspace_tokens` from Admin Directory `users/{userKey}/tokens`
  - [x] keep Google Workspace group member `member_id` so dependency breadth can expand through real identity nodes
- [x] Project graph relationships and nodes:
  - [x] map Okta application grants into scope permission edges
  - [x] emit principal-to-application consent edges for user-scoped Okta grants
  - [x] build first-class Google Workspace application nodes from token inventory
  - [x] emit Google Workspace user-to-app consent edges plus app-to-scope edges
- [x] Harden semantics with TDD:
  - [x] skip inactive Okta grants during relationship extraction
  - [x] preserve Okta admin consent vs principal consent in relationship properties
  - [x] keep Google token scope edges deterministic
  - [x] carry Google `anonymous` and `native_app` flags into vendor aggregation and scoring
- [x] Enrich vendor risk scoring:
  - [x] count anonymous and native Google Workspace applications on vendor nodes
  - [x] increase vendor risk for anonymous/native delegated OAuth apps
  - [x] let Okta grant consent edges contribute delegated grant, scope, and dependent-principal counts alongside Entra/Google
- [ ] Next vendor-access depth cuts after this slice:
  - [ ] add Okta application grant lifecycle/drift monitoring so vendor score changes alert when scopes or consent source change
  - [ ] ingest more Google Workspace admin-side app governance signals to distinguish merely-used apps from sanctioned apps
  - [ ] separate generic OAuth grant inventory from delegated-consent inventory on vendor nodes once more providers land

## Deep Review Cycle 111 - Vulnerability Reachability Prioritization on Workload Scans (2026-03-15)

### Review findings
- [x] Gap: `#234` added dependency depth and reachability to package usage, but vulnerability materialization still treated reachable and unreachable critical vulnerabilities the same way on scan nodes and workload-security facets.
- [x] Gap: scan-to-vulnerability and package-to-vulnerability edges did not carry any package-context prioritization hints, so downstream ranking still had to infer urgency from flat severity alone.
- [x] Gap: the right fix is to aggregate package context per vulnerability on the scan edge and summary counts, not to push workload-specific urgency onto canonical package or vulnerability nodes.

### Execution plan
- [x] Add TDD coverage for:
  - [x] prioritized vulnerability edge properties derived from package reachability/directness
  - [x] downranking unreachable critical vulnerabilities on workload scan risk
  - [x] workload-security prioritization preferring reachable vulnerability counts
- [x] Aggregate best package context per vulnerability during workload graph materialization.
- [x] Emit reachability/directness hints on `workload_scan --found_vuln--> vulnerability` and `package --affected_by--> vulnerability` edges.
- [x] Add scan-level reachable vulnerability summary counts and use them in workload-security prioritization.
- [x] Rerun focused workload/graph tests, lint, and ontology doc generation.

## Deep Review Cycle 110 - Lockfile-Owned npm Package Deduplication (2026-03-15)

### Review findings
- [x] Gap: once a `package-lock.json` dependency graph existed, the generic package parser could still inventory the same installed package again from `node_modules/*/package.json`.
- [x] Gap: because npm package identity includes `Location`, those duplicate installed-package records survived merge and could inflate package counts, SBOM components, and downstream vulnerability matches for the same manifest tree.
- [x] Gap: the right fix is not to disable installed-package parsing globally, because that fallback is still useful when no lockfile graph exists.

### Execution plan
- [x] Add TDD coverage for a lockfile-managed npm tree that also contains installed `node_modules/*/package.json`.
- [x] Canonicalize installed npm package records onto the owning lockfile-backed package identity when a dependency graph already owns that manifest tree.
- [x] Preserve fallback package parsing for npm trees that do not have a lockfile graph.
- [x] Rerun focused filesystem/workload tests and changed-package lint before pushing the updated head.

## Deep Review Cycle 107 - Go SBOM Root Dependencies + Non-Library Materialization Guard (2026-03-15)

### Review findings
- [x] Gap: Go module scans were inventorying packages and reachability, but emitted no CycloneDX dependency entries at all because `go.mod` parsing never contributed SBOM dependency relationships.
- [x] Gap: that left `Summary.DependencyCount` at zero for Go-only projects and made the SBOM materially weaker than the npm path.
- [x] Gap: the correct fix is not to invent package-to-package edges that `go.mod` cannot justify; the defensible relationship we do know is application/module -> direct requirements.
- [x] Gap: once application components are present in SBOM output, workload graph materialization must ignore them so package nodes stay package-only.

### Execution plan
- [x] Add TDD coverage for:
  - [x] Go SBOM application component plus direct dependency edges
  - [x] `dependency_count` reflecting the new Go SBOM dependency entry
  - [x] ignoring non-library SBOM components during workload package graph materialization
- [x] Parse the Go module path from `go.mod`.
- [x] Add Go application SBOM components and application -> direct dependency edges during inventory assembly.
- [x] Keep npm/package dependency edges unchanged while merging both dependency sources into the final SBOM.
- [x] Rerun focused filesystem/workload tests, lint, and full `go test ./...`.

## Deep Review Cycle 108 - Package Merge Contract Reuse (2026-03-15)

### Review findings
- [x] Gap: workload graph materialization still duplicated `PackageRecord` merge semantics instead of reusing the canonical analyzer merge logic.
- [x] Gap: that duplication made dependency-depth and reachability rules vulnerable to silent drift across two packages.
- [x] Gap: both packages also carried redundant `maxInt` helpers even though the repo targets a Go version with builtin `max`.

### Execution plan
- [x] Export the canonical package merge helper from `filesystemanalyzer`.
- [x] Route workload package aggregation through that shared helper instead of a duplicate merge function.
- [x] Replace the redundant `maxInt` helpers with builtin `max`.
- [x] Rerun focused tests/lint and keep the PR review loop on the updated head.

## Deep Review Cycle 109 - Go Longest-Prefix Reachability Matching (2026-03-15)

### Review findings
- [x] Gap: Go import reachability was marking every matching module-path prefix reachable instead of only the longest module prefix.
- [x] Gap: a repo that requires both `github.com/foo` and `github.com/foo/bar` would incorrectly mark both modules reachable for an import like `github.com/foo/bar/baz`.
- [x] Gap: that overstates reachable vulnerable surface for the shorter-prefix module and weakens the prioritization signal added in `#234`.

### Execution plan
- [x] Add TDD coverage for overlapping Go module prefixes.
- [x] Change Go import matching to keep only the longest matching module prefix while preserving multiple keys for the same exact module path.
- [x] Rerun focused filesystem analyzer tests plus changed-package lint/test validation.

## Deep Review Cycle 106 - Dependency Parser Cleanup After Review Pass (2026-03-14)

### Review findings
- [x] Gap: after the dependency-graph-first analyzer flow landed, the old `parsePackageRecords` cases for `package-lock.json`, `npm-shrinkwrap.json`, and `go.mod` were dead fallback code.
- [x] Gap: leaving those branches in place obscured the real parser control flow and suggested a fallback path that could never actually produce package records.

### Execution plan
- [x] remove dead `parsePackageRecords` cases for npm lockfiles and `go.mod`
- [x] remove the now-unused package-only helper wrappers in `dependencies.go`
- [x] rerun focused filesystem/workload tests and lint

## Deep Review Cycle 105 - Dependency Parser Edge Cases and Manifest Hygiene (2026-03-14)

### Review findings
- [x] Gap: `go.mod` and `go.sum` were still producing duplicate Go package records because the inventory key included different manifest locations.
- [x] Gap: the npm dependency-graph BFS could loop forever on circular lockfiles because it never stopped re-expanding already-seen package paths.
- [x] Gap: top-level `node_modules`, `vendor`, `dist`, `build`, `testdata`, and `fixtures` paths were still scanned as if they were first-party source files because the exclusion checks only matched slash-delimited interior segments.

### Execution plan
- [x] Add TDD coverage for:
  - [x] deduped Go module records across `go.mod` and `go.sum`
  - [x] circular npm lockfile parsing terminating cleanly
  - [x] ignoring top-level third-party/import-excluded directories for JS and Go reachability
- [x] normalize `go.sum` package locations onto the sibling `go.mod` manifest path
- [x] stop re-expanding already-visited npm package paths while still retaining dependency edges
- [x] switch import-file exclusion checks from substring matching to path-segment matching

## Deep Review Cycle 104 - Dependency Graph Review Follow-through (2026-03-14)

### Review findings
- [x] Gap: npm dependency resolution still skipped intermediate hoisted `node_modules` ancestors, so nested dependencies could resolve to the wrong version or disappear entirely.
- [x] Gap: package-lock and `go.mod` files were being parsed twice in the filesystem walk, which doubled work on the hottest new path for `#234`.
- [x] Gap: `packageFromSBOMComponent` reconstructed Go packages with `Manager: "golang"` instead of `Manager: "go"`.
- [x] Gap: canonical package nodes still carried workload-specific usage hints even though those belong on `workload_scan -> package` edges.

### Execution plan
- [x] Add TDD coverage for:
  - [x] hoisted npm ancestor resolution
  - [x] manager mapping from SBOM-derived Go packages
  - [x] keeping `direct_dependency` / `reachable` / `dependency_depth` / `import_file_count` off canonical package nodes
- [x] walk npm ancestor `node_modules` directories during dependency resolution instead of checking only the direct parent and root
- [x] stop reparsing `package-lock.json` and `go.mod` after dependency-graph extraction already produced package records
- [x] rerun focused filesystem/workload validation, lint, and full `go test ./...`

## Deep Review Cycle 103 - Nested Manifest Reachability Isolation (2026-03-14)

### Review findings
- [x] Gap: `#234` still scoped import reachability by simple path-prefix membership under each manifest directory.
- [x] Gap: nested `package-lock.json` and nested `go.mod` projects therefore leaked import evidence upward into ancestor manifests, marking the wrong package records reachable.
- [x] Gap: the upstream MIT patterns already pointed at the correct fix:
  - [x] `github/dependency-submission-toolkit` groups dependencies by manifest/build target ownership.
  - [x] `advanced-security/github-sbom-toolkit` keeps per-manifest SBOM context intact instead of flattening all package evidence together.

### Execution plan
- [x] Add TDD coverage for:
  - [x] nested npm manifests with the same package imported only from the child project
  - [x] nested Go modules with the same module imported only from the child module
- [x] assign import evidence to the nearest containing manifest base instead of every ancestor prefix match
- [x] rerun focused filesystem/workload/graph validation plus full `go test ./...`

## Deep Review Cycle 102 - Go Module Reachability and Directness Signals (2026-03-14)

### Review findings
- [x] Gap: `#234` only built dependency depth and reachability for npm lockfiles; Go modules were still a flat `go.sum` inventory.
- [x] Gap: this left `go.mod` direct vs indirect dependency intent unused, even though the issue explicitly calls out `go.sum` / `go.mod`.
- [x] Gap: Go source imports were not connected back to module records, so reachable-vs-unreachable vulnerability prioritization was still Node-only.
- [x] Gap: MIT upstream review sharpened the next slice:
  - [x] `github/dependency-submission-toolkit` models dependency relationships per manifest rather than as flat package presence.
  - [x] `samber/go-mod-graph` reinforces that Go module identity should come from explicit module-path semantics, not filename heuristics.

### Execution plan
- [x] Add TDD coverage for:
  - [x] `go.mod` direct and indirect requirement classification
  - [x] Go import reachability from source files
  - [x] subpackage import matching back to the parent module path
- [x] Parse `go.mod` requirements into package records and reachability metadata.
- [x] Scan `.go` files for import statements and map them back to module roots.
- [x] Reuse the existing dependency prioritization contract:
  - [x] `direct_dependency`
  - [x] `dependency_depth`
  - [x] `reachable`
  - [x] `import_file_count`

## Deep Review Cycle 99 - npm Lockfile Compatibility and Reachability Evidence (2026-03-14)

### Review findings
- [x] Gap: the initial `#234` slice only understood npm lockfiles with a `packages[""]` root, so valid npm v1 lockfiles still produced a flat-empty dependency view.
- [x] Gap: reachability seeding only used declared root dependencies, so directly imported transitive packages were incorrectly marked unreachable even when they were installed at root and imported by source code.
- [x] Gap: the package contract still lacked import evidence counts, so the issue's prioritization goal of "imported in N files" was still not representable.
- [x] Gap: extra MIT-licensed upstream review sharpened the contract direction:
  - [x] `github/dependency-submission-toolkit` models direct vs indirect relationships per manifest/build target instead of flattening dependencies globally.
  - [x] `advanced-security/github-sbom-toolkit` keeps manifest and package-url identity attached to collected SBOM data for later matching.
  - [x] `sverweij/dependency-cruiser` and `pahen/madge` both treat import extraction as a first-class graph-building input rather than a post-hoc annotation.

### Execution plan
- [x] Add TDD coverage for:
  - [x] npm v1 `package-lock.json` dependency graph extraction
  - [x] direct source imports of transitive-but-root-resolvable packages
  - [x] import evidence counts flowing into workload graph usage edges
- [x] Extend npm graph parsing to support:
  - [x] v2/v3 `packages[""]` lockfiles
  - [x] v1 nested `dependencies` lockfiles
- [x] Change reachability seeding from "declared direct dependency only" to "root-resolvable importable package" so hoisted transitive packages are modeled correctly.
- [x] Carry `import_file_count` through:
  - [x] package inventory
  - [x] SBOM components
  - [x] workload scan `contains_pkg` edges
  - [x] canonical package node properties
- [ ] Next depth cuts after this fix-up:
  - [ ] add manifest/path identity onto dependency edges so multi-manifest workloads stay separable
  - [ ] add another ecosystem slice with an explicit lockfile graph, most likely `go.mod`/`go.sum`
  - [ ] use import evidence counts in vulnerability prioritization once package-vulnerability ranking is wired

## Deep Review Cycle 98 - Node Dependency Graph and Reachability from Workload SBOMs (2026-03-14)

### Review findings
- [x] Gap: issue `#234` was still open even though the filesystem analyzer already had the right seam to enrich package inventory during the existing manifest walk.
- [x] Gap: package inventory stayed flat, so workload scans could not represent direct vs transitive package relationships or feed dependency-aware graph traversals.
- [x] Gap: the cheapest credible reachability slice is Node.js first, because `package-lock.json` gives an explicit dependency tree and JavaScript import scanning can distinguish unused direct dependencies from imported roots.
- [x] Gap: package nodes are canonical across workloads, so directness/depth/reachability should not be stored on the package node itself; they belong on scan-to-package usage edges and dependency edges.
- [x] Gap: MIT-licensed upstream patterns reinforce that shape:
  - [x] `github/dependency-submission-toolkit` groups dependencies by manifest/build target and models relationships explicitly instead of flattening them away.
  - [x] `advanced-security/github-sbom-toolkit` treats PURLs/SBOM refs as the stable join key for matching and downstream analysis.
  - [x] `octodemo/sbom-dependency-submission` shows why build-time/lockfile-derived dependency trees surface transitive dependencies that static manifest parsing misses.

### Execution plan
- [x] Add TDD coverage for:
  - [x] npm `package-lock.json` dependency graph extraction
  - [x] direct vs transitive depth tracking
  - [x] JavaScript import-driven reachability
  - [x] graph materialization of package usage hints and `package -> package depends_on` edges
- [x] Extend package/SBOM report contracts with:
  - [x] direct dependency hint
  - [x] reachability hint
  - [x] dependency depth
  - [x] SBOM dependency edges
- [x] Parse npm lockfiles into a manifest-scoped dependency graph during the existing filesystem walk.
- [x] Collect JavaScript/TypeScript imports during the same walk and propagate reachability from imported direct dependencies through the lockfile graph.
- [x] Materialize dependency-aware graph data by:
  - [x] carrying direct/depth/reachability hints on `workload_scan --contains_pkg--> package` edges
  - [x] adding canonical `package --depends_on--> package` edges from SBOM dependency refs
- [ ] Next depth cuts after this slice:
  - [ ] add `go.mod` / `go.sum` direct-vs-indirect modeling and selected Python lockfile support
  - [ ] add scan/report summaries for dependency-edge counts and reachable package counts once the cross-ecosystem contract settles
  - [ ] tie vulnerability prioritization to reachability/directness without polluting canonical package node properties

## Deep Review Cycle 101 - Technology Schema Metadata Preservation (2026-03-14)

### Review findings
- [x] Gap: the canonical-technology-node fix on `#308` removed all write metadata from `technology` nodes.
- [x] Gap: `technology` is a schema-registered node kind that still requires canonical write metadata fields: `source_system`, `observed_at`, `valid_from`, `recorded_at`, and `transaction_from`.
- [x] Gap: under schema enforcement, workload materialization could reject every technology node even though the canonical-node refactor was otherwise correct.

### Execution plan
- [x] Add TDD coverage that exercises technology materialization under `SchemaValidationEnforce`.
- [x] Restore schema-required metadata on canonical technology nodes without reintroducing workload-specific provenance like `source_event_id` or `file_path`.
- [x] Preserve the earliest canonical timestamps across repeated upserts from multiple workloads.
- [x] Rerun targeted workload/graph tests and lint before pushing the fix.

## Deep Review Cycle 100 - Canonical Technology Node Integrity (2026-03-14)

### Review findings
- [x] Gap: `#308` modeled `technology` nodes as canonical global entities by name/category/version, but still stamped them with per-scan write metadata like `source_event_id`, `observed_at`, and workload-specific `file_path`.
- [x] Gap: when multiple workloads reported the same technology, the later scan overwrote the canonical node properties and erased earlier observation metadata.
- [x] Gap: that workload-specific context belongs on the `workload -> technology` observation edge, not on the canonical technology node itself.

### Execution plan
- [x] Add TDD coverage for the multi-workload collision case where two workloads report the same technology version.
- [x] Keep canonical technology node properties stable:
  - [x] retain only technology identity fields on the node
  - [x] remove per-workload/per-scan metadata from the node
- [x] move workload-specific evidence to the `runs` edge:
  - [x] file path
  - [x] temporal/source metadata already derived from the scan
- [x] rerun targeted workload/filesystem/graph validation and lint on the fix

## Deep Review Cycle 97 - Workload Technology Stack Detection and Graph Inventory (2026-03-14)

### Review findings
- [x] Gap: issue `#240` was still open even though the workload-scan substrate already had the right seam to derive running technology signals during the existing filesystem walk.
- [x] Gap: package inventory alone could not answer the intended queries from the issue body such as "what runs Redis?" or "what runs Java 8?" because workload scans were not producing a first-class technology inventory.
- [x] Gap: the graph materialization layer had package/vulnerability/secret/malware projections but no corresponding technology nodes or workload-to-technology edges.
- [x] Gap: the ontology also lacked a first-class `technology` node kind and workload scan summaries did not persist a `technology_count`.
- [x] Gap: the initial six detector cases were a valid first slice, but the same seam could cheaply cover additional high-signal runtime/service configs without extra scan passes.

### Execution plan
- [x] Add TDD coverage for filesystem-derived technology detection across:
  - [x] Node.js
  - [x] Go
  - [x] .NET
  - [x] Nginx
  - [x] PostgreSQL
  - [x] Redis
- [x] Extend the same TDD surface for additional high-signal artifact families:
  - [x] Java
  - [x] Python
  - [x] Caddy
  - [x] RabbitMQ
  - [x] Kafka
  - [x] NATS
  - [x] Prometheus
- [x] Add first-class `TechnologyRecord` inventory to the filesystem analyzer report and summary.
- [x] Derive technology signals during the existing filesystem walk with no additional scan pass.
- [x] Add a first-class `technology` node kind and `technology_count` ontology support.
- [x] Materialize deduped technology inventory from workload scans into the graph as:
  - [x] `Technology` nodes
  - [x] `Workload --runs--> Technology` edges
- [x] Add workload graph TDD coverage for deduped multi-volume technology projection.
- [ ] Next depth cuts after this slice:
  - [ ] add more detector families from the issue backlog: Datadog/New Relic, selected orchestration/container runtime signals, and additional CI/CD runner/service-process fingerprints
  - [ ] expose technology inventory as a dedicated report/query surface instead of only graph/search traversal
  - [ ] correlate detected technology versions with vulnerability/advisory data where we have trustworthy version specificity

## Deep Review Cycle 94 - Entra Directory Role CDC Removal Parity (2026-03-14)

### Review findings
- [x] Gap: issue `#275` created Entra directory role nodes with the prefixed `azure_directory_role:` ID, but CDC removals still preferred the raw `resource_id`.
- [x] Gap: delete events for `entra_directory_roles` therefore left stale role nodes in the graph even after the source record was removed.
- [x] Gap: adding an `entra_directory_roles` branch to `cdcNodeID` alone was insufficient because the removal path bypassed `cdcNodeID` whenever `resource_id` was present.

### Execution plan
- [x] Add TDD coverage for:
  - [x] `cdcNodeID` returning the prefixed directory-role ID
  - [x] incremental CDC removal actually soft-deleting the prefixed directory-role node
- [x] Normalize CDC removal IDs through `cdcNodeID(table, payload, resourceID)` instead of trusting the raw event ID first.
- [x] Keep the table-specific `entra_directory_roles` ID normalization in `cdcNodeID` so adds and removes use the same node contract.

## Deep Review Cycle 95 - Azure Management Group Subscription Scope Hardening (2026-03-14)

### Review findings
- [x] Gap: issue `#279` was correctly trying to expand Azure discovery to org-scale management groups, but the enabled-subscription filter in `listManagementGroupSubscriptions` still compared subscription IDs case-sensitively.
- [x] Gap: Azure APIs can return the same subscription ID with different casing across the subscription list and management-group tree, which could incorrectly drop valid subscriptions and surface a false `no enabled subscriptions found` error.
- [x] Gap: management-group HTTP status checking happened after JSON decode, so non-2xx HTML/proxy responses were reported as decode failures instead of the real status error.
- [x] Gap: API-layer Azure subscription normalization duplicated the sync-layer logic, which would let future fixes drift again.

### Execution plan
- [x] Add TDD coverage for:
  - [x] case-insensitive enabled-subscription filtering for management-group expansion
  - [x] HTTP status evaluation preceding JSON decode for management-group queries
  - [x] sync API subscription normalization using the shared Azure helper contract
- [x] Make management-group filtering compare normalized lowercase keys while preserving the discovered subscription ID value.
- [x] Check management-group HTTP status before decoding the response body.
- [x] Replace duplicate API subscription normalization with the shared sync-layer helper.

## Deep Review Cycle 96 - GCP Asset Sync Contract Compatibility for Org Scope (2026-03-14)

### Review findings
- [x] Gap: issue `#279` was correctly trying to add organization-scoped GCP Asset sync, but the OpenAPI request schema silently removed the pre-existing required `projects` field.
- [x] Gap: the API contract compatibility gate treated that as a breaking change for `POST /api/v1/sync/gcp-asset`, which would block push/merge and also break generated clients that rely on the existing schema contract.
- [x] Gap: the internal API client also omitted `projects` entirely for organization-scoped requests, so the implementation and contract drifted in the same direction.

### Execution plan
- [x] Preserve the existing `projects` request-field contract in OpenAPI for `POST /api/v1/sync/gcp-asset`.
- [x] Represent organization-scoped asset sync as `projects: []` plus `organization`, so new org-scope behavior works without removing the old field contract.
- [x] Add/update client tests to lock the explicit-empty-projects payload for organization-scoped requests.
- [x] Re-run the contract-compatibility and OpenAPI checks before push.

## Deep Review Cycle 93 - Azure Key Vault Key Lineage and Scope Cleanup Follow-through (2026-03-14)

### Review findings
- [x] Gap: issue `#275` was already fixing Azure RBAC scope correctness, but Azure Key Vault key nodes still did not persist a `vault_id`, even though `azureKeyNodesForVault` advertised that as a matching path.
- [x] Gap: full-build and CDC Azure Key Vault key nodes therefore relied only on `vault_uri`, which is weaker and can be absent in partial datasets.
- [x] Gap: `azurePermissionsToEdgeKind` still used a redundant score switch that duplicated `azurePermissionScore` instead of directly taking the highest score.

### Execution plan
- [x] Add TDD coverage for:
  - [x] Key Vault access-policy edges still linking keys when only the key resource ID is available
  - [x] CDC Azure Key Vault key nodes deriving and storing `vault_id`
  - [x] Azure permission scoring still honoring the highest observed permission
- [x] Derive `vault_id` from Azure Key Vault key resource IDs in both full-build and CDC paths.
- [x] Keep key-to-vault matching working through either explicit `vault_id` or normalized `vault_uri`.
- [x] Replace the redundant Azure permission-score switch with direct max-of-score aggregation.

## Deep Review Cycle 92 - Azure RBAC Scope Boundaries and Fallback Table Correctness (2026-03-14)

### Review findings
- [x] Gap: issue `#275` was correctly trying to add first-class Azure RBAC graph modeling, but `azureNodeWithinScope` still had an over-broad substring fallback that could match sibling resources and similarly named subscriptions/resource groups.
- [x] Gap: resource-scoped Azure RBAC assignments could therefore over-grant `Can*` edges to unrelated resources in the same resource group instead of staying bounded to the scoped resource and its descendants.
- [x] Gap: `loadAzurePreferredIdentityNodes` stopped on the first discovered table with zero rows, which prevented fallback identity tables from loading in racey or partially populated environments.
- [x] Gap: `queryAzureRBACRoleAssignments` could not fall back from `azure_rbac_role_assignments` to `azure_authorization_role_assignments` when table discovery was unavailable and the preferred table query failed.

### Execution plan
- [x] Add TDD coverage for:
  - [x] resource-scoped Azure RBAC staying out of sibling resources in the same group
  - [x] direct scope matching rejecting similar subscription/resource-group substrings
  - [x] discovered-table identity fallback after an empty first result
  - [x] RBAC table fallback when discovery is unavailable and the preferred query fails
- [x] Remove the broad substring fallback from `azureNodeWithinScope` and keep matching boundary-aware:
  - [x] exact resource match
  - [x] descendant prefix match
  - [x] explicit subscription/resource-group scope handling
- [x] Continue across Azure identity fallback candidates on empty/error results instead of returning early.
- [x] Make Azure RBAC assignment loading iterate preferred tables in order and fall through to the legacy table when the preferred query is unavailable or empty.

## Deep Review Cycle 91 - Conditional Resource Enforcement in IAM Boundary and SCP Evaluation (2026-03-14)

### Review findings
- [x] Gap: issue `#277` was correctly separating conditional and unconditional access, but the later SCP allow-list / deny filtering and permission-boundary filtering only iterated `ep.Resources`.
- [x] Gap: conditional-only resources in `ep.Conditional` could therefore bypass SCP implicit-deny behavior and permission-boundary trimming entirely.
- [x] Gap: wildcard-target SCP edges with resource-dependent conditions such as `aws:ResourceAccount` were evaluated once against a `nil` target node, so valid per-resource denies could be skipped.

### Execution plan
- [x] Add TDD coverage for:
  - [x] permission boundaries stripping conditional-only access
  - [x] wildcard SCP resource-account conditions being evaluated per concrete resource
- [x] Evaluate SCP allow/deny edges against the concrete effective-permission target set instead of a single wildcard placeholder target.
- [x] Apply SCP allow-list and permission-boundary implicit denies across both unconditional and conditional resource buckets.
- [x] Keep wildcard resource evaluation deduplicated so shared resource IDs across unconditional/conditional buckets do not double-apply actions.

## Deep Review Cycle 90 - Audit Mutation Batch Poison-Pill and Change-Type Normalization (2026-03-14)

### Review findings
- [x] Gap: issue `#276` still allowed a single semantically invalid audit mutation record inside a batch to fail `parseAuditMutationCloudEvent`, which bubbles back into the JetStream consumer and `Nak()`s the whole message.
- [x] Gap: that creates a poison-pill loop for otherwise valid audit batches because the malformed record is retried forever and blocks the valid mutations that share the same message.
- [x] Gap: the parser compared the raw `change_type` string against `"removed"` before normalization, so valid deletion aliases like `"deleted"` and `"delete"` could be rejected when `resource_id` was absent.
- [x] Gap: the audit parser had no structured way to surface partial-drop behavior back to the handler for observability.

### Execution plan
- [x] Switch audit mutation parsing to best-effort batch handling:
  - [x] skip malformed records instead of failing the whole message
  - [x] preserve valid records from the same batch for CDC persistence
- [x] Normalize audit mutation change types before `resource_id` validation so delete aliases map to `removed`.
- [x] Return structured parse-drop metadata and log dropped-record counts/reasons from the audit handler.
- [x] Add TDD coverage for:
  - [x] mixed valid/invalid audit mutation batches persisting only the valid subset
  - [x] delete-synonym normalization with missing `resource_id`

## Deep Review Cycle 89 - Audit CDC Graph Ingestion Identity and Consumer Upgrade Correctness (2026-03-14)

### Review findings
- [x] Gap: issue `#276` was correctly trying to ingest cloud audit mutation events into CDC and then materialize them into the live graph, but the ID contract was not consistent end to end.
- [x] Gap: audit mutation fallback `resource_id` selection did not match graph node ID selection for network assets, so persisted CDC removals could target a different identifier than the one used to create the node.
- [x] Gap: the three network-asset CDC node cases bypassed the normal `event.ResourceID` path and built IDs directly from payload fields, which left add/remove behavior asymmetric when audit events carried a canonical top-level resource ID.
- [x] Gap: Azure NSG public-ingress detection was still using string heuristics over serialized rule blobs, which is too fragile for structured rule arrays and misses plural-prefix wildcard cases.
- [x] Gap: JetStream upgrade safety was incomplete for the new multi-subject audit ingestion path:
  - [x] existing streams were not updated to include newly configured subjects
  - [x] existing single-subject durable consumers could remain incompatible with multi-subject configs

### Execution plan
- [x] Unify audit CDC resource identity with graph identity:
  - [x] export table-aware CDC resource-ID resolution from graph builders
  - [x] route audit mutation fallback `resource_id` derivation through that shared resolver
- [x] Make network-asset CDC node creation honor the resolved/event resource ID:
  - [x] apply resolved IDs to AWS security-group CDC nodes
  - [x] apply resolved IDs to GCP firewall CDC nodes
  - [x] apply resolved IDs to Azure NSG CDC nodes
- [x] Replace Azure NSG public-exposure string heuristics with structured rule parsing first, plus string fallback only for unstructured inputs.
- [x] Harden JetStream consumer upgrade behavior for the new audit sources:
  - [x] update existing streams to include missing configured subjects
  - [x] delete/recreate incompatible durable consumers before multi-subject resubscribe
  - [x] add end-to-end JetStream upgrade tests once `nats-server` is available locally
- [x] Add TDD coverage for:
  - [x] table-aware audit mutation resource IDs for AWS/GCP/Azure network assets
  - [x] add/remove symmetry for network-asset CDC nodes
  - [x] structured Azure NSG wildcard prefix lists
  - [x] stream-subject and durable-consumer JetStream upgrade paths

## Deep Review Cycle 86 - Reuse Existing Terraform Subresource Addresses for Bucket Remediations (2026-03-14)

### Review findings
- [x] Gap: even after reusing existing bucket resource references, generated Terraform still minted new subresource labels for bucket remediations when `iac_state_id` already pointed at an existing `aws_s3_bucket_public_access_block` or `aws_s3_bucket_server_side_encryption_configuration`.
- [x] Gap: that creates duplicate Terraform resources and weakens the new state-reconciliation contract because the artifact no longer lines up with the resource Terraform is already managing.
- [x] Gap: `for_each` instances need an explicit boundary here. Reusing exact addresses is correct for plain managed resources, but blindly turning instance addresses like `resource.name["key"]` into block labels would generate invalid HCL.

### Execution plan
- [x] Reuse existing Terraform-managed subresource addresses when `iac_state_id` points directly at:
  - [x] `aws_s3_bucket_public_access_block.*`
  - [x] `aws_s3_bucket_server_side_encryption_configuration.*`
- [x] Keep generated fallback names for cases that cannot be represented as a single resource block:
  - [x] `for_each` instance addresses
  - [x] unrelated resource types
- [x] Add TDD coverage at both renderer and executor metadata layers.
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3
  - [ ] use parsed HCL and lineage to anchor generated blocks to existing module files/labels instead of only path-level placement

## Deep Review Cycle 87 - Normalize Terraform Attribute-Path State IDs Back to Managed Resources (2026-03-14)

### Review findings
- [x] Gap: the Terraform state-address parser only recognized bare managed resource addresses. When `iac_state_id` included an attribute suffix like `.id`, remediation codegen dropped back to literal identifiers and generated weaker patches.
- [x] Gap: that parser limitation also blocked reuse of existing `aws_s3_bucket_public_access_block` and `aws_s3_bucket_server_side_encryption_configuration` resources when lineage/state data pointed at one of their attributes instead of the bare resource address.
- [x] Gap: the right behavior is to normalize attribute-path state IDs back to the managed resource address and let the existing bucket/subresource reuse logic operate on that normalized form.

### Execution plan
- [x] Add TDD coverage for attribute-path `iac_state_id` inputs at the renderer layer:
  - [x] bucket reference reuse from `aws_s3_bucket.*.id`
  - [x] public-access-block reuse from `aws_s3_bucket_public_access_block.*.id`
  - [x] bucket-encryption reuse from `aws_s3_bucket_server_side_encryption_configuration.*.id`
- [x] Add parser-boundary coverage for `for_each` instance attribute paths so:
  - [x] bucket references still normalize to `<resource>.id` without `.id.id`
  - [x] subresource renderers still refuse to reuse invalid `for_each` instance labels as block names
- [x] Add executor-level regressions so artifact metadata keeps the normalized managed resource address.
- [x] Normalize `terraformStateResourceAddress` to accept attribute-path state IDs by stripping trailing attribute segments after the managed resource address.
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3
  - [ ] use parsed HCL and lineage to anchor generated blocks to existing module files/labels instead of only path-level placement

## Deep Review Cycle 88 - Terraform Removal Artifacts for Standalone Public Ingress Rules (2026-03-14)

### Review findings
- [x] Gap: `restrict_public_security_group_ingress` existed in the remediation catalog, but the Terraform path still stopped at S3. That left one of the core low-blast-radius network remediations stuck on remote apply only.
- [x] Gap: SG ingress is not the same shape as bucket subresources. The safe Terraform-first seam is not inline `aws_security_group` rewriting; it is targeting standalone managed rule resources where the desired end state is removal.
- [x] Gap: the current lineage/IaC context is already sufficient for that narrow cut when `iac_state_id` points at standalone `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` resources.
- [x] Gap: Terraform `removed` blocks impose a stricter boundary than ordinary address reuse. Multi-instance rule addresses with instance keys cannot be represented safely in this cut, so they need an explicit rejection path rather than optimistic generation.

### Execution plan
- [x] Extend the catalog so SG ingress restriction supports Terraform delivery while keeping remote apply as the default.
- [x] Add a Terraform renderer for standalone rule resources that emits a `removed` block targeting the existing managed rule address.
- [x] Preserve state-address fidelity for:
  - [x] plain managed rule addresses
  - [x] attribute-path forms of those addresses
- [x] Reject unsupported Terraform contexts explicitly until we add real HCL-editing support:
  - [x] inline `aws_security_group` resources
  - [x] multi-instance rule addresses with `for_each` / instance keys
- [x] Add renderer and executor TDD coverage for:
  - [x] standalone rule removal artifacts
  - [x] inline-security-group rejection
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] add HCL-edit support for inline `aws_security_group` ingress blocks so Terraform remediation can rewrite existing rule blocks instead of only handling standalone rule resources
  - [ ] add the next Terraform-backed safe actions: selected encryption defaults beyond S3 and additional low-blast-radius network remediations

## Deep Review Cycle 85 - Structured Terraform Import and State-Reconciliation Guidance (2026-03-14)

### Review findings
- [x] Gap: the Terraform remediation artifacts still exposed import/state handling mostly as freeform notes plus `resource_address` and `import_id`, which is weak for downstream automation and UI rendering.
- [x] Gap: now that Terraform resource selection is state-aware, the next practical step is not another renderer template. It is a structured artifact model that tells operators exactly how to reconcile generated HCL with Terraform state.
- [x] Gap: upstream reverse-Terraform tools reinforce that shape:
  - [x] `GoogleCloudPlatform/terraformer` keeps import identity, output paths, and plan-time behavior explicit rather than burying state handling in prose.
  - [x] `cycloidio/terracognita` similarly treats generated Terraform and Terraform state/import semantics as first-class output, not just side comments.

### Execution plan
- [x] Extend `TerraformArtifact` with structured state-reconciliation metadata.
- [x] Emit machine-readable Terraform commands for:
  - [x] `terraform state show`
  - [x] `terraform import`
  - [x] `terraform plan`
- [x] Emit Terraform v1.5-style import-block HCL as structured artifact data instead of only freeform notes.
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3
  - [ ] use parsed HCL and lineage to anchor generated blocks to existing module files/labels instead of only path-level placement

## Deep Review Cycle 84 - Preserve Terraform `for_each` State Addresses in Remediation Codegen (2026-03-14)

### Review findings
- [x] Gap: the new state-aware bucket-reference reuse path still parsed `iac_state_id` by splitting on raw dots, which breaks valid Terraform addresses like `aws_s3_bucket.buckets["audit.logs"]`.
- [x] Gap: when that happens, generated remediation HCL silently falls back to literal bucket strings even though the lineage/state context already points at the managed Terraform resource.
- [x] Gap: the parser seam needs to respect Terraform bracket/quote syntax so `for_each` and indexed resource addresses remain reusable instead of being degraded into weaker literal patches.

### Execution plan
- [x] Add TDD coverage for dotted `for_each` keys in Terraform state addresses.
- [x] Replace the raw dot splitter with an address parser that preserves bracketed and quoted segments.
- [x] Keep fallback behavior intact for malformed or unsupported addresses instead of guessing.
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] emit import-block/state-reconciliation guidance in a structured artifact model once Terraform v1.5+ import surfaces become first-class in generated output
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3

## Deep Review Cycle 83 - Reuse Existing Terraform Bucket References from State (2026-03-14)

### Review findings
- [x] Gap: even after the renderer-registry cut, generated remediation HCL still hardcoded literal bucket names when `iac_state_id` already pointed at the managed `aws_s3_bucket` resource.
- [x] Gap: that loses module/resource address fidelity and makes generated Terraform patches weaker than the lineage data Cerebro already has from state-derived provenance.
- [x] Gap: the right first reuse seam is state-aware address reuse, not speculative full-file rewriting. If `iac_state_id` is already an `aws_s3_bucket` address, generated remediation resources should bind to `<address>.id`; if not, they should fall back to the literal bucket identifier.

### Execution plan
- [x] Reuse existing bucket resource addresses when `iac_state_id` points at `aws_s3_bucket.*`
- [x] Apply that reuse consistently to:
  - [x] public access block generation
  - [x] default encryption generation
- [x] Keep fallback behavior explicit:
  - [x] root state IDs still work
  - [x] non-bucket state IDs fall back to the literal bucket name instead of emitting the wrong reference
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] emit import-block/state-reconciliation guidance in a structured artifact model once Terraform v1.5+ import surfaces become first-class in generated output
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3

## Deep Review Cycle 83 - Identity-Provider Application Access Edge Fidelity (2026-03-15)

### Review findings
- [x] Gap: vendor and third-party risk issue `#255` needs graph-native application access signals, but the current relationship builder silently degrades `CAN_ACCESS` relationships into generic `connects_to` edges.
- [x] Gap: that means Okta app assignments are present in `resource_relationships` but under-modeled in the graph itself, so downstream access review, risk scoring, and future vendor inventory logic start from lossy data.
- [x] Gap: Entra app-role assignments were not being extracted into `resource_relationships` at all, leaving a second major identity-provider application-access surface completely absent from the graph substrate.
- [x] Gap: adjacent MIT graph/risk tools reinforce the right structure here:
  - [x] `sverweij/dependency-cruiser` keeps dependency semantics explicit instead of flattening everything into one generic edge class.
  - [x] `Michal256/ESVerdict` and similar runtime-correlation tooling get leverage by preserving which package or component is actually used, not just that “something is connected”.
  - [x] blast-radius style tooling like `GuitaristForEver/tf-blast-radius-modern` and `texasbe2trill/constellation-engine` shows why risk scoring quality depends on preserving dependency/access semantics before aggregation.

### Execution plan
- [x] Add TDD regressions for the current graph/substrate loss:
  - [x] prove `CAN_ACCESS` must materialize as a permission edge instead of `connects_to`
  - [x] prove Entra app-role assignments should be extracted as `RelCanAccess` relationships with preserved assignment metadata
- [x] Fix relationship projection:
  - [x] map `CAN_ACCESS` to `can_read` in the generic relationship-edge builder
  - [x] extract `ENTRA_APP_ROLE_ASSIGNMENTS` into `resource_relationships`
  - [x] preserve `assignment_id`, `app_role_id`, and `resource_display_name` on Entra application-access relationships
- [ ] Next vendor-risk depth cuts after this slice:
  - [ ] project vendor inventory from application/service-principal access edges with provider-specific normalization
  - [ ] score vendors from graph-derived blast radius, sensitive-resource reach, and privilege depth rather than questionnaire-only metadata
  - [ ] add continuous vendor-risk drift detection from new application grants and cross-account/vendor trust changes

## Deep Review Cycle 82 - Terraform Renderer Registry by Action, Provider, and Resource Family (2026-03-14)

### Review findings
- [x] Gap: the Terraform codegen path still used a flat action-to-renderer map, which is the wrong seam for multi-provider remediation actions and would force future support into per-renderer guard logic instead of an explicit dispatch model.
- [x] Gap: that flat map was already hiding a real bug: `enable_bucket_default_encryption` could still emit AWS Terraform for explicit non-AWS input because its direct renderer had no provider guard.
- [x] Gap: the same flat map was also too trusting of resource shape. A public-storage action with an explicit non-bucket `resource_type` could still fall through to bucket Terraform generation as long as the identifier looked bucket-like.

### Execution plan
- [x] Replace the flat Terraform renderer map with an explicit registry keyed by:
  - [x] remediation action
  - [x] provider
  - [x] resource family
- [x] Infer registry lookup context from existing remediation data:
  - [x] normalize provider from execution context with catalog fallback when the action is single-provider
  - [x] normalize resource family from `resource_type` with catalog alias fallback when the action is single-family
- [x] Fail fast with explicit unsupported-context errors:
  - [x] reject non-AWS Terraform bucket-encryption rendering
  - [x] reject non-bucket Terraform public-storage rendering even when the identifier looks bucket-like
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [x] use lineage/state/HCL parsing to prefer existing Terraform resource references when available instead of literal identifiers
  - [ ] emit import-block/state-reconciliation guidance in a structured artifact model once Terraform v1.5+ import surfaces become first-class in generated output
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3

## Deep Review Cycle 81 - Provider-Aware Terraform Delivery Defaults (2026-03-14)

### Review findings
- [x] Gap: the first Terraform-backed public-storage cut still left delivery defaults modeled globally per action, which is wrong for mixed-provider actions where AWS is ready for Terraform-first change control but GCP/Azure still require remote apply.
- [x] Gap: approval and delivery selection were computed without execution context in parts of the remediation pipeline, so provider-aware defaults could not be applied consistently to playbook generation, approval gating, metadata, and approval webhooks.
- [x] Gap: explicit operator overrides still need to win. Provider-aware defaults are useful only if `delivery_mode=remote_apply` can still force a reviewed remote action on AWS when teams want imperative execution.

### Execution plan
- [x] Add provider-aware catalog defaults:
  - [x] support per-provider default delivery modes on catalog entries
  - [x] make `restrict_public_storage_access` default to Terraform for AWS while keeping the action-level global default at `remote_apply`
- [x] Thread execution-aware mode selection through remediation execution:
  - [x] compute delivery mode with provider context from the current execution
  - [x] compute approval requirements from the effective mode, not just the static catalog entry
  - [x] make catalog action plans, playbook generation, and approval notifications all use that same effective mode
- [x] Add TDD coverage for the new semantics:
  - [x] AWS default path auto-selects Terraform and skips approval
  - [x] GCP default path stays on remote apply and keeps approval
  - [x] explicit `delivery_mode=remote_apply` overrides the AWS default and still requires approval
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [ ] introduce a remediation codegen registry keyed by action + provider + resource family, not just a flat action-to-template map
  - [ ] use lineage/state/HCL parsing to prefer existing Terraform resource references when available instead of literal identifiers
  - [ ] emit import-block/state-reconciliation guidance in a structured artifact model once Terraform v1.5+ import surfaces become first-class in generated output
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3

## Deep Review Cycle 80 - Terraform-Backed Public Storage Remediation (2026-03-14)

### Review findings
- [x] Gap: the new remediation Terraform seam from `#301` only covered S3 encryption, so one of the highest-confidence catalog actions still fell back to remote apply even when operators wanted IaC-first change control.
- [x] Gap: `restrict_public_storage_access` was still modeled as a multi-provider remote action only; simply flipping the whole catalog entry to Terraform-first would have been wrong because the current default-delivery model is global per action, not provider-specific.
- [x] Gap: the renderer boundary itself was too trusting. Without a provider guard, any future direct caller could have generated AWS HCL for a non-AWS storage finding as long as a bucket-like identifier existed.
- [x] Gap: upstream IaC tooling points to the right next seam, not a template explosion:
  - [x] `GoogleCloudPlatform/terraformer` keeps resource import identity, output path structure, and plan-time customization explicit instead of burying them inside per-resource ad hoc writers.
  - [x] Cerebro already has the key placement hints for that model in `internal/lineage` and remediation trigger data: `iac_file`, `iac_module`, and `iac_state_id`.
  - [x] the shared `internal/iacrender` helper from `#301` is the correct base layer, but it still needs a higher-level remediation codegen registry once more Terraform-backed actions arrive.

### Execution plan
- [x] Extend the catalog/action path for Terraform-backed public storage remediation:
  - [x] allow `restrict_public_storage_access` to support both `remote_apply` and `terraform`
  - [x] keep the default delivery mode as `remote_apply` until provider-specific delivery defaults exist
- [x] Add the first AWS Terraform implementation for the action:
  - [x] generate `aws_s3_bucket_public_access_block` artifacts
  - [x] reuse existing IaC placement hints from `iac_file`, `iac_module`, and `iac_state_id`
  - [x] persist artifact metadata/evidence through execution results
- [x] Harden provider and approval semantics with TDD:
  - [x] terraform delivery completes without approval for this catalog action
  - [x] non-AWS terraform delivery fails preconditions instead of emitting the wrong provider HCL
  - [x] the renderer itself rejects explicit non-AWS provider context
- [ ] Next Terraform/IaC codegen depth cuts after this slice:
  - [x] add provider-specific default delivery preferences instead of one global default per remediation action
  - [ ] introduce a remediation codegen registry keyed by action + provider + resource family, not just a flat action-to-template map
  - [ ] use lineage/state/HCL parsing to prefer existing Terraform resource references when available instead of literal identifiers
  - [ ] emit import-block/state-reconciliation guidance in a structured artifact model once Terraform v1.5+ import surfaces become first-class in generated output
  - [ ] add the next Terraform-backed safe actions: public security-group ingress restriction and selected encryption defaults beyond S3

## Deep Review Cycle 80 - AWS Network Reachability Edge Correctness (2026-03-14)

### Review findings
- [x] Gap: issue `#272` was directionally correct, but the initial implementation treated security-group completeness as a prerequisite for both positive and negative reachability inference.
- [x] Gap: AWS network reachability is asymmetric. One observed public security-group rule plus one observed public subnet path is enough to prove exposure, while one fully observed private side of the path is enough to disprove it.
- [x] Gap: the original gating caused both false negatives and false positives:
  - [x] a resource with one observed public security group and one unobserved extra group fell back to the generic heuristic instead of emitting the intended path-aware edge
  - [x] a resource in a fully observed private subnet still fell through to heuristic public exposure if its security-group rows were missing
  - [x] partial subnet observation could suppress heuristic exposure entirely even when topology evidence was incomplete
- [x] Gap: subnet inventory alone is not route-topology coverage. Treating a subnet row as sufficient negative evidence can suppress heuristic exposure even when no applicable route table association is known for that subnet.
- [x] Gap: the PR also claimed incremental/full-build parity, but that behavior was not explicitly locked down with a CDC-path regression.

### Execution plan
- [x] Add TDD regressions for the incorrect inference cases:
  - [x] positive inference with one observed public SG and one missing SG
  - [x] negative suppression from fully observed private subnet topology with missing SG rows
  - [x] heuristic fallback when subnet coverage is partial
- [x] Refactor AWS network exposure inference semantics:
  - [x] allow positive path-aware inference from any observed public SG rule plus any observed public subnet path
  - [x] suppress heuristic exposure when either side of the path is fully observed and definitively private
  - [x] avoid suppressing heuristic exposure when the topology evidence is incomplete
- [x] Separate subnet inventory from route-topology coverage:
  - [x] track subnet route applicability from explicit or main route-table associations
  - [x] only use subnet-based negative suppression when every attached subnet has applicable route-topology coverage
- [x] Add incremental rebuild coverage:
  - [x] prove `ApplyChanges` uses the same private-subnet suppression semantics as full builds

## Deep Review Cycle 79 - Filesystem IaC Detection During Workload Scans (2026-03-13)

### Review findings
- [x] Gap: issue `#228` was still leaving obvious filesystem-level IaC and config evidence on the floor even though the workload scan walk already touches those files.
- [x] Gap: waiting for a separate `trivy config` parser would unnecessarily block a first shippable cut because the existing analyzer already has deterministic content and file-type heuristics available locally.
- [x] Gap: the scan graph still had no first-class representation for IaC findings, so scan nodes could report misconfiguration counts without any durable graph object to inspect.
- [x] Gap: IaC-only scans could still collapse to `risk:none` because workload-scan risk was driven primarily by vulnerability aggregates.

### Execution plan
- [x] Extend filesystem analyzer outputs with typed IaC artifact inventory:
  - [x] add `iac_artifacts` to analyzer reports
  - [x] track `iac_artifact_count` in scan summaries
- [x] Detect common IaC/config surfaces during the existing filesystem walk:
  - [x] Terraform and Terraform state
  - [x] CloudFormation and Kubernetes manifests
  - [x] Helm, Docker, Ansible, `.env`, and common app-config files
- [x] Add deterministic IaC/config findings without a new scan pipeline:
  - [x] flag Terraform state files as high severity
  - [x] flag public exposure patterns such as `0.0.0.0/0`
  - [x] flag public storage principals / ACLs
  - [x] flag bucket definitions missing explicit encryption settings
- [x] Materialize IaC findings into the graph:
  - [x] create `observation` nodes with `workload_iac_finding`
  - [x] link findings to the workload-scan node with `targets`
  - [x] surface `iac_artifact_count` on workload-scan nodes
- [x] Fix risk semantics so IaC-only findings raise workload-scan risk appropriately.
- [x] Add regression coverage for analyzer detection and graph materialization.

## Deep Review Cycle 78 - Graph-Derived Compliance Control Evaluation (2026-03-13)

### Review findings
- [x] Gap: issue `#252` was still compliance-by-findings, even though the graph already held the stronger substrate for many control questions: bucket encryption, public exposure, logging, versioning, sensitive-data posture, database exposure, and parts of GCP IAM.
- [x] Gap: leaving compliance on the findings path created a split-brain model: the graph could answer the control question, but exports and pre-audit checks still only knew how to count policy violations.
- [x] Gap: the right first cut is graph-first with explicit fallback, not a fake “all controls are graph-native now” rewrite. Unsupported controls should stay visible as findings-backed until the graph substrate actually earns the migration.
- [x] Gap: upstream graph/security platforms converge on the same lesson:
  - [x] `cartography-cncf/cartography` gets leverage when inventory relationships become reusable compliance evidence instead of remaining isolated snapshots.
  - [x] `cloudquery/cloudquery` reinforces that control logic becomes composable when it runs over normalized resource state rather than one-off scan outputs.
  - [x] `stackrox/stackrox` and similar posture systems keep the strongest checks close to the resource graph and use exported evidence as a downstream view, not the source of truth.

### Execution plan
- [x] Add a typed graph-backed compliance evaluator:
  - [x] evaluate per-control status as `passing|failing|partial|not_applicable|unknown`
  - [x] attach structured evidence entities, policy IDs, reasons, and evaluation source
  - [x] cache entity materialization per provider/kind slice instead of embedding logic in API handlers
- [x] Support the first graph-native control tranche:
  - [x] AWS S3 encryption, public access, policy public exposure, logging, and versioning
  - [x] AWS RDS encryption and public exposure
  - [x] DSPM sensitive-data public/unencrypted posture
  - [x] GCP service-account admin privilege, key rotation, and user-managed-key minimization
  - [x] GCP storage public-access checks
- [x] Keep findings fallback explicit where graph support is not yet real:
  - [x] unsupported policies remain findings-backed
  - [x] mixed controls are labeled `hybrid` when graph + fallback are both involved
- [x] Rewire existing compliance surfaces onto the evaluator:
  - [x] `/api/v1/compliance/frameworks/{id}/report`
  - [x] `/api/v1/compliance/frameworks/{id}/pre-audit`
  - [x] `/api/v1/compliance/frameworks/{id}/export`
  - [x] legacy `/api/v1/reports/compliance/{framework}` compatibility view
- [x] Tighten exported evidence:
  - [x] carry control evidence into audit-package ZIP exports
  - [x] preserve evaluation source and last-evaluated timestamps
- [x] Add regression coverage:
  - [x] mixed graph + findings-fallback control evaluation
  - [x] DSPM + GCP graph-backed control evaluation
  - [x] API test proving compliance report/export can fail from graph state without findings
- [ ] Next compliance depth cuts after this slice:
  - [ ] persist control-evaluation history on graph rebuilds instead of evaluating only at request time
  - [ ] add control-detail and history endpoints (`/status`, `/controls/{id}`, `/history`)
  - [ ] emit control-status-change events for alert routing and report drift
  - [ ] replace remaining findings fallbacks by deepening graph coverage for IAM MFA, CloudTrail/Config, flow logs, and Cloud SQL/Secrets posture

## Deep Review Cycle 77 - Autonomous Credential Exposure Workflow Demo (2026-03-13)

### Review findings
- [x] Gap: issue `#219` did not need a speculative orchestration framework first; Cerebro already had the core substrate pieces for one real autonomous loop:
  - [x] workload-secret detection and credential pivot edges
  - [x] first-class observation / claim / decision / outcome writes
  - [x] durable action execution with approval gates
  - [x] shared execution-store infrastructure
- [x] Gap: there was still no durable autonomous workflow resource tying those pieces together into one inspectable run with status, events, and approval continuation.
- [x] Gap: the first workflow should prove graph leverage, not just generic automation. Credential exposure response was the right entry cut because the graph can already trace secret -> principal -> impacted targets.
- [x] Gap: upstream patterns reinforce the same shape:
  - [x] `argoproj/argo-workflows` keeps workflow state and approval continuation as durable execution resources rather than implicit handler-local state.
  - [x] `StackStorm/st2` shows the value of explicit execution records and audit trails around automated action chains.
  - [x] `smithy-security/smithy` and `turbot/flowpipe` reinforce that security workflows get differentiated by graph/context-rich decisioning, not just generic task runners.

### Execution plan
- [x] Add a durable autonomous workflow substrate:
  - [x] add `autonomous_workflow` execution-store namespace
  - [x] add typed run + event records for autonomous workflows
  - [x] add durable run store on top of the shared execution store
- [x] Implement the first end-to-end workflow:
  - [x] add `credential_exposure_response` workflow ID
  - [x] analyze discovered secret nodes through `has_credential_for` pivots
  - [x] persist workflow run summary, impacted targets, and linked action execution
- [x] Stitch graph evidence trail into the workflow:
  - [x] write detection observation
  - [x] write detection claim
  - [x] write decision node
  - [x] on success, write remediation claim + outcome
- [x] Add tool surfaces for the demo loop:
  - [x] `cerebro.autonomous_credential_response`
  - [x] `cerebro.autonomous_workflow_approve`
  - [x] `cerebro.autonomous_workflow_status`
- [x] Reuse the configured runtime action handler when present:
  - [x] add `ResponseEngine.ActionHandler()` getter
  - [x] make autonomous workflow execution use the app-configured runtime handler before falling back to a default handler
  - [x] keep approval/execution durable under the shared action engine
- [x] Add regression coverage:
  - [x] start workflow -> awaiting approval -> durable run/action persistence
  - [x] approve workflow -> revoke credentials -> remediation claim/outcome persistence
  - [x] status tool returns workflow and action events
- [x] Keep generated SDK contracts in sync:
  - [x] regenerate Agent SDK docs/contracts/packages for the three new autonomous tools
- [ ] Next autonomous depth cuts after this slice:
  - [ ] add the second demo workflow: CVE response with blast-radius prioritization
  - [ ] add Slack/notification approval routing instead of tool-only approval continuation
  - [ ] add post-remediation validation step and explicit validation-stage run semantics
  - [ ] surface autonomous workflow runs through platform execution/report APIs, not only tools

## Deep Review Cycle 76 - Durable Graph-Powered Access Review Campaigns (2026-03-13)

### Review findings
- [x] Gap: issue `#253` was not blocked on another identity microservice; the repo already had graph access-review generation, identity review APIs, stale-access analytics, and effective-permissions calculation, but they lived in two disconnected implementations.
- [x] Gap: the graph access-review handlers still stored campaigns in a process-local map, which breaks restart durability and contradicts the shared execution-store direction already established for reports, scans, and action execution.
- [x] Gap: existing review items were under-enriched for real certification workflows: they lacked stable reviewer candidates, recommendation metadata, last-activity context, and graph risk signals such as toxic-combination involvement.
- [x] Gap: upstream authorization/identity projects converged on the same structural lesson:
  - [x] `openfga/openfga` keeps relationship state explicit and queryable rather than burying access decisions in application-local handlers.
  - [x] `infrahq/infra` and `gravitational/teleport` both reinforce that reviewability needs durable execution state and owner-aware access context, not just raw permission lists.

### Execution plan
- [x] Collapse duplicate access-review implementations onto one shared service:
  - [x] keep one identity review service as the durable workflow entry point
  - [x] route graph access-review endpoints through that same service instead of a local map
  - [x] move campaign persistence to the shared execution store namespace
- [x] Deepen review campaign data model:
  - [x] add scope mode support for `all`, `account`, `principal`, `resource`, `high_risk`, `cross_account`, and `privilege_creep`
  - [x] persist review events for `created`, `started`, `item_decided`, and `completed`
  - [x] add item-level recommendations, reviewer candidates, path context, and metadata
- [x] Generate graph-powered review items from existing substrate:
  - [x] reuse graph access-review generation and blast-radius caching
  - [x] enrich items with effective-permission grants, last-activity signals, and resource owners
  - [x] attach toxic-combination/attack-path context for risk-based prioritization
- [x] Eliminate ephemeral tool/API seams:
  - [x] make `/api/v1/graph/access-reviews/*` delegate to the shared identity service
  - [x] make the `cerebro.access_review` tool create durable campaigns instead of ad hoc graph payloads
- [x] Add regression coverage:
  - [x] graph-generated campaign enrichment and recommendation tests
  - [x] shared execution-store persistence tests for review state and events
  - [x] API test proving graph access-review routes use the shared durable service
- [ ] Next access-governance depth cuts after this slice:
  - [ ] resource-owner auto-assignment and overdue escalation scheduling
  - [ ] compliance evidence export from completed access reviews
  - [ ] auto-remediation handoff for approved revocation/reduction actions
  - [ ] provider-specific last-used evidence (AWS, GCP, Azure, SaaS) beyond principal-level activity

## Deep Review Cycle 75 - GCP Hierarchy and Inherited IAM Foundations (2026-03-13)

### Review findings
- [x] Gap: issue `#245` is broader than one inventory backlog, but the first enterprise-grade credibility seam is still structural: Cerebro had GCP resources and project IAM, yet no first-class `organization`, `folder`, or `project` graph nodes to anchor inheritance.
- [x] Gap: org/folder/project hierarchy was already partially present in raw sync context (`runGCPOrgSync`, Cloud Asset `parent_full_name`, org policy parent references), but it was not normalized into reusable platform nodes and `located_in` edges.
- [x] Gap: GCP IAM inheritance above the project was absent, so the graph systematically understated permissions that actually apply at folder or organization scope.
- [x] Gap: upstream patterns converged on the same structural lesson:
  - [x] `cartography-cncf/cartography` models GCP CRM resources explicitly and treats org, folder, and project hierarchy as first-class graph structure instead of implicit provider metadata.
  - [x] `forseti-security/forseti-security` split hierarchy/IAM analysis from project-local checks, reinforcing that inherited policy scope has to be queryable as graph material, not reconstructed ad hoc later.

### Execution plan
- [x] Add first-class hierarchy ontology kinds:
  - [x] add `organization`, `folder`, and `project` node kinds
  - [x] register schema definitions so hierarchy nodes can emit `located_in`
- [x] Sync GCP Resource Manager hierarchy metadata per project:
  - [x] add native tables for projects, folders, and organizations
  - [x] resolve project ancestry with Resource Manager APIs instead of guessing from one project row
  - [x] preserve ancestor path and folder IDs for downstream reasoning
- [x] Sync inherited IAM policy scopes:
  - [x] add folder-level IAM policy table
  - [x] add organization-level IAM policy table
  - [x] preserve binding conditions and hierarchy provenance in stored rows
- [x] Materialize hierarchy and inherited permissions in the graph:
  - [x] create `organization` / `folder` / `project` nodes
  - [x] add `located_in` hierarchy edges
  - [x] fan folder/org IAM bindings out to descendant project resources with `hierarchy_policy` provenance
- [x] Add regression coverage:
  - [x] lineage ordering and ancestor-path tests for Resource Manager fetch helpers
  - [x] builder tests for hierarchy nodes/edges
  - [x] builder tests for inherited folder/org IAM edge materialization
- [ ] Next GCP enterprise-depth cuts after this slice:
  - [ ] Secret Manager nodes + access controls
  - [ ] Pub/Sub and KMS resource-level IAM edges
  - [ ] service-account impersonation chain modeling (`iam.serviceAccounts.actAs`, `iam.serviceAccountTokenCreator`)
  - [ ] Workload Identity Federation trust edges
  - [ ] billing-account and service-enablement modeling

## Deep Review Cycle 74 - Credential Pivot Graph Materialization (2026-03-13)

### Review findings
- [x] Gap: issue `#243` is not fundamentally a scan-engine problem; Cerebro already detects secrets during workload scans, but it stops at findings instead of turning those discoveries into graph pivots.
- [x] Gap: attack-path and toxic-combination logic can already reason over arbitrary graph edges, so the missing substrate is credential-to-target materialization, not another standalone lateral-movement detector.
- [x] Gap: AWS and GCP identity nodes were still under-modeled for this use case because key metadata existed in synced tables but not on the graph identities that should be reachable from discovered credentials.
- [x] Gap: upstream patterns align on the same lesson:
  - [x] `trufflesecurity/trufflehog` treats credential detection as typed signal extraction, not just regex-only findings.
  - [x] `cartography-cncf/cartography` gets leverage by mapping cloud identity artifacts into graph-reachable relationships instead of leaving them as isolated inventory facts.
  - [x] `stackrox/stackrox` and `falcosecurity/falco` both reinforce that runtime/security value compounds when credential evidence is connected to reachable resources, not just reported.

### Execution plan
- [x] Deepen secret scan output so findings can drive graph resolution:
  - [x] add typed secret references for cloud identities and database connections
  - [x] extract AWS access-key IDs, GCP service-account key identities, and database connection targets without persisting raw secrets
- [x] Materialize discovered secret artifacts into the workload graph:
  - [x] add secret nodes derived from workload scans
  - [x] link scan nodes to discovered secret artifacts
  - [x] link secret artifacts to matched graph principals/resources
- [x] Add first-class credential pivot edges:
  - [x] add `has_credential_for` graph edges from compromised workloads to resolved targets
  - [x] resolve cloud-identity credentials through blast radius so keys expand to concrete reachable resources
  - [x] map database connection strings directly to database nodes
- [x] Enrich cloud identity nodes with key metadata needed for pivot resolution:
  - [x] hydrate AWS IAM users from `aws_iam_user_access_keys`
  - [x] hydrate GCP service accounts with synced key metadata and privilege signals
- [x] Fold pivots into existing security reasoning:
  - [x] teach lateral-movement detection to recognize `has_credential_for`
  - [x] verify attack-path simulation traverses credential pivots
- [ ] Next credential depth cuts after this slice:
  - [ ] SSH private-key to `authorized_keys` matching across scanned workloads
  - [ ] Azure service-principal secret and connection-string pivot resolution
  - [ ] SaaS token pivots where the graph already models the target system
  - [ ] confidence scoring for weak/ambiguous target matches

## Deep Review Cycle 73 - GCP IAM Binding Fidelity + Bucket Resource Policies (2026-03-13)

### Review findings
- [x] Gap: issue `#245` is not blocked on broader GCP inventory first; the immediate enterprise-credibility hole is that Cerebro already syncs richer IAM policy structures but the graph flattens them back into lossy member-level edges.
- [x] Gap: `gcp_iam_policies` preserves binding conditions, but the builder used fallback member rows in a way that could discard those conditions and silently under-model real-world access controls.
- [x] Gap: GCS bucket IAM policies are already present in `gcp_storage_buckets.iam_policy`, but the graph was still missing resource-level permission edges for them, which leaves one of the most common GCP posture questions trapped in raw JSON.
- [x] Gap: upstream patterns line up on the same lesson:
  - [x] `cartography-cncf/cartography` keeps GCP storage, IAM, and Secret Manager as distinct resource families because enterprise GCP modeling breaks down quickly when everything is reduced to project-level metadata.
  - [x] `forseti-security/forseti-security` treated IAM and bucket posture as separate audit domains, which reinforces that resource-scoped GCS policy edges should be first-class graph material, not inferred later from a bucket boolean.
  - [x] `google/security-command-center-docs` style product expectations still imply the same substrate requirement: conditional grants and resource-local public access need to stay queryable as edges with provenance.

### Execution plan
- [x] Prefer richer project IAM policy bindings over collapsed member rows:
  - [x] keep `gcp_iam_policies` as the primary project-edge source
  - [x] only fall back to `gcp_iam_members` when policy bindings are unavailable
  - [x] preserve binding `condition` payloads on graph edges
- [x] Materialize GCS bucket IAM bindings as resource-level permission edges:
  - [x] parse bucket `iam_policy` bindings from `gcp_storage_buckets`
  - [x] emit `resource_policy`-marked edges to bucket nodes
  - [x] map `allUsers` to the shared `internet` principal so public grants participate in exposure/risk traversals
- [x] Harden builder parsing and tests:
  - [x] make the GCP IAM binding parser tolerant of full policy objects and raw binding arrays/JSON strings
  - [x] add regression coverage for policy-preferred condition preservation
  - [x] add regression coverage for bucket IAM public and explicit-principal edges
- [ ] Next GCP depth cuts after this slice:
  - [ ] org/folder/project hierarchy nodes and inherited IAM edges
  - [ ] Secret Manager nodes + access controls
  - [ ] Pub/Sub and KMS resource-level IAM edges
  - [ ] service-account impersonation chain modeling (`actAs`, `tokenCreator`)
  - [ ] Workload Identity Federation trust edges

## Deep Review Cycle 72 - AWS Resource-Policy Permission Depth (2026-03-13)

### Review findings
- [x] Gap: issue `#220` is not blocked by more raw AWS inventory first; the immediate substrate hole is that `aws_s3_bucket_policies` are synced but not materialized into the permission graph.
- [x] Gap: the effective-permissions calculator already has a conceptual `resource_policy` source type, but the builder never emitted edges that would exercise it.
- [x] Gap: object-scoped S3 policy resources such as `arn:aws:s3:::bucket/*` do not map cleanly into the current node model because Cerebro does not model individual objects yet; without an explicit bridge, the graph drops the permission entirely.
- [x] Gap: wildcard principals with conditions such as `aws:SourceVpce` should not be flattened into unconstrained public access until the graph can evaluate those conditions, or the model will overstate exposure.
- [x] Gap: upstream patterns line up on the same lesson:
  - [x] `duo-labs/cloudmapper` and `cartography-cncf/cartography` both get value from turning provider-specific permission structure into reusable graph edges rather than leaving it trapped in raw tables.
  - [x] `cloud-custodian/cloud-custodian` and `prowler-cloud/prowler` treat S3 public/cross-account policy nuance as a first-class AWS depth area, not a cosmetic property flag.
  - [x] the local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces the same product lesson: entity snapshots and relationship-heavy query surfaces only stay credible when resource-policy provenance is queryable instead of inferred from bucket booleans.

### Execution plan
- [x] Materialize S3 bucket resource-policy edges into the shared permission graph:
  - [x] parse `aws_s3_bucket_policies`
  - [x] emit `resource_policy`-marked edges for explicit principals
  - [x] conservatively emit `internet` edges only for unconstrained wildcard principals
  - [x] preserve statement actions, conditions, owner resource, and policy provenance on each edge
- [x] Bridge object-level selectors into the current bucket node model:
  - [x] map `arn:aws:s3:::bucket/*`-style resources back to the owning bucket until object nodes exist
- [x] Tighten effective-permission provenance:
  - [x] classify resource-policy edges as `resource_policy` in inheritance chains
  - [x] surface serialized policy conditions on `ResourceAccess`
  - [x] merge multiple direct edges to the same resource instead of overwriting them
- [x] Add regression coverage:
  - [x] builder test for explicit principal + public wildcard S3 bucket policy handling
  - [x] calculator test for resource-policy source tracking and condition propagation
- [ ] Next AWS depth cuts after this slice:
  - [ ] KMS key policy edges
  - [ ] Lambda resource-policy edges
  - [ ] condition-aware evaluation for common S3/IAM keys (`aws:SourceVpce`, org/account scoping, secure transport)
  - [ ] bucket policy status integration so public exposure uses evaluated policy state instead of public-access-block heuristics alone

## Deep Review Cycle 71 - Credential Source Abstraction and Vault/File-Backed Secret Reload (2026-03-13)

### Review findings
- [x] Gap: issue `#249` still had one giant configuration assumption: every secret had to arrive as a process env var even though the app already had a periodic secret-reload path.
- [x] Gap: reusing provider-facing `VAULT_*` fields as bootstrap config for secret loading would have leaked secret-source concerns into the provider registry and implicitly enabled the Vault provider whenever Vault-backed config was used.
- [x] Gap: the right upstream patterns are consistent:
  - [x] `hashicorp/vault` keeps one explicit client path for point-in-time secret reads and lease-aware rotation instead of smearing Vault logic across unrelated config code.
  - [x] `external-secrets/external-secrets` treats mounted/file-backed secrets as first-class sync targets, which matches Cerebro's existing periodic reload loop better than inventing a second watch subsystem immediately.
  - [x] `dagster-io/dagster` keeps storage/config backends behind typed seams so runtime code consumes contracts, not one-off env lookups.
  - [x] the local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces the same architectural lesson as the graph work: large query surfaces stay manageable only when source state is typed, inspectable, and decoupled from one bootstrap path.

### Execution plan
- [x] Add a standalone credential-source seam behind config loading:
  - [x] add `internal/secretsource` with `env`, `file`, and Vault KV implementations
  - [x] keep the source as a point-in-time snapshot per `LoadConfig()` pass so reload semantics remain deterministic
- [x] Wire `LoadConfig()` through the source seam without creating a second config system:
  - [x] keep existing `getEnv(...)` call sites
  - [x] add bootstrap-only raw config reads for credential-source settings
  - [x] make non-env credential sources override matching secret keys while normal config still falls back to env/config-file values
- [x] Keep provider/bootstrap boundaries explicit:
  - [x] add dedicated `CEREBRO_CREDENTIAL_VAULT_*` settings instead of reusing provider `VAULT_*` fields
  - [x] keep Vault provider enablement tied to provider config, not secret-source bootstrap
- [x] Reuse the existing reload path for rotation:
  - [x] file-backed secret updates are picked up by `ReloadSecrets()`
  - [x] provider/API credential rotation continues to flow through the existing rebuild path
  - [x] leave lease renewal and API-key grace-period semantics as explicit follow-on work instead of hand-wavy half-implementation
- [x] Add regression coverage and docs:
  - [x] credential file source tests
  - [x] Vault KV source tests
  - [x] `LoadConfig()` file/vault source tests
  - [x] reload test for updated file-backed API keys
  - [x] config docs update for new credential-source env vars

## Deep Review Cycle 70 - Pluggable Warehouse Backends and Local Zero-Dependency Graph Startup (2026-03-13)

### Review findings
- [x] Gap: issue `#250` still had the classic half-abstraction smell: `DataWarehouse` existed, but app bootstrap still hard-wired Snowflake as the only real warehouse path.
- [x] Gap: local startup could pretend to have a warehouse backend, but scanner watermark persistence still emitted Snowflake-only SQL (`TIMESTAMP_NTZ`, `MERGE`, `CURRENT_TIMESTAMP()`), so SQLite was not actually a first-class backend.
- [x] Gap: findings initialization still treated any warehouse `*sql.DB` as a Snowflake store, which would have made new backends inherit broken SQL semantics immediately.
- [x] Gap: the right upstream storage shapes are consistent:
  - [x] `openfga/openfga` keeps one storage contract with backend-specific packages plus shared SQL helpers (`pkg/storage`, `pkg/storage/sqlcommon`, `pkg/storage/postgres`, `pkg/storage/sqlite`).
  - [x] `authzed/spicedb` keeps datastore backends explicit (`internal/datastore/postgres`, `mysql`, `spanner`, `memdb`) instead of hiding backend semantics behind one magical implementation.
  - [x] `dagster-io/dagster` keeps storage base contracts separate from concrete SQLite/Postgres storage modules, which matches the direction Cerebro needs for warehouse selection.
  - [x] the local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces that broad graph/query surfaces stay tractable only when the underlying source layer is typed and backend-neutral instead of implicitly tied to one warehouse vendor.

### Execution plan
- [x] Add concrete warehouse backends behind `internal/warehouse`:
  - [x] add `SQLiteWarehouse`
  - [x] add `PostgresWarehouse`
  - [x] keep Snowflake as the existing production backend
- [x] Add backend selection during app bootstrap:
  - [x] add `WAREHOUSE_BACKEND=snowflake|sqlite|postgres`
  - [x] add `WAREHOUSE_SQLITE_PATH`
  - [x] add `WAREHOUSE_POSTGRES_DSN`
  - [x] default to Snowflake when Snowflake auth is present, otherwise default to SQLite for local zero-dependency startup
- [x] Make warehouse-adjacent persistence backend-aware:
  - [x] teach `scanner.WatermarkStore` SQLite-safe DDL/upsert semantics
  - [x] add PostgreSQL-safe watermark DDL/upsert semantics
  - [x] keep Snowflake merge-based persistence for the existing production path
- [x] Remove Snowflake leakage from non-Snowflake app startup:
  - [x] only use `findings.SnowflakeStore` when the Snowflake backend is actually selected
  - [x] keep SQLite findings persistence for SQLite/Postgres warehouse modes until a generic SQL findings store exists
  - [x] keep Snowflake-only repositories gated behind the real Snowflake client
- [x] Add regression coverage and docs:
  - [x] sqlite warehouse tests
  - [x] sqlite watermark persistence test
  - [x] sqlite-backend startup/graph readiness tests
  - [x] config docs update for warehouse backend env vars

## Deep Review Cycle 69 - Tenant-Scoped Graph Reads and Cross-Tenant Audit Guards (2026-03-13)

### Review findings
- [x] Gap: issue `#247` still had the classic half-secure shape: tenant context existed in middleware, but the graph/entity/intelligence/risk read surfaces were still free to operate on the full graph.
- [x] Gap: cross-tenant routes were reachable through generic graph permissions instead of one explicit permission boundary, which made the audit story weaker than the API shape implied.
- [x] Gap: the right upstream patterns are consistent:
  - [x] `openfga/openfga` keeps storage/authorization seams explicit instead of relying on ambient context in downstream handlers.
  - [x] `authzed/spicedb` treats multi-backend datastore structure as a first-class contract, which is the right lead-in for `#250` after tenant scoping is correct.
  - [x] `dagster-io/dagster` keeps execution/storage boundaries explicit, which matches the current shared execution-store and graph-persistence direction.
  - [x] the local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces that project/issue/entity surfaces stay usable only when tenant/project boundaries are first-class in the graph substrate.

### Execution plan
- [x] Add first-class tenant metadata to graph nodes:
  - [x] add `tenant_id` to `graph.Node`
  - [x] normalize `tenant_id` from node properties on write
  - [x] preserve `tenant_id` through cloned/scoped graph views
- [x] Add one shared tenant-scope graph helper:
  - [x] add `Graph.SubgraphForTenant(...)`
  - [x] treat untagged nodes as shared/global for the incremental rollout
  - [x] rebuild indexes on scoped graph views so entity search/suggest stay correct
- [x] Enforce tenant-scoped reads on high-value graph surfaces:
  - [x] platform entity list/search/detail/time-diff
  - [x] platform intelligence event/risk/report query surfaces
  - [x] graph risk traversal/query surfaces (`blast-radius`, `attack-paths`, `toxic-combinations`, etc.)
  - [x] platform knowledge read/diff surfaces
- [x] Add explicit cross-tenant authorization and audit:
  - [x] add `platform.cross_tenant.read`
  - [x] add `platform.cross_tenant.write`
  - [x] route `/api/v1/graph/cross-tenant/*` through explicit permissions instead of generic graph read/write
  - [x] add structured audit entries for allowed cross-tenant reads
  - [x] add Prometheus access counters by operation and requesting/target tenant pair
- [x] Add regression coverage:
  - [x] graph tenant normalization/scoping tests
  - [x] platform entity tenant isolation tests
  - [x] intelligence/risk tenant isolation tests
  - [x] cross-tenant audit + metrics tests

## Deep Review Cycle 68 - Distributed Graph Persistence Foundation and Replica Recovery (2026-03-12)

### Review findings
- [x] Gap: issue `#246` was still conceptually correct but operationally hollow; snapshot artifacts existed, yet the live graph did not actually depend on a shared graph-persistence seam for activation, recovery, or API/tool reads.
- [x] Gap: snapshot usage was fragmented across API handlers, graph intelligence handlers, replay code, and tool paths via ad hoc `GRAPH_SNAPSHOT_PATH` lookups instead of a shared store owned at the application layer.
- [x] Gap: the graph had no replica-aware recovery path. Losing the local snapshot directory still meant rebuilding from the warehouse even though the issue explicitly called for replicated durability.
- [x] Gap: the right abstractions were visible in upstream references:
  - [x] `dagster-io/dagster` keeps durable run storage behind one seam even while the execution/runtime layer stays hot and in-process.
  - [x] `temporalio/temporal` treats recovery and coordination state as infrastructure, not handler-local glue.
  - [x] the local Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` reinforces that broad graph/intelligence query surfaces only stay operable when snapshot/entity state is typed, inspectable, and recoverable.

### Execution plan
- [x] Add a shared graph persistence store:
  - [x] add `internal/graph/persistence_store.go`
  - [x] keep the current local snapshot store as the hot/local durability layer
  - [x] add replica backends for `file://`, `s3://`, and `gs://`
- [x] Deepen the snapshot substrate:
  - [x] add reusable compressed snapshot encode/decode helpers
  - [x] teach `SnapshotStore` to return typed persisted records/manifests for the latest saved snapshot
  - [x] expose latest-snapshot record loading for recovery and status
- [x] Move graph persistence to the app boundary:
  - [x] add shared config-backed `App.GraphSnapshots`
  - [x] initialize it during app bootstrap next to the shared execution store
  - [x] persist graph snapshots automatically on graph activation
  - [x] recover from the latest persisted snapshot before the warehouse rebuild completes
- [x] Move graph read surfaces onto the shared store:
  - [x] platform graph snapshot APIs
  - [x] graph intelligence temporal diff path
  - [x] tool temporal graph-diff helpers
- [x] Add health and regression coverage:
  - [x] register `graph_persistence` health
  - [x] add replica fallback tests
  - [x] add activation-time persistence tests

### Detailed follow-on backlog
- [ ] Track A - complete `#246` HA control plane
  - Exit criteria:
  - [ ] add one-writer lease semantics for rebuild / CDC apply
  - [ ] add follower hydration mode and readiness gates on replica freshness
  - [ ] add replica integrity verification sweeps and background repair
- [ ] Track B - persistence substrate hardening
  - Exit criteria:
  - [ ] move diff artifacts onto the shared graph persistence path instead of sibling local-only storage
  - [ ] add explicit replica lag / hydration metrics
  - [ ] add object-store integration coverage for `s3://` and `gs://` backends
- [ ] Track C - downstream partitioning and tenancy
  - Exit criteria:
  - [ ] land `#247` on top of the shared graph persistence seam rather than directly on raw in-memory graphs
  - [ ] push tenant/account partition keys into snapshot manifests and hydration boundaries

## Deep Review Cycle 67 - Graph Horizontal Scaling Path and Persistence Decision Gate (2026-03-12)

### Review findings
- [x] Gap: issue `#221` was still only a design statement; the repo had no executable graph scaling benchmark to prove where the current in-memory copy-on-write graph actually becomes the bottleneck.
- [x] Gap: issue `#209` introduced a shared execution-store seam, but the graph itself still had no equivalent decision gate for persistence, hydration, or multi-worker coordination.
- [x] Gap: the highest-risk next issues (`#246`, `#247`) were both correctly urgent but still premature to implement blindly; they needed a measured breakpoint and an explicit persistence recommendation first.
- [x] Gap: upstream references point at the same practical boundary:
  - [x] `dagster-io/dagster` keeps durable run/storage seams stable before deepening indexes and orchestration layers.
  - [x] `temporalio/temporal` treats coordination state as durable infrastructure, not process-local behavior.
  - [x] `OpenLineage/OpenLineage` and `open-metadata/OpenMetadata` reinforce typed lineage/state resources rather than ambient runtime glue.
  - [x] the Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` is a warning about broad query surfaces: pagination, counts, and typed connection resources only stay tractable when the underlying execution/persistence model is explicit.

### Execution plan
- [x] Add an executable graph scale profiler:
  - [x] add `internal/graph/scale_profile.go`
  - [x] benchmark build/index/search/suggest/blast-radius/snapshot/clone/copy-on-write/diff costs
  - [x] benchmark tiers `1K`, `10K`, `50K`, `100K`
- [x] Add a usable CLI surface:
  - [x] add `cerebro graph profile-scale`
  - [x] support `table` and `json` output
  - [x] support custom tiers and query-iteration counts
- [x] Add guardrail coverage:
  - [x] unit-test scale-spec normalization and synthetic topology generation
  - [x] test CLI registration and output rendering
- [x] Document the architectural decision:
  - [x] add `docs/GRAPH_HORIZONTAL_SCALING_ARCHITECTURE.md`
  - [x] recommend hybrid hot-graph + durable backing storage
  - [x] make `#246` and `#247` explicitly follow this decision gate instead of guessing
  - [x] capture the first local breakpoint:
    - [x] `1K` stays comfortably single-node (`8.5s` total run, `43.6ms` copy-on-write)
    - [x] `10K` already crosses into uncomfortable latency (`15.5s` total run, `11.3s` search, `533.6ms` copy-on-write)
    - [x] `50K+` exceeds sane single-node local profiling budgets and pushes resident memory into `~1.6-1.7 GiB`

### Detailed follow-on backlog
- [ ] Track A - `#246` durable graph persistence and HA
  - Exit criteria:
  - [ ] add durable graph snapshot manifests plus lineage/index metadata
  - [ ] support object-backed / replicated snapshot storage for read-graph hydration
  - [ ] add one-writer lease semantics for rebuild / CDC apply jobs
  - [ ] add follower hydration health and freshness lag reporting
- [ ] Track B - `#247` tenant/account partitioning
  - Exit criteria:
  - [ ] add tenant/account partition keys to graph snapshot and query paths
  - [x] enforce tenant-scoped query guards on platform graph reads
  - [x] add explicit audited cross-tenant read/report paths rather than ambient joins
- [ ] Track C - graph persistence backend decision
  - Exit criteria:
  - [ ] keep the hot graph in memory for low-latency traversals
  - [ ] move full graph durability to snapshot/log-backed storage before considering graph-DB migration
  - [ ] revisit Neo4j/Dgraph only if the hybrid model fails on measured operational complexity, not by default

## Deep Review Cycle 66 - Shared Execution Store Convergence (2026-03-12)

### Review findings
- [x] Gap: issue `#209` was still only partially true; the repo had a shared execution-store package, but report runs, action executions, consumer dedupe, and scan materialization still reopened concrete SQLite stores and therefore kept backend assumptions in leaf services.
- [x] Gap: that concrete `*executionstore.SQLiteStore` coupling would make a future multi-worker backend migration harder than it needs to be, which matters because SQLite is an acceptable default but not the long-term answer for larger customers.
- [x] Gap: API/server tests were still proving persistence behavior through wrapper ownership assumptions instead of the actual shared execution-store boundary.
- [x] Gap: GitHub/wider-project references reinforce the right seam:
  - [x] `dagster-io/dagster` keeps run state on a generic storage contract while layering richer indexes/tags on top.
  - [x] `argoproj/argo-workflows` keeps execution status and node state explicit rather than hiding orchestration state in process memory.
  - [x] the Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` is a useful reminder that broad query surfaces stay tractable only when the underlying execution resources remain typed and inspectable.

### Execution plan
- [x] Extract a backend-neutral shared execution-store contract:
  - [x] add `executionstore.Store`
  - [x] move callers off concrete `*executionstore.SQLiteStore` dependencies where they only need the shared contract
- [x] Centralize app-level shared execution-store ownership:
  - [x] initialize one shared app execution store from `EXECUTION_STORE_FILE`
  - [x] thread that shared handle into API/report/action/consumer paths when they point at the same underlying store
  - [x] keep wrapper-specific `Close()` semantics from accidentally closing borrowed shared stores
- [x] Preserve durable behavior while removing wrapper-owned assumptions:
  - [x] update report-run persistence tests to fail through the shared store itself
  - [x] keep scan/action/report/consumer paths green under the shared contract
- [x] Add follow-on scale direction to the backlog:
  - [x] document that SQLite remains the default implementation for now
  - [x] make “higher-scale backend behind `executionstore.Store`” the next scale seam instead of deepening SQLite-only code paths

## Deep Review Cycle 65 - Durable CloudEvent Deduplication for NATS Consumer (2026-03-12)

### Review findings
- [x] Gap: issue `#248` was still materially open because the JetStream consumer acknowledged events after handler success but had no durable CloudEvent-ID suppression, so transient ack failures and consumer restarts could re-run the same mutation path.
- [x] Gap: the issue proposal allowed an in-memory sliding window with periodic persistence, but that would still leave a correctness hole on restart and does not match the broader platform direction toward shared execution state.
- [x] Gap: consumer observability exposed redeliveries and dropped messages, but not the actual successful-vs-deduplicated throughput split needed to prove the pipeline is suppressing duplicates instead of just retrying them.
- [x] Gap: external references were directionally useful but not prescriptive here:
  - [x] `argoproj/argo-events` reinforces durable event-processing state over process-local memory when workflows restart.
  - [x] `OpenLineage/OpenLineage` reinforces treating event identity as a first-class contract surface instead of an incidental transport detail.
  - [x] the Wiz schema dump in `/Users/jonathanhaas/Downloads/other/wiz.graphql` is a useful caution that very broad event/query surfaces become harder to reason about unless identity and processing contracts are explicit and inspectable.

### Execution plan
- [x] Add durable processed-event storage in the shared execution store:
  - [x] add `processed_events` persistence + indexes in the SQLite execution store
  - [x] add processed-event lookup/remember helpers with TTL and bounded retention
- [x] Add consumer-level CloudEvent dedupe:
  - [x] derive a deterministic dedupe key from tenant/source/event ID
  - [x] skip handler execution when the CloudEvent is already recorded in the dedupe window
  - [x] log payload-hash mismatches for duplicate IDs carrying different payloads
- [x] Expose config and metrics:
  - [x] add NATS consumer dedupe env/config fields with validation
  - [x] add processed and deduplicated Prometheus counters
  - [x] document the new config in `docs/CONFIG_ENV_VARS.md`
- [x] Add regression coverage:
  - [x] execution-store round trip + bounded retention tests
  - [x] consumer duplicate suppression tests
  - [x] metrics registration coverage

### Detailed follow-on backlog
- [ ] Track A - Stronger idempotency semantics
  - Exit criteria:
  - [ ] add durable in-flight / completed processing states instead of completed-event memory only
  - [ ] thread idempotency keys into graph mutation write paths so handler replay becomes a true no-op
- [ ] Track B - Dedupe lifecycle observability
  - Exit criteria:
  - [ ] add dedupe-store health metrics and storage-pressure telemetry
  - [ ] expose dedupe hit/miss posture in consumer health/readiness reporting
- [ ] Track C - Ordered entity-local sequencing
  - Exit criteria:
  - [ ] add per-entity ordering windows for create/update/delete event families that cannot tolerate reorder
  - [ ] keep that sequencing logic separate from the generic dedupe window

## Deep Review Cycle 64 - Coverage Ratchet for Critical Packages: Sync + API (2026-03-12)

### Review findings
- [x] Gap: issue `#152` was still open even after warehouse/test seams improved because CI was still enforcing stale package floors: `internal/api` at `40%` despite already exceeding `55%`, and `internal/sync` at `11.5%` despite the highest orchestration complexity in the repo.
- [x] Gap: the real blocker was not `internal/api`; shared app test helpers already existed via `internal/apptest`, and package coverage was already above the requested floor.
- [x] Gap: `internal/sync` needed honest coverage work in the warehouse-backed orchestration seams we actually rely on today: sync coordination, CDC event emission, scoped persistence helpers, and provider-specific change-history paths.
- [x] Gap: external references reinforced the same discipline from different angles:
  - [x] `openfga/openfga` keeps transport and service seams narrow enough that handler/service tests are cheap instead of requiring full-process integration.
  - [x] `grafana/grafana` is the warning case for broad surface area where package-level ratchets only work if helper seams exist first.
  - [x] the Wiz schema dump in `/Users/jonathanhaas/Downloads/wiz.graphql` remains the opposite cautionary example: large ambient surfaces become difficult to test rigorously unless they are broken into explicit modules and query seams.

### Execution plan
- [x] Raise real sync coverage with warehouse-backed tests:
  - [x] add CDC builder tests for event IDs, payload extraction, and scope fallback
  - [x] add sync engine tests for change history, partial fetch backfill, and CDC emission
  - [x] add scoped table operation tests for scoped deletes, provider change history, and merge behavior
  - [x] add GCP/Kubernetes provider tests covering CDC emission and shared persistence helpers
  - [x] add helper/fetch-wrapper tests for retry helpers, region-limit helpers, and thin provider fetch delegates
- [x] Re-measure package coverage before touching CI:
  - [x] `internal/sync` now measures `21.0%`
  - [x] `internal/api` measures `64.4%`
- [x] Ratchet CI floors to measured reality:
  - [x] raise `internal/api` threshold from `40.0` to `55.0`
  - [x] raise `internal/sync` threshold from `11.5` to `20.0`

### Detailed follow-on backlog
- [ ] Track A - Next sync coverage ratchet to `30%`
  - Exit criteria:
  - [ ] add deeper relationship extraction tests for AWS/GCP relationship builders
  - [ ] add more provider fetch/retry edge-case coverage around partial-page and auth failure handling
  - [ ] raise the `internal/sync` CI floor from `20.0` to `30.0` only after measured package coverage holds above that mark with headroom
- [ ] Track B - Coverage by package seam, not full-process setup
  - Exit criteria:
  - [ ] keep using `internal/apptest` / warehouse memory doubles instead of reintroducing full Snowflake/process dependencies into unit suites
  - [ ] extract any remaining broad setup helpers only where a new handler or sync surface still cannot be tested cheaply
- [ ] Track C - Package split pressure
  - Exit criteria:
  - [ ] use the next `internal/sync` coverage wave to identify the worst ambient files for later package extraction
  - [ ] keep coverage work aligned with the larger graph/app package-boundary cleanup instead of growing more monolithic provider files

## Deep Review Cycle 63 - Graph Package Split Phase 1: Reports Extraction (2026-03-12)

### Review findings
- [x] Gap: issue `#141` was still materially open because `internal/graph` remained a monolith even after concurrency and execution-store work, so every report/runtime change still loaded the full graph namespace and its private helpers.
- [x] Gap: reports were the best first extraction seam because they already behaved like a distinct runtime: definitions, executions, attempts, events, snapshots, contract catalogs, and typed result models.
- [x] Gap: the first extraction surfaced exactly the hidden coupling we needed to expose: report code was reaching into private graph helpers for temporal visibility, schema/profile utilities, facet applicability, and JSON-schema cloning.
- [x] Gap: external references reinforced the same package-boundary lesson from different angles:
  - [x] `open-metadata/OpenMetadata` keeps report/test/catalog resources under explicit module seams rather than one ambient metadata package.
  - [x] `backstage/backstage` keeps plugin contracts in bounded packages and pushes shared primitives through explicit exported surfaces.
  - [x] `OpenLineage/OpenLineage` treats contract catalogs and lineage payloads as versioned resources, not incidental helper code.
  - [x] the Wiz GraphQL schema dump in `/Users/jonathanhaas/Downloads/wiz.graphql` exposes `185` top-level `Query` fields and `144` top-level `Mutation` fields, which is a concrete warning against letting one ambient graph surface absorb every report/runtime concern.

### Execution plan
- [x] Extract the report subsystem into `internal/graph/reports`:
  - [x] move typed report payloads, report registry/contracts, run/attempt/event history, snapshot logic, and report-store logic out of root `internal/graph`
  - [x] keep the root `graph` package focused on graph primitives, schemas, entities, knowledge, snapshots, and risk substrate
- [x] Replace implicit same-package access with explicit boundaries:
  - [x] add narrow exported compatibility helpers in `internal/graph/package_exports.go` where reports genuinely need root graph services
  - [x] move report-local helper behavior into `reports` where it should not be shared ambiently
  - [x] convert report node visibility from direct `g.mu`/`g.nodes` access to an exported `GetNodeBitemporal(...)` graph API
- [x] Rewire external callers onto the new package:
  - [x] update API/app/client/script imports from `graph.*report*` to `reports.*`
  - [x] keep graph snapshot record types in root `graph` while moving report-run and report-contract types into `reports`
  - [x] update report contract/result-schema strings from `graph.*` to `reports.*`
- [x] Regenerate and validate the report contract surface:
  - [x] regenerate `docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md`
  - [x] regenerate `docs/GRAPH_REPORT_CONTRACTS.json`
  - [x] run report contract compatibility checks after the package-path migration

### Detailed follow-on backlog
- [ ] Track A - `internal/graph/entities`
  - Exit criteria:
  - [ ] move entity query/detail/facet/subresource/search logic behind an `entities` package
  - [ ] eliminate report compatibility shims that currently expose entity-facet helper behavior from root `graph`
- [ ] Track B - `internal/graph/knowledge`
  - Exit criteria:
  - [ ] split claims/evidence/observations/sources/proofs/diffs/adjudication into a dedicated `knowledge` package
  - [ ] replace remaining root/entity cross-calls with exported interfaces or package-level query functions
- [ ] Track C - `internal/graph/risk`
  - Exit criteria:
  - [ ] isolate risk engine, toxic combos, attack paths, and feedback/calibration into a dedicated package
  - [ ] prevent report/intelligence code from depending on root risk internals beyond explicit exported types
- [ ] Track D - remove migration shims
  - Exit criteria:
  - [ ] audit `internal/graph/package_exports.go` and delete compatibility exports once downstream packages are properly split
  - [ ] keep only stable graph-surface APIs that are justified independently of the migration

## Deep Review Cycle 62 - Graph Concurrency Phase 1: Copy-on-Write Live Mutations (2026-03-12)

### Review findings
- [x] Gap: issue `#144` was still materially open even after builder extraction because the live app/API surfaces were mutating the current `SecurityGraph` instance directly, so copy-on-write rebuilds existed alongside in-place writes on the hot path.
- [x] Gap: platform knowledge reads and identity calibration were still reading the injected `SecurityGraph` field in the API dependency bundle rather than the runtime's current graph pointer, which made copy-on-write swaps invisible to some read surfaces.
- [x] Gap: TAP/NATS consumer paths still mutated the live graph directly in multiple places: legacy business fallback ingestion, declarative mapper application, identity resolution during mapper `resolve(...)`, interaction aggregation, and activity materialization.
- [x] Gap: external references reinforced the same boundary lesson from different angles: `temporalio/temporal` isolates mutable execution/history state behind explicit services, `argoproj/argo-workflows` separates executor/progress/sync responsibilities instead of one shared mutable runtime, `open-metadata/OpenMetadata` treats jobs/events/metadata reads as explicit resources, and the large Wiz GraphQL schema in `/Users/jonathanhaas/Downloads/wiz.graphql` is a useful warning about how fast one ambient graph surface becomes ungovernable when mutation/read boundaries are not explicit.

### Execution plan
- [x] Introduce an app-level live-graph mutation seam:
  - [x] add `MutateSecurityGraph(...)` and `MutateSecurityGraphMaybe(...)`
  - [x] perform clone/mutate/index/swap under `graphUpdateMu`
  - [x] preserve schema validation and metadata counts across swaps
  - [x] allow lazy graph initialization through the mutation seam instead of direct hot-path graph creation
- [x] Move platform/API writeback flows onto copy-on-write:
  - [x] route claim/observation/decision/outcome/annotation/identity/actuation handlers through the graph mutation seam
  - [x] fix lifecycle-event emission and tests to reference the swapped current graph instead of stale pointers
- [x] Move app/tool writeback flows onto copy-on-write:
  - [x] route Cerebro writeback tools through the same mutation seam
  - [x] update tool tests to assert against `CurrentSecurityGraph()` after writes
- [x] Fix stale live-read surfaces:
  - [x] switch platform knowledge handlers to `CurrentSecurityGraph()`
  - [x] switch identity calibration to `CurrentSecurityGraph()`
  - [x] add regressions proving writes become visible through the runtime read surface after swap
- [x] Move TAP consumer mutation paths onto copy-on-write:
  - [x] route legacy business fallback event ingestion through `MutateSecurityGraphMaybe(...)`
  - [x] route declarative mapper application through the mutation seam
  - [x] bind mapper `resolve(...)` identity writes to the candidate graph instead of the live graph pointer
  - [x] route interaction aggregation and activity materialization through the mutation seam
  - [x] keep event-correlation refresh asynchronous and post-swap instead of nested under the mutation lock
- [x] Prove the concurrency cut with regressions:
  - [x] add swap-semantics tests for app writebacks
  - [x] add swap-semantics tests for TAP fallback mutation
  - [x] add swap-semantics tests for declarative mapping plus identity resolution

### Detailed follow-on backlog
- [ ] Track A - Shared execution store
  - Exit criteria:
  - [ ] move report runs, runtime response attempts, scan executions, replay jobs, and future graph mutation jobs onto one shared execution-state substrate instead of per-process in-memory coordination
  - [ ] define common execution records for status, attempts, progress, lease/ownership, retry policy, and durable event history
  - [ ] make API/app/worker paths consume the same execution records so horizontal scale does not depend on sticky process memory
- [ ] Track B - Graph read-view isolation
  - Exit criteria:
  - [ ] identify the hottest read-heavy graph surfaces (`blast_radius`, entity facets, knowledge lists, event correlations) and decide which should remain direct graph traversals vs materialized read views
  - [ ] add benchmarks for concurrent read throughput during event-ingest write load
  - [ ] only introduce sharding or MVCC beyond copy-on-write where the benchmark shows actual lock pressure remains
- [ ] Track C - Consumer/runtime cleanup
  - Exit criteria:
  - [ ] remove remaining direct `a.SecurityGraph` hot-path reads in app services where `CurrentSecurityGraph()` is the correct runtime source
  - [ ] isolate TAP ingestion mutation helpers from read-only parsing helpers so the consumer file stops mixing event parsing, graph mutation, and runtime coordination in one surface
  - [ ] feed the same mutation seam into later package splits for `internal/graph/knowledge`, `internal/graph/entities`, and future worker-only graph executors

## Deep Review Cycle 60 - API Service Bundle + App Composition Root Narrowing (2026-03-12)

### Review findings
- [x] Gap: issue `#146` remained open because `internal/api` still stored `*app.App` directly, so the HTTP layer kept a hidden dependency on the full composition root even after earlier graph-intelligence service seams landed.
- [x] Gap: the current server constructor made later graph/package splitting harder because handler code could still reach through `s.app.*` for any field added to `App`.
- [x] Gap: sync/graph tests were implicitly proving the API surface against the full app object, not against a minimal dependency bundle that a future graph-only or worker binary could construct.
- [x] Gap: external project references kept pointing at the same architectural lesson: `openfga/openfga` keeps transport surfaces thin around explicit services, while larger server monoliths like `argoproj/argo-cd` and `grafana/grafana` show how quickly composition roots become ambient dependencies.

### Execution plan
- [x] Replace the server's direct `*app.App` dependency with an explicit dependency bundle:
  - [x] add `internal/api/server_dependencies.go`
  - [x] capture only the concrete services and narrow runtime interfaces the API layer actually consumes
  - [x] keep `NewServer(*app.App)` as an adapter around `NewServerWithDependencies(...)`
- [x] Preserve graph-runtime behavior without tying the API layer back to `App`:
  - [x] add a graph-runtime adapter that follows the server dependency bundle's current graph/builder fields
  - [x] preserve incremental graph-update and rebuild behavior for sync handlers and tests
- [x] Remove remaining direct `internal/app` imports from handler/service files:
  - [x] rewire graph-intelligence service construction through the dependency bundle instead of `*app.App`
  - [x] keep `internal/api` imports of `internal/app` limited to the constructor/adapter surface and test config types
- [x] Prove the new seam with minimal construction:
  - [x] add a test that instantiates `Server` through `NewServerWithDependencies(...)` and a stub graph runtime, without constructing a full `*app.App`
- [x] Pull external reference patterns with `gh` and fold them into the design:
  - [x] `openfga/openfga` for thin transport/service boundaries
  - [x] `argoproj/argo-cd` as the warning case for server/composition-root sprawl
  - [x] `grafana/grafana` as another example of how broad server surfaces need explicit dependency seams

### Detailed follow-on backlog
- [ ] Track A - Finish API service slicing
  - Exit criteria:
  - [ ] extract explicit dependency bundles for graph-risk, findings/compliance, and ticketing/runtime handler families instead of relying on a single broad server bundle
  - [ ] reduce `s.app.*` field access in handlers by routing new work through service-specific helpers or interfaces first
  - [ ] add more `NewServerWithDependencies(...)` tests that stub only the handler family under test
- [ ] Track B - App container decomposition
  - Exit criteria:
  - [ ] use the same consumption-point dependency inventory to shrink `internal/app.App`
  - [ ] feed the resulting seams into issue `#141` package splitting and issue `#144` graph concurrency work
  - [ ] make graph-only and scan-only processes construct dependency bundles without initializing unrelated services

## Deep Review Cycle 61 - Graph Package Split Phase 1: Builders Extraction (2026-03-12)

### Review findings
- [x] Gap: issue `#141` remained blocked because `internal/graph` still forced builder/ETL code, report contracts, knowledge logic, and core mutation/query code through one namespace and one import path.
- [x] Gap: the first attempted extraction showed `reports/` was not the right first cut yet; it still depended on too many package-private helpers and would have created a cosmetic split with hidden coupling.
- [x] Gap: `builders/` was the cleanest real leaf package, but the move still exposed ad hoc helper duplication (`query_rows`, JSON snapshot helpers, mutation formatting) that needed explicit shared seams instead of dot-import sprawl.
- [x] Gap: external references pointed at the same lesson from different directions: `temporalio/temporal` keeps execution/history concerns behind explicit service boundaries, `argoproj/argo-workflows` isolates executor/progress/sync packages instead of one workflow namespace, and the large Wiz GraphQL schema in `/Users/jonathanhaas/Downloads/wiz.graphql` is a useful warning about how fast graph-adjacent surfaces become one giant ambient API when boundaries are not enforced early.

### Execution plan
- [x] Extract the builder/ETL subsystem into its own package:
  - [x] move graph build orchestration, provider-specific builders, and Snowflake graph-source code into `internal/graph/builders`
  - [x] colocate builder-focused tests with that package
  - [x] update `internal/app` and `internal/api` to depend on the extracted builders package explicitly
- [x] Keep the split honest instead of over-extracting:
  - [x] revert the initial `reports/` package move after confirming the dependency boundary was still too porous
  - [x] leave report execution/registry code in `internal/graph` until it can depend on stable shared helpers rather than package-private reach-through
- [x] Replace ambient helper leakage with explicit bridges:
  - [x] add shared compatibility helpers for atomic JSON writes and snapshot-record loading in core graph
  - [x] add a builders-local helper layer instead of dot-importing core graph symbols
  - [x] move `GraphMutationSummary` formatting back into core so builders depend on graph contracts, not the reverse
- [x] Validate the first split as a real package boundary:
  - [x] keep full-repo tests green
  - [x] keep lint green after removing dot-import usage
  - [x] verify API/app graph consumers build against the new package seam

### Detailed follow-on backlog
- [ ] Track A - Continue domain package extraction
  - Exit criteria:
  - [ ] extract `internal/graph/knowledge` behind explicit read/write/query interfaces instead of direct core reach-through
  - [ ] extract `internal/graph/entities` with stable facet/query contracts
  - [ ] extract `internal/graph/reports` only after its helper/state dependencies are reduced enough to avoid a fake split
  - [ ] extract `internal/graph/risk` and `internal/graph/simulate` once the core query/mutation interfaces are narrow enough
- [ ] Track B - Shared graph utility boundary
  - Exit criteria:
  - [ ] move remaining cross-domain helpers out of `internal/graph` file-local scopes into explicit shared utility contracts
  - [ ] remove any remaining need for alias-heavy bridge files by narrowing builder/core interfaces further
  - [ ] ensure new sibling packages depend on interfaces or small exported contracts, not broad type alias sets
- [ ] Track C - Shared execution store convergence
  - Exit criteria:
  - [ ] route graph/report/runtime derivation execution metadata through `internal/executionstore` instead of package-local persistence patterns
  - [ ] unify correlation/report/materialization run records on a shared execution-store contract for multi-worker consistency
  - [ ] keep package extraction aligned with execution-store ownership so new packages do not invent their own run-state silos

## Deep Review Cycle 59 - Policy CEL Migration + Legacy Conversion Path (2026-03-12)

### Review findings
- [x] Gap: issue `#145` was still only half-solved if CEL existed beside the legacy parser but no migration surface existed for repository policies.
- [x] Gap: API validation and policy loading now rejected invalid CEL cleanly, but the public contract still did not advertise `condition_format`.
- [x] Gap: a credible migration needed a deterministic converter for the common legacy operator surface instead of a manual rewrite expectation.
- [x] Gap: CEL evaluation for converted policies needed safe helpers for legacy semantics like missing nested paths, recursive `CONTAINS` / `MATCHES`, and array membership.
- [x] Gap: the CLI still described Cerebro as Cedar-backed even after the policy engine seam had started moving to CEL.

### Execution plan
- [x] Harden the CEL runtime seam:
  - [x] extend the CEL environment with safe helper functions for path lookup, existence, recursive contains/matches, list coercion, membership, and comparison
  - [x] keep compiled CEL programs cached in the engine while preserving legacy-default behavior
- [x] Add legacy-to-CEL conversion helpers:
  - [x] add typed conversion helpers for comparisons, `exists` / `not exists`, `IN` / `NOT IN`, `MATCHES`, `CONTAINS`, `starts_with`, and nested `ANY` / `NOT ANY`
  - [x] add round-trip regression coverage comparing converted CEL conditions against the legacy evaluator
- [x] Add a real operator-facing migration surface:
  - [x] add `cerebro policy convert [policy-file]`
  - [x] support stdout JSON output by default and `--write` for in-place conversion
  - [x] add CLI regression coverage
- [x] Update public/docs contract:
  - [x] advertise `condition_format` in OpenAPI
  - [x] update CLI copy to describe the CEL-backed policy engine
- [x] Pull external reference patterns with `gh` and fold them into the design:
  - [x] `google/cel-go` for the core parse/check/program model and extension registration shape
  - [x] `kubernetes/kubernetes` for practical CEL migration pressure in real policy surfaces
  - [x] `open-policy-agent/opa` as the contrast point for “policy engine” scope versus lightweight embedded expressions

### Detailed follow-on backlog
- [ ] Track A - Full repository migration
  - Exit criteria:
  - [ ] convert repository policies that are trivially translatable to `condition_format: cel`
  - [ ] report the remaining non-trivial policy files that still need manual review
  - [ ] decide when to flip new authored policies to CEL by default
- [ ] Track B - Legacy parser retirement
  - Exit criteria:
  - [ ] add shadow/dual evaluation for a bounded migration window if policy drift appears
  - [ ] remove the legacy recursive-descent evaluator once repo policies and API-created policies are predominantly CEL
  - [ ] delete legacy-only parser helpers no longer needed by conversion tooling

## Deep Review Cycle 58 - API Service Seams for Graph Intelligence Handlers (2026-03-12)

### Review findings
- [x] Gap: issue `#146` was still open because API handlers were reaching through `*app.App` for graph-intelligence reads, even after shared app-aware test helpers landed in cycle 47.
- [x] Gap: graph-intelligence routes mixed three concerns in one place: transport parsing, graph/report logic, and mapper/runtime configuration reads from `App`.
- [x] Gap: existing API tests still proved the handler family only through the full app container, not through a narrow consumption-point service seam.
- [x] Gap: external project references showed the same split pressure repeatedly: `openfga/openfga` keeps handler packages thin around narrower service/command seams, while `argoproj/argo-cd`'s large server surface is the cautionary example to avoid reproducing.

### Execution plan
- [x] Add a narrow graph-intelligence handler service surface:
  - [x] add `internal/api/server_services_graph_intelligence.go`
  - [x] model only the primitives this handler family actually consumes: current graph, mapper initialization, mapper stats, mapper config, and mapper contract catalog
  - [x] keep `*app.App` as the composition root by adapting it into that interface in `NewServer(...)`
- [x] Remove direct `*app.App` reach-through from the graph-intelligence handler family:
  - [x] route event-correlation, intelligence, quality, ingest-health, contract, weekly calibration, and graph-query reads through the new service seam
  - [x] keep legacy server-wide `app` access for unrelated handler families until their own slices are extracted
- [x] Prove the seam with a minimal mock:
  - [x] add a stub `graphIntelligenceService` in API tests
  - [x] force `app.SecurityGraph` / `TapEventMapper` to `nil` in the test and verify the handlers still operate through the stub service
- [x] Fold `gh` research into the design:
  - [x] `openfga/openfga` for thinner server/command boundaries
  - [x] `argoproj/argo-cd` as the anti-pattern warning for server monolith drift
  - [x] `grafana/grafana` as another example of large surface area needing consumption-point seams

### Detailed follow-on backlog
- [ ] Track A - Broaden handler/service decomposition
  - Exit criteria:
  - [ ] extract equivalent seams for findings/compliance, platform knowledge, and graph-risk handler families
  - [ ] reduce `internal/api` direct `s.app.*` reach-through counts materially from the current baseline
  - [ ] make new handler slices testable with interface stubs before touching the wider app container
- [ ] Track B - Constructor cleanup
  - Exit criteria:
  - [ ] decide whether `Server` should grow explicit dependency bundles/options instead of only `NewServer(*app.App)`
  - [ ] keep `App` as composition root while preventing new handler code from reaching back through it ad hoc

## Deep Review Cycle 57 - Cross-Event Correlation + Incident Pattern Detection (2026-03-12)

### Review findings
- [x] Gap: issue `#170` was still leaving Cerebro with event nodes but no shared causal layer, so analysts and agents still had to manually infer `PR -> deploy -> incident` chains from raw neighbors.
- [x] Gap: graph activation and live TAP ingest were both materializing event nodes independently, but neither path was projecting durable `triggered_by` / `caused_by` edges back into the graph substrate.
- [x] Gap: temporal pattern detection needed to be a typed catalog, not a report-only heuristic blob, or downstream APIs/tools would drift into duplicated correlation logic.
- [x] Gap: anomaly detection for event rates had no baseline contract, so operational reports could not distinguish one-off incidents from real volume spikes.
- [x] Gap: the platform intelligence surface had no dedicated read/tool endpoint for causal event neighborhoods.

### Execution plan
- [x] Add graph-level event-correlation substrate:
  - [x] add built-in edge kinds `triggered_by` and `caused_by`
  - [x] extend schema registry allowances for `deployment_run` and `incident`
  - [x] add `internal/graph/event_correlation.go` with typed pattern catalog and deterministic edge IDs
  - [x] materialize `pull_request -> deployment_run` and `deployment_run -> incident` chains from shared service target context plus time windows
- [x] Add baseline anomaly summaries:
  - [x] compare current 7d windows against the prior 28d baseline
  - [x] flag failed-deployment spikes
  - [x] flag first incident activity in 90d
- [x] Wire both graph build paths:
  - [x] rematerialize event correlations during `activateBuiltSecurityGraph(...)`
  - [x] rematerialize event correlations on live TAP declarative mappings when relevant event kinds change
- [x] Add platform read surfaces:
  - [x] `GET /api/v1/platform/intelligence/event-patterns`
  - [x] `GET /api/v1/platform/intelligence/event-correlations`
  - [x] `GET /api/v1/platform/intelligence/event-anomalies`
- [x] Add agent-facing tool surface:
  - [x] `cerebro.correlate_events`
  - [x] tool regression coverage
- [x] Add focused regression coverage:
  - [x] graph-level causal chain materialization
  - [x] graph-level anomaly detection
  - [x] live TAP ingest correlation materialization
  - [x] platform intelligence endpoint coverage
- [x] Pull external reference patterns with `gh` and fold them into the design:
  - [x] `argoproj/argo-events` trigger registry shape
  - [x] `OpenLineage/OpenLineage` explicit lineage contract surface
  - [x] `falcosecurity/falco` typed event-pattern/rule engine inspiration

### Detailed follow-on backlog
- [ ] Track A - Correlation rule expansion
  - Exit criteria:
  - [ ] add typed patterns for `pipeline_run -> deployment_run`, `check_run -> deployment_run`, and `incident -> decision/action/outcome`
  - [ ] support multi-step correlation chains without recomputing the entire graph client-side
  - [ ] attach confidence decay/ambiguity scoring when multiple candidate causes exist
- [ ] Track B - Shared execution + persistent derivation store
  - Exit criteria:
  - [ ] move event-correlation execution metadata out of process memory and into the shared execution store boundary
  - [ ] persist correlation runs / refresh metadata for multi-worker consistency
  - [ ] make manual re-correlation and backfill operations first-class platform jobs
- [ ] Track C - Report and simulation integration
  - Exit criteria:
  - [ ] expose correlation chains directly in incident, runtime, and org-dynamics reports
  - [ ] feed correlation edges into simulation/explanation payloads instead of duplicating neighborhood traversal
  - [ ] attach supporting evidence/claim lineage to correlation edges where source artifacts exist
- [ ] Track D - Asset/runtime deepening
  - Exit criteria:
  - [ ] connect image/workload scan findings into the same causal graph so deploy/runtime/incident chains become asset-aware
  - [ ] project runtime response executions and containment outcomes into event correlation chains
  - [ ] extend anomaly baselines with workload/image/runtime dimensions once shared execution storage is in place

## Deep Review Cycle 56 - Runtime Response Executors + Capability Boundaries (2026-03-12)

### Review findings
- [x] Gap: issue `#154` was still leaving runtime response policies half-stubbed even after the shared action engine landed in issue `#143`.
- [x] Gap: default runtime policies referenced `kill_process`, `isolate_container`, `block_ip`, `block_domain`, `revoke_credentials`, and `scale_down`, but only the action model existed; no concrete executor coverage was wired in app runtime initialization.
- [x] Gap: Cerebro needed an explicit split between direct local actions, Ensemble-delegated actions, and control-plane side effects instead of one undifferentiated handler interface.
- [x] Gap: scale-down actions needed a typed workload target contract or they would stay permanently heuristic and silently broken.
- [x] Gap: the architecture/docs still had no record of which runtime actions are genuinely local today versus which ones require remote actuator coverage.
- [x] Gap: default destructive runtime policies were auto-executing against finding-derived target identifiers without a trusted source/ownership gate.

### Execution plan
- [x] Add a concrete runtime action handler:
  - [x] add `internal/runtime/action_handler.go`
  - [x] implement direct local handlers for `block_ip`, `block_domain`, and `scale_down`
  - [x] implement Ensemble delegation for `kill_process`, `isolate_container`, `isolate_host`, `quarantine_file`, and `revoke_credentials`
  - [x] return typed capability errors when a remote-only action has no remote tool provider configured
- [x] Tighten scale-down targeting:
  - [x] add typed workload target parsing via `deployment:namespace/name` and `statefulset:namespace/name`
  - [x] resolve scale-down targets from runtime finding metadata before dispatch
  - [x] use Kubernetes client-go scale updates for direct workload scale-down
- [x] Wire runtime response initialization in the app:
  - [x] set `runtime.NewDefaultActionHandler(...)` during `initRuntime()`
  - [x] feed the runtime blocklist and optional `RemoteTools` provider into that handler
- [x] Add trust boundaries for destructive actuation:
  - [x] require a trusted actuation scope before destructive runtime targets are accepted
  - [x] force the default destructive runtime policies back behind approval until source identity binding exists
  - [x] reject out-of-range direct scale-down replica counts
- [x] Add focused regression coverage:
  - [x] blocklist containment tests
  - [x] Ensemble delegation tests
  - [x] scale-down target resolution tests
  - [x] app/runtime focused validation on the new handler path
- [x] Capture architecture + external references:
  - [x] add `docs/RUNTIME_RESPONSE_EXECUTION_ARCHITECTURE.md`
  - [x] pull runtime/executor reference patterns via `gh` from `falcosecurity/falco`, `stackrox/stackrox`, and `aquasecurity/trivy-operator`

### Detailed follow-on backlog
- [ ] Track A - Remote runtime action packs
  - Exit criteria:
  - [ ] publish documented contracts for `security.runtime.*` remote tools
  - [ ] add at least one reference implementation for host/container/process enforcement
  - [ ] make provider/action capability discovery queryable
- [ ] Track B - Direct provider-native containment
  - Exit criteria:
  - [ ] add first-class cloud credential revocation for supported providers
  - [ ] add provider-native network containment instead of best-effort remote tooling only
  - [ ] decide whether host isolation remains remote-only or grows direct cloud implementations
- [ ] Track C - Shared execution + distributed enforcement
  - Exit criteria:
  - [ ] stop treating runtime blocklists as process-local state only
  - [ ] attach runtime containment state to a shared execution/control-store boundary
  - [ ] propagate enforcement state cleanly across multi-worker/runtime instances
- [ ] Track D - Graph/incident integration
  - Exit criteria:
  - [ ] project runtime response executions and containment outcomes into the graph
  - [ ] connect runtime action outcomes to findings, workload vulnerability context, and incident timelines
  - [ ] feed issue `#170` cross-event correlation with concrete response-action outcomes

## Deep Review Cycle 55 - Shared Action Engine + Durable Security Actuation (2026-03-12)

### Review findings
- [x] Gap: issue `#143` still existed because remediation and runtime response were maintaining separate approval, sequencing, and execution-status models for the same underlying action problem.
- [x] Gap: issue `#154` would have duplicated "real executor" work again unless both application surfaces moved onto one shared substrate first.
- [x] Gap: the repo already had a shared execution-store seam, but security actuation was not using it consistently and could still drift back into process-local orchestration.
- [x] Gap: runtime approval flows were at risk of losing original finding context unless the triggering payload was preserved end-to-end through approval and execution.
- [x] Gap: a naive lock-scoped runtime refactor would deadlock or serialize action execution behind policy-map reads.

### Execution plan
- [x] Add a shared action-engine substrate:
  - [x] add `internal/actionengine` with typed `Signal`, `Trigger`, `Playbook`, `Step`, `Execution`, and `Event`
  - [x] add trigger matching, approval gating, ordered step execution, timeout handling, and failure-policy support
  - [x] persist executions and events through `internal/executionstore` under namespace `action_engine`
- [x] Replatform remediation execution on top of the shared action engine:
  - [x] map remediation rules to shared playbooks
  - [x] map trigger data to shared signals
  - [x] map shared execution state/results back onto remediation-native execution records
- [x] Replatform runtime response execution on top of the shared action engine:
  - [x] map response policies to shared playbooks
  - [x] map findings to shared signals
  - [x] preserve full finding payload in `TriggerData` so approval resumes with the original context
- [x] Wire app initialization to one durable action executor:
  - [x] build the executor from `EXECUTION_STORE_FILE`
  - [x] inject it into both remediation and runtime services
  - [x] keep in-memory fallback only as defensive startup behavior when the durable store cannot initialize
- [x] Harden concurrency and regression coverage:
  - [x] add `internal/actionengine/executor_test.go`
  - [x] add runtime approval-context regression coverage in `internal/runtime/response_test.go`
  - [x] fix the runtime policy lock-upgrade deadlock by copying matched policy state before execution creation
- [x] Capture the architecture and upstream learnings:
  - [x] add `docs/ACTION_ENGINE_ARCHITECTURE.md`
  - [x] pull reference patterns via `gh` from `StackStorm/st2`, `argoproj/argo-events`, and `argoproj/argo-workflows`

### Detailed follow-on backlog
- [ ] Track A - Shared action read/control surface
  - Exit criteria:
  - [ ] expose durable action executions and events over a typed API surface instead of application-local lists only
  - [ ] decide which parts belong under platform actions vs security application aliases
  - [ ] unify approval/reject/read semantics across remediation and runtime on top of the shared store
- [ ] Track B - Real executors on one substrate
  - Exit criteria:
  - [ ] land issue `#154` on top of `internal/actionengine` rather than extending runtime-only executors
  - [ ] support executor capability metadata so unsupported steps fail predictably before dispatch
  - [ ] capture provider/action output in shared execution events instead of one-off native structs
- [ ] Track C - Shared execution store extraction
  - Exit criteria:
  - [ ] decide whether SQLite remains sufficient for multi-worker action execution
  - [ ] define locking/lease semantics for multi-process action runners
  - [ ] avoid introducing new per-subsystem state stores for actions, scans, and graph jobs
- [ ] Track D - Graph/world-model integration
  - Exit criteria:
  - [ ] project action executions, approvals, and outcomes into claim/action/outcome graph primitives where it improves explanation and auditability
  - [ ] attach remediation/runtime outcomes back to finding, vulnerability, and incident context
  - [ ] connect future issue `#170` correlation work to the shared action execution timeline

## Deep Review Cycle 54 - Workload Scan Graph Projection + Attack-Path Context (2026-03-12)

### Review findings
- [x] Gap: issue `#182` was still sitting as architecture intent only; successful workload scans were durable in the shared execution store but still absent from the live security graph.
- [x] Gap: entity summary surfaces had no typed workload-security facet, so vulnerability depth, scan freshness, and attack-path context were still disconnected at read time.
- [x] Gap: the world-model/security docs still described workload scan graph projection as future work, even though the ontology and execution-store seams were already in place.
- [x] Gap: older scans needed temporal supersession semantics instead of naive append-only "latest wins" behavior.

### Execution plan
- [x] Extend the ontology for workload security projection:
  - [x] add node kinds `workload_scan`, `package`, and `vulnerability`
  - [x] add edge kinds `has_scan`, `contains_package`, `found_vulnerability`, and `affected_by`
  - [x] register schema contracts and runtime tests for the new kinds
- [x] Materialize durable workload scan runs from the shared execution store into the graph:
  - [x] add `internal/workloadscan/graph_materialization.go`
  - [x] resolve VM scan targets against existing canonical instance nodes
  - [x] preserve temporal supersession by setting `valid_to` on older scans when newer successful scans exist for the same workload
  - [x] keep graph writes idempotent on repeated hydration
- [x] Add workload-aware entity summaries:
  - [x] add `workload_security` facet contract
  - [x] surface last scan time, OS/package/vulnerability counts, KEV/fixable counts, and stale-scan signals
  - [x] fold in attack-path context via exposure, blast-radius admin reachability, and sensitive-data path counts
- [x] Wire graph activation to hydrate workload scan state:
  - [x] load successful workload scans from `WORKLOAD_SCAN_STATE_FILE`
  - [x] project them into the built security graph before activation
  - [x] keep the shared execution store as the durability boundary rather than introducing another in-memory side channel
- [x] Add focused regression coverage:
  - [x] materialization node/edge tests in `internal/workloadscan/graph_materialization_test.go`
  - [x] workload facet temporal visibility and attack-path context tests in `internal/graph/workload_security_facet_test.go`

### Detailed follow-on backlog
- [ ] Track A - Scan family parity
  - Exit criteria:
  - [ ] project image scan runs into the same `package` / `vulnerability` ontology
  - [ ] project function scan runs into the same ontology
  - [ ] converge image/function/workload asset facets on one reusable workload-security/read model
- [ ] Track B - Real-time graph refresh
  - Exit criteria:
  - [ ] add a fast-path consumer or job hook for `security.workload_scan.completed`
  - [ ] avoid waiting for the next graph rebuild/incremental apply cycle before new scan context appears
  - [ ] decide whether scan-driven graph projection becomes its own execution resource/job surface
- [ ] Track C - Claim/evidence projection depth
  - Exit criteria:
  - [ ] project package/vulnerability matches as first-class observations/evidence/claims, not just nodes and edges
  - [ ] attach advisory source attribution, confidence, and remediation decisions directly to vulnerability context
  - [ ] connect remediation outcomes back to workload scan history
- [ ] Track D - Prioritization depth
  - Exit criteria:
  - [ ] feed workload vulnerability context into risk-engine/ranking surfaces instead of entity summary only
  - [ ] distinguish exploitable-but-contained vs exploitable-and-exposed workloads in platform intelligence reports
  - [ ] include cross-account and crown-jewel reachability directly in vulnerability prioritization views

## Deep Review Cycle 53 - Persisted Vulnerability DB + Package Matching Pipeline (2026-03-12)

### Review findings
- [x] Gap: issue `#181` still existed only as an issue outline; there was no first-class persisted advisory knowledge layer behind the new shared filesystem analyzer.
- [x] Gap: package inventories from workload/image/function scans could be cataloged, but they were still dependent on scanner-local vulnerability bridging instead of one reusable package matcher.
- [x] Gap: KEV/EPSS/advisory context was not persisted together, which meant exploitability enrichment would drift between scan runtimes.
- [x] Gap: the repo still lacked a concrete operator surface for importing and inspecting the vulnerability database.
- [x] Gap: the architecture docs still described issue `#181` as future work even though the analyzer/runtime seams were already ready to consume a native advisory substrate.

### Execution plan
- [x] Add a persisted advisory store:
  - [x] add `internal/vulndb` with typed `Vulnerability`, `AffectedPackage`, `SyncState`, and `Stats` records
  - [x] persist advisories, aliases, package ranges, and sync state in SQLite at `VULNDB_STATE_FILE`
  - [x] support KEV/EPSS enrichment on the same canonical advisory record
- [x] Add a reusable advisory matching service:
  - [x] implement `vulndb.Service` as the shared package matcher
  - [x] normalize package ecosystems and map matches into `scanner.ImageVulnerability`
  - [x] start with semver-like ecosystem matching while keeping the storage contract broader than the current comparator depth
- [x] Wire the shared filesystem analyzer to the advisory layer:
  - [x] add `filesystemanalyzer.PackageVulnerabilityMatcher`
  - [x] allow workload/image/function scan CLIs to build analyzers backed by the persisted vulnerability DB
  - [x] keep existing Trivy-based bridging as fallback-compatible analyzer behavior instead of the only path
- [x] Add operator surface:
  - [x] add `cerebro vulndb stats`
  - [x] add `cerebro vulndb import-osv`
  - [x] add `cerebro vulndb import-kev`
  - [x] add `cerebro vulndb import-epss`
  - [x] add `cerebro vulndb sync`
- [x] Capture architecture and upstream learnings:
  - [x] add `docs/VULNERABILITY_DB_ARCHITECTURE.md`
  - [x] update shared analyzer + runtime docs to reflect the native advisory layer
  - [x] document GitHub-researched patterns from Trivy DB, Grype, OSV Scanner, and GitHub Advisory Database
- [x] Add focused regression coverage:
  - [x] advisory import + match + KEV/EPSS enrichment round trip
  - [x] CLI registration coverage for the new `vulndb` command group
  - [x] analyzer/runtime package integration coverage via focused package tests

### Detailed follow-on backlog
- [ ] Track A - Source breadth and sync execution
  - Exit criteria:
  - [ ] add NVD feed ingestion with delta semantics and stored cursors/ETags
  - [ ] add GitHub Advisory Database ingestion without depending on unstable `database_specific` fields
  - [ ] add distro advisory ingestion for `deb`, `rpm`, and `apk`
  - [ ] move feed sync orchestration onto the shared execution-store package instead of CLI-only sequencing
- [ ] Track B - Version comparator depth
  - Exit criteria:
  - [ ] add RPM version comparison semantics
  - [ ] add Debian/Ubuntu package version comparison semantics
  - [ ] add Alpine `apk` version comparison semantics
  - [ ] add ecosystem-specific edge-case coverage for prereleases, epochs, and vendor backports
- [ ] Track C - Scan/runtime integration depth
  - Exit criteria:
  - [ ] replace the remaining scanner-local vulnerability bridge paths with the shared matcher where practical
  - [ ] persist scan-package-to-advisory evidence in a reusable artifact format instead of transient finding-only output
  - [ ] expose advisory database stats/sync health over API or report surfaces where operators already look
- [ ] Track D - Graph and prioritization projection
  - Exit criteria:
  - [x] map workload scan vulnerabilities/packages into canonical graph entities and edges in issue `#182`
  - [ ] attach fix availability, KEV, EPSS, and runtime exposure context to prioritization
  - [ ] use advisory recency and exploitability as first-class report dimensions

## Deep Review Cycle 52 - Shared Filesystem Analyzer + Shared Execution Store (2026-03-11)

### Review findings
- [x] Gap: issue `#180` still existed only as a problem statement; workload, image, and function scans still used thin or stub analyzers instead of one shared filesystem cataloger.
- [x] Gap: the repo still had three near-identical scan run stores, which meant `EXECUTION_STORE_FILE` was a shared path but not a shared execution substrate.
- [x] Gap: workload scans were still defaulting to a noop analyzer in the CLI even though image and function scans had already started to grow filesystem analysis seams.
- [x] Gap: the architecture docs still described the scan stack as “later shared” instead of documenting the actual shared execution/analyzer boundaries the code now needs.
- [x] Gap: issue `#181` needed a stable package/SBOM catalog contract to consume, not more Trivy-only runtime glue.

### Execution plan
- [x] Extract a shared execution-store package:
  - [x] add `internal/executionstore` with shared `execution_runs` and `execution_events` tables
  - [x] refactor `internal/workloadscan`, `internal/imagescan`, and `internal/functionscan` stores onto that package
  - [x] keep runtime-level `RunStore` APIs stable while collapsing duplicate SQLite logic underneath
- [x] Add a real shared filesystem analyzer:
  - [x] add `internal/filesystemanalyzer`
  - [x] catalog OS identity, package inventory, SBOM components, secrets, and config findings from one mounted filesystem
  - [x] bridge vulnerabilities through `scanner.FilesystemScanner` so the advisory layer can be swapped in later
  - [x] add optional malware-engine seam instead of baking malware logic into one runtime
- [x] Converge scan runtimes on the shared analyzer:
  - [x] wire image scans through the shared cataloger
  - [x] wire function scans through the shared cataloger while keeping env/runtime-specific findings
  - [x] replace workload scan CLI noop analysis with the shared cataloger
  - [x] add workload scan Trivy config/flag parity
- [x] Capture the architecture shift:
  - [x] add `docs/FILESYSTEM_ANALYZER_ARCHITECTURE.md`
  - [x] update workload/image/function architecture docs to reflect the new analyzer/store reality
  - [x] document GitHub-researched upstream patterns from Trivy, Syft, Grype, OSV Scanner, and KubeClarity
- [x] Add regression coverage:
  - [x] test shared execution-store namespace isolation and event sequencing
  - [x] test filesystem analyzer package/secret/config/SBOM extraction
  - [x] verify runtime/CLI/app integration still compiles and passes

### Detailed follow-on backlog
- [ ] Track A - Advisory knowledge layer (`#181`)
  - Exit criteria:
  - [x] replace the Trivy vulnerability bridge with a first-class advisory matcher over the shared package catalog
  - [ ] ingest NVD/OSV/distro advisory data into a reusable knowledge surface
  - [x] score vulnerabilities with fix availability, KEV, EPSS, and distro/package context
- [ ] Track B - Graph contextualization (`#182`)
  - Exit criteria:
  - [x] map workload scan runs, packages, vulnerabilities, and SBOM coverage into canonical graph node/edge kinds
  - [x] attach workload scan freshness and exposure context to entity prioritization paths
  - [x] surface workload security facets with attack-path-aware context
  - [ ] extend the same graph contextualization to image and function scans
- [ ] Track C - Analyzer coverage depth
  - Exit criteria:
  - [ ] add RPM parsing and deeper language ecosystem coverage
  - [ ] add Windows artifact parsing
  - [ ] add persisted SBOM artifact storage instead of in-run embedding only
- [ ] Track D - Distributed execution
  - Exit criteria:
  - [ ] decide whether the shared execution store remains SQLite or moves to a multi-worker backend
  - [ ] expose execution resources over platform APIs instead of CLI-only delivery
  - [ ] add migration/import for legacy runtime-specific state tables if backward persistence compatibility matters

## Deep Review Cycle 51 - Durable Serverless Function Scan Runtime (2026-03-11)

### Review findings
- [x] Gap: issue `#179` still existed only as a problem statement; there was no durable serverless function package scan runtime or operator surface.
- [x] Gap: AWS Lambda layers, GCP source archives, and Azure run-from-package downloads all needed API-driven acquisition behind one shared contract instead of cloud-specific ad hoc flows.
- [x] Gap: the repo was at risk of creating a third execution-state silo unless function scans defaulted to the same `EXECUTION_STORE_FILE` durability boundary as workload and image scans.
- [x] Gap: source/package scanning needed to reuse the same filesystem analyzer seam rather than inventing a separate “serverless-only” scanner path.
- [x] Gap: issue `#179` needed an explicit architecture note capturing the external patterns worth reusing from Trivy, Syft, Semgrep, and OSV Scanner.

### Execution plan
- [x] Add a durable function scan runtime under `internal/functionscan`:
  - [x] add typed run, event, descriptor, artifact, filesystem, and analysis contracts
  - [x] persist runs/events in SQLite
  - [x] add a local ZIP materializer with symlink/traversal protection and ordered layer/package application
- [x] Add provider-specific acquisition seams:
  - [x] add AWS Lambda provider with function ZIP + layer download support
  - [x] add GCP Cloud Functions provider with Cloud Storage source archive support
  - [x] add Azure Functions provider with `WEBSITE_RUN_FROM_PACKAGE` / `SCM_RUN_FROM_PACKAGE` download support
- [x] Reuse the shared analyzer seam:
  - [x] add `FilesystemAnalyzer` backed by `scanner.TrivyFilesystemScanner`
  - [x] detect environment secrets, code secrets, and curated runtime deprecation
  - [x] redact presigned/package URLs in operator-visible errors
- [x] Add operator/config surface:
  - [x] add `cerebro function-scan list`
  - [x] add `cerebro function-scan run aws|gcp|azure`
  - [x] add function-scan env/config controls with `EXECUTION_STORE_FILE` fallback
  - [x] add lifecycle webhook event types for function scans
- [x] Add architecture/test coverage:
  - [x] add function scan architecture doc with OSS implementation references
  - [x] add store round-trip regressions
  - [x] add materializer ordering/safety regressions
  - [x] add persisted runner lifecycle and URL-redaction regressions

### Detailed follow-on backlog
- [ ] Track A - Analyzer depth
  - Exit criteria:
  - [x] replace the thin Trivy-plus-heuristics analyzer path with the richer shared filesystem analyzer from issue `#180`
  - [ ] normalize package/SBOM output so serverless, image, and VM scans emit the same package/vulnerability contracts
- [ ] Track B - Vulnerability knowledge + graph integration
  - Exit criteria:
  - [ ] feed function package/vulnerability outputs into the vulnerability knowledge pipeline from issue `#181`
  - [ ] attach function scans, packages, and vulnerabilities to the temporal graph from issue `#182`
  - [ ] cross-reference function roles, event sources, and network exposure during prioritization
- [ ] Track C - Shared execution store extraction
  - Exit criteria:
  - [x] move workload/image/function scan run storage off per-runtime helpers and onto a shared execution-store package
  - [ ] expose execution resources over platform APIs instead of CLI-only surfaces
  - [ ] decide whether the long-term backend remains SQLite with leadering or moves to a multi-worker store

## Deep Review Cycle 50 - Durable Container Image Scan Runtime (2026-03-11)

### Review findings
- [x] Gap: issue `#178` still existed only as a problem statement; there was no durable container image scan runtime or operator surface.
- [x] Gap: the existing registry clients could list repositories/tags and fetch manifests, but they did not yet resolve manifest lists, fetch config blobs, or download layers directly.
- [x] Gap: container image analysis would have drifted back into process-local orchestration unless it adopted the same persisted run/event model as workload scans.
- [x] Gap: workload scan and image scan were on track to create separate SQLite silos unless they shared at least the execution-store default path.
- [x] Gap: the issue stack `#179 -> #182` needed a stable rootfs/image execution substrate before deeper analyzers, vuln knowledge, or graph integration could land cleanly.

### Execution plan
- [x] Harden the registry scanner substrate:
  - [x] add manifest list / OCI index resolution
  - [x] load config blobs for labels, history, architecture, and base image hints
  - [x] add direct blob/layer download support for ECR, GCR, and ACR
- [x] Add a durable image scan runtime under `internal/imagescan`:
  - [x] add typed run, event, filesystem, layer, and analysis contracts
  - [x] persist runs/events in SQLite
  - [x] add a local rootfs materializer with gzip/zstd support and OCI whiteout handling
- [x] Add a first analyzer bridge:
  - [x] add `scanner.TrivyFilesystemScanner`
  - [x] analyze reconstructed rootfs paths instead of requiring a daemon image pull
  - [x] merge native registry findings with filesystem findings
- [x] Add operator/config surface:
  - [x] add `cerebro image-scan list`
  - [x] add `cerebro image-scan run ecr|gcr|acr`
  - [x] add image-scan env/config controls
  - [x] default workload/image execution state to shared `EXECUTION_STORE_FILE`
- [x] Add architecture/test coverage:
  - [x] add image scan architecture doc with OSS implementation references
  - [x] add store round-trip regressions
  - [x] add rootfs whiteout/materialization regressions
  - [x] add persisted runner lifecycle/cleanup regressions

### Detailed follow-on backlog
- [ ] Track A - Serverless and filesystem analyzer reuse
  - Exit criteria:
  - [ ] reuse the image-scan rootfs/analyzer substrate for issue `#179` serverless package scans where functions are container-backed
  - [ ] unify the container/serverless/VM analyzer contracts around the richer filesystem analyzer from issue `#180`
- [ ] Track B - Vulnerability knowledge + graph integration
  - Exit criteria:
  - [ ] feed image scan package/vulnerability outputs into the vulnerability knowledge pipeline from issue `#181`
  - [ ] attach image scan runs, packages, and vulnerabilities to the temporal graph from issue `#182`
  - [ ] correlate image digests to running workloads so prioritization can use runtime exposure, not just repository presence
- [ ] Track C - Shared execution store extraction
  - Exit criteria:
  - [ ] move workload/image scan run storage off per-runtime helpers and onto a shared execution-store package
  - [ ] expose execution resources over platform APIs instead of CLI-only surfaces
  - [ ] decide whether the long-term backend remains SQLite with leadering or moves to a multi-worker store

## Deep Review Cycle 49 - Durable VM Snapshot Scan Runtime (2026-03-11)

### Review findings
- [x] Gap: issue `#177` still existed only as an architecture outline; there was no typed runtime for inventory/snapshot/mount/analyze/cleanup execution.
- [x] Gap: workload scan orchestration would have defaulted to in-memory state without a persisted run/event model, which is not acceptable for long-running cloud snapshot workflows.
- [x] Gap: AWS-specific execution requirements like scanner availability zone, cross-account snapshot sharing, and cleanup reconciliation were not expressed as first-class contracts.
- [x] Gap: the CLI had no operator surface for listing, launching, or reconciling workload scans, so the connector work from cycle 48 had nothing concrete to feed.

### Execution plan
- [x] Add a durable workload scan runtime:
  - [x] add typed run, volume, artifact, cost, cleanup, and event contracts under `internal/workloadscan`
  - [x] persist workload scan runs and event timelines in SQLite instead of process-local memory
  - [x] add reconciliation that can recover leaked artifacts from persisted incomplete runs
- [x] Add the first provider and host seams:
  - [x] add `Provider`, `Mounter`, `Analyzer`, and `EventEmitter` interfaces
  - [x] implement AWS volume inventory, snapshot, share, inspection-volume creation, attach, detach, and cleanup
  - [x] implement local read-only mounting for scanner hosts
- [x] Add operator surface:
  - [x] add `cerebro workload-scan list`
  - [x] add `cerebro workload-scan run aws`
  - [x] add `cerebro workload-scan reconcile aws`
  - [x] make `scanner-zone` explicit at the CLI contract level
- [x] Wire runtime observability and config:
  - [x] add workload scan lifecycle webhook event types
  - [x] add workload scan config/env knobs and validation
  - [x] add workload scan architecture documentation
- [x] Add focused regressions for runtime orchestration, config loading, CLI command shape, and webhook validation

### Detailed follow-on backlog
- [ ] Track A - Provider breadth
  - Exit criteria:
  - [ ] add GCP persistent disk snapshot orchestration behind the same provider contract
  - [ ] add Azure managed disk snapshot orchestration behind the same provider contract
  - [ ] normalize provider-specific cost and cleanup metadata for cross-cloud reporting
- [ ] Track B - Analyzer integration
  - Exit criteria:
  - [ ] replace `NoopAnalyzer` with a real analyzer contract implementation from issue `#180`
  - [ ] record analyzer outputs as persisted run artifacts instead of log-only side effects
  - [ ] map scan outputs into graph evidence/claims for later intelligence surfaces
- [ ] Track C - Execution surface hardening
  - Exit criteria:
  - [ ] expose workload scan runs/events over the platform API or job surface instead of CLI-only delivery
  - [ ] decide whether the long-term state backend remains SQLite or moves to a shared multi-worker store
  - [ ] add bounded mount-space accounting and artifact-retention policies

## Deep Review Cycle 48 - Connector Provisioning Contracts + Dry-Run Validation (2026-03-11)

### Review findings
- [x] Gap: the workload scan issue stack had no typed provisioning contract, so IAM snippets and trust configuration would have drifted across issues, docs, and customer setup guides.
- [x] Gap: there was no `cerebro connector` CLI surface for generating provider-specific install artifacts, which meant the provisioning story would remain ad hoc and hard to evolve.
- [x] Gap: validation semantics were not explicit by provider; GCP and Azure can verify permissions non-destructively, while AWS needs caller-supplied sample resources for honest mutation dry-run probes.
- [x] Gap: connector requirements were not part of the repo's codegen/doc workflow, so provider permissions and template outputs could have silently diverged from implementation.

### Execution plan
- [x] Add a typed connector provisioning catalog:
  - [x] add built-in provider catalogs for AWS, GCP, and Azure under `internal/connectors`
  - [x] model artifact kinds, required permissions, and validation checks explicitly
- [x] Add provider-specific bundle rendering:
  - [x] render AWS StackSet-safe CloudFormation bundle
  - [x] render GCP Terraform bundle with optional Workload Identity Federation
  - [x] render Azure ARM + Terraform bundle
- [x] Add CLI surface:
  - [x] add `cerebro connector catalog`
  - [x] add `cerebro connector scaffold aws|gcp|azure`
  - [x] add `cerebro connector validate aws|gcp|azure`
- [x] Make validation non-destructive and provider-aware:
  - [x] AWS: prove STS + describe access and optional dry-run mutation probes using sample resources
  - [x] GCP: prove auth and use `projects.testIamPermissions`
  - [x] Azure: prove auth and inspect effective subscription permissions from ARM
- [x] Integrate docs/codegen:
  - [x] add generated connector provisioning catalog docs
  - [x] add Makefile drift check target
  - [x] add architecture doc links and manual connector architecture notes
- [x] Add focused regression coverage for rendering, validation dispatch, and permission-matching helpers

### Detailed follow-on backlog
- [ ] Track A - Connector API surface
  - Exit criteria:
  - [ ] expose connector bundle/catalog resources over the platform API instead of CLI-only delivery
  - [ ] persist generated bundle metadata and rollout history as first-class platform artifacts
- [ ] Track B - Contract hardening
  - Exit criteria:
  - [ ] add connector contract baseline compatibility checks against `docs/CONNECTOR_PROVISIONING_CATALOG.json`
  - [ ] add provider-specific example fixtures and smoke validators in CI
- [ ] Track C - Workload scan integration
  - Exit criteria:
  - [ ] wire connector validation results into the issue `#176 -> #182` workload scan execution path
  - [ ] carry validated connector metadata into graph entities and asset provenance

## Deep Review Cycle 47 - Shared Test Helpers + Narrow Service Interfaces for Testability (2026-03-11)

### Review findings
- [x] Gap: `internal/testutil` was still too thin to standardize new test suites; common setup lived ad hoc in package-local helpers, especially `internal/api/server_test.go`.
- [x] Gap: several services still consumed concrete implementations where they only needed a small capability slice, forcing tests to construct `*policy.Engine`, `*webhooks.Service`, or `*ticketing.Service` even for isolated behavior.
- [x] Gap: moving app-level test construction directly into `internal/testutil` would create import cycles for same-package `internal/app` tests, so shared helper extraction needed a separate app-aware test package instead of a naive move.
- [x] Gap: interface seams were not being proven directly, which meant "testability" claims could drift back into concrete-type coupling without targeted regressions.

### Execution plan
- [x] Expand shared test helpers without introducing cycles:
  - [x] add `testutil.NewMemoryWarehouse()` with stable metadata defaults
  - [x] keep `internal/testutil` app-agnostic so `internal/app` tests can continue importing it safely
  - [x] add `internal/apptest` with `NewConfig`, `NewApp`, and `NewAppWithWarehouse`
- [x] Narrow concrete dependencies to capability interfaces:
  - [x] add `scanner.PolicyEvaluator`
  - [x] add `findings.PolicyCatalog`
  - [x] add `agents.PolicyEvaluator`
  - [x] add `remediation.TicketService`
  - [x] add `remediation.NotificationSender`
  - [x] add `remediation.FindingsWriter`
  - [x] add `remediation.EventPublisher`
- [x] Move shared API app setup onto the new helper package:
  - [x] replace the in-file `newTestApp()` implementation in `internal/api/server_test.go` with `apptest.NewApp(t)`
  - [x] preserve legacy API-test behavior by keeping the default shared app helper warehouse-free unless a test explicitly injects one
- [x] Add direct regressions proving the seams:
  - [x] add `internal/apptest` tests for config/path and injected warehouse behavior
  - [x] add interface-focused scanner, findings, agents, remediation, and testutil tests
  - [x] keep the full repo green under `go test ./...`

### Detailed follow-on backlog
- [ ] Track A - Handler/service decomposition
  - Exit criteria:
  - [ ] continue issue `#146` by defining handler-facing `GraphQuerier`, `FindingsReader`, and related API service interfaces
  - [ ] remove direct `*app.App` field reach-through from at least one handler family as proof of concept
  - [ ] make new handler tests depend on minimal interface mocks instead of the full app container
- [ ] Track B - Shared mock/test fixture generation
  - Exit criteria:
  - [ ] decide whether a small curated `go:generate` mockgen surface is worth it for the now-stable service interfaces
  - [ ] consolidate repeated fake providers/stores in agents, notifications, and provider tests onto shared fixtures where it reduces duplication without obscuring behavior

## Deep Review Cycle 46 - CDC-Driven Incremental Graph Updates + Copy-On-Write Rebuilds (2026-03-11)

### Review findings
- [x] Gap: the graph scheduler already knew how to read CDC deltas, but successful sync endpoints still returned without advancing the live graph, leaving freshness tied to the rebuild interval instead of sync completion.
- [x] Gap: full graph rebuilds still mutated the builder’s live graph instance in place, so the rebuild path could expose a partially rebuilt graph during long-running warehouse reads.
- [x] Gap: there was no reusable app-level graph update workflow; scheduler logic, manual rebuilds, and sync-triggered mutation paths were drifting into separate behaviors.
- [x] Gap: incremental mutation correctness had no first-class consistency-check loop against a fresh full rebuild.

### Execution plan
- [x] Make full rebuilds copy-on-write:
  - [x] add a fresh-graph candidate build path in `internal/graph.Builder`
  - [x] swap the completed graph into the builder only after the candidate build finishes
  - [x] add regression coverage proving the live graph remains readable while a rebuild is in progress
- [x] Centralize app-level graph mutation orchestration:
  - [x] add one `ApplySecurityGraphChanges(...)` path that prefers incremental CDC apply and falls back to full rebuild only on failure
  - [x] serialize graph update operations through the app so scheduler/manual/sync paths stop racing each other
- [x] Trigger graph updates directly after successful syncs:
  - [x] wire `/api/v1/sync/aws`
  - [x] wire `/api/v1/sync/aws-org`
  - [x] wire `/api/v1/sync/azure`
  - [x] wire `/api/v1/sync/gcp`
  - [x] wire `/api/v1/sync/gcp-asset`
  - [x] wire `/api/v1/sync/k8s`
  - [x] surface `graph_update` status in sync responses
- [x] Add drift checking:
  - [x] add optional `GRAPH_CONSISTENCY_CHECK_ENABLED`
  - [x] add optional `GRAPH_CONSISTENCY_CHECK_INTERVAL`
  - [x] run background consistency diffs between the live incremental graph and a fresh rebuild candidate
- [x] Validate and document:
  - [x] add graph/api/app tests for copy-on-write rebuild and post-sync incremental apply
  - [x] regenerate config docs
  - [x] update OpenAPI sync response schema

### Detailed follow-on backlog
- [ ] Track A - Reduce incremental edge rebuild cost
  - Exit criteria:
  - [ ] replace whole-graph edge rebuilds during CDC apply with table-scoped or entity-scoped edge invalidation
  - [ ] persist and consume a durable CDC cursor so incremental applies can recover independently of process memory
  - [ ] measure p95/p99 incremental apply latency by table family and publish it in graph freshness/status reporting
- [ ] Track B - Durable graph state beyond process memory
  - Exit criteria:
  - [ ] define the durable live-graph backing model instead of relying on in-process memory plus snapshots
  - [ ] decide whether the source of truth for live graph state is warehouse tables, append-only mutation log, or both
  - [ ] add restart restore semantics for the live graph that do not require a full rebuild before serving reads

## Deep Review Cycle 45 - JetStream Historical Replay for Graph Ingest (2026-03-11)

### Review findings
- [x] Gap: the TAP/JetStream consumer could only move forward on its live durable cursor, so operators had no safe way to replay a historical window after mapper bugs or ingest regressions.
- [x] Gap: dead-letter replay existed, but stream-history replay from sequence/time did not, leaving non-dead-letter business events unrecoverable without republishing or full source rebuilds.
- [x] Gap: replay safety was still assumed rather than proven for the legacy TAP fallback path; duplicate events could append duplicate business edges.
- [x] Gap: standalone replay would have remained process-local unless it materialized a durable graph artifact after successful processing.

### Execution plan
- [x] Add a bounded JetStream replay substrate:
  - [x] introduce an ephemeral pull-consumer replay helper that accepts `from-sequence` or `from-time`
  - [x] capture the initial stream upper bound so replay does not chase new live traffic forever
  - [x] surface replay counters for fetched, parsed, handled, parse-error, and handler-error cases
- [x] Add CLI recovery flow:
  - [x] add `cerebro ingest replay`
  - [x] support checkpoint/resume by last successful stream sequence
  - [x] support `--dry-run`
  - [x] materialize a durable graph snapshot on successful non-dry-run replay
- [x] Prove replay safety:
  - [x] add JetStream integration tests for replay-from-sequence
  - [x] add JetStream integration tests for replay-from-time
  - [x] add JetStream integration tests proving replay stops at the initial upper bound
  - [x] add TAP handler regression proving duplicate business events no longer append duplicate deterministic edges

### Detailed follow-on backlog
- [ ] Track A - Recovery ergonomics
  - Exit criteria:
  - [ ] add base-snapshot selection so replay can apply on top of a chosen graph snapshot instead of always starting from a fresh graph
  - [ ] add filtered replay by subject/source/type for targeted business-event recovery
  - [ ] emit replay-run records/events so operators can inspect historical reprocessing like any other execution resource
- [ ] Track B - Toward incremental graph updates
  - Exit criteria:
  - [ ] connect replay checkpoints and graph snapshots to the planned CDC-driven incremental graph path
  - [ ] decide how replayed business-event graphs merge with warehouse-built cloud/security graph state
  - [ ] add diff/explanation tooling for “what changed because of this replay window”

## Deep Review Cycle 44 - Alert Router State Persistence (2026-03-11)

### Review findings
- [x] Gap: alert-router throttle windows, digest buckets, and pending acknowledgement timers still lived only in process memory, so rolling restarts dropped state and produced duplicate or missing alerts.
- [x] Gap: router startup had no restore path for in-flight digests or escalation timers, making graceful deploys semantically unsafe even when routing config stayed constant.
- [x] Gap: operators had no default persistence path configured for the alert router, so durability depended on ad hoc local wiring.

### Execution plan
- [x] Add a persistent alert-router state seam:
  - [x] introduce `AlertRouterStateStore`
  - [x] add a SQLite-backed state store for throttle, digest, and pending-ack snapshots
  - [x] restore persisted state on router startup and persist snapshots on route/ack/close transitions
- [x] Wire persistence through app startup:
  - [x] expose `ALERT_ROUTER_STATE_FILE`
  - [x] initialize the SQLite state store in alert-router startup with a durable default path
  - [x] close the state store on router shutdown / failed initialization paths
- [x] Prove restart semantics:
  - [x] add restart regressions for throttle-window continuity
  - [x] add restart regressions for digest delivery continuity
  - [x] add restart regressions for escalation timer continuity

### Detailed follow-on backlog
- [ ] Track A - Persistence robustness
  - Exit criteria:
  - [ ] decide whether route-time state persistence failures should block alert sends or degrade to best-effort mode with explicit health signaling
  - [ ] add corruption-recovery handling for unreadable persisted router state
  - [ ] expose alert-router state health/age in readiness or status surfaces
- [ ] Track B - Storage/backplane choices
  - Exit criteria:
  - [ ] evaluate NATS KV as a multi-replica/shared state backend once alert routing moves beyond single-node durability
  - [ ] add state schema/versioning to support future route payload evolution without manual DB resets

## Deep Review Cycle 43 - Findings Semantic Identity + Persistent Dedup (2026-03-11)

### Review findings
- [x] Gap: findings were still deduplicated only by exact `id`, so policy version bumps or renamed controls split one logical issue into multiple finding histories.
- [x] Gap: the first pass at semantic dedup lived only in store-local indexes and had not been carried through SQLite/Snowflake persistence semantics.
- [x] Gap: operators had no explicit config surface to disable semantic dedup when strict finding IDs were preferred.
- [x] Gap: semantic identity metadata (`semantic_key`, observed finding/policy lineage) was not yet documented on the API contract.

### Execution plan
- [x] Add first-class semantic finding identity:
  - [x] define stable semantic-key derivation from tenant/resource/issue/severity
  - [x] track observed finding IDs and observed policy IDs on canonical findings
  - [x] preserve semantic metadata through metadata serialization/deserialization
- [x] Carry semantic dedup through persistent stores:
  - [x] teach the in-memory store to maintain a semantic index alongside exact-ID lookup
  - [x] teach SQLite upsert to reconcile semantic duplicates before insert and persist lineage across reopen
  - [x] teach the Snowflake-backed cache to reuse canonical findings and keep dirty/sync state keyed by canonical IDs
  - [x] keep update paths refreshing semantic identity so indexes do not drift after mutation
- [x] Add operator controls and contract docs:
  - [x] expose `FINDINGS_SEMANTIC_DEDUP_ENABLED`
  - [x] wire the toggle through in-memory, SQLite, and Snowflake findings initialization
  - [x] document semantic finding fields in OpenAPI and config docs
- [x] Prove the behavior:
  - [x] add regressions for policy-version dedup, strict-ID mode, SQLite reopen persistence, resource-type fallback matching, and canonical dirty tracking
  - [x] run focused findings/app tests plus full-repo tests

### Detailed follow-on backlog
- [ ] Track A - Semantic identity hardening
  - Exit criteria:
  - [ ] decide whether semantic identity should fold severity into the canonical key or treat severity changes as state transitions on the same finding
  - [ ] add richer resource-identity normalization for cases where provider IDs drift but stable external IDs remain available
  - [ ] expose semantic-match explanations so operators can tell why two findings were merged
- [ ] Track B - Findings storage scalability
  - Exit criteria:
  - [ ] eliminate last-resort in-memory fallback for findings initialization or make it explicit as a dev-only mode
  - [ ] add indexed lookup support in persistent stores for semantic key queries once findings volume grows beyond small local datasets
  - [ ] add background maintenance/compaction hooks for long-lived SQLite deployments

## Deep Review Cycle 42 - Hardening Batch: Findings Bounds + Provider Circuit Breaking + Indexed Entity Search (2026-03-10)

### Review findings
- [x] Gap: the default in-memory findings store still had effectively unbounded growth semantics, leaving fallback/dev paths vulnerable to OOM if SQLite or warehouse persistence was unavailable.
- [x] Gap: provider HTTP clients still relied on a shared 30-second timeout with no circuit breaker or transport-level retry/backoff policy, so degraded providers could keep burning request time without fast failover semantics.
- [x] Gap: entity search still lived as an O(n) substring scan on the listing API and had no dedicated autocomplete/indexed search surface for graph-native discovery.

### Execution plan
- [x] Bound and instrument the in-memory findings store:
  - [x] change `findings.NewStore()` to use sane bounded defaults instead of implicit unlimited growth
  - [x] add default resolved-finding retention so stale resolved findings age out automatically
  - [x] add `cerebro_findings_store_size`
  - [x] add app-side fallback warnings only when operators explicitly choose unlimited/no-retention mode
  - [x] expose `FINDINGS_MAX_IN_MEMORY` and `FINDINGS_RESOLVED_RETENTION`
- [x] Add resilient provider HTTP semantics at the shared seam:
  - [x] add per-provider circuit breaker state with open / half-open / closed transitions
  - [x] add transport-level retry/backoff with retryable response/error classification
  - [x] add `cerebro_provider_circuit_state{provider=...}`
  - [x] allow per-provider config-map overrides for timeout, retry, and circuit settings via `BaseProvider`
  - [x] wire the shared resilient client into Okta, CrowdStrike, and Snyk
- [x] Add indexed entity search and autocomplete:
  - [x] build token / trigram / prefix indexes as part of `Graph.BuildIndex()`
  - [x] add `GET /api/v1/platform/entities/search`
  - [x] add `GET /api/v1/platform/entities/suggest`
  - [x] add graph + API tests covering `s3 bucket` matching and `ali` autocomplete

### Detailed follow-on backlog
- [ ] Track A - Search quality and query ergonomics
  - Exit criteria:
  - [ ] add highlighted match fragments and stronger field-aware scoring so name matches outrank incidental provider/region matches
  - [ ] add bitemporal-aware historical entity search instead of limiting the new index to current active graph state
  - [ ] add graph-native explanation payloads showing why a result matched (tokens, trigrams, field hits)
- [ ] Track B - Provider resilience rollout
  - Exit criteria:
  - [ ] extend the resilient shared client beyond Okta/CrowdStrike/Snyk to the broader provider fleet in dependency-priority order
  - [ ] add operator-facing status/report surfaces for open provider circuits and recent retry/failure streaks
  - [ ] add env-backed default override surfaces for shared provider HTTP resilience settings where app-only deployment needs them
- [ ] Track C - Findings retention and persistence
  - Exit criteria:
  - [ ] decide whether SQLite/file-backed findings stores should enforce the same bounded semantics or expose their own retention guarantees
  - [ ] add periodic maintenance for long-idle in-memory stores so retention cleanup does not depend solely on write traffic
  - [ ] feed findings-store bound/retention state into `/ready` or status surfaces when fallback storage is active

## Deep Review Cycle 41 - Ontology Ingest Depth: Kubernetes Materialization + Conditional Business Mappings (2026-03-10)

### Review findings
- [x] Gap: the graph schema already defined Kubernetes node kinds, but neither full builds nor CDC rebuilds materialized those resources into the graph.
- [x] Gap: the K8s sync layer emitted ambiguous `cluster/namespace/name` IDs that would collide across pods, deployments, service accounts, and configmaps once the ontology was actually turned on.
- [x] Gap: K8s toxic-combination logic expected pod -> service account -> role paths, but the builder never constructed those prerequisite edges from normalized RBAC data.
- [x] Gap: business-domain mappings needed deeper optional nodes, but the declarative mapper had no way to gate node/edge emission on sparse CRM/support fields.

### Execution plan
- [x] Materialize Kubernetes ontology in the graph builder:
  - [x] add full-build node loading for `pod`, `deployment`, `namespace`, `service_account`, `cluster_role`, `cluster_role_binding`, `configmap`, `persistent_volume`, and namespaced RBAC `role`
  - [x] add incremental CDC node handling for the same K8s resource tables
  - [x] build pod -> service account and service account -> role / cluster role edges from normalized K8s tables
  - [x] expose pod security signals (`privileged`, `host_path_volumes`, `run_as_root`) directly on pod nodes so existing toxic-combination logic works on real sync data
- [x] Fix K8s identifier semantics before rollout:
  - [x] switch sync-emitted K8s `_cq_id` values to typed resource IDs (`cluster/pod/ns/name`, `cluster/deployment/ns/name`, etc.)
  - [x] keep the graph builder resilient to old untyped `_cq_id` rows by deriving typed IDs from semantic fields
- [x] Deepen declarative business mappings safely:
  - [x] add `when` support for conditional node/edge emission in the declarative mapper
  - [x] deepen support events into optional `customer`, `company`, and `subscription` nodes
  - [x] deepen sales-call events into optional `company`, `lead`, `opportunity`, and `deal` nodes
  - [x] update mapper contract inference so conditionally emitted fields stay optional instead of becoming global required keys
- [x] Prove the new substrate:
  - [x] add full-build K8s ontology tests
  - [x] add CDC K8s materialization + edge rebuild tests
  - [x] add mapper tests for conditional node/edge creation and empty-field suppression

### Detailed follow-on backlog
- [ ] Track A - K8s graph depth beyond baseline ontology
  - Exit criteria:
  - [ ] add first-class K8s service / ingress / node materialization where they improve pathing and blast-radius analysis
  - [ ] connect deployment/template selectors to workload/service topology instead of leaving deployments as isolated resource nodes
  - [ ] model namespaced secret access explicitly so `TC-K8S-004` can reason over real K8s secrets rather than only generic secret nodes
- [ ] Track B - External ingest convergence
  - Exit criteria:
  - [ ] decide where K8s data should stay warehouse/builder-native vs emit CloudEvents into the declarative mapper
  - [ ] add additional CRM/billing event families so `invoice` and broader customer/revenue surfaces stop depending on synthetic nodes
  - [ ] add compatibility fixtures for conditional mappings with sparse and fully populated payloads
- [ ] Track C - Identifier governance
  - Exit criteria:
  - [ ] add explicit K8s ID-shape guardrails/tests across sync, CDC, and graph query layers
  - [ ] add migration/cleanup handling for any historical untyped K8s IDs that may already exist in raw tables or snapshots

## Deep Review Cycle 40 - API Contract Governance + Graph Freshness + Temporal/Changelog Surfaces (2026-03-10)

### Review findings
- [x] Gap: HTTP API compatibility was the only major public contract surface without a generated baseline and CI diff gate.
- [x] Gap: graph freshness still answered only the aggregate question, not which provider or ontology slice had gone stale.
- [x] Gap: graph snapshots and temporal history existed internally, but operators and agents could not ask what changed or reconstruct an entity at a point in time.
- [x] Gap: the SCM ontology deepening work still lacked first-class `repository` and `ci_workflow` creation in declarative ingest mappings.

### Execution plan
- [x] Add HTTP API contract governance:
  - [x] generate a typed HTTP API contract catalog from `api/openapi.yaml`
  - [x] add compatibility diff logic for endpoints, params, request fields, response fields, and success codes
  - [x] add `api-contract-docs` / `api-contract-compat` tooling plus CI jobs and codegen catalog wiring
- [x] Add provider/kind freshness surfaces:
  - [x] add graph freshness breakdowns by provider and node kind
  - [x] expose `GET /api/v1/status/freshness` and embed freshness in `/status`
  - [x] add per-provider freshness health/SLA evaluation and Prometheus gauges
- [x] Expose graph changelog and temporal inspection:
  - [x] add graph changelog and diff-details APIs with provider/kind attribution filters
  - [x] emit graph changelog computed platform events
  - [x] add entity point-in-time and temporal diff APIs
  - [x] add Agent SDK tools for graph changelog and entity history
- [x] Deepen SCM ingest mappings:
  - [x] create first-class `repository` nodes from GitHub PR/check events
  - [x] create first-class `ci_workflow` nodes from GitHub checks and CI pipeline events
  - [x] add mapper coverage for the new SCM nodes and edges

### Detailed follow-on backlog
- [ ] Track A - Remaining ontology ingest depth (`#169`)
  - Exit criteria:
  - [ ] add K8s declarative ingest for `pod`, `deployment`, `namespace`, `cluster_role`, and `cluster_role_binding`
  - [ ] add business-domain declarative ingest for `customer`, `company`, `deal`, `opportunity`, `subscription`, and `invoice`
  - [ ] connect sync-produced K8s/business change events to the declarative graph ingest path where it creates leverage
- [ ] Track B - Freshness and mutation explainability
  - Exit criteria:
  - [ ] attach changelog entries directly to freshness/report views so stale providers can show the last successful mutation window
  - [ ] add time-slice aware diff summaries for higher-level report consumption
  - [ ] add source-specific freshness burn-rate alerting beyond static SLA thresholds
- [ ] Track C - Contract governance expansion
  - Exit criteria:
  - [ ] add versioning policy/reporting for API contract changes, not just breaking-change detection
  - [ ] expose the API contract catalog over a typed platform endpoint
  - [ ] add generated examples for the new temporal/changelog HTTP surfaces

## Deep Review Cycle 39 - Operational Hardening: Drain + Freshness + Startup Bounds (2026-03-10)

### Review findings
- [x] Gap: `App.Close()` canceled the graph build before draining the JetStream pull consumer, so rolling shutdown could abandon in-flight ingest work.
- [x] Gap: the consumer defaulted to a 30-second `AckWait` with no in-progress extension, inviting redelivery storms during long graph mutations.
- [x] Gap: readiness had malformed-drop integrity checks but no lag/staleness/freshness signal, so operators still could not answer how stale the graph was.
- [x] Gap: graph build failure lived only in logs, while `/ready` and normal API responses stayed too polite about a failed or missing graph.
- [x] Gap: startup still relied on unbounded background contexts in a few init-time network paths, and retention defaults still silently meant unbounded growth.

### Execution plan
- [x] Harden consumer execution semantics:
  - [x] add `Drain(ctx)` to the JetStream consumer
  - [x] stop fetching new batches during drain while letting in-flight handlers finish
  - [x] add periodic `InProgress()` heartbeats during long-running handler execution
  - [x] add `cerebro_nats_consumer_redeliveries_total`
- [x] Add freshness and graph-update observability:
  - [x] add consumer lag and lag-seconds gauges
  - [x] add graph last-update and graph staleness gauges
  - [x] add event end-to-end processing duration histogram
  - [x] wire freshness threshold into `tap_consumer` readiness
- [x] Fix shutdown/startup coordination:
  - [x] drain `TapConsumer` before graph cancellation in `App.Close()`
  - [x] add `NATS_CONSUMER_DRAIN_TIMEOUT`
  - [x] coordinate threat-intel background sync with cancel + waitgroup
  - [x] add `CEREBRO_INIT_TIMEOUT` and apply it to init-phase work
  - [x] propagate init context through remote tool discovery and ticketing provider validation
- [x] Surface graph build state:
  - [x] track explicit graph build states (`not_started`, `building`, `success`, `failed`)
  - [x] add `cerebro_graph_build_status`
  - [x] register `graph_build` in readiness
  - [x] expose root `/status`
  - [x] attach warning headers when API responses are served while graph build is unhealthy
- [x] Tighten operational defaults:
  - [x] raise `NATS_CONSUMER_ACK_WAIT` default to 120s
  - [x] set bounded retention defaults for audit/session/graph/access-review data
  - [x] log startup warnings when any retention remains disabled
- [x] Prove behavior with tests:
  - [x] drain waits for handler completion without canceling it
  - [x] in-progress heartbeat fires during long handler execution
  - [x] config loading covers new timeout/freshness controls and bounded defaults

### Detailed follow-on backlog
- [ ] Track A - Graph freshness and replay operations
  - Exit criteria:
  - [ ] implement `#158` follow-through on graph-dependent API gating for the highest-value graph endpoints, not just headers + readiness
  - [ ] implement `#167` changelog/diff APIs so freshness and mutation state are directly explorable
  - [ ] implement `#168` point-in-time reconstruction so stale/failed graph rebuilds have a recovery/debugging story
- [ ] Track B - Provider and startup resilience
  - Exit criteria:
  - [ ] implement `#161` per-provider circuit breaking and partial-sync completion
  - [ ] sweep remaining init/runtime `context.Background()` network call sites beyond the now-fixed startup hot paths for `#159`
  - [ ] expose provider degradation state in `/status` and readiness
- [ ] Track C - Cost and retention governance
  - Exit criteria:
  - [ ] implement `#162` table-level retained-row estimation in `/status`
  - [ ] implement `#157` bounded findings-store defaults and runtime enforcement
  - [ ] add retention preset profiles plus startup validation for contradictory settings

## Deep Review Cycle 38 - NATS Consumer Dead-Letter Integrity + Health Signals (2026-03-10)

### Review findings
- [x] Gap: malformed NATS/CloudEvent payloads were ACKed and dropped from `internal/events/consumer.go`, creating silent business-event loss.
- [x] Gap: the consumer had no dead-letter path of its own, so operator replay/debugging started only after the graph mapper layer, which is too late for serialization failures.
- [x] Gap: the platform had JetStream publisher metrics and outbox health, but no consumer-side dropped-message signal or health surface.
- [x] Gap: the app health registry did not reflect consumer ingestion integrity at all, so `/ready` could stay healthy while events were being discarded.

### Execution plan
- [ ] Add consumer-local quarantine behavior:
  - [x] require a consumer dead-letter path in `ConsumerConfig`
  - [x] append malformed payloads to a JSONL dead-letter file before ACK
  - [x] requeue with `Nak()` when dead-letter persistence fails
  - [x] log payload preview at `ERROR` level for malformed events
- [ ] Add operator-visible integrity signals:
  - [x] add `cerebro_nats_consumer_dropped_total{stream,durable,reason}`
  - [x] track recent dropped-event history in the consumer
  - [x] expose a consumer health snapshot for registry wiring
- [ ] Wire application configuration and health:
  - [x] add env-backed config for dead-letter path, health lookback, and health threshold
  - [x] register `tap_consumer` health after consumer initialization
  - [x] document the new env vars through generated config docs
- [ ] Prove behavior with direct tests:
  - [x] malformed payload is dead-lettered and ACKed
  - [x] dead-letter write failure causes `Nak()` instead of silent drop
  - [x] dropped-message metric increments only after successful quarantine
  - [x] config loading covers new consumer controls

### Detailed follow-on backlog
- [ ] Track A - Consumer operational hardening
  - Exit criteria:
  - [ ] implement `#160` so `AckWait` sizing is workload-aware and redelivery storms stop masking real failures
  - [ ] implement `#163` so shutdown drains the pull consumer instead of abandoning in-flight delivery
  - [ ] implement `#153` lag/staleness metrics so health can incorporate freshness, not just malformed-drop rate
- [ ] Track B - Replay and quarantine tooling
  - Exit criteria:
  - [ ] add a CLI/API path to inspect and replay NATS consumer dead-letter records
  - [ ] add bounded retention and pruning policy for consumer dead-letter files
  - [ ] add dead-letter record schemas/examples to generated contract docs
- [ ] Track C - Ingest contract tightening
  - Exit criteria:
  - [ ] classify post-unmarshal failures separately (`validation_failed`, `unsupported_type`, `handler_rejected`) instead of folding everything into handler retries
  - [ ] add consumer-side event contract validation before graph-mapper handoff where it creates leverage
  - [ ] connect consumer integrity health to broader graph freshness/build health surfaces

## Deep Review Cycle 37 - Warehouse Interface + Testability Seams (2026-03-10)

### Review findings
- [x] Gap: `snowflake.Client` still leaked through sync entry points, scan helpers, and read handlers even after lower-level graph/sync seams were introduced.
- [x] Gap: the codebase had no reusable in-memory warehouse test double that could exercise sync/query/asset flows without a live database client.
- [x] Gap: read/query code paths that only needed warehouse behavior were still keyed to the concrete Snowflake type, limiting unit-test reach and making broader platform extraction harder.
- [x] Gap: table-discovery and column-introspection helpers were treated as Snowflake-only concerns even though they are part of the generic warehouse contract needed by scans and query policies.

### Execution plan
- [ ] Add a reusable warehouse contract package:
  - [x] create `internal/warehouse`
  - [x] define narrow query/exec/schema/asset/CDC interfaces
  - [x] define broader `DataWarehouse` application contract
  - [x] provide `MemoryWarehouse` for unit tests
- [ ] Migrate core sync and graph seams:
  - [x] move sync engines and relationship extraction onto `warehouse.SyncWarehouse`
  - [x] move graph snowflake source onto warehouse query interface
  - [x] keep compile-time assertion that `*snowflake.Client` satisfies the contract
- [ ] Widen testability through higher-level read paths:
  - [x] add table-discovery and column-introspection methods to the warehouse contract
  - [x] move query-policy scans and scan column discovery onto `App.Warehouse`
  - [x] move obvious read/asset handlers onto `App.Warehouse`
  - [x] move identity/report read fetches onto `App.Warehouse`
- [ ] Prove the seam with direct tests:
  - [x] add `MemoryWarehouse` package tests
  - [x] add sync watermark/query tests against `MemoryWarehouse`
  - [x] add handler tests that succeed with `Warehouse` set and `Snowflake` unset
- [ ] Validate full repo and ship through PR feedback loop

### Detailed follow-on backlog
- [ ] Track A - API/service warehouse adoption
  - Exit criteria:
  - [ ] move remaining asset/query consumers in app and API layers off direct `Snowflake` reads where they only need warehouse behavior
  - [ ] convert sync HTTP wrappers to accept the warehouse interface where engine constructors already do
  - [ ] isolate the remaining true Snowflake-only responsibilities behind smaller contracts
- [ ] Track B - Test coverage unlocks
  - Exit criteria:
  - [ ] add more sync-engine unit tests that use `MemoryWarehouse` rather than query function stubbing
  - [ ] add handler-level tests for dry-run asset loads, identity reports, and stale-access detection using the memory warehouse
  - [ ] measure and raise `internal/sync` coverage on the back of the new seam
- [ ] Track C - Warehouse portability
  - Exit criteria:
  - [ ] define whether a second concrete warehouse implementation is actually needed or whether contract-only portability is enough for now
  - [ ] document which capabilities are generic warehouse primitives vs Snowflake-specific extensions
  - [ ] keep platform extraction work from reintroducing concrete-client coupling in new code

## Deep Review Cycle 36 - Codegen Catalog + CI-to-Local Contract Map (2026-03-10)

### Review findings
- [x] Gap: codegen-heavy families had real generators and compatibility checks, but family definitions still lived as duplicated handwritten logic across `Makefile`, `.github/workflows/ci.yml`, and `scripts/devex.py`.
- [x] Gap: there was no single machine-readable catalog telling a contributor or editor integration which generated surfaces exist, what files trigger them, what they output, and which CI jobs enforce them.
- [x] Gap: adding a new generated contract family still required editing planner routing code directly, which is precisely the kind of DevEx drift that codegen governance should eliminate.
- [x] Gap: PR preflight had converged on “generated-contracts” as a concept, but the actual membership of that set was still hardcoded instead of declared.

### Research synthesis to adopt
- [x] Buf lesson: generation governance works best when versioned declarative manifests define plugins, inputs, and outputs rather than scattering that logic across wrappers.
- [x] Smithy lesson: build/projection configuration should be inspectable data so tooling can reason about generation behavior without re-deriving it from script branches.
- [x] OpenAPI Generator lesson: reproducible batch/config execution matters more than one-off command history because it creates a stable automation boundary for local and CI workflows.
- [x] Backstage lesson: discoverable catalogs unlock better editor and platform tooling than prose documentation alone because the extension surface becomes queryable.

### Execution plan
- [x] Add a canonical codegen family catalog:
  - [x] create `devex/codegen_catalog.json`
  - [x] define family IDs, trigger globs, outputs, local checks, compatibility commands, and CI job mappings
  - [x] include OpenAPI and DevEx codegen governance itself, not just docs/contracts families
- [x] Add typed validation and generated artifacts:
  - [x] add `internal/devex` loader/validator for the catalog
  - [x] add `scripts/generate_devex_codegen_docs/main.go`
  - [x] emit `docs/DEVEX_CODEGEN_AUTOGEN.md`
  - [x] emit `docs/DEVEX_CODEGEN_CATALOG.json`
- [x] Refactor the local planner onto the catalog:
  - [x] make `scripts/devex.py` load codegen families from the catalog
  - [x] derive changed-file routing for codegen families from catalog triggers
  - [x] derive PR generated-contract membership from catalog metadata
- [x] Tighten local entry points and regression coverage:
  - [x] add `make devex-codegen`
  - [x] add `make devex-codegen-check`
  - [x] add tests that validate catalog references against real Make targets and CI jobs
  - [x] document the codegen catalog workflow in `docs/DEVELOPMENT.md`

### Detailed follow-on backlog
- [ ] Track A - Generator family autowiring
  - Exit criteria:
  - [ ] generate CI job fragments or validation reports from the same catalog instead of only validating references
  - [ ] let generator families declare dependent validation steps without planner code changes
  - [ ] support family-level ownership metadata for review routing and code search
- [ ] Track B - Stronger compatibility governance
  - Exit criteria:
  - [ ] add compatibility catalogs for knowledge read contracts and snapshot/diff contracts
  - [ ] generate changelog artifacts from compatibility diffs rather than only failing on breakage
  - [ ] expose “breaking/additive/docs-only” classification consistently across all contract families
- [ ] Track C - Editor and automation consumption
  - Exit criteria:
  - [ ] expose the codegen catalog through a lightweight CLI or API read surface for editor integrations
  - [ ] emit family-specific JSON execution plans keyed by changed files
  - [ ] attach catalog metadata to DevEx review-loop tooling so pending checks can be explained by family rather than raw job name

## Deep Review Cycle 35 - DevEx Preflight + Hook Automation + Local PR Parity (2026-03-10)

### Review findings
- [ ] Gap: contract-heavy development now spans too many separate `make` targets and CI jobs for a contributor to infer the right local preflight from memory.
- [ ] Gap: the repository had a strong staged-file `pre-commit` hook, but no corresponding `pre-push` guard for generated-artifact drift, contract compatibility, or broader changed-file validation.
- [ ] Gap: CI workflow knowledge lived primarily in `.github/workflows/ci.yml`, not in an inspectable local runner that developers and tooling could plan against.
- [ ] Gap: the development guide documented individual checks, but not the higher-level “changed diff preflight vs full PR preflight” workflow that now matters more than any single command.

### Execution plan
- [ ] Add a first-class DevEx preflight runner:
  - [ ] add `scripts/devex.py plan --mode changed|pr`
  - [ ] add `scripts/devex.py run --mode changed|pr`
  - [ ] support explicit file lists for editor/tool integrations
  - [ ] support baseline-aware contract compatibility execution against `origin/main`
- [ ] Add stable local entry points:
  - [ ] add `make devex-changed`
  - [ ] add `make devex-pr`
  - [ ] add missing local parity targets for `graph-ontology-guardrails`, `gosec`, and `govulncheck`
- [ ] Add hook automation:
  - [ ] keep fast staged-file linting in `.githooks/pre-commit`
  - [ ] add `.githooks/pre-push` to run changed-file-aware DevEx preflight
  - [ ] support explicit skip and base-ref overrides for controlled exceptions
- [ ] Tighten docs and workflow tests:
  - [ ] document the DevEx workflow in `docs/DEVELOPMENT.md`
  - [ ] add static tests for Make targets, hooks, and documented commands
  - [ ] add a regression test that exercises `scripts/devex.py plan` against representative changed files

### Detailed follow-on backlog
- [ ] Track A - CI/local parity convergence
  - Exit criteria:
  - [ ] move more duplicated CI shell logic behind reusable Make/DevEx entry points
  - [ ] expose a machine-readable CI-to-local command map for editor integrations
  - [ ] keep local and CI contract-baseline behavior aligned
- [ ] Track B - Smarter changed-scope execution
  - Exit criteria:
  - [ ] expand changed-file routing to more graph/report/SDK families without overfiring checks
  - [ ] add package dependency awareness so changed Go tests can include directly affected dependents where useful
  - [ ] add optional JSON output meant for IDE task runners
- [ ] Track C - PR review-loop tooling
  - Exit criteria:
  - [ ] script recurring `gh` review-thread + check monitoring into a reusable local command
  - [ ] expose “new unresolved feedback since last poll” summaries instead of raw thread dumps
  - [ ] keep the review loop cheap enough to run continuously during active PR cycles

## Deep Review Cycle 34 - Asset Subresource Promotion + Facet Contract Governance + Bucket Support Normalization (2026-03-10)

### Review findings
- [x] Gap: entity facet modules existed, but there was still no discoverable machine-readable facet contract surface for generated tooling, UI composition, or compatibility control.
- [x] Gap: bucket support remained too flat; posture-critical nested constructs still lived as raw properties instead of durable subresource nodes with their own support context.
- [x] Gap: entity-summary had facet and posture modules, but it still lacked a first-class subresource section for “what concrete nested control objects explain this posture.”
- [x] Gap: bucket posture normalization still depended too heavily on read-time derivation instead of durable normalized claims backed by promoted support artifacts.
- [x] Gap: the backlog for deeper asset support needed to move from generic “deepen assets” phrasing to specific execution tracks by family, subresource type, and claim pack.

### Research synthesis to adopt
- [x] Backstage rule: stable entity contracts need a discoverable schema/contract catalog, not just handler behavior.
- [x] DataHub rule: deep asset modules become reusable only when contract IDs, versions, and field definitions are inspectable by downstream tooling.
- [x] Cartography rule: provider-specific nested objects should be promoted when they drive traversal, explanation, or remediation, especially for storage/network posture.
- [x] OpenLineage rule: derived artifacts need deterministic identity and typed link surfaces so support chains can be traversed rather than reconstructed heuristically.
- [x] OpenMetadata rule: family-specific deepening should arrive as strict typed fragments and registries, not expanding opaque per-entity blobs.

### Execution plan
- [x] Publish entity facet contracts as a first-class registry:
  - [x] add `graph.BuildEntityFacetContractCatalog(...)`
  - [x] add compatibility diffing/reporting for facet contract evolution
  - [x] add generated markdown + machine-readable facet catalogs
  - [x] add CI compatibility/docs drift checks
- [x] Promote bucket support subresources into durable graph nodes:
  - [x] add `bucket_policy_statement`
  - [x] add `bucket_public_access_block`
  - [x] add `bucket_encryption_config`
  - [x] add `bucket_logging_config`
  - [x] add `bucket_versioning_config`
  - [x] connect promoted subresources back to buckets via `configures`
- [x] Normalize bucket support into durable knowledge objects:
  - [x] emit deterministic observations for promoted support modules
  - [x] emit deterministic configuration-backed claims on promoted subresources
  - [x] emit bucket-level normalized posture claims supported by subresource claims
  - [x] run normalization in the graph build path so fresh builds materialize durable support automatically
- [x] Extend typed entity/report surfaces:
  - [x] expose `subresources` on `GET /api/v1/platform/entities/{entity_id}`
  - [x] expose `GET /api/v1/platform/entities/facets`
  - [x] expose `GET /api/v1/platform/entities/facets/{facet_id}`
  - [x] add a `subresources` section and `subresource_count` measure to `entity-summary`
  - [x] extend explanation-grade proof fragments so support chains include subject/object anchors
- [ ] Deepen the next asset families with the same pattern:
  - [ ] database: encryption, logging/audit, backup, public endpoint, table/column support
  - [ ] network/security boundary: security-group rule, ingress/egress exposure, route target, gateway linkage
  - [ ] compute/service: runtime endpoint, attached role, image/build provenance, deployment binding

### Detailed follow-on backlog
- [ ] Track A - Multi-family support packs
  - Exit criteria:
  - [ ] add `database_*` facet pack with promoted config subresources and durable posture claims
  - [ ] add `service_*` facet pack covering exposure, runtime/deployment linkage, and secret/dependency support
  - [ ] add `instance_*` or compute pack covering public reachability, IMDS posture, attached role/profile, backup, and patch state
- [ ] Track B - Deeper support graph semantics
  - Exit criteria:
  - [ ] add explicit support graph edges for “configured_by”, “enforced_by”, “collects_to”, and “protects” where `configures` is too weak
  - [ ] expose subresource-to-claim and subresource-to-evidence traversal helpers as typed proof/report fragments
  - [ ] add family-specific explanation templates that traverse entity -> subresource -> claim -> evidence/source
- [ ] Track C - Durable normalization lifecycle
  - Exit criteria:
  - [ ] split normalization into inspectable executions/jobs instead of only builder-side hooks
  - [ ] emit lifecycle events for normalized support claim creation, correction, and retraction
  - [ ] preserve source/raw observation lineage so normalized posture claims remain auditable after re-ingest
- [ ] Track D - Contract governance and generation
  - Exit criteria:
  - [ ] make facet registry the single source for generated OpenAPI/doc fragments where practical
  - [ ] add example generation per facet and per subresource family
  - [ ] add compatibility gates for family-specific subresource schemas and claim packs
- [ ] Track E - Asset reports as extensible modules
  - Exit criteria:
  - [ ] add timeline, remediation, benchmark overlay, and docs/link modules to `entity-summary`
  - [ ] make report modules bind to facet IDs, subresource kinds, and claim predicates instead of provider field names
  - [ ] ensure future asset-family views stay report-driven instead of growing new `/assets/*` trees

## Deep Review Cycle 33 - Canonical Entity Identity + Facet Modules + Entity Summary Report (2026-03-10)

### Review findings
- [x] Gap: typed entity reads existed, but they still treated provider/source IDs as the public identity surface instead of separating canonical platform identity from external refs.
- [x] Gap: asset deepening was still trapped inside `properties`; there was no typed facet layer for ownership, exposure, encryption, logging, versioning, or sensitivity modules.
- [x] Gap: posture and support were visible at the claim layer, but entity detail still lacked a normalized posture block for “why is this asset risky / supported”.
- [x] Gap: asset pages still had no first-class report surface built from platform primitives, which left a risk of backsliding into bespoke asset endpoint trees.
- [x] Gap: the asset-deepening backlog needed sharper external guidance on per-family control packs and modular support facets.

### Research synthesis to adopt
- [x] Backstage rule: canonical refs should be stable and serializable, with relations layered on top instead of inventing identity shape per source.
- [x] DataHub rule: ownership and asset summaries should be typed modules/aspects, not loose strings or page-specific payload glue.
- [x] OpenMetadata rule: deep entities need strict typed fragments and typed cross-entity refs, not larger `additionalProperties` blobs.
- [x] Cartography rule: one resource family should accumulate composable support fragments instead of one giant provider payload.
- [x] Steampipe rule: one asset family should expose a reusable pack of small control modules (public access, encryption, logging, versioning, lifecycle) rather than one monolithic posture object.

### Execution plan
- [x] Add canonical entity identity surfaces:
  - [x] add `canonical_ref` to typed entity records
  - [x] add `external_refs` for source-native identity
  - [x] add `aliases` for explicit alternate identity records
- [x] Add schema-backed facet modules:
  - [x] add built-in facet contracts for `ownership`, `exposure`, `data_sensitivity`
  - [x] add first deep family pack for `bucket_public_access`, `bucket_encryption`, `bucket_logging`, `bucket_versioning`
  - [x] materialize facet records directly on entity detail
- [x] Add normalized posture/support summary on entities:
  - [x] add typed `posture` summary on entity detail
  - [x] include support/dispute/staleness signals on posture claims
  - [x] keep raw config in `properties` while exposing normalized posture separately
- [x] Add report-level asset view:
  - [x] add `reports.BuildEntitySummaryReport(...)`
  - [x] register `entity-summary` in the platform report catalog
  - [x] expose `GET /api/v1/platform/intelligence/entity-summary`
  - [x] make the report runnable through the existing report-run substrate
- [x] Tighten contracts/docs/tests:
  - [x] extend OpenAPI for canonical refs, external refs, aliases, facets, posture, and entity-summary
  - [x] add focused graph/API regression coverage for entity detail/report enrichment
  - [x] add [GRAPH_ENTITY_FACET_ARCHITECTURE.md](./docs/GRAPH_ENTITY_FACET_ARCHITECTURE.md)
  - [x] deepen [GRAPH_ASSET_DEEPENING_RESEARCH.md](./docs/GRAPH_ASSET_DEEPENING_RESEARCH.md) with the Steampipe control-pack pattern

### Detailed follow-on backlog
- [ ] Track A - Facet contract generation + compatibility
  - Exit criteria:
  - [x] generate machine-readable facet catalogs from one canonical registry
  - [x] add facet compatibility checks in CI similar to CloudEvents and report contracts
  - [x] generate facet docs/examples so schema names and field keys stop being hand-maintained
- [ ] Track B - Bucket subresource deepening
  - Exit criteria:
  - [x] add promoted subresource nodes for bucket policy statements / public-access controls when evidence and explanation need durable IDs
  - [x] connect bucket subresources to evidence/claims instead of storing all posture only on the bucket node
  - [x] expose bucket-family explanation paths that traverse bucket -> subresource -> claim -> evidence
- [ ] Track C - Write-side posture normalization
  - Exit criteria:
  - [x] add normalization jobs or ingest hooks that convert raw asset config into durable posture claims automatically
  - [x] make entity detail and entity-summary prefer durable claims over read-time derivation when both exist
  - [ ] emit lifecycle events for normalized posture claim creation/update
- [ ] Track D - Broader facet packs
  - Exit criteria:
  - [ ] add first-class facet packs for `database`, `service`, and `instance`
  - [ ] keep field names and assessments durable across providers where semantics match
  - [ ] add provider-specific external ref coverage without losing canonical platform identity
- [ ] Track E - Entity summary module overlays
  - Exit criteria:
  - [ ] add docs/links, timeline, remediation, and subresource modules to `entity-summary`
  - [ ] bind report modules to facet IDs and posture predicates rather than provider property names
  - [ ] support module overlays/benchmark packs without inventing new asset-specific endpoint trees

## Deep Review Cycle 32 - Append-Only Claim Adjudication + Proof Objects + Knowledge Diffs + Asset Entity Surface (2026-03-10)

### Review findings
- [x] Gap: the platform could surface contradiction queues, but still had no safe write path for claim repair that preserved historical visibility.
- [x] Gap: claim explanation still stopped at summaries and flat lists, which was not strong enough for real “show me the proof” or downstream UI composition.
- [x] Gap: cross-slice change reporting existed for claims only, which left evidence and observations outside the main “what changed” contract.
- [x] Gap: asset support was still too shallow at the platform layer; security assets were readable as raw tables and graph nodes, but not as typed platform entities with support and relationship context.
- [x] Gap: the backlog for asset deepening was still too generic and needed concrete external patterns to keep implementation honest.

### Research synthesis to adopt
- [x] Backstage rule: entities need one canonical envelope plus reusable ownership/dependency/part-of relations; assets should not invent custom identity shapes per source.
- [x] DataHub rule: asset summaries are modular views over an asset, not special-case asset types; ownership and curated context deserve typed aspects/modules.
- [x] OpenMetadata rule: deep asset support requires strict typed fragments and entity references, not ever-larger untyped property blobs.
- [x] Cartography rule: provider assets should use a base entity plus composable facet fragments and promoted subresources where posture/explanation depends on them.
- [x] Platform rule: risky posture should be representable as claims/evidence/observations attached to entities, not only as report rows or free-form properties.

### Execution plan
- [x] Add append-only claim adjudication writes:
  - [x] add `graph.AdjudicateClaimGroup(...)`
  - [x] support `accept_existing`, `replace_value`, and `retract_group`
  - [x] preserve history by emitting a new claim version and superseding active claims rather than mutating existing rows
  - [x] expose `POST /api/v1/platform/knowledge/claim-groups/{group_id}/adjudications`
- [x] Add explanation-grade proof objects:
  - [x] add `graph.BuildClaimProofs(...)`
  - [x] emit typed proof fragments with explicit nodes/edges for source, evidence, observation, support, refutation, conflict, and supersession paths
  - [x] expose `GET /api/v1/platform/knowledge/claims/{claim_id}/proofs`
  - [x] embed proof summaries into `GET /api/v1/platform/knowledge/claims/{claim_id}/explanation`
- [x] Add cross-slice knowledge diffs:
  - [x] add `graph.DiffKnowledgeGraphs(...)`
  - [x] support bitemporal and snapshot-pair comparisons
  - [x] include claim, evidence, and observation changes in one typed response
  - [x] expose `GET /api/v1/platform/knowledge/diffs`
- [x] Add typed platform entity reads:
  - [x] add `graph.QueryEntities(...)` and `graph.GetEntityRecord(...)`
  - [x] expose typed relationship summaries and typed knowledge support summaries on entity records
  - [x] expose `GET /api/v1/platform/entities`
  - [x] expose `GET /api/v1/platform/entities/{entity_id}`
- [x] Tighten contracts/docs:
  - [x] extend OpenAPI for entity, adjudication, proof, and knowledge-diff surfaces
  - [x] add lifecycle contract for `platform.claim.adjudicated`
  - [x] add graph/API regression coverage for new routes and append-only semantics
  - [x] add [GRAPH_ASSET_DEEPENING_RESEARCH.md](./docs/GRAPH_ASSET_DEEPENING_RESEARCH.md)

### Detailed follow-on backlog
- [ ] Track A - Canonical entity identity
  - Exit criteria:
  - [ ] add canonical entity refs on typed entity records (`kind`, namespace/scope, canonical name)
  - [ ] add explicit external refs / alias records on entity detail
  - [ ] stop treating source-native asset IDs as the only durable public identity
- [ ] Track B - Entity facet registry
  - Exit criteria:
  - [ ] add schema-backed facet fragments for high-value resource kinds
  - [ ] add facet compatibility checks and generated docs the same way report and event contracts are already gated
  - [ ] expose typed facet summaries on entity detail without turning `properties` into the contract
- [ ] Track C - Subresource deepening
  - Exit criteria:
  - [ ] pick one asset family and model it deeply end-to-end
  - [ ] likely first target: `bucket` plus policy statements, logging config, encryption config, and public-access controls
  - [ ] promote nested objects into nodes when lifecycle, evidence, or remediation depends on them
- [ ] Track D - Support and posture claims
  - Exit criteria:
  - [ ] normalize risky configurations into evidence-backed claims attached to entities
  - [ ] surface active/supported/disputed/stale posture claims on entity detail
  - [ ] add entity-level explanation payloads for “why is this asset risky”
- [ ] Track E - Asset summary/report modules
  - Exit criteria:
  - [ ] build entity summary modules as report sections over `/api/v1/platform/entities` plus knowledge/report registries
  - [ ] support modules for ownership, posture, topology, support coverage, docs/links, and change timeline
  - [ ] avoid bespoke asset-summary endpoint sprawl

## Deep Review Cycle 31 - Knowledge Artifact Reads + Claim Adjudication Queue + Claim Explanation/Diff Surfaces (2026-03-10)

### Review findings
- [x] Gap: the platform could now write claims, evidence, and observations, but typed knowledge inspection still stopped at claim collection/detail, which left evidence and observation reads hidden behind generic graph traversals.
- [x] Gap: `observation` existed as a first-class ontology kind, but the write path still serialized observations as `evidence`, which blurred raw observation semantics and made the ontology less honest than the docs claimed.
- [x] Gap: contradiction reporting existed as a report surface, but there was still no first-class adjudication queue resource keyed by `subject_id + predicate` for downstream repair workflows.
- [x] Gap: clients still could not ask the platform “why is this claim true”, “why is it disputed”, or “what changed in the claim layer between two bitemporal slices” without reimplementing the knowledge model client-side.
- [x] Gap: platform docs still described observations, evidence, and claim explanation as design intent more than actual contract, which risked the code/docs boundary drifting again.

### Research synthesis to adopt
- [x] Knowledge-artifact rule: once observations and evidence are ontology kinds, they need the same typed collection/detail contracts as claims, otherwise report outputs become the only stable read surface.
- [x] Adjudication-queue rule: contradiction repair should start as typed grouped read resources with explicit `needs_adjudication` and `recommended_action` signals before the system pretends it has safe claim-mutation workflows.
- [x] Explanation rule: claim explanation should be a first-class resource composed from claim, source, evidence, observation, and support/refute/supersession chains rather than a report-only narrative blob.
- [x] Diff rule: a world-model graph needs explicit “what changed” resources over bitemporal slices, even if the first version is claim-ID based and not yet a full historical version store.

### Execution plan
- [x] Normalize the observation write path onto the actual ontology:
  - [x] add `graph.WriteObservation(...)`
  - [x] make API/tool observation writes create `NodeKindObservation`
  - [x] preserve backward-tolerant request fields (`entity_id`, `observation`) while exposing canonical platform fields (`subject_id`, `observation_type`)
- [x] Add typed knowledge artifact reads:
  - [x] add `QueryEvidence(...)`, `GetEvidenceRecord(...)`, `QueryObservations(...)`, and `GetObservationRecord(...)`
  - [x] include target, claim, source, and referencing-link summaries on artifact records
  - [x] expose `GET /api/v1/platform/knowledge/evidence`
  - [x] expose `GET /api/v1/platform/knowledge/evidence/{evidence_id}`
  - [x] expose `GET /api/v1/platform/knowledge/observations`
  - [x] expose `GET /api/v1/platform/knowledge/observations/{observation_id}`
  - [x] expose `POST /api/v1/platform/knowledge/observations`
- [x] Add adjudication-oriented claim grouping:
  - [x] add `QueryClaimGroups(...)` and `GetClaimGroupRecord(...)`
  - [x] group by `subject_id + predicate`
  - [x] emit grouped values, active/resolved claim IDs, supportability counts, and `recommended_action`
  - [x] expose `GET /api/v1/platform/knowledge/claim-groups`
  - [x] expose `GET /api/v1/platform/knowledge/claim-groups/{group_id}`
- [x] Add claim explanation and history surfaces:
  - [x] add `GetClaimTimeline(...)`
  - [x] add `ExplainClaim(...)`
  - [x] include support/refute/supersession/conflict claim chains plus evidence, observations, and sources
  - [x] expose `GET /api/v1/platform/knowledge/claims/{claim_id}/timeline`
  - [x] expose `GET /api/v1/platform/knowledge/claims/{claim_id}/explanation`
- [x] Add claim-layer diffs:
  - [x] add `DiffClaims(...)` over `from_*` and `to_*` bitemporal slices
  - [x] return typed added/removed/modified claim records plus modified-field summaries
  - [x] expose `GET /api/v1/platform/knowledge/claim-diffs`
- [x] Tighten tests/contracts/docs:
  - [x] add graph tests for observation writes, artifact reads, claim groups, timelines, explanations, and diffs
  - [x] add API tests for the new platform knowledge routes and invalid param handling
  - [x] update OpenAPI with typed artifact/group/timeline/explanation/diff schemas
  - [x] update platform/world-model/intelligence docs to describe the new knowledge inspection substrate

### Detailed follow-on backlog
- [ ] Knowledge artifact track:
  - [ ] add first-class read/query surfaces for `source`, `annotation`, `decision`, `action`, and `outcome` with the same typed derivation rigor now used for claims and artifacts
  - [ ] add cross-resource filters for claim/evidence/observation reads by trust tier, source type, producer fingerprint, and artifact type family
  - [ ] add cursor pagination and explicit sort selectors for knowledge collections once list sizes outgrow offset semantics
- [ ] Adjudication workflow track:
  - [ ] add review-state resources (status, assignee, SLA, owner) on claim groups instead of keeping the queue purely derived/read-only
  - [ ] add decision/write-back workflows for contradiction repair once claim-state mutation can preserve historical visibility correctly
  - [ ] add calibration metrics for adjudication throughput, reopened contradictions, and source-accuracy outcomes
- [ ] Explanation/runtime track:
  - [ ] add claim-neighborhood expansion resources for downstream traversal without falling back to generic graph query mode
  - [ ] add richer explanation narratives with value comparisons, trust deltas, and freshness decay signals
  - [ ] add source-trust scoring and explanation weighting so “why true” can separate raw support from source credibility
- [ ] Historical fidelity track:
  - [ ] add durable versioned claim mutation/history so claim diffs can report true modifications across slices instead of primarily added/removed visibility changes
  - [ ] add first-class adjudication/repair events to CloudEvents and lifecycle catalogs once claim repair becomes writable
  - [ ] add generated example payloads and compatibility gates for the new knowledge inspection contracts

## Deep Review Cycle 30 - Claim Query Surface + Knowledge Read RBAC + Source Attribution Hardening (2026-03-10)

### Review findings
- [x] Gap: the platform had first-class claim writes and contradiction reports, but no first-class claim collection/detail read surface for the world model itself.
- [x] Gap: derived truth signals such as supported vs unsupported, source-backed vs sourceless, and conflicted vs uncontested still had to be reconstructed ad hoc from raw node properties and edge walks.
- [x] Gap: `/api/v1/platform/knowledge/*` only existed as a write namespace, so the permission model implicitly treated all knowledge routes as write-scoped.
- [x] Gap: the existing claim write path silently synthesized generic source nodes when no explicit source attribution was supplied, which made sourceless-claim metrics and queues less honest than they appeared.
- [x] Gap: historical/bitemporal claim reads were easy to test incorrectly because fixture entities without temporal metadata defaulted to `created_at=now`, hiding support/evidence links in older fact-time slices.

### Research synthesis to adopt
- [x] Knowledge-contract rule: once `claim` is a first-class ontology kind, it needs both a write surface and a typed read surface; otherwise reports and tools become the de facto API.
- [x] Derived-state rule: supportability, contradiction, supersession, and source attribution should be emitted as typed fields on the read model instead of forcing every consumer to recalculate them differently.
- [x] Permission honesty rule: namespace splits only matter if read/query and write/record semantics are scoped separately in RBAC and route mapping.
- [x] Provenance honesty rule: “unknown/generic system source” is not equivalent to “explicit source attribution”; the model must preserve that distinction if source quality metrics are meant to guide adjudication.

### Execution plan
- [x] Add a graph-native claim query/read model:
  - [x] add `ClaimQueryOptions`, `ClaimCollection`, `ClaimRecord`, link summaries, and derived-state summaries
  - [x] add bitemporal claim filtering over `valid_at` + `recorded_at`
  - [x] add subject/predicate/object/source/evidence/status filters
  - [x] add derived filters for `supported`, `sourceless`, and `conflicted`
  - [x] sort collections deterministically by recorded/fact recency
- [x] Expose the claim read surface through platform APIs:
  - [x] add `GET /api/v1/platform/knowledge/claims`
  - [x] add `GET /api/v1/platform/knowledge/claims/{claim_id}`
  - [x] return typed collection pagination, filters, summaries, links, and derived state
  - [x] validate query booleans, status enums, and RFC3339 temporal selectors
- [x] Split knowledge read vs write permissions:
  - [x] add `platform.knowledge.read`
  - [x] map `GET /api/v1/platform/knowledge/*` to read scope and writes to write scope
  - [x] propagate the new scope through default roles and permission implications
- [x] Harden source-attribution semantics:
  - [x] stop creating synthetic `source:*` nodes when no explicit source identity/metadata was supplied
  - [x] add regression coverage proving sourceless claims remain sourceless until attributed
- [x] Tighten tests/contracts/docs:
  - [x] add graph-level tests for derived claim state, conflict peers, and bitemporal visibility
  - [x] add API tests for collection/detail reads and invalid param handling
  - [x] extend OpenAPI with typed claim collection/detail schemas
  - [x] update world-model/platform docs to include the claim read surface

### Detailed follow-on backlog
- [ ] Knowledge read track:
  - [x] add `GET /api/v1/platform/knowledge/evidence` and `GET /api/v1/platform/knowledge/evidence/{evidence_id}`
  - [x] add `GET /api/v1/platform/knowledge/observations` and typed observation-to-evidence linkage views
  - [ ] add cross-resource filters so claims can be queried by source trust tier, producer fingerprint, or evidence type
  - [ ] add stable sort selectors and cursor pagination once claim collections grow beyond offset-only ergonomics
- [ ] Claim history / adjudication track:
  - [x] add claim timeline/history resources that show supersession, correction, and refutation chains explicitly
  - [x] add claim-group/adjudication queue resources keyed by `subject_id + predicate`
  - [ ] add review statuses, assignees, and decision write-back for contradiction repair workflows
  - [x] add “why is this claim true” and “why is this claim disputed” explanation payloads built from support/refute/source chains
- [ ] Graph reasoning track:
  - [ ] add queryable claim-neighborhood expansions for follow-on graph traversals without forcing consumers into generic graph-query mode
  - [ ] add claim/evidence/source trust scoring that distinguishes asserted truth from confidence in the asserting producer
  - [x] add bitemporal diff helpers for “what changed in the claim layer between two slices”
  - [ ] add read APIs for decisions/actions/outcomes with the same typed derivation rigor used for claims
- [ ] Contract/autogen track:
  - [ ] generate claim collection/detail example payloads from canonical schemas
  - [ ] add compatibility checks for knowledge read contracts the same way report, CloudEvent, and Agent SDK contracts are gated
  - [ ] generate SDK bindings for typed knowledge read/write resources from one source of truth

## Deep Review Cycle 29 - Snapshot Manifest Index + Materialized Diff Artifacts + Async Diff Jobs (2026-03-10)

### Review findings
- [x] Gap: graph snapshot resources existed, but catalog and payload lookup still depended on scanning compressed snapshot artifacts instead of reading a durable manifest/index layer.
- [x] Gap: typed graph diffs existed, but they were still effectively request-scoped computations rather than durable derived artifacts addressable by stable IDs.
- [x] Gap: snapshot ancestry was still mostly chronological; the platform lacked explicit parent metadata on snapshot resources and references.
- [x] Gap: integrity and retention semantics were starting to matter for snapshot/report portability, but graph snapshot resources still did not expose them directly.
- [x] Gap: API tests could still emit package-local `.cerebro` artifacts through relative snapshot-store defaults, which hid storage assumptions and polluted the worktree.

### Research synthesis to adopt
- [x] Apache Iceberg metadata-table rule: snapshot history and ancestry reads should resolve through lightweight metadata structures instead of replaying every heavy artifact on every read.
- [x] Delta Lake checkpoint rule: once artifact count grows, a durable index/checkpoint layer becomes part of the contract, not just a performance optimization.
- [x] lakeFS and Dolt lineage rule: ancestry and diff are first-class resources keyed by stable IDs and parent relationships, not timestamp conveniences reconstructed at read time.
- [x] Control-plane rule: expensive snapshot comparisons should degrade cleanly to async jobs with durable artifacts rather than forcing all callers through synchronous handler latency.

### Execution plan
- [x] Add an explicit graph snapshot manifest/index layer:
  - [x] persist `index.json` under the snapshot store
  - [x] persist per-snapshot manifest documents with artifact path, retention, integrity, and record metadata
  - [x] make snapshot catalog reads resolve from the manifest/index layer
  - [x] make targeted snapshot payload loads resolve by record ID through the index instead of rescanning all artifacts
- [x] Deepen graph snapshot resources:
  - [x] attach `parent_snapshot_id` to `GraphSnapshotRecord`
  - [x] attach `retention_class`, `integrity_hash`, and `expires_at` to `GraphSnapshotRecord`
  - [x] expose explicit `parent` and `children` relationships on `GraphSnapshotAncestry`
  - [x] propagate parent lineage into `GraphSnapshotReference`
- [x] Add durable diff artifacts:
  - [x] persist `GraphSnapshotDiffRecord` artifacts in a dedicated local diff store
  - [x] expose `GET /api/v1/platform/graph/diffs/{diff_id}`
  - [x] attach `stored_at`, `materialized`, `storage_class`, `byte_size`, `integrity_hash`, and `job_id` to diff artifacts
- [x] Add async diff execution:
  - [x] allow `POST /api/v1/platform/graph/diffs` to run as `execution_mode=async`
  - [x] materialize async diff results as durable diff artifacts
  - [x] return a typed platform job for async diff creation
- [x] Tighten runtime/tests/contracts:
  - [x] extend OpenAPI for snapshot lineage/integrity fields and async diff responses
  - [x] add graph-level tests for manifest/index persistence and explicit parent/child ancestry
  - [x] add API regression coverage for async diff jobs and artifact retrieval
  - [x] isolate API tests from package-local snapshot-path defaults

### Detailed follow-on backlog
- [ ] Snapshot substrate track:
  - [ ] promote parent assignment from chronological fallback to explicit write-time lineage once graph snapshot creation becomes a first-class platform write path
  - [ ] add snapshot reference/tag resources (`current`, `baseline`, `candidate`, `imported`) instead of forcing clients to memorize raw snapshot IDs
  - [ ] add branch-aware ancestry metadata such as `is_current_ancestor`, rollback lineage, and fork/join semantics
  - [ ] persist snapshot artifact format version separately from graph schema version and ontology contract version
- [ ] Diff runtime track:
  - [ ] add a diff catalog/list surface with filterable snapshot pairs and materialization state
  - [ ] add canonical diff change classes (`node_added`, `node_removed`, `node_modified`, `edge_added`, `edge_removed`, `temporal_change`, `ontology_change`) for higher-level reports
  - [ ] add filtered diff summaries by node kind, edge kind, provider, account, and report lineage scope
  - [ ] add diff cache reuse keyed by snapshot pair, filter parameters, and contract version
  - [ ] add async diff cancel/retry controls where comparisons become expensive enough to justify operator control
- [ ] Integrity/retention track:
  - [ ] add a background integrity verification sweep for snapshot and diff artifacts
  - [ ] add orphan manifest/diff cleanup when artifact files disappear or retention sweeps expire them
  - [ ] add retention tiers (`hot`, `metadata_only`, `expired`) instead of one local-retained default
  - [ ] add a degraded metadata-only mode when manifests remain but payload artifacts are intentionally dropped
- [ ] Contract/autogen track:
  - [ ] generate machine-readable snapshot manifest and diff artifact contract catalogs alongside OpenAPI
  - [ ] generate concrete example payloads for snapshot manifests, ancestry responses, and diff artifacts
  - [ ] add compatibility checks for snapshot/diff contract evolution the same way report and CloudEvent contracts are already gated
  - [ ] generate SDK bindings for snapshot and diff resources from one canonical contract source
- [ ] Platform/report leverage track:
  - [ ] let report runs target explicit snapshot IDs or snapshot pairs instead of only implicit current-graph lineage
  - [ ] attach report-run lineage to materialized diff artifacts for “what changed since last run” surfaces
  - [ ] expose snapshot/diff lineage navigation from report sections and recommendations where it improves explainability

## Deep Review Cycle 28 - Snapshot Ancestry + Typed Diffs + Contract Example Autogen (2026-03-10)

### Review findings
- [x] Gap: `graph_snapshot_id` existed as a typed resource, but clients still could not traverse ordered snapshot ancestry or ask for a typed diff between two durable snapshot resources.
- [x] Gap: the public graph diff surface was still timestamp-shaped and legacy (`/api/v1/graph/diff`), which leaked storage details instead of exposing platform snapshot primitives.
- [x] Gap: strict report envelope matching still only validated top-level required fields, so nested contract drift could still be mislabeled as strict payloads.
- [x] Gap: report contract docs listed envelope schemas but did not generate concrete example payloads from those schemas, which weakened downstream UI/SDK extension work.

### Research synthesis to adopt
- [x] Resource-navigation rule: once snapshot IDs are durable, diffs and ancestry should be navigable through those IDs, not reconstructed indirectly from timestamps.
- [x] Artifact honesty rule: a snapshot resource should advertise whether it is materialized/diffable so clients do not guess whether lineage metadata points at a real artifact.
- [x] Contract-proof rule: a payload should only claim strict envelope conformance when nested objects, arrays, and format constraints all validate recursively.
- [x] Autogen rule: example payloads should be synthesized from canonical schemas so docs do not drift from runtime contracts.

### Execution plan
- [x] Deepen graph snapshot resources:
  - [x] merge file-backed snapshot artifacts into the platform snapshot catalog
  - [x] expose `captured_at`, `materialized`, `diffable`, `storage_class`, and `byte_size` on `GraphSnapshotRecord`
  - [x] add chronological `GraphSnapshotAncestry`
- [x] Replace the legacy diff surface:
  - [x] remove `/api/v1/graph/diff`
  - [x] expose `POST /api/v1/platform/graph/diffs`
  - [x] expose `GET /api/v1/platform/graph/snapshots/{snapshot_id}/diffs/{other_snapshot_id}`
  - [x] return typed `GraphSnapshotDiffRecord` / `GraphSnapshotDiffSummary`
- [x] Tighten envelope honesty:
  - [x] validate strict envelope matches recursively across nested arrays/objects
  - [x] enforce `additionalProperties: false` and `format: date-time` for strict matching
  - [x] extend report runtime tests for nested-envelope fallback behavior
- [x] Improve contract autogen:
  - [x] generate deterministic envelope example payloads in `GRAPH_REPORT_CONTRACTS_AUTOGEN.md`
  - [x] keep examples derived from schema inputs rather than versioned contract fields

### Detailed follow-on backlog
- [ ] Snapshot/runtime hardening:
  - [x] persist standalone graph snapshot manifests with explicit parent/child lineage instead of inferring ancestry from timestamps
  - [x] attach integrity hashes and retention policy directly to graph snapshot resources
  - [ ] expose snapshot-to-snapshot change classes and filtered diff summaries for higher-level report/reporting use
- [ ] Report contract/autogen hardening:
  - [ ] generate example payloads for section fragments and benchmark overlays
  - [ ] emit machine-readable example catalogs alongside markdown docs
  - [ ] reuse the recursive validator for generated SDK fixture verification

## Deep Review Cycle 27 - Report Execution Control + Graph Snapshot Resources + Payload Contracts (2026-03-10)

### Review findings
- [x] Gap: durable report runs exposed retry and cancel verbs, but execution control was still operation-shaped instead of resource-shaped, leaving retry policy and allowed actions implicit.
- [x] Gap: report lineage carried `graph_snapshot_id`, but the platform still lacked a typed graph snapshot resource that clients could inspect independently of one report run.
- [x] Gap: section envelopes existed in registries, but section payload contracts were still too implicit at runtime and too loose in OpenAPI for downstream SDK/UI consumers.

### Research synthesis to adopt
- [x] Control-plane rule: long-lived execution resources need their own control state, not just state-changing verbs.
- [x] Lineage navigation rule: IDs in lineage metadata should resolve to inspectable platform resources wherever possible.
- [x] Payload honesty rule: section metadata should distinguish between strict typed envelope matches and flexible JSON fallbacks instead of pretending all report sections are equally structured.

### Execution plan
- [x] Add resource-shaped report execution control:
  - [x] add typed `ReportRunControl` snapshot
  - [x] add typed `ReportRunRetryPolicyState` snapshot
  - [x] expose `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/control`
  - [x] expose `GET|PUT /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/retry-policy`
- [x] Tighten attempt/cancel semantics:
  - [x] add explicit attempt statuses including `scheduled`
  - [x] propagate scheduled retry state when async backoff is active
  - [x] persist cancel-request metadata (`cancel_requested_at`, `cancel_requested_by`, `cancel_reason`)
  - [x] make cancellation preserve operator intent instead of degrading to generic context-canceled errors
- [x] Add graph snapshot resources:
  - [x] add typed `GraphSnapshotRecord` / `GraphSnapshotCollection`
  - [x] derive snapshot catalog from current graph metadata plus persisted report lineage
  - [x] expose `GET /api/v1/platform/graph/snapshots`
  - [x] expose `GET /api/v1/platform/graph/snapshots/current`
  - [x] expose `GET /api/v1/platform/graph/snapshots/{snapshot_id}`
- [x] Tighten section payload contracts:
  - [x] record actual payload contract metadata on `ReportSectionResult`
  - [x] distinguish strict envelope matches from flexible JSON fallback contracts
  - [x] extend OpenAPI with typed section payload unions and explicit payload schema metadata
- [x] Regenerate/validate contract surfaces:
  - [x] extend CloudEvents contract payloads for cancel/control/snapshot URL metadata
  - [x] extend API and graph regression coverage for control, retry-policy, cancel, snapshot, and payload-contract behavior

### Detailed follow-on backlog
- [ ] Execution-control hardening:
  - [ ] add pause/resume semantics for scheduled attempts if deferred execution grows beyond simple backoff
  - [ ] expose cancel provenance on platform jobs and report-run events through one typed control fragment
  - [ ] add policy-controlled automatic retry surfaces instead of manual retry only
- [ ] Snapshot/runtime hardening:
  - [ ] persist graph snapshot manifests independently of report runs once the graph has its own durable storage layer
  - [ ] expose graph snapshot diffs/version ancestry as first-class platform resources
  - [ ] attach report snapshots to graph snapshot retention/integrity policy instead of report-local retention only
- [ ] Payload/autogen hardening:
  - [ ] generate concrete section payload examples per envelope family
  - [ ] add deeper runtime validation for strict envelope matches beyond top-level required-field/type checks
  - [ ] move section payload contract generation fully into the report contract autogen pipeline

## Deep Review Cycle 26 - Report Section Telemetry + Cache Reuse + Fragment Governance (2026-03-10)

### Review findings
- [x] Gap: section metadata exposed lineage and truncation, but not the execution facts operators actually need to interpret derived artifacts: cache reuse, retry backoff, and real section materialization timing.
- [x] Gap: section lineage still stopped at nodes only, which meant explanation surfaces could not trace the supporting graph edges or the exact bitemporal slice used to produce one section.
- [x] Gap: lineage/materialization metadata existed in code and OpenAPI, but not in the governed report contract catalog, so compatibility checks could not detect drift when section metadata evolved.
- [x] Gap: report cache keys existed, but the report runtime still did not actually reuse prior compatible runs, leaving `cache_key` as metadata theater instead of an operational capability.

### Research synthesis to adopt
- [x] Runtime observability rule: section metadata must surface the execution facts that materially affect interpretation, not just payload shape.
- [x] Explainability rule: a derived section should expose both the referenced entities and the supporting relationships/time basis that made the section true.
- [x] Contract-governance rule: reusable metadata fragments deserve the same registry/versioning discipline as envelopes and benchmark packs.
- [x] Cache honesty rule: if a run reuses a prior artifact, that fact should be explicit on the run, the section, and the lifecycle events.

### Execution plan
- [x] Deepen reusable section telemetry:
  - [x] add `ReportSectionTelemetry`
  - [x] capture real per-section materialization duration
  - [x] expose cache hit/miss and cache source run ID
  - [x] expose retry backoff on section artifacts
- [x] Deepen section provenance:
  - [x] add supporting edge counts/IDs to section lineage
  - [x] add `valid_at` / `recorded_at` lineage selectors for point-in-time runs
  - [x] make lineage extraction respect bitemporal visibility when a run carries a time slice
- [x] Make cache reuse real:
  - [x] add compatible run reuse keyed by report, cache key, and lineage
  - [x] persist cache status and cache source run ID on `ReportRun`
  - [x] propagate cache reuse through sync runs, retries, events, SSE, and MCP progress
- [x] Govern section metadata contracts:
  - [x] add `ReportSectionFragmentDefinition` registry
  - [x] publish fragment contracts in `ReportContractCatalog`
  - [x] add field-level diff summaries to report-contract compatibility reports
  - [x] expose section fragment discovery endpoints
- [x] Tighten contracts/tests/docs:
  - [x] extend OpenAPI for section fragments, run cache metadata, telemetry, and bitemporal lineage fields
  - [x] regenerate report and CloudEvents contract docs
  - [x] extend generated SDK report models
  - [x] add graph/API regression coverage for cache reuse, retry telemetry, fragment discovery, and bitemporal supporting-edge lineage

### Detailed follow-on backlog
- [ ] Section execution depth:
  - [ ] add per-section partial-failure classification separate from truncation
  - [ ] add section-local cache tier / freshness metadata once storage tiering exists
  - [ ] add configurable lineage sample limits by report family
- [ ] Derived artifact graph write-back:
  - [ ] materialize high-value section lineage back into graph annotations/outcomes where it creates leverage
  - [ ] attach section lineage to recommendation acceptance and outcome review loops
  - [ ] add graph navigation links from section metadata into query/templates surfaces
- [ ] Contract/autogen hardening:
  - [ ] generate section example payload fixtures from one canonical source
  - [ ] expose live contract diff summaries over an admin/report-governance surface
  - [ ] generate concrete envelope/fragment unions to eliminate the remaining unused-component warnings in OpenAPI
- [ ] Storage/runtime hardening:
  - [ ] add retention enforcement and integrity verification for report snapshots
  - [ ] add cache invalidation policy surfaces instead of lineage-only implicit invalidation
  - [ ] add report-run storage migrations for future schema evolution

## Deep Review Cycle 25 - Report Section Lineage + Truncation Metadata (2026-03-10)

### Review findings
- [x] Gap: durable report runs had stable section summaries, but section artifacts still lacked graph-aware lineage that downstream tools could use for explanation, drill-down, and follow-on reasoning.
- [x] Gap: truncation hints lived inside report-specific payloads, which forced clients to scrape arbitrary section content instead of reading one stable section contract.
- [x] Gap: section-emitted lifecycle events and stream payloads exposed content shape, but not enough metadata to explain which claims, evidence, and sources anchored the emitted section.

### Research synthesis to adopt
- [x] Derived-artifact rule: report sections are typed derived artifacts and should carry explicit lineage/sample metadata alongside payload content.
- [x] Explainability rule: section contracts should expose supportability metadata directly so UI, SDK, and automation layers do not need report-specific parsers for every explanation workflow.
- [x] Truncation-transparency rule: if a report section reflects partial output, that fact belongs in stable section metadata rather than being buried in one report family's custom fields.

### Execution plan
- [x] Enrich `ReportSectionResult` with reusable lineage metadata:
  - [x] add referenced-node, claim, evidence, and source counts
  - [x] add sampled lineage ID sets with truncation protection
  - [x] expand direct claim references to linked evidence/source nodes
- [x] Enrich `ReportSectionResult` with reusable materialization metadata:
  - [x] add stable `truncated` flag
  - [x] add sampled truncation-signal paths detected from report payloads
- [x] Thread enriched section metadata through runtime surfaces:
  - [x] persist it on durable report runs
  - [x] include it in `section_emitted` lifecycle events
  - [x] include it in platform SSE and MCP section/progress payloads
- [x] Tighten tests and contracts:
  - [x] add graph-level tests for lineage/truncation enrichment
  - [x] add API regression coverage for claim-conflict report runs exposing lineage/truncation metadata
  - [x] extend OpenAPI section schemas with lineage/materialization subcontracts

### Detailed follow-on backlog
- [ ] Section telemetry deepening:
  - [x] add real per-section duration capture instead of synthetic timing guesses
  - [x] add cache-hit/cache-miss and retry-backoff metadata where the runtime actually has those signals
  - [ ] add per-section partial-failure classification separate from truncation
- [ ] Section provenance deepening:
  - [x] expose supporting edge IDs and bitemporal windows for section lineage samples
  - [ ] add configurable lineage sample limits by report family
  - [ ] materialize high-value section lineage back into graph annotations/outcomes where it creates leverage
- [ ] Section contract generation:
  - [x] derive section lineage/materialization schema fragments from one canonical contract source
  - [x] generate report-definition diff summaries when section metadata fields evolve
  - [ ] emit section example payloads with lineage/truncation fixtures in generated docs

## Deep Review Cycle 24 - External SDK Packages + Section Streams + Managed Credential Control (2026-03-09)

### Review findings
- [x] Gap: generated Agent SDK contracts existed, but there were still no externally consumable Go/Python/TypeScript package surfaces or reproducible package validation targets.
- [x] Gap: long-running report execution exposed durable runs and MCP progress, but section-level payload delivery was still missing from the live transport contracts.
- [x] Gap: SDK auth had structured credential parsing, but there was still no managed lifecycle surface for creation/rotation/revocation or protected-resource discovery metadata for OAuth-aware clients.
- [x] Gap: the public Agent SDK catalog still had a hidden contract bug where `simulate` and `cerebro.simulate` collapsed to the same external tool ID.
- [x] Gap: OpenAPI had drifted behind the real runtime surface for `report_run:*` routes, report streaming, and the new SDK auth/admin resources.

### Research synthesis to adopt
- [x] Package generation discipline: a generated SDK is only real once language-native validation is wired into deterministic generation and CI drift checks.
- [x] MCP/report-runtime rule: partial execution insight should stream as stable section envelopes over the same durable run substrate, not via handler-local ad hoc progress blobs.
- [x] OAuth protected-resource rule: external clients should discover supported scopes and authorization servers from one machine-readable endpoint instead of vendor-specific docs.
- [x] Contract-governance rule: stable external tool IDs must be unique even when internal tool names converge semantically.

### Execution plan
- [x] Externalize generated SDK packages:
  - [x] add generated Go package output under `sdk/go/cerebro`
  - [x] add generated Python package output under `sdk/python/cerebro_sdk`
  - [x] add generated Python `pyproject.toml`
  - [x] add generated TypeScript package output under `sdk/typescript`
  - [x] add `docs/AGENT_SDK_PACKAGES_AUTOGEN.md`
  - [x] add `make agent-sdk-packages-check`
- [x] Deepen report streaming:
  - [x] emit section payload notifications over MCP as `notifications/report_section`
  - [x] add platform report-run SSE stream endpoint
  - [x] persist section emission events in report-run lifecycle history
  - [x] include section progress/payload metadata in stream events
- [x] Add managed credential control:
  - [x] add file-backed managed credential store with hashed secret persistence
  - [x] add admin create/get/list/rotate/revoke routes for SDK credentials
  - [x] add scoped credential enforcement through auth and RBAC
  - [x] add `/.well-known/oauth-protected-resource`
- [x] Tighten public contracts:
  - [x] fix duplicate simulation tool IDs in the generated Agent SDK catalog
  - [x] align OpenAPI with `report_run:{run_id}` status routes
  - [x] extend OpenAPI with protected-resource, credential admin, and report-stream resources
  - [x] add regression coverage for section streaming and managed credential lifecycle

### Detailed follow-on backlog
- [ ] Package publishing and release governance:
  - [ ] publish semantic version metadata from one canonical SDK release manifest
  - [ ] generate changelogs directly from Agent SDK compatibility diffs
  - [ ] emit per-language examples and README snippets from the generated catalog
- [ ] Runtime telemetry deepening:
  - [ ] stream cache-hit/cache-miss and retry-backoff metadata alongside section events
  - [x] extend section emissions with source/claim/evidence cardinality and truncation metadata
  - [ ] reuse the same runtime streaming contract for simulation-heavy non-report tools
- [ ] Auth and control-plane deepening:
  - [ ] per-tool and per-tenant throttling policies for managed SDK credentials
  - [ ] signed request support for higher-trust agent clients
  - [ ] SDK usage/audit reports over credential, tool, and approval pressure dimensions

## Deep Review Cycle 23 - Agent SDK Contract Governance + Progress Runtime + Structured Credentials (2026-03-09)

### Review findings
- [x] Gap: the new Agent SDK gateway existed as a first-class surface, but it still lacked generated contract artifacts and a compatibility gate comparable to the report and CloudEvents surfaces.
- [x] Gap: `cerebro_report` had a durable async execution model, but MCP consumers still needed explicit progress binding to the underlying report-run lifecycle instead of transport-local polling.
- [x] Gap: SDK API authentication was still effectively secret-string centric; it needed stable credential IDs, client IDs, and rate-limit buckets for attribution and governance.
- [x] Gap: the middleware response-writer wrapper stripped streaming interfaces from SSE routes, which made the new MCP progress path fail under real middleware composition.
- [x] Gap: the repo had no consumer-grade client bindings for the Agent SDK surface, which meant the public contract was still mostly server-side and doc-driven.

### Research synthesis to adopt
- [x] MCP Streamable HTTP discipline: progress and long-running execution should ride one stable session + notification channel, not a parallel custom stream protocol.
- [x] OpenMetadata/OpenLineage contract lesson: machine-readable generated catalogs plus compatibility checks are the real API boundary for extension ecosystems, not prose docs alone.
- [x] Platform governance rule: stable credential identity should be separate from raw shared-secret material so audit, rate limiting, and attribution can survive key rotation.

### Execution plan
- [x] Generate and govern the Agent SDK contract surface:
  - [x] add `internal/agentsdk` catalog + compatibility helpers
  - [x] generate `docs/AGENT_SDK_AUTOGEN.md`
  - [x] generate `docs/AGENT_SDK_CONTRACTS.json`
  - [x] add `scripts/check_agent_sdk_contract_compat/main.go`
  - [x] add Make targets and CI jobs for docs drift + compatibility enforcement
- [x] Deepen MCP/runtime behavior:
  - [x] route `cerebro_report` through the durable `ReportRun` substrate
  - [x] bind MCP progress tokens to report-run IDs
  - [x] emit `notifications/progress` from report-run lifecycle changes
  - [x] fix middleware streaming compatibility by preserving `http.Flusher`/stream-capable writer behavior
- [x] Deepen SDK auth/attribution:
  - [x] add structured `API_CREDENTIALS_JSON` parsing and fallback from `API_KEYS`
  - [x] propagate stable credential/client metadata through auth and rate limiting
  - [x] enrich Agent SDK write surfaces with SDK attribution metadata before delegating to platform handlers
  - [x] propagate `traceparent` through the SDK path and into write/report artifacts where available
- [x] Add consumer bindings and regression coverage:
  - [x] add in-repo client bindings for Agent SDK tool discovery/call, report execution, and MCP
  - [x] add API tests for MCP progress delivery and SDK attribution enrichment
  - [x] add catalog/compatibility tests for the generated Agent SDK surface

### Detailed follow-on backlog
- [ ] Externalize SDK packages cleanly:
  - [ ] publish a non-`internal` Go SDK package
  - [ ] add generated Python models + client helpers from the contract catalog
  - [ ] add generated TypeScript models + client helpers from the contract catalog
  - [ ] generate versioned changelogs from Agent SDK compatibility diffs
- [ ] Deepen report/runtime streaming:
  - [ ] stream section-level completion events, not just coarse report-run progress
  - [ ] expose partial section payloads when materialization policy allows
  - [ ] extend progress notifications with cache-hit/miss and attempt/backoff metadata
  - [ ] stream simulation status through the same runtime contract where applicable
- [ ] Deepen SDK governance:
  - [ ] scoped credential provisioning and rotation UX
  - [ ] per-tool and per-tenant throttling policies
  - [ ] signed request support for higher-trust agent clients
  - [ ] audit/report surfaces for SDK client usage, failures, and approval pressure
- [ ] Deepen SDK discovery and auth metadata:
  - [ ] add `.well-known/oauth-protected-resource`
  - [ ] add machine-readable auth-scope metadata per tool/resource
  - [ ] expose generated examples and schema URLs directly from the live catalog endpoints

## Deep Review Cycle 22 - Agent SDK Gateway + MCP Transport + Shared Tool Registry (2026-03-09)

### Review findings
- [x] Gap: Cerebro already had a curated internal/NATS tool surface, but HTTP and MCP clients still had no first-class gateway over the same registry.
- [x] Gap: the shared tool catalog was not exported from `internal/app`, which meant new transports would drift into hand-maintained copies of tool definitions and parameters.
- [x] Gap: the two highest-value agent workflows from issue `#125` were missing from the curated tool surface itself: pre-action policy checks and first-class claim writes.
- [x] Gap: route-level RBAC alone was insufficient for generic tool invocation; `/agent-sdk/tools/*` and MCP required per-tool authorization or they would become permission bypasses.
- [x] Gap: the platform lacked a stable external tool naming layer for SDK consumers; internal names like `cerebro.intelligence_report` and `insight_card` were usable internally but poor public contract IDs.

### Research synthesis to adopt
- [x] MCP Streamable HTTP guidance (official protocol as of 2026-03-10, version `2025-06-18`): keep `initialize`, `tools/list`, `tools/call`, `resources/list`, and `resources/read` small, explicit, and JSON-RPC native.
- [x] Backstage/OpenMetadata style contract lesson: discovery catalogs only stay durable when they are generated from one canonical registry instead of mirrored across transports.
- [x] Existing Cerebro architecture rule: report, quality, leverage, policy-check, and writeback flows should reuse the graph/policy substrate and not become a parallel agent-only backend.

### Execution plan
- [x] Export the canonical tool registry:
  - [x] add `App.AgentSDKTools()`
  - [x] switch NATS tool publication to consume the exported registry
- [x] Deepen the curated tool surface itself:
  - [x] add `evaluate_policy`
  - [x] add `cerebro.write_claim`
  - [x] add tool tests for policy-check and claim write conflict detection
- [x] Add HTTP Agent SDK surface:
  - [x] add `GET /api/v1/agent-sdk/tools`
  - [x] add `POST /api/v1/agent-sdk/tools/{tool_id}:call`
  - [x] add typed wrappers for context/report/quality/leverage/templates/check/simulate
  - [x] add typed wrappers for observation/claim/decision/outcome/annotation/identity-resolve writes
  - [x] add schema discovery endpoints for node/edge kinds
- [x] Add MCP transport:
  - [x] add `GET /api/v1/mcp`
  - [x] add `POST /api/v1/mcp`
  - [x] implement `initialize`
  - [x] implement `tools/list`
  - [x] implement `tools/call`
  - [x] implement `resources/list`
  - [x] implement `resources/read`
  - [x] expose MCP resources for node kinds, edge kinds, and tool catalog
- [x] Tighten auth/governance:
  - [x] add `sdk.context.read`
  - [x] add `sdk.enforcement.run`
  - [x] add `sdk.worldmodel.write`
  - [x] add `sdk.schema.read`
  - [x] add `sdk.invoke`
  - [x] add `sdk.admin`
  - [x] enforce per-tool permission checks for generic invoke and MCP
- [x] Tighten contracts and docs:
  - [x] extend OpenAPI with the full Agent SDK + MCP surface
  - [x] add `docs/AGENT_SDK_GATEWAY_ARCHITECTURE.md`
  - [x] update architecture/intelligence docs with the shared-registry boundary
- [x] Add regression coverage:
  - [x] API tests for tool discovery and generic invoke
  - [x] API tests for typed Agent SDK routes
  - [x] API tests for MCP initialize/tools/resources flows
  - [x] API tests for per-tool RBAC enforcement

### Deep follow-on backlog
- [ ] Generate language SDKs from the typed contract:
  - [ ] Go SDK from OpenAPI + tool catalog metadata
  - [ ] Python SDK with typed models and retry/stream helpers
  - [ ] TypeScript SDK with Zod schemas and framework adapters
- [ ] Deepen MCP/runtime behavior:
  - [ ] progress notifications for long-running tool calls
  - [ ] streaming report sections over SSE / MCP progress
  - [ ] `.well-known/oauth-protected-resource` metadata
  - [ ] explicit MCP session lifecycle tracking and telemetry
- [ ] Deepen SDK governance:
  - [ ] SDK-specific API key lifecycle and provisioning UX
  - [ ] per-tool and per-tenant rate limiting
  - [ ] request signing and richer trace/audit propagation
  - [ ] generated example payloads per tool from the shared registry
- [ ] Expand high-value resources:
  - [ ] report-definition resource URIs
  - [ ] measure/check registry URIs
  - [ ] report-run snapshot URIs where retention policy allows

## Deep Review Cycle 21 - Execution Control + Report Contract Compatibility (2026-03-09)

### Review findings
- [x] Gap: `ReportRun`/`ReportRunAttempt`/`ReportRunEvent` were durable and inspectable, but operators still could not actively control queued or running executions.
- [x] Gap: retry semantics were implicit in operator behavior instead of explicit in the platform contract surface (`retry`, `cancel`, backoff policy, attempt classification).
- [x] Gap: section-envelope and benchmark-pack registries were discoverable, but there was still no generated machine-readable contract catalog or CI compatibility gate to stop silent drift.
- [x] Gap: the backlog had become too self-similar; it needed explicit delivery tracks with exit criteria instead of a flat pile of correct-sounding future work.

### Research synthesis to adopt
- [x] Backstage task-control pattern: durable execution resources need active control (`cancel`, rerun/retry) once status, attempts, and history are first-class.
- [x] OpenMetadata definition/result discipline: compatibility pressure moves from handler code to typed registry/catalog contracts once execution and definition surfaces separate cleanly.
- [x] OpenLineage/DataHub contract rule: generated catalogs and compatibility checks are the operational boundary that keeps extension registries from drifting into ceremonial mirrors of code.

### Execution plan
- [x] Add active execution control:
  - [x] add `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:retry`
  - [x] add `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:cancel`
  - [x] add retry policy metadata (`max_attempts`, `base_backoff_ms`, `max_backoff_ms`)
  - [x] classify attempts as `transient`, `deterministic`, `cancelled`, or `superseded`
  - [x] propagate cancellation into linked platform jobs with cancel timestamps/reasons
- [x] Add report contract generation and compatibility governance:
  - [x] add `graph.ReportContractCatalog`
  - [x] generate `docs/GRAPH_REPORT_CONTRACTS.json`
  - [x] generate `docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md`
  - [x] add report-contract compatibility checker script
  - [x] add Make targets and CI jobs for docs drift + compatibility enforcement
- [x] Tighten public contract surfaces:
  - [x] extend OpenAPI with retry/cancel requests and retry policy schema
  - [x] extend OpenAPI/job schemas with canceled status and cancel metadata
  - [x] extend OpenAPI attempt/envelope schemas with classification/backoff/version metadata
  - [x] extend lifecycle CloudEvent contracts for retry/cancel metadata
- [x] Add regression coverage:
  - [x] graph tests for retry policy normalization/backoff
  - [x] graph tests for report-contract compatibility detection
  - [x] API tests for sync retry, async retry/backoff metadata, and async cancellation

### Program tracks with exit criteria
- [ ] Track: execution control
  - Exit criteria:
  - retry/cancel are available for all durable report runs
  - attempt classification is stable and emitted in history/events
  - cancellation propagates to linked jobs and leaves no ambiguous terminal state
  - retry policy is visible in run summaries, attempts, and lifecycle payloads
- [ ] Track: contract governance
  - Exit criteria:
  - report registries generate one machine-readable contract catalog
  - section-envelope and benchmark-pack changes are compatibility-checked in CI
  - generated docs/examples are derived from the same canonical registry source
  - report-definition drift is visible before merge
- [ ] Track: section telemetry / provenance
  - Exit criteria:
  - each section exposes duration and partial-failure semantics
  - each section exposes claim/evidence/source counts
  - each section can link back to graph lineage IDs without bespoke handler logic
  - section truncation/cache status is explicit in run artifacts
- [ ] Track: storage / retention policy
  - Exit criteria:
  - snapshot retention is configurable by report family
  - expiration/sweeping is automated
  - integrity verification exists for persisted snapshots
  - storage tier migration and metadata-only downgrade paths are defined and tested

## Deep Review Cycle 20 - Report History Resources + Lineage/Storage Semantics + Contract Registries (2026-03-09)

### Review findings
- [x] Gap: `ReportRun` persistence existed, but there was no first-class way to inspect execution-attempt history or lifecycle history as durable resources.
- [x] Gap: runs and snapshots carried structural metadata, but they still lacked explicit graph lineage and storage/retention semantics needed for replay, audit, and report portability.
- [x] Gap: typed section envelopes and benchmark packs were implied by report definitions, but the platform still lacked discoverable registries for those contracts.
- [x] Gap: OpenAPI had typed report definitions and run resources, but not explicit typed components for envelope families, benchmark-pack families, attempt history, or event history.
- [x] Gap: the backlog was still describing contract registries and lineage metadata as future work even though they had become the next gating primitive for deeper report extensibility.

### Research synthesis to adopt
- [x] OpenMetadata result-history pattern: definitions, parameterized runs, attempt history, and lifecycle output should stay as distinct resources with stable IDs and typed retrieval contracts.
- [x] PROV-O derivation pattern: every derived report artifact should carry graph lineage, execution timestamps, and retention/storage semantics rather than collapsing provenance into flat event payloads.
- [x] OpenLineage facet discipline: extension registries should publish stable schema names/URLs so downstream generated tools can bind contracts without depending on handler-local conventions.
- [x] Backstage task-history rule: execution history should be inspectable directly instead of inferred from webhook traces or job state alone.

### Execution plan
- [x] Add durable execution-history resources:
  - [x] add `ReportRunAttempt`
  - [x] add `ReportRunEvent`
  - [x] persist attempts/events alongside report runs
  - [x] add `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/attempts`
  - [x] add `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/events`
- [x] Add lineage/storage semantics to runs and snapshots:
  - [x] add `graph_snapshot_id`
  - [x] add `graph_built_at`
  - [x] add `graph_schema_version`
  - [x] add `ontology_contract_version`
  - [x] add `report_definition_version`
  - [x] add `storage_class`
  - [x] add `retention_tier`
  - [x] add `materialized_result_available`
  - [x] add `result_truncated`
- [x] Add discoverable contract registries:
  - [x] add section-envelope registry helpers
  - [x] add benchmark-pack registry helpers
  - [x] add `GET /api/v1/platform/intelligence/section-envelopes`
  - [x] add `GET /api/v1/platform/intelligence/section-envelopes/{envelope_id}`
  - [x] add `GET /api/v1/platform/intelligence/benchmark-packs`
  - [x] add `GET /api/v1/platform/intelligence/benchmark-packs/{pack_id}`
- [x] Tighten typed contract surface:
  - [x] extend `PlatformReportDefinition` with report-definition version and section benchmark/envelope bindings
  - [x] add typed OpenAPI schemas for attempts/events/lineage/storage
  - [x] add concrete OpenAPI schema components for envelope families and benchmark-pack families
  - [x] extend lifecycle CloudEvent contract docs for the deeper report metadata
- [x] Add regression coverage:
  - [x] graph-level lineage/storage helper tests
  - [x] graph-level contract-registry tests
  - [x] graph-level persistence round-trip coverage for attempts/events/lineage/storage
  - [x] API-level registry endpoint coverage
  - [x] API-level attempt/event resource coverage
  - [x] API-level restart persistence coverage for report history resources

### Detailed follow-on backlog
- [ ] Add section-level execution telemetry:
  - [ ] per-section duration
  - [ ] per-section cache hit/miss
  - [ ] per-section evidence/claim/source counts
  - [ ] per-section lineage refs to claim/evidence/source IDs
  - [ ] per-section partial-failure status and truncation semantics
- [ ] Add stronger contract-generation and compatibility gates:
  - [ ] derive section-envelope registries from one canonical schema source instead of duplicating JSON Schema fragments
  - [x] generate benchmark-pack docs/examples from registry definitions
  - [x] add CI compatibility checks for envelope schema evolution
  - [x] add CI compatibility checks for benchmark-pack threshold changes
  - [ ] generate report-definition diffs when measure/check/section contracts drift
- [ ] Deepen reusable benchmark semantics:
  - [ ] support benchmark inheritance and overrides
  - [ ] support benchmark scope families (`platform`, `security`, `org`, `admin`)
  - [ ] add rationale/citation metadata per band
  - [ ] add provenance for benchmark sources and approval history
  - [ ] attach benchmark outcomes to generated recommendations
- [ ] Deepen report-run storage policy:
  - [ ] snapshot expiration sweeper
  - [ ] storage-tier migration path beyond local filesystem
  - [ ] configurable retention by report family
  - [ ] metadata-only downgrade path for old snapshots
  - [ ] integrity verification and repair for missing snapshot payloads
- [ ] Deepen graph/report coupling where it creates actual leverage:
  - [ ] materialize report runs and snapshots as graph workflow/artifact nodes
  - [ ] link report sections to supporting claims/evidence/source nodes
  - [ ] link accepted recommendations to `action` and `decision` writes
  - [ ] materialize benchmark-band results as annotations/outcomes when useful
  - [ ] expose report-to-graph derivation chains in query/simulation flows
- [ ] Add richer report package composition:
  - [ ] reusable report packs bundling definitions + benchmark packs + extension defaults
  - [ ] report family manifests for `platform`, `security`, and `org`
  - [ ] generated SDK bindings for report registries and run resources
  - [ ] stable section rendering hints separate from UI implementation details
  - [ ] typed report export formats with snapshot references and integrity hashes

## Deep Review Cycle 19 - Durable Report Runs + Lifecycle Events + Typed Section Metadata (2026-03-09)

### Review findings
- [x] Gap: `ReportRun` had become a real platform resource, but its state still lived only in process memory, which made report execution history non-durable across restarts.
- [x] Gap: report snapshots were modeled, but the platform lacked a concrete persistence split between lightweight run metadata and heavier materialized result payloads.
- [x] Gap: report execution had no lifecycle event stream, which left downstream automation and audit flows blind to queued, started, completed, failed, and snapshot-materialized transitions.
- [x] Gap: section summaries described content shape only loosely; they still needed typed envelope hints and stable field-key capture to support stronger autogeneration and UI/tool composition.
- [x] Gap: the previous execution backlog in this file still treated persistence and lifecycle events as future work even though they had become the next structural constraint on report extensibility.

### Research synthesis to adopt
- [x] Backstage Scaffolder task model: execution resources should have durable identifiers, retrievable status, and step/status metadata rather than transient handler-local state.
- [x] OpenMetadata test definition / test case split: typed definitions, instantiated parameterized executions, and execution history should stay separate resources with tight schemas.
- [x] OpenLineage custom-facet rule: report lifecycle enrichments should remain schema-identifiable and namespaced instead of growing unbounded opaque payload maps.
- [x] PROV-O derivation rule: report runs and snapshots are derived artifacts and should carry explicit execution, recording, and retention metadata.

### Execution plan
- [x] Persist report-run state durably:
  - [x] Add `internal/graph/report_run_store.go`.
  - [x] Persist report-run metadata atomically to a platform state file.
  - [x] Persist materialized report results separately as compressed snapshot payload artifacts.
  - [x] Restore persisted runs and snapshot payloads when the API server starts.
  - [x] Add config paths for report-run state and snapshot storage.
- [x] Emit report lifecycle events:
  - [x] Add webhook/CloudEvent types for `platform.report_run.queued`.
  - [x] Add webhook/CloudEvent types for `platform.report_run.started`.
  - [x] Add webhook/CloudEvent types for `platform.report_run.completed`.
  - [x] Add webhook/CloudEvent types for `platform.report_run.failed`.
  - [x] Add webhook/CloudEvent types for `platform.report_snapshot.materialized`.
  - [x] Extend generated lifecycle contracts to cover the new events.
- [x] Tighten section result metadata:
  - [x] Add `envelope_kind` to `ReportSectionResult`.
  - [x] Add `field_keys` capture for object-backed section content.
  - [x] Update OpenAPI to expose the stronger section contract.
- [x] Add restart and lifecycle regression coverage:
  - [x] Add graph-level persistence round-trip tests.
  - [x] Add API-level restart recovery tests.
  - [x] Add API-level lifecycle event emission tests.

### Detailed follow-on backlog
- [ ] Add report execution-history resources:
  - [ ] `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/events`
  - [ ] `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/attempts`
  - [ ] `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:retry`
  - [ ] `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:cancel`
  - [ ] classify attempts as `transient`, `deterministic`, `cancelled`, or `superseded`
  - [ ] store per-attempt execution host, actor, and triggering surface metadata
- [ ] Add deeper execution metadata to `ReportRun` and `ReportSnapshot`:
  - [ ] `graph_snapshot_id`
  - [ ] `graph_schema_version`
  - [ ] `ontology_contract_version`
  - [ ] `report_definition_version`
  - [ ] `storage_class` / retention tier
  - [ ] `materialized_result_available` / `result_truncated`
- [ ] Add section-level execution telemetry:
  - [ ] per-section duration
  - [ ] per-section cache hit/miss metadata
  - [ ] per-section evidence/claim/source counts
  - [ ] per-section partial-failure reporting
  - [ ] per-section provenance edge materialization into the graph
- [ ] Deepen typed section envelope infrastructure:
  - [ ] publish JSON Schema for each `envelope_kind`
  - [ ] add `network_slice`, `recommendations`, `evidence_list`, and `narrative_block` envelope contracts
  - [ ] add envelope compatibility checks in CI
  - [ ] add explicit section rendering hints separate from measure semantics
- [ ] Add reusable dimensions and benchmark packs:
  - [ ] dimensions registry with stable IDs and value types
  - [ ] benchmark pack registry with threshold bands and rationale
  - [ ] benchmark overlays by application family (`security`, `org`, `admin`)
  - [ ] support benchmark inheritance and overrides
  - [ ] attach benchmark provenance to report recommendations
- [ ] Add a deeper reusable measure registry:
  - [ ] canonical aggregation semantics (`sum`, `avg`, `latest`, `rate`, `percentile`)
  - [ ] confidence/freshness qualifiers
  - [ ] dimensional compatibility rules
  - [ ] graph evidence/claim/source lineage hints
  - [ ] machine-readable measure compatibility rules for generated tools/UI
- [ ] Add a deeper reusable check/assertion registry:
  - [ ] parameter schemas
  - [ ] rationale and remediation templates
  - [ ] history/trend storage
  - [ ] waiver/suppression model with expiry and actor attribution
  - [ ] recommendation-generation hooks and benchmark bindings
- [ ] Add report-run retention and storage policy:
  - [ ] expiration sweeper for persisted snapshots
  - [ ] retention rules by report family and tenant
  - [ ] materialized-result compaction for older runs
  - [ ] stale-run detection for abandoned async executions
  - [ ] storage migration path beyond local filesystem state
- [ ] Deepen graph/report coupling where it creates real leverage:
  - [ ] link report runs to graph snapshots and graph mutation lineage
  - [ ] link section outputs to supporting claims/evidence/source nodes
  - [ ] expose source trust and freshness decay as reusable measures
  - [ ] materialize contradiction-aging and supportability trends
  - [ ] reify high-value report recommendations into actions/decisions when operators accept them
- [ ] Expand autogeneration around the report substrate:
  - [ ] generate report-section envelope schemas
  - [ ] generate benchmark-pack catalogs
  - [ ] generate report compatibility diff summaries
  - [ ] generate lifecycle-event docs/examples for report executions
  - [ ] generate starter report-definition templates for new application families

## Deep Review Cycle 18 - Report Runs + Measure/Check Registries + Platform Query Parity (2026-03-09)

### Review findings
- [x] Gap: the report registry described reports, but the platform still lacked instantiated report-run resources with durable IDs, typed parameter bindings, and snapshot metadata.
- [x] Gap: reusable measures and checks were present only as fields inside report definitions, which made downstream autogeneration and threshold-pack reuse harder than necessary.
- [x] Gap: the last legacy graph-read seam still existed in `/api/v1/graph/query*`, even though the platform transition had already established `/api/v1/platform/*` as the shared primitive namespace.
- [x] Gap: platform-intelligence execution was still implicitly governed by read permissions, even though report-run creation is an execution surface and should carry its own capability.
- [x] Gap: the report extensibility research still needed sharper execution-resource guidance drawn from real task/run models in Backstage and definition/case/result separation in OpenMetadata.

### Research synthesis to adopt
- [x] Backstage Scaffolder task pattern: long-running derived work should be addressable as task/run resources with durable IDs and follow-up retrieval URLs.
- [x] OpenMetadata definition/case/result pattern: definitions, parameterized instances, and execution results should remain separate resources with typed parameter contracts.
- [x] OpenLineage facet pattern: extension payloads should remain schema-identifiable and versioned rather than free-form enrichment maps.
- [x] PROV-O derivation pattern: report runs and report snapshots should be treated as derived artifacts with explicit execution and recording timestamps.

### Execution plan
- [x] Add executable report-run resources:
  - [x] Add `GET /api/v1/platform/intelligence/reports/{id}/runs`.
  - [x] Add `POST /api/v1/platform/intelligence/reports/{id}/runs`.
  - [x] Add `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}`.
  - [x] Store run status, execution mode, requested-by identity, typed parameters, time-slice extraction, cache key, linked job, section summaries, and result payload.
  - [x] Add snapshot metadata with content hash, result schema, generated/recorded timestamps, and section count.
- [x] Add reusable registry discovery surfaces:
  - [x] Add `GET /api/v1/platform/intelligence/measures`.
  - [x] Add `GET /api/v1/platform/intelligence/checks`.
  - [x] Deduplicate reusable measures/checks across built-in report definitions.
- [x] Finish platform graph read parity:
  - [x] Add `GET /api/v1/platform/graph/queries`.
  - [x] Add `GET /api/v1/platform/graph/templates`.
  - [x] Remove `/api/v1/graph/query`.
  - [x] Remove `/api/v1/graph/query/templates`.
  - [x] Move affected tests to the platform surface.
- [x] Tighten auth for report execution:
  - [x] Add `platform.intelligence.run`.
  - [x] Route `POST /api/v1/platform/intelligence/reports/{id}/runs` through the new execution capability.
  - [x] Extend role defaults and implication rules.
- [x] Update docs and contract surfaces:
  - [x] Update OpenAPI for report runs, measure/check catalogs, platform graph GET parity, and report endpoint execution metadata.
  - [x] Update report extensibility and intelligence docs to distinguish definitions from runs.
  - [x] Record the deeper execution backlog below.

### Detailed follow-on backlog
- [x] Persist report runs beyond process memory:
  - [x] back runs with durable storage instead of in-memory maps
  - [ ] support retention tiers by report family and tenant
  - [ ] add explicit snapshot expiry/reaping behavior
  - [ ] make cache invalidation depend on graph snapshot/version and schema version
- [ ] Add report-run execution history surfaces:
  - [ ] `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}/events`
  - [ ] `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:retry`
  - [ ] `POST /api/v1/platform/intelligence/reports/{id}/runs/{run_id}:cancel`
  - [ ] per-section timing and failure telemetry
  - [ ] retryability classification for transient vs deterministic failures
- [x] Add report lifecycle events:
  - [x] `platform.report_run.queued`
  - [x] `platform.report_run.started`
  - [x] `platform.report_run.completed`
  - [x] `platform.report_run.failed`
  - [x] `platform.report_snapshot.materialized`
- [ ] Add typed section result envelopes:
  - [x] `summary`
  - [ ] `timeseries`
  - [x] `distribution`
  - [x] `ranking`
  - [ ] `network_slice`
  - [ ] `recommendations`
  - [ ] `evidence_list`
  - [ ] `narrative_block`
- [ ] Add a deeper reusable measure registry:
  - [ ] canonical aggregation semantics (`sum`, `avg`, `latest`, `rate`, `percentile`)
  - [ ] confidence/freshness qualifiers
  - [ ] benchmark bands and threshold packs
  - [ ] dimensional compatibility rules
  - [ ] provenance hints back to graph evidence/claims
- [ ] Add a deeper reusable check/assertion registry:
  - [ ] parameter schemas
  - [ ] rationale and remediation templates
  - [ ] history/trend storage
  - [ ] suppression/waiver model with expiry
  - [ ] recommendation-generation hooks
- [ ] Add extension contract infrastructure:
  - [ ] schema URLs on extension payloads
  - [ ] compatibility checks for extension-schema drift
  - [ ] namespaced ownership/approval workflow
  - [ ] generated JSON Schema catalog for extensions
- [ ] Deepen the report authoring substrate:
  - [ ] explicit dimensions registry
  - [ ] benchmark overlays
  - [ ] threshold packs by domain/application
  - [ ] section composition presets for security/org/admin consumers
  - [ ] report-definition versioning and compatibility rules
- [ ] Move more heavy analysis/report work onto the execution substrate:
  - [ ] provider sync jobs
  - [ ] graph rebuild jobs
  - [ ] large simulation jobs
  - [ ] cross-tenant pattern build jobs
  - [ ] scheduled report materialization jobs
- [ ] Deepen graph/report coupling where it creates real leverage:
  - [ ] report section provenance edges to claims/evidence/source nodes
  - [ ] source trust scoring and freshness decay inputs exposed as reusable measures
  - [ ] contradiction-aging and supportability trend measures
  - [ ] report-ready relationship reification where lifecycle/evidence matters
  - [ ] graph snapshot lineage linked to report snapshots

## Deep Review Cycle 17 - Report Definition Registry + Extensibility Research + Alias Pruning (2026-03-09)

### Review findings
- [x] Gap: report payloads existed, but there was no discoverable report-definition registry exposing reusable sections, measures, checks, and extension points.
- [x] Gap: org/security dynamics were correctly moving into the derived report layer, but the system still lacked a concrete composition model for those reports.
- [x] Gap: existing intelligence endpoints were typed at the payload level, but not at the report-definition level, making autogeneration and UI/tool composition harder than necessary.
- [x] Gap: compatibility aliases remained for intelligence, claim/decision writeback, and org report routes even though there are no current API consumers to justify carrying them.
- [x] Gap: report architecture guidance was spread across world-model and intelligence docs without a dedicated research-backed extensibility document.

### Research synthesis to adopt
- [x] RDF Data Cube pattern: keep report `dimensions`, `measures`, and qualifying attributes distinct.
- [x] PROV-O pattern: treat report runs and sections as derived artifacts with explicit provenance.
- [x] OpenLineage pattern: use namespaced, schema-backed extension points instead of untyped extension blobs.
- [x] DataHub pattern: model checks/assertions separately from run history and use module-based summary surfaces.
- [x] OpenMetadata pattern: keep metric and test-definition registries typed and parameterized with `additionalProperties: false`.
- [x] Backstage/Roadie pattern: keep scorecards over shared facts instead of proliferating new product-specific primitives.

### Execution plan
- [x] Document the report extensibility architecture:
  - [x] Add `docs/GRAPH_REPORT_EXTENSIBILITY_RESEARCH.md`.
  - [x] Link it from the core architecture and intelligence/world-model docs.
  - [x] Define the target report substrate: `ReportDefinition`, `ReportParameter`, `ReportMeasure`, `ReportSection`, `ReportCheck`, `ReportExtensionPoint`, `ReportRun`, `ReportSnapshot`.
- [x] Add the first discoverable report registry surface:
  - [x] Add built-in report definitions for `insights`, `quality`, `metadata-quality`, `claim-conflicts`, `leverage`, and `calibration-weekly`.
  - [x] Add `GET /api/v1/platform/intelligence/reports`.
  - [x] Add `GET /api/v1/platform/intelligence/reports/{id}`.
  - [x] Add handler tests and OpenAPI schemas for the report-definition registry.
- [x] Prune alias baggage where exact replacements already exist:
  - [x] Remove `/api/v1/graph/intelligence/*` compatibility aliases.
  - [x] Remove `/api/v1/graph/write/claim` and `/api/v1/graph/write/decision`.
  - [x] Remove `/api/v1/graph/who-knows`, `/api/v1/graph/recommend-team`, and `/api/v1/graph/simulate-reorg`.
  - [x] Move affected tests/docs to `/api/v1/platform/*` and `/api/v1/org/*` routes only.

### Detailed follow-on backlog
- [x] Add `ReportRun` resources:
  - [x] `POST /api/v1/platform/intelligence/reports/{id}/runs`
  - [x] `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}`
  - [x] Store run scope, bitemporal slice, provenance, status, cache metadata, and section-level execution details.
- [ ] Add section result envelopes:
  - [ ] `summary`
  - [ ] `timeseries`
  - [ ] `distribution`
  - [ ] `ranking`
  - [ ] `network_slice`
  - [ ] `recommendations`
  - [ ] `evidence_list`
- [ ] Add a reusable measure registry:
  - [x] discovery endpoint + deduplicated built-in catalog
  - [ ] canonical IDs
  - [ ] value types
  - [ ] units
  - [ ] aggregation semantics
  - [ ] freshness/confidence attributes
  - [ ] benchmark metadata
- [ ] Add a reusable check/assertion registry:
  - [x] discovery endpoint + deduplicated built-in catalog
  - [ ] stable check IDs and severities
  - [ ] parameter schemas
  - [ ] rationale and remediation templates
  - [ ] run history and trend storage
  - [ ] recommendation generation hooks
- [ ] Add namespaced report extension contracts:
  - [ ] schema URLs for extension payloads
  - [ ] compatibility checks for extension schema changes
  - [ ] validation at report-definition registration time
- [ ] Add report autogeneration:
  - [ ] OpenAPI fragments
  - [ ] MCP/tool descriptors
  - [ ] docs pages/examples
  - [ ] JSON Schema catalogs
  - [ ] report lifecycle CloudEvents
- [ ] Add materialization and scheduling rules:
  - [ ] synchronous vs job-backed thresholds
  - [ ] report snapshot retention
  - [ ] cache invalidation on graph/version changes
  - [ ] scheduled refresh policies
- [ ] Add high-value report families over the shared graph:
  - [ ] identity trust and reviewer calibration
  - [ ] org dynamics and knowledge fragility
  - [ ] information-flow lag and coordination bottlenecks
  - [ ] privilege concentration and risky-configuration posture
  - [ ] decision closure and operating cadence
  - [ ] source trust and ingestion confidence
  - [ ] change risk and rollout readiness
- [ ] Deepen the graph data needed for those reports:
  - [ ] source trust scoring and freshness decay policy
  - [ ] richer document/context linkage into the graph
  - [ ] relationship reification where report logic needs lifecycle/evidence
  - [ ] bitemporal claim coverage SLOs and contradiction aging metrics

## Deep Review Cycle 16 - Platform Intelligence Contracts + Lifecycle Events + Scoped Auth (2026-03-09)

### Review findings
- [x] Gap: the new `/api/v1/platform/*` split existed for graph query and writeback aliases, but intelligence/report endpoints still lived primarily under legacy `/api/v1/graph/intelligence/*` paths.
- [x] Gap: the weekly calibration endpoint still returned an ad hoc map payload instead of a shared typed report model.
- [x] Gap: writeback flows recorded claims, decisions, outcomes, and actions without emitting first-class platform lifecycle events for downstream automation.
- [x] Gap: CloudEvents compatibility checks and generated docs covered mapper contracts, but not the newly added platform lifecycle event contracts.
- [x] Gap: auth scopes still centered on legacy security-first permissions instead of explicit `platform`, `security`, `org`, and `admin` capability families.
- [x] Gap: transition docs still needed a sharper rule that org/security dynamics belong primarily in derived reports over the shared metadata/context graph, not as new substrate primitives.

### Execution plan
- [x] Tighten the platform intelligence surface:
  - [x] Add concrete `/api/v1/platform/intelligence/*` OpenAPI paths for `insights`, `quality`, `metadata-quality`, `claim-conflicts`, `leverage`, and `calibration/weekly`.
  - [x] Keep `/api/v1/graph/intelligence/*` as deprecated compatibility aliases.
  - [x] Replace `additionalProperties: true` response contracts for those endpoints with typed report schemas.
  - [x] Add a typed `reports.WeeklyCalibrationReport` model and route handler output.
- [x] Add lifecycle event emission + contract hardening:
  - [x] Emit `platform.claim.written`, `platform.decision.recorded`, `platform.outcome.recorded`, and `platform.action.recorded` from writeback handlers.
  - [x] Add generated lifecycle event contract metadata under `internal/platformevents`.
  - [x] Extend CloudEvents docs generation and contract catalogs to include lifecycle events.
  - [x] Extend compatibility checks to detect breaking lifecycle contract changes without schema-version bumps.
  - [x] Add writeback tests that assert lifecycle event emission.
- [x] Move auth to namespace-scoped capability families:
  - [x] Add `platform.*`, `security.*`, `org.*`, and `admin.*` permissions to RBAC defaults.
  - [x] Add implication rules from legacy permissions to the new scoped permissions for compatibility.
  - [x] Update route-permission mapping and RBAC permission listing to reflect the new scope model.
  - [x] Add scoped RBAC tests.
- [x] Update docs and execution guidance:
  - [x] Update transition/world-model/intelligence docs to frame org/security dynamics as report-level views over the graph.
  - [x] Regenerate `docs/CLOUDEVENTS_AUTOGEN.md` and `docs/CLOUDEVENTS_CONTRACTS.json`.
  - [x] Record this cycle in `TODO.md`.

## Deep Review Cycle 15 - Platform Alias Execution + Org Route Extraction + First Job Resource (2026-03-09)

### Review findings
- [x] Gap: the transition architecture existed, but the router and OpenAPI still forced all shared primitives through legacy `/api/v1/graph/*` paths.
- [x] Gap: org-intelligence capabilities (`who-knows`, `recommend-team`, `simulate-reorg`) still lived under `/api/v1/graph/*`, reinforcing the false idea that graph namespace equals platform namespace.
- [x] Gap: legacy graph routes lacked runtime deprecation metadata, so compatibility aliases had no migration pressure.
- [x] Gap: the platform split had no concrete proof that a heavy operation could return an execution resource instead of a synchronous payload.
- [x] Gap: the transition doc still needed sharper classification for ambiguous analytics, stronger job rules, and explicit auth/deprecation/eventing sections.

### Execution plan
- [x] Add concrete platform and org aliases in code:
  - [x] Add `POST /api/v1/platform/graph/queries`.
  - [x] Add `POST /api/v1/platform/knowledge/claims`.
  - [x] Add `POST /api/v1/platform/knowledge/decisions`.
  - [x] Add `GET /api/v1/org/expertise/queries`.
  - [x] Add `POST /api/v1/org/team-recommendations`.
  - [x] Add `POST /api/v1/org/reorg-simulations`.
- [x] Add runtime deprecation metadata on selected legacy graph aliases:
  - [x] `/api/v1/graph/query`
  - [x] `/api/v1/graph/write/claim`
  - [x] `/api/v1/graph/write/decision`
  - [x] `/api/v1/graph/who-knows`
  - [x] `/api/v1/graph/recommend-team`
  - [x] `/api/v1/graph/simulate-reorg`
- [x] Add the first execution-resource proof point:
  - [x] Add `POST /api/v1/security/analyses/attack-paths/jobs`.
  - [x] Add `GET /api/v1/platform/jobs/{id}`.
  - [x] Back the new endpoints with an in-memory async job record for attack-path analysis.
- [x] Tighten the contract surface:
  - [x] Add `Platform` and `Security` tags in OpenAPI.
  - [x] Add typed schemas for platform graph query, platform claim write, platform decision write, platform jobs, attack-path job request, and reorg simulation request.
  - [x] Mark the selected legacy graph endpoints `deprecated: true` in OpenAPI.
- [x] Harden the transition doc:
  - [x] Reclassify ambiguous analytics (`impact-analysis`, `cohort`, `outlier-score`) as pending proof instead of auto-promoting them to platform primitives.
  - [x] Add explicit permission model, compatibility/deprecation policy, eventing model, and hidden-security-bias audit guidance.

## Deep Review Cycle 14 - Platform Transition Architecture + API Boundary Cleanup (2026-03-09)

### Review findings
- [x] Gap: `docs/ARCHITECTURE.md` still described Cerebro primarily as a security data platform instead of a graph platform with security as the first application.
- [x] Gap: the current OpenAPI exposes 189 `/api/v1/*` routes, with 61 `/api/v1/graph/*` routes that mix platform primitives, security workflows, and org-intelligence endpoints.
- [x] Gap: graph platform candidates, security application endpoints, org-intelligence endpoints, and admin/control-plane concerns are interleaved under shared namespaces.
- [x] Gap: historical drift created duplicate/alias surfaces (`/policy/evaluate`, top-level attack-path APIs, dual access-review APIs, dual sync surfaces).
- [x] Gap: too many platform-grade endpoints still use weak object contracts (`additionalProperties: true`) and lack consistent envelope/job conventions.
- [x] Gap: user-facing docs and OpenAPI descriptions still said "security graph" for shared graph substrate APIs.

### Execution plan
- [x] Produce a concrete platform transition architecture doc:
  - [x] Inventory current routes by platform, security, org, and admin layers.
  - [x] Diagnose bad abstractions, duplicates, and security-domain leakage.
  - [x] Define target namespace structure for `/api/v1/platform`, `/api/v1/security`, `/api/v1/org`, and `/api/v1/admin`.
  - [x] Define the canonical domain-agnostic platform model for entities, edges, evidence, claims, annotations, decisions, outcomes, actions, provenance, temporal semantics, identity, and schema modules.
  - [x] Map current security concepts into the generalized platform model.
  - [x] Provide endpoint reorganization, migration phases, and typed schema proposals.
- [x] Wire the transition plan into the main architecture docs:
  - [x] Add `docs/PLATFORM_TRANSITION_ARCHITECTURE.md`.
  - [x] Update `docs/ARCHITECTURE.md` to describe the platform-first direction and link the transition doc.
- [x] Reduce security-domain leakage in current user-facing platform contracts:
  - [x] Normalize shared graph endpoint terminology from "security graph" to "graph platform" in OpenAPI/user-facing graph messaging.
  - [x] Rename the router comment for shared graph endpoints to reflect platform ownership.

### Follow-on execution backlog
- [ ] Add new `/api/v1/platform/*` aliases backed by existing graph handlers, then mark legacy `/api/v1/graph/*` routes deprecated in OpenAPI.
- [ ] Move org-intelligence endpoints (`who-knows`, `recommend-team`, `simulate-reorg`) out of `/api/v1/graph/*` and into `/api/v1/org/*`.
- [ ] Collapse duplicate access-review surfaces onto `/api/v1/security/access-reviews/*`.
- [ ] Collapse duplicate policy-evaluation routes onto `/api/v1/security/policy-evaluations`.
- [ ] Convert provider sync, graph rebuild, attack-path analysis, and large simulation endpoints to explicit async job resources.
- [ ] Replace `additionalProperties: true` on the highest-value platform endpoints with typed request/response schemas and shared envelopes.

## Deep Review Cycle 13 - World Model Foundation + Claim Layer + Bitemporal Reasoning (2026-03-09)

### Review findings
- [x] Gap: the graph modeled entities and operational events well, but did not model facts as first-class claims.
- [x] Gap: provenance existed, but there was no durable `source` abstraction to separate “who asserted this” from the write path that stored it.
- [x] Gap: temporal semantics were fact-time heavy (`observed_at`, `valid_from`, `valid_to`) but lacked system-time fields for “when Cerebro learned this.”
- [x] Gap: no API write path existed for a proper claim/assertion workflow.
- [x] Gap: no intelligence surface existed for contradiction detection, unsupported claims, or sourceless claims.
- [x] Gap: ingest/runtime metadata normalization did not stamp bitemporal fields on declarative mapper writes.
- [x] Gap: architecture docs described ontology depth, but not the claim-first world-model target state.

### Execution plan
- [x] Add world-model ontology primitives:
  - [x] Add node kinds: `claim`, `source`, `observation`.
  - [x] Add edge kinds: `asserted_by`, `supports`, `refutes`, `supersedes`, `contradicts`.
  - [x] Register built-in schema contracts and required relationships for the new kinds.
- [x] Extend metadata contract to bitemporal writes:
  - [x] Add `recorded_at`, `transaction_from`, `transaction_to` to `graph.WriteMetadata`.
  - [x] Extend `NormalizeWriteMetadata(...)` defaults and property emission.
  - [x] Extend metadata profiles and timestamp validation to cover new fields.
- [x] Add bitemporal graph reads:
  - [x] Add `GetAllNodesBitemporal(...)`.
  - [x] Add `GetOutEdgesBitemporal(...)` / `GetInEdgesBitemporal(...)`.
  - [x] Add `SubgraphBitemporal(...)`.
- [x] Add first-class claim write flow:
  - [x] Add `graph.ClaimWriteRequest` / `graph.WriteClaim(...)`.
  - [x] Link claims to subjects, objects, sources, evidence, and superseding/supporting/refuting claims.
  - [x] Validate referenced entities before writes.
- [x] Add claim intelligence surface:
  - [x] Add `BuildClaimConflictReport(...)`.
  - [x] Detect contradictory active claims by `subject_id` + `predicate`.
  - [x] Track unsupported, sourceless, and stale-claim counts.
- [x] Expose runtime APIs:
  - [x] Add `POST /api/v1/graph/write/claim`.
  - [x] Add `GET /api/v1/graph/intelligence/claim-conflicts`.
  - [x] Add handler tests and route coverage.
- [x] Bring ingest up to the new metadata contract:
  - [x] Stamp `recorded_at` and `transaction_from` during declarative mapper writes.
  - [x] Extend mapper contract tests to assert bitemporal metadata presence.
  - [x] Normalize malformed fact-time inputs into safe metadata defaults rather than silently dropping writes.
- [x] Update architecture docs:
  - [x] Add `docs/GRAPH_WORLD_MODEL_ARCHITECTURE.md`.
  - [x] Update ontology/intelligence/architecture docs to describe the claim-first substrate.

## Deep Review Cycle 12 - Contract Versioning + Runtime Event Validation + Generated Schema Catalogs (2026-03-09)

### Review findings (external-pattern driven)
- [x] Gap: Backstage-style envelope contract versioning (`apiVersion` + kind-specific validation) was not present in declarative mapper config.
- [x] Gap: CloudEvents docs existed, but machine-readable contract artifacts (JSON catalog + per-event data schemas) were missing.
- [x] Gap: enforce-mode validation happened at node/edge write time only; event payload contract validation did not run before mapping.
- [x] Gap: OpenLineage facet learnings (`_producer`, `_schemaURL`) were not mapped into ingest metadata pointers on graph writes.
- [x] Gap: no API endpoint exposed generated ingest contracts for runtime introspection/automation.
- [x] Gap: no compatibility checker enforced version bumps for required data-key additions or enum tightening.
- [x] Gap: CI drift checks covered markdown catalogs but not machine-readable contracts.

### Execution plan
- [x] Introduce mapping contract/version surface:
  - [x] Extend mapper config with top-level `apiVersion`/`kind`.
  - [x] Extend per-mapping contract metadata: `apiVersion`, `contractVersion`, `schemaURL`, `dataEnums`.
  - [x] Add normalization defaults (`cerebro.graphingest/v1alpha1`, `MappingConfig`, `1.0.0`) in parser/runtime.
- [x] Build shared contract extraction in `internal/graphingest`:
  - [x] Add contract catalog model (`ContractCatalog`, `MappingContract`, envelope field contracts).
  - [x] Derive required/optional/resolve/context keys from mapping templates.
  - [x] Generate per-mapping JSON data schemas from template-derived required keys + enum constraints.
- [x] Add enforce-path runtime event validation:
  - [x] Validate required CloudEvent envelope fields (id/source/type/time) before mapping writes.
  - [x] Validate required data key presence and enum constraints against derived contracts.
  - [x] Validate optional `schema_version` and `dataschema` alignment when producer emits them.
  - [x] Reject + dead-letter whole event in enforce mode on contract mismatch (`invalid_event_contract`).
  - [x] Track event-level rejection counters and reject-code breakdowns in mapper stats.
- [x] Deepen node/edge metadata enrichment:
  - [x] Add ingest metadata pointers on writes:
    - [x] `source_schema_url`
    - [x] `producer_fingerprint`
    - [x] `contract_version`
    - [x] `contract_api_version`
    - [x] `mapping_name`
    - [x] `event_type`
- [x] Add generated machine-readable contracts:
  - [x] Extend CloudEvents generator to emit:
    - [x] `docs/CLOUDEVENTS_AUTOGEN.md` (human-readable)
    - [x] `docs/CLOUDEVENTS_CONTRACTS.json` (machine-readable)
  - [x] Add unit coverage for contract extraction and compatibility logic.
- [x] Add compatibility checker:
  - [x] Add `scripts/check_cloudevents_contract_compat/main.go`.
  - [x] Compare current contracts against baseline git ref (`HEAD^1`/`HEAD^`/`origin/main` fallback).
  - [x] Fail on required-key additions or enum tightening without major contract version bump.
- [x] Expose runtime contracts API:
  - [x] Add `GET /api/v1/graph/ingest/contracts`.
  - [x] Serve generated contract catalog from runtime mapper when initialized; fallback to default config.
  - [x] Add handler test + OpenAPI route contract.
- [x] Harden CI/Make guardrails:
  - [x] Extend `cloudevents-docs-check` to include both markdown + JSON contract artifacts.
  - [x] Add CI job `cloudevents-contract-compat`.
  - [x] Keep drift checks green for generated contract artifacts.
- [x] Update architecture/research docs:
  - [x] Add contract catalog references in architecture + ontology docs.
  - [x] Extend external-pattern doc with google-cloudevents catalog-generation learnings.

## Deep Review Cycle 11 - CloudEvents Contract Auto-Generation + Drift Guardrails (2026-03-09)

### Review findings
- [x] Gap: graph ontology had autogen docs, but CloudEvents + mapper contract surfaces were still implicit in code.
- [x] Gap: CI lacked generated-doc drift checks for event contract catalogs.
- [x] Gap: external-pattern learnings (CloudEvents envelope rigor, Backstage-style contract visibility) were not reflected in generated artifacts.

### Execution plan
- [x] Add CloudEvents contract autogen:
  - [x] Add `scripts/generate_cloudevents_docs/main.go`.
  - [x] Generate `docs/CLOUDEVENTS_AUTOGEN.md` from `internal/events.CloudEvent` + `internal/graphingest/mappings.yaml`.
  - [x] Extract template-derived required/optional data keys per mapping and identity `resolve(...)` usage.
- [x] Add guardrails:
  - [x] Add `make cloudevents-docs` and `make cloudevents-docs-check`.
  - [x] Add CI job `cloudevents-docs-drift` in `.github/workflows/ci.yml`.
- [x] Add coverage tests:
  - [x] Add script unit tests for template normalization and mapping contract extraction.
- [x] Update architecture/intelligence docs to link CloudEvents autogen catalog.

## Deep Review Cycle 10 - Metadata Profiles + Metadata Quality Intelligence + External Pattern Benchmarking (2026-03-09)

### Review findings
- [x] Gap: ontology schema validated required properties but lacked first-class metadata profile contracts (required metadata keys, enum constraints, timestamp validation) per kind.
- [x] Gap: schema health did not expose dedicated metadata issue classes, making metadata drift hard to prioritize.
- [x] Gap: no dedicated intelligence API existed for metadata profile coverage and per-kind metadata quality.
- [x] Gap: ontology autogen docs did not include metadata profile matrices.
- [x] Gap: external project design patterns were not captured in one benchmark-to-implementation doc.

### Execution plan
- [x] Add metadata profile contract surface in schema registry:
  - [x] Add `NodeMetadataProfile` to `NodeKindDefinition`.
  - [x] Add new schema issue codes for metadata gaps (`missing_metadata_key`, `invalid_metadata_enum`, `invalid_metadata_timestamp`).
  - [x] Extend node validation with metadata profile checks.
  - [x] Extend normalization/merge/clone/compatibility-warning logic for metadata profiles.
- [x] Deepen built-in ontology metadata enrichment:
  - [x] Add metadata profiles to core operational/decision kinds.
  - [x] Add canonical enum constraints for high-variance fields (`status`, `state`, `severity`, `verdict`, etc.).
  - [x] Validate temporal metadata keys as RFC3339 timestamps.
- [x] Improve metadata observability/intelligence:
  - [x] Extend schema health report with metadata issue breakdowns and recommendations.
  - [x] Add `BuildGraphMetadataQualityReport(...)` with per-kind rollups.
  - [x] Add `GET /api/v1/graph/intelligence/metadata-quality` endpoint + tests + OpenAPI contract.
- [x] Expand auto-generated ontology docs:
  - [x] Extend `scripts/generate_graph_ontology_docs/main.go` to emit node metadata profile matrix.
  - [x] Regenerate `docs/GRAPH_ONTOLOGY_AUTOGEN.md`.
- [x] Capture external benchmark research via GH CLI:
  - [x] Add `docs/GRAPH_ONTOLOGY_EXTERNAL_PATTERNS.md` covering OpenLineage, DataHub, OpenMetadata, Backstage, and CloudEvents learnings.
  - [x] Link benchmark doc from architecture/ontology docs.

## Deep Review Cycle 9 - Ontology Auto-Generation + CI/CD Runtime Ontology Depth (2026-03-09)

### Review findings
- [x] Gap: graph ontology docs were narrative-only and not machine-regenerated from schema/mappings.
- [x] Gap: CI lacked a drift check for generated ontology catalog artifacts.
- [x] Gap: CI/CD ingestion events still collapsed execution semantics and lacked dedicated `pipeline_run` / `check_run` kinds.

### Execution plan
- [x] Add ontology auto-generation:
  - [x] Add `scripts/generate_graph_ontology_docs/main.go`.
  - [x] Generate `docs/GRAPH_ONTOLOGY_AUTOGEN.md` from registered schema + mapper config.
  - [x] Add `make ontology-docs` and `make ontology-docs-check`.
  - [x] Add CI job `ontology-docs-drift` to enforce generated doc freshness.
- [x] Deepen CI/CD ontology:
  - [x] Add node kinds `pipeline_run` and `check_run` with schema contracts.
  - [x] Add mappings `github_check_run_completed` and `ci_pipeline_completed`.
  - [x] Extend schema + mapper contract fixtures/tests for new kinds.
  - [x] Update ontology architecture/intelligence docs for new operational node kinds.

## Deep Review Cycle 8 - Source SLOs + Weekly Calibration + Queryable DLQ + Burn-Rate Guardrails (2026-03-09)

### Review findings
- [x] Gap: ingest health reported only aggregate mapper counters without per-source SLO posture.
- [x] Gap: replay CLI had no durable checkpoint/resume semantics for incremental dead-letter drain workflows.
- [x] Gap: dead-letter backend was JSONL-only with no queryable storage option for focused triage.
- [x] Gap: ontology SLO health checks used static thresholds without fast/slow burn-rate indicators.
- [x] Gap: no dedicated weekly calibration endpoint unified risk-feedback backtest, identity calibration, and ontology trend context.
- [x] Gap: CI lacked explicit source-domain ontology guardrail and replay dry-run checks.
- [x] Gap: enforce-mode mapper validation was schema-only and did not strictly validate provenance integrity fields.

### Execution plan
- [x] Add ingest per-source SLO reporting:
  - [x] Extend mapper runtime stats with `source_stats`.
  - [x] Add source-level match/reject/dead-letter SLO rollups to `/api/v1/graph/ingest/health`.
- [x] Add replay checkpoint + resume:
  - [x] Extend `cerebro ingest replay-dead-letter` with `--checkpoint-path` and `--resume`.
  - [x] Persist processed event keys and resume safely across runs.
- [x] Add queryable DLQ backend and query surface:
  - [x] Add sqlite dead-letter sink backend and auto-select by DLQ path.
  - [x] Add backend-aware inspect/stream/query helpers.
  - [x] Add `GET /api/v1/graph/ingest/dead-letter`.
- [x] Improve ontology alerting with burn-rate signals:
  - [x] Add fast/slow burn-rate evaluation on fallback and schema-valid SLO budgets.
  - [x] Include burn-rate alerts in health-check degradation/unhealthy transitions.
- [x] Add weekly calibration API:
  - [x] Add `GET /api/v1/graph/intelligence/calibration/weekly`.
  - [x] Return risk-feedback weekly backtest slice + identity calibration + ontology trend.
- [x] Strengthen CI guardrails:
  - [x] Add mapper ontology guardrail job by source domain.
  - [x] Add ingest replay dry-run CI job with JSON summary assertion.
- [x] Strengthen enforce-path provenance checks:
  - [x] Reject invalid temporal/provenance metadata in enforce mode (`source_system`, `source_event_id`, `observed_at`, `valid_from`, `valid_to`, `confidence`).
  - [x] Emit `invalid_provenance` issue code for mapper rejection accounting and DLQ triage.

## Deep Review Cycle 7 - Ingest Observability + Replay + Ontology Alerting (2026-03-09)

### Review findings
- [x] Gap: no dedicated API surface exposed event mapper rejection counters plus dead-letter tail quality.
- [x] Gap: dead-letter records were difficult to replay after ontology/mapping fixes.
- [x] Gap: ontology SLO regressions had no explicit health thresholds for automated alerting.
- [x] Gap: generated config docs skipped float-based env readers, excluding new threshold settings.

### Execution plan
- [x] Add graph ingest health API:
  - [x] Register `GET /api/v1/graph/ingest/health`.
  - [x] Return mapper initialization state, validation mode, dead-letter path, and runtime stats.
  - [x] Return bounded dead-letter tail metrics (`tail_limit`) with issue/entity/event distributions.
  - [x] Add handler tests + OpenAPI contract updates.
- [x] Add dead-letter replay foundations:
  - [x] Extend dead-letter records with replay-safe event payload metadata (`event_time`, `event_data`, etc.).
  - [x] Add `StreamDeadLetter(...)` and `InspectDeadLetterFile(...)` helpers with tests.
  - [x] Add CLI command `cerebro ingest replay-dead-letter` with dedupe, limit controls, and replay outcome summary.
- [x] Add ontology SLO health thresholds:
  - [x] Add config/env controls:
    - [x] `GRAPH_ONTOLOGY_FALLBACK_WARN_PERCENT`
    - [x] `GRAPH_ONTOLOGY_FALLBACK_CRITICAL_PERCENT`
    - [x] `GRAPH_ONTOLOGY_SCHEMA_VALID_WARN_PERCENT`
    - [x] `GRAPH_ONTOLOGY_SCHEMA_VALID_CRITICAL_PERCENT`
  - [x] Register `graph_ontology_slo` health check with healthy/degraded/unhealthy transitions.
  - [x] Add focused tests for threshold evaluation and health-check behavior.
- [x] Refresh generated config env var docs:
  - [x] Regenerate `docs/CONFIG_ENV_VARS.md` to keep CI drift checks green.

## Deep Review Cycle 6 - Ingestion Hardening + Activity Migration + Ontology SLOs (2026-03-09)

### Review findings
- [x] Gap: declarative mapper lacked strict ontology rejection controls and per-write dead-letter persistence.
- [x] Gap: legacy `activity` nodes persisted in historical graphs with no one-time canonical migration flow.
- [x] Gap: runtime fallback for `ensemble.tap.activity.*` overused generic `activity` kind for known domains.
- [x] Gap: leverage reporting lacked explicit ontology SLOs and trend samples for canonical coverage and schema-valid writes.
- [x] Gap: mapper regressions across TAP domains relied on ad-hoc tests instead of fixture-driven contracts.
- [x] Gap: actuation readiness lacked action-to-outcome completion/latency/staleness metrics.

### Execution plan
- [x] Strict mapper validation + dead-letter + counters:
  - [x] Add `MapperValidationMode` (`enforce`/`warn`) and enforce-mode defaults.
  - [x] Add JSONL dead-letter sink for rejected node/edge writes.
  - [x] Add mapper runtime stats and rejection counters by schema issue code.
  - [x] Wire app config/env controls:
    - [x] `GRAPH_EVENT_MAPPER_VALIDATION_MODE`
    - [x] `GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH`
- [x] Historical activity migration:
  - [x] Add graph migrator to rewrite legacy `activity` nodes to canonical kinds when inferable.
  - [x] Fallback uncertain records to `action` with explicit review tags.
  - [x] Add optional startup toggle `GRAPH_MIGRATE_LEGACY_ACTIVITY_ON_START`.
- [x] Runtime fallback canonicalization:
  - [x] Route known activity sources/types to canonical kinds (`action`, `meeting`, `document`, etc.).
  - [x] Keep generic `activity` only for unknown/unstructured sources.
  - [x] Use `targets` edge semantics from canonical activity nodes to target entities.
- [x] Leverage ontology SLOs + trends:
  - [x] Add ontology section to leverage report with canonical coverage, fallback share, schema-valid write percent, and daily trend samples.
  - [x] Add ontology-aware recommendations for fallback overuse and schema conformance drift.
- [x] Contract fixtures:
  - [x] Add fixture file `internal/graphingest/testdata/mapper_contracts.json`.
  - [x] Add fixture-driven contract test covering TAP source families (github, incident, slack, jira, ci, calendar, docs, support, sales).
- [x] Action efficacy:
  - [x] Add actuation metrics for `actions_with_outcomes`, completion rate, median outcome latency, and stale actions without outcomes.
  - [x] Add recommendation logic for poor action-to-outcome closure.

## Deep Review Cycle 5 - Residual Activity Mapper Canonicalization (2026-03-09)

### Review findings
- [x] Gap: declarative TAP mappings still emitted generic `activity` nodes for Slack message, support ticket update, and sales call events.
- [x] Gap: mapper tests did not pin canonical kind output for those domains, allowing regression back to ambiguous kinds.
- [x] Gap: ontology architecture doc did not explicitly state that generic `activity` should be fallback-only.

### Execution plan
- [x] Migrate residual declarative mappings away from `activity`:
  - [x] `slack_thread_message`: convert per-message node to `action`.
  - [x] `support_ticket_updated`: convert update node to `action`.
  - [x] `sales_call_logged`: convert call node to `action`.
- [x] Extend mapper tests for canonical-kind enforcement:
  - [x] Assert support update writes `action:support_update:*` as `NodeKindAction`.
  - [x] Add Slack mapping test for `action:slack_message:*` output.
  - [x] Add sales call mapping test for `action:sales_call:*` output.
- [x] Update ontology architecture guidance to mark `activity` as fallback-only for unknown/unstructured ingestion paths.

## Deep Review Cycle 4 - Ontology Depth + Metadata Consistency + Architecture Docs (2026-03-09)

### Review findings
- [x] Gap: operational event domains were still overusing generic `activity` nodes in declarative mappings.
- [x] Gap: metadata normalization logic was duplicated across API/tool writeback paths and graph actuation.
- [x] Gap: ontology architecture guidance was split across implementation and narrative docs without one extension contract.
- [x] Gap: complex scoring/prioritization logic lacked inline rationale comments for future calibration.

### Execution plan
- [x] Deepen ontology kinds for operational intelligence:
  - [x] Add built-in node kinds: `pull_request`, `deployment_run`, `meeting`, `document`, `communication_thread`, `incident`.
  - [x] Register schema contracts (required properties + relationship allowances).
  - [x] Extend schema tests to validate registration and required semantics.
- [x] Improve declarative mapper ontology usage:
  - [x] Migrate GitHub PR mappings from generic `activity` to `pull_request`.
  - [x] Add first-class `incident` node linkage in incident timeline mappings.
  - [x] Migrate deploy mappings to `deployment_run`.
  - [x] Migrate calendar/doc/slack thread mappings to `meeting`/`document`/`communication_thread`.
  - [x] Add mapper tests validating new kind outputs.
- [x] Unify write metadata normalization:
  - [x] Add `graph.WriteMetadata` + `NormalizeWriteMetadata(...)`.
  - [x] Refactor API writeback handlers to use shared graph metadata helper.
  - [x] Refactor app tool writeback handlers to use shared graph metadata helper.
  - [x] Refactor graph actuation writeback to use shared graph metadata helper.
  - [x] Add dedicated graph metadata helper tests.
- [x] Improve maintainability documentation/comments:
  - [x] Add `docs/GRAPH_ONTOLOGY_ARCHITECTURE.md`.
  - [x] Cross-link architecture + intelligence docs to ontology architecture.
  - [x] Add targeted comments for identity queue prioritization and leverage score weighting rationale.

## Deep Review Cycle 3 - Graph Leverage + Calibration + Actuation (2026-03-09)

### Review findings
- [x] Gap: no single leverage surface combining quality, ingestion breadth, identity calibration backlog, temporal freshness, closed-loop execution, and actuation readiness.
- [x] Gap: no reusable graph query templates endpoint/tool for repeatable investigations.
- [x] Gap: no identity reviewer loop (`accepted` / `rejected` / `uncertain`) to calibrate alias quality continuously.
- [x] Gap: no recommendation-to-action writeback interface to connect insight acceptance to executable actions.
- [x] Gap: declarative mapper breadth too narrow for org intelligence domains (Slack/Jira/CI/Docs/Support/Sales/Calendar).

### Execution plan
- [x] Add graph leverage report:
  - [x] `BuildGraphLeverageReport` with weighted leverage score/grade.
  - [x] Ingestion coverage (`expected` vs `observed` sources + missing list).
  - [x] Temporal activity coverage + freshness roll-up.
  - [x] Closed-loop decision/outcome closure + stale decision detection.
  - [x] Predictive readiness proxy metrics.
  - [x] Query readiness and actuation readiness sections.
  - [x] Prioritized recommendations from leverage gaps.
- [x] Add identity calibration subsystem extensions:
  - [x] Reviewer decision API (`accepted` / `rejected` / `uncertain`) persisted on alias history.
  - [x] Queue generation for ambiguous/unresolved aliases.
  - [x] Calibration report with precision, review coverage, linkage, backlog, per-source breakdown.
- [x] Add recommendation actuation writeback:
  - [x] `ActuateRecommendation` graph function.
  - [x] Action node creation with temporal/provenance metadata.
  - [x] Target edges and optional decision linkage (`executed_by`).
- [x] Add graph query template surface:
  - [x] Built-in template catalog in graph package.
  - [x] API endpoint and MCP/tool exposure for template retrieval.
- [x] Expand declarative mapper source breadth:
  - [x] GitHub PR opened + review submitted.
  - [x] Slack thread messages.
  - [x] Jira transitions.
  - [x] CI deploy completed.
  - [x] Calendar meeting recorded.
  - [x] Docs page edited.
  - [x] Support ticket updated.
  - [x] Sales call logged.
- [x] Add API surfaces:
  - [x] `GET /api/v1/graph/intelligence/leverage`
  - [x] `GET /api/v1/graph/query/templates`
  - [x] `POST /api/v1/graph/identity/review`
  - [x] `GET /api/v1/graph/identity/calibration`
  - [x] `POST /api/v1/graph/actuate/recommendation`
- [x] Add tool surfaces:
  - [x] `cerebro.graph_leverage_report`
  - [x] `cerebro.graph_query_templates`
  - [x] `cerebro.identity_review`
  - [x] `cerebro.identity_calibration`
  - [x] `cerebro.actuate_recommendation`
- [x] Update OpenAPI for all new graph leverage/identity/actuation/query-template endpoints.
- [x] Add/extend tests across graph, mapper, API handlers, and app tools.
- [x] Validate all CI-equivalent checks locally.

### Validation log
- [x] `go test ./internal/graph ./internal/graphingest ./internal/api ./internal/app -count=1`
- [x] `make openapi-check`
- [x] `go test ./... -count=1`
- [x] `$(go env GOPATH)/bin/gosec -quiet -severity medium -confidence medium -exclude-generated ./...`
- [x] `$(go env GOPATH)/bin/golangci-lint run --timeout=15m ./cmd/... ./internal/... ./api/...`

## Deep Review Cycle 2 - Graph Quality Intelligence (2026-03-09)

### Review findings
- [x] Gap: no consolidated graph-quality report surface for ontology + identity + temporal + write-back health.
- [x] Gap: no `/api/v1/graph/intelligence/quality` endpoint for product consumption.
- [x] Gap: no MCP/tool surface for graph-quality reporting.
- [x] Correctness issue: temporal metadata completeness was over-penalized for node-only graphs due fixed denominator averaging.

### Execution plan
- [x] Add `BuildGraphQualityReport` graph surface with:
  - [x] summary maturity score/grade
  - [x] ontology quality metrics
  - [x] identity linkage metrics
  - [x] temporal freshness + metadata completeness metrics
  - [x] write-back loop closure metrics
  - [x] domain coverage and prioritized recommendations
- [x] Fix temporal completeness averaging to use only available node/edge metric dimensions.
- [x] Add graph unit tests for quality report behavior and nil/node-only edge cases.
- [x] Add API endpoint:
  - [x] `GET /api/v1/graph/intelligence/quality`
  - [x] query validation (`history_limit`, `since_version`, `stale_after_hours`)
  - [x] API handler tests (happy path + invalid params)
- [x] Add MCP tool:
  - [x] `cerebro.graph_quality_report`
  - [x] tool tests (happy path + validation)
- [x] Update contracts/docs:
  - [x] OpenAPI route documentation
  - [x] `docs/GRAPH_INTELLIGENCE_LAYER.md` with quality interface/tool notes
- [x] Validate and ship:
  - [x] `gofmt` changed files
  - [x] targeted tests for graph/api/app
  - [x] `make openapi-check`
  - [x] `go test ./... -count=1`
  - [x] gosec + golangci-lint
  - [x] push + verify CI green

## Phase 0 - Ground rules and acceptance criteria
- [x] Every new node/edge written by new APIs/tools includes provenance and temporal metadata (`source_system`, `source_event_id`, `observed_at`, `valid_from`, optional `valid_to`, `confidence`).
- [x] New surfaces are covered by tests (graph + api + app tool tests).
- [x] OpenAPI updated for all new HTTP endpoints/params.
- [x] CI-equivalent checks pass locally.

## Phase 1 - Ontology spine expansion
- [x] Add canonical node kinds:
  - [x] `identity_alias`
  - [x] `service`
  - [x] `workload`
  - [x] `decision`
  - [x] `outcome`
  - [x] `evidence`
  - [x] `action`
- [x] Add canonical edge kinds:
  - [x] `alias_of`
  - [x] `runs`
  - [x] `depends_on`
  - [x] `targets`
  - [x] `based_on`
  - [x] `executed_by`
  - [x] `evaluates`
- [x] Register built-in schema definitions for new kinds with required properties and relationship contracts.
- [x] Add/extend schema tests to assert built-ins and relationship allowances.

## Phase 2 - Identity resolution subsystem (first-class)
- [x] Add graph identity resolution engine with deterministic + heuristic scoring.
- [x] Implement alias assertion ingestion:
  - [x] Upsert `identity_alias` nodes.
  - [x] Emit `alias_of` edges with confidence and reason metadata.
- [x] Add merge candidate report output with scored candidates and reasons.
- [x] Add reversible split operation to remove/disable incorrect alias links.
- [x] Add graph tests:
  - [x] deterministic match by normalized email
  - [x] heuristic match fallback
  - [x] merge confirmation
  - [x] split reversal

## Phase 3 - Declarative event-to-graph mapping
- [x] Add a YAML-backed mapping engine for event-to-node/edge upserts.
- [x] Support template expansion:
  - [x] `{{field.path}}`
  - [x] `{{resolve(field.path)}}` for identity canonicalization
- [x] Add default mapping config file for at least:
  - [x] PR merge event -> person/service contribution edges
  - [x] Incident/ticket event -> action/evidence edges
- [x] Integrate mapper into TAP cloud event handling before legacy fallback mapping.
- [x] Add mapper + integration tests.

## Phase 4 - Continuous temporal semantics
- [x] Add time-window aware graph filters/helpers for nodes/edges (`as_of`, `from`, `to`).
- [x] Extend graph query API and tool surfaces to accept temporal parameters.
- [x] Ensure neighbors/paths queries are time-scoped when temporal params are supplied.
- [x] Add freshness metrics and recency weighting into intelligence confidence.
- [x] Add tests for:
  - [x] temporal edge visibility at `as_of`
  - [x] window filtering
  - [x] confidence recency penalty behavior

## Phase 5 - Agent + API write-back surfaces
- [x] Add API endpoints under `/api/v1/graph`:
  - [x] `POST /write/observation`
  - [x] `POST /write/annotation`
  - [x] `POST /write/decision`
  - [x] `POST /write/outcome`
  - [x] `POST /identity/resolve`
  - [x] `POST /identity/split`
- [x] Add MCP tools:
  - [x] `cerebro.record_observation`
  - [x] `cerebro.annotate_entity`
  - [x] `cerebro.record_decision`
  - [x] `cerebro.record_outcome`
  - [x] `cerebro.resolve_identity`
  - [x] `cerebro.split_identity`
- [x] Ensure all write surfaces enforce required provenance + temporal metadata defaults.
- [x] Add API and tool tests for happy path + validation failures.

## Phase 6 - Documentation and contracts
- [x] Update graph intelligence doc with:
  - [x] canonical ontology spine
  - [x] identity resolution lifecycle
  - [x] declarative mapper format
  - [x] temporal semantics
  - [x] write-back loop model
- [x] Update OpenAPI for all new endpoints and params.

## Phase 7 - Validation and ship
- [x] `goimports`/`gofmt` all changed files.
- [x] Run targeted tests for graph/api/app changes.
- [x] Run `make openapi-check`.
- [x] Run `go test ./... -count=1`.
- [x] Run gosec + golangci-lint.
- [x] Push to remote and verify CI status.
- [x] Mark every TODO item complete.

## Validation log
- [x] `go test ./internal/graph ./internal/graphingest ./internal/api ./internal/app -count=1`
- [x] `make openapi-check`
- [x] `go test ./... -count=1`
- [x] `$(go env GOPATH)/bin/gosec -quiet -severity medium -confidence medium -exclude-generated ./...`
- [x] `$(go env GOPATH)/bin/golangci-lint run --timeout=15m ./cmd/... ./internal/... ./api/...`

## Finalization record
- [x] Committed implementation and fixes on `codex/graph-intelligence-layer-exec`.
- [x] Pushed branch and validated GitHub Actions run `22841427603` for `ae2df0c8954e0501607d61ae5b5e6660879b5efa`.
- [x] Merged PR [#108](https://github.com/evalops/cerebro/pull/108) into `main`.
