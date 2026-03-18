# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-17 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

## Deep Review Cycle 194 - Tiered Tenant Graph Storage (2026-03-17)

### Review findings
- [x] Gap: issue `#356` still kept tenant-scoped graph access entirely in the hot in-memory layer, so a live-graph clear or restart dropped tenant queryability even when persisted graph snapshots were available.
- [x] Gap: the tenant shard cache had no warm tier, so every invalidation forced tenant reads back through `SubgraphForTenant` against the live graph instead of reusing a versioned on-disk tenant snapshot.
- [x] Gap: idle shard eviction treated every tenant the same, so active-incident tenants with open findings could fall out of the hot cache even though they are the least acceptable candidates for cold recovery latency.

### Execution plan
- [x] Extend the tenant shard manager into a tier manager with hot memory shards, warm on-disk tenant snapshots, and cold recovery through `GraphPersistenceStore`.
- [x] Preserve tenant generation state across live-graph clears so warm shards stay usable after restart-like transitions, while still invalidating hot shards when the live graph version changes.
- [x] Pin hot tenant shards when the tenant has open findings, and add TDD coverage for cold recovery, warm recovery, and pin-aware eviction.

## Deep Review Cycle 194 - Event Pipeline Distributed Tracing (2026-03-17)

### Review findings
- [x] Gap: issue `#360` still injected `traceparent` at JetStream publish time, but the staged consumer path dropped that upstream context before decode, dedupe, handler execution, and ack/nak.
- [x] Gap: the ingest path had no first-class consumer spans for fetch, decode, ingest, dedupe, handler, or ack, so pipeline latency could not be attributed to the stage actually stalling.
- [x] Gap: the events package had no regression coverage proving handler contexts inherited the upstream trace or that handler failures stayed in the same trace through `nak`.

### Execution plan
- [x] Extract remote `traceparent` into the consumer context and emit consumer-side fetch/decode/ingest/dedup/handle/ack spans with event and stream attributes.
- [x] Record handler and dedupe failures on spans while keeping `nak` and `ack` in the same trace as the event ingest span.
- [x] Add TDD coverage for happy-path trace propagation and failure-path `nak` tracing.
- [x] Re-run focused event tests plus lint and changed-file validation.

## Deep Review Cycle 194 - Typed Observation Property Storage (2026-03-17)

### Review findings
- [x] Gap: issue `#385` still stored high-frequency observation fields in the generic per-node `map[string]any`, so every live observation duplicated hot-path strings and timestamps even though the graph already had typed readers for those fields.
- [x] Gap: observation-heavy query, temporal, and snapshot paths assumed raw map-backed properties, which made a typed-storage migration risky unless the read model stayed stable across live graphs, JSON round-trips, and bitemporal filtering.
- [x] Gap: schema validation and runtimegraph tests still reached directly into live observation maps, so they would silently regress the compact-storage contract unless the exported property surface stayed materialized.

### Execution plan
- [x] Add compact typed storage for the stable observation fields with on-demand `PropertyValue` and `PropertyMap` materialization, while keeping overflow metadata in the generic map.
- [x] Preserve observation semantics across snapshots, WAL normalization, bitemporal visibility, schema validation, and knowledge/runtimegraph readers by routing those paths through the materialized property surface.
- [x] Add regression coverage for compact live storage, snapshot restore, observation-property mutation history, and affected runtimegraph/materialization expectations, then re-run focused and changed-file validation.

## Deep Review Cycle 193 - Tenant-Sharded Hot Graphs (2026-03-17)

### Review findings
- [x] Gap: issue `#354` still served tenant-scoped graph reads by cloning a fresh `SubgraphForTenant` on every request, so large multi-tenant graphs paid repeated clone/index cost even when the live graph had not changed.
- [x] Gap: the app had no first-class tenant shard lifecycle, so there was no cache boundary for lazy per-tenant hydration, idle eviction, or invalidation when the hot global graph pointer swapped after rebuilds or incremental mutations.
- [x] Gap: the API layer had no dedicated tenant-scoped live-graph accessor, which kept tenant graph routing coupled to ad hoc per-handler cloning instead of one app-owned read path.

### Execution plan
- [x] Add an app-owned tenant shard manager that lazily hydrates tenant subgraphs from the current live graph and evicts idle shards after a configurable inactivity TTL.
- [x] Invalidate cached tenant shards whenever `setSecurityGraph` swaps the live graph so tenant reads never outlive the source graph version boundary.
- [x] Route the live tenant API graph path through the shard manager while preserving clone-based scoping for snapshot and other non-live graph views.
- [x] Add TDD coverage for shard reuse, source-swap invalidation, idle eviction, and tenant API reuse, then re-run focused and broad app/API validation.

## Deep Review Cycle 192 - Materialized Detection Views (2026-03-17)

### Review findings
- [x] Gap: issue `#359` still left common dashboard-heavy graph queries on the synchronous request path, so blast-radius leaderboards and toxic-combination summaries recomputed after every request even when the graph had not changed.
- [x] Gap: the graph had a point-in-time `BlastRadiusTopN` cache, but nothing proactively kept that cache warm or maintained any durable snapshot for toxic combinations as mutations streamed in.
- [x] Gap: there was no regression coverage proving a manager could ignore irrelevant graph changes, coalesce rapid relevant mutations, and keep a materialized view consistent with the current graph version.

### Execution plan
- [x] Add a materialized detection view manager that owns reactive refresh workers on top of the graph change-feed substrate.
- [x] Materialize and keep warm the blast-radius top-N leaderboard and active toxic-combination snapshot with bounded debounce windows.
- [x] Add TDD coverage for irrelevant-change suppression, burst coalescing, and post-mutation view consistency.
- [x] Re-run focused and full graph tests, lint, and changed-file validation.

## Deep Review Cycle 193 - Tenant-Scoped Live Graph Readers (2026-03-17)

### Review findings
- [x] Gap: issue `#347` still enforced tenant isolation for many API reads by cloning `SubgraphForTenant()` snapshots, which preserved correctness but turned every tenant-scoped query into an avoidable graph copy.
- [x] Gap: the graph package had no first-class reader abstraction that could derive tenant scope from context, reject implicit multi-tenant reads, and filter nodes and edges in-place over the live graph.
- [x] Gap: cross-tenant graph reads had no graph-level audit hook or tenant-count summary, so later boundary handlers could not reuse one consistent authorization and observability substrate.

### Execution plan
- [x] Add a context-derived tenant read scope with explicit cross-tenant opt-in and graph-level audit hook support.
- [x] Add a tenant reader that filters nodes, temporal node reads, and temporal edge reads over the live graph without cloning.
- [x] Add TDD coverage for required scope on multi-tenant graphs, tenant filtering, cross-tenant audit hook execution, and focused reader throughput.

## Deep Review Cycle 191 - Reactive Graph Monitors (2026-03-17)

### Review findings
- [x] Gap: issue `#353` still drove `ToxicCombinationMonitor`, `AttackPathMonitor`, and `PrivilegeEscalationMonitor` from fixed polling intervals, which kept detection latency coupled to the next ticker and re-scanned the full graph even when nothing relevant changed.
- [x] Gap: the graph had no first-class change subscription substrate, so monitors could not express the node kinds or edge kinds they care about and react only when matching mutations happened.
- [x] Gap: the monitoring package had no regression coverage proving that irrelevant graph changes are ignored and rapid bursts of relevant mutations are coalesced into one debounced rescan.

### Execution plan
- [x] Add a graph change-feed substrate with typed node/edge reset events plus filtered subscriptions and coalescing delivery.
- [x] Switch the three graph monitors from ticker polling to an initial scan followed by debounced rescans triggered by relevant graph mutations.
- [x] Add TDD coverage for filtered change delivery, irrelevant-change suppression, and rapid-change coalescing.
- [x] Re-run focused and full graph tests, lint, and changed-file validation.

## Deep Review Cycle 192 - Streaming Event Pipeline With Backpressure (2026-03-17)

### Review findings
- [x] Gap: issue `#358` still processed each fetched JetStream message sequentially inside one loop, so handler throughput stayed capped at one in-flight event even when batches contained unrelated entities.
- [x] Gap: the existing consumer heartbeat model only covered the current sequential message, so introducing concurrency without a queue-aware handoff would risk losing `InProgress()` extensions for messages waiting behind slow handlers.
- [x] Gap: batch-local duplicate events could only stay suppressed if dedupe and handler execution remained ordered for a stable shard key, which ruled out naive per-message goroutines.

### Execution plan
- [x] Split the batch path into parallel decode plus ordered worker-shard execution, keeping malformed payload handling in decode and preserving per-shard ordering for dedupe, handler, and ack.
- [x] Add configurable handler worker concurrency, bounded shard queues, and adaptive fetch sizing that backs off after observed queue saturation and ramps back up when batches stay healthy.
- [x] Keep batch heartbeats active until a worker starts a message, then switch to the existing per-message heartbeat so queued work continues extending ack wait under backpressure.
- [x] Add TDD coverage for same-entity ordering across concurrent workers, duplicate suppression within one batch, and adaptive batch-size behavior.

## Deep Review Cycle 188 - Cross-Adapter Observation Corroboration (2026-03-17)

### Review findings
- [x] Gap: issue `#367` still materialized semantically identical runtime observations from Falco, Tetragon, and other adapters as unrelated graph observation nodes even when they described the same workload activity inside one short time window.
- [x] Gap: runtimegraph had no graph-native corroboration edge or deterministic primary-selection rule, so multi-sensor agreement could not increase confidence or reduce investigation noise.
- [x] Gap: the primary observation node was not inheriting richer metadata from corroborating adapters, which kept high-value fields such as image, domain, and tags fragmented across sibling nodes.

### Execution plan
- [x] Add a semantic observation correlation key keyed by subject, kind, detail, and 5-second observation bucket.
- [x] Extend the graph ontology with observation corroboration properties plus a first-class `corroborates` edge kind.
- [x] Materialize deterministic primary/corroborating observation relationships during runtimegraph projection and update primary confidence from corroborating source count.
- [x] Merge richer corroborating metadata onto the primary observation while keeping corroborating nodes and edges explicit.
- [x] Add TDD coverage for cross-adapter corroboration, confidence scaling, metadata inheritance, and 5-second bucket boundaries.

## Deep Review Cycle 189 - Runtime Trace Call Topology (2026-03-17)

### Review findings
- [x] Gap: issue `#369` still reduced OTel spans to isolated `trace_link` observations, so the graph kept per-service runtime breadcrumbs but not the actual caller-to-callee runtime topology.
- [x] Gap: trace materialization had no replay-safe aggregation path for call frequency, latency, and error rate, so even when both services existed in the graph there was no durable `calls` overlay for blast-radius and dependency analysis.
- [x] Gap: OTel normalization did not project destination service identity from peer-service or in-cluster address attributes, which prevented later graph stages from resolving the callee side of a span without re-parsing raw OTLP payloads.

### Execution plan
- [x] Extend OTel span normalization to capture destination service identity and inferred call protocol from peer-service and service-address attributes.
- [x] Add a first-class `calls` edge kind to the graph ontology and allow it from service and workload-like runtime subjects.
- [x] Materialize replay-safe runtime `calls` edges with call count, latency, error rate, and first/last seen aggregation from trace observations.
- [x] Add TDD coverage for destination-service extraction, trace observation metadata persistence, call-edge creation, aggregation, and duplicate replay suppression.
- [x] Re-run focused graph/runtimegraph/OTel tests, lint, ontology doc generation, and changed-file validation.

## Deep Review Cycle 190 - Copy-On-Write Graph Mutation Forks (2026-03-17)

### Review findings
- [x] Gap: issue `#348` still routed speculative graph mutation workloads through full `Clone()` calls, so simulations and incremental rebuilds paid O(n) deep-copy cost before the first actual write.
- [x] Gap: the existing graph API returns mutable node and edge pointers from getters, which means full persistent sharing cannot be dropped into public `Clone()` without violating current semantics.
- [x] Gap: the mutation-heavy internal workflows already mutate through graph methods, so they lacked only a graph-method-safe copy-on-write fork substrate to unlock structural sharing without breaking external behavior.

### Execution plan
- [x] Add a copy-on-write `Fork()` path that shares node, edge, and adjacency storage until graph-method mutations detach the touched objects and buckets.
- [x] Switch internal mutation-heavy workflows to the fork path for simulations, reorg analysis, CDC rebuild working graphs, and scale-profile mutation measurement.
- [x] Add regression coverage proving parent and fork diverge cleanly across node-property, node-add, edge-add, and edge-remove mutations.
- [x] Add a focused benchmark comparing deep clone plus one mutation against fork plus one mutation.
- [x] Re-run focused and broad graph tests plus lint before pushing the branch.

## Deep Review Cycle 187 - Observation Correlation Windows (2026-03-17)

### Review findings
- [x] Gap: issue `#364` still materialized runtime observations independently, so multi-step workload activity had no first-class graph node representing one correlated attack sequence.
- [x] Gap: repeated graph rebuilds had no deterministic, idempotent sequence materialization pass that could regroup observations by workload and time window without duplicating prior sequence nodes.
- [x] Gap: there was no graph-native edge model linking workloads to correlated observation windows and projecting the underlying `based_on` evidence back onto the derived sequence node.

### Execution plan
- [x] Add an `attack_sequence` node kind plus `has_sequence` and `contains` edge kinds to the graph schema.
- [x] Materialize deterministic workload-scoped observation windows during runtimegraph finalization using configurable duration and inactivity-gap policy.
- [x] Project ordered observation membership and inherited `based_on` evidence targets onto each derived sequence node.
- [x] Add TDD coverage for single-window grouping, window splits, evidence propagation, and idempotent rematerialization.
- [x] Re-run focused and full graph/runtimegraph tests, lint, and changed-file validation.

## Deep Review Cycle 188 - Observation Compaction Protections (2026-03-17)

### Review findings
- [x] Gap: issue `#368` still compacted stale runtime observations even when an active `attack_sequence` node still referenced them through `contains` edges, which could delete the evidence backing a live sequence.
- [x] Gap: the first compaction slice only treated `based_on` chains as protected, so corroborated multi-sensor observations with live `corroborates` relationships could also be summarized away prematurely.
- [x] Gap: compaction metrics did not distinguish why stale observations were retained, which made it hard to tell whether hot-graph cardinality was driven by findings, sequences, or corroboration state.

### Execution plan
- [x] Extend compaction protection to retain observations referenced by attack-sequence `contains` edges.
- [x] Extend compaction protection to retain observations participating in corroboration groups through metadata or `corroborates` edges.
- [x] Split preserved-observation counters by linked, sequenced, and correlated reasons.
- [x] Add TDD coverage for attack-sequence and corroboration preservation.
- [ ] Re-run focused and changed-file runtimegraph validation before pushing the follow-up branch.

## Deep Review Cycle 186 - Workload Behavioral Baseline Profiles (2026-03-17)

### Review findings
- [x] Gap: issue `#363` still had no per-workload behavioral memory, so runtime detection could only match explicit rules and had no way to surface novel process, network, DNS, or file activity after a learning period.
- [x] Gap: the runtime package already carried a compact bloom-filter substrate for processed-event dedupe, but nothing reused that bounded-memory structure to learn workload-local behavior across the highest-cardinality runtime signals.
- [x] Gap: there was no regression coverage proving learned workload profiles suppress findings during the learning window, evict least-recently-used profiles under a memory cap, and start emitting anomaly findings once new behavior appears later.

### Execution plan
- [x] Add bounded per-workload behavior profiles with bloom filters for process names/paths, network destinations, DNS domains, and file paths.
- [x] Add a simple per-workload rate baseline so sharp post-learning spikes can surface as behavioral anomalies alongside novel signals.
- [x] Integrate behavioral anomaly findings into normalized observation processing without disturbing existing rule routing and suppression behavior.
- [x] Add TDD coverage for learning-mode suppression, learned-signal reuse, novel process/network/file detection, rate spikes, and LRU profile eviction.
- [x] Re-run focused runtime tests, full runtime tests, lint, and changed-file validation.

## Deep Review Cycle 185 - Correlation Refresh Coalescing Queue (2026-03-17)

### Review findings
- [x] Gap: issue `#346` still routed event-correlation refresh through a single-slot `chan string`, so any refresh request arriving while one was already buffered was silently dropped.
- [x] Gap: the refresh path had no direct observability for backlog, runtime, or dropped work, which made correlation staleness invisible under hot TAP ingest.
- [x] Gap: the ingest path had no bounded slow-down when refresh work fell behind, so correlation lag and ingestion rate could diverge without any feedback loop.

### Execution plan
- [x] Replace the single-slot channel with a coalescing refresh queue that merges pending scopes and preserves shutdown semantics.
- [x] Add Prometheus metrics for dropped refreshes, refresh duration, and pending queue depth.
- [x] Apply bounded ingest backpressure when refresh work is already running and aged pending work exists.
- [x] Add TDD coverage for coalescing and backpressure behavior, then re-run focused app/metrics validation.
