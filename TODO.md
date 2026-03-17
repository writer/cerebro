# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-17 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
