# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-17 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
