# Source Health and Coverage

This document covers the source health, coverage evaluation, and resource scoping packages in Cerebro that support source runtime observability, blind-spot detection, and ingestion exclusion policies.

It complements [Source Runtime Guide](source-runtime-guide.md), [Architecture](../reference/architecture.md), and [GRC Architecture](grc-architecture.md).

## Packages Covered

- `internal/sourcecoverage` — source coverage contract evaluation
- `internal/sourcehealth` — source runtime health evaluation
- `internal/sourcehealthview` — source health dashboard view model
- `internal/resourcescope` — resource-scope exclusion policies

## sourcecoverage — Coverage Evaluation

`internal/sourcecoverage` evaluates source coverage contracts from the CDK registry against observed source runtime states. It produces per-dimension coverage records, detects blind spots, computes gate status, and builds full reports for source health dashboards and agent coverage context.

### Key Types

- `Record` — per-dimension coverage record with state, support level, and blind-spot flag
- `Report` — full coverage report with totals, gate, records, blind spots, and summaries
- `RuntimeObservation` — observed runtime state for coverage evaluation
- `Options` — tenant and source filtering

### Coverage States

| State | Meaning |
| --- | --- |
| `healthy` | Dimension is fully covered and fresh |
| `partial` | Dimension is partially covered |
| `unsupported` | Source does not support this dimension |
| `unconfigured` | Dimension is supported but not configured |
| `stale` | Coverage data is stale |
| `failed` | Coverage evaluation failed |
| `unknown` | Coverage state could not be determined |

### Key Exports

- `ContractsFromRegistry()` — extracts coverage contracts from the CDK registry
- `ObservationsFromRuntimes()` — converts protobuf runtimes to observations
- `Evaluate()` — evaluates contracts against observations, producing records
- `BuildReport()`, `BuildScopedReport()` — build full coverage reports
- `BlindSpots()`, `TotalsFor()`, `GateForTotals()`, `Summaries()` — report helpers

### Boundaries

- Coverage evaluation logic stays behind this package
- CDK contract definitions are owned by `internal/sourcecdk`
- Agent platform coverage context is bridged by `internal/agentplatformcoverage`

### Dependencies

`sourcecdk`; protobuf types from `gen/cerebro/v1`

### RBAC Ownership

`source_manager` (reports run, sources preview), `viewer` (read)

## sourcehealth — Runtime Health Evaluation

`internal/sourcehealth` evaluates source runtime health from raw runtime protobuf data. It computes lifecycle, schedule, freshness, source-sync, graph-ingest, and finding-evaluation states, plus backfill eligibility and recommended next actions.

### Key Types

- `Record` — raw health signals extracted from a runtime (enabled state, status, lag, cursors, cadence, graph/finding runs)
- `State` — evaluated health state with lifecycle, schedule, freshness, sync, graph, finding, failure class, backfill eligibility, next action, and recommended workflow
- `GraphRun` — latest graph ingestion run state
- `FindingEvaluation` — latest finding evaluation run state

### Key Exports

- `RecordFromRuntime()` — extracts a health Record from a protobuf SourceRuntime
- `Evaluate()` — computes a full State from a Record
- `BackfillEligibility()` — determines if graph backfill is warranted
- Individual state extractors: `RuntimeEnabledState()`, `SourceSyncState()`, `GraphIngestState()`, `FindingEvaluationState()`, `FreshnessState()`

### Boundaries

- Health evaluation logic stays behind this package
- Dashboard view model serialization is owned by `internal/sourcehealthview`
- Backfill job execution is owned by `internal/jobs` and the graph rebuild pipeline

### Dependencies

Protobuf types from `gen/cerebro/v1`; no internal package dependencies

### RBAC Ownership

`source_manager` (source runtimes, reports), `job_manager` (backfill job recommendations)

## sourcehealthview — Health Dashboard View Model

`internal/sourcehealthview` defines the JSON-serializable view model types for the source health dashboard and API. It combines runtime health signals, sync metrics, graph run details, finding evaluation metrics, and the associated resource scope policy.

### Key Types

- `Record` — top-level health view record with scope policy, sync lag, checkpoint, graph/finding run summaries, and cadence config
- `Sync` — recent sync metrics (scanned, accepted, rejected, projected)
- `GraphRun` — graph ingestion run details with node/link deltas
- `FindingEvaluation` — finding evaluation run details with event/finding counts

### Boundaries

- Pure type definitions for API serialization; no business logic
- Embeds `resourcescope.Policy` to surface exclusion policies alongside health data

### Dependencies

`resourcescope`

### RBAC Ownership

`source_manager` (source runtimes, reports), `viewer` (read-only dashboard)

## resourcescope — Resource Exclusion Policies

`internal/resourcescope` defines and manages resource-scope exclusion policies for source runtimes. It allows operators to skip specific resource families, asset classes, kinds, URNs, or concrete resources during source ingestion and event projection.

### Key Types

- `Policy` — exclusion policy with families, asset classes, kinds, URNs, and resource selectors
- `ResourceSelector` — identifies a concrete resource by URN or type/ID with a reason

### Key Exports

- `FromConfig()` — parses policy from a source runtime config map
- `ConfigValue()` — serializes policy to canonical JSON for storage
- `Normalize()` — trims, deduplicates, and validates policy values
- `Policy.Empty()` — checks if policy has no exclusions
- `SelectorFromURN()` — builds a selector from a Cerebro URN
- `AddExcludedResource()`, `RemoveExcludedResource()` — mutate exclusions
- `Policy.ExcludesFamily()`, `Policy.ExcludesEvent()` — runtime filtering checks

### Boundaries

- Policy definition, parsing, serialization, and evaluation stay behind this package
- Runtime ingestion applies the policy; this package does not perform filtering itself
- No internal package dependencies; pure stdlib only

### RBAC Ownership

`source_manager` (source runtimes write scope)

## Code Map

- `internal/sourcecoverage/coverage.go` — coverage contract evaluation and report builder
- `internal/sourcehealth/health.go` — runtime health evaluation and state computation
- `internal/sourcehealthview/types.go` — health dashboard view model types
- `internal/resourcescope/policy.go` — resource exclusion policy definition and management
