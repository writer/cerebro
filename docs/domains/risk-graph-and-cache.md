# Risk Planning, Graph Provenance, and Query Cache

This document covers three infrastructure-level service packages in Cerebro: risk-action planning, graph entity provenance lookup, and the versioned query cache abstraction.

It complements [Findings Platform Architecture](findings-platform-architecture.md), [Graph Operations](graph-operations.md), and [Architecture](../reference/architecture.md).

## Packages Covered

- `internal/riskplan` — risk-action plan generation and scoring
- `internal/graphprovenance` — graph entity provenance lookup
- `internal/querycache` — versioned cache abstraction with fresh/stale/miss semantics

## riskplan — Risk-Action Planning

`internal/riskplan` generates ranked, simulated risk-action plans from findings using pluggable candidate generators. It scores candidates with risk-delta simulation, assesses ownership, effort, and evidence confidence, and supports plan diffing against previous runs.

### Candidate Generators

Six built-in generators produce candidate seeds from findings and graph context:

1. `publicExposureGenerator` — candidates from publicly exposed resources
2. `privilegeGenerator` — candidates from privileged identity risks
3. `vulnerabilityGenerator` — candidates from vulnerability findings
4. `credentialGovernanceGenerator` — candidates from credential governance gaps
5. `ownerAssignmentGenerator` — candidates for missing owner assignment
6. `evidenceRefreshGenerator` — candidates for stale evidence refresh

### Key Types

- `Options` — planner configuration (tenant, limits, generators, graph neighborhoods, previous candidates)
- `Plan` — full ranked action plan
- `Candidate` — ranked action with identity, scoring, references, execution details, and risk delta
- `CandidateGenerator` — interface for pluggable seed generators
- `ScoreBreakdown`, `Effort`, `Ownership`, `EvidenceConfidence`, `OutcomeLearning` — scoring detail types
- `PlanDiff`, `CandidateDiff` — plan diff types for comparing runs

### Key Exports

- `DefaultGenerators()` — returns the six built-in generators
- `Analyze()` — builds a ranked plan from findings and graph context
- `TargetURNs()` — returns candidate graph roots in seed priority order
- `DecodeCandidates()` — decodes prior candidates from JSON
- `DiffCandidates()` — compares previous vs current candidate sets

### MCP Surface

The planner is exposed to MCP clients through read-only tools:

- `cerebro.risk.actions.list` — returns a bounded ranked plan with typed candidate contract
- `cerebro.risk.actions.explain` — returns full explanation for one candidate ID

### Boundaries

- Plan generation, scoring, and diffing stay behind this package
- The planner is read-only; it recommends next-best actions without executing remediation
- No new store is introduced; the planner operates on current findings and graph evidence
- Reports such as `risk-action-plan` in the findings platform delegate to this engine

### Dependencies

`findings` (aliased as `findinganalysis`), `ports`

### RBAC Ownership

`analyst` (risk scoring, dashboards), `finding_manager` (findings, risk scoring), `grc_reviewer` (risk scoring, dashboards)

## graphprovenance — Graph Entity Provenance

`internal/graphprovenance` provides graph entity provenance lookup by URN via Cypher queries. It returns entity metadata, projection classification, source URNs, citation status, and freshness signals.

### Key Types

- `Service` — provenance service wrapping a `ports.GraphQueryStore`
- `Request` — URN lookup request
- `Response` — full provenance response with entity details
- `Provenance` — surface, scope, source URNs, citation status, and freshness signals

### Key Exports

- `New(store)` — constructor
- `Service.Get()` — queries the graph for entity provenance by URN
- `TenantIDFromURN()` — extracts tenant ID from a Cerebro URN

### Boundaries

- Provenance query and response shaping stay behind this package
- Graph query execution is delegated to `ports.GraphQueryStore`
- Projection metadata is sourced from `internal/projectionmeta`
- Requires Neo4j/Aura graph store to be configured

### Dependencies

`graphquery`, `ports`, `projectionmeta`

### RBAC Ownership

`viewer` (cosmo security read), `analyst` (investigation)

## querycache — Versioned Cache Abstraction

`internal/querycache` provides a versioned cache abstraction with fresh, stale, and miss TTL semantics. It offers both an in-memory implementation (with LRU eviction) and a Redis implementation (with telemetry instrumentation).

### Key Types

- `Cache` — interface with `Get`, `Set`, `Version`, `BumpVersion`, `Ping`, and `Close`
- `Entry` — cache entry with payload, timestamps, and `State()` method
- `State` — enum: `StateMiss`, `StateFresh`, `StateStale`
- `Options` — namespace, max payload bytes, max entries
- `MemoryCache` — in-memory implementation with mutex, eviction, and version tracking
- `RedisCache` — Redis-backed implementation using `go-redis/v9`

### Key Exports

- `NewMemory(options)` — constructs in-memory cache
- `OpenRedis(rawURL, options)` — constructs Redis cache from URL
- `ErrMiss` — sentinel error for cache misses

### Cache Semantics

Entries have two TTL boundaries:

| State | Meaning |
| --- | --- |
| `fresh` | Entry is within its primary TTL; serve directly |
| `stale` | Entry is past its primary TTL but within stale-until; serve and trigger background refresh |
| `miss` | Entry is past stale-until or absent; fetch fresh data |

Version tracking allows callers to invalidate all entries for a namespace by bumping the version, without enumerating keys.

### Boundaries

- Cache storage, eviction, TTL, and version tracking stay behind this package
- Callers own serialization and deserialization of payload bytes
- Redis telemetry instrumentation is included in the Redis implementation

### Dependencies

`telemetry` (Redis implementation only); external: `github.com/redis/go-redis/v9`

### RBAC Ownership

`admin` (infrastructure-level; no direct security domain scope)

## Code Map

- `internal/riskplan/planner.go` — plan generation and scoring
- `internal/riskplan/generators.go` — built-in candidate generators
- `internal/riskplan/types.go` — plan, candidate, and scoring types
- `internal/riskplan/diff.go` — plan diffing
- `internal/graphprovenance/provenance.go` — provenance lookup service
- `internal/querycache/cache.go` — cache interface and entry types
- `internal/querycache/memory.go` — in-memory cache implementation
- `internal/querycache/redis.go` — Redis cache implementation
