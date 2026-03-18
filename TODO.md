# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-17 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

## Deep Review Cycle 205 - Graph Store Compliance Evaluation Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left compliance framework evaluation coupled to `CurrentSecurityGraphForTenant(...)`, so report and status endpoints silently dropped graph-derived evidence whenever the runtime exposed only a tenant `GraphStore`.
- [x] Gap: the findings/compliance service only needs a read-only tenant graph view, so it can rebuild from `CurrentSecurityGraphStoreForTenant(...).Snapshot()` without changing any handler contracts.
- [x] Gap: there was no regression proving compliance framework endpoints still return graph-backed control results in store-only runtimes or that the live graph still wins when both sources exist.

### Execution plan
- [x] Teach the findings/compliance service to fall back from the live tenant graph to a snapshot-backed graph view sourced from `CurrentSecurityGraphStoreForTenant(...)`.
- [x] Preserve the live-graph fast path so existing in-memory runtimes do not pay the snapshot restore cost.
- [x] Add store-only and live-graph-preference regressions for compliance framework handlers, then rerun focused API tests, lint, and changed-file validation.

## Deep Review Cycle 205 - Graph Store Stats Path (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `GET /api/v1/graph/stats` dependent on a live tenant graph pointer, so the endpoint returned `503` whenever the runtime exposed only a graph store.
- [x] Gap: the stats endpoint only needs graph metadata, which is already present in `Snapshot.Metadata`, so requiring a live graph was unnecessary coupling.
- [x] Gap: there was no regression proving graph stats still work when the API is constructed with only a `GraphStore`.

### Execution plan
- [x] Teach `graphRisk.GraphStats(...)` to fall back from the live tenant graph to `CurrentSecurityGraphStoreForTenant(...).Snapshot()` and return stats from snapshot metadata.
- [x] Preserve the live-graph fast path so the endpoint avoids snapshot work when the graph is already resident.
- [x] Add store-only and live-graph-preference regressions, then rerun focused API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 205 - Graph Store Platform Knowledge Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left platform knowledge reads bound to `CurrentSecurityGraphForTenant(...)`, so claims, evidence, observations, claim groups, timelines, explanations, and proofs returned `503` whenever the runtime exposed only tenant-scoped `GraphStore` readers.
- [x] Gap: the server already had tenant-aware snapshot helpers for other read-only graph surfaces, but the platform-knowledge service bypassed them and therefore diverged from the rest of the graph-store migration.
- [x] Gap: there was no regression proving platform knowledge read handlers still work when the API is constructed with only a graph store and no live in-memory graph pointer.

### Execution plan
- [x] Teach `serverPlatformKnowledgeService.tenantGraph(...)` to fall back from the live tenant graph to `CurrentSecurityGraphStoreForTenant(...).Snapshot()` and build a read-only graph view from that snapshot.
- [x] Leave the adjudication write path on the writable live graph so the slice stays scoped to read-path migration only.
- [x] Add store-only platform knowledge handler regressions, then rerun API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 205 - Graph Store Platform Snapshot Catalog Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the platform graph snapshot catalog building its synthetic "current" entry from `s.app.SecurityGraph`, so `/api/v1/platform/graph/snapshots` and snapshot lookup by current ID lost the current graph record whenever the runtime exposed only a `GraphStore`.
- [x] Gap: the platform snapshot catalog only needs graph metadata plus persisted report lineage, but it bypassed the existing store snapshot seam and therefore diverged from the other store-backed read paths.
- [x] Gap: there was no store-only API regression proving the platform snapshot catalog still returns the current graph snapshot record when the live in-memory graph pointer is absent.

### Execution plan
- [x] Synthesize the current platform snapshot record from `CurrentSecurityGraphStore().Snapshot(...)` when no live `SecurityGraph` pointer is available, while preserving the persisted-record merge path.
- [x] Add store-only API regressions covering platform snapshot catalog listing and lookup by snapshot ID.
- [x] Re-run focused API tests, lint, and changed-file validation before pushing the next `#392` slice.

## Deep Review Cycle 205 - Graph Store Platform Report Run Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left platform report-run creation and retry rebuilding lineage from `s.app.SecurityGraph`, so queued and retried runs lost graph snapshot lineage whenever the runtime exposed only a `GraphStore`.
- [x] Gap: report section summarization still injected `s.app.SecurityGraph` directly into `ReportSectionBuildOptions`, so section lineage disappeared in store-backed runtimes even after the report execution path itself succeeded.
- [x] Gap: there was no store-only regression proving sync report runs, sync retries, or section lineage still work when the live in-memory graph pointer is absent.

### Execution plan
- [x] Route platform report lineage and section graph resolution through a shared current-platform graph-view helper that falls back to `CurrentSecurityGraphStore().Snapshot(...)`.
- [x] Keep the rest of the platform report execution flow unchanged so this slice only covers read-only lineage and section summarization.
- [x] Add store-only regressions for sync create, sync retry, and artifact section lineage, then rerun focused API tests, lint, and changed-file validation.

## Deep Review Cycle 205 - Graph Store Platform Snapshot And Attack-Path Jobs (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `GET /api/v1/platform/graph/snapshots/current` bound to `s.app.SecurityGraph`, so the endpoint returned `404` whenever the runtime exposed only a graph store and no live in-memory graph pointer.
- [x] Gap: the async attack-path analysis job also closed over `s.app.SecurityGraph`, so store-backed runtimes could not queue attack-path analysis even though a stable snapshot view was available.
- [x] Gap: there was no regression proving either endpoint still works when the server is constructed with only a `GraphStore`.

### Execution plan
- [x] Route current platform snapshot lookup through the shared snapshot-backed tenant graph helper and preserve `404` only for the genuine no-snapshot case.
- [x] Capture a stable snapshot-backed graph view before launching the async attack-path job so the job no longer depends on a live mutable graph pointer.
- [x] Add store-only regressions for both endpoints, then rerun focused API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 203 - Graph Store Risk Engine Feedback Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left outcome feedback, rule discovery, and cross-tenant pattern handlers coupled to `graphRiskEngine()`, which returned `nil` whenever the live `SecurityGraph` pointer was absent even if `GraphStore` snapshots were available.
- [x] Gap: these endpoints are stateful, so simply switching them to a fresh snapshot-backed graph view would have regressed request-to-request behavior in local and test runtimes that do not configure `RiskEngineStateRepo`.
- [x] Gap: there was no store-only API regression proving risk-engine state survives across outcome recording, discovery, and cross-tenant pattern learning when the server is backed only by `GraphStore`.

### Execution plan
- [x] Teach `graphRiskEngine()` to rebuild from `CurrentSecurityGraphStore().Snapshot()` when no live graph pointer exists, while restoring prior risk-engine state from Snowflake or the previous in-memory engine snapshot.
- [x] Keep the handler surface unchanged so outcomes, feedback, rule discovery, and cross-tenant pattern endpoints inherit store-backed behavior without a separate service seam.
- [x] Add store-only API regressions covering feedback, discovery, and cross-tenant pattern flows, then rerun focused API tests and changed-file validation.

## Deep Review Cycle 205 - Tenant Store Intelligence Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left tenant-scoped graph intelligence and tenant-scoped risk-report paths dependent on a live in-memory tenant shard, so those endpoints returned `503` when the runtime exposed only tenant `GraphStore` readers.
- [x] Gap: `graphIntelligenceService` only surfaced a raw `*graph.Graph`, which meant the intelligence handlers could not fall back to `GraphStore.Snapshot()` the way the other `#392` read-path slices already do.
- [x] Gap: there was no regression proving tenant-scoped intelligence lookups or tenant-scoped risk reports still work when only tenant-scoped graph stores are available.

### Execution plan
- [x] Route `graphIntelligenceService` current-graph resolution through tenant-aware live-graph or store-snapshot lookup instead of a raw global graph pointer.
- [x] Teach `currentTenantRiskEngine(...)` to build from the shared tenant graph-view helper so tenant-scoped risk reports work without a live in-memory shard.
- [x] Add tenant-scoped store-only regressions for graph intelligence and risk report handlers, then rerun focused and changed-file API validation.

## Deep Review Cycle 203 - Graph Store Policy Evaluation Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `POST /api/v1/policy/evaluate` using the raw `s.app.SecurityGraph` pointer for proposed-change propagation analysis, so store-backed runtimes would deny the analysis path even when a graph snapshot was available.
- [x] Gap: the graph-store migration already introduced a shared snapshot-backed tenant graph helper, but policy evaluation still bypassed it and therefore diverged from the other read-only analysis endpoints.
- [x] Gap: there was no regression proving policy evaluation with `proposed_change` still returns propagation results when the server is constructed with only a `GraphStore`.

### Execution plan
- [x] Route proposed-change propagation analysis in `policy/evaluate` through the shared snapshot-backed tenant graph view helper.
- [x] Add a store-only API regression for policy evaluation so the proposed-change path no longer depends on a live in-memory graph pointer.
- [x] Re-run focused API tests, lint, and changed-file validation before pushing the next `#392` slice.

## Deep Review Cycle 199 - API Endpoint Graph Substrate (2026-03-18)

### Review findings
- [x] Gap: issue `#242` had no first-class `api_endpoint` node kind, so URI-backed workloads were still represented only as generic functions or services and could not participate in API-specific graph queries.
- [x] Gap: the graph builder already knew about public Cloud Run workloads through `uri` and `ingress`, but it never materialized those endpoints as graph entities or linked them back to the serving workload.
- [x] Gap: incremental CDC rebuilds would have diverged from full builds for endpoint projection unless the endpoint substrate was added to both rebuild paths.

### Execution plan
- [x] Add a first-class `api_endpoint` node kind plus a `serves` edge kind and register both in the graph ontology.
- [x] Project endpoint nodes from existing URI-backed workloads, starting with Cloud Run data already present in the builders, and connect public endpoints to the existing `internet` entry node through the normal exposure pipeline.
- [x] Add full-build and CDC regression coverage, then regenerate ontology docs and rerun the graph validation guardrails.

## Deep Review Cycle 202 - Graph Store Analysis Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `evaluate-change` and schema-health reading directly from `s.app.SecurityGraph`, so those analysis endpoints would fail outright in a store-backed runtime with no live graph pointer.
- [x] Gap: the first store-backed risk and visualization slices proved the snapshot-view helper, but these two read-only analysis handlers were still bypassing it and therefore skipping tenant-aware store fallback.
- [x] Gap: there was no regression proving change-propagation or schema-health API behavior still works when only `GraphStore` is available.

### Execution plan
- [x] Route graph change-propagation and schema-health handlers through the shared snapshot-backed graph view helper.
- [x] Add store-only HTTP regressions for both handlers so the API surface no longer depends on a raw in-memory graph.
- [x] Re-run focused API tests, lint, and changed-file validation before pushing the next `#392` slice.

## Deep Review Cycle 202 - Graph Store Simulation Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `graph/simulate` and org reorg simulation hard-wired to `s.app.SecurityGraph`, so those endpoints would fail once the runtime exposes only a graph store.
- [x] Gap: both handlers are read-only analysis flows, but they still bypassed the snapshot-backed tenant graph view already used by the other store-migration slices.
- [x] Gap: there was no API regression proving either simulation endpoint still works when the server is constructed with only a `GraphStore`.

### Execution plan
- [x] Route graph simulation and reorg simulation through the snapshot-backed tenant graph view.
- [x] Add store-only API regressions for both simulation endpoints.
- [x] Re-run focused and changed-file API validation before pushing the next `#392` slice.

## Deep Review Cycle 198 - Organizational Policy Graph Substrate (2026-03-17)

### Review findings
- [x] Gap: issue `#256` still had no first-class graph primitive for organizational policies, so policy registry state could not plug into the existing person and department hierarchy.
- [x] Gap: employee policy acknowledgments were not modeled in the graph, which blocked current-version re-acknowledgment tracking and left compliance evidence disconnected from HR-synced employees.
- [x] Gap: department-level acknowledgment reporting had no reusable graph helper, even though the graph already stores department membership and org-structure edges.

### Execution plan
- [x] Add a first-class `policy` node kind plus an `acknowledged` edge kind and register them in the graph ontology.
- [x] Add graph helper APIs to write policies, scope required acknowledgments to departments and people, and record person acknowledgments against the active policy version.
- [x] Add rollup coverage that computes department-level acknowledgment gaps from existing membership edges and validates re-acknowledgment on policy version updates.

## Deep Review Cycle 198 - CEL Policy Migration Parity (2026-03-17)

### Review findings
- [x] Gap: issue `#212` still left 466 resource-condition repository policies in implicit legacy mode with no `condition_format`, so CEL runtime coverage existed in code but not in the shipped policy corpus.
- [x] Gap: the legacy parser and CEL converter still failed on real repository patterns including `IS NULL`, `IS NOT NULL`, single `=`, `not_contains`, `ends_with`, object-literal containment, bucket-public-reference predicates, field-to-field comparisons, and `NOW() - INTERVAL` expressions.
- [x] Gap: there was no repository-level invariant proving resource-condition policies had actually migrated to CEL, so future policy additions could silently regress the migration.

### Execution plan
- [x] Extend legacy evaluation and CEL conversion to cover the remaining repository condition shapes, including object containment, relative-time parsing, bucket-public-reference checks, and field-reference operands.
- [x] Add focused regression coverage for legacy evaluation, legacy-to-CEL round-trips, and a repository invariant requiring `condition_format: cel` for resource-condition policies.
- [x] Bulk-convert the repository condition-policy corpus to CEL with explicit `condition_format: cel`, then re-run policy tests and bundle validation.

## Deep Review Cycle 197 - Configurable Operational Timeouts (2026-03-17)

### Review findings
- [x] Gap: issue `#217` still left API request deadlines, max request body size, shutdown waits, health checks, and several app-side operational budgets hardcoded in transport and lifecycle code instead of flowing through validated config.
- [x] Gap: `LoadConfig()` accepted the surrounding runtime knobs but had no validation for timeout/resource feasibility, so obviously broken values such as zero deadlines or a health check that outlived the enclosing API request could boot and fail later.
- [x] Gap: the generated environment variable docs did not describe these operational budgets, which meant deploy-time tuning would stay tribal knowledge even after the code paths were made configurable.

### Execution plan
- [x] Add explicit app config fields plus default helpers for the operational timeouts and body limit currently hardcoded in API, shutdown, threat intel, graph consistency, risk-engine state, and ticketing validation paths.
- [x] Route the affected API and app lifecycle call sites through the config-backed helpers and add startup validation for positive bounds plus simple feasibility checks.
- [x] Regenerate config docs and add focused tests that prove the new env vars load, validate, and influence runtime behavior.

## Deep Review Cycle 196 - Graph Writeback Service Seam (2026-03-17)

### Review findings
- [x] Gap: issue `#210` still left the graph writeback handlers reaching directly through `s.app` for graph mutation, lifecycle webhook emission, and identity calibration reads, so those endpoints could not be tested against a narrow service stub.
- [x] Gap: the handler layer still owned mutation-side orchestration for knowledge writes, annotation writes, identity resolution/review flows, and recommendation actuation, which kept transport logic tangled with graph write semantics.
- [x] Gap: `NewServerWithDependencies` still had no writeback-family seam, so tests for these endpoints had to construct a live mutable graph runtime even when they only needed request parsing and response wiring.

### Execution plan
- [x] Add a dedicated `graphWritebackService` interface plus a default adapter that owns mutation, lifecycle event emission, and identity calibration reads.
- [x] Route the graph writeback handler family through the new service so the HTTP layer no longer reaches through `s.app` for graph mutation and lifecycle side effects.
- [x] Add `NewServerWithDependencies` stub tests covering knowledge writes, identity writeback flows, and recommendation actuation without a full `*app.App`.
- [x] Re-run focused and changed-file API validation, then push the stacked branch once the seam compiles cleanly.

## Deep Review Cycle 196 - Platform Knowledge Service Seam (2026-03-17)

### Review findings
- [x] Gap: issue `#210` still left the platform knowledge handlers wired straight to graph plumbing and snapshot-store lookup, so read endpoints could not be tested against a narrow service stub.
- [x] Gap: the claim adjudication handler still reached through `s.app` for a mutable graph while the surrounding read handlers used ad hoc graph access, which kept the family split across package functions and raw runtime state.
- [x] Gap: snapshot-based knowledge diffs rebuilt graph views directly in the handler, which meant the HTTP layer still owned tenant scoping and snapshot-comparison behavior instead of a typed API seam.

### Execution plan
- [x] Add a dedicated `platformKnowledgeService` interface plus a default adapter backed by the current security graph and snapshot store.
- [x] Route platform knowledge claim, artifact, claim-group, proof, diff, and adjudication handlers through the service seam instead of direct graph access.
- [x] Add `NewServerWithDependencies` tests that stub only the platform knowledge family without constructing a full `*app.App`.
- [x] Re-run focused and changed-file API tests, lint, and push the branch once the seam compiles cleanly.

## Deep Review Cycle 196 - Sync Handler Service Seam (2026-03-17)

### Review findings
- [x] Gap: issue `#210` still left the sync handler family coupled directly to `s.app.Snowflake`, `s.app.SecurityGraphBuilder`, and live graph-update orchestration, so those endpoints could not be tested against a narrow dependency stub.
- [x] Gap: the provider-specific sync runners were already factored behind package-level helpers, but the HTTP layer still owned post-sync graph mutation status shaping and therefore kept sync behavior split across transport and runtime concerns.
- [x] Gap: `NewServerWithDependencies` still had no way to supply a sync-only seam, which meant tests for this family had to boot a full in-memory app even when they only needed normalized request parsing and response wiring.

### Execution plan
- [x] Add a dedicated `syncHandlerService` interface plus a default adapter for relationship backfill and provider sync workflows.
- [x] Move post-sync graph update orchestration into the sync adapter so handlers depend only on the seam.
- [x] Add `NewServerWithDependencies` tests that stub only the sync family and prove normalized request options reach the service layer.
- [x] Re-run focused and changed-file API validation, then push the branch once the seam is green.

## Deep Review Cycle 195 - Findings And Compliance Handler Service Seam (2026-03-17)

## Deep Review Cycle 196 - Graph Risk Handler Service Seam (2026-03-17)

### Review findings
- [x] Gap: issue `#210` still left the graph-risk handler family reaching directly through `s.app` and ad hoc server state for graph metadata, rebuilds, risk reports, toxic-combination analysis, attack-path simulation, privilege-escalation checks, peer-group analysis, and effective-permission reads.
- [x] Gap: the risk family had route coverage but no `NewServerWithDependencies` seam tests proving those handlers can run against a narrow graph-risk stub without a live `*app.App`, `SecurityGraph`, or `SecurityGraphBuilder`.
- [x] Gap: the first traversal endpoints had already moved to `GraphStore`, but the rest of the risk surface still mixed store-backed and pointer-backed reads in one handler file, which kept future backend migration and handler testing inconsistent.

### Execution plan
- [x] Add a dedicated graph-risk handler service in `internal/api/` that owns graph stats, store-backed traversals, rebuild orchestration, risk-report evaluation/persistence, attack-path simulation, privilege-escalation checks, peer-group analysis, and effective-permission reads.
- [x] Route the graph-risk handler family through the new service so the HTTP layer no longer reaches directly through `s.app` or server-side risk-engine state helpers.
- [x] Add `NewServerWithDependencies` stub tests covering traversal, rebuild, risk-intelligence, and access-analysis endpoints without a full app.

### Review findings
- [x] Gap: issue `#210` still left the findings/compliance handler family reaching directly through `s.app` for tenant findings stores, warehouse scans, policy-backed compliance reporters, graph-backed compliance evaluation, and logger warnings.
- [x] Gap: that family had route coverage, but not `NewServerWithDependencies` tests proving findings, scan, reporting, and compliance status endpoints can run against a narrow stub without constructing a full `*app.App`.
- [x] Gap: tenant-aware findings access and graph-aware compliance evaluation were implemented as server helpers, which kept the family testable only through the broad dependency bundle instead of a typed seam.

### Execution plan
- [x] Add a dedicated findings/compliance handler service in `internal/api/` that owns tenant-scoped findings store access, scan orchestration, reporter construction, framework evaluation, and warning logging.
- [x] Route the findings, reporting, and compliance handlers through the new family service so the handler file no longer reaches through `s.app` for warehouse, scanner, policy, graph, or logger access.
- [x] Add `NewServerWithDependencies` stub tests covering findings list, findings scan, executive summary, and compliance status endpoints without a full app.

## Deep Review Cycle 196 - Graph Store Query Paths (2026-03-17)

### Review findings
- [x] Gap: issue `#392` still left the highest-traffic graph traversal endpoints calling raw `*graph.Graph` helpers directly, so the new store seam existed on paper but not on the HTTP read path.
- [x] Gap: `ReverseAccess` was not part of `graph.GraphStore`, which meant one of the core graph risk traversals would still need pointer-specific plumbing in every future backend implementation.
- [x] Gap: API tests did not prove that traversal handlers could run with only a `GraphStore` and no live raw graph pointer, so the migration seam could regress without detection.

### Execution plan
- [x] Extend `graph.GraphStore` and the live app-backed store wrapper with `ReverseAccess` parity.
- [x] Route tenant-scoped blast-radius, cascading-blast-radius, reverse-access, and blast-radius visualization handlers through `CurrentSecurityGraphStoreForTenant`.
- [x] Add regression coverage proving store-backed traversal handlers succeed when the server only has a `GraphStore` runtime and no raw `SecurityGraph` pointer.

## Deep Review Cycle 199 - Graph Store Visualization Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left Mermaid attack-path, toxic-combination, and report handlers coupled to raw `*graph.Graph` pointers, so the store seam stopped at JSON traversal reads instead of covering the rest of the graph read surface.
- [x] Gap: those handlers only need a read-only graph view, but they bypassed the existing `GraphStore.Snapshot()` contract and would fail in any future backend that does not expose an in-memory graph pointer.
- [x] Gap: API tests only proved store-backed traversal JSON endpoints, so visualization/report routes could regress back to pointer-only behavior without detection.

### Execution plan
- [x] Materialize read-only graph views for visualization handlers via `GraphStore.Snapshot()` and `graph.GraphViewFromSnapshot(...)`.
- [x] Route Mermaid attack-path, toxic-combination, and report handlers through the store-backed view path instead of `s.app.SecurityGraph`.
- [x] Add store-only API regression coverage for the visualization/report handlers so they succeed with no raw live graph pointer.

## Deep Review Cycle 199 - Graph Store Risk Analysis Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the JSON risk-analysis endpoints backed by raw `*graph.Graph` reads in `serverGraphRiskService`, so the store seam stopped at traversals and Mermaid exports instead of covering the rest of the read-only analysis surface.
- [x] Gap: toxic combination analysis, attack-path simulation, permission diffing, and peer-group analysis only require a stable read-only graph view, but they bypassed `GraphStore.Snapshot()` and would fail against a future backend with no direct in-memory pointer.
- [x] Gap: API regression coverage did not prove these analysis endpoints could execute with only a `GraphStore`, so pointer-coupled behavior could silently return during the Neptune/Spanner migration.

### Execution plan
- [x] Materialize analysis graphs in `serverGraphRiskService` from `GraphStore.Snapshot()` plus `graph.GraphViewFromSnapshot(...)`.
- [x] Route toxic-combination, attack-path, simulate-fix, chokepoint, privilege-escalation, peer-group, effective-permissions, and compare-permissions analysis through that snapshot-backed view path.
- [x] Add store-only API regression coverage for the migrated analysis endpoints.

## Deep Review Cycle 195 - Graph Store Abstraction (2026-03-17)

### Review findings
- [x] Gap: issue `#392` still left app and API graph access hard-wired to raw `*graph.Graph` pointers, so every future Neptune/Spanner slice would have to peel apart direct in-memory reads and writes before a backend seam even existed.
- [x] Gap: the graph package had no backend-shaped contract for CRUD, snapshot, or traversal parity, which made it hard to prove an external store could match the current in-memory semantics without copying call sites first.
- [x] Gap: tenant-scoped graph readers had no live store wrapper, so any first abstraction would have gone stale across graph swaps unless callers re-fetched raw pointers manually.

### Execution plan
- [x] Add a `graph.GraphStore` contract and make the in-memory `*graph.Graph` satisfy it through thin context-aware wrappers over the existing CRUD, snapshot, and traversal primitives.
- [x] Expose live and tenant-scoped graph-store accessors from the app/runtime layer so future API and app slices can depend on a backend seam that survives graph swaps.
- [x] Add regression coverage for store CRUD/traversal parity, context cancellation, live-store graph swaps, and API dependency wiring.

## Deep Review Cycle 195 - Typed Attack Sequence Property Storage (2026-03-17)

### Review findings
- [x] Gap: issue `#385` still left `attack_sequence` nodes fully map-backed even though they carry a fixed temporal/runtime schema and are created in a hot runtime correlation path.
- [x] Gap: clone, snapshot, and temporal query paths only preserved typed storage for observations, so extending compact storage to another node kind would silently regress if those paths were not updated together.
- [x] Gap: there was no regression coverage proving compact `attack_sequence` storage preserved property mutation validation, snapshot restore behavior, and materialized property export.

### Execution plan
- [x] Add compact typed storage for stable `attack_sequence` fields with on-demand `PropertyValue` and `PropertyMap` materialization.
- [x] Extend graph clone, snapshot restore, and temporal readers to preserve the new typed property carrier.
- [x] Add regression and benchmark coverage for compact live storage, property mutation semantics, snapshot restore, and typed-vs-map property reads.

## Deep Review Cycle 195 - HA Graph Writer Lease And Follower Fencing (2026-03-17)

### Review findings
- [x] Gap: issue `#355` still assumed one local graph writer, so a second Cerebro instance could race the first and mutate the security graph without any split-brain fence.
- [x] Gap: persisted graph snapshots could restore a follower-readable graph after restart, but the app had no explicit writer election path to keep followers read-only until they safely promote.
- [x] Gap: TAP ingest and graph mutation paths had no shared HA control point, so even if leader election existed later, stale writers could keep ingesting and mutating after lease loss.

### Execution plan
- [x] Add an app-owned graph writer lease manager with NATS KV-backed acquire/renew/release semantics, status reporting, and explicit follower versus writer role tracking.
- [x] Fence security-graph rebuild, incremental apply, ad hoc mutation, DSPM enrichment, and TAP consumer startup behind the writer lease so stale writers demote cleanly.
- [x] Start the app in follower mode from the recovered snapshot when the lease is held elsewhere, and promote by rebuilding plus starting TAP consumption only after local lease acquisition.
- [x] Add TDD coverage for write fencing, deferred consumer startup, and NATS-backed lease acquire/renew/failover, then regenerate config docs and rerun focused plus broad validation.

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

## Deep Review Cycle 195 - App Graph And Detection Tracing (2026-03-17)

### Review findings
- [x] Gap: issue `#360` still lost event identity once control moved from the consumer handler into app-layer graph mutation, so downstream graph spans could not be tied back to the original event or tenant.
- [x] Gap: the live graph mutation path rebuilt indexes as an opaque side effect, which meant trace data could not distinguish mutation cost from index rebuild cost.
- [x] Gap: runtime detections still evaluated rules without emitting a dedicated span, so end-to-end traces stopped before the detection phase that actually produced findings.

### Execution plan
- [x] Add a telemetry context helper that carries event attributes from the consumer handler into downstream child spans without widening every handler signature.
- [x] Emit `cerebro.graph.mutate` and nested `cerebro.graph.index_update` spans from `MutateSecurityGraphMaybe` with before/after graph counts and mutation totals.
- [x] Emit `cerebro.detection.evaluate` spans from the runtime detection engine and add TDD coverage for consumer-to-child attribute propagation plus graph/detection tracing.

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

## Deep Review Cycle 201 - Graph Store Org Analytics Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the org analytics handlers backed by raw `s.app.SecurityGraph` reads, so onboarding plans, meeting insights, information-flow queries, and org graph recommendations would fail in a store-backed runtime with no live graph pointer.
- [x] Gap: those handlers only need a stable read-only graph view, but they still bypassed the existing `GraphStore.Snapshot()` plus `graph.GraphViewFromSnapshot(...)` seam already used by the other migration slices.
- [x] Gap: API regressions did not prove these org analytics endpoints could execute with only a `GraphStore`, so pointer-only behavior could slip back in unnoticed.

### Execution plan
- [x] Route org onboarding, meeting insights, meeting analysis, information flow, clock speed, and recommended-connections handlers through the snapshot-backed tenant graph view.
- [x] Add store-only API regressions covering the migrated org analytics handlers.

## Deep Review Cycle 200 - Graph Store Org Expertise Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the org expertise and team recommendation endpoints hard-wired to `s.app.SecurityGraph`, so they could not run against a store-backed graph runtime once the raw in-memory graph pointer is absent.
- [x] Gap: the existing graph-store migration slices already covered traversal, visualization, and risk analysis paths, but these org knowledge endpoints still bypassed `GraphStore.Snapshot()` entirely.
- [x] Gap: there was no regression proving the org expertise endpoints still behave correctly when the server is constructed with only a `GraphStore` and no raw graph.

### Execution plan
- [x] Add a shared tenant-scoped graph-view helper that restores read-only graph views from `GraphStore.Snapshot()` when a store is present.
- [x] Route `whoKnows` and `recommendTeam` through the snapshot-backed graph view instead of directly reading `s.app.SecurityGraph`.
- [x] Add store-only API regressions covering both org expertise endpoints.

## Deep Review Cycle 202 - Graph Store Entity Impact Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left entity cohort lookup, outlier scoring, and impact-path analysis hard-wired to the raw in-memory graph pointer, so those endpoints would fail once the runtime provides only a graph store.
- [x] Gap: this handler family only requires a read-only graph view, but it still bypassed the existing snapshot-backed tenant graph seam already used by the earlier graph-store API slices.
- [x] Gap: there was no API regression proving these entity-impact endpoints still work when the server is constructed with only a `GraphStore` and no live `SecurityGraph`.

### Execution plan
- [x] Route the entity-impact handlers through the snapshot-backed tenant graph view.
- [x] Add store-only API regressions for cohort, outlier-score, and impact-analysis.
- [x] Re-run focused and changed-file API validation before pushing the branch.

## Deep Review Cycle 204 - Graph Store Workload Scan Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the platform workload-scan target endpoint hard-wired to `CurrentSecurityGraph()`, so target prioritization would fail whenever the runtime exposes only a graph store and no live in-memory graph pointer.
- [x] Gap: the workload-scan prioritization path is read-only and only needs the tenant-scoped graph view helper that already restores `GraphStore.Snapshot()` into a stable graph view for the other migration slices.
- [x] Gap: there was no regression proving workload-scan target prioritization still works, or returns `503`, when the server runs with only a graph store.

### Execution plan
- [x] Route the workload-scan target handler through the snapshot-backed tenant graph view helper.
- [x] Add store-only API regressions for the workload-scan happy path and missing-snapshot `503` path.

## Deep Review Cycle 203 - Graph Store Platform Entity Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the platform entity list, search, suggest, detail, point-in-time, and diff handlers tied to `CurrentSecurityGraphForTenant(...)`, so those endpoints would fail whenever the runtime exposes only a graph store and no live graph pointer.
- [x] Gap: these handlers only need a read-only tenant-scoped graph view, but they were still bypassing the snapshot-backed tenant graph helper added by the earlier graph-store slices.
- [x] Gap: there was no regression proving the platform entity family still works when the server is constructed with only a `GraphStore`.

### Execution plan
- [x] Route the platform entity read handlers through the tenant graph view helper so they restore from `GraphStore.Snapshot()` when needed.
- [x] Add store-only API regressions covering list, search, suggest, detail, point-in-time reconstruction, and diff.
- [x] Re-run focused and changed-file API validation before pushing the branch.
