# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-09 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
  - [x] Add a typed `graph.WeeklyCalibrationReport` model and route handler output.
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
