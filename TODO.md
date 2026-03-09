# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-09 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
