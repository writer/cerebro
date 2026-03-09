# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-09 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
