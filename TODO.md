# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-10 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

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
  - [ ] add real per-section duration capture instead of synthetic timing guesses
  - [ ] add cache-hit/cache-miss and retry-backoff metadata where the runtime actually has those signals
  - [ ] add per-section partial-failure classification separate from truncation
- [ ] Section provenance deepening:
  - [ ] expose supporting edge IDs and bitemporal windows for section lineage samples
  - [ ] add configurable lineage sample limits by report family
  - [ ] materialize high-value section lineage back into graph annotations/outcomes where it creates leverage
- [ ] Section contract generation:
  - [ ] derive section lineage/materialization schema fragments from one canonical contract source
  - [ ] generate report-definition diff summaries when section metadata fields evolve
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
