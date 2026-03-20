# Cerebro Intelligence Layer Execution TODO

Last updated: 2026-03-19 (America/Los_Angeles)
Owner: @haasonsaas
Mode: implement in full, keep CI green
Status: executed end-to-end via PR workflow

## Deep Review Cycle 248 - TAP Schema Handler Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_mapping.go` still mixed declarative mapping logic with TAP schema registration, so schema runtime handling remained bundled into the mapper-specific file even after the schema parse helpers moved out.
- [x] Gap: schema registration is a separate concern from declarative mapper setup and apply flow, and it can move into its own file without widening graph mutation behavior.
- [x] Gap: existing coverage proved successful schema registration, but there was no direct regression ensuring an empty schema payload remains a no-op and does not register standalone edge kinds or allocate a graph.

### Execution plan
- [x] Move `handleTapSchemaEvent(...)` into a dedicated TAP schema handler file with small registration helpers.
- [x] Leave `app_stream_consumer_mapping.go` focused on declarative mapper setup and apply flow.
- [x] Add an empty-schema-payload no-op regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 247 - TAP Schema Parse Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_parse.go` still mixed TAP schema registration parsing with generic event-type decoding and activity-target helpers, so schema-only normalization remained bundled into the last broad parse file after the business, interaction, and activity splits.
- [x] Gap: the schema entity-definition parsing, category inference, and capability/relationship normalization logic is cohesive enough to live in its own helper file without touching dispatch or graph mutation flow.
- [x] Gap: existing coverage exercised schema entity parsing broadly, but there was no direct regression proving integration-name fallback still works from the event type when the payload omits provider metadata.

### Execution plan
- [x] Move the TAP schema-specific parse helpers into a dedicated `app_stream_consumer_schema_parse.go` file.
- [x] Leave generic TAP type decoding and activity-target parsing in `app_stream_consumer_parse.go`.
- [x] Add a focused integration-fallback regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 248 - Post-Sync Graph Update Timeout Config (2026-03-19)

### Review findings
- [x] Gap: issue `#217` still left the post-sync graph apply timeout hardcoded in `internal/api/server_handlers_sync.go`, so one operational deadline still bypassed config/env control.
- [x] Gap: the sync timeout was already exercised by tests through a package global override, which made the HTTP layer depend on mutable process state instead of the app config surface that `#217` is centralizing.
- [x] Gap: generated env-var docs and startup validation did not mention any post-sync graph update timeout control, so operators had no documented way to tune this path.

### Execution plan
- [x] Add a dedicated `GRAPH_POST_SYNC_UPDATE_TIMEOUT` config/env control with the same default behavior as today.
- [x] Route post-sync graph applies through the config helper and update the focused sync timeout regression to set config instead of mutating a package global.
- [x] Regenerate config docs and rerun focused `internal/app` and `internal/api` validation before opening the PR.

## Deep Review Cycle 246 - TAP Activity Modeling Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_modeling.go` still bundled all activity-specific node-kind and property-shaping logic with business modeling and generic coercion helpers, which kept one TAP concern family unnecessarily broad even after the activity parse split.
- [x] Gap: the activity-kind derivation and property-shaping helpers are cohesive on their own and belong with the TAP activity path rather than the shared mixed modeling file.
- [x] Gap: existing coverage exercised activity node-kind derivation, but there was no direct regression around the fallback action-to-status mapping that feeds several activity kinds.

### Execution plan
- [x] Move the TAP activity-specific modeling helpers into a dedicated `app_stream_consumer_activity_modeling.go` file.
- [x] Leave business modeling and generic coercion utilities in `app_stream_consumer_modeling.go`.
- [x] Add a focused activity-status fallback regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 245 - TAP Identity Resolve Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_runtime.go` still mixed graph readiness/runtime concerns with TAP identity-resolution state, so the runtime file was carrying per-event identity logic that issue `#211` explicitly wants separated from coordination concerns.
- [x] Gap: the scoped-resolve-graph helpers and email canonicalization path are cohesive on their own and can move into a dedicated identity-resolution file without changing event dispatch or graph-init semantics.
- [x] Gap: existing coverage proved scoped resolve-graph preference, but there was no regression confirming that email canonicalization still works without allocating a live graph when the app has no current graph loaded.

### Execution plan
- [x] Move the TAP identity-resolution helpers out of the runtime file into a dedicated helper file.
- [x] Leave only graph-init and graph-ready waiting logic in `app_stream_consumer_runtime.go`.
- [x] Add a focused no-live-graph canonicalization regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 244 - TAP Business Parse Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_business.go` still mixed business-event planning with mutation and correlation-refresh control flow, so another TAP path remained only partially decomposed for issue `#211`.
- [x] Gap: the business planner is graph-independent apart from shaping graph nodes and edges, which makes it a clean candidate for its own parse-focused file beside the activity and interaction splits.
- [x] Gap: existing coverage exercised the snapshot-heavy update path, but there was no focused no-graph regression proving the planner still works from the scalar `id` fallback and preserves deleted-event inactivity semantics.

### Execution plan
- [x] Move the business event plan type and builder into a dedicated parse-focused file.
- [x] Leave mutation application and correlation refresh control flow in `app_stream_consumer_business.go`.
- [x] Add a focused scalar-id/deleted-flag regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 243 - TAP Activity Parse Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_activity.go` still mixed activity-event planning with graph mutation/apply logic, so one TAP path remained only partially aligned with issue `#211`'s parse-vs-mutation split.
- [x] Gap: the activity planner depends only on event payload normalization plus graph metadata shaping, not on a live graph instance, so it should live in its own parse-focused file beside the earlier interaction split.
- [x] Gap: coverage proved the structured actor/target object path, but there was no focused regression showing the planner still builds an activity event from the scalar fallback fields (`actor_email`, `entity_id`) without a graph.

### Execution plan
- [x] Move the activity event plan type and builder into a dedicated parse-focused file.
- [x] Leave the mutation/apply path in `app_stream_consumer_activity.go` so runtime writes stay isolated from parse-only helpers.
- [x] Add a focused scalar-fallback planner regression and rerun targeted `internal/app` validation before opening the PR.

## Deep Review Cycle 242 - TAP Interaction Parse Split (2026-03-19)

### Review findings
- [x] Gap: `internal/app/app_stream_consumer_interaction.go` still mixed interaction-event parsing/planning with graph mutation and person-node upsert logic, which left one TAP subpath misaligned with issue `#211`'s goal of separating event parsing from mutation behavior.
- [x] Gap: the interaction planner and participant-normalization helpers are fully graph-independent, so they should live in their own parse-focused file and stay directly testable without a live graph.
- [x] Gap: coverage already proved the interaction event plan can be built without a graph, but there was no direct regression around participant deduplication across the scalar and slice fallback fields that the parser accepts.

### Execution plan
- [x] Move the interaction event plan builder and participant/duration/weight parsing helpers into a dedicated parse-focused file.
- [x] Leave the mutation path and person-node upsert logic in `app_stream_consumer_interaction.go` so write behavior stays isolated from parse-only helpers.
- [x] Add a focused no-graph participant deduplication regression and rerun the targeted `internal/app` validation gate before opening the PR.

## Deep Review Cycle 235 - Graph Rule Discovery Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the graph rule-discovery run/list/decision handlers reaching directly into the risk-engine lifecycle from the HTTP layer.
- [x] Gap: those three endpoints form a compact approval-workflow family with stable request parsing and response semantics, which makes them a low-risk extraction seam.
- [x] Gap: there was no constructor-level regression proving the rule-discovery handlers can execute through `NewServerWithDependencies(...)` with only a narrow typed discovery stub.

### Execution plan
- [x] Add a dedicated `graphRuleDiscoveryService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route run/list/decision handlers through that service while preserving unavailable, not-found, and bad-request behavior.
- [x] Add focused service-stub coverage and rerun targeted API validation before opening the PR.

## Deep Review Cycle 234 - Ticketing Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the ticket list/detail/mutation handlers reaching directly into `s.app.Ticketing`, so that family could not be exercised through `NewServerWithDependencies(...)` with only a narrow typed stub.
- [x] Gap: the ticketing endpoints already form a compact operational family with stable request normalization and existing no-provider semantics, which makes them a clean extraction seam.
- [x] Gap: there was no constructor-level regression proving those handlers can execute without a concrete `*ticketing.Service` on `*app.App`.

### Execution plan
- [x] Add a dedicated `ticketingService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route ticket list/detail/create/update/comment/close handlers through that service while preserving the existing `200 empty` list behavior and `503` mutation behavior when no provider is configured.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 233 - Graph Advisory Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left `POST /api/v1/graph/evaluate-change`, `GET /api/v1/org/expertise/queries`, and `POST /api/v1/org/team-recommendations` reaching directly into graph view resolution and graph package helpers from the HTTP layer.
- [x] Gap: those three endpoints form a compact graph advisory family with stable request validation and small dependency surfaces, making them a clean extraction seam without touching the larger graph risk or writeback services.
- [x] Gap: there was no constructor-level regression proving those handlers can execute through `NewServerWithDependencies(...)` with only a narrow typed advisory stub.

### Execution plan
- [x] Add a dedicated `graphAdvisoryService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route evaluate-change, who-knows, and team-recommendation handlers through that service while preserving existing validation and error semantics.
- [x] Add focused service-stub coverage plus one store-backed regression and rerun targeted API validation before opening the PR.

## Deep Review Cycle 231 - Platform Workload Scan Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left `/api/v1/platform/workload-scan/targets` reaching directly into the shared graph view plus `s.app.ExecutionStore` and `s.app.Config`, so that endpoint could not be exercised through `NewServerWithDependencies(...)` with only a narrow stub.
- [x] Gap: workload-scan target prioritization already sits behind a compact dependency surface, which makes it a clean extraction seam without dragging the larger platform report handlers into the same PR.
- [x] Gap: there was no constructor-level regression proving the endpoint can execute with only a typed workload-scan service and no concrete execution store or graph wiring on `*app.App`.

### Execution plan
- [x] Add a dedicated `platformWorkloadScanService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route `/api/v1/platform/workload-scan/targets` through that service while preserving request validation and error semantics.
- [x] Add focused service-stub regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 230 - Platform Execution Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left `/api/v1/platform/executions` reaching directly into `s.app.Config` and `s.app.ExecutionStore`, so that handler could not be exercised through `NewServerWithDependencies(...)` with only a narrow stub.
- [x] Gap: execution listing already sits on a small dependency surface, which makes it a low-risk extraction seam that preserves the existing query validation and execution-store fallback behavior.
- [x] Gap: there was no constructor-level regression proving the handler can execute with a typed execution-listing service and no concrete execution store on `*app.App`.

### Execution plan
- [x] Add a dedicated `platformExecutionService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route `/api/v1/platform/executions` through that service while preserving not-configured, unavailable, and list-failure semantics.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 232 - Entity Impact Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the entity cohort, outlier-score, and impact-analysis handlers reaching directly into graph resolution helpers inside the HTTP layer, so that family could not be exercised through `NewServerWithDependencies(...)` with only a narrow typed stub.
- [x] Gap: those endpoints already form a compact graph-read-only family with stable validation and not-found semantics, which makes them a clean extraction seam.
- [x] Gap: there was no constructor-level regression proving the handlers can execute against a dedicated service dependency without a concrete live graph on `*app.App`.

### Execution plan
- [x] Add a dedicated `entitiesImpactService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the entity cohort, outlier-score, and impact-analysis handlers through that service while preserving validation, not-found, and service-unavailable behavior.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 228 - Scheduler Operations Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the scheduler status/list/run/enable/disable handlers reaching directly into `s.app.Scheduler`, `s.app.Webhooks`, and `s.app.Logger`, so that handler family could not be exercised through `NewServerWithDependencies(...)` with only a narrow stub.
- [x] Gap: the scheduler operations endpoints already form a cohesive admin handler family with stable request normalization and existing unavailable/conflict/not-found semantics, which makes them a clean extraction seam.
- [x] Gap: there was no constructor-level regression proving those handlers can execute using only a typed scheduler-operations service dependency and no concrete scheduler on `*app.App`.

### Execution plan
- [x] Add a dedicated `schedulerOperationsService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the scheduler status/list/run/enable/disable handlers through that service while preserving unavailable, conflict, and not-found behavior.
 - [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 229 - Lineage Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the `/lineage` handlers reaching directly into `s.app.Lineage`, so that family could not be exercised through `NewServerWithDependencies(...)` with only a narrow stub.
- [x] Gap: the lineage read and drift endpoints form a compact handler family with stable request normalization and existing unavailable/not-found behavior, making them a clean extraction seam.
- [x] Gap: there was no constructor-level regression proving those handlers can execute without a concrete `*lineage.LineageMapper` on `*app.App`.

### Execution plan
- [x] Add a dedicated `lineageService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the `/lineage` handlers through that service without changing validation or status semantics.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 227 - RBAC Admin Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the `/rbac` admin handlers reaching directly into `s.app.RBAC` and `s.app.Webhooks`, so that family could not be exercised through `NewServerWithDependencies(...)` with only a narrow stub.
- [x] Gap: the `/rbac` routes form a coherent handler family with stable request normalization and permission checks, which makes them a clean extraction seam without touching the separate `/scan` admin endpoints.
- [x] Gap: there was no constructor-level regression proving the RBAC list/create/assign handlers can execute with only a typed service dependency and no concrete RBAC engine on `*app.App`.

### Execution plan
- [x] Add a dedicated `rbacAdminService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the `/rbac` handlers through that service while preserving unavailable, forbidden, not-found, and bad-request behavior.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 226 - Agent SDK Admin Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the protected-resource metadata and admin credential handlers reaching directly into `s.app.Config`, `s.app.RBAC`, and managed API credential methods, so that family could not be exercised through `NewServerWithDependencies(...)` with a narrow stub.
- [x] Gap: the admin Agent SDK credential endpoints already sit on top of a smaller dependency surface for credentials and RBAC scope discovery, which makes them a clean extraction seam without touching the broader Agent SDK tool/runtime paths.
- [x] Gap: there was no constructor-level regression proving those handlers can execute using only a typed service dependency and no concrete managed-credential store or RBAC engine on `*app.App`.

### Execution plan
- [x] Add a dedicated `agentSDKAdminService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the protected-resource metadata and admin credential handlers through that service without changing validation or error semantics.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 225 - Remediation Operations Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the remediation rule and execution handlers reaching directly into `s.app.Remediation` and `s.app.RemediationExecutor`, so that handler family could not be exercised through `NewServerWithDependencies(...)` with a narrow stub.
- [x] Gap: the remediation CRUD and approval endpoints already form a coherent handler family with stable request normalization and existing status semantics, which makes them a good next extraction seam.
- [x] Gap: there was no constructor-level regression proving those remediation handlers can run with only a typed service dependency and without a concrete remediation engine on `*app.App`.

### Execution plan
- [x] Add a dedicated `remediationOperationsService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route remediation rule and execution handlers through that service without widening unavailable/not-found/error behavior.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 224 - Threat Runtime Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the threat-intel and runtime list/control handlers reaching through `s.app` directly, so that handler family could not be exercised through `NewServerWithDependencies(...)` using a narrow stub.
- [x] Gap: the threat-runtime ingest hot path is substantially larger and more stateful, but the feed lookup/sync and runtime list/policy endpoints are a clean sub-family with stable request normalization.
- [x] Gap: there was no constructor-level regression proving those handlers can execute with only a typed service dependency and no concrete threat-intel or runtime engines wired into `*app.App`.

### Execution plan
- [x] Add a dedicated `threatRuntimeService` in `internal/api/` for the threat-intel and runtime list/control endpoints.
- [x] Route those handlers through the new service without widening ingest-path behavior or changing unavailable/error contracts.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 229 - App Graph Store Snapshot Fallback (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left `App.CurrentSecurityGraphStore()` live-graph-only, so callers that correctly depended on the graph-store seam still got `graph.ErrStoreUnavailable` whenever the app was serving from persisted snapshots without an in-memory graph pointer.
- [x] Gap: the graph-store seam is read-heavy across the app and API layers, so it should resolve persisted snapshots passively instead of mutating graph recovery status on every read.
- [x] Gap: writes must stay pinned to a live graph; snapshot-backed fallback should remain read-only so this slice does not widen mutation semantics.

### Execution plan
- [x] Add a passive persisted-snapshot fallback to the app graph-store seam while preserving the live-graph fast path.
- [x] Keep snapshot-backed writes read-only and add focused regressions for both unscoped and tenant-scoped fallback behavior.
- [x] Re-run focused app validation and changed-file gates before opening the PR.

## Deep Review Cycle 223 - Org Handler Service Seam (2026-03-19)

### Review findings
- [x] Gap: issue `#210` still left the org analysis handlers wired directly to graph package helpers, so that family was not testable through `NewServerWithDependencies(...)` with a narrow typed stub.
- [x] Gap: the org information-flow, meeting-insights, and onboarding endpoints had already converged on the tenant graph-view resolver, which made them a clean handler-family seam without widening behavior.
- [x] Gap: there was no constructor-level regression proving those org handlers can execute against a dedicated service interface with no live `*app.App` graph wiring.

### Execution plan
- [x] Add a dedicated `orgAnalysisService` in `internal/api/` and wire it through `NewServerWithDependencies(...)`.
- [x] Route the org information-flow, meeting-insights, and onboarding handlers through that service without changing request validation or not-found semantics.
- [x] Add focused handler-interface regressions and rerun targeted API validation before opening the PR.

## Deep Review Cycle 222 - CLI Readable Graph Snapshot Fallback (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left the CLI `scan` and `sync` graph-analysis paths gated on the live `SecurityGraph` pointer, so they silently skipped graph analysis whenever only persisted snapshots were available.
- [x] Gap: the app layer already had the persisted/live graph resolution primitives, but the CLI had no exported "wait for a usable graph view" seam and therefore kept dereferencing the live graph directly.
- [x] Gap: there was no focused regression proving the app can hand CLI callers a readable persisted snapshot when no live graph has been materialized yet.

### Execution plan
- [x] Add an app-level helper that returns a readable graph view from either the ready live graph or the latest persisted snapshot.
- [x] Route the CLI `scan` and `sync` graph-analysis paths through that helper without widening the write-path behavior.
- [x] Add focused app regressions for the new readable-graph helper and rerun targeted app/CLI validation before opening the PR.

## Deep Review Cycle 220 - App Event Routing Snapshot Fallback (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left app event alert routing bound to `CurrentSecurityGraph()` only, so alert enrichment silently lost graph context whenever the app was serving from persisted snapshots without a live in-memory graph pointer.
- [x] Gap: alert routing is read-only and should use the passive persisted/live graph helper, not trigger its own live-only resolution path.
- [x] Gap: there was no focused regression proving event routing prefers the live graph when present and otherwise falls back to the persisted snapshot.

### Execution plan
- [x] Route the alert-routing graph resolver through the passive persisted/live graph helper.
- [x] Preserve the existing nil-on-unavailable behavior so router startup semantics do not widen unexpectedly.
- [x] Add focused app regressions for persisted-snapshot fallback and live-graph preference before pushing the branch.

## Deep Review Cycle 221 - App Health Snapshot Fallback (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left the app health checks for graph freshness and ontology SLO hard-gated on `CurrentSecurityGraph()`, so they incorrectly returned `unknown` whenever the app was serving only from persisted snapshots.
- [x] Gap: both checks are read-only and the underlying app freshness/status helpers already support passive persisted-snapshot reads without recovery side effects.
- [x] Gap: there was no focused regression proving either health check continues to work from persisted snapshots while preserving the existing `unknown` result when no graph source exists.

### Execution plan
- [x] Route the graph freshness and ontology SLO health checks through the passive persisted/live graph resolver.
- [x] Preserve the existing `unknown` result when neither a live graph nor a persisted snapshot can be resolved.
- [x] Add focused persisted-snapshot regressions for both health checks, then rerun targeted app validation before pushing the branch.

## Deep Review Cycle 219 - App DSPM Snapshot Mutation Base (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left DSPM graph enrichment gated on `CurrentSecurityGraph()`, so scan results were dropped entirely whenever the app was serving from persisted snapshots without a live in-memory graph pointer.
- [x] Gap: the app mutation seam already knows how to seed writes from the latest persisted snapshot, but `enrichSecurityGraphWithDSPMResult(...)` was bypassing it and therefore diverged from the newer snapshot-backed app mutation behavior.
- [x] Gap: there was no regression proving DSPM enrichment can hydrate a live graph from persisted snapshots while preserving the existing copy-on-write live-graph behavior.

### Execution plan
- [x] Remove the unnecessary live-graph gate so DSPM enrichment can reuse `MutateSecurityGraphMaybe(...)` whenever there is no builder graph to update directly.
- [x] Preserve the existing builder-only mutation path so in-progress builder graphs keep their current update semantics.
- [x] Add a focused persisted-snapshot regression and rerun targeted app validation before pushing the branch.

## Deep Review Cycle 216 - App Temporal Snapshot Current Record Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left app temporal graph changelog reads deriving the synthetic current snapshot record from `CurrentSecurityGraph()` only.
- [x] Gap: when a live graph pointer existed without usable snapshot metadata, the temporal tools stopped marking the newest persisted snapshot as current even though a persisted snapshot was available.
- [x] Gap: there was no regression proving `cerebro.graph_changelog` preserves the current-snapshot marker from persisted storage.

### Execution plan
- [x] Add a passive app helper that resolves the current snapshot record from either the live graph or the latest persisted snapshot.
- [x] Route temporal snapshot-record collection through that helper without introducing recovery side effects.
- [x] Extend graph changelog tool coverage to assert the persisted latest snapshot remains current when the live graph cannot supply a current record.

## Deep Review Cycle 215 - App Graph Mutation Snapshot Base (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `MutateSecurityGraphMaybe(...)` seeding writes from `graph.New()` whenever the live graph pointer was absent, so app write flows could silently mutate a blank graph even when a persisted snapshot was available.
- [x] Gap: `cerebro.autonomous_credential_response` was the last app tool still calling `requireSecurityGraph()`, so it could not even begin its analysis path on persisted-snapshot runtimes.
- [x] Gap: there was no regression proving app mutations preserve persisted graph context before appending new workflow artifacts.

### Execution plan
- [x] Teach `MutateSecurityGraphMaybe(...)` to hydrate its mutation base from the current persisted snapshot before falling back to an empty graph.
- [x] Route `cerebro.autonomous_credential_response` through the readable graph helper so its analysis path works without a live pointer.
- [x] Add focused regressions for both direct graph mutation and the autonomous credential workflow, then rerun targeted app validation before opening the PR.

## Deep Review Cycle 214 - App Identity Tool Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the app-level `cerebro.access_review` and `cerebro.identity_calibration` tools hard-bound to `requireSecurityGraph()`, so those read-heavy identity workflows failed whenever the app was serving from persisted snapshots without a live in-memory graph pointer.
- [x] Gap: `cerebro.access_review` also delegated to the default `Identity` service, whose app wiring still resolves only `CurrentSecurityGraph()`, so simply swapping the tool's initial graph lookup would not have fixed the end-to-end path.
- [x] Gap: there was no persisted-snapshot regression covering either tool, so the app-level `#392` migration still had an untested hole in the identity tool surface.

### Execution plan
- [x] Route `cerebro.access_review` and `cerebro.identity_calibration` through `requireReadableSecurityGraph()`.
- [x] Build snapshot-aware access-review service resolution so the tool still uses the readable graph view even when the default app `Identity` service is wired to live graph state only.
- [x] Extend the persisted-snapshot app tool regression coverage for both identity tools, then rerun focused app validation before opening the PR.

## Deep Review Cycle 213 - App Graph View Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left app-layer read flows like `evaluate_policy` proposed-change analysis and org-topology policy scans hard-bound to `CurrentSecurityGraph()`, so they silently failed once the app was running from persisted graph snapshots without a live in-memory graph pointer.
- [x] Gap: there was no shared app-level helper for "live graph or latest persisted snapshot" reads, which meant each remaining app consumer would otherwise re-implement its own fallback logic.
- [x] Gap: there was no regression proving those app policy flows keep working with `SecurityGraph == nil` as long as `GraphSnapshots` can hydrate a read-only view.

### Execution plan
- [x] Add a shared app-level resolver for current live graph or latest persisted snapshot views.
- [x] Route `toolCerebroEvaluatePolicy(...)` proposed-change analysis and `ScanOrgTopologyPolicies(...)` through that resolver while preserving the current no-source behavior.
- [x] Add focused persisted-snapshot regressions for both callers, then rerun targeted app validation before opening the PR.

## Deep Review Cycle 212 - Platform Knowledge Graph Mutation Runtime Path (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left platform knowledge adjudication bound to `CurrentSecurityGraph()`, so the write path failed when the server was running against the graph runtime/store abstraction without a populated raw graph field.
- [x] Gap: the read side of platform knowledge already used the store/runtime resolver, but adjudication still bypassed the shared mutation seam and therefore blocked managed-graph migration for that workflow.
- [x] Gap: there was no regression proving claim-group adjudication can succeed with `SecurityGraph == nil` as long as the runtime/store path and graph mutator are configured.

### Execution plan
- [x] Route platform knowledge adjudication through `MutateSecurityGraph(...)` instead of the raw current-graph field.
- [x] Preserve the existing tenant-scoped read validation before mutation so wrong-tenant group IDs still fail cleanly.
- [x] Add a store/runtime-backed HTTP regression for adjudication with no direct graph pointer, then rerun focused API validation before opening the PR.

## Deep Review Cycle 211 - Platform Snapshot Record Resolver Seam (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `currentPlatformGraphSnapshotRecord()` hand-rolling its own live-graph-then-store fallback instead of using the shared graph resolver infrastructure.
- [x] Gap: that duplication preserved the right behavior today, but it left the platform snapshot catalog outside the common resolver seam that already guards live-vs-store precedence elsewhere in `internal/api`.
- [x] Gap: there was no focused unit coverage for snapshot-record precedence itself, so a future runtime/store migration could regress the catalog while graph-view resolver tests still passed.

### Execution plan
- [x] Add a shared current-or-stored graph snapshot record resolver alongside the existing graph-view resolvers.
- [x] Route `currentPlatformGraphSnapshotRecord()` through that resolver while preserving the fallback from a live graph with no current record to a store snapshot.
- [x] Add focused resolver tests for live-record preference, store fallback, and unavailable-source behavior, then rerun API validation before opening the PR.

## Deep Review Cycle 212 - Post-Sync Graph Runtime Apply Path (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left post-sync graph updates gated on the legacy in-memory `SecurityGraphBuilder` field, even though the actual apply path already runs through `TryApplySecurityGraphChanges(...)` on the graph runtime abstraction.
- [x] Gap: that builder-only check meant a runtime-backed server could finish a sync successfully but silently skip the post-sync graph apply step once the local builder pointer is absent.
- [x] Gap: there was no regression proving the sync endpoints still emit `graph_update` payloads when the runtime can apply graph changes without exposing a local builder.

### Execution plan
- [x] Add a dependency-level capability check for post-sync graph apply support that prefers the runtime abstraction over the raw builder field.
- [x] Route the sync service gate through that capability check instead of `SecurityGraphBuilder != nil`.
- [x] Add focused sync handler regressions for runtime-only apply support and the no-runtime/no-builder skip path, then rerun API validation before opening the PR.
## Deep Review Cycle 215 - Organizational Policy Assignee Acknowledgment Sync (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no policy-scoped graph helper to record one acknowledgment event across the people who currently owe a policy, so LMS import flows had to fan out one write call per assignee.
- [x] Gap: the graph already had a policy assignee roster and a single-person acknowledgment write path, but there was no reusable helper that combined those two seams and treated already-current assignees as no-ops.
- [x] Gap: there was no focused regression proving a policy-scoped acknowledgment sync upgrades stale assignees to the current version, acknowledges pending assignees, and rejects people who are not currently assigned to the policy.

### Execution plan
- [x] Add a policy-scoped acknowledgment sync helper that can acknowledge all current assignees or a caller-specified subset of those assignees.
- [x] Reuse the existing assignee-roster and single-policy acknowledgment helpers so status semantics stay consistent.
- [x] Add focused graph tests for pending, stale, already-current, subset, and invalid-target behavior, then rerun graph validation before opening the PR.

## Deep Review Cycle 211 - Organizational Policy Assignee Roster (2026-03-18)

## Deep Review Cycle 212 - Organizational Policy Direct Person Assignment Sync (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no narrow graph helper to change direct person assignments on an existing policy, so onboarding and HR-sync flows had to resend the full policy registry payload just to add or remove one employee.
- [x] Gap: `WriteOrganizationalPolicy(...)` correctly tracked required-person history, but that logic was only reachable through a full policy rewrite path, which made direct assignment maintenance more error-prone than the rest of the policy graph surface.
- [x] Gap: there was no focused regression proving direct person-assignment updates preserve department assignment scope and only append policy history when the effective direct-assignee set actually changes.

### Execution plan
- [x] Add a graph helper that updates only direct person assignments for an existing policy while preserving department assignments and policy metadata.
- [x] Reuse the existing policy version-history machinery so direct-assignment changes are tracked as `required_person_ids` diffs without duplicating the policy write path.
- [x] Add focused graph tests for mixed add/remove updates, no-op rewrites, and invalid input, then rerun graph validation before opening the PR.

## Deep Review Cycle 213 - Organizational Policy Department Assignment Sync (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no narrow graph helper to change department assignment scope on an existing policy, so org-level onboarding and HR sync flows still had to resend the full policy registry payload to add or remove one department.
- [x] Gap: department assignment churn should preserve direct person assignments and the existing policy metadata, but there was no focused mutation path that guaranteed that behavior.
- [x] Gap: there was no regression proving department-assignment updates only touch `required_department_ids` history while leaving direct assignee scope intact.

### Execution plan
- [x] Add a department-scoped assignment sync helper for existing policies that preserves direct person assignments.
- [x] Reuse the direct-assignment mutation infrastructure so both write paths share the same history and edge-rewrite semantics.
- [x] Add focused graph tests for mixed add/remove updates, no-op rewrites, and invalid input, then rerun graph validation before opening the PR.

## Deep Review Cycle 214 - Organizational Policy Person Acknowledgment Sync (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no person-scoped graph helper to record one explicit acknowledgment event across all currently assigned policies, so LMS or onboarding flows had to fan out one write call per policy.
- [x] Gap: stale and pending policy requirements were already visible through the person-status helper, but there was no corresponding mutation helper that reused that report to acknowledge only the policies the person currently owes.
- [x] Gap: there was no focused regression proving a person-scoped sync treats already-current acknowledgments as no-ops, upgrades stale acknowledgments to the new policy version, and rejects unassigned policy targets.

### Execution plan
- [x] Add a person-scoped acknowledgment sync helper that can acknowledge all currently assigned policies or a caller-specified subset of those assignments.
- [x] Reuse the existing single-policy acknowledgment path so current-version semantics and edge metadata stay consistent.
- [x] Add focused graph tests for pending, stale, already-current, subset, and invalid-target behavior, then rerun graph validation before opening the PR.

### Review findings
- [x] Gap: issue `#256` still had no policy-centered assignee roster, so callers could see aggregate acknowledgment gaps and reminder candidates but not the full assigned employee set with current status in one graph query.
- [x] Gap: direct person assignments and department-derived assignments were only exposed through separate helpers, which made it awkward to answer the core operational question: who owes this policy right now, and why?
- [x] Gap: there was no reusable graph-layer report that distinguished `acknowledged`, `pending`, and `stale` assignees while preserving assignment provenance for follow-on onboarding and reminder flows.

### Execution plan
- [x] Add a policy-scoped assignee roster helper that returns the full assigned employee set for one policy version.
- [x] Include current acknowledgment status plus direct-assignment and department-assignment provenance on each assignee record.
- [x] Add focused graph tests for mixed assignment scope, stale acknowledgments after a version change, and invalid policy input, then rerun graph validation before opening the PR.

## Deep Review Cycle 211 - Organizational Policy Program Reminder Queue (2026-03-18)

### Review findings
- [x] Gap: issue `#256` had a per-policy reminder helper and emerging person/department rollups, but no single graph-layer queue that emitted every outstanding person-policy reminder across the whole policy program.
- [x] Gap: reminder automation needs one actionable backlog for batch jobs and dashboards, not a separate policy-by-policy scan in every caller.
- [x] Gap: framework-scoped compliance operations need to narrow reminder work to one mapped framework family without reimplementing policy filtering in the API layer.

### Execution plan
- [x] Add a program-wide reminder queue helper that emits one row per pending or stale person-policy obligation.
- [x] Preserve direct-assignment and department-assignment context on each row so reminder workflows can explain why the person owes the policy.
- [x] Add focused graph tests for aggregate counts, framework filtering, assignment context preservation, and nil-graph validation, then rerun graph validation before opening the PR.

## Deep Review Cycle 209 - Platform Snapshot Catalog Context Propagation (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the platform snapshot catalog resolving the current graph snapshot via `context.Background()`, so managed `GraphStore` backends could not observe request cancellation or deadlines on that path.
- [x] Gap: the snapshot catalog helpers fanned out into list, lookup, ancestry, changelog, and diff reads, but they did not thread a request context through their shared record-resolution path, which left a hidden runtime/store escape hatch even after the earlier graph-store migration.
- [x] Gap: there was no regression proving the catalog stops waiting on a blocked store snapshot once the caller context is canceled.

### Execution plan
- [x] Thread `context.Context` through the platform snapshot catalog helper chain that resolves current snapshot records and diff inputs.
- [x] Keep synchronous request paths on `r.Context()` and async diff jobs on the job context so cancellation behavior stays correct in both modes.
- [x] Add a blocking-store regression for caller cancellation, then rerun focused API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 210 - Risk Engine Caller Context Propagation (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `graphRiskEngine()` loading graph snapshots and durable risk-engine state under `context.Background()`, so store-backed runtimes could keep blocking on managed graph reads even after the caller canceled the request.
- [x] Gap: the cross-tenant patterns, rule-discovery, and risk-feedback handlers all reuse that cached risk engine, so they silently inherited the same unmanaged snapshot/state load behavior.
- [x] Gap: there was no regression proving a blocked store snapshot stops waiting once the caller context is canceled.

### Execution plan
- [x] Thread caller context into `graphRiskEngine()` and the durable risk-engine state restore path, preserving the existing timeout wrapper.
- [x] Update the non-tenant handlers that rely on the cached risk engine to pass `r.Context()`.
- [x] Add a blocking-store cancellation regression, then rerun focused API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 210 - Organizational Policy Program Status Rollup (2026-03-18)

### Review findings
- [x] Gap: issue `#256` had per-policy acknowledgment rollups, templates, and reminder helpers, but no single graph-layer report for the overall policy program.
- [x] Gap: compliance and HR follow-on flows need one place to answer "which policies still have gaps?" without iterating policy-by-policy in every caller.
- [x] Gap: framework-specific reporting needs to filter the policy registry by mapped framework family so SOC 2 and HIPAA views can be generated from the same graph substrate.

### Execution plan
- [x] Add an organization-wide policy program status helper with optional framework filtering.
- [x] Surface per-policy coverage, pending counts, and department gap IDs in a stable rollup shape.
- [x] Add focused graph tests for aggregate coverage, framework filtering, and nil-graph validation, then rerun graph validation before opening the PR.

## Deep Review Cycle 207 - Graph Runtime Snapshot Catalog Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the platform snapshot catalog's synthetic current record coupled to the raw `SecurityGraph` field, so runtime-backed servers with no stored in-memory pointer could still lose the current snapshot entry even after the earlier graph-store catalog migration.
- [x] Gap: this helper only needs the current graph view abstraction, not direct field access, so continuing to read `s.app.SecurityGraph` was an infrastructure leak inside the server layer.
- [x] Gap: there was no regression proving the platform snapshot catalog prefers the runtime-provided live graph over `GraphStore.Snapshot()` when the runtime abstraction supplies a graph without populating the raw field.

### Execution plan
- [x] Route `currentPlatformGraphSnapshotRecord()` through `CurrentSecurityGraph()` instead of the raw `SecurityGraph` field.
- [x] Add a runtime-backed API regression that fails if the catalog falls through to `GraphStore.Snapshot()` while a runtime graph is already available.
- [x] Re-run focused API tests, lint, and changed-file validation before opening the next `#392` PR.

## Deep Review Cycle 208 - Tenant Resolver Reuse For Identity Services (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `NewServerWithDependencies(...)` hand-rolling its own tenant live-graph-or-store fallback inside the default identity service resolver instead of reusing the shared graph-view resolver seam.
- [x] Gap: `tenant_graph.go` and the constructor-level identity resolver were both making the same tenant-scoped graph resolution decision in different places, which raises the odds that future graph-runtime changes will update one path and miss the other.
- [x] Gap: there was no focused unit coverage proving the dependency-based tenant resolver still prefers the runtime graph when available and only snapshots the store when the live graph is absent.

### Execution plan
- [x] Add shared tenant-scoped resolver helpers on top of the existing graph-view resolver primitives.
- [x] Route both the request-path tenant graph helpers and the default identity graph resolver through the shared tenant-scoped helpers.
- [x] Add focused resolver tests for tenant live-graph preference and tenant store fallback, then rerun API validation.

## Deep Review Cycle 209 - Graph Rebuild Runtime Metadata Path (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `POST /api/v1/graph/rebuild` hard-gated on `SecurityGraphBuilder` plus a live `CurrentSecurityGraph()` pointer, so a runtime-backed rebuild could succeed and still return `503` when no in-memory graph field was populated.
- [x] Gap: the rebuild response only needs graph metadata, which is already available from `CurrentSecurityGraphStore().Snapshot(...)`, so requiring a live graph after rebuild was unnecessary coupling to the old in-memory runtime.
- [x] Gap: there was no regression proving rebuild works in a runtime/store-backed server or that the live graph still wins when both a runtime graph and a store snapshot are available.

### Execution plan
- [x] Teach `serverGraphRiskService.Rebuild(...)` to use the graph runtime abstraction first and fall back to store snapshot metadata when no live graph pointer is present.
- [x] Preserve the live-graph fast path so in-memory runtimes keep returning rebuild metadata without paying the snapshot restore path.
- [x] Add runtime/store-backed rebuild regressions, then rerun focused API tests, lint, and changed-file validation before opening the PR.

## Deep Review Cycle 206 - Graph View Resolver Infrastructure (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still had the same live-graph-or-store-snapshot fallback logic hand-copied across tenant graph helpers and multiple API services, which made the migration surface harder to reason about and easier to regress one caller at a time.
- [x] Gap: `serverGraphRiskService.RiskReport(...)` still had a server-less path that only used the live tenant graph pointer, so store-only runtimes could miss the fallback even though the rest of the risk-analysis surface already supported `GraphStore`.
- [x] Gap: there was no focused unit coverage for the resolver precedence rules themselves, so future `#392` slices could accidentally flip live-vs-snapshot behavior without any tight regression signal.

### Execution plan
- [x] Add shared helper functions for current live-or-store graph views and snapshot-backed graph views.
- [x] Route the tenant graph helpers plus the findings/compliance, graph-intelligence, graph-risk, platform-knowledge, and platform graph-view call sites through those helpers.
- [x] Add focused unit coverage for helper precedence and for store-backed risk reports without a full server wrapper, then rerun focused API validation.

## Deep Review Cycle 206 - Risk Engine Runtime Graph Abstraction (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `graphRiskEngine()` coupled to the raw `serverDependencies.SecurityGraph` field instead of the graph runtime abstraction, so runtime-backed servers could expose a current graph without the cached risk engine ever seeing it.
- [x] Gap: that coupling meant the risk-engine cache could miss runtime graph swaps even though `serverDependencies.CurrentSecurityGraph()` already models the managed-graph seam the API is supposed to consume.
- [x] Gap: there was no regression proving `graphRiskEngine()` works when the server is constructed from a graph runtime without a stored in-memory `SecurityGraph` pointer.

### Execution plan
- [x] Teach `graphRiskEngine()` to resolve its live source through `CurrentSecurityGraph()` instead of the raw dependency field.
- [x] Preserve the existing store-snapshot fallback and cache invalidation behavior so handler contracts stay unchanged.
- [x] Add runtime-only regressions covering initial engine creation and engine refresh after a graph runtime swap, then rerun focused API validation.

## Deep Review Cycle 206 - Organizational Policy Template Catalog (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no shipped library of starter organizational policies, so teams could model acknowledgments and versioning only after hand-authoring every common policy from scratch.
- [x] Gap: there was no graph-layer helper to filter templates by framework or turn a template into a concrete `OrganizationalPolicyWriteRequest`, which would force the future API layer to duplicate policy defaults and mapping logic.
- [x] Gap: template content, review cadence, and framework mappings needed deterministic defaults so follow-on policy management slices could reuse them without inventing per-handler copies.

### Execution plan
- [x] Add a graph-layer organizational policy template catalog covering the common policies listed in issue `#256`.
- [x] Add helpers to list templates, filter them by framework, and build concrete policy write requests from a selected template.
- [x] Add focused graph tests for catalog coverage, framework filtering, write-request defaults, overrides, and invalid input handling.
## Deep Review Cycle 206 - Organizational Policy Reminder Candidates (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no reusable graph helper for automated policy reminders, so follow-up workflows could only see aggregate pending counts and not the specific people who needed current-version acknowledgment.
- [x] Gap: stale acknowledgments after a policy update were treated as generic pending gaps in policy rollups, which meant reminder automation could not distinguish "never acknowledged" from "needs re-acknowledgment".
- [x] Gap: reminder targeting needed direct-assignment and department-assignment context on each person so future notification and onboarding flows can explain why the person owes the policy.

### Execution plan
- [x] Add a policy-scoped reminder helper that returns pending and stale reminder candidates for the current policy version.
- [x] Include assignment scope and acknowledgment metadata in the candidate records so future automation can render actionable notifications.
- [x] Add focused graph tests for pending reminders, stale reminders, direct assignments, and invalid policy input, then rerun graph validation.
## Deep Review Cycle 206 - Organizational Policy Review Schedule (2026-03-18)

### Review findings
- [x] Gap: issue `#256` already stored `review_cycle_days` on policy nodes, but there was no graph helper to tell which policies were current, due, or overdue for review.
- [x] Gap: once version history landed, the review schedule needed to follow the latest policy revision timestamp instead of the original creation timestamp, otherwise updated policies would still appear overdue.
- [x] Gap: future policy-management surfaces need a deterministic schedule view from the graph layer so they do not each reimplement review-date math.

### Execution plan
- [x] Add a graph helper that computes review schedule status from policy review cadence and the latest policy revision timestamp.
- [x] Classify policies as current, due, or overdue and expose deterministic next-review metadata per policy.
- [x] Add focused graph tests for cadence filtering, due/overdue classification, version-history timestamps, and nil-graph input, then rerun graph validation.

## Deep Review Cycle 206 - Organizational Policy Person Status (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no reusable graph helper to answer which policies a specific person currently owes, which blocked reminder and new-hire onboarding flows from reusing the existing policy assignment graph.
- [x] Gap: stale acknowledgments after a policy version update were only visible from policy-centric rollups, not from the person-centric view needed for employee follow-up.
- [x] Gap: direct person assignments and department-scoped assignments needed to be merged into one deterministic person report so future API slices would not reimplement graph joins in handlers.

### Execution plan
- [x] Add a person-scoped organizational policy acknowledgment report that combines direct assignments, department assignments, and current-vs-stale acknowledgment state.
- [x] Add focused graph tests covering direct assignments, department assignments, acknowledged policies, stale policies, and invalid person input.
- [x] Re-run graph tests, lint, and changed-file validation before opening the next `#256` slice.

## Deep Review Cycle 206 - Organizational Policy Department Status (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no department-scoped acknowledgment report, even though the graph already models department membership and policy assignment edges.
- [x] Gap: department leads need a policy-by-policy view of current gaps for their team, not just the policy-centric rollup already exposed by the graph helper.
- [x] Gap: there was no regression proving direct department assignments, direct person assignments for department members, and stale acknowledgments all show up correctly in one department report.

### Execution plan
- [x] Add a graph helper that returns all policies currently owed by one department, including direct department assignments and direct assignments for current members.
- [x] Surface per-policy counts, pending people, and whether the policy came from a direct department assignment.
- [x] Add focused graph tests for mixed assignment sources, stale acknowledgments, and invalid department input.

## Deep Review Cycle 206 - Organizational Policy Control Evidence (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still had no graph-layer bridge from `framework_mappings` like `soc2:cc6.1` to current policy acknowledgment coverage, so future compliance handlers would have to duplicate policy-to-control joins outside the graph package.
- [x] Gap: policy status needed to surface per-policy evidence for a framework control, including current version, required people, acknowledged people, and pending acknowledgments, before the compliance layer can consume it safely.
- [x] Gap: there was no regression proving control matching is case-insensitive or that stale acknowledgments stop counting once a mapped policy version advances.

### Execution plan
- [x] Add a graph helper that returns current-version policy acknowledgment evidence for one framework/control pair derived from `framework_mappings`.
- [x] Normalize framework and control identifiers so callers can query controls without depending on template-specific casing.
- [x] Add focused graph tests for mapped control coverage, stale acknowledgments, unmapped policies, and input validation.

## Deep Review Cycle 205 - Graph Store Compliance Evaluation Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left compliance framework evaluation coupled to `CurrentSecurityGraphForTenant(...)`, so report and status endpoints silently dropped graph-derived evidence whenever the runtime exposed only a tenant `GraphStore`.
- [x] Gap: the findings/compliance service only needs a read-only tenant graph view, so it can rebuild from `CurrentSecurityGraphStoreForTenant(...).Snapshot()` without changing any handler contracts.
- [x] Gap: there was no regression proving compliance framework endpoints still return graph-backed control results in store-only runtimes or that the live graph still wins when both sources exist.

### Execution plan
- [x] Teach the findings/compliance service to fall back from the live tenant graph to a snapshot-backed graph view sourced from `CurrentSecurityGraphStoreForTenant(...)`.
- [x] Preserve the live-graph fast path so existing in-memory runtimes do not pay the snapshot restore cost.
- [x] Add store-only and live-graph-preference regressions for compliance framework handlers, then rerun focused API tests, lint, and changed-file validation.

## Deep Review Cycle 205 - Graph Store Access Review Paths (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left graph access-review creation hard-gated on `s.app.SecurityGraph`, so `/api/v1/graph/access-reviews` returned `503` whenever the API runtime exposed only a graph store.
- [x] Gap: the default server wiring did not initialize an identity review service when `NewServerWithDependencies(...)` was used without a full `App`, so store-backed API workers had no shared access-review service at all.
- [x] Gap: there was no regression proving graph-generated access reviews still create and persist when the API is backed only by `GraphStore` snapshots.

### Execution plan
- [x] Teach the server constructor to default an identity service whose graph resolver can rebuild a tenant-scoped read-only graph view from `CurrentSecurityGraphStoreForTenant(...).Snapshot()`.
- [x] Remove the obsolete live-graph gate from graph access-review creation and preserve `503` only for the real no-graph/no-store case.
- [x] Add a store-only API regression, then rerun focused API tests, identity tests, lint, and changed-file validation.

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

## Deep Review Cycle 199 - Organizational Policy Version History (2026-03-18)

### Review findings
- [x] Gap: issue `#256` still lacked version-history and diff tracking on policy writes, so the graph could only answer the latest policy state and could not support audit-friendly change review.
- [x] Gap: a no-op policy rewrite would have been indistinguishable from a meaningful policy revision, which would create noisy history once API-level management arrives.
- [x] Gap: policies created before explicit history tracking needed a compatibility path so the first tracked update preserved the previous baseline instead of starting history at the new version.

### Execution plan
- [x] Extend organizational policy writes to derive stable content digests, track changed fields, and persist structured version-history entries on the policy node.
- [x] Add a reusable graph helper to read back policy version history with a synthesized baseline for pre-history nodes.
- [x] Add focused regressions for version diffs, no-op rewrites, and legacy-policy history backfill, then rerun graph and ontology validation.

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

## Deep Review Cycle 214 - Graph Store Identity Calibration Path (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left `GET /api/v1/graph/identity/calibration` tied directly to the raw in-memory graph pointer through `serverGraphWritebackService.IdentityCalibration`, so the endpoint failed whenever the runtime exposed only a graph store.
- [x] Gap: identity calibration is a read-only report and only needs the same live-or-store graph view resolver already used by the other graph-store API migrations.
- [x] Gap: there was no regression proving the calibration endpoint still works from a store-only runtime, still prefers the live graph when present, and still returns `503` when neither source exists.

### Execution plan
- [x] Route identity calibration through the shared `currentOrStoredGraphView(...)` resolver and preserve the existing unavailable error contract.
- [x] Add focused HTTP regressions for store-backed success, live-graph preference, and missing-source `503`.
- [x] Re-run focused API tests, package tests, lint, and changed-file validation before pushing the branch.

## Deep Review Cycle 216 - App Simulate And Risk Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the read-only `cerebro.simulate` and `cerebro.risk_score` app tools tied to `requireSecurityGraph()`, so they failed when only persisted snapshots were available.
- [x] Gap: the prior app-tool slice already introduced `requireReadableSecurityGraph()`, but these two tools were still bypassing it.
- [x] Gap: the shared persisted-snapshot regression did not cover low-level graph simulation or risk-score reporting.

### Execution plan
- [x] Route `cerebro.simulate` and `cerebro.risk_score` through the read-only app graph helper.
- [x] Extend the existing persisted-snapshot app-tool regression to cover both tools.
- [x] Re-run app package tests, lint, and changed-file validation against the stacked base before pushing.

## Deep Review Cycle 217 - App Identity Resolver Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the app-level identity service bound to `CurrentSecurityGraph()` only, so tenant-scoped identity flows failed when only persisted snapshots were available.
- [x] Gap: the app already had persisted graph-view helpers for tools, but `initIdentity()` was still bypassing them.
- [x] Gap: existing coverage only proved tenant scoping with a live graph; it did not prove store-backed tenant scoping.

### Execution plan
- [x] Add a tenant-aware persisted graph-view helper in the app layer.
- [x] Route `initIdentity()` through the persisted/live helper for both tenant-scoped and cross-tenant graph resolution.
- [x] Add a store-only tenant-scope regression and rerun focused app validation before pushing.

## Deep Review Cycle 218 - App Status Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left the app status helpers tied to `CurrentSecurityGraph()`, so build status and freshness silently fell back to empty/live-only behavior when only persisted snapshots were available.
- [x] Gap: the app already had a shared persisted graph-view helper, but `GraphBuildSnapshot()` and `GraphFreshnessStatusSnapshot()` were bypassing it.
- [x] Gap: there was no regression proving the app status surface reports node counts and freshness breaches from persisted snapshots.

### Execution plan
- [x] Route app build-status and freshness snapshots through the persisted/live graph helper.
- [x] Keep failure behavior non-fatal by preserving the existing empty-status fallback when no graph can be resolved.
- [x] Add focused persisted-snapshot regressions and rerun app validation before pushing.

## Deep Review Cycle 215 - App Analysis Tool Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left several read-only app tools tied to `CurrentSecurityGraph()` through `requireSecurityGraph()`, so those tools failed whenever only persisted snapshots were available.
- [x] Gap: the prior app-layer slice added `currentOrStoredSecurityGraphView()`, but the read-only analysis tools and `entity_history` path were still bypassing it.
- [x] Gap: there was no regression proving those app tools continue to work from a persisted snapshot when the live graph pointer is absent.

### Execution plan
- [x] Add a read-only app graph helper that requires either the live graph or the latest persisted snapshot.
- [x] Route the read-only analysis tools and `entity_history` through that helper without widening the write-path behavior.
- [x] Add focused persisted-snapshot regressions and rerun app/package validation before pushing.

## Deep Review Cycle 218 - App Scheduled Scan Snapshot Fallback (2026-03-18)

### Review findings
- [x] Gap: issue `#392` still left scheduled graph analyses in `runScheduledScan()` gated on `CurrentSecurityGraph()`, so attack-path analysis and org-topology policy evaluation were skipped whenever only persisted snapshots were available.
- [x] Gap: the app already had a persisted-snapshot graph-view helper, but the scheduled scan path still bypassed it and therefore diverged from the newer app-tool snapshot behavior.
- [x] Gap: there was no regression proving scheduled graph analyses use a persisted snapshot when no live graph is loaded, while still preserving the existing live-graph wait behavior during startup.

### Execution plan
- [x] Add a scheduled-scan graph resolver that preserves live-graph wait semantics and falls back to persisted snapshots only when no live graph is present.
- [x] Refactor the graph-analysis portion of `runScheduledScan()` through that resolver.
- [x] Add focused app regressions for snapshot-only scheduled scans and the preserved live-wait contract, then rerun focused app validation before pushing.
## Deep Review Cycle 219 - Event Remediation Snapshot Propagation (2026-03-19)

### Review findings
- [x] Gap: issue `#392` still left remediation propagation gating tied to the live graph pointer, so restart paths skipped propagation review whenever only a persisted snapshot was available.
- [x] Gap: the app already had a passive persisted/live graph resolver, but `propagationEngine()` was bypassing it and returning `nil` whenever `SecurityGraph` was unset.
- [x] Gap: existing remediation coverage only proved propagation gating with an in-memory live graph; it did not cover the snapshot-only runtime path.

### Execution plan
- [x] Route remediation propagation evaluation through the passive persisted graph resolver when no live graph is loaded.
- [x] Preserve the existing cached live-graph engine behavior once a live graph exists.
- [x] Add a snapshot-backed remediation regression and rerun focused app validation before pushing.

## Deep Review Cycle 220 - API Server Socket Timeout Controls (2026-03-19)

### Review findings
- [x] Gap: issue `#217` still left the HTTP server socket timeouts hardcoded in `internal/api/server.go`, so read, write, and idle budgets could not be tuned through env-backed config.
- [x] Gap: the app already had env-backed operational budget helpers for request timeout, body size, shutdown, and health checks, but the listen-server path was bypassing that pattern.
- [x] Gap: there was no regression proving the server constructor actually applies configured read/write/idle timeouts after config load.

### Execution plan
- [x] Add env-backed config fields and defaults for API read, write, and idle socket timeouts.
- [x] Route `Server.Run()` through a small HTTP server builder that consumes those configured budgets instead of inline literals.
- [x] Add focused config and server regressions, then rerun changed-file validation before pushing.

## Deep Review Cycle 236 - TAP Parser Separation (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left TAP schema parsing, interaction type parsing, and activity target parsing embedded in `app_stream_consumer.go`, mixed with the mutation hot path.
- [x] Gap: those parser helpers were only indirectly covered through graph mutation tests, which made it harder to validate them without a graph instance.
- [x] Gap: there was no parser-only regression proving TAP schema entity definitions can be deserialized without touching graph state.

### Execution plan
- [x] Move the remaining read-only TAP parser helpers into a dedicated parser file.
- [x] Keep the interaction and activity mutation files consuming those helpers without changing mutation behavior.
- [x] Add a focused schema parser regression and rerun the changed-package validation gate before pushing.

## Deep Review Cycle 237 - TAP Runtime Coordination Split (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left TAP readiness gating and resolver-graph scoping embedded in `app_stream_consumer.go`, mixed into the same file as consumer bootstrapping and event dispatch.
- [x] Gap: declarative TAP mapping identity resolution depends on a temporary scoped graph, but there was no focused regression proving that scoped graph is preferred over the live graph pointer.
- [x] Gap: the remaining runtime helper block was small and stable enough to extract without widening the event mutation behavior.

### Execution plan
- [x] Move the TAP runtime coordination helpers into a dedicated runtime helper file.
- [x] Keep event dispatch and declarative mapping behavior unchanged while routing through those extracted helpers.
- [x] Add a focused scoped-resolver regression and rerun the changed-package validation gate before pushing.

## Deep Review Cycle 238 - TAP Mapping Helper Split (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left declarative TAP mapper loading, mapper application, and schema-registration logic embedded in `app_stream_consumer.go` alongside event dispatch.
- [x] Gap: that mapping block is largely graph-independent setup and registration logic, but its coverage was still tied mostly to broader `handleTapCloudEvent(...)` flows.
- [x] Gap: there was no direct regression proving TAP schema registration works without a live graph pointer, even though it should remain a graph-free path.

### Execution plan
- [x] Move the TAP mapping and schema-registration helpers into a dedicated helper file.
- [x] Keep event dispatch behavior unchanged while routing the existing mapper and schema paths through the extracted helpers.
- [x] Add a focused no-live-graph schema registration regression and rerun the changed-package validation gate before pushing.

## Deep Review Cycle 239 - TAP Modeling Helper Split (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left TAP activity-kind derivation, business-edge derivation, computed-field calculation, and generic coercion helpers embedded in `app_stream_consumer.go`, even though that file had already been reduced to lifecycle and dispatch concerns.
- [x] Gap: those helpers are graph-free modeling logic shared across the activity, business, interaction, and parse paths, but they were still only indirectly separated through broader event-handling tests.
- [x] Gap: there was no direct regression covering the read-only helper paths that classify activity node kinds and derive business edges without mutating a graph instance.

### Execution plan
- [x] Move the remaining TAP modeling and coercion helpers into a dedicated helper file.
- [x] Leave consumer lifecycle and dispatch behavior unchanged while keeping the activity/business paths wired through the extracted helpers.
- [x] Add direct helper regressions for activity-kind classification and business-edge derivation, then rerun the changed-package validation gate before pushing.

## Deep Review Cycle 240 - TAP Consumer Lifecycle Split (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left TAP consumer initialization, health registration, and shutdown lifecycle code mixed into `app_stream_consumer.go` alongside event dispatch.
- [x] Gap: after the parser, runtime, mapping, mutation, and modeling extractions, the remaining lifecycle block was the last non-dispatch concern still sharing the same file with the hot-path entrypoints.
- [x] Gap: there was no direct regression proving `stopTapGraphConsumer(...)` remains a no-op when no consumer has been initialized, which is the minimal guard for this lifecycle-only slice.

### Execution plan
- [x] Move TAP consumer lifecycle helpers into a dedicated lifecycle file.
- [x] Leave event dispatch behavior unchanged in `app_stream_consumer.go`.
- [x] Add a direct no-consumer shutdown regression and rerun changed-package validation before pushing.

## Deep Review Cycle 241 - TAP Dispatch Split (2026-03-19)

### Review findings
- [x] Gap: issue `#211` still left the remaining TAP dispatch/router functions in `app_stream_consumer.go`, even after parser, runtime, mapping, modeling, mutation, and lifecycle logic had already been extracted.
- [x] Gap: that file had become a pure dispatch shim, so keeping it as the old catchall file no longer reflected the actual responsibility split.
- [x] Gap: there was no direct regression proving `cloudEventType(...)` correctly falls back to `Subject` when `Type` is empty, even though that behavior is central to the dispatcher entrypoint.

### Execution plan
- [x] Move the remaining dispatch/router functions into a dedicated dispatch file.
- [x] Remove the now-empty catchall TAP consumer file.
- [x] Add a focused `cloudEventType(...)` fallback regression and rerun changed-package validation before pushing.
