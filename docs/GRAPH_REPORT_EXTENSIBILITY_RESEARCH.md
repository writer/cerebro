# Graph Report Extensibility Research

This document turns external platform patterns into concrete design rules for Cerebro's derived report layer.

The bar is not "more endpoints." The bar is a reusable report substrate over the metadata/context graph so org dynamics, security dynamics, and future domain views can be composed from the same primitives.

## Research Goal

Cerebro already has several useful report payloads:

- intelligence insights
- graph quality
- metadata quality
- claim conflicts
- leverage
- weekly calibration

The gap is that these are still mostly endpoint-shaped products of individual handlers. To make them extensible, Cerebro needs:

- reusable dimensions and measures
- reusable checks and assertions
- composable report sections/modules
- namespaced extension points
- durable run/snapshot provenance
- autogeneration from one definition registry

## Primary External Patterns

### 1) W3C RDF Data Cube

Source:
- https://www.w3.org/TR/vocab-data-cube/

Useful pattern:
- analytical outputs should separate `dimensions`, `measures`, and `attributes`
- dimensions define how data is sliced
- measures define the observed values
- attributes carry qualifying metadata

Adopt in Cerebro:
- every report definition should declare query dimensions separately from returned measures
- section-level presentation hints should not be mixed into the measure definition itself
- provenance, freshness, completeness, confidence, and benchmark metadata should be treated as report attributes, not ad hoc fields per handler

Reject:
- a full RDF Data Cube implementation inside the API surface; Cerebro only needs the contract shape, not the entire vocabulary stack

### 2) W3C PROV-O

Source:
- https://www.w3.org/TR/prov-o/

Useful pattern:
- separate `Entity`, `Activity`, and `Agent`
- model derivation explicitly instead of flattening everything into one record

Adopt in Cerebro:
- a `ReportRun` should be a derived entity
- report computation should be a first-class execution activity
- sources, jobs, and users should be modeled as agents involved in report generation
- sections, recommendations, and metrics should carry derivation metadata back to graph claims/evidence/sources

Reject:
- forcing the public API to expose raw PROV classes directly; use Cerebro-native names while preserving the semantics

### 3) OpenLineage Facets

Sources:
- https://openlineage.io/docs/spec/facets/
- https://github.com/OpenLineage/OpenLineage/blob/main/spec/OpenLineage.md

Useful pattern:
- extensions attach as small named facets
- custom facets must be namespaced to avoid collisions
- facets should point to immutable schema URLs
- standard and custom facets can coexist without destabilizing the core event model

Adopt in Cerebro:
- report definitions, report sections, and report runs should expose explicit extension points
- extensions should be namespaced and schema-backed
- custom report enrichments should not require new endpoints or untyped blobs in the base schema

Reject:
- arbitrary inline `map[string]any` extension payloads with no schema identity or ownership

### 4) DataHub Assertions

Sources:
- https://docs.datahub.com/docs/managed-datahub/observe/assertions
- https://github.com/datahub-project/datahub/blob/master/metadata-models/src/main/pegasus/com/linkedin/assertion/AssertionInfo.pdl

Useful pattern:
- assertions are reusable quality/test building blocks
- assertion definitions are separate from assertion run results
- run history, alerts, and result timelines matter as much as the rule itself

Adopt in Cerebro:
- report checks should be reusable definitions, not hard-coded one-off conditions hidden in handlers
- checks should have stable IDs, severities, rationale, and remediation hints
- report failures should support history and trend analysis over time

Reject:
- promoting every check into a global substrate primitive immediately; keep them as report-level primitives first unless a shared write lifecycle emerges

### 5) DataHub Asset Summaries + Context Documents

Sources:
- https://github.com/datahub-project/datahub/blob/master/docs/features/feature-guides/custom-asset-summaries.md
- https://github.com/datahub-project/datahub/blob/master/docs/features/feature-guides/context/context-documents.md
- https://github.com/datahub-project/datahub/blob/master/metadata-models/src/main/pegasus/com/linkedin/settings/asset/AssetSummarySettings.pdl

Useful pattern:
- summaries are module-based, not monolithic
- default and custom modules can coexist on the same surface
- curated context documents are first-class assets with version history and publishing state

Adopt in Cerebro:
- report responses should be organized as explicit sections/modules
- narrative or context blocks should link to document/context graph nodes, not embed opaque markdown blobs everywhere
- report definitions should support owner-curated section ordering and future custom modules

Reject:
- coupling report composition to one UI layout; the API should expose module metadata, not presentation-specific markup

### 6) OpenMetadata Test Definitions + Metrics Registry + Data Insight Charts

Sources:
- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/api/tests/createTestDefinition.json
- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/tests/testDefinition.json
- https://github.com/open-metadata/OpenMetadata/blob/main/ingestion/src/metadata/profiler/metrics/README.md
- https://github.com/open-metadata/OpenMetadata/blob/main/ingestion/src/metadata/profiler/metrics/registry.py
- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/api/dataInsight/createDataInsightChart.json

Useful pattern:
- typed test definitions with parameter schemas and supported entity kinds
- metric registries to centralize available measures
- charts/reports explicitly declare `dimensions` and `metrics`
- `additionalProperties: false` on core contracts

Adopt in Cerebro:
- define report measures and checks in registries, not inline
- parameterize checks instead of cloning nearly identical report handlers
- keep report definition schemas tight and typed
- use dimensions + metrics arrays for chart-like sections

Reject:
- free-form report definitions with no validation or compatibility guarantees

### 7) Backstage / Roadie Tech Insights and Scorecards

Sources:
- https://roadie.io/backstage/plugins/tech-insights/
- https://github.com/backstage/backstage/blob/master/microsite/data/plugins/tech-insights.yaml
- https://github.com/backstage/backstage/blob/master/microsite/data/plugins/dora-scorecard.yaml

Useful pattern:
- scorecards/checks are built over collected facts
- one framework can host many domain-specific scorecards without changing the core platform contract

Adopt in Cerebro:
- treat org and security dynamics as report families over shared graph facts
- separate data collection/derivation from scoring/report rendering
- allow multiple scorecards to reuse the same measures with different thresholds or recommendations

Reject:
- turning each scorecard into a new top-level API family

## Synthesis: What Cerebro Should Adopt

### Core Rule

Derived reports should be composed from:

- graph entities and edges
- claims, evidence, observations, and sources
- reusable measures
- reusable checks
- typed sections/modules
- versioned extension points
- report runs with provenance and time scope

### Canonical Report Model

Cerebro should standardize on these report-layer primitives:

- `ReportDefinition`
- `ReportParameter`
- `ReportMeasure`
- `ReportSection`
- `ReportCheck`
- `ReportExtensionPoint`
- `ReportRun`
- `ReportSectionResult`
- `ReportRecommendation`
- `ReportSnapshot`

### Required Invariants

- every report definition has a stable `id`
- every measure has a stable `id`, value type, and optional unit
- every section declares its kind and referenced measures
- every extension point is namespaced and schema-backed
- every report run stores `generated_at`, scope, time slice, provenance, and execution identity
- any report that can exceed latency/resource thresholds must be promotable to a job resource
- no new report family should require a brand-new top-level namespace if it can fit the shared report substrate

## Proposed Cerebro API Shape

### Immediate discovery surface

- `GET /api/v1/platform/intelligence/reports`
- `GET /api/v1/platform/intelligence/reports/{id}`

Purpose:
- expose built-in report definitions
- make sections/measures/checks discoverable
- provide a stable autogeneration input for OpenAPI, MCP tools, docs, and UI composition

### Next execution surface

- `POST /api/v1/platform/intelligence/reports/{id}/runs`
- `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}`
- `GET /api/v1/platform/jobs/{id}`

Purpose:
- allow heavy reports to materialize as runs/jobs
- preserve inputs, time scope, provenance, and cached results

### Optional future configuration surface

- `POST /api/v1/platform/intelligence/report-definitions`
- `POST /api/v1/platform/intelligence/report-modules`
- `POST /api/v1/platform/intelligence/report-checks`

Purpose:
- register tenant-specific report definitions later without destabilizing built-in definitions

Not for now:
- fully user-authored arbitrary reports without validation
- direct inline code execution as part of report definitions

## Report Families Cerebro Should Support

These should remain report families over the graph, not new substrate primitives:

- identity trust and resolution quality
- org dynamics and knowledge fragility
- information-flow lag and coordination bottlenecks
- decision closure and operating cadence
- privilege concentration and risky-configuration posture
- blast radius trend views
- source trust and ingestion confidence
- change risk and rollout readiness

## Autogeneration Targets

The report registry should eventually generate:

- OpenAPI schemas and examples
- MCP/tool descriptors
- docs pages and quick references
- compatibility diff reports
- JSON Schema for extension payloads
- report UI defaults for section ordering and chart types
- event contracts for report-run lifecycle events

## Recommended Execution Order

### 1) Structural cleanup

- remove alias-backed report routes that already have exact replacements
- stop documenting report surfaces under legacy graph-intelligence paths
- expose the built-in report registry

### 2) Reusable report substrate

- add `ReportRun` and `ReportSnapshot`
- add explicit section result envelopes
- add provenance/evidence references per section and recommendation

### 3) Reusable checks and measures

- move report-specific scoring checks into reusable definitions
- add shared measure registry with units and type metadata
- add benchmark overlays and threshold packs

### 4) Extension contract

- add namespaced, schema-versioned extension payloads on report definitions and section results
- add compatibility checks for extension schema changes

### 5) Materialization + scheduling

- add job-backed execution for heavy reports
- add snapshot history and cache invalidation rules
- emit lifecycle events for report runs

## What Cerebro Should Avoid

- endpoint-per-report-section sprawl
- ad hoc `map[string]any` report definitions
- mixing UI layout state into the core API contract
- inventing new substrate nouns for every org/security analytic view
- treating recommendations as untyped strings with no provenance

## Implementation Consequence

The report layer is now the correct home for most org/security dynamics.

That means the graph platform should deepen:

- provenance
- claims/evidence
- dimensions/measures
- report checks
- report runs
- extension contracts

It should not respond by multiplying bespoke org or security APIs.
