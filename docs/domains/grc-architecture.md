# GRC Architecture

This document covers the Governance, Risk, and Compliance (GRC) domain in Cerebro: its package boundaries, contracts, data flow, and ownership model.

It complements [Architecture](../reference/architecture.md), [Compliance Controls](compliance-controls.md), [Policies](policies.md), and [Findings Platform Architecture](findings-platform-architecture.md).

## Why This Exists

The GRC surface is the fastest-growing part of the Cerebro platform. It spans six packages:

- `internal/grccatalog` — bounded report source catalog for custom dashboards
- `internal/grccontrol` — control evidence packet builder and report rendering
- `internal/grcinventory` — inventory posture, scope, accountability, and filtering
- `internal/grcprogram` — program readiness scoring and work-item generation
- `internal/grctrends` — time-bucketed finding trend aggregation
- `internal/compliance` — control family catalog, profiles, and coverage mapping

Before this doc, GRC behavior was described only in accumulating paragraphs inside the architecture "bootstrap ownership" section. This doc is the dedicated contract reference that those paragraphs can point to.

## Domain Model

```text
                    GRC Report Builder
                    (grccontrol packets)
                          |
          +---------------+---------------+
          |               |               |
     grcprogram      grccatalog      grcinventory
   (readiness)    (source catalog)  (posture/scope)
          |               |               |
          +-------+-------+-------+-------+
                  |               |
             grctrends        compliance
           (trend buckets)   (control catalog)
                  |               |
                  v               v
           Postgres trends    Control families
           + findings         + coverage index
```

## Package Contracts

### grccatalog — Report Source Catalog

`internal/grccatalog` defines the bounded, allowlisted set of GRC report sources that custom dashboards and the report builder can query. It is the semantic catalog: each source maps to one existing, tenant-scoped, row-limited GRC read endpoint and declares the parameters a caller may bind.

This is deliberately not a general-purpose query engine. There are no free-form dimensions, measures, joins, or ad-hoc filters. Callers pick a named source from the catalog and supply values for its declared parameters.

Key exports:

- `Catalog()` — returns the full source catalog
- `Lookup(id)` — returns one source by ID
- `ValidateWidgetQuery(query)` — validates that a query references a known source and only binds declared parameters with well-typed values within the source row limit

Current catalog sources: `findings`, `controls`, `evidence`, `trends`, `frameworks`, `control-coverage`, `inventory-assets`, `inventory-categories`. Each source declares its method, path, parameters, visualizations, default/max limits, cache scope, and exportability.

Boundaries:

- Does not execute queries; tenant scoping and data access remain the responsibility of the dispatched GRC handler
- Row limits mirror the bounds enforced by the GRC read handlers
- Aggregation, traversal, and tenant scoping stay in the underlying GRC handlers

### grccontrol — Control Evidence Packets

`internal/grccontrol` builds control evidence packets from findings, evidence records, and source runtime context. It resolves control profiles, maps findings to controls, evaluates evidence freshness, computes control status, and renders export-ready packets.

Key types:

- `BuildInput` / `CustomBuildInput` — inputs for built-in and custom control pack builds
- `PacketResult` / `CustomPacketResult` — rendered packet with profile, controls, metadata
- `Profile` — control profile identity (e.g., `soc2-security-core`)
- `ControlItem`, `FindingItem`, `EvidenceItem` — structured packet rows
- `ReportMetadata` — report generation metadata
- `ReportReadinessBlocker` — readiness blocking condition

Boundaries:

- Profile resolution, rule coverage, evidence freshness, control status behavior, custom profile resolution, report metadata construction, and export rendering stay behind this package
- Bootstrap only handles HTTP request decoding, status selection, and response mapping

Dependencies: `compliance`, `ports`, `resourcescope`

### grcinventory — Inventory Posture

`internal/grcinventory` manages GRC inventory posture logic: applies scope records and asset report summaries to graph inventory assets, computes review disposition and accountability states, filters assets by scope/review/accountability, and produces summary statistics.

Key exports:

- `ApplyScope(asset, record)` — applies a GRC scope record to an inventory asset
- `ApplyAssetReportSummary(asset, summary)` — applies asset report summary
- `ApplyReviewPosture(asset)` — computes review disposition (baseline, needs_review, out_of_scope, reported_issue) and accountability (known, required, none)
- `FilterByScope`, `FilterByReviewDisposition`, `FilterByAccountability` — filter assets by state
- `Summarize(assets)` — produces aggregate `Summary` with totals, coverage percentages, risk distribution

Review disposition states:

| State | Meaning |
| --- | --- |
| `baseline` | No immediate GRC action required |
| `needs_review` | GRC-relevant evidence indicates the asset needs an accountable owner |
| `out_of_scope` | Excluded from controls, evidence collection, and review |
| `reported_issue` | A reviewer reported this asset for triage |

Accountability states:

| State | Meaning |
| --- | --- |
| `known` | Owner is known and assigned |
| `required_missing` | Owner is required but missing (high risk or public exposure) |
| `not_required` | Owner is not required for this asset |

Boundaries:

- Posture classification and inventory filtering remain in this package
- Bootstrap only handles GRC inventory request/response mapping and tenant authorization

Dependencies: `graphquery`, `ports`

### grcprogram — Program Readiness

`internal/grcprogram` generates program readiness reports from control evidence packets. It scores overall readiness, breaks down per-framework and per-control status, generates prioritized work items, and assembles proof bundles.

Key types:

- `Readiness` — top-level readiness report with summary, frameworks, controls, work items, proof bundle, connectors, and metadata
- `Summary` — aggregate readiness score with control counts (passing, failing, missing evidence, stale evidence, manual review, exception), finding counts, connector status, coverage blind spots, and readiness blockers
- `Framework` — per-framework readiness breakdown
- `Control` — per-control status with evidence items and finding links
- `WorkItem` — prioritized remediation action item
- `ProofBundle` — collected evidence for audit export

Boundaries:

- Readiness scoring, work-item prioritization, and proof bundle assembly stay behind this package
- Bootstrap only handles request/response mapping and tenant authorization

Dependencies: `grccontrol`

### grctrends — Finding Trends

`internal/grctrends` provides time-bucketed finding trend aggregation. It produces per-bucket opened/closed counts, severity breakdowns, SLA breach counts, average time-to-close, aging buckets, and optional period-over-period comparison.

Key types:

- `RequestParams` — interval, days, compare, severity, framework, target params
- `Point` — one time bucket with opened/closed counts, severity splits, SLA metrics, open total
- `AgingBucket` — finding age distribution bucket
- `Provider` interface — wraps the `GRCFindingTrendsStore` port
- `DrilldownFilters` — filters for trend drilldown queries

Boundaries:

- Time-bucketed aggregation, severity classification, and open-at-window-start baseline stay behind `internal/statestore/postgres`
- Bootstrap only handles HTTP request parameter parsing, per-tenant runtime query fan-out, bucket merging, and response mapping

Dependencies: `ports`

### compliance — Control Catalog and Coverage

`internal/compliance` is documented in [Compliance Controls](compliance-controls.md). It owns the control family catalog, control profiles, evidence expectations, coverage mapping, and policy rule extensions. The GRC domain builds on compliance for control resolution and coverage scoring.

## Data Flow

1. Source runtimes produce findings and evidence through the findings platform.
2. `grccatalog` validates widget queries against the bounded source catalog.
3. `grccontrol` builds control evidence packets from findings, evidence, and runtime context using compliance control definitions.
4. `grcprogram` consumes control packets to score readiness and generate work items.
5. `grctrends` queries persisted findings for time-bucketed trend analysis.
6. `grcinventory` applies scope and accountability posture to graph inventory assets.
7. All reads are tenant-scoped; the bootstrap layer enforces tenant authorization before dispatching to any GRC package.

## RBAC Ownership

The GRC domain maps to these RBAC roles defined in `internal/authz`:

| Role | Scopes | GRC Surface |
| --- | --- | --- |
| `grc_reviewer` | `grc.inventory.write`, `ask_queries.write`, `dashboards.write`, `risk_scoring.write`, `cosmo.security.read` | Inventory posture, dashboards, risk scoring, GRC ask |
| `analyst` | `finding_candidates.promote`, `findings.write`, `grc.inventory.write`, `ask_queries.write`, `dashboards.write`, `risk_scoring.write`, `cosmo.security.read` | Findings, inventory, dashboards, risk scoring |
| `viewer` | `cosmo.security.read` | Read-only GRC views |
| `admin` | all scopes | Full GRC access |

## Code Map

- `internal/grccatalog/catalog.go` — report source catalog and query validation
- `internal/grccontrol/packets.go` — control evidence packet builder
- `internal/grccontrol/finding_reports.go` — finding report assembly
- `internal/grccontrol/helpers.go` — shared control helpers
- `internal/grcinventory/posture.go` — inventory posture, scope, accountability, filtering
- `internal/grcprogram/readiness.go` — program readiness scoring and work items
- `internal/grctrends/trends.go` — finding trend aggregation
- `internal/compliance/` — control catalog, profiles, coverage (see [Compliance Controls](compliance-controls.md))
- `internal/bootstrap/grc.go` — GRC route registration and wiring
- `internal/bootstrap/grc_catalog.go` — GRC catalog bootstrap
- `internal/bootstrap/grc_control_packs.go` — control pack bootstrap
- `internal/bootstrap/grc_inventory.go` — inventory bootstrap
- `internal/bootstrap/grc_program_readiness.go` — readiness bootstrap
- `internal/bootstrap/grc_trends.go` — trends bootstrap
- `internal/statestore/postgres/` — persisted GRC trends, dispositions, and inventory scope storage

## What This Does Not Solve Yet

- Cross-tenant GRC rollups and multi-tenant program dashboards
- Automated evidence collection scheduling beyond finding evaluation runs
- GRC workflow orchestration (approval chains, exception management lifecycle)
- Custom control framework versioning and migration tooling
- Real-time GRC alerting on posture changes

These are intentionally out of scope for the current GRC platform foundation.
