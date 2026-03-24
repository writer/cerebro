# Graph Store Cutover Parity

This document describes the first cutover-safety primitives for durable graph
store migration.

## Scope in this slice

The initial implementation adds two graph-layer building blocks:

- `CompareGraphStores(...)`
  - snapshots two stores
  - computes structural drift with `DiffSnapshots`
  - runs representative traversal probes
  - classifies mismatch types for operator review
- `ShadowReadGraphStore`
  - always returns the primary store result
  - executes a shadow read against the candidate backend
  - emits drift reports when snapshot or traversal outputs diverge
- `CompareGraphStoreReports(...)` plus report-parity probes
  - snapshots both stores
  - materializes graph views from those snapshots
  - executes the same derived report builders against both graphs
  - emits deterministic report drift mismatches for supported report families

## Mismatch classes

The current report model distinguishes:

- `missing_node`
- `missing_edge`
- `node_modified`
- `traversal_drift`
- `report_drift`
- `shadow_error`

These are intentionally narrow and deterministic so later tooling can group and
count them without reinterpreting raw diffs.

## Why this matters

Migration risk is not limited to CRUD parity. Cerebro derives intelligence from
traversals and report inputs, so a target backend must match both:

- structural graph contents
- traversal behavior over the same contents
- derived report behavior over the same contents

The shadow-read wrapper makes that measurable before cutover because it keeps
serving the primary backend while capturing divergence from the shadow backend.

The report-parity harness currently supports:

- claim conflict reports
- entity summary reports
- evaluation temporal analysis reports
- playbook effectiveness reports

## Next slices

Follow-on work should add:

- dual-write fan-out for graph mutations
- operator-facing parity diff tooling and metrics
- backfill verification over snapshot exports/imports
- staged rollout controls and rollback guidance
