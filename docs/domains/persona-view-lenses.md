# Persona View Lenses

Cerebro supports multiple product personas on the same tenant-scoped graph by
letting clients present different lenses over the same runtime, finding,
evidence, report, inventory, and graph contracts.

This is a product-facing composition pattern. It is not a storage split, a graph
schema fork, a tenant boundary, or an authorization model.

## Core Boundary

The shared substrate stays the same:

- source runtimes collect and replay operational signals,
- Postgres stores durable current state for claims, findings, evidence, reports,
  inventory posture, and GRC views,
- Neo4j/Aura stores the rebuildable graph projection,
- API auth and tenant scoping remain enforced by the bootstrap service.

A persona lens may change:

- navigation order,
- default entry points,
- page copy,
- default filters,
- saved dashboard layouts,
- report profile selection,
- which graph-backed summaries appear first.

A persona lens must not change:

- tenant authorization,
- RBAC permissions,
- graph projection identity,
- source runtime durability,
- finding lifecycle semantics,
- raw Cypher safety rules,
- the set of backend stores.

## Initial Lens Set

| Lens | Primary question | First contracts to compose |
| --- | --- | --- |
| Security Ops | What active risk needs action first, and what graph path explains it? | `/grc/findings`, `/platform/graph/*`, `/grc/inventory`, `/grc/trends` |
| Compliance & Audit | Are controls provable, fresh, and exportable? | `/grc/controls`, `/grc/evidence`, `/grc/control-packs*`, `/grc/reports*` |
| Platform Owners | Are sources, runtimes, and graph projection healthy enough to trust? | `/sources`, `/source-runtimes/*`, `/platform/graph/ingest-*`, `/grc/inventory` |
| Leadership | What is the program posture, trend direction, and material exposure? | `/grc/dashboard`, `/grc/trends`, `/grc/report-runs`, `/platform/graph/impact/*` |

Clients can add more lenses when a new audience has a distinct first question
and can be served by composing existing contracts.

## Design Rules

1. Keep the graph shared. Prefer route composition, report profiles, saved
   dashboards, and product copy before adding backend fields.
2. Keep RBAC separate. A lens is a wayfinding and prioritization layer; it does
   not grant or deny permissions.
3. Keep personas additive. Every graph-backed fact should be addressable from a
   general route even when a lens hides it from primary navigation.
4. Keep labels audience-specific, not platform-specific. Security can say
   "risk" or "finding"; compliance can say "control" or "evidence"; platform
   contracts should still expose graph, source runtime, report, claim, workflow,
   and GRC route families.
5. Keep examples public-safe. Do not document tenant names, hostnames, account
   IDs, resource labels, URNs, graph counts, or environment-specific rollout
   details in this repository.

## When Backend Work Is Justified

Most persona work should live in clients. Backend work is justified only when a
lens needs a reusable, tenant-scoped contract that more than one client can use.
Good candidates include:

- named report profiles,
- bounded dashboard source catalog entries,
- explicit source coverage dimensions,
- graph impact routes with fixed traversal limits,
- typed readiness summaries.

Avoid backend changes for presentation-only needs such as navigation grouping,
marketing copy, card ordering, or default tabs.

## Relation To Non-Goals

Persona lenses reinforce the platform/application boundary in
[`non-goals.md`](../engineering/non-goals.md): Cerebro is not exclusively a
security product, and this repository does not ship an end-user web UI. Runtime
contracts remain shared primitives; product-specific clients decide which
routes, summaries, and report profiles should be prominent for each audience.
