# Persona View Lenses

Cerebro supports multiple product personas on the same tenant-scoped graph by
letting clients present different lenses over the same runtime, finding,
evidence, report, inventory, and graph contracts.

This is a product-facing composition pattern. It is not a storage split, a graph
schema fork, a tenant boundary, or an authorization model.

The UI should not make people learn Cerebro's persona model before it shows
value. Persona selection is a prioritization preference. The first screen for a
security operator should answer what is risky, what changed, who owns it, what
evidence is missing, and what to fix first. The first screen for an auditor
should answer which controls are provable, stale, blocked, or export-ready.

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
- prioritized work queues,
- prioritized signal ordering,
- decision criteria,
- recommended next actions,
- suggested questions,
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

| Audience | First question the product should answer | First contracts to compose |
| --- | --- | --- |
| Security | What active risk needs action first, who owns it, and what assets or evidence make it urgent? | `/grc/findings`, `/platform/graph/*`, `/grc/inventory`, `/grc/trends` |
| Audit | Which controls are provable, stale, blocked, or export-ready? | `/grc/controls`, `/grc/evidence`, `/grc/control-packs*`, `/grc/reports*` |
| Platform | Are sources, runtimes, owners, and graph projection healthy enough to trust? | `/sources`, `/source-runtimes/*`, `/platform/graph/ingest-*`, `/grc/inventory` |
| Leadership | What is the program posture, trend direction, and material exposure? | `/grc/dashboard`, `/grc/trends`, `/grc/report-runs`, `/platform/graph/impact/*` |

Clients can add more lenses when a new audience has a distinct first question
and can be served by composing existing contracts.

## Enrichment Model

Shallow lenses only rename the same dashboard for different audiences. Useful
lenses enrich the same graph facts into a different operating frame. Client
implementations should define the following persona-level fields before adding
new backend contracts:

- first question: the sentence the page should answer before showing
  navigation,
- promoted signals: the ordered metrics that matter most to the audience,
- decision frame: the criteria that explain why those signals are promoted,
- work queue: the items the audience should act on next,
- next actions: links that move directly from the briefing to work,
- question starters: useful prompts that teach the user what Cerebro can answer.

For example, the same missing owner fact means different things by audience:

| Audience | Enriched meaning |
| --- | --- |
| Security | Remediation may stall unless the finding has an accountable owner. |
| Audit | Control evidence may not be defensible without an accountable owner. |
| Platform | Inventory and source ownership need cleanup before downstream teams rely on the graph. |
| Leadership | The program review needs a named follow-up owner before the risk can leave the agenda. |

## Design Rules

1. Lead with work, not navigation. Home surfaces should show active risk,
   changed signals, missing owners, stale or missing evidence, affected assets,
   and useful questions before they show routes or product taxonomy.
2. Keep the graph shared. Prefer route composition, report profiles, saved
   dashboards, and product copy before adding backend fields.
3. Keep RBAC separate. A lens is a wayfinding and prioritization layer; it does
   not grant or deny permissions.
4. Keep personas additive. Every graph-backed fact should be addressable from a
   general route even when a lens hides it from primary navigation.
5. Keep labels audience-specific, not platform-specific. Security can say
   "risk", "owner", "affected asset", or "fix first"; audit can say "control",
   "evidence", or "export"; platform contracts should still expose graph,
   source runtime, report, claim, workflow, and GRC route families.
6. Keep the persona control quiet. Clients may expose a "prioritize for"
   selector, but that control should not dominate the page or repeat the same
   audience label in headers, cards, and explanatory copy.
7. Keep examples public-safe. Do not document tenant names, hostnames, account
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
