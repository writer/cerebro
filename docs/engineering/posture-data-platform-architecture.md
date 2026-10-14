# Posture Data Platform Architecture

- **Status:** Proposed
- **Date:** 2026-10-14
- **Related boundaries:** [`non-goals.md`](non-goals.md), [`rust-source-runtime-adr.md`](rust-source-runtime-adr.md), [`durability-contract.md`](durability-contract.md), [`source-sync-recovery.md`](source-sync-recovery.md), [`jetstream-durability-acceptance-matrix.md`](jetstream-durability-acceptance-matrix.md)

## Decision

Cerebro's next-generation posture platform is built as seven layers with one
shared ingestion contract. Every layer has explicit delivery guarantees,
bounded resource use, measurable freshness, and a documented failure mode.

1. **Telemetry lake access.** Security telemetry already lands in the
   organization's security lakehouse (Panther on Databricks). Cerebro reads it
   in place. It does not copy raw logs.
2. **Posture collection.** Cloud, SaaS, and identity collectors gather current
   configuration state, starting with organization-wide AWS fan-out.
3. **Ingestion core.** One pipeline for every source: idempotent records,
   per-record quarantine, classified failures, bounded runs, and per-source
   service level objectives.
4. **Security graph and findings.** The existing Rust graph and policy kernel
   remain the authority for durable, current-state findings.
5. **Alert delivery.** Findings leave Cerebro through a durable outbox and a
   typed Action, with deduplication, throttling, and delivery receipts.
6. **Web application and API.** A typed, versioned API and the Next.js console
   expose source health, findings with evidence, and delivery state.
7. **Reliability and operations.** End-to-end tracing, SLOs, runbooks, and
   gated promotion.

This document is the umbrella plan. Each layer ships as its own reviewed
change. A layer that crosses a non-goal amends [`non-goals.md`](non-goals.md)
in the same change that crosses it.

## Principles

- **One copy of telemetry.** The security lakehouse is the system of record for
  raw telemetry. Cerebro stores posture state: entities, relationships,
  findings, and bounded derived signals.
- **Compute next to the data.** Aggregation over raw logs runs inside the
  lakehouse. Cerebro reads compact, incremental results.
- **Same guarantees for every source.** Replay-safe identity, per-record
  isolation, classified retry, bounded runs, and measured freshness are
  substrate properties, not per-connector code.
- **Fail closed and stay honest.** A source that cannot prove freshness reports
  degraded. Unknown is never reported as healthy or as a failing control.
- **Everything in code.** Schemas, contracts, policies, lakehouse jobs, and
  infrastructure are versioned and reviewed.

## Layer 1: Telemetry lake access

### Shape

- Storage and compute are separate in the lakehouse. Cerebro does not need a
  read replica. It uses a **dedicated serverless SQL warehouse** that reads the
  same tables as the SIEM. Workload isolation comes from separate compute, not
  copied data.
- Cerebro authenticates as a **Unity Catalog service principal** with OAuth
  machine-to-machine credentials. Personal access tokens are not supported.
- The principal has `SELECT` on the telemetry schemas it needs and ownership of
  one Cerebro-owned derived schema. Column masks or views restrict sensitive
  fields before Cerebro reads them.

### Derived signals

- Lakehouse jobs, defined as versioned code and deployed with the lakehouse's
  own tooling, materialize compact signals in the derived schema. Examples:
  identity last-seen by principal, failed-authentication rate, privileged API
  use, data access by principal and asset.
- Jobs process incrementally by event-time partition or change data feed. They
  never full-scan history on a schedule.
- Each derived table declares its grain, key, freshness target, and the raw
  tables it reads.

### Reading

- A Deep-tier Source reads derived tables through the SQL Statement Execution
  API. Large results use Arrow external links. The source never issues
  unbounded queries.
- Each query carries a timeout, a row limit, a cost tag, and a parameterized
  watermark. The watermark is the source checkpoint, so freshness is measurable
  and replay is bounded.
- The warehouse auto-stops when idle. Query cost is attributed per derived
  table.

### SIEM alerts

- SIEM alerts and rule matches are read incrementally on a short interval with
  a cursor. They become correlation evidence and graph context, never findings
  on their own. See "Findings are not a one-to-one mirror of upstream alerts"
  in [`non-goals.md`](non-goals.md).
- Push delivery of alerts is a later option. It requires the non-goal amendment
  described under Layer 3.

### Non-goal alignment

- "One log of record. One state store. One graph projection. No fourth store."
  The derived schema is part of the external analytics layer, not a Cerebro
  store. Cerebro holds no copy of raw telemetry and does not replay from the
  lakehouse.
- "Cerebro is a posture product. It is not a SIEM." Raw log retention and
  investigation stay in the SIEM.
- "Sources are the only path to the outside world." All lakehouse access goes
  through the Source CDK.

## Layer 2: Posture collection

- **Organization fan-out.** An organization-level AWS source discovers member
  accounts and assumes a read-only role per account. Work is sharded by
  account, region, and service family, with bounded concurrency per account and
  provider throttling respected per API.
- **Per-shard health.** Freshness, coverage, and failure class are reported per
  account and region, so one inaccessible account degrades only its own shard.
- **Coverage.** Existing resource families and rules are kept. Coverage is
  mapped to CIS AWS Foundations and AWS Foundational Security Best Practices,
  and gaps are closed by priority.
- **SaaS and identity.** Okta, Google Workspace, GitHub, and similar collectors
  use the same fan-out, health, and coverage model.

## Layer 3: Ingestion core

The runtime enforces the error contract and page recovery rules already
ratified in [`rust-source-runtime-adr.md`](rust-source-runtime-adr.md). This
layer closes the gap between that contract and current runtime behavior.

### Record path

`provider page → validate per record → normalize → append (stable message ID) → project → progress`

- Event identity is stable across retries and replays. Equivalent replays are
  idempotent. Changed content is a new revision of the same identity.
- An `invalid_record` failure quarantines that record with a bounded receipt
  (reason, field path, contract revision, payload digest). The rest of the page
  continues. Quarantined records are listable and replayable after a contract
  fix.
- Page progress never advances ahead of append and projection, as required by
  [`source-sync-recovery.md`](source-sync-recovery.md).

### Failure classes and policy

| Class | Policy |
| --- | --- |
| `unauthorized`, `permission_denied`, `invalid_config` | Stop the family, report the required operator action, no retry loop |
| `rate_limited` | Wait for the provider's declared delay, then resume from the checkpoint |
| `provider_unavailable` | Exponential backoff with full jitter, bounded attempts, then open a per-source circuit |
| `decode_failed` | Stop the family until the contract changes |
| `invalid_record` | Quarantine the record and continue |
| `budget_exhausted` | Commit completed pages, resume next run from the checkpoint |

Every run has a time, page, record, and byte budget. A run that hits its budget
is incomplete, not failed.

### Backbone and contracts

- JetStream runs with three replicas for the source and workflow streams.
- Event contracts are versioned in `proto/`, with breaking-change checks in CI.
- Replay and backfill are first-class, rate-limited operations with receipts.

### Push intake

[`non-goals.md`](non-goals.md) limits push traffic to first-party device agents.
Third-party webhook intake is out of scope until a separate change amends that
entry. Such a change must define per-provider signature verification, replay
windows, durable acceptance before acknowledgement, and the same record path as
pulls. Until then, near-real-time sources use short-interval incremental pulls.

## Layer 4: Security graph and findings

- The Rust graph, policy kernel, and stale-finding resolution remain the
  authority for findings.
- Findings are current-state and graph-correlated. Lakehouse signals enrich
  posture state; for example, an offboarded identity with recent activity, or a
  publicly reachable asset accessed by an unexpected principal.
- Every finding carries its evidence, including the derived-table row and
  query identity behind a lakehouse-derived signal.

## Layer 5: Alert delivery

- A finding transition that requires notification writes a delivery intent to a
  durable outbox in the same transaction as the finding state change.
- A delivery worker sends each intent through a typed Action provider, so
  outbound calls follow the Action contract and the "Sources are the only path
  to the outside world" boundary.
- Each intent carries a dedupe key derived from the finding fingerprint and
  transition. Throttling and digesting are applied per route.
- Delivery state (`pending`, `sent`, `failed`, `acknowledged`) is recorded and
  visible.
- The default route sends findings to the SIEM as the alert hub, so existing
  on-call routing is reused. Direct chat and paging routes are supported as
  explicit routes, not as silent fallbacks.

## Layer 6: Web application and API

- The API is typed and versioned, generated from `proto/` and the OpenAPI
  contract. The console reaches it through its server-side proxy.
- Sign-in uses OIDC single sign-on. Roles map from identity provider groups.
- Console surfaces: source health (freshness, failure class, quarantine),
  findings with graph path and evidence, asset and identity exploration, and
  alert delivery state.

## Layer 7: Reliability and operations

- OpenTelemetry traces follow a record from source page through append,
  projection, finding transition, and delivery.
- Per-source metrics: freshness lag, records read, committed, and quarantined,
  and failures by class.
- SLOs: per-source freshness, finding-to-delivery latency, and pipeline error
  budget. Each SLO has a dashboard, an alert, and a runbook per failure class.
- Releases promote through environments with health gates.

## Build sequence and acceptance gates

1. **Ingestion core.** Per-record quarantine, classified failure policy,
   run budgets, per-source metrics. Gate: one invalid record cannot fail a run;
   every failure reports a class; freshness lag is emitted for every source.
2. **Telemetry lake access.** Service principal, dedicated warehouse, derived
   schema, first derived tables, Deep-tier reader with watermarks. Gate: reads
   are incremental, bounded, and cost-attributed.
3. **Organization fan-out.** Gate: per-account health, and one denied account
   does not affect others.
4. **SIEM alert evidence.** Gate: alerts correlate as evidence; no one-to-one
   findings.
5. **Alert delivery.** Gate: no duplicate deliveries for one transition, and
   every intent reaches a terminal or visible failed state.
6. **Console surfaces.**
7. **SLOs and dashboards,** added per layer and formalized here.

## Open decisions

- The repository location for lakehouse job definitions.
- Whether third-party push intake is worth a non-goal amendment once
  short-interval pulls are measured.
