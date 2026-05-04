# PLAN — Cerebro Next: Primitives, Stores, and Invariant Enforcement

> Status: DRAFT (initial landing, intended for PR discussion)
> Branch: `feat/cerebro-next-invariants-20260422`
> Owner: Platform
> Last updated: 2026-04-22

This document describes a ground-up redesign of Cerebro collapsed onto the smallest set of common primitives, backed by exactly three stores, with structural enforcement of the architectural invariants that caused the current codebase to decay.

It is both a **design doc** and a **contract**: every design decision in §3–§6 has a machine-checked rule in §7. The first concrete deliverable on this branch is the linter framework that enforces §7, independent of any migration decision.

---

## 0. TL;DR

1. **Six primitives** — `Event`, `Stream`, `View`, `Rule`, `Action`, `Agent`. Everything else (providers, findings, scans, checks, reports, nudges, runbooks) is an arrangement of these six.
2. **Three stores** — `JetStream` is the log of record; `Postgres` is current state and OLTP; `Neo4j/Aura` is a graph projection for traversal queries. No fourth store. No in-memory fallback.
3. **Sources are a CDK** — each integration is a self-contained Go module (≤300 LOC budget) behind a `Source` interface, vendored cleanly. The CDK is the *only* way to reach the outside world.
4. **Invariants are enforced structurally**, not by convention. 18 cardinal sins have lint rules; each rule fails CI, not review.
5. **Graph is second-class by intent**. All entities & findings live in Postgres; Neo4j/Aura contains URNs + edges only and is rebuilt from JetStream.

---

## 1. Problem statement

The current Cerebro exhibits every symptom of a system that grew faster than its skeleton:

| Symptom | Evidence (writer/main @ 8fa3f1ba2) |
|---|---|
| God-struct `*App` | 120+ fields, 8 mutexes, touched by every subsystem |
| Config bloat | `Config` struct: 372 exported fields |
| Graph god-struct | `Graph` struct: 44 fields |
| Provider duplication | 46 providers, ~2,400 LOC of duplicated HTTP/retry/pagination/error-wrapping |
| Silent errors | 1,802 `fmt.Errorf` without `%w` |
| Hook-driven tests | 38 package-level `var X = func(...)` test seams |
| Env-driven control flow | 172 `os.Getenv` calls outside `cmd/` |
| String-sniffed errors | 74 `strings.Contains(err.Error(), …)` |
| Unbounded resources | 31 places create goroutines without a `context.Context` tied to lifecycle |
| In-memory fallback | SQLite fallback compiled into production binary |

The common root cause is the same in every case: **invariants exist only in reviewers' heads**. The goal of this branch is to end that pattern — first by restating the design, then by making violations structurally impossible before new code lands.

---

## 2. Goals & non-goals

### Goals

- Collapse the existing surface area onto the six primitives and three stores.
- Make the new design the *default* path; legacy subsystems adapt to it.
- Eliminate every class of bug in §7 by making violations fail `make check`.
- Keep local dev friction-free: `docker compose up` runs everything with no cloud dependency.
- Keep the runtime cloud-agnostic: no AWS/GCP/Azure-specific control plane.

### Non-goals

- Rewriting all 46 providers in a single push. Providers migrate onto the Source CDK incrementally.
- Replacing Postgres or JetStream with something exotic. Both are boring, proven, and operable.
- Shipping an in-memory mode "for local dev". Local dev is Postgres + JetStream + Neo4j via compose, always.

---

## 3. Architecture — three stores

```
                    ┌────────────────────────────────────────────┐
                    │                  Sources                   │
                    │  (CDK plugins: GitHub, Okta, AWS, Slack…)  │
                    └─────────────────────┬──────────────────────┘
                                          │ CloudEvents
                                          ▼
                  ┌────────────────────────────────────────────────┐
                  │           JetStream (source of truth)           │
                  │  ENTITIES · EVENTS · FINDINGS · ACTIONS · AUDIT  │
                  └──────────┬──────────────────────────┬──────────┘
                             │                          │
                             ▼                          ▼
                 ┌───────────────────────┐    ┌──────────────────────┐
                 │  Postgres projection  │    │   Neo4j projection    │
                 │  (current state, TS)  │    │   (graph traversals) │
                 └───────────┬───────────┘    └──────────┬───────────┘
                             │                           │
                             └───────────┬───────────────┘
                                         ▼
                        ┌────────────────────────────────┐
                        │   Query/Rule/Action runtimes    │
                        │  (SQL + Cypher, authored once)  │
                        └────────────────────────────────┘
```

### 3.1 JetStream — source of truth

JetStream is the only writable long-term substrate. Every other store is a rebuildable projection.

Stream configuration:

| Stream     | Subjects                          | Retention  | Dedup window | Replicas |
|------------|-----------------------------------|-----------:|-------------:|---------:|
| `ENTITIES` | `entity.*`                        | 30 d       | 24 h         | 3        |
| `EVENTS`   | `event.*`                         | 90 d       | 1 h          | 3        |
| `FINDINGS` | `finding.*`                       | 2 y        | 24 h         | 3        |
| `ACTIONS`  | `action.*`                        | 180 d      | 24 h         | 3        |
| `AUDIT`    | `audit.*`                         | 7 y (WORM) | off          | 5        |
| `AGENT`    | `agent.*`                         | 30 d       | 1 h          | 3        |
| `DLQ`      | `*.dlq`                           | 14 d       | off          | 3        |

Subject taxonomy is append-only and versioned via a leading segment: `event.v1.cloudtrail.console_login`. `v0` is disallowed in code.

Dedup is performed with `Nats-Msg-Id = sha256(tenant|source|external_id|event_time)`. No other dedup mechanism is permitted.

The **killer capability** this unlocks is `cerebro replay`: rebuild Postgres/Neo4j from JetStream for a tenant, for a rule, or for a bug, at any past point in time.

### 3.2 Postgres — current state

Postgres holds:

- `entities` — URN-keyed current state (no history; history lives in `EVENTS`).
- `events` — TimescaleDB hypertable, `PARTITION BY LIST (tenant_id), PARTITION BY RANGE (event_time)`.
- `findings` — fingerprinted, tsvector-indexed, attached to 1..n entities, with lifecycle (open/suppressed/resolved).
- `rule_state` — counters, windows, dedup for correlation rules.
- `control_plane` — users, tenants, connectors, destinations, rule definitions.

Conventions:

- One schema per tenant for large tenants, one row per small tenant. No `WHERE tenant_id = $1` sprinkled in application code — it lives in `search_path`.
- `pg_trgm` + `tsvector` for all user-facing search.
- `LISTEN/NOTIFY` is **not** used for business logic. Notifications come from JetStream.

### 3.3 Neo4j/Aura — graph projection

Neo4j/Aura is the supported graph DB. It holds URNs and edges, not entity bodies.

- **Write path:** a single consumer reads `entity.*` from JetStream and applies MERGE/DETACH to Neo4j.
- **Read path:** traversal queries only. No analytical SQL via Neo4j. No graph writes from anywhere else.
- **Schema shape:** ≤20 indexed attributes per node type, ≤6 hops per query, URNs are the only identifier.
- **Rebuild budget:** full rebuild from JetStream must fit in ≤1 h for a median tenant.

### 3.4 Split line

| Query shape                                            | Store    |
|--------------------------------------------------------|----------|
| "Current state of entity X"                            | Postgres |
| "Events for entity X between T1 and T2"                | Postgres (Timescale) |
| "Findings matching fingerprint X, open, since T"       | Postgres |
| "All public S3 buckets reachable from role R"          | Neo4j    |
| "Blast radius of identity I in ≤4 hops"                | Neo4j    |
| "Replay from T0, apply rule R, emit findings"          | JetStream → worker → PG |

Rules that cross the split line are forbidden. If a rule needs both, it runs twice and joins at the application layer.

---

## 4. The six primitives

All user-facing concepts decompose to exactly one of these:

```go
// Every input to the system.
type Event struct {
    ID         string            // content-addressed
    Tenant     string
    Source     string            // URN of the source
    Type       string            // dotted, versioned: event.v1.cloudtrail.console_login
    OccurredAt time.Time
    Body       proto.Message     // typed per Type; never map[string]any
}

// A named, durable ordering of Events.
type Stream interface {
    Publish(ctx context.Context, e Event) error
    Subscribe(ctx context.Context, filter string, h Handler) (Subscription, error)
}

// A read-only materialization over one or more Streams.
type View interface {
    Query(ctx context.Context, q Query) (Cursor, error)
    Freshness() time.Duration
}

// A deterministic function from Events/Views to Findings (0..n).
type Rule interface {
    Spec() RuleSpec            // declarative: inputs, outputs, SLO
    Eval(ctx context.Context, in In) ([]Finding, error)
}

// A side-effecting operation with strong authorization and audit.
type Action interface {
    Preflight(ctx context.Context, f Finding) (Plan, error)
    Execute(ctx context.Context, p Plan) (Receipt, error)  // must be idempotent on (plan.id)
}

// A conversational entity that orchestrates the five above with a policy.
type Agent interface {
    Handle(ctx context.Context, turn Turn) (Response, error)
}
```

Mapping of existing concepts:

| Old concept            | New primitive                                        |
|------------------------|------------------------------------------------------|
| Provider scan          | Source → Events → Stream                             |
| Finding                | Finding (derived by Rule)                            |
| Cedar / CEL policy     | Rule                                                 |
| Runbook / autoresolve  | Action                                               |
| Slack nudge / report   | Agent                                                |
| Graph builder          | View (projection over `entity.*` stream)             |
| NLQ endpoint           | Agent + View                                         |

Every new feature must fit in this table before it is merged. "Misc" is not a primitive.

---

## 5. Source CDK

Sources are the only component allowed to talk to the outside world. Each source is a Go module under `sources/<name>/`.

### 5.1 Per-source budget

- ≤300 LOC of Go (excluding generated code and fixtures).
- 0 direct use of `net/http`, `database/sql`, `context.Background`, `os.Getenv`.
- Must declare catalog entries in `catalog.yaml`.
- Must ship golden fixtures and a replay test.

### 5.2 Interface

```go
type Source interface {
    Spec() Spec                                             // static metadata
    Check(ctx context.Context, cfg Config) error            // auth / reachability
    Discover(ctx context.Context, cfg Config) ([]URN, error)// what exists
    Read(ctx context.Context, cfg Config, since Cursor) (Pull, error)
}
```

`Pull` is a stream of `Event`, a checkpoint, and an optional next `Cursor`. Sources never write; they never know about JetStream, Postgres, or Neo4j.

### 5.3 Plugin boundary

The initial sources are in-process. When the CDK crosses an operational threshold (measured in source count + deploy blast radius), we lift the `Source` interface over hashicorp/go-plugin with the same signatures. Source authors do not notice.

### 5.4 First six sources

1. GitHub (audit + PRs + secrets).
2. Okta (users + sessions).
3. AWS CloudTrail (via Kinesis firehose → replay).
4. Slack (audit + messages for compliance).
5. Jira (issues + transitions).
6. Stripe (events, for finance-adjacent controls).

These six exercise every surface of the CDK: polling, push, pagination, large payloads, OAuth, HMAC.

---

## 6. Graph design (Neo4j/Aura)

### 6.1 Ontology

- Node types are listed in `ontology.yaml`. Adding a type requires a design-doc PR.
- Every node has a URN: `urn:cerebro:<tenant>:<type>:<id>`.
- Every edge has a typed predicate and an `asserted_at` timestamp. Edges are never "updated" — a new assertion supersedes the old.

### 6.2 Indexing & limits

- Hard cap of 20 indexed attrs per node type.
- Hard cap of 6 hops per query (enforced in the query translator).
- Global timeout of 10 s per query (p95 budget).

### 6.3 Rebuild

The graph is rebuildable in two ways:

- **Hot**: stream the last 30 d of `entity.*` and apply MERGE.
- **Cold**: re-scan via the Source CDK (last-resort, for a previously-unreachable period).

A CI job runs `cerebro graph rebuild --tenant=dogfood --dry-run` weekly and fails if rebuild time > 2× baseline.

---

## 7. The 18 cardinal sins

Each sin corresponds to an analyzer or arch test in this branch. ID = folder name under `tools/linters/`.

| # | ID                         | Rule (plain English)                                                                             |
|---|----------------------------|---------------------------------------------------------------------------------------------------|
| 1 | `maxmutex`                 | A struct may declare at most one `sync.Mutex` or `sync.RWMutex` field (transitively).            |
| 2 | `maxfields`                | A struct may declare at most 24 fields (exported + unexported).                                  |
| 3 | `novarfunc`                | Package-level `var X = func(...) …` is forbidden outside `_test.go`.                             |
| 4 | `nosleep`                  | `time.Sleep` and `time.After` are forbidden outside `_test.go` and the `runtime/backoff` pkg.   |
| 5 | `noerrstringmatch`         | `strings.Contains(err.Error(), …)` and siblings are forbidden; use `errors.Is/As`.              |
| 6 | `nountypedboundary`        | Exported functions/methods cannot accept or return `map[string]any` or `interface{}`.           |
| 7 | `nobackpointer`            | No field of type `*App` or `*Server` inside `internal/`; pass dependencies by interface.         |
| 8 | `sealedinterface`          | Interfaces tagged `//cerebro:sealed` may only be implemented in their own package.               |
| 9 | `nopanicprod`              | `panic()` is forbidden outside `_test.go`, `init()`, and the `panicsafe` pkg.                    |
| 10 | `noinmemorydb`            | SQLite/`:memory:`/embedded DB usage is forbidden in non-test builds.                             |
| 11 | `noenvoutsidecmd`         | `os.Getenv/LookupEnv` is forbidden outside `cmd/` and the `config` pkg.                          |
| 12 | `nobackgroundctx`         | `context.Background()` and `context.TODO()` are forbidden outside `cmd/` and tests.              |
| 13 | `errwrap`                 | `fmt.Errorf` with a `%s` or `%v` applied to an error is forbidden; use `%w`.                     |
| 14 | `nogoroutineleak`         | `go func()` without either `errgroup` or a `context.Context` in scope is forbidden.              |
| 15 | `noglobalstate`           | Package-level mutable `var` (non-const, non-sync.Once) is forbidden outside `cmd/`.             |
| 16 | `nofallback`              | No construct of the form "if X fails, try Y"; each capability has exactly one implementation.    |
| 17 | `noalter`                 | `ALTER TABLE` in migrations must go through the `schema/` pkg; ad-hoc SQL migrations are out.    |
| 18 | `authznotoptional`        | Any HTTP handler lacking a `//cerebro:authz:<policy>` annotation is rejected.                    |

Sins 1–6 ship in the first PR on this branch. 7–12 ship in a follow-up. 13–18 are tracked separately.

---

## 8. Seven-layer enforcement stack

Defence in depth against agentic and human drift.

1. **Architectural impossibility.** Keep the worst sins from being expressible in the first place — e.g. no package-level mutable state means no init-order bugs.
2. **Custom linters.** `tools/linters/cerebrolint` is a multichecker binary. `make check-lint` runs it.
3. **Arch tests.** `make check-arch` runs `go test ./tools/archtests/...` — module graph, back-pointer graph, SCC checks.
4. **Pre-tool hooks.** The agent runner refuses to edit a file that introduces a known-bad AST shape before invoking the tool.
5. **Pre-commit.** Cannot be bypassed with `-n`: the hook verifies its own SHA256 against `tools/hooks/integrity.sha256`.
6. **CI (sealed).** No `continue-on-error`. No `[skip ci]`. `require_status_checks` is on in branch protection.
7. **Review droid.** A separate droid scans merged diffs for any sin that escaped 1–6 and opens a revert PR.

The first three ship with this branch.

---

## 9. Deliverables on this branch

| Deliverable                                                     | Ships when |
|-----------------------------------------------------------------|:----------:|
| `PLAN.md` (this doc)                                            | PR 1       |
| `tools/linters/` module with first six analyzers + tests        | PR 1       |
| `cerebrolint` multichecker binary                               | PR 1       |
| `make check-structural` target wired into `make verify`          | PR 1       |
| Six more analyzers (sins 7–12)                                  | PR 2       |
| Arch tests (module graph, back-pointer, SCC)                    | PR 2       |
| Pre-commit integrity hook + `make verify-hook-integrity`         | PR 2       |
| Remove every existing violation (`.cerebrolint-allowlist.yml`)   | PR 3+      |
| First source on the CDK (GitHub)                                 | PR N       |

This document intentionally does not propose a rewrite cutover. It proposes the **scaffolding** that the rewrite, when (and if) authorized, is forced to honour.

---

## 10. Risks and trade-offs

- **Risk:** Linters false-positive and slow agent work. *Mitigation:* every analyzer ships with precise diagnostics that point to the exact AST node and a fix suggestion.
- **Risk:** The arch tests drift from runtime reality. *Mitigation:* they run on every PR via `make verify`; there is no local-only mode.
- **Risk:** Contributors add exceptions to the allowlist. *Mitigation:* the allowlist file is `CODEOWNERS`-protected (`@writer/platform`), every entry requires a linked issue and a date.
- **Trade-off:** The 24-field struct cap and the ≤300-LOC-per-source budget will occasionally force awkward splits. This is the intended cost.

---

## Appendix A — File layout introduced by this branch

```
PLAN.md
tools/
  linters/
    go.mod
    go.sum
    cerebrolint/
      main.go
    maxmutex/
      maxmutex.go
      maxmutex_test.go
      testdata/src/a/a.go
    maxfields/
      ...
    novarfunc/
      ...
    nosleep/
      ...
    noerrstringmatch/
      ...
    nountypedboundary/
      ...
Makefile (adds: check, check-structural, check-lint, check-arch)
```

`tools/linters/` is a **separate Go module** (its own `go.mod`). It is not vendored into the main module; it does not run at runtime; its deps (`golang.org/x/tools/go/analysis`) never reach production.

---

## Appendix B — Why these six analyzers first

The six analyzers in PR 1 address the top six by blast-radius on the current codebase:

| # | Analyzer            | Violations counted on writer/main |
|---|---------------------|----------------------------------:|
| 1 | `maxmutex`          | 8 on `App` + 11 elsewhere = 19    |
| 2 | `novarfunc`         | 38 test seams                     |
| 3 | `nosleep`           | 27 non-test `time.Sleep`          |
| 4 | `noerrstringmatch`  | 74 string-sniffs                  |
| 5 | `maxfields`         | `Config` 372, `App` 120+, `Graph` 44 |
| 6 | `nountypedboundary` | 63 exported signatures            |

Every one of those violations is a ticking correctness bug waiting to bite in production.

---

## Appendix C — Workflow graph durability plan

> Status: IN PROGRESS
> Branch: `feat/cerebro-next-workflow-durability-20260427`
> Owner: Platform
> Last updated: 2026-04-27

Recent finding workflow work added notes, ticket links, decision writes, action writes, outcome writes, and lifecycle bridges into the graph. That proved the workflow vocabulary, but it also introduced a dangerous gap: several workflow mutations can now write directly to Neo4j, or mutate Postgres and then project to Neo4j as a side effect. The graph should remain a rebuildable projection, not an unreplayable second source of truth.

### C.1 Problem statement

The workflow layer currently has five concrete risks:

1. **Graph-only durability risk** — `internal/knowledge.Service` creates decision/action/outcome graph nodes directly. If Neo4j is rebuilt from the append log, those workflow nodes disappear.
2. **Partial-failure risk** — finding notes/tickets persist to Postgres and then project to graph; graph failure can leave durable state without graph state.
3. **Silent drift risk** — finding resolve/suppress bridges intentionally ignore graph projection errors so callers cannot tell whether lifecycle workflow artifacts were materialized.
4. **Contract drift risk** — route names and event names are split across `/platform/knowledge/*`, `/graph/write/*`, and `/graph/actuate/*` without one canonical workflow event contract.
5. **Read-loop gap** — writes exist before a typed timeline/read model, so product clients cannot reliably answer "what happened to this finding?"

### C.2 Target architecture

Workflow writes should follow the same model as source-runtime sync:

```
request
  -> validate and normalize
  -> append workflow EventEnvelope to JetStream
  -> project the same event into Neo4j immediately
  -> replay the same event later to rebuild Neo4j
```

Postgres remains the current-state store for findings; Neo4j remains a graph projection; JetStream is the durable workflow event stream. Direct graph writes are allowed only inside workflow projectors that can be run both inline and during replay.

### C.3 Event contract

Workflow events use `cerebro.v1.EventEnvelope` with JSON payloads and stable event IDs.

| Event kind | Trigger | Durable payload |
|---|---|---|
| `workflow.v1.knowledge.decision_recorded` | `WriteDecision` | decision ID/type/status, target IDs, evidence IDs, action IDs, temporal metadata, freeform metadata |
| `workflow.v1.knowledge.action_recorded` | `WriteAction` | action ID/type/title, recommendation context, decision ID, target IDs, temporal metadata |
| `workflow.v1.knowledge.outcome_recorded` | `WriteOutcome` | outcome ID/type/verdict, decision ID, target IDs, impact/confidence, temporal metadata |
| `workflow.v1.finding.note_added` | `AddFindingNote` | finding snapshot keys, note ID/body/created-at, primary resource URN |
| `workflow.v1.finding.ticket_linked` | `LinkFindingTicket` | finding snapshot keys, ticket URL/name/external ID/linked-at, primary resource URN |
| `workflow.v1.finding.status_changed` | resolve/suppress | finding snapshot keys, new status, generated decision/outcome IDs |

Required event attributes:

- `tenant_id`
- `source_system`
- `workflow_kind`
- entity-specific IDs such as `decision_id`, `action_id`, `outcome_id`, or `finding_id`

### C.4 Implementation phases

#### Phase 1 — Durable knowledge workflow events

Goal: make decision/action/outcome graph writes replayable without changing external API behavior.

1. Add `internal/workflowevents` with:
   - event kind constants
   - typed decision/action/outcome payload structs
   - deterministic event ID helpers
   - JSON payload encode/decode helpers
2. Add `internal/workflowprojection` with:
   - a projector that converts workflow events into `ports.ProjectedEntity` and `ports.ProjectedLink`
   - idempotent projection for decision/action/outcome events
3. Extend `knowledge.Service` so it can receive an optional `ports.AppendLog`.
4. For `WriteDecision`, `WriteAction`, and `WriteOutcome`:
   - build the workflow event before graph projection
   - append the event when an append log is configured
   - project from the event, not from duplicate handwritten graph code
5. Wire the bootstrap app and Connect service constructors to pass `deps.AppendLog`.
6. Add tests proving:
   - append failure prevents graph writes
   - graph failure leaves an appended event available for replay
   - replaying the same workflow event is idempotent

#### Phase 2 — Replay support beyond runtime-scoped events

Goal: replay workflow events independently of source runtime IDs.

1. Extend `ports.ReplayRequest` with optional fields:
   - `KindPrefix`
   - `TenantID`
   - `AttributeEquals`
2. Update JetStream replay filtering to support runtime replay and workflow replay.
3. Add a workflow replay service that replays `workflow.v1.*` events and projects them through `internal/workflowprojection`.
4. Add focused JetStream replay tests for kind-prefix and tenant filtering.

#### Phase 3 — Finding workflow events

Goal: make finding notes, tickets, and lifecycle decisions replayable.

1. Emit workflow events for note/ticket/status changes with enough finding snapshot metadata to rebuild graph annotations.
2. Project those events through `internal/workflowprojection`.
3. Replace direct note/ticket/status graph helper calls with event projection.
4. Stop swallowing status bridge projection errors; either return them or record durable failed-projection metadata.
5. Add tests for persisted finding state plus durable workflow event emission.

#### Phase 4 — Transactional outbox

Goal: make Postgres finding state changes and workflow event creation atomic.

1. Add a small Postgres workflow outbox table for finding mutations.
2. Write finding state and outbox records in the same transaction.
3. Add a dispatcher that appends outbox records to JetStream and marks them delivered.
4. Add reconciliation/dead-letter paths for failed dispatch.

#### Phase 5 — Typed workflow reads and timeline

Goal: expose the product loop that the write primitives enable.

1. Add typed read models for decisions, actions, and outcomes.
2. Add a finding timeline API that merges notes, tickets, status, evidence, decisions, actions, and outcomes.
3. Add report metrics for stale actions, unresolved decisions, and outcome effectiveness.

### C.5 Execution rules for this branch

This branch will execute Phase 1 only. It should not attempt a transactional outbox or public read API yet. The branch is complete when:

- knowledge workflow writes append durable workflow events when `AppendLog` is configured
- the same events can be projected by a reusable workflow projector
- existing decision/action/outcome HTTP and Connect behavior is preserved
- focused tests and `make verify` pass

### C.6 Follow-up branch order

1. `feat/workflow-replay-filters` — Phase 2.
2. `feat/finding-workflow-events` — Phase 3.
3. `feat/finding-workflow-outbox` — Phase 4.
4. `feat/workflow-timeline-reads` — Phase 5.
