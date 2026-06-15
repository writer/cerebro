# Findings Platform Architecture

This document explains why Cerebro now treats findings as a shared platform primitive instead of leaving detection logic trapped inside one-off source flows.

It complements [ARCHITECTURE.md](./ARCHITECTURE.md), [SOURCE_RUNTIME_GUIDE.md](./SOURCE_RUNTIME_GUIDE.md), and [GRAPH_OPERATIONS.md](./GRAPH_OPERATIONS.md).

## Why This Exists

The platform already had several durable seams that pointed in the right direction:

- source runtimes give us a stable replay boundary
- claims give us normalized, runtime-scoped state
- graph projection gives us relationship context
- findings persist a durable current-state outcome
- reports summarize persisted outcomes instead of recomputing everything ad hoc

The missing piece was how detections entered that system.

Before this change, runtime finding evaluation was effectively a hardcoded branch for one Okta rule inside `internal/findings/service.go`. That worked as a spike, but it had the wrong long-term shape:

- adding a new finding meant editing service orchestration instead of registering a new rule
- platform clients had no catalog of what rules existed
- the service owned source-specific detection logic instead of remaining a generic replay/evaluation seam
- the API contract implied a platform capability, but the implementation still behaved like a one-off detector

The rule registry fixes that.

## Design Goals

- Keep the service generic and deterministic.
- Make rules discoverable to platform clients.
- Keep persisted finding lineage explicit through `rule_id`.
- Make each evaluation attempt durable and inspectable after the request returns.
- Make adding a new detector a registration step, not a service fork.
- Preserve the current storage model where findings remain current-state records in Postgres.

## Current Platform Model

The current findings platform now has six layers.

### 1. Runtime Replay

`SourceRuntime` remains the control-plane boundary that scopes evaluation. The service replays runtime events through the append log for one runtime at a time.

Why:

- replay is the durable substrate
- it avoids coupling rule execution to live source reads
- it gives us deterministic re-evaluation over the same runtime history

### 2. Registered Finding Rules

`internal/findings/registry.go` defines the platform rule interface:

```go
type Rule interface {
    primitives.Rule
    SupportsRuntime(*cerebrov1.SourceRuntime) bool
    Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error)
}
```

Why this shape:

- `primitives.Rule` keeps findings aligned with the repo's broader rule abstraction
- `SupportsRuntime` keeps source scoping declarative instead of leaking source checks into the service
- `Evaluate(...)` returns normalized persisted findings, which means rules emit platform records directly

### 3. Generic Evaluation Service

`internal/findings/service.go` now selects a rule from the registry and runs replay through that rule.

Why the service selects exactly one rule per call:

- the response returns one `RuleSpec`
- persisted findings already carry one `rule_id`
- fingerprints remain stable and rule-scoped
- failures stay attributable to one rule and one event

That is why the API now accepts `rule_id` for explicit rule selection.

### 4. Durable Evaluation Runs

Each evaluation now persists a `FindingEvaluationRun` record before replay starts and finishes that record with either completed or failed status.

Why this layer exists:

- evaluation is operational work, not just a transient HTTP response
- platform clients need a durable audit trail for when a rule last ran
- failures need to be inspectable without scraping logs
- reports and future orchestration can anchor on a run identifier instead of guessing from timestamps

The run captures:

- which `runtime_id` and `rule_id` were evaluated
- how many events were replayed
- which finding IDs were upserted
- whether the run completed or failed
- when the run started and finished

This keeps evaluation lineage separate from the findings themselves. Findings remain current-state security outcomes; runs explain how those outcomes were produced.

### 5. Persisted Finding Reads

Persisted findings remain the contract clients consume after evaluation:

- `GET /source-runtimes/{runtimeID}/findings`
- `ListFindings(...)`

These reads stay generic and source-agnostic. Rules populate persisted findings; clients read findings, not source-specific detector internals.

### 6. Reporting

Reports such as `finding-summary`, `risk-delta`, and `risk-action-plan` operate on persisted findings instead of on raw source logic. `risk-action-plan` is backed by the shared `internal/riskplan` engine, which ranks remediation candidates by reusing the bounded `risk-delta` simulation path and returns typed score breakdowns, expected reduction, effort, ownership, evidence quality, prior outcome signals, and optional plan diffs. It recommends next-best actions without executing remediation or introducing a new store.

Why:

- reporting should summarize durable state
- rules should emit findings
- reports should consume findings
- action planning should remain an explainable, read-only plan over current findings and graph evidence

That separation keeps the platform layered cleanly.

The same planner engine is exposed to MCP clients through read-only tools:

- `cerebro.risk.actions.list` returns a bounded ranked plan with the typed candidate contract.
- `cerebro.risk.actions.explain` returns the full explanation for one candidate ID, including score breakdown, risk delta, effort, ownership, evidence quality, and outcome-learning signals.

## Public Platform Surfaces

The bootstrap layer now exposes a minimal but explicit findings platform:

### List registered finding rules

```bash
curl http://localhost:8080/finding-rules
```

This returns the discoverable rule catalog so clients can choose a `rule_id` instead of hardcoding assumptions.

### Evaluate one runtime through one rule

```bash
curl -X POST \
  "http://localhost:8080/source-runtimes/<runtime-id>/findings/evaluate?rule_id=<rule-id>&event_limit=100"
```

This replays one runtime, persists findings emitted by the selected rule, and returns the durable evaluation run metadata.

### Inspect evaluation runs

```bash
curl \
  "http://localhost:8080/source-runtimes/<runtime-id>/finding-evaluation-runs?rule_id=<rule-id>&status=completed&limit=20"

curl http://localhost:8080/finding-evaluation-runs/<run-id>
```

These endpoints answer operational questions like "when did this rule last run?", "did it fail?", and "which findings came from that pass?"

### Read persisted findings

```bash
curl \
  "http://localhost:8080/source-runtimes/<runtime-id>/findings?rule_id=<rule-id>&status=open"
```

This reads normalized persisted findings, not transient rule output.

## Current Built-In Catalog

The built-in public detection catalog currently contains 66 rules across cloud, identity, GitHub, GRC, runtime, endpoint, and vulnerability domains. The generated public catalog lives at `internal/findings/public_detection_catalog.json`; `make detection-catalog-check` verifies that it stays in sync with the registered rule metadata.

Rules live as small files under `internal/findings/` and register through the built-in registry. The original Okta lifecycle-tampering detector is now one example in a broader catalog, not the only supported rule. This shape keeps the service generic:

- the service should not know Okta-specific event semantics
- rule logic stays independently testable
- future rules remain sibling registrations, not service branching

## Code Map

- `internal/findings/registry.go` — rule interface and rule catalog
- `internal/findings/service.go` — replay orchestration, explicit rule selection, and durable evaluation run lifecycle
- `internal/findings/*_rule.go` — built-in signal and graph-backed finding rules
- `internal/findings/public_detection_catalog.json` — generated public detection catalog
- `internal/statestore/postgres/findingevaluationruns.go` — persisted evaluation run storage and query filters
- `internal/bootstrap/app.go` — HTTP and ConnectRPC exposure
- `proto/cerebro/v1/bootstrap.proto` — transport contract for rule listing, rule-scoped evaluation, and run inspection

## How To Add A New Finding Rule

1. Create a new rule file under `internal/findings/`.
2. Implement `Spec()`, `SupportsRuntime(...)`, and `Evaluate(...)`.
3. Emit normalized `ports.FindingRecord` values with stable IDs/fingerprints.
4. Register the rule in `Builtin()`.
5. Add:
   - registry coverage
   - service selection coverage
   - bootstrap forwarding coverage

## What This Does Not Solve Yet

This is a platform foundation, not the final findings system.

Still intentionally out of scope:

- evaluating many rules in one request
- cross-runtime or tenant-wide rule orchestration
- control/check mapping
- evidence bundles beyond current finding attributes and graph/report joins
- retries, leases, or scheduler-owned evaluation execution
- suppression, assignment, and lifecycle workflows in the bootstrap surface

## Why This Is The Right Intermediate Step

This change is intentionally small but architectural:

- it makes findings extensible without pretending the full policy/control system already exists
- it gives clients a discoverable rule catalog now
- it gives the platform a durable execution history instead of burying evaluation inside request logs
- it preserves replay as the authoritative evaluation substrate
- it keeps rule logic, finding persistence, and reporting as separate layers

That is the platform shape we want to keep building on.
