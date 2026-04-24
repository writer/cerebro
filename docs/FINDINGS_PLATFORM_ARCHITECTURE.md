# Findings Platform Architecture

This document explains why Cerebro now treats findings as a shared platform primitive instead of leaving detection logic trapped inside one-off source flows.

It complements [ARCHITECTURE.md](./ARCHITECTURE.md), [PLATFORM_TRANSITION_ARCHITECTURE.md](./PLATFORM_TRANSITION_ARCHITECTURE.md), and [RUNTIME_VISIBILITY_ARCHITECTURE.md](./RUNTIME_VISIBILITY_ARCHITECTURE.md).

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
- Make adding a new detector a registration step, not a service fork.
- Preserve the current storage model where findings remain current-state records in Postgres.

## Current Platform Model

The current findings platform now has five layers.

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

### 4. Persisted Finding Reads

Persisted findings remain the contract clients consume after evaluation:

- `GET /source-runtimes/{runtimeID}/findings`
- `ListFindings(...)`

These reads stay generic and source-agnostic. Rules populate persisted findings; clients read findings, not source-specific detector internals.

### 5. Reporting

Reports such as `finding-summary` operate on persisted findings instead of on raw source logic.

Why:

- reporting should summarize durable state
- rules should emit findings
- reports should consume findings

That separation keeps the platform layered cleanly.

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
  "http://localhost:8080/source-runtimes/writer-okta-audit/findings/evaluate?rule_id=identity-okta-policy-rule-lifecycle-tampering&event_limit=100"
```

This replays one runtime and persists findings emitted by the selected rule.

### Read persisted findings

```bash
curl \
  "http://localhost:8080/source-runtimes/writer-okta-audit/findings?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=open"
```

This reads normalized persisted findings, not transient rule output.

## Current Built-In Rule

Today the built-in catalog contains one rule:

- `identity-okta-policy-rule-lifecycle-tampering`

It lives in `internal/findings/okta_policy_rule_lifecycle_tampering_rule.go`.

Why it was extracted into its own file:

- the service should not know Okta-specific event semantics
- rule logic should be independently testable
- future rules should look like sibling registrations, not more service branching

## Code Map

- `internal/findings/registry.go` — rule interface and rule catalog
- `internal/findings/service.go` — replay orchestration and explicit rule selection
- `internal/findings/okta_policy_rule_lifecycle_tampering_rule.go` — first built-in finding rule
- `internal/bootstrap/app.go` — HTTP and ConnectRPC exposure
- `proto/cerebro/v1/bootstrap.proto` — transport contract for rule listing and rule-scoped evaluation

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
- suppression, assignment, and lifecycle workflows in the bootstrap surface

## Why This Is The Right Intermediate Step

This change is intentionally small but architectural:

- it makes findings extensible without pretending the full policy/control system already exists
- it gives clients a discoverable rule catalog now
- it preserves replay as the authoritative evaluation substrate
- it keeps rule logic, finding persistence, and reporting as separate layers

That is the platform shape we want to keep building on.
