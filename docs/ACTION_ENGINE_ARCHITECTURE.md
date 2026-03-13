# Shared Action Engine Architecture

Issue `#143` moves Cerebro's security-side actuation away from two parallel execution stacks and onto one shared action substrate.

The immediate goal is modest and structural:

- keep `remediation` and `runtime response` as application-facing concepts
- unify their execution model underneath
- persist action executions and timelines in the shared execution store instead of process-local state

## Why This Exists

Before this cut, Cerebro had two overlapping execution systems:

- remediation rules/executions with approval and ticketing/webhook side effects
- runtime response policies/executions with a separate approval and action loop

They were solving the same underlying problem:

- match a signal against a typed trigger
- build a plan of ordered steps
- gate on approval when required
- execute steps with failure policy and timeout semantics
- persist execution state and event history

Keeping that duplicated would make issue `#154` worse, not better. "Actual executors" would have landed twice.

## Core Model

`internal/actionengine` is the shared substrate.

It defines:

- `Signal`: the triggering input
- `Trigger`: matching rules for signals
- `Playbook`: an ordered action plan
- `Step`: one executable action with parameters, timeout, approval, and failure policy
- `Execution`: durable run state
- `Event`: append-only execution timeline

This is intentionally smaller than a general workflow engine. It is the minimum model needed to unify remediation and runtime response without importing a full DAG/orchestration product into the core.

## Persistence Boundary

The action engine persists through `internal/executionstore` using namespace `action_engine`.

That gives Cerebro one shared durability seam for:

- workload scans
- image scans
- function scans
- connector validation
- action executions

This is the correct boundary for now because it prevents new subsystems from drifting back into ad hoc in-memory orchestration.

Longer term, the execution-store backend may move beyond SQLite. The contract should stay stable even if the storage implementation changes.

## Application Adapters

The current integration keeps external behavior stable while removing duplicated sequencing logic.

### Remediation

`internal/remediation/executor.go` now:

- converts a remediation rule into an action-engine playbook
- converts trigger data into a generic signal
- executes through the shared action engine
- maps shared execution state/results back onto remediation-native execution records

### Runtime Response

`internal/runtime/response.go` now:

- converts a response policy into an action-engine playbook
- converts findings into a generic signal
- persists the full finding context through `TriggerData`
- executes approvals and action steps through the shared action engine

Preserving the original finding payload is important. Approval-based executions must resume with the same context that triggered them, not a partially reconstructed placeholder.

## Locking Rule

Action execution must not happen under policy-map locks.

The runtime engine now copies the matched policy before leaving the read path, then creates the execution outside the map lock. This avoids lock-upgrade deadlocks and keeps action execution from being serialized behind policy reads.

The same standard should apply anywhere Cerebro moves toward longer-running execution control.

## External Reference Points

GitHub repos worth stealing from, selectively:

- `StackStorm/st2`
  - strong rule -> action/execution separation
  - event-driven automation is treated as a durable execution domain, not just handler glue
- `argoproj/argo-events`
  - clear signal/trigger bridge
  - useful mental model for event ingestion feeding durable execution
- `argoproj/argo-workflows`
  - durable workflow runtime and execution history
  - useful reference for how far Cerebro should not go unless DAG-level orchestration is actually needed

The point is not to copy those systems wholesale. The point is to keep Cerebro's substrate typed, durable, and composable.

## Next Steps

1. Land issue `#154` on top of this substrate so runtime and remediation stop carrying separate executor growth.
2. Expose shared action executions/events through a typed platform or security read surface.
3. Move more execution families onto the shared execution store without inventing new persistence silos.
4. Decide whether the execution-store backend remains SQLite or becomes a multi-worker store.
