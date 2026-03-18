# Runtime Response Execution Architecture

Issue `#154` is the first concrete executor layer on top of the shared action engine from issue `#143`.

The design goal is practical:

- make default runtime response policies capable of taking real action
- avoid building a second orchestration subsystem beside `internal/actionengine`
- distinguish between actions Cerebro can do directly now and actions that require remote execution
- require an explicit trusted actuation scope before destructive runtime targets are accepted
- keep the default destructive runtime policies approval-gated until source identity binding exists

## Execution Tiers

Runtime response actions now fall into three buckets.

### 1. Direct local executors

These are actions Cerebro can perform itself without a remote agent:

- `block_ip`
- `block_domain`
- `scale_down`

Current behavior:

- `block_ip` and `block_domain` update the runtime blocklist immediately
- `scale_down` uses a Kubernetes client when the finding carries an explicit workload target

For `scale_down`, the target must resolve to a typed workload reference like:

- `deployment:namespace/name`
- `statefulset:namespace/name`

Resolution currently uses runtime finding metadata first, then explicit resource identifiers where available.

### 2. Ensemble-delegated executors

These actions depend on a host, container, or cloud-side actuator:

- `kill_process`
- `isolate_container`
- `isolate_host`
- `quarantine_file`
- `revoke_credentials`

They use the same remote tool invocation path as remediation:

- `RemoteTools.CallTool(...)`

Default tool names are:

- `security.runtime.kill_process`
- `security.runtime.isolate_container`
- `security.runtime.isolate_host`
- `security.runtime.quarantine_file`
- `security.runtime.revoke_credentials`
- `security.runtime.scale_down`
- `security.runtime.block_ip`
- `security.runtime.block_domain`

If no remote tool provider is configured, these actions fail with a typed capability error instead of silently pretending to succeed.

If no trusted actuation scope is attached to the execution context, these actions fail closed before any local or remote containment target is invoked.

### 3. Control-plane side effects handled elsewhere

These remain outside the runtime action handler itself:

- `alert`
- `create_ticket`

They are still modeled in policy/action execution, but their concrete side effects are owned by other subsystems.

## Why This Split

This keeps the runtime layer honest:

- local actions stay local
- remote actions go through one reusable remote-execution seam
- unsupported actions fail explicitly

That is better than a half-local, half-stubbed action set where policies "succeed" without containment happening.

## Direct Action Semantics

### Blocklist updates

`block_ip` and `block_domain` now produce immediate containment state inside the runtime blocklist.

If a remote tool provider is present, Cerebro also attempts best-effort remote enforcement with the matching `security.runtime.*` tool.

The local blocklist update is the guaranteed action.

### Kubernetes scale down

`scale_down` uses a Kubernetes client loaded from:

- explicit kubeconfig/context if configured in the scaler
- otherwise normal default kubeconfig loading
- otherwise in-cluster config fallback

This is intentionally narrow:

- `deployment`
- `statefulset`

Anything else must resolve through metadata or fall back to a remote tool.

`scale_down`, `block_ip`, and `block_domain` also require a trusted actuation scope. Cerebro will not mutate containment state from unauthenticated runtime target identifiers.

## Follow-On Gaps

This cut is intentionally not the end state.

Still missing:

1. Persisted/runtime-distributed blocklist propagation instead of process-local memory only.
2. Stronger target resolution from graph identity instead of heuristic runtime metadata.
3. Provider-native credential revocation and host/network isolation for common clouds.
4. Typed API visibility into runtime action capability coverage and executor mode.

## GitHub Reference Points

Patterns worth stealing selectively:

- `falcosecurity/falco`
  - runtime detections should map cleanly onto containment paths, not just alert streams
- `stackrox/stackrox`
  - runtime security benefits from separating detection from enforcement capability
- `aquasecurity/trivy-operator`
  - strong example of Kubernetes-native control loops and typed security CRD/result boundaries

The useful lesson across them is not "copy their architecture." It is:

- keep detection, execution, and result recording separate
- make capability boundaries explicit
- do not hide missing actuator coverage behind successful-looking status
