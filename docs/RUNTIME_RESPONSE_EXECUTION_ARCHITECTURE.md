# Runtime Response Execution Architecture

Issue `#154` is the first concrete executor layer on top of the shared action engine from issue `#143`.

See [RUNTIME_VISIBILITY_ARCHITECTURE.md](./RUNTIME_VISIBILITY_ARCHITECTURE.md) for the complementary sensor, ingest, graph-projection, and response-outcome design that should feed this execution layer.

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

Current behavior:

- `block_ip` and `block_domain` update the runtime blocklist immediately
- `scale_down` is advertised as unsupported until a Kubernetes executor is wired in

### 2. Ensemble-delegated executors

These actions depend on a host, container, or cloud-side actuator:

- `scale_down`
- `kill_process`
- `isolate_container`
- `isolate_host`
- `quarantine_file`
- `revoke_credentials`

The intended future path is the same remote tool invocation path as remediation:

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

Until a remote tool provider is configured and wired, these actions fail with a typed capability error instead of silently pretending to succeed.

If no server-derived trusted actuation scope is attached to the execution context, these actions fail closed before any local or remote containment target is invoked.

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

The blocklist is persisted through the Postgres state store and exposed through `/platform/runtime-response/blocklist`, so multiple bootstrap replicas see the same containment state.

The local blocklist update is the guaranteed action.

### Kubernetes scale down

`scale_down` is a planned direct executor. It should use a Kubernetes client loaded from:

- explicit kubeconfig/context if configured in the scaler
- otherwise normal default kubeconfig loading
- otherwise in-cluster config fallback

This is intentionally narrow:

- `deployment`
- `statefulset`

Anything else should resolve through metadata or fall back to a remote tool.

`block_ip` and `block_domain` require a server-derived trusted actuation scope. Cerebro will not mutate containment state from unauthenticated runtime target identifiers.

## Follow-On Gaps

This cut is intentionally not the end state.

Still missing:

1. Remote propagation from the durable blocklist into concrete network/device controls.
2. Stronger target resolution from graph identity instead of heuristic runtime metadata.
3. Provider-native credential revocation and host/network isolation for common clouds.
4. Kubernetes `scale_down` and remote-tool executors wired behind the same trusted-scope checks.

Capability coverage is visible at `/platform/runtime-response/capabilities`; unsupported actions return typed errors instead of successful-looking no-ops.

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
