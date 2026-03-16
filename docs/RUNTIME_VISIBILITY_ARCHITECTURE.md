# Runtime Visibility Architecture

This document defines how Cerebro should add runtime visibility without creating a second disconnected security subsystem.

The design goal is practical:

- reuse the existing runtime detection, response, action-execution, and graph seams
- ingest richer runtime telemetry than the current `RuntimeEvent` shape can represent safely
- project runtime observations and response outcomes into the graph as durable evidence
- keep high-volume raw telemetry out of the graph and out of the shared execution store hot path
- make runtime visibility provider-pluggable instead of coupling the system to one sensor

This document complements [RUNTIME_RESPONSE_EXECUTION_ARCHITECTURE.md](./RUNTIME_RESPONSE_EXECUTION_ARCHITECTURE.md) and [GRAPH_INTELLIGENCE_LAYER.md](./GRAPH_INTELLIGENCE_LAYER.md).

## Why This Needs A Separate Architecture

Today Cerebro already has:

- runtime event ingest under `POST /api/v1/runtime/events`
- rule-based runtime detections in `internal/runtime`
- runtime response execution through the shared action engine
- durable execution state through `internal/executionstore`
- graph-level causal modeling through `triggered_by` and `caused_by`

That is the right control-plane skeleton, but it is not yet runtime visibility.

Current gaps:

- `RuntimeEvent` is too narrow for real process, file, network, audit, and trace correlation data.
- raw runtime observations are not durably modeled as a first-class substrate.
- runtime observations are not projected into the graph as `observation` or `evidence`.
- response outcomes are not joined back into the same causal graph.
- the shared execution store is the right place for ingestion jobs and checkpoints, not the right place for every raw runtime event.

## Principles

- One canonical normalized runtime observation contract should sit behind all providers.
- Detection, graph projection, and response execution should remain separate stages.
- Raw event retention should be short-lived and queryable; durable graph state should be promoted, summarized, and bounded.
- Runtime visibility should bind to existing graph identities: workload, image, package, principal, vendor, deployment, and service.
- The first production cut should prefer proven upstream sensors over bespoke collection code.

## Visibility Layers

Runtime visibility should be modeled as four complementary layers.

### 1. Control-Plane Visibility

Purpose:

- answer who initiated change or access
- capture API intent before or around runtime behavior

Primary sources:

- Kubernetes audit logs
- cloud audit trails where they materially affect runtime identity or containment

Examples:

- `kubectl exec`
- pod spec mutation
- RBAC changes
- ephemeral debugging actions

### 2. Runtime Sensor Visibility

Purpose:

- capture what the workload actually did inside the kernel/runtime boundary

Primary sources:

- eBPF-backed process/file/security telemetry

Examples:

- process exec and exit
- privilege escalation attempts
- namespace escape indicators
- credential file access
- unexpected binary execution

### 3. Network Flow Visibility

Purpose:

- capture who the workload talked to and how

Primary sources:

- CNI/service-mesh flow telemetry

Examples:

- external egress
- east-west service calls
- DNS requests
- long-lived suspicious connections

### 4. Application Correlation Visibility

Purpose:

- bind runtime behavior to service-level request context and workload identity

Primary sources:

- OpenTelemetry traces, logs, and resource metadata

Examples:

- trace/span linkage
- service name
- deployment environment
- pod/container identity normalization

OpenTelemetry is useful here, but it is not the primary runtime security signal source.

## Recommended Source Stack

### First Choices

- `Tetragon` for process/file/runtime security telemetry
- `Hubble` for network flows
- `Kubernetes audit` for control-plane activity
- `OpenTelemetry` for service and trace correlation

### Secondary / Optional Sources

- `Falco` as a detection feed adapter
- `Tracee` as an alternate runtime sensor
- `osquery` for host-state and selective event augmentation
- managed cloud runtime feeds such as AWS GuardDuty Runtime Monitoring

## Why Tetragon First

Tetragon is the best first runtime sensor because it already provides:

- Kubernetes-aware workload identity
- process, file, and security event coverage
- kernel-level visibility without Cerebro owning an eBPF implementation
- stable export surfaces through JSON export and gRPC

The initial production recommendation is:

- use JSON export or a collector-fed JSON path first
- normalize that into Cerebro's internal runtime observation contract
- defer direct gRPC streaming until the normalized event model and backpressure rules are proven

## Why Hubble Next To Tetragon

Tetragon is not a full network flow substrate. Hubble fills that gap well:

- workload-aware network flows
- DNS visibility
- service-to-service pathing
- Cilium identity context

Cluster-wide Cerebro integration should prefer Hubble Relay or exported flow pipelines rather than node-local direct consumers.

## Why Kubernetes Audit Must Be In Scope

Pure runtime telemetry cannot answer control-plane causality well enough.

Examples:

- a shell spawned because an attacker executed code inside the container
- a shell spawned because a legitimate operator ran `kubectl exec`

Those are not equivalent. Kubernetes audit is the authoritative source for that distinction.

## Why OpenTelemetry Is Complementary, Not Sufficient

OpenTelemetry gives:

- standard resource identity
- traces, logs, metrics
- request context
- service-level correlation

It does not replace:

- kernel/runtime process visibility
- file activity visibility
- network enforcement and low-level flow evidence
- direct containment-target context

The right use is enrichment and correlation, not making OTel the only runtime source.

## Canonical Internal Contract

Introduce a normalized contract behind provider adapters.

Illustrative shape:

```go
type RuntimeObservation struct {
	ID          string                 `json:"id"`
	Kind        string                 `json:"kind"`
	Source      string                 `json:"source"`
	ObservedAt  time.Time              `json:"observed_at"`
	RecordedAt  time.Time              `json:"recorded_at"`

	Cluster     string                 `json:"cluster,omitempty"`
	Namespace   string                 `json:"namespace,omitempty"`
	NodeName    string                 `json:"node_name,omitempty"`

	WorkloadRef string                 `json:"workload_ref,omitempty"`
	WorkloadUID string                 `json:"workload_uid,omitempty"`
	ContainerID string                 `json:"container_id,omitempty"`
	ImageRef    string                 `json:"image_ref,omitempty"`
	ImageID     string                 `json:"image_id,omitempty"`

	PrincipalID string                 `json:"principal_id,omitempty"`
	TraceID     string                 `json:"trace_id,omitempty"`
	SpanID      string                 `json:"span_id,omitempty"`

	Process     *ProcessContext        `json:"process,omitempty"`
	File        *FileContext           `json:"file,omitempty"`
	Network     *NetworkContext        `json:"network,omitempty"`
	Audit       *ControlPlaneContext   `json:"audit,omitempty"`

	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]any         `json:"metadata,omitempty"`
	Raw         map[string]any         `json:"raw,omitempty"`
	Provenance  map[string]any         `json:"provenance,omitempty"`
}
```

Important rule:

- `internal/runtime.RuntimeEvent` should become a compatibility envelope or derived simplified view, not the canonical ingest model.

## Observation Kinds

The normalized contract should support at least:

- `process_exec`
- `process_exit`
- `file_open`
- `file_write`
- `network_flow`
- `dns_query`
- `k8s_audit`
- `runtime_alert`
- `trace_link`
- `response_outcome`

Do not overload one generic `event_type` string forever. Use a stable enum-like contract with bounded extension.

## Provider Adapter Seams

Add provider adapters under a dedicated package such as:

- `internal/runtime/adapters/tetragon`
- `internal/runtime/adapters/hubble`
- `internal/runtime/adapters/k8saudit`
- `internal/runtime/adapters/otel`
- `internal/runtime/adapters/falco`

Each adapter should do only three things:

1. decode upstream payloads
2. normalize them into `RuntimeObservation`
3. preserve raw provider data in bounded provenance/raw payloads

Detection logic should not live in the adapters.

For `OpenTelemetry`, prefer accepting OTLP/JSON envelopes that carry:

- `resourceLogs`
- `resourceSpans`

The adapter should treat logs and spans as correlation inputs, not primary runtime
security signals:

- logs become `trace_link` or `runtime_alert` observations depending on whether
  trace/service identity is present
- spans become `trace_link` observations
- resource attributes populate workload, service, cluster, namespace, node,
  container, and image context when those fields are present

## Ingestion Pipeline

Recommended pipeline:

1. provider adapter emits normalized `RuntimeObservation`
2. observation is written to a streaming ingest path
3. checkpoint/run metadata is persisted through `internal/executionstore`
4. raw observations go to bounded short-retention storage
5. detection engine evaluates normalized observations
6. graph materialization promotes selected observations into graph state
7. response engine executes on derived findings
8. response outcomes are fed back as runtime observations and graph evidence

## Storage Boundaries

### Use `executionstore` For

- ingestion run metadata
- source checkpoints and cursors
- backfill jobs
- materialization jobs
- response execution history
- replay and reconciliation state

### Do Not Use `executionstore` For

- every raw runtime observation at production event rates
- long retention of packet/process/file event streams

The current backend-neutral execution contract is the right control-plane seam, not the raw telemetry lake.

## Raw Retention Strategy

Use a short-retention raw observation store or stream-backed sink for:

- recent incident pivoting
- replay into detectors/materializers
- source debugging

Use graph materialization for:

- durable evidence
- summarized process/network relationships
- causal links
- high-confidence promoted observations

## Graph Projection Model

Do not start by making every process or flow a permanent top-level node kind.

Phase 1 should prefer:

- `observation` nodes for normalized runtime observations that matter durably
- `evidence` nodes for promoted security-relevant observations
- existing `workload`, `service`, `image`, `package`, `deployment_run`, `incident`, `vendor`, and `identity_alias` nodes as the durable spine

Recommended first edges:

- `workload -> targets -> observation`
- `observation -> based_on -> evidence`
- `finding -> based_on -> evidence`
- `response action/execution -> targets -> workload`
- `response action/execution -> caused_by -> finding`
- `observation -> triggered_by -> deployment_run`
- `observation -> triggered_by -> control-plane audit event`
- `incident -> caused_by -> finding`

If query pressure later justifies it, add a durable `process_instance` node kind after the observation model proves stable.

## Identity Binding Requirements

Runtime visibility is only useful if the observation can bind to the world model.

Minimum identity-binding targets:

- workload
- namespace
- cluster
- image
- package when process path can be mapped back to installed component context
- principal or actor where control-plane or delegated identity exists
- deployment run when temporal correlation is strong
- vendor when the runtime behavior materially touches third-party integrations

This is why the graph integration matters. Runtime visibility without entity binding becomes another alert silo.

## Detection Integration

The current detection engine should evolve from:

- direct evaluation of narrow `RuntimeEvent`

to:

- evaluation of normalized `RuntimeObservation`
- optional provider-specific enrichers that run before rule evaluation
- rule packs that can target process/file/network/audit/trace fields consistently

Practical migration path:

1. add normalized observation ingest
2. derive the current `RuntimeEvent` view from it where possible
3. migrate built-in rules onto the new contract
4. retire direct raw `RuntimeEvent` assumptions gradually

## Response Integration

Runtime response should not become its own data island.

Every response execution should emit a response outcome observation that captures:

- action type
- target identity
- execution mode
- approval state
- success/failure
- response latency
- actuator/provider details

That outcome should then feed:

- graph evidence
- causal correlation
- future confidence scoring
- autonomous workflow/adjudication loops

## Confidence And Outcome Loops

Runtime visibility should improve graph intelligence quality, not just add more data.

Examples:

- if a response repeatedly fails against a target class, reduce confidence in future auto-containment recommendations for that class
- if Kubernetes audit shows a human-approved `kubectl exec`, reduce incident confidence for the subsequent shell event
- if Hubble and Tetragon agree on suspicious egress from the same workload, raise confidence for the finding

## Phased Implementation Plan

### Phase 1. Normalize And Persist Runtime Observation Control State

- define `RuntimeObservation`
- add provider adapter seams
- add ingestion-run/checkpoint persistence via `executionstore`
- keep current `/api/v1/runtime/events` as a compatibility path

### Phase 2. First Real Sensor Path

- add `Tetragon -> RuntimeObservation`
- add `Kubernetes audit -> RuntimeObservation`
- bind observations to workload/image/namespace identities
- emit promoted runtime `observation` / `evidence` graph records

### Phase 3. Close The Loop

- emit response outcome observations from runtime response execution
- project response outcomes into graph causal chains
- expose runtime visibility health/coverage through platform intelligence

### Phase 4. Network And Correlation Depth

- add `Hubble -> RuntimeObservation`
- add OpenTelemetry trace/resource correlation
- materialize suspicious egress and service-call path evidence

### Phase 5. Provider And Platform Expansion

- optional Falco adapter
- optional Tracee adapter
- managed cloud runtime feeds where they add coverage
- drift/anomaly layers on top of the observation graph

## First Experiments

The first experiments should prove architecture, not UI.

### Experiment 1. Tetragon Process Exec Path

Goal:

- ingest process exec events
- bind them to workload/image/container identity
- drive one existing runtime rule from normalized observations

Success criteria:

- the same process exec is queryable as raw observation, finding evidence, and response target context

### Experiment 2. Control-Plane Causality

Goal:

- correlate Kubernetes audit `kubectl exec` or workload mutation activity with subsequent runtime observations

Success criteria:

- graph can answer whether a shell was operator-initiated or suspicious

### Experiment 3. Network + Process Correlation

Goal:

- correlate Hubble egress flow with the process/workload that produced it

Success criteria:

- graph can explain suspicious egress as a concrete process chain rather than a flat alert

## Anti-Patterns To Avoid

- Do not make OpenTelemetry the only runtime source.
- Do not treat Falco alerts as the canonical runtime graph model.
- Do not write every raw runtime event into SQLite-backed execution state.
- Do not create a second orchestration/execution subsystem beside `internal/actionengine`.
- Do not store every syscall or flow forever in the graph.

## Initial API Direction

Near-term compatibility:

- preserve `POST /api/v1/runtime/events`
- add a typed internal ingest path for normalized observations

Longer-term platform direction:

- `/api/v1/platform/runtime/observations`
- `/api/v1/platform/runtime/sources`
- `/api/v1/platform/runtime/coverage`
- `/api/v1/platform/runtime/replays`

The platform-facing resources should describe the shared runtime substrate, while `/api/v1/security/runtime/*` should remain the application surface for detections, policies, containment, and investigations.

## Research References

- OpenTelemetry Logs Data Model: <https://opentelemetry.io/docs/specs/otel/logs/data-model/>
- OpenTelemetry OTLP: <https://opentelemetry.io/docs/specs/otlp/>
- OpenTelemetry resource semantic conventions: <https://opentelemetry.io/docs/specs/semconv/resource/>
- OpenTelemetry Kubernetes collector components: <https://opentelemetry.io/docs/platforms/kubernetes/collector/components/>
- Kubernetes Auditing: <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- Tetragon Overview: <https://tetragon.io/docs/overview/>
- Tetragon Events: <https://tetragon.io/docs/concepts/events/>
- Tetragon gRPC API: <https://tetragon.io/docs/reference/grpc-api/>
- Hubble CLI and observability docs: <https://docs.cilium.io/en/stable/observability/hubble/hubble-cli.html>
- Falco Output Channels: <https://falco.org/docs/concepts/outputs/channels/>
- osquery Process Auditing: <https://osquery.readthedocs.io/en/stable/deployment/process-auditing/>
- AWS GuardDuty Runtime Monitoring: <https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html>
