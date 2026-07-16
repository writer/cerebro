# Agent Service Lifecycle Contract

Status: proposed public contract. Runtime adoption and compatibility promises require an explicit lifecycle owner decision.

The Agent Service Lifecycle contract defines how an agent-facing service admits durable work, changes availability,
hands work between generations, resumes after interruption, and reports compatibility without depending on a chat
transport, cloud provider, orchestrator, or private deployment topology.

The contract sits beside the existing agent-platform contract:

- the agent-platform contract governs Cerebro capabilities, evidence, missions, actions, and policy;
- the service-lifecycle contract governs service availability and the continuity of admitted runs;
- product applications bind transport-specific identities and presentation to the neutral records;
- deployment repositories implement the ports and choose operational policy.

The lifecycle contract does not turn Cerebro into a deployment controller.

## Proposal Artifacts

The checked-in artifacts are proposal inputs, not an approved runtime compatibility promise:

- `schemas/agent-service-lifecycle.schema.json` defines the append-only `LifecycleEventV1` envelope.
- `schemas/agent-service-lifecycle-contract.schema.json` defines discovery metadata and portable record shapes.
- `internal/agentplatform/agent_service_lifecycle.go` builds the proposed discovery snapshot.
- `internal/agentplatform/lifecyclecontract/generated.go` contains namespaced Go event bindings.
- `sdk/typescript/src/generated/agent-service-lifecycle.ts` and
  `sdk/typescript/src/generated/agent-service-lifecycle-contract.ts` contain generated TypeScript bindings.

Topology-specific deployment schemas, values, routing, secret references, rollout thresholds, and recovery policy are
not public contract artifacts. They belong to the operator implementing these ports.

## Durable Acceptance Boundary

The central invariant is:

> A transport may acknowledge accepted work only after a durable run receipt exists that another compatible worker can resume.

Input deduplication is not admission. A status indicator is not admission. A process-local queue is not admission.
The admission store must atomically apply the idempotency rule and commit the recoverable `RunReceiptV1` before the
transport reports that the request was saved.

`RunReceiptV1` begins at `admitted`; `received` and `rejected` describe the transport boundary before a durable run
receipt exists. This keeps `admitted_at` meaningful and prevents a rejected request from looking recoverable.

## Orthogonal State Machines

Installation, deployment generation, service availability, and run progress are separate state machines. A deployment
may still be validating while the previous generation is ready. A service may be degraded while a compatible run
completes. A run may be waiting without making the whole service unavailable.

The discovery endpoint returns the allowed states and transitions. JSON Schema conditions reject a state from one
machine when it appears in another machine's transition.

## Event And Record Model

`LifecycleEventV1` is the append-only audit and replay envelope. It carries:

- event kind and transition axis;
- tenant, service, subject type, and subject identity;
- monotonic subject sequence;
- previous and next state;
- occurred and observed times;
- stable reason code and bounded summary;
- producer version and optional generation identity;
- idempotency, correlation, causation, and trace identities;
- optional lease, checkpoint, effect, delivery, and snapshot references.

The strict schema couples each event kind to its transition axis. A `service.transition` event cannot contain a work
transition, and a generation-scoped service event must carry deployment identity.

The portable record catalog contains service bindings, deployment generations, capability manifests, run receipts,
scheduled occurrences, leases, checkpoints, effects, delivery receipts, presence snapshots, release receipts, and
migration receipts.

## Crash And Replacement Semantics

- Every lease identifies its owner, generation, lease token, fencing token, expiry, and heartbeat.
- Every mutation proves the current generation and lease before it changes run, effect, or delivery state.
- A checkpoint carries an ordered resume cursor and completed effect references. A waiting reference is present only
  when the run is actually waiting.
- An effect moves through `planned`, `executing`, `succeeded`, `failed`, or `unknown`. `unknown` records the case where
  the external call may have completed but the worker died before recording its result.
- Terminal effects carry result receipts; approval-gated effects carry the exact approval reference; independently
  verified effects carry a verification receipt.
- Delivery parts have stable idempotency keys. Destination receipts are required only after delivery succeeds.
- Multipart delivery may be `paused` or `abandoned`; a drain cannot misreport incomplete delivery as completed.
- A release receipt reports orphaned runs and stuck delivery. Release verification cannot pass while either count is
  non-zero.

## Scheduled Continuity

`ScheduledOccurrenceV1` uses `(schedule_id, due_at, schedule_revision)` as its logical identity. The occurrence records
its deterministic idempotency key, misfire policy, run identity, state, generation, and full lease/fencing data while
leased or running. This prevents overlapping schedulers from executing the same occurrence during replacement or
recovery.

Scheduled work, interactive work, autonomy, triage, attestations, and reconciliation use the same run, lease,
checkpoint, effect, and delivery semantics. Product-specific objectives remain in their owning domain ledgers.

## Compatibility

The initial proposal reads and writes only `cerebro.agent-service-lifecycle/v1`. An N-1 version must not be advertised
until a checked-in fixture and an actual reader prove that compatibility. Future schema changes follow expand,
migrate, observe, and contract phases.

Capability negotiation returns `supported`, `degraded`, `blocked`, or `incompatible`. Missing required capabilities
prevent lease acquisition. Missing optional capabilities may continue only with an explicit degraded decision.

## Health Surfaces

- `/livez` reports process liveness.
- `/readyz` reports readiness for the component's assigned responsibility.
- `/presencez` reports durable admission and delivery readiness.
- `/capabilities` reports capability and contract compatibility.
- `/drainz` reports generation, active leases, queued checkpoints, and the drain deadline.

These are responsibilities, not required deployment paths. An adapter may expose them through its native health
surface while preserving the same meanings.

## Review And Adoption Gate

Before runtime code depends on this proposal, the lifecycle owner must approve:

1. state and transition ownership;
2. schema versioning and N-1 policy;
3. durable port implementations and retention behavior;
4. capability compatibility behavior;
5. lease, fencing, checkpoint, effect, and delivery semantics;
6. the boundary between portable application behavior and private operational policy.

Until that decision is recorded, the endpoint and generated bindings are discovery artifacts for review and
conformance work, not permission to cut over production traffic.
