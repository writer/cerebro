# Cerebro Slack companion

This workspace owns the portable behavior of the Cerebro Slack companion. It is an adapter over the public `AgentServiceLifecycle` contract, not a deployment definition.

The first supported path is durable admission:

1. Verify the installation, service presence, and required capabilities.
2. Atomically deduplicate the Slack input, commit its run receipt, append the admission transitions, and place the run on a durable queue.
3. Permit the Slack acknowledgement only after that transaction succeeds.
4. Return the existing receipt when Slack retries the same input.

## Slack To Cerebro And Back

The companion treats Slack as transport and attention, not as the system of record. It persists and acknowledges Slack input first, performs work through portable Cerebro contracts, then delivers the result back through a durable outbox.

```mermaid
sequenceDiagram
  participant Slack as Slack
  participant Transport as Transport handler
  participant Admission as Durable admission
  participant Queue as Run and work queue
  participant Worker as Companion worker
  participant Cerebro as Cerebro contracts/API
  participant Delivery as Delivery outbox

  Slack->>Transport: event, mention, or interaction
  Transport->>Transport: verify signature or socket presence
  Transport->>Admission: persist payload and normalize envelope
  Admission->>Queue: dedupe, write run receipt, enqueue work
  Admission-->>Slack: acknowledge only after durable commit
  Worker->>Queue: claim work with lease and fencing
  Worker->>Cerebro: read evidence, graph, policy, and source context
  Cerebro-->>Worker: return grounded context and contract-shaped results
  Worker->>Delivery: plan response parts with stable ids
  Delivery->>Slack: send message or status update
  Slack-->>Delivery: destination receipt
  Delivery->>Queue: record delivered, retry, paused, or abandoned state
```

The same shape applies to longer-running work. Slack-visible status can show queued, degraded, recovery, or completed states while leases, checkpoints, and receipts keep retries idempotent.

## Assistant turns

`assistantTurnBudget` maps the model-selected execution lane to bounded tool calls, selected capabilities, and latency. Hosts may lower those limits, but they cannot expand them past the portable contract. `normalizeAssistantTurnProgress` exposes the same planning, checking, synthesis, delivery, completion, and blocked phases across Slack hosts.

Hosts should record the message parts Slack accepted, not an internal draft. Evaluation and conversation continuity then describe what the person actually received, including partial and failed deliveries.

`evaluateAssistantTurn` scores one text-free observation derived from durable delivery, claim, source, feedback, and outcome records. An unwanted response, missed response, incomplete delivery, omitted required action, ungrounded or subject-misbound claim, unused available source, missing coverage boundary, hidden source failure, exposed internal machinery, redundant tool call, unnecessary clarification, user correction, or negative feedback is explicit in the receipt. `decideAssistantTurnPromotion` compares one candidate with its exact baseline on at least eight sealed static cases and eight independently generated shadow cases. Duplicate case content cannot count in both partitions. Promotion requires a strict score gain, no blocker increase, fewer blockers when the baseline has any, no material case regression, and no new per-case blocker.

`ImprovementCoordinator.recordOutcomeEvidence` is the only path that can make evaluation, shadow, and promotion evidence fresh. It binds the baseline rows to the pre-authoring head, binds candidate rows to the authored head, runs the promotion decision, and records those three evidence classes only when the decision passes. Generic CI and canary receipts cannot bypass the outcome gate. A candidate becomes ready only when all five exact-head evidence classes are fresh.

## Command and delivery projections

`encodeSlackCommandEnvelope` and `encodeSlackActionEnvelope` produce bounded, versioned values for transport-owned command and interaction handlers. Their decoders reject unknown fields and malformed input before admission. `projectSlackVisibleStatus`, `projectAssistantTurnProgress`, and `projectSlackMultipartDelivery` produce stable host-neutral operations and exact accepted-part records. Private adapters choose routes and Slack API methods.

Durable schedule definitions keep a stable schedule identity, revision, work
digest, cadence anchor, and misfire policy. The portable planner derives the
same due times after a restart or topology change and materializes occurrences
with the existing `(schedule_id, due_at, schedule_revision)` identity. Runtime
stores, destination bindings, and scheduler deployment policy remain host-owned.

## Canonical work cases

`src/canonical-work` projects a Cerebro compliance work item into a resumable
Slack-facing case. Cerebro remains authoritative for queue state, ownership,
versions, occurrences, remediation, and assurance verification. The companion
stores the case projection, exact command intent, and digest-bound approval
receipt.

Every write is fenced by the current work-item version. A retry after an
unknown command result first reads canonical state and does not repeat an
effect that Cerebro already applied. Remediation and fresh assurance remain
separate commands; the case closes only after the canonical response reaches a
terminal state.

Hosts implement `CanonicalWorkItemPort` with the public Cerebro SDK and provide
a durable `DurableCanonicalWorkCasePort`. Credentials, endpoints, deployment
configuration, and provider-specific stores are outside this workspace.

## Alert triage

`src/triage` owns portable alert-triage, evidence, and suggestion lifecycles.
Machine-specific transitions keep triage, evidence freshness, and suggestion
delivery states distinct. An actionable decision can plan a suggestion only
when every referenced receipt is current, accessible, and within its validity
window. Planning uses stable caller-provided action identity so a retry produces
the same suggestion identity.

The portable channel policy classifies host-supplied message text and applies
host-supplied channel membership and confidence thresholds. The host owns
channel membership lookup, source queries, prompts, persistence, and delivery
adapters. Those adapters persist the versioned records and transition events
without changing the portable decision policy.

The deterministic fallback accepts host-supplied alert text and research
records. It never authorizes a reply: explicit test markers are non-actionable,
and every other degraded result needs more context. Model and research calls,
credentials, transport, persistence, and deployment remain host-owned.

## History learning admission

`slackLearningCandidateRejection` classifies a host-supplied message projection
before it can become a learning candidate. Machine-authored messages, Slack
subtypes, incomplete records, empty text, and direct mentions of the companion
are rejected with stable reason codes. Slack history fetching, authorization,
storage, and learning execution remain host-owned.

## Durable answer watches

`src/watch` binds a watch to one read-only, server-resolved target recorded with
the delivered answer. Interactive requests carry the binding reference, while
the host resolves the target and records the evidence, version, and digest.
Only the original requester or a recorded operator can start the watch.

Each check uses the canonical scheduled-occurrence lease and fencing contract.
Portable policy compares structured state, publishes material changes,
suppresses unchanged checks, shows degraded and recovered states, and
distinguishes a satisfied condition from a target that closed first. The host
owns source polling, durable storage, authorization lookup, and Slack transport.

Observation and stop retries require a durable receipt lookup before portable
policy runs. A first execution returns an immutable receipt that the host must
commit with the watch update. Later retries return that receipt even after
other observations or retirement, while the current watch revision remains
unchanged. A missing or conflicting receipt lookup fails closed.

## Evidence rechecks

`src/recheck` admits a recheck only for evidence already bound server-side to a
fully delivered answer and its durable conversation thread. The requester does
not select an evidence location or submit the binding contents. A required
host-owned lookup resolves the immutable binding before authorization policy
runs. Only the original requester or a recorded operator can use the binding.
The binding includes a canonical digest of the
completed delivery receipt and its ordered part receipts; duplicate part or
idempotency identities fail closed.

Admission derives stable recheck, run, queue-item, and receipt identities. The
host must commit the immutable request, canonical reconciliation run, admission
transitions, queue item, and receipt in one durable transaction before transport
acknowledgement is permitted. Exact retries return the existing receipt;
conflicting receipt reuse fails closed. Portable status projections show queued,
duplicate, in-progress, completed, degraded, and rejected states.

The public module contains only records, validation, deterministic policy, and
synthetic tests. Evidence resolution, persistence, execution, authorization
lookup, and Slack transport remain host-owned.
Production implementations of `DurableAdmissionPort` must use durable storage with one transaction or an equivalent recoverable commit protocol. The in-memory implementation under `src/testing` is a conformance fixture only.

This workspace must not contain credentials, infrastructure identifiers, environment routes, deployment manifests, or provider-specific persistence adapters. Those belong in the private operational repository. A deployment may replace every port without changing the Slack application identity, binding identity, run identity, or thread identity.
