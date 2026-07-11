# Finding-to-Verified-Fix Reference Implementation

Status: implementation proposal

Issues: #1760 and #1761

Depends on: #1740 and #1742

## Outcome

Deliver one enforceable remediation path where Cerebro can prove, in order:

1. which finding and evidence justified a proposed action;
2. which immutable action proposal an authenticated human approved;
3. which worker durably claimed the provider mutation;
4. which provider request and external action resulted;
5. which fresh post-action evidence was collected;
6. whether the same finding predicate still matched;
7. and why the finding remained open or moved to resolved.

The first certified pair is:

```text
finding rule: identity-okta-terminated-active-account
action:       identity.okta.suspend_user
reversal:     identity.okta.unsuspend_user
relationship: remediates_predicate
```

The rule detects a terminated employee whose Okta account remains active. The
action targets that Okta account. Fresh Okta user state can show that the
account is no longer active, after which the same rule can be evaluated again.

This document is deliberately narrower than a general workflow engine. It
defines exact package boundaries, records, transitions, transaction rules,
APIs, failure behavior, verification logic, and PR slices for one safe vertical
path.

## Current-State Findings

The shipped graph-action path has useful components but no trusted end-to-end
approval or verification boundary:

| Area | Current behavior | Required change |
| --- | --- | --- |
| Request approval | `ExecuteGraphActionRequest.approved` is a caller-supplied boolean. | Mutation requires a durable approval receipt over an immutable proposal digest. |
| Actor binding | The graph-action input does not carry an authenticated approver. Provider responses may contain actor fields, but they are not the approval authority. | Resolve actor from auth context and store it with the approval decision. |
| Plan binding | Dry run returns action, target, provider metadata, and a generated idempotency key. It has no canonical proposal digest or durable revision. | Persist a versioned proposal containing every execution-relevant field. |
| Idempotency | The default key hashes action, finding, and target. | Provider request identity derives from the full proposal digest and execution generation. |
| Dispatch ordering | The provider is called before the workflow event and finding external reference are written. | Commit the execution claim, outbound request digest, and event outbox row before dispatch. |
| Ambiguous result | The access-approvals client can read by external ID only. A timed-out create may not return an ID. | Certify provider idempotency replay or add lookup by idempotency key before enforcement. Never blind-retry an uncertified ambiguous create. |
| Reconciliation | Provider state is refreshed into a finding external reference and a generic action event. | Reconciliation updates the durable execution record; it does not verify or close the finding. |
| Verification | Reversible remediation metadata contains prose verification steps only. | Store a machine-readable verification plan and run fresh collection plus the exact finding rule. |
| Action correctness | Finding attributes contain a string allowlist. Two existing rules advertise an action that cannot negate their predicates. | Complete #1761 and authorize from a certified rule/action binding catalog. |
| Graph dependency | Workflow action events project to the graph, but graph state is not suitable as approval authority. | Keep proposal, approval, execution, and verification rows canonical in Postgres. Project asynchronously. |

## Pilot Choice And Exclusions

### Certified pilot

Use `policies/identity/identity-okta-terminated-active-account.yaml` because its
predicate, target, action effect, and verification observation align:

```text
predicate before: employee.status = terminated
                  AND okta_user.status in active states

action effect:    Okta user transitions out of active states

predicate after:  employee.status = terminated
                  AND okta_user.status not in active states
                  => no match
```

The binding is certified only for an Okta `user` runtime that can return the
account ID and current status. Employee termination evidence remains part of the
decision packet but does not need to change for remediation to succeed.

### Explicit exclusions

Do not certify these existing combinations:

- `identity-okta-deprovisioned-active-in-github` with
  `identity.okta.suspend_user`;
- `identity-okta-deprovisioned-active-cloud-access` with
  `identity.okta.suspend_user`.

Those predicates already require an inactive Okta identity and remain true
because downstream GitHub or cloud access persists. #1761 removes the unsafe
advertisement and defines provider-specific follow-up work.

Do not certify `endpoint.cerebro.revoke_device` merely because the provider is
first-party. No production finding currently provides a reviewed binding that
proves device revocation negates its predicate.

## Non-Negotiable Invariants

1. A write scope authorizes use of a route; it is not approval of a proposal.
2. A decision packet receipt is not an action proposal or approval receipt.
3. `approved=true` never authorizes mutation in enforced mode.
4. Every approved byte that can change provider behavior is covered by the
   proposal digest.
5. A changed finding, target, action catalog version, binding version, evidence
   revision, reason, ticket, parameter, reversal, expiry, or verification plan
   requires a new proposal and approval.
6. One proposal has at most one forward execution. Reversal is a new proposal.
7. Provider dispatch starts only after the execution claim and event outbox row
   commit in one Postgres transaction.
8. A worker never blind-retries an ambiguous provider create unless the provider
   contract is certified to return the same action for the same key.
9. Provider success does not close a finding.
10. Verification uses evidence observed after provider completion and evaluates
    the exact rule and finding fingerprint.
11. Missing, stale, truncated, failed, or unauthorized verification evidence
    cannot produce `verified`.
12. Neo4j and JetStream delivery may lag; neither may weaken the approval gate or
    cause provider dispatch to repeat.
13. Tenant is part of every key, lookup, uniqueness constraint, digest input,
    event, metric boundary, and provider request.

## Canonical Ownership

| Concern | Owner | Stored form |
| --- | --- | --- |
| Evidence conclusion | `internal/decisionpacket` from #1742 | Immutable packet receipt and digest |
| Rule/action safety | remediation binding catalog from #1761 | Generated, versioned binding |
| Provider capability | graph-action catalog | Generated, versioned action capabilities |
| Proposal | `internal/graphactionworkflow` | Postgres row plus canonical JSON and digest |
| Approval | `internal/graphactionworkflow` | Postgres row attributed to authenticated actor |
| Execution claim and provider result | `internal/graphactionworkflow` | Postgres execution row and transition history |
| Verification plan and result | `internal/graphactionworkflow` | Postgres verification row referencing source and finding evaluation runs |
| Provider state | `internal/graphactions` provider adapter | External action plus normalized provider status |
| Finding lifecycle | `internal/findings` and `ports.FindingStore` | Existing finding row and status history |
| Replayable transitions | workflow event outbox and append log | Versioned event envelopes |
| Search/reasoning projection | workflow projector | Rebuildable Neo4j state |

## Package Layout

Extend the existing package instead of building a second action service:

```text
internal/graphactionworkflow/
  model.go             domain records and enums
  canonical.go         deterministic proposal/request digests
  service.go           propose, approve, reject, execute, read
  transitions.go       pure state transition validation
  worker.go            dispatch, reconciliation, verification scheduling
  verification.go      post-action plan evaluator
  events.go            durable transition event construction
  recorder.go          existing generic action event compatibility adapter

internal/ports/
  graphactionworkflow.go

internal/statestore/postgres/
  graph_action_workflow.go
  graph_action_workflow_test.go

internal/graphactionapi/
  workflow_messages.go
  workflow_executor.go
  errors.go

internal/sourcehttp/graphactionhandler/
  workflow_handler.go
```

Keep provider execution and target normalization in `internal/graphactions`.
The workflow service depends on a narrow provider port; provider packages do not
import the workflow service.

## Domain Records

### Actor

```go
type Actor struct {
    Type         string // human, service, agent
    SubjectID    string
    AuthMode     string
    CredentialID string
    ClientID     string
}
```

Populate it from `authContext.principal` using the same stable ordering as
`agentPlatformPrincipalActorID`: name, client ID, device ID, credential ID.
Approval policy requires `Type=human` for the pilot. A service or agent may
create a proposal but cannot satisfy human approval.

Do not accept actor fields in public request bodies.

### Proposal

```go
type Proposal struct {
    ID                   string
    TenantID             string
    FindingID            string
    FindingRevision      FindingRevision
    DecisionPacketID     string
    DecisionPacketDigest string
    ActionID             string
    ActionCatalogVersion string
    BindingID            string
    BindingVersion       string
    Provider             string
    ProviderAction       string
    TargetKind           string
    Target               string
    Parameters           map[string]string
    Reason               string
    TicketURL            string
    ReversibleBy         string
    EvidenceRefs         []string
    EvidenceDigest       string
    VerificationPlan     VerificationPlan
    SchemaVersion        string
    Digest               string
    State                ProposalState
    ProposedBy           Actor
    ProposedAt           time.Time
    ExpiresAt            time.Time
    Revision             int64
}

type FindingRevision struct {
    Status          string
    StatusUpdatedAt time.Time
    LastObservedAt  time.Time
    Fingerprint     string
}
```

Pilot proposal states:

```text
awaiting_approval
approved
rejected
expired
superseded
execution_claimed
```

`approved` is not mutable execution authority by itself. The execution service
must still load the matching approval row and revalidate the proposal.

### Approval

```go
type Approval struct {
    ID             string
    TenantID       string
    ProposalID     string
    ProposalDigest string
    Decision       string // approved or rejected
    Reason         string
    Actor          Actor
    PolicyVersion  string
    ApprovedAt     time.Time
    ExpiresAt      time.Time
    Revision       int64
}
```

The pilot policy is one human approver. Keep policy evaluation separate so a
later binding can require two people, a group, a hardware-backed principal, or a
change-window constraint without changing the proposal digest.

### Execution

```go
type Execution struct {
    ID                     string
    TenantID               string
    ProposalID             string
    ProposalDigest         string
    ApprovalIDs            []string
    State                  ExecutionState
    Generation             int64
    RequestDigest          string
    ProviderIdempotencyKey string
    ProviderExternalID     string
    ProviderStatus         string
    ProviderStatusReason   string
    DispatchOwner          string
    DispatchLeaseExpiresAt time.Time
    DispatchStartedAt      time.Time
    SubmittedAt            time.Time
    ProviderCompletedAt    time.Time
    LastReconciledAt       time.Time
    LastErrorCode          string
    LastErrorDetail        string
    Revision               int64
}
```

Execution states:

```text
claimed
dispatching
submitted
submission_unknown
provider_running
provider_succeeded
provider_failed
cancelled
needs_attention
verification_pending
verified
verification_failed
closed
```

`closed` means the verification result was recorded and the finding lifecycle
shows resolved. It is not a provider terminal state.

### Verification

```go
type VerificationPlan struct {
    Strategy              string
    RuntimeID             string
    RuleID                string
    FindingID             string
    FindingFingerprint    string
    RequiredSourceIDs     []string
    RequiresGraphIngest   bool
    EventLimit            uint32
    EarliestStartAt       time.Time
    DeadlineAt            time.Time
    MaxAttempts           uint32
    RequiredFreshAfter    time.Time
    CompleteCoverageOnly  bool
}

type Verification struct {
    ID                   string
    TenantID             string
    ExecutionID          string
    State                VerificationState
    Attempt              uint32
    Plan                 VerificationPlan
    PlatformJobID        string
    SourceSyncObservedAt time.Time
    GraphIngestRunID     string
    EvaluationRunID      string
    EvidenceRefs         []string
    FindingStatus        string
    FindingLastObserved  time.Time
    ReasonCode           string
    Detail               string
    StartedAt            time.Time
    FinishedAt           time.Time
    Revision             int64
}
```

Verification states:

```text
pending
collecting
evaluating
verified
failed
incomplete
deadline_exceeded
needs_attention
```

## Canonical Digests And IDs

### Canonical proposal JSON

Use a private digest DTO. Do not hash the public API response or a Go map
directly.

The exact top-level field order is:

```text
schema_version
tenant_id
finding_id
finding_revision
decision_packet_id
decision_packet_digest
action_id
action_catalog_version
binding_id
binding_version
provider
provider_action
target_kind
target
parameters
reason
ticket_url
reversible_by
evidence_refs
evidence_digest
verification_plan
expires_at
```

Rules:

- UTF-8 only; trim identifiers and URLs where existing validators do so.
- Encode timestamps in UTC RFC3339Nano.
- Sort parameter keys and repeated identifier fields bytewise.
- Deduplicate evidence and source IDs after normalization.
- Preserve reason text after validation; do not lowercase it.
- Represent missing optional values consistently as empty string or empty list,
  never sometimes omitted and sometimes null.
- Prefix the SHA-256 input with
  `cerebro.graph_action_proposal/v1\x00`.

Set:

```text
proposal_id = gap_<base32(first 20 digest bytes)>
proposal_digest = sha256:<lowercase hex>
```

The ID is addressable; the full digest is the precondition and audit identity.

### Provider request digest

Build the provider DTO after the execution claim. Hash:

```text
proposal_digest
approval_policy_version
sorted approval IDs
execution_generation
normalized provider request body
```

The provider idempotency key is:

```text
cerebro:graph-action:v2:<base32(sha256(tenant_id + request_digest))>
```

Do not accept a caller-provided provider key in enforced mode.

### Golden fixtures

Check in:

```text
internal/graphactionworkflow/testdata/canonical/
  proposal_v1.json
  proposal_v1.digest
  provider_request_v1.json
  provider_request_v1.digest
```

Tests must prove that map/slice input order does not change a digest and that
every execution-relevant field does.

## Postgres Schema

Follow the repository's `ensureStatements` and schema-migration checksum
pattern. Use tenant-qualified primary/unique keys even when IDs contain entropy.

### `graph_action_proposals`

Required columns:

```text
tenant_id text
id text
finding_id text
finding_status text
finding_status_updated_at timestamptz
finding_last_observed_at timestamptz
finding_fingerprint text
decision_packet_id text
decision_packet_digest text
action_id text
action_catalog_version text
binding_id text
binding_version text
provider text
provider_action text
target_kind text
target text
proposal_json jsonb
proposal_digest text
state text
proposed_by_json jsonb
proposed_at timestamptz
expires_at timestamptz
revision bigint
created_at timestamptz
updated_at timestamptz
```

Constraints and indexes:

- primary key `(tenant_id, id)`;
- unique `(tenant_id, proposal_digest)`;
- index `(tenant_id, finding_id, created_at desc)`;
- index `(tenant_id, state, expires_at)`;
- `revision > 0`;
- known-state check constraint.

### `graph_action_approvals`

Required columns:

```text
tenant_id text
id text
proposal_id text
proposal_digest text
decision text
reason text
actor_json jsonb
actor_subject_id text
policy_version text
approved_at timestamptz
expires_at timestamptz
revision bigint
created_at timestamptz
```

Constraints:

- primary key `(tenant_id, id)`;
- foreign key `(tenant_id, proposal_id)`;
- unique `(tenant_id, proposal_id, actor_subject_id)` for the pilot;
- decision check `approved|rejected`.

Do not update an approval row. A corrected decision creates a new proposal.

### `graph_action_executions`

Required columns are the `Execution` fields plus canonical provider request
JSON, response summary JSON, and timestamps.

Constraints:

- primary key `(tenant_id, id)`;
- foreign key `(tenant_id, proposal_id)`;
- unique `(tenant_id, proposal_id)` for one forward execution;
- unique `(tenant_id, provider, provider_idempotency_key)`;
- revision and known-state constraints;
- due-work index `(state, dispatch_lease_expires_at, updated_at)`.

### `graph_action_verifications`

Constraints:

- primary key `(tenant_id, id)`;
- foreign key `(tenant_id, execution_id)`;
- unique `(tenant_id, execution_id, attempt)`;
- index `(state, plan_deadline_at, updated_at)`.

Store the plan JSON and normalized searchable columns. Evidence references are
bounded and canonicalized.

### `graph_action_command_dedup`

Persist public idempotency semantics:

```text
tenant_id
operation
idempotency_key
request_hash
resource_type
resource_id
response_status
response_json
expires_at
created_at
```

Primary key is `(tenant_id, operation, idempotency_key)`. The same hash replays
the stored status/body. A different hash returns `409 idempotency_conflict`.

### `graph_action_event_outbox`

```text
tenant_id
aggregate_type
aggregate_id
revision
event_kind
event_id
event_json
created_at
appended_at
append_attempts
last_error_code
next_attempt_at
```

Primary key is `(tenant_id, aggregate_type, aggregate_id, revision,
event_kind)`. `event_id` is globally unique. Insert it in the same transaction
as each canonical transition. A worker appends to JetStream and marks
`appended_at`; replay never repeats provider dispatch.

## Transaction Rules

### Create proposal

In one transaction:

1. lock or re-read the finding through a tenant-qualified store method;
2. require open status and matching finding revision;
3. resolve the certified rule/action binding and current action catalog entry;
4. resolve the target from the finding; do not accept a target that merely has
   the right shape;
5. validate the packet receipt, action ceiling, evidence digest, and expiry;
6. build canonical JSON and digest;
7. insert proposal or return the same tenant/digest row;
8. insert `proposal_created` outbox event;
9. store the idempotency response;
10. commit.

The transaction performs no provider call and no Neo4j write.

### Approve or reject

Use `SELECT ... FOR UPDATE` on `(tenant_id, proposal_id)`.

Before approval:

- compare expected proposal digest and revision;
- require `awaiting_approval`;
- require unexpired proposal;
- re-read the finding and require the stored finding revision still matches;
- require the binding and action catalog versions are current and certified;
- require the packet action ceiling still permits approval;
- derive the actor from auth context and evaluate the approval policy.

Then insert the immutable approval, update proposal state/revision, add outbox
event and idempotency response, and commit. A rejected proposal is terminal.

### Claim execution

Use one transaction and a unique `(tenant_id, proposal_id)` constraint:

1. lock the proposal;
2. load all approvals and evaluate the stored policy version;
3. repeat expiry, digest, finding-revision, binding, catalog, target, and action
   ceiling checks;
4. construct the outbound provider DTO and request digest;
5. insert the execution in `claimed` state with generation `1`;
6. set proposal to `execution_claimed`;
7. insert `execution_claimed` outbox event;
8. store the idempotent API response;
9. commit.

Concurrent callers return the same execution. None calls the provider inline.

### Worker dispatch claim

Claim bounded work with `FOR UPDATE SKIP LOCKED` and an expiring lease, following
the report-schedule claim pattern. Transition `claimed -> dispatching`, record
owner/start time, insert an event, and commit before network I/O.

After the provider call, use compare-and-swap on execution ID, generation,
revision, state, and lease owner:

- response with external ID: `submitted` or normalized provider terminal state;
- definitive validation/rejection before mutation: `provider_failed`;
- timeout, connection reset, invalid success body, or cancellation after request
  write: `submission_unknown`;
- lease/revision mismatch: do not overwrite the newer worker's state.

### Expired dispatch lease

An expired `dispatching` lease is ambiguous. It does not return to `claimed`.
Move it to `submission_unknown` and run provider recovery.

For the access-approvals pilot, enforcement requires one of:

1. GET/list by the provider idempotency key; or
2. documented and contract-tested replay where the same key returns the same
   external action ID without another mutation.

If neither exists, set `needs_attention` and require an operator to attach the
external action or confirm no submission before a new proposal is allowed.

## Public API

Add Connect/protobuf and JSON/OpenAPI parity for:

```text
POST /platform/graph/action-proposals
GET  /platform/graph/action-proposals/{proposalID}
POST /platform/graph/action-proposals/{proposalID}/approval
POST /platform/graph/action-proposals/{proposalID}/execute
POST /platform/graph/action-executions/{executionID}/reconcile
POST /platform/graph/action-executions/{executionID}/verify
```

### Create request

```json
{
  "finding_id": "finding-id",
  "decision_packet_id": "packet-id",
  "decision_packet_digest": "sha256:...",
  "action": "identity.okta.suspend_user",
  "reason": "Terminated employee account remains active",
  "ticket_url": "https://tickets.example/SEC-123",
  "expires_at": "2026-07-12T19:00:00Z"
}
```

The server resolves target, binding, catalog versions, evidence digest, finding
revision, reversal, and verification plan. Do not accept those authority fields
from the caller.

### Approval request

```json
{
  "proposal_digest": "sha256:...",
  "expected_revision": "1",
  "decision": "approved",
  "reason": "Termination confirmed in SEC-123"
}
```

### Execute request

```json
{
  "proposal_digest": "sha256:...",
  "expected_revision": "2"
}
```

The server discovers approval IDs. The caller cannot choose or omit approvals.

### Read response

Return one aggregate view with:

- proposal ID/digest/state/revision/expiry;
- redacted target label and stable target reference;
- decision packet ID/digest;
- action, binding, and catalog versions;
- approval state, actors, reasons, and times;
- execution ID/state/provider reference/status;
- verification state, evidence/run references, and reason code;
- current finding status and last observation;
- stable blockers and allowed next actions.

Never return provider bearer tokens, raw credentials, unrestricted provider
payloads, or cross-tenant existence hints.

## Compatibility Bridge

Add `approval_id` and `proposal_id` to the existing execute proto before
deprecating `approved`.

Modes:

| Mode | Behavior |
| --- | --- |
| `legacy` | Preserve `approved=true`; emit a deprecation metric and structured audit event. |
| `audit` | Build or resolve a proposal and report enforcement blockers, but allow the legacy execution path for explicitly allowlisted tenants. |
| `enforced` | Ignore `approved` as authority. Require a valid proposal/approval and durable execution claim. |

New deployments default to `enforced`. Existing deployments must name their
mode explicitly during the migration window. An unset mode cannot silently mean
legacy after the enforcement release.

Reserve the proto field number for `approved` and mark it deprecated. Do not
reuse it.

## Authorization

Add separate scopes:

```text
cerebro.graph_action_proposals.write
cerebro.graph_action_proposals.read
cerebro.graph_action_approvals.write
cerebro.graph_action_executions.write
cerebro.graph_action_executions.reconcile
cerebro.graph_action_verifications.write
```

The pilot approval policy also requires a human principal. Execution may be
performed by a service after human approval. Reconciliation and verification
workers use service identity and do not create new approval.

Update all of:

- `internal/bootstrap/auth_route_policy.go`;
- `internal/bootstrap/auth_connect_policy.go`;
- supported OAuth scopes and protected-resource metadata;
- route-policy tests;
- auth/tenancy reference documentation.

Every ID lookup first applies tenant authorization and returns tenant-safe
not-found behavior.

## Typed Remediation Binding

Extend the policy schema under `spec.remediation`:

```yaml
remediation:
  summary: Disable or remove provider access for terminated employees within 24 hours and verify all active sessions are revoked.
  graphAction:
    action: identity.okta.suspend_user
    relationship: remediates_predicate
    bindingVersion: identity-okta-terminated-active-account/v1
    target:
      kind: identity.okta.user
      resultColumn: id
      resourceType: okta_user
    verification:
      strategy: source_rule_re_evaluation
      sourceID: okta
      runtimeFamily: user
      ruleID: identity-okta-terminated-active-account
      requiresGraphIngest: false
      completeCoverageOnly: true
      earliestDelay: 30s
      deadline: 15m
      maxAttempts: 5
```

Generate this into the finding rule catalog and remediation binding registry.
Catalog validation rejects:

- unknown action or rule;
- target kind mismatch;
- missing result column or source family;
- non-reversible destructive action when policy requires reversal;
- action effect that is not certified for the relationship;
- missing provider idempotency/reconciliation capability;
- missing verification strategy or fixture.

The finding may project binding ID/version, target reference, and action ID for
reads. `FindingAllowsAction` reloads the catalog binding; it does not trust
finding attributes.

## Provider Capability Contract

Extend `action_catalog.yaml` entries with reviewed capabilities:

```yaml
capabilities:
  idempotency: replay_returns_same_external_id
  reconciliation: by_external_id
  ambiguousSubmissionRecovery: by_idempotency_replay
  terminalStatuses: [succeeded, failed, cancelled, needs_attention]
  verificationEvidence: [okta.user]
```

The generated `ActionSpec` exposes these fields. Enforcement refuses an action
whose capability is `unknown` or `uncertified`.

For access-approvals, add contract tests against its actual behavior. Passing an
`idempotency_key` in JSON is not proof that replay is safe. The test must submit
the same key twice and assert the same external action ID and one provider-side
mutation, or exercise lookup by key.

## End-To-End Pilot Sequence

### 1. Finding and packet

- A successful evaluation emits the terminated-active Okta finding.
- The packet builder resolves finding, policy query evidence, source coverage,
  target identity, and certified binding.
- Missing HR termination or Okta account evidence blocks the proposal.
- Packet construction returns a proposal preview only.

### 2. Proposal

- Operator selects the action.
- The proposal service re-resolves the live finding, packet receipt, target,
  binding, action metadata, reversal, and verification plan.
- It stores canonical proposal and emits `proposal_created` through the outbox.

### 3. Approval

- A human reads the full aggregate and confirms the exact digest.
- The approval service validates actor, digest, revision, expiry, binding, and
  live finding revision.
- It records an immutable approval.

### 4. Execution

- The execute request creates one durable execution claim.
- A worker claims it, calls access-approvals with the derived provider key, and
  records external ID/status.
- Reconciliation continues until a terminal provider result.

### 5. Verification

After provider success and the binding's earliest delay:

1. Create an idempotent `source_runtime_orchestrate` platform job for the
   finding runtime. Set `rule_ids` to only
   `identity-okta-terminated-active-account`.
2. The existing orchestration path runs `SyncWithLease`, graph ingest when the
   plan requires it, and `EvaluateSourceRuntimeRules`.
3. Require completed source sync and finding evaluation run after the provider
   completion time.
4. Re-read the same finding by tenant-qualified ID.
5. Return `verification_failed` when it is open and `LastObservedAt` advanced
   after execution: the predicate still matches.
6. Return `incomplete` when sync/evaluation failed, coverage was truncated,
   runtime/rule was unsupported, or evidence freshness cannot be proven.
7. Return `verified` only when the completed rule evaluation did not re-emit the
   fingerprint and the finding lifecycle is resolved by the normal rule path.
8. Record sync, graph, evaluation, evidence, and finding-status references.
9. Transition execution to `closed` only after the verified result and resolved
   finding are both durable.

Do not call `ResolveFinding` merely because the provider succeeded. Let the
existing rule evaluation produce the lifecycle transition. If the policy rule
path cannot currently resolve stale findings safely, that is a prerequisite bug
for the pilot, not permission to bypass verification.

### 6. Reversal

Unsuspension is a new proposal:

- references the original execution and verified result;
- uses `identity.okta.unsuspend_user`;
- re-resolves current finding/identity state;
- receives its own digest and human approval;
- has a verification plan appropriate to the reason for reversal.

The original approval is never reusable.

## Workflow Events

Add registry-backed versioned events:

```text
workflow.v1.graph_action.proposal_created
workflow.v1.graph_action.proposal_superseded
workflow.v1.graph_action.approval_recorded
workflow.v1.graph_action.execution_claimed
workflow.v1.graph_action.submission_recorded
workflow.v1.graph_action.reconciliation_recorded
workflow.v1.graph_action.verification_requested
workflow.v1.graph_action.verification_recorded
```

Every event includes:

- tenant ID;
- aggregate ID and revision;
- proposal ID/digest;
- action/binding/catalog versions;
- actor or worker identity where applicable;
- execution, provider external, verification, and finding IDs where applicable;
- observed and valid times;
- trace/request ID;
- stable transition reason code.

The existing generic `knowledge.action_recorded` event may remain as a
compatibility projection of provider submission/reconciliation. It is not the
approval ledger and must reference the proposal/execution IDs when available.

## Error Contract

| Condition | HTTP | Connect | Stable code |
| --- | ---: | --- | --- |
| Malformed request or digest | 400 | invalid argument | `invalid_request` |
| Unauthorized or foreign ID | 404 or 403 per existing policy | not found or permission denied | tenant-safe existing code |
| Idempotency key reused with different body | 409 | already exists | `idempotency_conflict` |
| Transition conflicts with live state | 409 | aborted | `transition_conflict` |
| Proposal revision/digest is stale | 412 | failed precondition | `proposal_precondition_failed` |
| Approval policy not satisfied | 422 | failed precondition | `approval_required` |
| Binding missing/uncertified/superseded | 422 | failed precondition | `remediation_uncertified` |
| Finding revision changed | 422 | failed precondition | `finding_changed` |
| Provider submission ambiguous | 202 with state | success envelope | `submission_unknown` |
| Canonical store/outbox unavailable before dispatch | 503 | unavailable | `workflow_unavailable` |
| Verification incomplete or overdue | 202 with state | success envelope | `verification_incomplete` |

Never encourage a caller to retry `submission_unknown` by creating a new
proposal. The read response tells the operator whether reconciliation or manual
resolution is the next action.

## Crash And Retry Matrix

| Crash/failure point | Durable state after recovery | Allowed recovery | Forbidden recovery |
| --- | --- | --- | --- |
| Before proposal commit | no proposal | retry same idempotency key | partial graph record |
| After proposal commit, before event append | proposal + outbox | append event | recreate proposal with new digest |
| During approval transaction | old proposal state | retry same key | infer approval from request log |
| After execution claim commit, before worker claim | `claimed` | worker claims | inline provider call from API retry |
| After worker claim, before request write | expired `dispatching` | capability-aware recovery | automatic new generation without recovery |
| After provider accepts, before response persists | `submission_unknown` | lookup/replay certified key | blind new provider request/key |
| After provider result commit, before event append | terminal provider state + outbox | append event | call provider again |
| After provider success, before verification job | `verification_pending` | enqueue same idempotent job | close finding |
| After verification run, before result commit | prior verification state | re-read run/finding and commit | re-run provider action |
| After verified result, before finding read projection | verified canonical rows | rebuild projection | reopen approval/execution |

## Observability

Metrics use bounded attributes only:

- `graph_action_proposal_total{action,state,reason}`;
- `graph_action_approval_total{action,decision,policy}`;
- `graph_action_execution_total{provider,action,state}`;
- `graph_action_dispatch_conflict_total{provider,action}`;
- `graph_action_submission_unknown_total{provider,action}`;
- `graph_action_reconciliation_lag_seconds{provider,action}`;
- `graph_action_verification_total{rule,action,state,reason}`;
- `graph_action_provider_to_verified_seconds{provider,action}`;
- `graph_action_legacy_approval_total{action,tenant_mode}`;
- `graph_action_outbox_backlog{event_kind}`.

Do not put tenant IDs, finding IDs, targets, actor subjects, ticket URLs, or
provider external IDs in metric labels.

Structured logs and traces include those identifiers only through the existing
redaction policy and authorized trace storage.

Alerts:

- mutation in enforced mode without proposal and approval IDs;
- `dispatching` lease expired;
- `submission_unknown` older than provider recovery objective;
- provider success with verification overdue;
- verified result while finding remains open;
- closed execution without verification ID;
- outbox backlog or dead-letter growth;
- legacy mutation after the tenant enforcement date.

## Security And Abuse Cases

Required negative tests cover:

- cross-tenant proposal, approval, execution, external action, and verification
  identifiers;
- caller-supplied actor spoofing;
- approval by agent/service when human policy is required;
- target substitution after dry run;
- digest confusion between packet and action proposal;
- proposal created from an uncertified binding;
- replayed approval after expiry or supersession;
- approval reuse for reversal;
- concurrent execution requests;
- provider response with wrong action, provider, tenant, target, or external ID;
- malicious reason/ticket metadata and control characters;
- stale finding status and post-approval re-emission;
- projection poisoning attempting to change canonical approval state;
- forced append failure and outbox replay;
- worker lease theft and stale-worker response overwrite.

## Golden End-To-End Fixtures

Add a hermetic suite under:

```text
internal/graphactionworkflow/testdata/pilot/
  terminated_active_before/
  provider_suspend_succeeded/
  okta_inactive_after/
  okta_still_active_after/
  source_sync_failed/
  provider_timeout_reconciled/
```

The suite must use the real:

- policy YAML and generated rule metadata;
- remediation binding registry;
- graph-action target resolver;
- access-approvals provider contract fake;
- Postgres repositories where the test environment supports them;
- source projection/replay and finding evaluation services;
- workflow event constructors.

Core assertions:

1. canonical proposal digest is stable;
2. wrong/unsafe rule action is absent;
3. exactly one provider mutation occurs under 50 concurrent execute requests;
4. provider timeout recovers to the same external ID;
5. provider success plus still-active Okta data leaves the finding open;
6. fresh inactive Okta data resolves the same fingerprint and records
   `verified`;
7. truncated or stale evaluation never verifies;
8. reversal requires a new approval.

## Pull Request Slices

### PR 0: Contain incorrect actions

Owner: #1761.

Files:

- `internal/findings/identity_deprovisioned_okta_active_github_rule.go`;
- `internal/findings/identity_okta_deprovisioned_active_cloud_rule.go`;
- focused tests.

Remove the unsafe action attributes and prove execution eligibility rejects both
rules. This PR is independently shippable and should land first.

### PR 1: Remediation binding and provider capability catalogs

Files:

- policy schema and loader;
- `policies/identity/identity-okta-terminated-active-account.yaml`;
- `internal/graphactions/action_catalog.yaml`;
- generators and generated registries;
- catalog checks and fixtures.

No approval store, API, or provider call. Deliver pure, reviewable metadata and
certification validation.

### PR 2: Workflow types, digests, and transition tests

Files:

- `internal/graphactionworkflow/model.go`;
- `canonical.go`;
- `transitions.go`;
- canonical fixtures and pure tests.

No Postgres, bootstrap, transport, or provider imports.

### PR 3: Postgres repositories and event outbox

Files:

- `internal/ports/graphactionworkflow.go`;
- `internal/statestore/postgres/graph_action_workflow.go`;
- schema and concurrency tests;
- outbox append worker tests.

Deliver tenant-qualified rows, revision compare-and-swap, idempotency conflict,
50-caller execution claim, and outbox recovery tests.

### PR 4: Proposal and approval service

Files:

- workflow service and approval policy;
- finding/packet/binding adapters;
- authenticated actor adapter;
- unit and integration tests.

No provider dispatch. A completed PR can create/read/approve/reject proposals.

### PR 5: Public API and authorization parity

Files:

- `proto/cerebro/v1/bootstrap.proto`;
- generated code;
- graph action API/handler/bootstrap routes;
- auth policies and OAuth scopes;
- `api/openapi.yaml`;
- SDK and route/telemetry parity tests;
- reference docs.

Run proto breaking/lint/generation, OpenAPI, SDK, auth-policy, route-label, and
structural checks.

### PR 6: Durable execution worker and provider recovery

Files:

- execution claim service;
- worker lease/dispatch/reconciliation;
- access-approvals provider capability implementation;
- compatibility bridge and mode config;
- fault-injection tests.

Do not enable enforcement until the provider duplicate-key or lookup contract is
proven.

### PR 7: Verification orchestrator

Files:

- verification worker;
- platform-job integration;
- exact rule evaluation/readback;
- workflow events;
- pilot golden fixtures.

No manual `ResolveFinding` fallback. The finding rule lifecycle is the closure
authority.

### PR 8: Pilot rollout and operator runbook

- enable audit mode for selected tenants;
- expose aggregate read status;
- add dashboards/alerts and recovery commands;
- compare provider terminal state with verification result;
- move the certified binding to enforced mode after gates pass.

Each PR states which invariant it establishes and which later invariant remains
unimplemented. Do not merge a transport that appears to enforce approval before
the canonical store and execution claim exist.

## Validation Commands

Every slice:

```bash
git diff --check
make docs-drift-check
make readme-check
```

Catalog slices:

```bash
make graph-action-generate graph-action-check
make policy-rule-generate policy-rule-check
make catalog-check
```

Transport slices:

```bash
make proto-lint proto-generate-check proto-breaking
make openapi-check
make sdk-test
make check-structural check-structural-test check-arch
```

Stateful and worker slices:

```bash
go test ./internal/graphactionworkflow/... ./internal/graphactions/... ./internal/graphactionapi/... ./internal/sourcehttp/graphactionhandler/... ./internal/statestore/postgres/...
go test -race ./internal/graphactionworkflow/... ./internal/graphactions/...
make test
make test-race
make docker-smoke
```

If an exact Make target does not exist on the implementation branch, use the
repository's generated/catalog umbrella target and record the actual command in
the PR. Do not invent a passing result.

## Rollout Gates

### Audit entry gate

- #1761 containment landed;
- canonical store and outbox concurrency tests pass;
- actor binding and tenant tests pass;
- provider capability remains visible as uncertified until contract proof;
- audit mode produces no provider mutation through the new path.

### Enforced pilot gate

- provider same-key recovery is contract-tested;
- 50 concurrent execute requests produce one external action ID and mutation;
- crash matrix passes;
- fresh still-active evidence produces `verification_failed`;
- fresh inactive evidence produces `verified` through the rule lifecycle;
- no unexplained legacy mutation in the audit window;
- alerts and operator recovery are exercised.

### Expansion gate

No second action or finding binding enters enforcement until it has:

- a predicate/effect proof;
- concrete target semantics;
- provider idempotency and reconciliation certification;
- post-action evidence coverage;
- negative provider-success/still-open fixture;
- reversal or explicit irreversible containment policy;
- an owner and operating objective.

## Rollback

Rollback changes mode from `enforced` to `audit` for new claims only. It does
not:

- delete proposals, approvals, executions, verifications, or outbox rows;
- convert in-flight execution to legacy;
- retry ambiguous provider submissions;
- change verified or finding history;
- reuse an approval after a binding/catalog rollback.

Workers continue reconciliation and verification for already claimed
executions. New execution claims stop. Read APIs and operator recovery remain
available.

## Completion Criteria

- The two unsafe downstream-access action advertisements are removed.
- The terminated-active Okta policy has a generated, certified remediation
  binding and provider capability contract.
- A caller cannot mutate from `approved=true`, packet acceptance, agent stage,
  or write scope in enforced mode.
- Proposal, approval, execution, verification, and transition events remain
  durable without Neo4j availability.
- Exactly one provider mutation occurs under concurrency, retry, worker crash,
  append failure, and response-loss tests.
- Provider success never directly resolves the finding.
- Fresh post-action rule evaluation is the proof boundary.
- The aggregate read API explains every blocked, pending, ambiguous, failed,
  verified, and closed state with stable codes and references.
- Each PR slice can be implemented without inventing domain ownership, state
  transitions, or failure semantics.

Refs #1740, #1742, #1760, and #1761.
