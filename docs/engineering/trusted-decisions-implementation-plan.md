# Trusted Decisions Implementation Plan

Status: implementation proposal

Roadmap: [#1727](https://github.com/writer/cerebro/issues/1727)

Primary workstreams: [#1721](https://github.com/writer/cerebro/issues/1721), [#1722](https://github.com/writer/cerebro/issues/1722), [#1723](https://github.com/writer/cerebro/issues/1723), [#1724](https://github.com/writer/cerebro/issues/1724), [#1725](https://github.com/writer/cerebro/issues/1725), and [#1726](https://github.com/writer/cerebro/issues/1726)

## Purpose

Cerebro should scale around one product outcome: an agent or operator completes a
trusted, evidence-backed risk decision.

The implementation should not use connector count, route count, graph size,
finding volume, or release count as substitutes for that outcome. Those numbers
are useful operating inputs, but they do not prove that a decision was accurate,
understood, approved, completed, or verified.

This document is an implementation handoff. It names the contracts, package
boundaries, migration sequence, tests, rollout controls, and small pull requests
needed to deliver the roadmap. An implementation agent should be able to take one
slice without designing a parallel architecture.

## Existing Foundations To Preserve

The current repository already contains important parts of the target design.
New work should extend these paths:

- `internal/knowledge` and `internal/workflowevents` already record durable
  decisions, actions, and outcomes.
- `internal/evidencepackets` already builds audit-oriented evidence packets with
  lineage, claims, findings, graph paths, freshness, and review state.
- `internal/agentplatform` already defines capability preflight, coverage context,
  provenance requirements, write-back rules, and agent evaluation contracts.
- `internal/sourcecdk`, `internal/sourcecoverage`, and
  `internal/connectorcatalog` already model source coverage and provider API
  proof.
- `internal/sourceruntime` and
  `internal/statestore/postgres/source_runtime_page_ledger.go` already write a
  page ledger and outbox before append and projection.
- `internal/appendlog/recovery` and
  `internal/statestore/postgres/append_log_dead_letters.go` already persist
  exhausted publishes and support CLI list, replay, and discard operations.
- `internal/telemetry` and `internal/observability` already implement main-span
  wide events and bounded metrics.
- `api/openapi.yaml`, `proto/cerebro/v1/bootstrap.proto`, and
  `internal/bootstrap/mcp.go` are the current public transport contracts.

Do not create replacement packages for these responsibilities merely to obtain
new names.

## Required Invariants

Every implementation slice must preserve these invariants:

1. The authenticated tenant is forced at the transport boundary. A request field
   cannot expand the caller's tenant or resource scope.
2. NATS JetStream or Postgres owns durable records. Neo4j/Aura is a rebuildable
   projection and never becomes the only record of a decision, claim, finding, or
   workflow event.
3. Source progress cannot advance ahead of accepted event persistence and
   projection.
4. A missing, stale, unsupported, unverified, or failed source is represented as
   a concrete coverage state. It is not converted into a clean result.
5. Read, propose, approve, execute, and verify remain separate states.
6. A model may summarize a decision packet. It may not invent evidence,
   confidence, source coverage, or authorization state.
7. Public responses remain bounded, redacted, and traceable to stable evidence
   references.
8. New persistent-state changes use an ordered migration and a documented
   rollback or forward-repair path.
9. New public operations have one domain service implementation. HTTP, Connect,
   MCP, and SDK adapters must not reimplement domain rules.
10. Deployment-specific schedules, account identifiers, hostnames, and secrets
    stay outside this public runtime repository.

## Target Request Flow

```text
authenticated caller
        |
        v
transport adapter
  - force tenant and scope
  - authorize operation
  - apply request budgets
        |
        v
decision packet service
  - run agent preflight
  - resolve source coverage/certification
  - read claims, findings, evidence, controls, and graph projections
  - classify freshness and conflicts
  - derive decision state and deterministic confidence basis
        |
        +--> immutable packet receipt in Postgres
        |
        +--> optional durable knowledge decision event
        |
        v
HTTP / Connect / MCP response
  - same semantic packet
  - bounded evidence references
  - no write side effect
        |
        v
separate propose -> approve -> execute -> verify workflow
```

## Delivery Order

Use this order. Later slices depend on the contracts and safety properties of
earlier slices.

1. Reconcile already-landed durability work with its open issues.
2. Define workflow and outcome telemetry.
3. Add the decision packet domain contract and pure builder.
4. Persist packet receipts and expose one HTTP/Connect operation.
5. Add connector certification as a computed read model.
6. Add opt-in certification availability gates.
7. Add the task-level MCP surface and evaluation suite.
8. Replace mutable schema checksums with ordered migrations.
9. Complete source-page recovery and harden dead-letter replay.
10. Introduce runtime roles after projection can be recovered independently.
11. Pilot data-only signed content packs.
12. Separate candidate artifacts from stable release publication.

Do not implement the content-pack or runtime-role work before the durability and
migration gates are complete.

## Phase 0: Reconcile Existing Durability Work

Several open issues describe code that is partially or substantially present on
`main`. The first implementation PR should test the acceptance criteria against
current behavior and either close the issue with evidence or open a narrower
follow-up.

### Source page ledger

Current implementation:

- `internal/sourceruntime/service.go` calls `BeginSourceRuntimePage`,
  `MarkSourceRuntimePageAppended`, `MarkSourceRuntimePageProjected`, and
  `CommitSourceRuntimePage`.
- `internal/statestore/postgres/source_runtime_page_ledger.go` persists accepted
  events before external append and commits runtime progress with the ledger
  state in one Postgres transaction.

Remaining gaps:

- The attempt ID includes sync start time, so a retry creates a new attempt
  instead of resuming the same logical page.
- The target runtime/checkpoint is not stored until commit.
- There is no store port for listing incomplete attempts or reading the outbox.
- No recovery worker resumes `started`, `appended`, or `projected` pages.
- Per-event `appended_at` and `projected_at` columns exist, but the service marks
  the whole page at once.
- An old incomplete attempt has no terminal `failed`, `superseded`, or
  `quarantined` state.

The existing ledger therefore improves ordering but is not yet a complete
transactional outbox.

### Append-log dead letters

Current implementation:

- `internal/appendlog/recovery` records an
  `AppendLogPublishExhaustedError` in Postgres.
- `cmd/cerebro/append_log.go` supports list, replay, and discard.
- The record contains subject, event identity, runtime/source/job context,
  payload hash, retry count, and event JSON.

Remaining hardening:

- Concurrent replays can both read `pending` before either marks the record.
- Replay has no lease or `replaying` state.
- Raw `error_message` and event JSON need explicit redaction, encryption, and
  retention rules.
- Batch replay, retry limits, operator identity, and audit events are not part of
  the store contract.
- The findings subject has a separate client-side concurrency bulkhead, but
  findings do not yet have an independently managed JetStream stream.

### Reconciliation checks

Run and attach results to the relevant issues:

```bash
go test ./internal/sourceruntime ./internal/statestore/postgres \
  ./internal/appendlog/recovery ./internal/appendlog/jetstream ./cmd/cerebro
go test ./internal/observability ./internal/telemetry
```

For #1300 through #1304, record which acceptance criteria are already satisfied
and leave the issue open only for remaining behavior.

## Workstream 1: Golden Workflows And Outcome Metrics

Issue: [#1721](https://github.com/writer/cerebro/issues/1721)

### Workflow identifiers

Use these stable workflow IDs:

- `change_decision`
- `finding_to_verified_fix`
- `continuous_evidence`

Do not use persona names or client navigation labels as workflow IDs.

### Durable and ephemeral events

Reuse `internal/knowledge` and `internal/workflowevents` for durable records:

- `workflow.v1.knowledge.decision_recorded`
- `workflow.v1.knowledge.action_recorded`
- `workflow.v1.knowledge.outcome_recorded`

Do not add a durable event for every request phase. Request attempts and
intermediate phases belong in main-span telemetry. A durable event is required
when a decision, approved action, or terminal outcome must survive replay.

Add bounded telemetry fields:

```text
decision.workflow
decision.operation
decision.state
decision.coverage_state
decision.freshness_state
decision.conflict_state
decision.action_state
decision.outcome
decision.dismissal_reason
decision.packet.schema_version
decision.evidence.count
decision.coverage_gap.count
decision.duration_ms
```

Allowed values must be constants. Never label metrics with decision IDs, packet
IDs, URNs, source event IDs, raw errors, user text, or model output.

### Product metrics

Add counters and histograms through `internal/observability`:

- `cerebro_decisions_requested_total`
- `cerebro_decision_packets_built_total`
- `cerebro_decisions_completed_total`
- `cerebro_decision_actions_total`
- `cerebro_decision_outcomes_total`
- `cerebro_decision_duration_seconds`
- `cerebro_decision_evidence_freshness_seconds`

Low-cardinality dimensions:

- workflow
- decision state
- coverage state
- action state
- outcome

Calculate weekly completed decisions from durable outcomes, not from request
logs. A completed decision must have:

1. a durable decision ID,
2. a supported terminal decision state,
3. a terminal outcome or delivered audit packet, and
4. an authenticated tenant.

### Files

- Add `internal/decisionworkflow/types.go` for workflow and state constants.
- Add `internal/decisionworkflow/telemetry.go` for bounded field construction.
- Extend `internal/observability/metrics.go`.
- Extend `internal/workflowevents/events.go` only if an existing durable payload
  cannot express the required workflow or outcome attributes.
- Add `docs/domains/decision-workflows.md` after the event vocabulary is
  executable.

### Tests

- Enum validation rejects arbitrary workflow and state strings.
- Telemetry tests prove high-cardinality fields are not metric dimensions.
- Durable outcome aggregation ignores requests without a terminal outcome.
- Reopened findings do not count as verified closure.
- An audit packet counts as delivered only after an export receipt exists.

## Workstream 2: Canonical Decision Packets

Issue: [#1726](https://github.com/writer/cerebro/issues/1726)

### Package boundary

Create `internal/decisionpacket`.

The package may depend on `internal/ports`, `internal/sourcecoverage`,
`internal/agentplatform`, and domain response types. It must not depend on
`internal/bootstrap`, HTTP request types, MCP types, or generated Connect
handlers.

Do not rename or replace `internal/evidencepackets`. Audit evidence packets and
decision packets serve different grains:

- an audit evidence packet is an evidence collection and export,
- a decision packet is a bounded decision-time view that may reference audit
  evidence packets.

### Contract

Use a versioned shape equivalent to:

```go
type Packet struct {
    SchemaVersion  string
    ID             string
    GeneratedAt    time.Time
    Workflow       Workflow
    Scope          Scope
    Decision       Decision
    Confidence     Confidence
    Freshness      Freshness
    Evidence       []EvidenceReference
    Contradictions []Contradiction
    CoverageGaps   []CoverageGap
    Affected       []SubjectReference
    Controls       []ControlReference
    Actions        []ActionProposal
    Provenance     Provenance
    Limits         ResultLimits
}
```

Required decision states:

- `supported`
- `supported_with_gaps`
- `blocked`
- `insufficient_evidence`
- `not_applicable`

Authorization failures remain transport errors. Do not return an
`unauthorized` packet that confirms whether protected evidence exists.

Required coverage states:

- `complete`
- `partial`
- `stale`
- `failed`
- `unconfigured`
- `unsupported`
- `unverified`

Required action states:

- `informational`
- `proposal`
- `approval_required`

A decision packet never returns `executed`.

### Confidence

Confidence must be deterministic and explainable:

```go
type Confidence struct {
    Level string
    Basis []string
}
```

Start with `high`, `medium`, `low`, and `unknown`. Do not add a percentage until
the team has a calibrated outcome dataset.

The initial derivation should use explicit rules:

- missing required coverage caps confidence at `low`,
- stale required evidence caps confidence at `low`,
- one unresolved contradiction caps confidence at `medium`,
- unverified required sources cap confidence at `low`,
- no supporting evidence produces `unknown`,
- `high` requires fresh supporting evidence, no unresolved contradiction, and
  no required coverage gap.

### Builder algorithm

`Service.Build(ctx, Request)` should:

1. Validate workflow, scope, and budgets.
2. Receive the forced tenant from the caller; do not accept a tenant override
   inside the service request.
3. Run `agentplatform.AgentRunPreflight` for capability, provenance, and
   coverage requirements.
4. Resolve effective connector certification and source health.
5. Load findings, claims, evidence, controls, and bounded graph context through
   ports.
6. Normalize evidence references and deduplicate by stable source/evidence ID.
7. Calculate freshness from observed timestamps and declared freshness
   expectations.
8. Detect contradictions by subject, predicate, and overlapping validity
   interval.
9. Build coverage gaps before deriving the decision state.
10. Derive confidence from explicit rules.
11. Build action proposals without dispatching them.
12. Sort all repeated fields deterministically.
13. Hash the canonical JSON to produce the packet ID and receipt digest.
14. Persist the bounded receipt when a receipt store is configured.

The builder must return the same packet for the same normalized inputs and
clock. Tests should inject the clock.

### Receipt store

Add a `ports.DecisionPacketReceiptStore` and Postgres implementation.

Suggested table:

```sql
CREATE TABLE decision_packet_receipts (
  tenant_id TEXT NOT NULL,
  packet_id TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  workflow TEXT NOT NULL,
  scope_urn TEXT NOT NULL DEFAULT '',
  decision_state TEXT NOT NULL,
  confidence_level TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  coverage_digest TEXT NOT NULL,
  packet_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, packet_id)
);
```

Requirements:

- Packet JSON is already redacted and bounded before persistence.
- Tenant ID is part of every key and query.
- Receipt lookup never accepts a packet ID without authenticated tenant scope.
- Retention is configurable by deployment and documented.
- A packet receipt is immutable. A later decision creates a new packet.
- Store the packet schema version and digests required for audit comparison.

Do not project the full packet into Neo4j. A durable knowledge decision may link
to the packet receipt URN and evidence URNs.

### Transport contract

Add `proto/cerebro/v1/decision.proto` for reusable packet messages. Add one RPC
to `BootstrapService`:

```text
BuildDecisionPacket(BuildDecisionPacketRequest)
  returns (BuildDecisionPacketResponse)
```

Add one JSON operation:

```text
POST /api/v1/platform/decision-packets
```

The HTTP and Connect adapters must call the same `decisionpacket.Service`.
`operationId` should be `buildDecisionPacket`.

The first request supports:

- workflow
- scope URN
- finding IDs
- control IDs
- include graph context
- bounded evidence and graph limits

Tenant ID is forced from auth and is not a public request field.

### Tests

Add golden fixtures for:

- fresh and complete evidence,
- partial coverage,
- stale evidence,
- provider verification expired,
- contradictory claims,
- no evidence,
- graph store unconfigured,
- evidence truncation,
- cross-tenant references,
- deterministic ordering and packet ID,
- action proposal with required approval,
- receipt lookup under the wrong tenant.

Contract tests must compare HTTP, Connect, and domain results after normalizing
transport-specific metadata.

## Workstream 3: Connector Certification

Issue: [#1725](https://github.com/writer/cerebro/issues/1725)

### Static proof and live state are separate

Do not add `production_observed` or `outcome_validated` as self-declared catalog
fields. Catalog files can declare static proof. Live runtime and outcome data
must determine dynamic tiers.

Use these ordered tiers:

1. `cataloged`
2. `spec_verified`
3. `contract_tested`
4. `production_observed`
5. `outcome_validated`

`invalidated` is an overriding state, not a tier.

### Static catalog evidence

Extend source catalog normalization with a certification evidence block:

```yaml
certification:
  owner: source-runtime
  reviewed_at: 2026-07-10T00:00:00Z
  expires_at: 2026-10-10T00:00:00Z
  evidence:
    - kind: provider_spec
      reference: https://provider.example/api/openapi.json
      digest: sha256:...
    - kind: sandbox_contract
      receipt: source-contract/github/2026-07-10
      digest: sha256:...
      families: [repository, pull_request]
```

Allowed static evidence kinds:

- `provider_spec`
- `provider_documentation`
- `sandbox_contract`
- `recorded_replay`

The existing `provider_api` and `provider_api_disproof` blocks remain
authoritative for API mapping and invalidation. Certification consumes their
computed proof; it does not create a second provider-proof score.

### Computed read model

Create `internal/sourcecertification`.

Inputs:

- `connectorcatalog.ProviderAPIDepthForSourceCatalog`
- normalized certification evidence
- `sourcecoverage.Report`
- latest source runtime status and freshness
- durable decision/outcome summaries by source ID

Output:

```go
type Result struct {
    SourceID       string
    EffectiveTier  Tier
    StaticTier     Tier
    DynamicTier    Tier
    Invalidated    bool
    ExpiresAt      time.Time
    Gaps           []string
    Evidence       []Evidence
    LastObservedAt time.Time
}
```

Effective tier rules:

- invalidation overrides every tier,
- expired static proof falls back to `cataloged`,
- provider proof can produce at most `spec_verified`,
- sandbox contract proof can produce at most `contract_tested`,
- fresh successful runtime observations can raise a
  `contract_tested` source to `production_observed`,
- accepted durable outcomes referencing the source can raise a
  `production_observed` source to `outcome_validated`,
- a failed or stale runtime does not erase static proof, but availability views
  must show the live failure separately.

Do not compute `outcome_validated` from request volume.

### Availability gates

Add an opt-in minimum tier to connector/source list filters before changing any
default:

```text
min_certification_tier
include_preview
```

Add deployment configuration only after the API filter works:

```text
CEREBRO_SOURCE_MIN_CERTIFICATION_TIER
```

Rollout:

1. Compute and return certification with no filtering.
2. Add explicit caller filters.
3. Add warning-only deployment policy.
4. Measure which configured runtimes would be hidden.
5. Enable enforcement per environment.
6. Consider a production default only in a documented stable release.

Never silently hide an already configured runtime. Return it with a blocked or
below-policy state so the operator can repair or explicitly allow it.

### Files

- `internal/sourcecdk/certification.go`
- `internal/sourcecertification/service.go`
- `internal/sourcecertification/service_test.go`
- `internal/connectorcatalog/entries.go`
- `internal/bootstrap/connectors.go`
- `internal/bootstrap/mcp.go`
- `api/openapi.yaml`
- `proto/cerebro/v1/source.proto`
- selected `sources/<source_id>/catalog.yaml` files for the pilot cohort

### Pilot cohort

Choose one source from each of these categories:

- source control,
- identity,
- cloud,
- work management,
- vulnerability or endpoint security.

The pilot selection must be based on deployed usage and decision workflow
requirements. Do not choose only by catalog implementation convenience.

## Workstream 4: Task-Level MCP Surface

Issue: [#1722](https://github.com/writer/cerebro/issues/1722)

### Inventory first

Add a checked-in inventory generated from `mcpTools()` with:

- tool name,
- owning domain,
- read or write behavior,
- required scopes,
- task-level or expert classification,
- response contract,
- deprecation state.

The generator should fail CI when a tool is added without ownership,
authorization, and classification.

### Initial task-level tools

Expose these six task tools to clients that request the task profile:

- `cerebro.change.context`
- `cerebro.risk.explain`
- `cerebro.evidence.packet`
- `cerebro.controls.status`
- `cerebro.sources.health`
- `cerebro.action.plan`

These tools compose existing services. They are not aliases that call the MCP
endpoint recursively.

`cerebro.action.plan` returns proposals only. Existing execution operations
remain separate and require write scopes and approval state.

### Profiles and compatibility

Add MCP tool profiles:

- `task` — the six task-level tools plus health/version,
- `expert` — current low-level read tools,
- `operator` — approved operational and write tools.

Default existing deployments to the current full behavior until compatibility
telemetry shows the task profile is safe. New agent onboarding examples should
request `task`.

Do not remove or rename an existing tool in the first release. Mark expert tools
in metadata and documentation.

Resolve the profile from authenticated credential or OAuth entitlement first,
then from deployment default. A request may select a narrower profile, but it
cannot use an initialize parameter or HTTP header to elevate beyond its
credential entitlement. Operator tools still require their existing write
scopes even when the credential has the `operator` profile.

Add `full` as a temporary compatibility profile for existing credentials. Do
not advertise `full` in new onboarding material.

### Shared operation metadata

Create `internal/operationcatalog` with one record per public operation:

```go
type Operation struct {
    ID             string
    Domain         string
    Risk           string
    ReadOnly       bool
    RequiredScopes []string
    HTTPPath       string
    ConnectMethod  string
    MCPTool        string
    MCPProfile     string
}
```

The registry does not generate handlers. It provides structural checks so
authorization, operation IDs, telemetry, and transport exposure cannot drift.

Add checks:

- every MCP tool has one operation record,
- every OpenAPI operation has `operationId`,
- every Connect method has an auth policy,
- an operation marked read-only cannot map to a write handler,
- a task-profile operation cannot require an operator-only scope,
- HTTP and Connect adapters mapped to one operation call the same domain service.

### Evaluation suite

Add fixtures under `internal/agentplatform/testdata/task_tools/`.

For each golden workflow, record:

- user request,
- permitted scopes,
- available connectors and certification,
- expected selected tool,
- allowed follow-up tools,
- forbidden write,
- required partial-evidence behavior,
- maximum call count.

The evaluation passes when the task profile improves correct tool selection and
does not increase unsafe writes or unsupported conclusions.

## Workstream 5: Ordered Database Migrations

Issue: [#289](https://github.com/writer/cerebro/issues/289)

### Problem with the current ledger

`schema_migrations` currently stores one mutable checksum for each
`ensure:<label>` group. When statements change, the checksum is updated. This
records drift but does not prove that every intermediate migration ran in order.

Some current statements use `CREATE INDEX CONCURRENTLY`, which cannot run inside
a normal transaction. The migration runner must model this explicitly.

### Migration format

Add:

```text
internal/statestore/postgres/migrations/
  migrations.go
  v000001_baseline.go
  v000002_decision_packet_receipts.go
  ...
```

Use Go migration definitions so transaction mode and verification can be
tested:

```go
type Migration struct {
    Version       string
    Name          string
    Transactional bool
    Statements    []string
    Verify        func(context.Context, *sql.DB) error
}
```

Version values use `vNNNNNN_name`. Applied checksums are immutable.

### Runner behavior

1. Acquire a Postgres advisory lock dedicated to Cerebro migrations.
2. Read applied `v%` rows in version order.
3. Fail if an applied checksum differs from the compiled checksum.
4. Fail if a version gap exists.
5. Run transactional migrations in one transaction.
6. Run non-transactional migrations under the advisory lock and verify their
   result before recording success.
7. Insert the immutable version and checksum.
8. Release the lock.

Keep existing `ensure:*` rows for compatibility. The new runner ignores them
when ordering `v%` migrations.

### Deployment commands

Add:

```text
cerebro deploy migrate
cerebro deploy migrate status
cerebro deploy migrate verify
```

Initial compatibility:

- `serve` may apply pending migrations while the rollout is opt-in.
- production deployments should move to an explicit migration job followed by
  `serve` in verify-only mode.
- no migration mode may silently skip required schema and report ready.

Every persistent-state PR must document:

- expand step,
- data migration or backfill,
- contract step,
- forward-repair behavior,
- downgrade limitation.

### Adoption

Do not convert all current ensure groups in one PR.

1. Land the runner and baseline verification.
2. Put all new tables behind ordered migrations.
3. Convert the page ledger, dead letters, and decision receipts.
4. Convert remaining domains one package at a time.
5. Remove mutable checksum updates only after every required table has an
   ordered owner.

## Workstream 6: Finish Source-Page Recovery

Related issues: [#1303](https://github.com/writer/cerebro/issues/1303) and
the source-sync recovery contract.

### Stable logical page key

Replace the start-time attempt ID with a logical page key derived from:

- tenant ID,
- runtime ID,
- source ID,
- runtime progress config hash,
- starting cursor/checkpoint digest,
- ending cursor/checkpoint digest,
- ordered accepted event IDs.

Keep a separate random execution ID for telemetry. Re-running the same logical
page must address the same ledger row.

### Store the target state before append

At `BeginSourceRuntimePage`, persist:

- starting progress digest,
- target runtime JSON,
- target progress digest,
- event count and ordered outbox,
- logical page key,
- execution ID,
- retry count.

This gives recovery enough information to commit the page after append and
projection succeed.

### Recovery ports

Extend `ports.SourceRuntimePageLedgerStore`:

```go
ListIncompleteSourceRuntimePages(ctx, limit, leaseOwner)
LeaseSourceRuntimePage(ctx, pageKey, leaseOwner, leaseTTL)
GetSourceRuntimePageOutbox(ctx, pageKey)
MarkSourceRuntimePageEventAppended(ctx, pageKey, eventID)
MarkSourceRuntimePageEventProjected(ctx, pageKey, eventID, projection)
FailSourceRuntimePage(ctx, pageKey, category)
SupersedeSourceRuntimePage(ctx, pageKey, reason)
```

Use `FOR UPDATE SKIP LOCKED` or an equivalent lease transition so multiple
recovery workers do not process one page.

### Recovery state machine

```text
started
  -> appending
  -> appended
  -> projecting
  -> projected
  -> committed

any nonterminal state -> failed
failed -> appending | superseded
```

Recovery behavior:

- append only events without `appended_at`,
- project only events without `projected_at`,
- use the existing stable event ID for idempotency,
- commit target runtime progress only after all events are projected,
- supersede an attempt only when current runtime progress provably moved beyond
  the target progress,
- never infer completion from Neo4j alone.

### Runner

Add a bounded job kind in `internal/jobs`:

```text
source_runtime_page_recover
```

The job accepts tenant/runtime filters, maximum pages, and dry-run. The global
scan requires admin authorization; tenant-scoped recovery may use source-manager
authorization.

Add CLI:

```text
cerebro source-runtime recover list
cerebro source-runtime recover run runtime_id=<id> limit=<n> dry_run=true
cerebro source-runtime recover run runtime_id=<id> limit=<n>
```

### Failure-injection tests

Cover process termination:

- after ledger begin,
- after one event append,
- after all appends,
- after one projection,
- after all projections,
- after runtime progress commit before response.

Run recovery twice in every case and assert:

- no duplicate durable event identity,
- no duplicate graph relationship,
- progress advances exactly once,
- committed pages are not selected again.

## Workstream 7: Harden Dead-Letter Replay And Stream Isolation

Issues: [#1300](https://github.com/writer/cerebro/issues/1300),
[#1301](https://github.com/writer/cerebro/issues/1301),
[#1303](https://github.com/writer/cerebro/issues/1303), and
[#1304](https://github.com/writer/cerebro/issues/1304)

### Replay lease

Add states:

- `pending`
- `replaying`
- `replayed`
- `discarded`
- `failed`

Replay must atomically claim `pending -> replaying` with operator identity and a
lease expiry. A crashed replay may return to `pending` after the lease expires.

On successful append, mark `replayed` in the same store transaction that writes
the replay audit record. Because JetStream and Postgres cannot share a
transaction, the stable NATS message ID and event ID provide append idempotency.

### Privacy and retention

- Store a normalized error category and fingerprint. Do not persist an arbitrary
  provider or broker error string without redaction.
- Apply the same event redaction contract used by replay and public evidence.
- Encrypt event JSON using the deployment's existing state-store encryption
  boundary when configured.
- Add `expires_at` and a cleanup job.
- Record actor, reason, original record ID, and resulting publish sequence for
  replay or discard.

### Findings stream

Keep the existing subject family stable:

```text
sec.findings.v1.>
```

Create a dedicated stream that owns that subject. Update the general stream so
its subject set no longer overlaps. JetStream rejects overlapping ownership, so
the deployment must use this order:

1. deploy consumers able to read the new stream,
2. pause findings publishers,
3. remove the findings subject from the general stream,
4. create or update the findings stream,
5. resume publishers,
6. verify publish ACKs and consumers,
7. drain old retained findings according to the migration plan.

Configuration must name stream ownership explicitly. A client-side semaphore is
not stream isolation.

### SLO checks

Before adding new metrics, audit current `RecordJetStreamPublish` dimensions.
Close #1301 if success, failure, retry, exhaustion, and ACK latency are already
exported with bounded subject normalization. Add only missing signals.

For #1304, keep NATS server scraping outside the request path. Use a timed
collector with strict timeouts and bounded stream names.

## Workstream 8: Runtime Roles

Issue: [#433](https://github.com/writer/cerebro/issues/433)

The issue references historical package names. Re-cut ownership against the
current bootstrap-centered repository before implementation.

### Roles

Target roles:

- `all` — current compatibility behavior,
- `api` — public HTTP, Connect, MCP, and read/query services,
- `ingest` — source schedules, source reads, page outbox, and append,
- `projector` — page recovery, source/workflow projection, findings evaluation,
  and graph projection,
- `agent` — graph reasoning, agent jobs, and action planning/execution.

### Do not expose a fake projector role

Current source sync appends and projects in the same call. An independently
scalable projector role is not real until the page outbox and recovery worker
can project accepted events without the ingest process.

Implement roles in stages:

1. Add an ownership matrix and startup-job registry.
2. Add `all` and `api`; make `api` omit warmups, schedulers, and backfills that
   are not request-owned.
3. Add `ingest` after page recovery exists.
4. Add `projector` after projection consumes durable outbox/event records.
5. Add `agent` after action job ownership and idempotency are explicit.

### Command contract

Change `serve` to accept:

```text
cerebro serve role=all
cerebro serve role=api
cerebro serve role=ingest
cerebro serve role=projector
cerebro serve role=agent
```

Use a CLI argument as the primary contract. A deployment environment variable
may supply the default, but command-line configuration must win.

### Startup ownership

Create `internal/runtimehost`:

```go
type Role string

type Component struct {
    Name     string
    Roles    []Role
    Required []Dependency
    Start    func(context.Context) error
    Stop     func(context.Context) error
}
```

Move these startup choices out of `cmd/cerebro/main.go`:

- GRC read-model warmup,
- finding risk backfill,
- report scheduler,
- source recovery workers,
- projector consumers,
- agent/action workers.

`cmd/cerebro` remains process and signal wiring. `internal/bootstrap` remains the
transport composition root.

### Readiness

Readiness is role-specific:

- `api` requires only dependencies used by enabled routes,
- `ingest` requires state store, append log, and provider egress,
- `projector` requires state store, append log, and graph store when graph
  projection is enabled,
- `agent` requires its selected LLM/action providers in addition to data stores.

Every health response includes role and enabled component names.

### Rate limiting and tenant fairness

The current HTTP rate limiter is per process. Before scaling `api`, put the
authoritative rate limit at the load balancer/gateway or use a shared limiter.
Keep a local limiter only as an instance-protection bulkhead.

Background workers need:

- tenant-aware queues,
- per-provider concurrency limits,
- per-tenant in-flight caps,
- lease ownership,
- backpressure metrics,
- no schedule multiplication when replicas increase.

### Projection generations

An independently scalable projector also needs a safe graph rollout boundary.
Use the existing `internal/projectionmeta`, `internal/graphingest`,
`internal/graphquery`, and `internal/graphstore/neo4j` packages rather than
adding a second graph abstraction.

Add a projection generation to every projector-owned graph write. Keep the
active generation pointer in Postgres so Neo4j does not become authoritative.

Rebuild flow:

1. allocate a new generation for one tenant and projection schema version,
2. replay durable records into the new generation,
3. compare entity, relationship, finding-link, and provenance counts,
4. run bounded semantic canary queries against both generations,
5. record the comparison receipt in Postgres,
6. atomically change the active generation pointer,
7. retain the previous generation through the rollback window,
8. garbage-collect only after the new generation remains healthy.

Graph reads must resolve the active generation from a cached Postgres-owned
pointer. A missing pointer uses the current compatibility generation. Raw
Cypher and maintenance commands must require an explicit generation rather than
quietly mixing data.

The generation schema includes:

- tenant ID,
- projection schema version,
- generation ID,
- source runtime/checkpoint range,
- created, completed, activated, and retired timestamps,
- build status and comparison receipt,
- active flag owned by Postgres.

Failure injection must prove that a failed build or failed pointer switch leaves
the prior generation readable.

## Workstream 9: Data-Only Signed Content Packs

Issue: [#1724](https://github.com/writer/cerebro/issues/1724)

### Pilot boundary

The first pack format is data-only. It must not load Go plugins, shared
libraries, scripts, templates with code execution, or arbitrary binaries.

Pilot contents:

```text
manifest.json
connectors/*.yaml
policies/<domain>/*.yaml
controls/*.yaml
checksums.txt
signature.sig
certificate.pem
```

Handwritten executable sources remain in the kernel during the pilot. Generated
declarative connector definitions may move when the existing dynamic connector
runtime can consume them safely.

### Manifest

```json
{
  "schema_version": "v1",
  "pack_id": "cerebro-default-security",
  "version": "2026.07.10",
  "kernel_compatibility": ">=2.2.0 <3.0.0",
  "created_at": "2026-07-10T00:00:00Z",
  "contents": [],
  "required_capabilities": [],
  "certification_summary": {},
  "digest": "sha256:..."
}
```

Use the existing release workflow's keyless cosign blob-signing pattern. Do not
invent a second signature format for the pilot.

### Loader

Create `internal/contentpacks`:

1. Read a local file or OCI-downloaded immutable artifact.
2. Verify digest and signature before parsing content.
3. Check kernel compatibility.
4. Validate every catalog with existing validators.
5. Detect duplicate IDs and deterministic precedence conflicts.
6. Build a complete candidate registry in memory.
7. Swap the registry only after the full pack set validates.
8. Preserve the last known-good registry if reload fails.

Pack selection is deployment configuration. Tenant-specific selection requires
an explicit allowlist and must not permit one tenant to influence another
tenant's registry.

### Pilot measurements

Record before and after:

- repository checkout size,
- core binary size,
- clean and incremental build time,
- source/security scan time,
- startup and validation time,
- memory used by loaded catalogs,
- rollback time,
- failure behavior for an invalid signature or incompatible pack.

Do not move more content until the pilot proves a material benefit.

## Workstream 10: Candidate Builds And Stable Release Train

Issue: [#1723](https://github.com/writer/cerebro/issues/1723)

### Per-merge candidate

Replace automatic stable tagging on every `main` push with a candidate workflow
that publishes:

- image pinned by commit SHA and digest,
- binaries or build artifacts pinned by commit SHA,
- SBOM and provenance,
- runtime contract,
- contract diff,
- test receipts,
- no stable semantic version.

Suggested image tag:

```text
sha-<12-character-commit>
```

The digest remains the deployment identity.

### Stable release

Keep `release.yml` as the stable publication path, but trigger it through a
scheduled or explicitly approved release cut.

The release body must include:

- user-visible changes,
- API and MCP contract changes,
- event/schema changes,
- database migration requirements,
- configuration changes,
- content-pack compatibility,
- canary/load-smoke evidence,
- rollback and downgrade limits.

### Version policy

- patch: compatible fixes and content changes within existing contracts,
- minor: additive public contracts, opt-in behavior, new migrations,
- major: removal, incompatible event/schema behavior, or changed default trust
  boundary.

An emergency security release may cut immediately with the same evidence except
for the normal schedule.

### Workflow migration

1. Add the candidate workflow while keeping current stable publication.
2. Prove deployment automation can consume a candidate digest.
3. Change `cut-release.yml` so `main` no longer creates a stable tag.
4. Add scheduled/manual stable release selection.
5. Preserve cosign signatures, attestations, checksums, multi-arch images, and
   runtime-contract assets.
6. Document the supported stable-version window.

## Cross-Cutting Test Matrix

Every implementation PR should run the smallest relevant set plus structural
checks.

| Change | Required checks |
| --- | --- |
| Decision workflow/telemetry | `go test ./internal/decisionworkflow ./internal/telemetry ./internal/observability` |
| Decision packet domain | `go test ./internal/decisionpacket ./internal/agentplatform ./internal/evidencepackets` |
| Decision packet transports | `go test ./internal/bootstrap`; `make proto-generate-check openapi-check mcp-contract-check` |
| Certification | `go test ./internal/sourcecdk ./internal/sourcecoverage ./internal/sourcecertification ./internal/connectorcatalog`; `make catalog-check` |
| MCP profiles | `go test ./internal/bootstrap ./internal/agentplatform`; `make mcp-contract-check mcp-sdk-compat` |
| Migrations | `go test ./internal/statestore/postgres`; Postgres integration job from an old schema fixture |
| Page recovery | `go test ./internal/sourceruntime ./internal/jobs ./internal/statestore/postgres` |
| Dead letters/JetStream | `go test ./internal/appendlog/... ./cmd/cerebro`; NATS integration job |
| Runtime roles | `go test ./cmd/cerebro ./internal/runtimehost ./internal/bootstrap`; Docker smoke per role |
| Projection generations | `go test ./internal/projectionmeta ./internal/graphingest ./internal/graphquery ./internal/graphstore/neo4j`; rebuild comparison fixture |
| Content packs | `go test ./internal/contentpacks`; signature, compatibility, invalid-pack, and rollback fixtures |
| Release workflows | workflow unit/script tests, candidate dry run, stable release smoke |

Before any stable release:

```bash
make check
make sdk-test
make release-smoke
make docker-smoke
```

## Implementation Pull Request Slices

Do not assign this entire document as one coding task. Use these bounded PRs:

1. **Durability reconciliation** — verify current #1300–#1304 behavior and add
   missing acceptance tests without changing architecture.
2. **Workflow vocabulary** — add workflow/state constants and bounded telemetry.
3. **Decision packet types** — pure contract, normalization, confidence, and
   golden tests.
4. **Decision packet builder** — compose existing read ports; no transport.
5. **Decision packet receipt migration/store** — ordered migration plus tenant
   tests.
6. **Decision packet HTTP/Connect** — shared service adapters and contract
   parity.
7. **Certification static proof** — catalog schema and computed static tier.
8. **Certification live overlay** — runtime freshness and outcome validation.
9. **Certification filters** — explicit API/CLI/MCP filters, warning-only
   deployment policy.
10. **MCP inventory and operation catalog** — metadata and structural tests.
11. **MCP task profile** — six tools and evaluation fixtures, no removal.
12. **Ordered migration runner** — baseline, advisory lock, checksum failure,
    deploy commands.
13. **Page recovery store ports** — stable page key, incomplete-page reads, and
    leases.
14. **Page recovery worker** — state machine, job, CLI, and failure injection.
15. **Dead-letter leases/privacy** — replay claim, audit, retention, and
    redaction.
16. **Findings stream isolation** — code/config contract and deployment runbook.
17. **Runtime ownership matrix** — `all` and `api` roles only.
18. **Ingest/projector roles** — only after durable recovery is proven.
19. **Projection generations** — Postgres-owned active pointer, shadow rebuild,
    comparison receipt, activation, and rollback.
20. **Content-pack manifest/verifier** — data-only library and negative tests.
21. **Content-pack pilot** — one connector definition set and one policy/control
    set with measurements.
22. **Candidate release workflow** — no stable behavior change.
23. **Stable release train switch** — deployment readback and rollback proof
    required.

Each PR description must include:

- owning issue and slice number,
- exact contract change,
- persistent-state impact,
- feature flag or compatibility behavior,
- tests and failure injection,
- deployment order,
- rollback or forward-repair procedure,
- metrics that prove the slice works.

## Rollout Gates

The roadmap is ready to expand only when these gates pass:

### Value gate

- At least one golden workflow records a request, packet, durable decision, and
  terminal outcome.
- The team can calculate completed decisions without joining raw request logs.

### Trust gate

- Decision packets expose stale, missing, conflicting, and unverified evidence.
- Connector certification cannot be raised by a catalog declaration alone.

### Durability gate

- Failure injection proves page recovery from every nonterminal state.
- Dead-letter replay is leased, idempotent, audited, and bounded.
- Neo4j can be cleared and rebuilt without losing durable decisions.

### Scale gate

- Two API replicas produce consistent authorization and rate-limit behavior.
- Multiple workers do not duplicate schedules, page recovery, actions, or
  projections.
- Tenant and provider concurrency limits prevent one workload from consuming
  every worker.

### Delivery gate

- A candidate can deploy by digest and roll back.
- A stable release includes migrations, contract diffs, canary evidence, and
  downgrade limits.
- An invalid content pack cannot replace the last known-good registry.

## Definition Of Done

This plan is complete when:

- the three golden workflows have executable state and outcome contracts,
- consequential read operations return one versioned decision packet,
- connector availability reflects computed proof and live health,
- agent onboarding uses a task-level MCP profile,
- schema evolution is ordered and immutable,
- source page recovery and dead-letter replay survive process failure,
- runtime roles scale independently without changing durable semantics,
- one signed data-only pack can be validated and rolled back independently,
- stable releases are explicit while every merge remains available by immutable
  candidate digest,
- before/after reports show decision completion, closure time, evidence
  freshness, and cost per completed decision.
