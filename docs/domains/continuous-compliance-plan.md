# Continuous Compliance Execution Plan

## Outcome

Cerebro should produce one durable answer for a compliance scope:

- what is in scope
- which controls pass, fail, or still need a decision
- which evidence supports each result and whether that evidence is fresh and trusted
- which source or coverage gaps limit the result
- who owns each next action and when it is due
- what changed since the previous assessment
- which immutable packet was delivered for review

The unit of work is a versioned **compliance assessment**. A request-time report is
not an assessment until its scope, inputs, control results, review decisions, and
content hash can be read again by ID.

This plan turns the existing control catalog, evidence, findings, policy lifecycle,
readiness, source coverage, workflow events, jobs, and exports into that closed loop.
It does not add a second control catalog, a second evidence store, or a web UI.

## Why The Current Model Needs A New Center

The existing components are useful, but they stop at different points in the same
workflow:

| Current component | What it does now | Gap to close |
| --- | --- | --- |
| `internal/compliance` | Resolves control scope, rule coverage, evidence requirements, posture, and packet contents. | The result is computed in memory and has no durable assessment identity. |
| `internal/grccontrol` | Adapts findings, evidence, and runtimes into control packet and report types. | It introduces another control-result representation. |
| `internal/grcprogram` | Scores readiness and creates a request-time work queue. | Work items have no lifecycle, owner history, or stable link to an assessment. |
| `internal/evidencepackets` | Builds a detailed packet, lineage rows, exports, and a snapshot hash. | Each read creates a new snapshot ID; the snapshot and packet are not stored as an immutable run. |
| `internal/grcpolicylifecycle` | Reads policy operations from graph projection and appends lifecycle actions. | Policy gaps, exceptions, and approvals are not evaluated in the same assessment as technical controls. |
| `internal/bootstrap` GRC handlers | Gather current runtimes, findings, and evidence, then build responses. | HTTP handlers own orchestration, and the GRC contract has no equivalent Connect surface. |

The same control state is represented by `compliance.ControlPosture`,
`grccontrol.ControlItem`, `grcprogram.Control`, and
`evidencepackets.ControlPosture`. The current single status also combines three
different questions: whether a control applies, whether it is operating, and
whether the supporting evidence is sufficient. That makes missing, stale,
conflicting, untrusted, and failing evidence difficult to explain without losing
information during conversion.

The overhaul should not start with more framework rows or another export format. It
should make the assessment run the canonical operating record and adapt existing
read surfaces from it.

## Target Package Boundaries

Add `internal/complianceassessment` as the orchestration and result domain.

```text
control packs + profiles                 source runtimes + coverage
            |                                      |
            v                                      v
    internal/compliance                    findings + evidence
            |                                      |
            +------------------+-------------------+
                               v
                 internal/complianceassessment
                     |        |        |
                     |        |        +--> workflow.v1.compliance.* events
                     |        +-----------> Postgres assessment projection
                     +--------------------> immutable packet + work items
                               |
             +-----------------+------------------+
             v                 v                  v
       JSON / Connect     MCP task tool      export / diff
```

Responsibilities:

- `internal/compliance` remains the pure catalog, selection, mapping, evidence
  requirement, and evaluation library.
- `internal/complianceassessment` owns assessment state, canonical control results,
  orchestration, review decisions, diffs, and work-item derivation.
- `internal/evidencepackets` renders a versioned packet from an immutable completed
  assessment. It does not independently recalculate control state.
- `internal/grccontrol` and `internal/grcprogram` become compatibility adapters for
  existing routes while clients migrate.
- `internal/bootstrap` authorizes, decodes, and maps transports. It does not decide
  control status.
- Postgres is the current-state read model. JetStream workflow events are the log of
  record. Neo4j remains an optional rebuildable projection.

## Canonical Contracts

### Assessment

`Assessment` should include:

| Field | Requirement |
| --- | --- |
| `id` | Tenant-scoped stable ID. |
| `tenant_id` | Required on every store query and event. |
| `profile_id` | Selected built-in or extension profile. |
| `catalog_version` | Exact control catalog version used for the run. |
| `packet_version` | Exact output contract version. |
| `state` | `queued`, `collecting`, `evaluating`, `review_required`, `complete`, `failed`, `cancelled`, or `superseded`. |
| `scope` | Frameworks, controls, sources, runtimes, exclusions, and evidence cutoff. |
| `minimum_source_tier` | Minimum acceptable source proof for an asserted pass. |
| `baseline_assessment_id` | Optional completed assessment used for a diff. |
| `job_id` | Durable platform job executing the run. |
| `requested_by` | Authenticated actor ID. |
| `requested_at`, `started_at`, `completed_at` | Run timeline. |
| `content_hash` | Hash of the canonical completed snapshot, excluding transport-only fields. |
| `failure_code` | Bounded machine-readable failure reason. Internal errors stay out of the public response. |

An assessment is immutable after `complete`. A rerun creates a new assessment. A
review action creates a new review event and a derived assessment revision; it does
not rewrite the original evidence cutoff or collected inputs.

### Control Result

Replace the overloaded single status inside the new contract with separate axes:

| Axis | Values | Question answered |
| --- | --- | --- |
| `scope_state` | `in_scope`, `not_applicable`, `unresolved` | Should this control be evaluated for this scope? |
| `outcome` | `pass`, `fail`, `exception`, `unresolved` | What did the control evaluation conclude? |
| `evidence_state` | `sufficient`, `missing`, `stale`, `conflicting`, `untrusted`, `manual_review` | Can the supplied proof support that outcome? |
| `assurance` | `high`, `medium`, `low`, `none` | How strong is the declared basis after coverage, freshness, source proof, and conflicts are considered? |

Each result also carries:

- framework, family, and control identity
- mapped rule IDs and policy IDs
- finding, evidence, claim, event, run, and graph references
- evidence requirement results, including missing fields
- source coverage and certification state captured at the assessment cutoff
- exception and not-applicable decision references
- reason codes and concrete next actions
- evaluation timestamp and evaluator contract version

Assurance is deterministic. It is derived from declared inputs and includes basis
codes such as `coverage_partial`, `source_unverified`, `evidence_stale`, and
`contradicting_observation`. It is not a model-generated confidence score.

Existing status fields remain compatible through one shared adapter:

| New result | Existing status |
| --- | --- |
| `scope_state=not_applicable` | `not_applicable` |
| `outcome=exception` | `exception` |
| `outcome=fail` | `failing` |
| `evidence_state=missing` | `missing_evidence` |
| `evidence_state=stale` | `stale_evidence` |
| `evidence_state=manual_review`, `conflicting`, or `untrusted` | `manual_review` with a reason code |
| `outcome=pass` and `evidence_state=sufficient` | `passing` |
| any unresolved combination | `manual_review` with `assessment_unresolved` |

The adapter preserves the current failure precedence while the new result keeps
both a failing condition and weak evidence visible.

### Evidence Reference

The assessment stores references and receipt metadata, not duplicate raw provider
payloads:

- evidence ID and evidence type
- source and runtime ID
- source entity type and stable resource URN
- observed, collected, and expiry times
- claim, event, finding, evaluation-run, and graph references
- redaction mode
- content or receipt hash when available
- source coverage dimension and certification tier

An absent required source, an unsupported dimension, an unconfigured source, a
failed source, and a stale source remain different states. None of them can produce
an asserted pass.

### Work Item

`WorkItem` is the durable reviewer queue for an assessment. Required kinds:

- `remediate_finding`
- `collect_evidence`
- `refresh_evidence`
- `resolve_conflict`
- `review_manual_evidence`
- `repair_source`
- `assign_owner`
- `map_control`
- `renew_exception`
- `resolve_policy_gap`

Required states are `open`, `in_progress`, `blocked`, `resolved`, `accepted`, and
`snoozed`. Each item has a stable ID, assessment and control refs, owner, due date,
reason codes, evidence and finding refs, and append-only action history.

Do not create a second exception or finding-workflow model. Work items reference
the existing finding workflow and policy exception records. Acceptance, exception,
and remediation actions continue through their typed approval boundaries.

## Assessment Execution

One assessment job performs these steps:

1. Authorize the tenant and normalize the requested scope.
2. Resolve the profile against exact catalog and extension-pack versions.
3. Capture source runtime, coverage, certification, and freshness state at the
   evidence cutoff.
4. Resolve the required evidence requirements and mapped finding rules for the
   selected controls.
5. Queue existing single-rule evaluation jobs only when the caller requested fresh
   evaluation. Do not add multi-rule behavior to the findings evaluation API.
6. Read findings, evidence, policy lifecycle facts, exceptions, and scope decisions
   through ports, not from transport handlers.
7. Evaluate one canonical `ControlResult` per selected control.
8. Derive work items from unresolved, failing, stale, missing, conflicting, and
   expiring states.
9. Append bounded workflow events and project the assessment into Postgres.
10. Build and hash the immutable packet from the projected results.
11. Mark the assessment `review_required`, `complete`, or `failed` with bounded
    reason codes.

Source runtimes remain the only provider I/O path. An assessment can request a
source-runtime sync job; it cannot call a provider client directly. A source outage
produces a source work item and a limited result, not a false pass and not a global
report failure when unaffected controls can still be evaluated.

## Durability Model

Add these workflow events under `internal/workflowevents`:

- `workflow.v1.compliance.assessment_requested`
- `workflow.v1.compliance.control_evaluated`
- `workflow.v1.compliance.review_recorded`
- `workflow.v1.compliance.work_item_updated`
- `workflow.v1.compliance.assessment_completed`
- `workflow.v1.compliance.assessment_failed`

The `control_evaluated` event contains one bounded control result and evidence IDs,
not raw evidence. Projectors must be idempotent by event ID. A replay must rebuild
the same assessment content hash.

Add Postgres tables through the existing state-store migration mechanism:

- `compliance_assessments`
- `compliance_assessment_controls`
- `compliance_assessment_reviews`
- `compliance_assessment_work_items`
- `compliance_assessment_events`

Store JSON only for bounded versioned details such as reason-code arrays and
reference lists. Put tenant ID and query fields in typed columns. Every primary or
unique key that can collide across tenants includes tenant scope.

Do not persist raw evidence again. Do not read assessments from Neo4j. Optional
graph projection may link an assessment to controls, findings, policies, and
evidence after the Postgres projection is complete.

## API And Transport Contract

Add these resources:

| Operation | Purpose |
| --- | --- |
| `POST /grc/compliance-assessments` | Create an idempotent assessment and queue its platform job. |
| `GET /grc/compliance-assessments` | List assessments by tenant, profile, state, and time. |
| `GET /grc/compliance-assessments/{id}` | Read one assessment summary and immutable scope. |
| `GET /grc/compliance-assessments/{id}/controls` | Read canonical control results with filters. |
| `GET /grc/compliance-assessments/{id}/work-items` | Read the reviewer queue. |
| `POST /grc/compliance-assessments/{id}/reviews` | Record a control review or scope decision. |
| `POST /grc/compliance-assessments/{id}/work-items/{workItemID}/actions` | Assign, block, snooze, accept, or resolve one work item. |
| `GET /grc/compliance-assessments/{id}/packet` | Read the versioned decision and evidence packet. |
| `GET /grc/compliance-assessments/{id}/diff?baseline_id=...` | Compare scope, results, evidence freshness, and work items. |

Create matching message types in `proto/cerebro/v1/compliance.proto` and add RPCs
to `BootstrapService` in the first API PR. JSON HTTP and Connect handlers call the
same `complianceassessment.Service`. Update `api/openapi.yaml` from the same
contract work; do not ship another HTTP-only GRC resource.

Assessment creation requires an idempotency key and a GRC assessment write scope.
Reads use the existing tenant-scoped GRC read authority. Review and work-item writes
derive the actor from the authenticated principal and ignore actor IDs supplied in
the request body.

Compatibility behavior:

- Existing `/grc/control-packets`, `/grc/evidence-packets`, and
  `/grc/program-readiness` responses remain available.
- Add an optional `assessment_id` to those routes so they can render a stable
  completed assessment.
- Without `assessment_id`, keep request-time behavior during the migration window.
- Use one adapter from canonical results to all existing control-status responses.
- Publish a removal criterion before changing the default to the latest completed
  assessment.

## Delivery Sequence

Each phase is a separate PR. Do not combine a contract change, a storage migration,
and route migration unless the earlier phase has already landed. Generated outputs
are updated only through their repository targets.

### Phase 0: Freeze Semantics With Golden Cases

Files:

- add `internal/complianceassessment/types.go`
- add `internal/complianceassessment/evaluate.go`
- add `internal/complianceassessment/legacy_status.go`
- add `internal/complianceassessment/testdata/*.json`
- add `internal/complianceassessment/*_test.go`

Tasks:

- Define `Assessment`, `ControlResult`, evidence reference, assurance basis, and
  work-item types.
- Implement the four-axis result and the legacy-status adapter.
- Reuse `compliance.AssessControlEvidenceRequirements`; do not copy its matching
  rules.
- Add golden cases for pass, active finding, missing evidence, missing required
  fields, stale evidence, conflicting observations, untrusted source, manual
  evidence, active exception, not applicable, partial coverage, and no configured
  source.
- Prove deterministic ordering and hashes with shuffled input.

Exit criteria:

- Every golden case has exact reason codes and next actions.
- A pass is impossible when required coverage or evidence is unresolved.
- The compatibility adapter matches current status precedence.

Validation:

```bash
go test ./internal/compliance ./internal/complianceassessment -count=1
```

### Phase 1: Add Durable Assessment Runs

Files:

- add `internal/ports/compliance_assessments.go`
- add `internal/statestore/postgres/compliance_assessments.go`
- add `internal/statestore/postgres/compliance_assessments_test.go`
- add compliance event models and codecs under `internal/workflowevents`
- add the Postgres assessment projector under `internal/complianceassessment`
- add `KindComplianceAssessment` to `internal/jobs/service.go`
- register the runner in `internal/bootstrap/jobs.go`

Tasks:

- Implement tenant-scoped create, get, list, result, review, work-item, and event
  store methods.
- Append `assessment_requested` before the job starts.
- Append one `control_evaluated` event per control, then a terminal event.
- Make event projection idempotent and safe to replay after partial failure.
- Use the platform job ID as the execution reference; do not add a second job
  scheduler.
- Keep failed runs readable with completed control results and a bounded failure
  code.

Exit criteria:

- Replaying the event sequence into an empty Postgres projection produces the same
  assessment and content hash.
- A duplicate create with the same tenant and idempotency key returns the original
  assessment and job.
- A foreign tenant cannot read, update, or infer an assessment ID.

Validation:

```bash
go test ./internal/complianceassessment ./internal/workflowevents ./internal/statestore/postgres ./internal/jobs -count=1
```

### Phase 2: Integrate Source Trust And Evaluation

Files:

- update `internal/complianceassessment/evaluate.go`
- add `internal/complianceassessment/collector.go`
- update source coverage adapters under `internal/sourcecoverage`
- update the compliance assessment job runner in `internal/bootstrap/jobs.go`

Tasks:

- Resolve selected controls to evidence requirements and single-rule evaluation
  requests.
- Capture source runtime health, coverage dimensions, freshness, known unsupported
  fields, and certification tier.
- Default an absent certification value to `unknown`; never silently promote it.
- Detect contradictory current observations for the same requirement and route
  them to review.
- Allow unaffected controls to finish when one source is unavailable.
- Emit source repair or evidence collection work items instead of generic errors.

This phase consumes the source coverage and certification contracts tracked in
#899 and #1725. If certification has not landed, keep the adapter value `unknown`
and cap assurance below `high`.

Exit criteria:

- The supported, partial, stale, failed, unconfigured, unsupported, and unverified
  source states produce different result reason codes.
- Fresh evidence from a lower source tier remains visible but cannot satisfy a
  higher configured minimum tier.
- Assessment execution does not call provider clients outside source runtimes.

Validation:

```bash
go test ./internal/complianceassessment ./internal/sourcecoverage ./internal/bootstrap -count=1
make catalog-check
```

### Phase 3: Ship Typed APIs And Compatibility Adapters

Files:

- add `proto/cerebro/v1/compliance.proto`
- update `proto/cerebro/v1/bootstrap.proto`
- update `api/openapi.yaml`
- add `internal/bootstrap/compliance_assessments.go`
- update HTTP and Connect authorization policy files
- update `internal/grccontrol`, `internal/grcprogram`, and `internal/evidencepackets`
  through adapters only

Tasks:

- Implement create, list, get, control-result, and packet reads in both JSON HTTP
  and Connect.
- Add tenant, idempotency, pagination, and bounded-filter tests.
- Add `assessment_id` support to the existing control packet, evidence packet, and
  readiness routes.
- Keep the old response shapes byte-compatible for existing fields.
- Add generated contract drift tests before hand-written handler tests.

Exit criteria:

- HTTP and Connect return the same semantic assessment for the same principal and
  scope.
- Existing routes render the same legacy status from the shared adapter.
- No transport handler contains evidence matching or control precedence logic.

Validation:

```bash
make contracts-check
go test ./internal/bootstrap ./internal/grccontrol ./internal/grcprogram ./internal/evidencepackets -count=1
make docs-drift-check
```

### Phase 4: Make Reviews And Work Items Operational

Files:

- add `internal/complianceassessment/reviews.go`
- add `internal/complianceassessment/work_items.go`
- add review and work-item event projection
- add the review and work-item action handlers to JSON HTTP and Connect
- integrate references from `internal/grcpolicylifecycle` and finding workflow

Tasks:

- Support assign, block, snooze, accept, resolve, not-applicable, and evidence-review
  actions with explicit allowed state transitions.
- Require owner, rationale, expiry, and evidence links for accepted risk or an
  exception.
- Reopen work when an exception expires, evidence becomes stale, a finding reopens,
  or the source scope changes.
- Preserve the original automated result beside the reviewer decision.
- Reference existing policy exceptions and finding workflow events rather than
  storing copies.

This phase should align with the remediation lifecycle in #898.

Exit criteria:

- Every state change is append-only, actor-attributed, tenant-scoped, and replayable.
- Review history explains why the effective result differs from the automated
  result.
- Expired exceptions and superseded evidence create concrete open work.

Validation:

```bash
go test ./internal/complianceassessment ./internal/grcpolicylifecycle ./internal/workflowevents ./internal/bootstrap -count=1
```

### Phase 5: Deliver Reproducible Packets And Diffs

Files:

- refactor `internal/evidencepackets/packets.go` to accept a completed assessment
- add `internal/complianceassessment/diff.go`
- add packet and diff routes to HTTP, Connect, CLI, and the bounded MCP task surface

Tasks:

- Build packets only from the immutable assessment cutoff and projected results.
- Include supporting and contradicting evidence, source gaps, policies, controls,
  work items, approval requirements, provenance, and receipt IDs.
- Make packet JSON deterministic and verify its content hash on read.
- Diff control scope, outcome, evidence state, assurance, source health, exceptions,
  and work items against a completed baseline.
- Record `packet_delivered` with assessment ID, packet version, and redaction mode;
  do not record packet contents in telemetry.

Use the shared decision-packet contract from #1726 rather than inventing a
compliance-only envelope.

Exit criteria:

- Repeated reads of one completed assessment return the same snapshot ID and hash.
- Golden packets cover supported, partial, stale, conflicting, unauthorized, and
  no-evidence cases.
- A diff identifies both newly failing controls and assurance degradation without a
  control outcome change.

Validation:

```bash
go test ./internal/complianceassessment ./internal/evidencepackets ./internal/bootstrap -count=1
make contracts-check
```

### Phase 6: Schedule, Observe, And Retire Duplicate Logic

Tasks:

- Add a compliance assessment schedule kind to the existing durable scheduling
  subsystem. Generalize the schedule contract in a separate PR; do not create a
  second polling loop.
- Emit bounded events for assessment requested, completed, review required, packet
  delivered, and work item resolved.
- Measure assessment completion, fresh-evidence rate, explicit coverage-gap rate,
  evidence reuse, time to review, and time to resolve.
- Compare request-time and durable results in shadow mode before changing existing
  route defaults.
- Remove duplicate status calculation only after parity fixtures and caller
  inventory are complete.

Metrics and event names should follow #1721. Scheduling must use platform jobs and
the repository's existing lease and cancellation behavior.

Exit criteria:

- A scheduled run cannot overlap itself for the same tenant and scope.
- Failed and cancelled runs remain inspectable and retryable.
- Existing routes use canonical assessment results by default only after parity is
  demonstrated and the compatibility window is documented.
- `grccontrol`, `grcprogram`, and `evidencepackets` no longer calculate independent
  control precedence.

Validation:

```bash
go test ./internal/complianceassessment ./internal/jobs ./internal/bootstrap ./internal/statestore/postgres -count=1
make verify
```

## Implementation Rules For Follow-On Agents

- Implement one phase per PR and copy that phase's exit criteria into the PR body.
- Start each PR from current `main`; do not build later phases on an unmerged branch.
- Read `docs/engineering/non-goals.md` before changing storage, workflow, findings,
  graph, or action behavior.
- Reuse `internal/compliance` evaluation primitives. A second evidence matcher or
  status precedence function is a review blocker.
- Keep provider I/O in source runtimes and long-running work in platform jobs.
- Append workflow events before projecting mutable review or work-item state.
- Keep Neo4j optional for assessment reads and rebuildable from durable records.
- Add a regression test for every tenant boundary, idempotency rule, state
  transition, and compatibility mapping changed by the phase.
- Run `make contracts-check` for proto or OpenAPI changes, `make docs-drift-check`
  for generated docs, and `make oss-audit` for public examples or fixtures.
- Do not hand-edit generated catalogs, contract outputs, or mapping CSVs.

## Completion Criteria

The overhaul is complete when:

- a caller can create, poll, review, diff, and export a tenant-scoped assessment by
  stable ID through JSON HTTP and Connect
- every control result separates scope, outcome, evidence state, and assurance
- missing coverage and source trust limitations prevent unsupported pass claims
- assessment events replay into the same Postgres state and content hash
- work items have owners, due dates, state transitions, and links to existing
  findings, policies, exceptions, and evidence
- one immutable packet carries evidence, contradictions, gaps, approvals,
  provenance, and redaction state
- existing GRC routes use the shared compatibility adapter with no independent
  status logic
- scheduled assessments use platform jobs and the existing scheduler instead of a
  new polling subsystem
- outcome telemetry can report completed assessments, packet delivery, review time,
  evidence freshness, coverage gaps, and resolution time without storing sensitive
  evidence values

## Non-Goals

- No end-user web UI in this repository.
- No new control catalog or raw evidence store.
- No direct provider calls from the assessment service.
- No direct Neo4j writes or graph-authoritative assessment reads.
- No multi-rule findings evaluation request.
- No full workflow engine or autonomous remediation.
- No pass inferred from an empty finding set when coverage or evidence is missing.
- No breaking removal of existing GRC response fields during the migration window.
