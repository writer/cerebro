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

## Product Contract

The product outcome is not "controls mapped" or "tests run." The outcome is a
trusted decision completed with enough evidence, scope, ownership, and history for
another reviewer to reproduce it.

A complete compliance operation moves through this chain:

```text
program scope
  -> applicable requirements
  -> scope-specific control implementations
  -> test and evidence requirements
  -> observations and evidence claims
  -> control-objective results
  -> findings, risks, and exceptions
  -> owned remediation
  -> assessment and audit snapshot
```

The first release should make the chain work for one program, one reusable
assessment plan, one completed assessment run, and one exportable packet. Later
releases should add continuous triggers, audit collaboration, and reuse across
policy, access-review, vendor, and questionnaire workflows. Each later workflow
must consume the same control, evidence, assessment, and work-item records instead
of creating a parallel readiness model.

The primary operating measure is completed evidence-backed decisions. Supporting
measures are:

- time from program creation to first trusted assessment
- percentage of in-scope control objectives with sufficient current evidence
- percentage of results with explicit source or coverage limitations
- percentage of evidence claims safely reused across compatible controls and
  periods
- time from a failed result to an owner, remediation plan, and verified closure
- percentage of exceptions reviewed or closed before expiry
- time from an audit request to accepted evidence
- percentage of questionnaire answers supported by approved current citations
- assessment queue time, collection-error rate, and cost per completed assessment

Connector count, framework count, evidence count, and finding count remain input
measures. They are not substitutes for a completed decision.

## User Jobs The Contracts Must Support

The repository does not ship the end-user interface, but its APIs must support
these jobs without forcing a client to reconstruct domain logic.

| Actor and question | Required result |
| --- | --- |
| Program owner: "What applies before I create work?" | A versioned program scope with systems, products, regions, data, people, vendors, requirements, parameter values, applicability decisions, reasons, approvers, and effective dates. |
| Control owner: "Why is this control healthy or blocked?" | One explanation that shows implementation status, test runs, evidence claims, collection errors, open findings, policy state, risks, exceptions, overdue work, and the exact reason for the effective result. |
| Evidence owner: "Can I reuse this artifact here?" | A compatibility decision based on control objective, implementation, subject scope, covered population, period, source, freshness, reviewer decision, and direct or inherited linkage. |
| Security or platform owner: "What changed and what should I fix?" | Newly failed or degraded results, affected assets and identities, source changes, evidence invalidations, prioritized work, a safe proposed action, and a required verification step. |
| Risk owner: "Can this gap be accepted temporarily?" | A risk decision with business justification, affected scope, compensating controls, approver, expiry, review date, and automatic reopen behavior. |
| Access reviewer: "Did we remove the access we rejected?" | A frozen review population, per-account decision, reviewer and justification, remediation task, and separate proof that the requested change completed. |
| Vendor owner: "Can this vendor be approved and kept under review?" | Intake scope, service and data use, inherent risk, assessment requirements, questionnaire and evidence state, findings, decision, renewal date, monitoring signals, and offboarding work. |
| Policy owner: "Which policy changes affect readiness?" | Version diff, affected controls and people, approval state, required reacceptance, evidence invalidations, exceptions, and review work. |
| Questionnaire owner: "Which answers are safe to send?" | Draft answers from approved sources with exact citations, scope, freshness, conflicts, unsupported claims, owner, reviewer, and approver state. |
| Auditor: "Show only the evidence for this scope and period." | A read-scoped engagement, request list, population and sample records, messages, submitted and accepted evidence, immutable package, manifest, and checksums. |
| Leadership: "What is blocking the program?" | Trend and delta views over material failed controls, weak assurance, missing owners, overdue work, expiring exceptions, source blind spots, and audit-request progress. |
| Operator: "Can I recover or reproduce this run?" | Job and event history, exact versions and inputs, bounded failure code, replay or retry operation, immutable completed snapshot, and packet-hash verification. |

## Existing Assets To Reuse

The implementation should assemble the existing platform rather than replace it.

| Existing asset | Reuse in the target model | Do not duplicate |
| --- | --- | --- |
| `internal/compliance` | Catalogs, profiles, selections, control mappings, evidence requirements, readiness metadata, and pure evaluation helpers. | Catalog parsing, evidence matching, control mapping, or status precedence. |
| `internal/findings` and finding evaluation runs | Durable remediable states, rule metadata, evidence links, lifecycle, multi-rule orchestration, and single-rule evaluation lineage. | A second finding engine or parallel evaluation protocol. |
| `FindingEvidenceStore`, EvidenceCAS references, and `internal/grcupload` | Existing evidence IDs, content-addressed references, uploaded document facts, parser quality, and provenance. | Raw artifact bytes in an assessment table or arbitrary attachments in findings. |
| `internal/sourcecoverage`, source health, and connector catalog contracts | Supported dimensions, blind spots, runtime freshness, collection state, and source proof. | A compliance-only connector registry. |
| `internal/jobs` and report schedule claiming | Queued work, cancellation, job events, and recurring execution; harden these paths with leases and recovery before scheduled assessment use. | A compliance goroutine, polling loop, or second job state machine. |
| `internal/workflowevents` and projections | Append-first decisions, replay, actor history, and optional graph links. | Direct graph writes or mutable state without an event. |
| `internal/grcpolicylifecycle` | Policy versions, approvals, attestations, reviews, exceptions, documents, risk-register links, and lifecycle actions. | Another policy, approval, or exception model. |
| `internal/questionnaire` | Durable questionnaire runs, assignments, comments, citations, review decisions, vendor links, and graph projection. | A second questionnaire workflow in the assessment service. |
| `internal/grcvendor` | Vendor inventory, ownership, review, questionnaire, monitoring, exposure, remediation, and offboarding posture. | A second vendor inventory. |
| `internal/grcinventory` and `internal/resourcescope` | Asset surface, scope decisions, accountability, exclusions, and resource identity. | Free-form assessment subjects that cannot map to a tenant-scoped resource. |
| `internal/evidencepackets` | Packet, lineage, questionnaire, access-evidence, export, and manifest shaping after canonical results exist. | Independent recalculation of control state. |
| `internal/grcprogram` and `internal/grccontrol` | Compatibility responses during migration. | Long-term ownership of separate control-result types. |

## Capability Boundaries

The target is a compliance operating model with explicit layers:

1. **Control layer** — versioned catalogs, requirements, parameters, mappings, and
   tailored profiles.
2. **Implementation layer** — systems, components, policies, processes, owners,
   responsibility, inheritance, and descriptions of how each statement is
   satisfied.
3. **Assessment layer** — reusable plans, objectives, methods, tasks, populations,
   samples, activities, observations, results, findings, and risks.
4. **Remediation layer** — exceptions, risk responses, milestones, work items,
   approvals, retests, and verified closure.
5. **Audit and assurance layer** — engagements, evidence requests, messages,
   sampling, recipient access, immutable packages, questionnaire answers, and
   disclosure history.

These layers share stable identifiers and references, but they do not share one
overloaded status. A policy can be published while its control still lacks
operating evidence. A test can error while the last approved evidence remains
current. An auditor can reject an evidence submission without changing the
underlying automated observation. The contract keeps those facts separate and
derives the current program view from them.

## Target Package Boundaries

The center is a small set of cooperating domain services, not one package that
absorbs the entire GRC surface.

```text
catalog revisions + tailored profiles
                   |
                   v
       grcprogram: scope + implementations
                   |
                   v
  complianceassessment: plan + run + objective results
        |                   |                    |
        v                   v                    v
 evidenceledger       findings / risks       work items
        |                   |                    |
        +-------------------+--------------------+
                            v
               grcaudit: requests + samples
                            |
                +-----------+-----------+
                v           v           v
          packet/diff   exchange     task APIs
```

Responsibilities:

- `internal/compliance` remains the pure catalog, profile resolution, mapping,
  evidence-requirement, readiness-metadata, and evaluation library.
- `internal/grcprogram` gains durable program revisions, scope versions, system and
  component references, control implementations, control parameters, responsibility
  assignments, and applicability decisions. Its current readiness builder becomes a
  compatibility view.
- `internal/evidenceledger` owns evidence artifact metadata, immutable versions,
  claims about what an artifact proves, validation and review state, reuse
  compatibility, invalidation, and lineage. It stores EvidenceCAS or external
  references, not artifact bytes.
- `internal/complianceassessment` owns reusable assessment plans, immutable
  automated runs, activities, observations, objective results, human review
  revisions, diffs, and assessment work-item derivation.
- `internal/grcaudit` owns audit engagements, evidence requests, populations,
  samples, messages, submissions, recipient access, acceptance decisions, delivery
  receipts, and package manifests.
- `internal/complianceexchange` owns portable JSON, YAML, CSV, and package adapters,
  layered validation, extension handling, and round-trip tests. Internal services do
  not depend on an exchange schema.
- `internal/evidencepackets` renders a versioned packet from an exact assessment
  revision or audit package. It does not independently recalculate control state.
- `internal/grccontrol` remains a compatibility adapter. It is not the owner of a
  fifth control-result model.
- `internal/grcpolicylifecycle`, `internal/questionnaire`, `internal/grcvendor`,
  `internal/grcinventory`, and finding workflow remain owners of their records and
  expose typed references into program, assessment, work, and audit services.
- `internal/bootstrap` authorizes, decodes, paginates, and maps transports. It does
  not collect unbounded assessment inputs or decide control status.

### Truth And Storage Hierarchy

| Layer | Authority |
| --- | --- |
| Versioned catalog and exchange artifacts | Definitions, profile resolution inputs, mappings, and imported implementation content. |
| Source runtimes and existing stores | Provider observations, current findings, finding evidence, policies, questionnaires, vendors, inventory, and workflow-owned records. |
| JetStream workflow events | Log of record for program decisions, assessment lifecycle, reviews, audit requests, and work-item transitions. |
| Postgres | Tenant-scoped current-state projections, immutable revisions, collection receipts, and query indexes. |
| EvidenceCAS or external artifact system | Raw evidence bytes and content-addressed objects. Assessment tables store references and digests only. |
| Neo4j | Optional rebuildable relationship and impact-analysis projection. It is never required to read an assessment or audit package. |
| Packet and exchange artifacts | Immutable outputs derived from exact revisions and redaction policies. They are not mutable state stores. |

Every mutable resource uses append-first workflow events and a Postgres projection.
Every completed run, review revision, and delivered packet is immutable. Mutable
work-item projections can point to immutable assessment occurrences but cannot
change historical result or packet hashes.

## Canonical Contracts

### Version And Identity Rules

Every versioned subject has two identities:

- a stable logical ID that follows the same program, control implementation,
  evidence artifact, plan, or audit engagement over time
- an immutable revision ID with `version`, `last_modified`, `content_digest`,
  `created_by`, and predecessor or successor references

Completed assessment runs never change revisions. Updated framework content,
profiles, mappings, implementations, evidence, plans, reviewer decisions, or
redaction policies create new revisions or artifacts.

An assessment `InputManifest` pins all semantic inputs, not only the catalog
version:

- resolved control and objective set hash
- catalog, profile, parameter, and extension-pack IDs, revisions, and hashes
- mapping set and mapping-review revision
- evidence requirement and evaluator revisions
- control implementation and system-boundary revisions
- test definitions, rule IDs, rule revisions, and parameters
- source runtime, coverage-contract, connector, collector, and source-proof
  revisions
- policy, exception, applicability, and risk-decision revisions used by the run
- requested scope, evidence period, collection cutoff, and included evaluation-run
  IDs
- packet schema, reason-code registry, and compatibility-adapter versions

The initial implementation supports built-in profiles only unless a tenant-scoped
extension registry with immutable versions and hashes lands first. An assessment
request must never reference an arbitrary server filesystem path.

### Compliance Program And Scope Revision

`ComplianceProgram` is the durable unit that says what an organization is trying
to operate and assess. It includes:

- tenant-scoped stable ID, name, owner team, risk owner, and status
- selected framework/profile revisions and resolved baseline hash
- system, product, business unit, region, environment, data, people, asset,
  application, and vendor scope selectors
- scope inclusions and exclusions with source, reason, approver, effective period,
  review date, and superseding decision
- organization-defined control parameter values and rationale
- expected assessment periods, evidence windows, monitoring cadence, and source
  proof policy
- materiality and risk thresholds that drive assessment depth, sampling, and
  escalation

`ScopeRevision` is immutable after activation. A framework, boundary, parameter, or
applicability change creates a new revision and an impact-analysis request. Scope
suggestions remain proposed until an authorized actor records the decision.

### Control Implementation

`ControlImplementation` explains how one scoped program satisfies a control or
control statement. It is distinct from the catalog definition and from proof that
the implementation operated.

Required fields:

- stable implementation ID and immutable revision
- program, scope revision, framework, control, statement, and objective refs
- implementation status: `planned`, `partial`, `implemented`, `alternative`,
  `not_applicable`, or `retired`
- design narrative, procedure, responsible and accountable roles, owner team,
  review cadence, and effective period
- component, system, asset, identity, policy, process, service, vendor, and data refs
- control parameter values actually implemented
- responsibility type: `direct`, `provided`, `customer_responsibility`, `shared`, or
  `inherited`
- upstream implementation or external system ref for inherited or shared controls
- expected tests, evidence requirements, source dimensions, risks, and exceptions
- material-change criteria and invalidation rules

One implementation may map to multiple framework requirements, but mapping is an
explicit record with source and target revisions, granularity, relationship
(`equivalent`, `subset`, `superset`, `overlap`, or `none`), method, rationale,
coverage estimate, gaps, author, reviewer, and decision state. A mapping does not
silently grant full coverage.

### Assessment Plan

`AssessmentPlan` is a reusable, approved execution blueprint. It contains:

- stable plan ID and immutable revision
- imported program scope and control-implementation revisions
- planned controls, statements, objectives, and explicit exclusions
- assessment methods: `examine`, `interview`, and `test`
- required evidence objects, collection queries, manual procedures, interview
  subjects, and expected outputs
- assessment subjects: systems, components, inventory items, locations, users,
  groups, services, vendors, and populations
- depth, coverage, sample method, sample size rule, tolerance, and assurance target
- assessor roles, independence requirements, tools, tool versions, and platforms
- ordered tasks, dependencies, start/end windows, recurring frequency, triggers,
  milestones, and cancellation behavior
- rules of engagement, assumptions, limitations, disclosure terms, and methodology
- owner and assessor approval records

A plan is publishable only after validation and required approvals. A plan revision
does not alter runs created from an earlier revision.

### Assessment Run And Review Revision

`AssessmentRun` is the immutable automated execution of one plan revision.

| Field | Requirement |
| --- | --- |
| `id` | Tenant-scoped stable run ID. |
| `program_id`, `scope_revision_id`, `plan_revision_id` | Exact operating context. |
| `state` | `queued`, `collecting`, `evaluating`, `review_required`, `complete`, `failed`, `cancelled`, or `superseded`. |
| `period_start`, `period_end` | Period whose operating effectiveness is being assessed. |
| `requested_at` | Time the run was requested. |
| `collection_barrier_at` | Time fresh sync and evaluation work completed or was declared unavailable. |
| `collection_cutoff` | Final cutoff applied after the barrier. |
| `job_id`, `attempt`, `lease_owner`, `heartbeat_at` | Recoverable execution state. |
| `baseline_run_id` | Optional completed run used for a diff. |
| `input_manifest` and `input_hash` | Immutable normalized inputs and receipts. |
| `automated_result_hash` | Hash of ordered automated results and observations. |
| `failure_code` | Bounded machine-readable failure reason. Internal errors stay private. |

`AssessmentReviewRevision` records human decisions without mutating the automated
run. It has `revision_id`, `parent_revision_id`, `aggregate_version`, reviewer,
review decisions, effective results, `revision_hash`, and created time. Concurrent
writes require `expected_version` or `If-Match`; stale writes return conflict.

Packet artifacts point to an exact review revision and redaction policy. Live work
items point to assessment occurrences but are excluded from the immutable revision
hash. Use distinct `input_hash`, `automated_result_hash`, `revision_hash`, and
`artifact_hash` values.

### Assessment Activity, Population, And Sample

`AssessmentActivity` records what was actually performed, not only what was
planned:

- plan task and objective refs
- method, tool or interviewer, configuration, start/end time, and actor
- included and excluded subjects
- execution status and bounded error code
- observations and evidence refs

`PopulationSnapshot` records the full set from which evidence is selected. It
includes query or source receipt, expected and observed counts, completeness state,
period, subject IDs or page receipts, deduplication rules, and content hash.

`SampleSelection` records method, seed where deterministic, requested size, selected
subject refs, replacements, exclusions, rationale, selector, reviewer, and hash.
Uploading one example cannot satisfy a population-based procedure unless the plan
explicitly permits illustrative evidence.

### Test Definition And Test Run

Automated and manual tests share one contract without sharing one execution engine.

`TestDefinition` includes:

- stable ID and revision
- control implementation, statement, and objective refs
- method and mode: `automated`, `manual`, or `hybrid`
- rule, query, procedure, interview guide, or script ref and parameters
- required sources, fields, expected population, frequency, triggers, grace period,
  and maximum evidence age
- pass, fail, inconclusive, exclusion, and not-applicable criteria
- owner, escalation route, and supported collector versions

`TestRun` keeps execution state separate from conclusion:

| Axis | Values |
| --- | --- |
| `execution_state` | `queued`, `running`, `succeeded`, `error`, `cancelled`, `skipped` |
| `result` | `pass`, `fail`, `inconclusive`, `not_applicable`, `not_assessed` |
| `coverage_state` | `complete`, `partial`, `empty`, `unknown` |

Collection errors, disabled tests, unsupported fields, and skipped non-production
subjects never become a pass or fail. Existing finding-rule orchestration is reused
while preserving one persisted evaluation run per rule.

### Observation, Finding, And Risk

Keep three separate records:

- `Observation` is a raw fact from an examine, interview, or test activity. It has
  origin, subject, evidence, collection time, validity period, and result data.
- `Finding` is the assessor or rules-engine conclusion against a statement or
  objective. It references observations and existing durable finding records where
  a remediable condition exists.
- `Risk` is the consequence to the scoped program or system. It has likelihood,
  impact, severity, business context, mitigating factors, owner, deadline,
  treatment, and history.

Risk responses support `avoid`, `mitigate`, `transfer`, `accept`, `share`,
`contingency`, and `none`. Recommended, planned, and completed responses are
separate. Closure requires verification evidence. Accepted risks and deviations
require owner, justification, compensating controls, approval, expiry, and automatic
reopen rules.

### Control Objective Result

Compute results at control-objective or statement granularity, then aggregate them
to a control. Do not infer a passing control from an empty finding set.

| Axis | Values | Question answered |
| --- | --- | --- |
| `scope_state` | `in_scope`, `not_applicable`, `unresolved` | Should this objective be assessed? |
| `automated_outcome` | `satisfied`, `not_satisfied`, `indeterminate`, `not_assessed` | What did current assessment activity conclude? |
| `design_state` | `effective`, `ineffective`, `unknown`, `not_assessed` | Is the implementation designed to satisfy the objective? |
| `operating_effectiveness_state` | `effective`, `ineffective`, `unknown`, `not_tested` | Did it operate over the assessment period? |
| `evidence_state` | `sufficient`, `missing`, `stale`, `conflicting`, `untrusted`, `incomplete`, `manual_review` | Can the proof support the conclusion? |
| `disposition_state` | `none`, `accepted_exception`, `accepted_risk`, `review_override` | Has an authorized human disposition changed treatment of the result? |
| `assurance` | `high`, `medium`, `low`, `none` | How strong is the deterministic basis? |
| `auditor_state` | `not_reviewed`, `accepted`, `changes_requested`, `rejected` | What did the engagement reviewer decide about submitted evidence? |

Each result carries exact test runs, population and sample refs, observations,
evidence claims, findings, risks, policies, exceptions, source coverage and proof,
reason codes, next actions, evaluator revision, and timestamps.

Assurance is derived from visible basis facts: source authentication, collection
success, scope and population completeness, period coverage, artifact integrity,
freshness, reviewer approval, conflicts, assessor independence, and supported
collector version. It is not a model-generated score.

Existing status fields remain compatible through one shared adapter:

| New result | Existing status |
| --- | --- |
| `scope_state=not_applicable` | `not_applicable` |
| active accepted exception or risk | `exception` |
| `automated_outcome=not_satisfied` | `failing` |
| `evidence_state=missing` or `incomplete` | `missing_evidence` |
| `evidence_state=stale` | `stale_evidence` |
| `evidence_state=manual_review`, `conflicting`, or `untrusted` | `manual_review` with a reason code |
| `automated_outcome=satisfied` and `evidence_state=sufficient` | `passing` |
| any unresolved combination | `manual_review` with `assessment_unresolved` |

The adapter preserves current precedence while the canonical result retains the
automated outcome beside any disposition, evidence limitation, or auditor decision.

### Evidence Ledger

Separate the artifact from the claim that the artifact proves something.

`EvidenceArtifact` is a stable logical record. `EvidenceVersion` is immutable and
contains:

- title, description, type, media type, publication version, publication date, and
  producer
- EvidenceCAS or package-relative URI, content digest, size, and derivation chain
- source, runtime, connector, collector, tool, tool version, configuration hash,
  source event, and idempotency refs
- collection, observation, period start/end, validity, renewal, and expiry times
- subject, component, asset, identity, vendor, policy, finding, claim, event, graph,
  and evaluation-run refs
- sensitivity, access policy, retention, legal-hold, redaction, parser quality, and
  quarantine state
- superseded, revoked, or deleted-content tombstone refs

`EvidenceClaim` states what one evidence version supports:

- control implementation, statement, objective, policy, risk, questionnaire answer,
  access-review decision, vendor assessment, or audit-request ref
- subject scope, covered period, population, sample, and extraction method
- linkage type: `direct`, `inherited`, or `inferred`
- claim strength, limitation, mapping rationale, and overclaim guard
- reviewer, review result, review time, invalidation reason, and invalidation time

Reuse is allowed only when objective, implementation, subject scope, covered period,
population, source proof, and review policy are compatible. Approximate mappings,
scope drift, period gaps, source degradation, superseded versions, or changed test
definitions require review. Invalidation propagates to every dependent result,
packet, audit request, and questionnaire answer without rewriting historical
snapshots.

Evidence states are `collected`, `validation_failed`, `under_review`, `approved`,
`stale`, `superseded`, and `revoked`. Untrusted uploaded content remains quarantined
and cannot support a passing result or enter an AI context until validation policy
allows it.

### Work Item And Remediation Milestone

`WorkItem` is the durable operating queue. Required kinds include:

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
- `complete_access_change`
- `answer_audit_request`
- `review_vendor`

States are `open`, `in_progress`, `blocked`, `resolved`, `accepted`, `snoozed`, and
`superseded`. Each item has owner team and optional user, due date, SLA class,
priority, blocker reason, external ticket refs, evidence and finding refs, and
append-only action history.

The stable work fingerprint uses tenant, program and scope, control or objective,
kind, and affected subject. Each assessment creates an occurrence against that
fingerprint. A recurring run carries forward, reopens, or supersedes work instead
of creating a duplicate task.

`RemediationPlan` records risk response, milestones, target dates, owners, planned
and completed actions, compensating controls, retest requirement, and verification
evidence. Do not create a second exception or finding lifecycle; work items and
remediation plans reference the current owning record.

### Audit Engagement And Evidence Request

`AuditEngagement` has stable identity, immutable scope and period revisions,
framework and plan refs, assigned auditors, client owners, disclosure policy, and
states `planning`, `fieldwork`, `clarification`, `complete`, and `closed`.

`AuditRequest` has requirement and control refs, requested period, expected format,
population and sample refs, owner, due date, messages, evidence submissions, and
states `open`, `in_progress`, `submitted`, `changes_requested`, `accepted`,
`rejected`, `withdrawn`, and `closed`.

An auditor receives a read-focused principal scoped to one engagement. Evidence
access is purpose- and period-bounded, records every access and delivery, and expires
without granting general tenant access. Sampling freezes a population snapshot and
selected subjects. New live evidence does not enter an existing package unless the
sample or package revision is explicitly replaced.

### Portable Package And Validation Result

A delivered package contains:

- `manifest.json` with logical type, schema versions, stable IDs, revision IDs,
  artifact paths, redaction mode, and digests
- resolved control and mapping records
- program scope and control-implementation revisions
- assessment plan, activities, observations, objective results, findings, risks,
  reviews, and remediation records
- evidence index, package-relative evidence resources, and checksums
- approvals, exceptions, audit requests, samples, and delivery receipts
- optional signature metadata and predecessor-manifest digest
- a human-readable index generated from the same manifest

Validation is layered: parse, schema, referential integrity, business rules,
temporal and role separation, package paths and digests, signature verification,
and semantic round-trip checks. Every validation issue has rule ID, severity,
artifact revision, document path, message, remediation, validator version, and rule
set version.

## Assessment Execution

One assessment job performs these steps:

1. Authorize the principal, tenant, program, scope revision, and plan revision.
2. Normalize the request and persist its hash with route, method, principal,
   idempotency key, and requested freshness behavior.
3. Resolve exact catalog, profile, mapping, implementation, evidence-requirement,
   test-definition, reason-code, and evaluator revisions.
4. Create the immutable planned control/objective set and refuse an unbounded or
   unresolved selection.
5. If fresh collection is requested, enqueue source sync and existing finding-rule
   orchestration with one persisted evaluation run per rule. Record every successful,
   failed, cancelled, and skipped child job.
6. Establish a collection barrier only after the required child jobs reach a
   terminal state or the plan's partial-source policy decides they are unavailable.
7. Set `collection_cutoff` after the barrier. Never declare the cutoff before
   running the work whose output must be included.
8. Scan runtimes, evaluation runs, findings, evidence, source coverage, policy
   facts, exceptions, scope decisions, and other required inputs through
   assessment-specific cursor ports.
9. Persist normalized immutable input receipts, page hashes, observed totals,
   completeness state, and selected record revisions. Do not depend on later reads
   of mutable current-state finding or evidence rows.
10. Build populations and samples, then perform planned examine, interview, and test
    activities.
11. Create observations, objective results, findings, risks, and evidence claims.
12. Derive or update stable cross-run work items and remediation milestones.
13. Append bounded result chunks plus a manifest, project the run into Postgres, and
    verify projected counts and hashes against the manifest.
14. Build the automated result hash. If review is required, create review revision
    zero without changing the automated run.
15. Mark the run `review_required`, `complete`, `failed`, or `cancelled` with bounded
    reason codes and child-job references.
16. Generate packets or audit packages as separate jobs for an exact review revision
    and redaction policy.

### Complete-Input Guarantee

Assessment execution must not use `grcListFindingRecords`,
`grcListEvidenceRecords`, `grcListRuntimes`, or any transport helper intended for a
100- or 500-row screen. Add deterministic keyset or cursor pagination for every
assessment input. The collection manifest records:

- query and filter hash
- cursor sequence and per-page receipt hash
- expected total when available
- observed raw, deduplicated, included, and excluded totals
- first and last stable sort keys
- source and store revision or watermark
- collection cutoff
- completeness: `complete`, `partial`, `truncated`, `changed_during_scan`, or
  `unknown`

`truncated`, `changed_during_scan`, or `unknown` input cannot yield a passing
objective. A plan may allow unaffected objectives to finish when one source is
unavailable, but it must emit a coverage limitation and source work item. The run
fails with `collection_incomplete` when missing inputs prevent the promised scope
from being represented honestly.

### Source And Job Boundaries

Source runtimes remain the only provider I/O path. An assessment runner can enqueue
a source-runtime sync; it cannot call a provider client. The runner checks
cancellation between pages and activities, heartbeats its lease, and can resume from
persisted collection receipts after process loss.

The existing job service must gain claim leases, heartbeats, stale-running recovery,
attempt metadata, startup recovery for queued work, and idempotent schedule delivery
before scheduled assessments are called durable execution. Until then, only the
assessment record and projected results are durable.

## Durability Model

Add event families under `internal/workflowevents` as their owning phases land:

- `workflow.v1.compliance.program_scope_recorded`
- `workflow.v1.compliance.control_implementation_recorded`
- `workflow.v1.compliance.evidence_claim_recorded`
- `workflow.v1.compliance.evidence_claim_reviewed`
- `workflow.v1.compliance.evidence_claim_invalidated`
- `workflow.v1.compliance.assessment_plan_published`
- `workflow.v1.compliance.assessment_requested`
- `workflow.v1.compliance.assessment_input_collected`
- `workflow.v1.compliance.assessment_result_chunk_recorded`
- `workflow.v1.compliance.assessment_review_recorded`
- `workflow.v1.compliance.assessment_completed`
- `workflow.v1.compliance.assessment_failed`
- `workflow.v1.compliance.work_item_updated`
- `workflow.v1.compliance.audit_request_updated`
- `workflow.v1.compliance.packet_delivered`

Adding an event means updating the generated event-registry contract and all repo
integration points: model structs, registry, registry adapters, Avro decoder,
projector dispatch, round-trip fixtures, and replay entrypoint. Do not add a local
JSON-only event that the registry cannot validate.

### Result Chunk And Replay Contract

A full profile can contain more controls than the current replay limit. Do not emit
one event per control and assume the existing 1,000-event replay cap is sufficient.

`assessment_result_chunk_recorded` contains:

- assessment and automated-run IDs
- aggregate version
- chunk index and declared chunk count
- ordered objective-result records within a bounded payload size
- evidence and observation IDs, not raw artifact content
- previous chunk digest and current chunk digest
- input and evaluator hashes

`assessment_completed` contains a manifest of expected chunk indexes, record count,
and digest. The projector rejects missing, duplicate-with-different-content,
out-of-order aggregate versions, and manifest mismatches. Before full-catalog runs
ship, replay must support cursors beyond 1,000 events or a snapshot-plus-delta
contract. Add a fixture with more than 1,000 controls and a complete replay after an
empty projection.

### Postgres Projections

Add tenant-scoped tables in bounded groups:

Program and implementation:

- `grc_programs`
- `grc_program_scope_revisions`
- `grc_control_implementations`
- `grc_control_implementation_revisions`
- `grc_control_mapping_decisions`

Evidence ledger:

- `grc_evidence_artifacts`
- `grc_evidence_versions`
- `grc_evidence_claims`
- `grc_evidence_claim_events`

Assessment:

- `compliance_assessment_plans`
- `compliance_assessment_plan_revisions`
- `compliance_assessment_runs`
- `compliance_assessment_input_receipts`
- `compliance_assessment_activities`
- `compliance_assessment_populations`
- `compliance_assessment_samples`
- `compliance_assessment_result_chunks`
- `compliance_assessment_objective_results`
- `compliance_assessment_review_revisions`

Work and audit:

- `compliance_work_items`
- `compliance_work_item_occurrences`
- `compliance_remediation_milestones`
- `grc_audit_engagements`
- `grc_audit_requests`
- `grc_audit_messages`
- `grc_audit_submissions`
- `grc_audit_packages`
- `grc_audit_delivery_receipts`
- `compliance_event_application_receipts`

`compliance_event_application_receipts` stores event ID, aggregate ID and version,
projector version, applied time, and result. It is not a second payload log.

Use typed columns for tenant, IDs, states, timestamps, versions, hashes, cursor
fields, and common filters. Use bounded versioned JSON only for reason codes,
selectors, refs, and extension details. Every primary or unique key that can collide
across tenants includes tenant scope.

Migrations must be tested against a database containing the prior schema. A changed
table shape cannot rely on `CREATE TABLE IF NOT EXISTS` to repair an existing table.
Each phase includes upgrade, rollback or forward-fix, and checksum tests.

### Ordering, Idempotency, And Concurrency

- Creation stores method, route, authenticated principal, idempotency key,
  normalized request hash, and response ref.
- Same key and same request returns the original resource. Same key and different
  request returns conflict.
- Mutable aggregate events carry `aggregate_version` and expected prior version.
- Projectors ignore an exact duplicate, reject conflicting duplicates, detect a
  version gap, and expose poison events for operator action.
- HTTP mutations use `ETag` and `If-Match`; Connect mutations use
  `expected_version`.
- Foreign-tenant direct lookups return a non-disclosing not-found response.

Do not persist raw evidence again. Do not read assessment or audit state from
Neo4j. Optional graph projection can link programs, implementations, evidence
claims, assessment revisions, findings, policies, risks, vendors, and audit requests
after the Postgres projection succeeds.

## API And Transport Contract

Add route families as their owning service lands.

Program and implementation:

| Operation | Purpose |
| --- | --- |
| `POST /grc/programs` | Create a tenant-scoped program shell. |
| `GET /grc/programs` | List programs by owner, framework, status, and updated time. |
| `GET /grc/programs/{id}` | Read current program, active scope, and operating summary. |
| `POST /grc/programs/{id}/scope-revisions` | Propose or activate a versioned scope and parameter set. |
| `GET /grc/programs/{id}/control-implementations` | List scope-specific implementation records and gaps. |
| `POST /grc/programs/{id}/control-implementations` | Create a new implementation revision with expected aggregate version. |
| `GET /grc/programs/{id}/impact` | Explain records affected by a proposed scope, framework, policy, component, or mapping change. |

Evidence ledger:

| Operation | Purpose |
| --- | --- |
| `GET /grc/evidence-artifacts` | List artifact metadata and current versions by owner, subject, type, state, and expiry. |
| `GET /grc/evidence-artifacts/{id}` | Read version history, provenance, access policy, and dependent claims. |
| `POST /grc/evidence-claims` | Propose a claim that an existing evidence version supports a scoped objective. |
| `POST /grc/evidence-claims/{id}/reviews` | Approve, reject, or limit a claim. |
| `POST /grc/evidence-claims/{id}/invalidate` | Invalidate a claim and enqueue dependent impact work. |
| `POST /grc/evidence-claims/compatibility` | Evaluate whether a claim can be reused for a new scope and period. |

Assessment plans and runs:

| Operation | Purpose |
| --- | --- |
| `POST /grc/assessment-plans` | Create a draft plan against exact program and implementation revisions. |
| `GET /grc/assessment-plans/{id}` | Read one plan and revision history. |
| `POST /grc/assessment-plans/{id}/publish` | Validate and publish an approved plan revision. |
| `POST /grc/compliance-assessments` | Create an idempotent run and queue its platform job. |
| `GET /grc/compliance-assessments` | List runs by program, plan, state, period, and time. |
| `GET /grc/compliance-assessments/{id}` | Read run state, input manifest, child jobs, and current review revision. |
| `GET /grc/compliance-assessments/{id}/objectives` | Page canonical objective results with bounded filters. |
| `GET /grc/compliance-assessments/{id}/activities` | Read planned and performed assessment actions, populations, and samples. |
| `GET /grc/compliance-assessments/{id}/work-items` | Read work occurrences and owning cross-run items. |
| `POST /grc/compliance-assessments/{id}/reviews` | Create a review revision without mutating automated results. |
| `POST /grc/compliance-assessments/{id}/cancel` | Request cancellation of queued or running work. |
| `POST /grc/compliance-assessments/{id}/retry` | Retry a failed run with a new attempt and explicit reuse policy. |
| `POST /grc/compliance-assessments/{id}/supersede` | Create a replacement run and preserve the prior record. |
| `GET /grc/compliance-assessments/{id}/diff?baseline_id=...` | Compare scope, inputs, results, evidence, dispositions, and work. |
| `POST /grc/compliance-assessments/{id}/packets` | Queue an immutable packet job for an exact review revision and redaction mode. |
| `GET /grc/compliance-assessments/{id}/packets/{packetID}` | Read packet receipt, manifest, verification state, and download ref. |

Work and audit:

| Operation | Purpose |
| --- | --- |
| `GET /grc/compliance-work-items` | List cross-run work by program, owner, state, SLA, kind, control, or subject. |
| `POST /grc/compliance-work-items/{id}/actions` | Assign, block, snooze, accept, resolve, reopen, or supersede work. |
| `POST /grc/audit-engagements` | Create a scoped audit engagement. |
| `GET /grc/audit-engagements/{id}` | Read engagement scope, requests, progress, and current package. |
| `POST /grc/audit-engagements/{id}/requests` | Create a control or evidence request with period and sampling requirements. |
| `POST /grc/audit-requests/{id}/messages` | Add a request-scoped clarification. |
| `POST /grc/audit-requests/{id}/submissions` | Submit selected evidence claims or a new package revision. |
| `POST /grc/audit-requests/{id}/reviews` | Accept, reject, or request changes with actor attribution. |
| `POST /grc/audit-engagements/{id}/packages` | Freeze and queue a scoped audit package. |
| `POST /grc/audit-packages/{id}/deliveries` | Record recipient, purpose, expiry, and delivery receipt. |

### Transport And Pagination Rules

Create message types in `proto/cerebro/v1/compliance.proto` and add RPCs to
`BootstrapService` in the same PR as each JSON HTTP route. Both transports call the
same domain service. Update `api/openapi.yaml`, operation IDs, generated SDK
contracts, and auth policies together; do not ship another HTTP-only GRC resource.

Every list uses cursor pagination over an immutable stable sort. Responses contain
`next_cursor`, applied filters, result revision or cutoff, and optional total only
when the store can compute it without truncation. Invalid cursors fail closed. No
assessment or package builder gathers complete input through a public list route.

Long-running mutations return `202` with resource, job, and event links. Packet and
bulk export endpoints return artifact receipts rather than recalculating on every
read.

### Authorization

Use distinct write permissions:

- `cerebro.grc.programs.write`
- `cerebro.grc.evidence.write`
- `cerebro.grc.assessments.run`
- `cerebro.grc.assessments.review`
- `cerebro.grc.assessments.work_items.write`
- `cerebro.grc.audits.manage`
- `cerebro.grc.audits.review`

Reads use tenant-scoped GRC read authority plus object scope. Audit principals are
limited to assigned engagement IDs. The server derives actors from authenticated
principals and ignores request-body actor IDs. Sensitive evidence refs require both
object permission and disclosure policy.

### MCP And Agent Surface

Start read-only and stay within the task-tool budget tracked in #1722:

- `cerebro.compliance_assessments.get`
- `cerebro.compliance_controls.explain`
- `cerebro.compliance_work.list`
- resources such as `cerebro://compliance-assessment/{id}` and
  `cerebro://compliance-program/{id}`

Do not expose review, exception approval, risk acceptance, evidence submission, or
audit delivery through MCP until the same typed approval and expected-version
semantics exist in HTTP and Connect.

### Compatibility And Caller Migration

- Existing `/grc/control-packets`, `/grc/evidence-packets`, and
  `/grc/program-readiness` responses remain available.
- Add optional exact assessment and review revision refs so those routes can render
  stable completed state.
- Without a revision ref, keep request-time behavior during the shadow window.
- Use one adapter from canonical objective results to all legacy status fields.
- Inventory and migrate every consumer: GRC control and readiness routes,
  evidence packets, questionnaires, vendor packets, inventory reports, reports,
  agent evidence packets, A2A responses, MCP tools/resources, CLI, and SDK helpers.
- Shadow reads compare legacy and canonical results with sampled mismatch reason
  codes. Do not change defaults until caller inventory reaches zero and parity gates
  pass.
- Publish deprecation and removal criteria before changing or deleting fields.

## Delivery Sequence

Each phase is a separate PR and must deliver a testable vertical contract. A phase
may add storage and APIs for one aggregate, but it must not quietly implement the
next aggregate. Every PR copies its tasks, exit criteria, migration effect, and
rollback condition into its description. Generated outputs are changed only
through their repository targets.

The order is intentional. Phases 0 and 1 remove correctness limits that would make
later results incomplete or non-recoverable. Phases 2 through 8 establish the
operating loop. Phases 9 through 11 expand integration and automation only after
the underlying records are reproducible.

### Phase 0: Remove Correctness Blockers

Primary files:

- `internal/ports/findings.go`
- `internal/ports/jobs.go`
- `internal/statestore/postgres/findings.go`
- `internal/statestore/postgres/jobs.go`
- `internal/jobs/service.go`
- `internal/bootstrap/jobs.go`
- `internal/workflowevents/events.go`
- `internal/workflowevents/registry.go`
- `internal/workflowevents/avro_decoder.go`

Tasks:

- Add assessment-only cursor scans for findings, evidence links, source runtimes,
  policy state, and other required inputs. Do not use the GRC UI collectors, whose
  default and maximum limits can truncate an assessment.
- Require stable ordering, opaque cursors, per-page counts, final total counts, and
  a collection watermark. Return `input_changed` if a collection cannot finish at
  one consistent watermark.
- Add job claim leases, heartbeat, attempt count, cancellation checkpoints,
  retry classification, expired-lease recovery, and startup recovery to the shared
  job subsystem.
- Change schedule claiming so advancing `next_run_at` and enqueueing the job cannot
  lose an occurrence between the two operations.
- Add chunked event semantics and replay pagination. Never assume one event per
  catalog control fits within the current replay ceiling.
- Add compliance event types to the internal registry, external registry model,
  codec, decoder, and compatibility tests together.
- Define whether policy lifecycle state has a Postgres assessment read model. Until
  it does, the collector reports policy state as `unresolved`; it must not make
  graph availability part of assessment correctness.
- Restrict the first release to built-in catalog profiles. Extension profiles
  become selectable only after they have immutable IDs, revisions, and digests in
  a durable registry.

Exit criteria:

- A collector returns every row for inputs larger than 500 and proves the final
  count and watermark.
- A result stream larger than 1,000 controls can be replayed without truncation.
- Killing a worker after claim, after event append, and after projection causes
  safe recovery with no duplicate logical result.
- A scheduler crash cannot skip or duplicate a logical occurrence.
- Unknown policy state and non-durable profile state are explicit, bounded values.

Validation:

```bash
go test ./internal/ports ./internal/statestore/postgres ./internal/jobs ./internal/workflowevents ./internal/bootstrap -count=1
make contracts-check
```

### Phase 1: Freeze Canonical Semantics And Conformance Cases

Primary files:

- add `internal/compliance/types.go`
- add `internal/compliance/identifiers.go`
- add `internal/compliance/mappings.go`
- add `internal/complianceassessment/types.go`
- add `internal/complianceassessment/evaluate.go`
- add `internal/complianceassessment/legacy_status.go`
- add `internal/complianceassessment/testdata/*.json`

Tasks:

- Define stable logical IDs and immutable revision IDs for programs, scopes,
  implementations, plans, tests, evidence claims, runs, results, reviews, and
  artifacts.
- Define canonical serialization, sort rules, timestamp precision, optional-field
  handling, and hashing rules. Hash semantic content, not map iteration order or
  database row order.
- Define the `InputManifest`, result axes, mapping relationships, evidence quality
  reasons, source-state reasons, and bounded next-action codes.
- Reuse `compliance.AssessControlEvidenceRequirements` and the existing multi-rule
  finding orchestration. Preserve one persisted evaluation run per rule; do not
  add a second matcher or a new evaluation protocol.
- Add conformance cases for pass, active finding, missing evidence, invalid
  evidence, stale evidence, conflicting evidence, insufficient coverage, untrusted
  source, unknown source trust, manual evidence, exception, not applicable,
  inherited responsibility, sampled testing, and no configured source.
- Add forward-compatibility cases proving unknown enum values are retained or
  rejected at the correct boundary.
- Publish fixtures that every HTTP, Connect, projector, packet, and exchange
  implementation must consume.

Exit criteria:

- Every case has exact reason codes, result axes, next actions, canonical bytes,
  and expected hashes.
- Shuffling inputs cannot change output bytes or hashes.
- No result can pass when required evidence, population coverage, source scope, or
  trust remains unresolved.
- The legacy adapter reproduces existing status precedence without becoming the
  canonical model.

Validation:

```bash
go test ./internal/compliance ./internal/complianceassessment -count=1
make catalog-check
```

### Phase 2: Add Programs, Scope Revisions, And Control Implementations

Primary files:

- add `internal/ports/compliance_programs.go`
- add program and implementation tables under
  `internal/statestore/postgres/migrations/`
- add `internal/statestore/postgres/compliance_programs.go`
- add program and implementation services under `internal/grcprogram/`
- add program and implementation events under `internal/workflowevents/`

Tasks:

- Implement versioned program scope with included and excluded systems, resources,
  business units, regions, accounts, data classes, environments, and time bounds.
- Resolve a scope revision into a deterministic subject manifest and record
  unresolved selectors separately from zero matches.
- Record control implementations with owner, narrative, status, applicability,
  parameters, responsible roles, components, implementation mode, inheritance,
  customer responsibility, provider responsibility, and source references.
- Record mappings as structured relationships with direction, rationale,
  confidence, gaps, review state, and provenance. Do not treat every mapping as
  equivalence.
- Require a new immutable revision for any semantic change. Preserve predecessor
  links and a human-readable change summary.
- Project program and implementation state to Postgres from append-only events.

Exit criteria:

- The same scope revision always resolves to the same subject manifest at the same
  source watermark.
- Shared, inherited, provider, and customer responsibilities remain distinct.
- A mapping can express subset, superset, overlap, equivalent, and no relationship.
- A foreign tenant cannot infer whether a program, implementation, or revision ID
  exists.

Validation:

```bash
go test ./internal/grcprogram ./internal/workflowevents ./internal/statestore/postgres -count=1
```

### Phase 3: Establish The Evidence Ledger

Primary files:

- add `internal/ports/evidence_ledger.go`
- add `internal/evidenceledger/`
- add evidence ledger migrations and Postgres adapters
- adapt `internal/findings/evidence.go`
- adapt `internal/grccontrol/evidence.go`

Tasks:

- Separate an evidence artifact, an immutable artifact version, and a claim about
  what that version proves. Existing finding and control links become adapters to
  claims rather than independent evidence truth.
- Store digest, media type, size, producer, producer version, collection time,
  validity period, subjects, source event, derivation, sensitivity, access policy,
  retention, redaction state, and predecessor.
- Reference bytes in the existing content-addressed store or an approved external
  URI. Do not place evidence contents in events, logs, metrics, or graph properties.
- Validate a claim against subject, period, requirement, control objective,
  collection method, freshness, trust minimum, and reviewer state.
- Make reuse explicit. Reuse creates a new claim with its own scope and decision;
  it never mutates the source claim or artifact version.
- Quarantine malformed, malware-flagged, digest-mismatched, inaccessible, or
  over-retention artifacts with bounded reason codes.
- Emit expiry, supersession, revocation, and access-policy-change events.

Exit criteria:

- One artifact version can support multiple scoped claims without conflating their
  approvals or validity periods.
- A digest mismatch, inaccessible object, revoked version, or expired claim cannot
  satisfy a requirement.
- Existing finding and control evidence callers receive compatible reads through
  adapters backed by the ledger.
- Every evidence read and export enforces tenant, sensitivity, and purpose.

Validation:

```bash
go test ./internal/evidenceledger ./internal/findings ./internal/grccontrol ./internal/statestore/postgres -count=1
make oss-audit
```

### Phase 4: Add Assessment Plans And Durable Runs

Primary files:

- add `internal/ports/compliance_assessments.go`
- add `internal/complianceassessment/plan.go`
- add `internal/complianceassessment/runner.go`
- add assessment migrations and Postgres adapters
- add assessment event codecs and projectors
- register `KindComplianceAssessment` in the platform job runner

Tasks:

- Create immutable plan revisions covering objectives, control selection, included
  and excluded subjects, activities, sampling rules, depth, coverage target,
  assurance target, tools, team, approvals, windows, dependencies, and rules of
  engagement.
- On run request, persist the request event and input revision IDs before enqueue.
  Bind the platform job ID to the run; do not add another scheduler.
- Collect all inputs using Phase 0 scans. Persist page receipts, counts, watermarks,
  cutoff, and `InputManifest` before evaluation starts.
- Stop with a typed incomplete-input result if any required collector truncates,
  changes watermark, cannot resolve a revision, or cannot prove completeness.
- Append result chunks with sequence, range, count, chunk digest, and previous
  digest, then append a terminal manifest only after all chunks are durable.
- Keep cancelled and failed runs readable. Record completed activities and a
  bounded failure without presenting a partial run as completed.
- Store separate `input_hash` and `automated_result_hash` values.

Exit criteria:

- Replaying events into an empty Postgres projection reproduces the plan, run,
  results, manifests, and hashes.
- A duplicate tenant and idempotency key with the same request hash returns the
  original run; a different request hash returns conflict.
- Post-cutoff changes do not alter the completed run.
- A crash at every durable boundary resumes safely or terminates explicitly.

Validation:

```bash
go test ./internal/complianceassessment ./internal/workflowevents ./internal/statestore/postgres ./internal/jobs ./internal/bootstrap -count=1
```

### Phase 5: Execute Tests, Populations, Samples, And Source Checks

Primary files:

- add `internal/complianceassessment/activities.go`
- add `internal/complianceassessment/populations.go`
- add `internal/complianceassessment/tests.go`
- update `internal/complianceassessment/evaluate.go`
- update adapters under `internal/sourcecoverage/`
- update `internal/findingrules/` through its existing orchestration boundary

Tasks:

- Implement examine, interview, and test activities with explicit procedure,
  expected result, operator or tool, start and end time, subject set, and output
  references.
- Materialize populations and deterministic samples. Record population query,
  source watermark, total size, exclusions, sample method, seed, sample size, and
  selected subject IDs.
- Keep test execution state separate from test result: queued, running, completed,
  failed, error, skipped, and cancelled must not be used as control outcomes.
- Capture source runtime health, coverage dimensions, freshness, unsupported
  fields, and certification tier. Missing certification is `unknown`, never an
  implied trusted tier.
- Use existing finding-rule orchestration for batches while retaining one durable
  evaluation result per rule.
- Detect contradictory observations and claims. Preserve both sides and require a
  review instead of choosing by recency alone.
- Let unaffected objectives finish when one source fails, while marking affected
  objectives incomplete and creating source-repair work.

Exit criteria:

- Supported, partial, stale, failed, unconfigured, unsupported, and unverified
  source states have distinct results and actions.
- Re-running a sample from its recorded population and seed returns the same
  subjects.
- A lower-trust source remains visible but cannot satisfy a higher minimum.
- Provider access occurs only inside source runtimes.

Validation:

```bash
go test ./internal/complianceassessment ./internal/sourcecoverage ./internal/findingrules ./internal/bootstrap -count=1
make catalog-check
```

### Phase 6: Ship Typed APIs, Authorization, And Compatibility

Primary files:

- add compliance messages and services under `proto/cerebro/v1/`
- update `proto/cerebro/v1/bootstrap.proto`
- update `api/openapi.yaml`
- add handlers under `internal/bootstrap/`
- update authorization policies for HTTP and Connect
- add read-only tools and resources under `internal/mcp/` within its task budget

Tasks:

- Implement program, scope, implementation, evidence, plan, run, result, review,
  and work-item reads in JSON HTTP and Connect. Mutation routes arrive only with
  the phase that owns the corresponding invariant.
- Enforce distinct permissions for run, review, evidence decision, work-item
  mutation, audit access, and export. A broad GRC read cannot imply evidence-byte
  access.
- Use 202 responses for durable commands, returning job and resource links. Use
  receipts for artifact and event acceptance.
- Add stable cursor pagination and bounded filters. Never expose internal offsets
  or use the 100-item UI default for canonical reads.
- Add conditional mutation using aggregate version or ETag. A stale review or work
  update returns conflict with the current version.
- Add `assessment_id` adapters to current readiness, control-packet, evidence-packet,
  report, questionnaire, agent, CLI, and SDK consumers as applicable.
- Return tenant-scoped not-found responses so callers cannot distinguish forbidden
  from nonexistent IDs.

Exit criteria:

- HTTP and Connect pass the same conformance fixtures and authorization matrix.
- Every collection can traverse more than 500 rows without loss or duplication.
- Existing response fields remain compatible during the migration window.
- No transport handler owns evidence matching, precedence, hashing, or workflow
  transition logic.

Validation:

```bash
make contracts-check
go test ./internal/bootstrap ./internal/mcp ./internal/grccontrol ./internal/grcprogram ./internal/evidencepackets -count=1
make docs-drift-check
```

### Phase 7: Add Review Revisions, Risk, And Remediation

Primary files:

- add `internal/complianceassessment/reviews.go`
- add `internal/complianceassessment/work_items.go`
- add remediation projections and events
- integrate references from `internal/grcpolicylifecycle/` and finding workflow
- add review and work-item actions to JSON HTTP and Connect

Tasks:

- Preserve the automated result and create immutable review revisions above it.
  A review records decisions, rationale, actor, role, evidence references, prior
  revision, and `revision_hash`.
- Model observation, finding, risk, exception, work item, and remediation milestone
  separately. Exception is a disposition with expiry, not a test outcome.
- Support assign, request evidence, block, snooze, accept risk, reject risk, approve
  exception, reject exception, remediate, verify, close, and reopen through explicit
  state transitions.
- Require owner, rationale, approval, expiry, and linked risk for accepted risk or
  exception. Closure requires independent verification evidence where configured.
- Fingerprint work across runs by tenant, program, subject, objective, reason, and
  source. Record each run as an occurrence so repeated failures update one active
  work item without erasing history.
- Reopen work when an exception expires, evidence becomes stale or revoked, a
  finding reopens, a source loses coverage, or scope adds affected subjects.
- Enforce optimistic concurrency for every review and work-item mutation.

Exit criteria:

- Review history explains every difference between automated and effective state.
- Two simultaneous reviewers cannot silently overwrite each other.
- Repeated runs deduplicate active work and retain per-run occurrences.
- Expiry and revocation events create concrete work with an owner and due state.

Validation:

```bash
go test ./internal/complianceassessment ./internal/grcpolicylifecycle ./internal/workflowevents ./internal/bootstrap -count=1
```

### Phase 8: Add Audit Engagements, Requests, Sampling, And Packages

Primary files:

- add `internal/grcaudit/`
- add audit tables, ports, events, and projectors
- refactor `internal/evidencepackets/packets.go`
- add `internal/complianceassessment/diff.go`
- add audit and package routes to HTTP and Connect

Tasks:

- Create audit engagements with program, scope revision, period, participants,
  disclosure policy, deadlines, and status.
- Create evidence requests with objective, subject, period, sample, requester,
  owner, due date, response versions, change requests, and acceptance state.
- Let auditors request or refine samples without altering the source assessment
  plan or completed run.
- Build packets from an immutable run plus a selected review revision. Keep live
  work-item state in a clearly labeled projection outside the signed result.
- Include supporting and contradicting claims, population and sample facts, source
  gaps, policies, implementations, findings, risks, exceptions, work, provenance,
  receipts, redaction decisions, and validation issues.
- Generate a machine-readable manifest, human index, attachment inventory,
  per-file digests, package digest, signature metadata, and predecessor link.
- Diff scope, implementation revision, result axes, evidence claims, source health,
  exceptions, and work against a completed baseline.
- Record delivery receipt and redaction mode, never packet contents, in telemetry.

Exit criteria:

- Rebuilding the same package revision produces identical semantic content and
  digest.
- Auditor access is limited to the engagement, approved requests, and disclosed
  artifact versions.
- A diff reports newly failing objectives and assurance degradation even when the
  legacy status is unchanged.
- Every exported attachment is covered by the manifest and signature envelope.

Validation:

```bash
go test ./internal/grcaudit ./internal/complianceassessment ./internal/evidencepackets ./internal/bootstrap -count=1
make contracts-check
```

### Phase 9: Connect Policies, Access Reviews, Vendors, And Questionnaires

Primary files:

- adapters under `internal/grcpolicylifecycle/`
- adapters under `internal/grcaccessreview/`
- adapters under `internal/grcvendor/`
- adapters under `internal/grcquestionnaire/`
- compliance impact adapters under `internal/inventory/` and `internal/findings/`

Tasks:

- Link policy approval, acknowledgement, exception, and review state to relevant
  implementations and objectives without copying policy records.
- Turn access-review decisions and remediation proof into scoped evidence claims;
  an attestation alone cannot prove a completed revocation.
- Link vendor ownership, review period, service scope, inherited controls, customer
  responsibilities, findings, and remediation to program scope.
- Answer questionnaires from approved implementations and evidence claims with
  citations, validity period, and confidence. Generated suggestions remain drafts
  until a named reviewer accepts them.
- Compute change impact for catalog revisions, mappings, source coverage, inventory,
  policies, vendors, claims, and findings. Report affected programs, plans,
  objectives, packages, and open work before scheduling reevaluation.
- Keep each source domain authoritative for its own lifecycle and use stable
  references rather than replicated status strings.

Exit criteria:

- Every derived answer or status identifies its exact source revisions and claims.
- Suggestions cannot approve evidence, accept risk, close work, or submit an audit
  response without an authorized human action.
- A domain change produces a bounded impact set with reasons and no cross-tenant
  references.
- Deleting or revoking a source record invalidates dependent claims and projections
  without rewriting completed artifacts.

Validation:

```bash
go test ./internal/grcpolicylifecycle ./internal/grcaccessreview ./internal/grcvendor ./internal/grcquestionnaire ./internal/inventory ./internal/findings ./internal/complianceassessment -count=1
```

### Phase 10: Add Portable Exchange And Layered Validation

Primary files:

- add `internal/complianceexchange/`
- add import, export, validation, and round-trip conformance fixtures
- add exchange jobs and routes to HTTP and Connect

Tasks:

- Export programs, scope revisions, implementations, plans, results, remediation,
  claims, and manifests through versioned adapters. Keep the internal canonical
  model independent of any exchange schema.
- Import to a staging area first. Parse, validate, resolve references, check tenant
  policy, and present a change plan before committing canonical revisions.
- Validate in layers: archive safety, parse, schema, referential integrity, business
  rules, package digests, signatures, authorization, round trip, and semantic
  conformance.
- Return machine-readable issues with path, code, severity, message, related IDs,
  and repair guidance.
- Reject path traversal, decompression bombs, duplicate logical IDs, unknown
  mandatory types, digest mismatch, invalid signatures, and cross-tenant
  references.
- Preserve unknown optional fields when the selected exchange version requires
  round-trip fidelity.

Exit criteria:

- Export, import to staging, and export again preserves canonical semantics and
  expected unknown fields.
- Invalid packages cannot write canonical records or content bytes.
- Validation issues are deterministic and safe to expose to the importing tenant.
- All accepted artifacts have verified digests and recorded import provenance.

Validation:

```bash
go test ./internal/complianceexchange ./internal/complianceassessment ./internal/statestore/postgres ./internal/bootstrap -count=1
make contracts-check
make oss-audit
```

### Phase 11: Schedule, Monitor, Roll Out, And Retire Duplicate Logic

Primary files:

- shared schedule adapters under `internal/jobs/` and `internal/bootstrap/`
- outcome events and metrics under the existing observability packages
- compatibility callers identified in Phase 6
- operational runbooks under `docs/`

Tasks:

- Add program schedules to the hardened shared scheduler. Prevent overlapping runs
  for the same tenant, plan revision, and logical occurrence.
- Support time triggers and change triggers for scope, implementation, evidence,
  source health, policy, finding, exception, risk, and catalog changes. Debounce
  related changes into one explainable reevaluation request.
- Record monitoring definition, frequency, expected coverage, maximum evidence age,
  last success, next due, consecutive failures, grace period, and escalation owner.
- Emit bounded events for run requested, input incomplete, completed, review needed,
  request overdue, package delivered, work resolved, and monitor missed.
- Measure completion latency, complete-input rate, evidence freshness, evidence
  reuse, explicit coverage gaps, time to review, time to fulfill requests, reopened
  work, and time to verified remediation.
- Run canonical and legacy calculations in shadow mode. Compare exact conformance
  fields, classify differences, and publish a tenant-safe parity report.
- Migrate one caller cohort at a time. Keep a reversible read switch and documented
  rollback threshold.
- Remove duplicate status and evidence-selection logic only after the compatibility
  window ends and the caller inventory reaches zero.

Exit criteria:

- Missed schedules, stuck leases, repeated source failures, and overdue evidence
  requests have alerts and named runbook actions.
- A scheduled run is inspectable, cancellable, retryable, and non-overlapping.
- Migration cohorts meet the parity and error-budget gates below before advancing.
- `grccontrol`, `grcprogram`, `evidencepackets`, reports, questionnaires, agent
  surfaces, CLI, and SDK no longer calculate independent control precedence.

Validation:

```bash
go test ./internal/complianceassessment ./internal/jobs ./internal/bootstrap ./internal/statestore/postgres -count=1
make verify
```

## Security And Abuse Cases

The implementation threat model must cover the following boundaries before the
first mutation API ships:

- Tenant isolation applies to IDs, cursors, idempotency records, event subjects,
  object-store keys, cache keys, job payloads, logs, metrics, graph projections,
  packages, and validation errors.
- An evidence reader is not automatically allowed to read artifact bytes. Enforce
  purpose, sensitivity, engagement disclosure, retention, and redaction at read and
  export time.
- Treat imported files, evidence attachments, source text, questionnaire content,
  and implementation narratives as untrusted data. They cannot change tool calls,
  reviewer permissions, package scope, or automated decisions.
- Generated summaries and suggestions must cite immutable input revisions. They are
  advisory and cannot approve evidence, change scope, accept risk, close work, or
  submit an audit response.
- Verify digest before parsing or rendering. Scan supported attachments, bound
  archive depth and expansion, reject active content where possible, and render
  unsafe types only through isolated conversion.
- Sign the outer package manifest and cover every included artifact. Record the
  signer, algorithm, key reference, signature time, package digest, and predecessor.
- Make deletion and retention behavior explicit. Legal hold prevents destruction;
  it does not make an expired claim valid for a new assessment.
- Use opaque public IDs and tenant-scoped not-found responses. Timing, counts,
  validation paths, and error text must not disclose another tenant's resources.
- Audit every evidence decision, risk acceptance, exception approval, scope change,
  export, external disclosure, and administrative override with actor and reason.

## Required Regression Matrix

Every phase adds focused tests for the rows it touches. The full matrix is a release
gate, not a manual checklist:

| Area | Required cases |
| --- | --- |
| Collection | 0, 1, 500, 501, and more than 1,000 rows; duplicate and missing cursors; watermark changes; deleted rows between pages |
| Catalog | empty selection resolving the full catalog; built-in revision change; unavailable extension revision; mapping cycles and missing targets |
| Time | post-cutoff evidence, finding, policy, source, and inventory mutations; clock skew; expiry exactly at cutoff; daylight-saving schedule boundaries |
| Jobs | crash before claim, after claim, after input manifest, between result chunks, after terminal append, and before projection; cancellation and lease expiry |
| Events | duplicate, gap, reordering, unknown optional field, unsupported version, poison event, projector restart, and full rebuild |
| Idempotency | same key and same body; same key and different body; concurrent creates; expired key policy; retry after transport timeout |
| Review | simultaneous reviewers, stale ETag, superseded review, rejected evidence, accepted risk expiry, exception expiry, and independent closure verification |
| Evidence | digest mismatch, inaccessible bytes, unsupported type, revoked version, superseded claim, reuse across periods, sensitivity denial, and retention hold |
| Source trust | supported, partial, stale, failed, unconfigured, unsupported, unverified, conflicting, and insufficient certification |
| Sampling | zero population, exclusions, deterministic random sample, judgmental sample rationale, changed population, and missing sampled subject |
| Work | stable fingerprint across runs, multiple occurrences, reopen triggers, owner change, milestone dependency, duplicate remediation, and verified closure |
| Audit | request changes, late response, sample expansion, disclosure removal, auditor removal, accepted response, redaction, and external receipt |
| Package | deterministic rebuild, every attachment covered, altered attachment, signature failure, predecessor chain, unauthorized field, and redaction manifest |
| Exchange | parse failure, unsafe archive, decompression limit, duplicate IDs, broken reference, invalid business rule, round trip, and staged rollback |
| Authorization | every permission by HTTP and Connect; tenant non-disclosure; evidence-byte purpose; auditor engagement scope; service principal expiry |
| Compatibility | canonical-to-legacy mapping for every result combination; every existing caller; JSON field stability; pagination migration; CLI and SDK fixtures |
| Scheduling | overlap prevention, enqueue failure, missed occurrence recovery, debouncing, retry budget, cancellation, disabled schedule, and tenant deletion |

## Rollout Gates And Rollback

Rollout advances by tenant cohort and caller, not by global flag:

1. **Fixture gate:** canonical contracts, hashing, event compatibility, and legacy
   mappings pass conformance fixtures.
2. **Replay gate:** a production-shaped event corpus rebuilds an empty projection
   with matching counts and hashes.
3. **Shadow gate:** canonical collection and evaluation run without serving results.
   Input completeness must be 100 percent; unexplained legacy differences must be
   zero.
4. **Read gate:** internal readers use canonical projections while mutations remain
   on the current path. Latency, error rate, authorization denials, and result parity
   stay within the documented budget.
5. **Write gate:** one low-risk cohort creates canonical plans and runs. Every write
   remains visible through compatibility reads and has a tested replay path.
6. **Audit gate:** immutable package rebuild, access enforcement, redaction, and
   external receipt are verified for a controlled engagement.
7. **Default gate:** canonical reads become the default only after two complete
   assessment cycles pass all earlier gates.
8. **Retirement gate:** remove a legacy calculation only when no caller remains,
   rollback has not been used for one compatibility window, and its parity fixtures
   remain in the canonical suite.

Each cohort has a kill switch for canonical reads, assessment creation, scheduling,
and external package delivery. Rolling back serving does not delete canonical events
or mutate completed runs. A rollback runbook records the switch owner, decision
threshold, projection recovery procedure, and reconciliation query.

## Implementation Rules For Follow-On Agents

- Implement one phase per PR and copy that phase's exit criteria into the PR body.
- Start each PR from current `main`; do not build later phases on an unmerged branch.
- Before coding, inventory every existing caller and record which contract, store,
  event, and route it uses. Update that inventory in the PR.
- Read `docs/engineering/non-goals.md` before changing storage, workflow, findings,
  graph, or action behavior.
- Reuse `internal/compliance` evaluation primitives. A second evidence matcher or
  status precedence function is a review blocker.
- Keep provider I/O in source runtimes and long-running work in platform jobs.
- Reuse existing multi-rule finding orchestration while keeping one persisted
  evaluation run per rule.
- Append workflow events before projecting mutable state. Use event receipts and
  aggregate versions; do not rely on at-most-once delivery.
- Keep Neo4j optional for assessment reads and rebuildable from durable records.
- Never use GRC UI list helpers as an assessment collector. A collector must prove
  completeness, ordering, watermark, and cutoff.
- Do not call an in-process goroutine durable execution. Use a claimed job with a
  lease, heartbeat, retry classification, cancellation, and recovery.
- Do not add a selected extension profile to an input manifest until its immutable
  revision and digest exist in durable storage.
- Add migrations as versioned schema changes and test upgrade from the prior
  schema. `CREATE TABLE IF NOT EXISTS` alone is not a migration test.
- Keep automated run, review revision, live work projection, and package artifact
  separate. A review or work update cannot change a completed run hash.
- Treat enum additions, reason-code changes, event changes, and canonical sort
  changes as compatibility changes requiring conformance fixtures.
- Add a regression test for every tenant boundary, idempotency rule, state
  transition, and compatibility mapping changed by the phase.
- Run `make contracts-check` for proto or OpenAPI changes, `make docs-drift-check`
  for generated docs, and `make oss-audit` for public examples or fixtures.
- Do not hand-edit generated catalogs, contract outputs, or mapping CSVs.
- Stop the phase if an earlier exit criterion is not true. Record the dependency;
  do not hide the gap behind `unknown`, a default pass, or a best-effort query.

## Completion Criteria

The overhaul is complete when:

- a program owner can version scope and implementations, explain every mapping, and
  resolve the exact subjects assessed
- an assessor can author a plan, run complete-input collection, execute documented
  procedures and samples, and reproduce the same automated result from its manifest
- an evidence owner can register immutable versions and scoped claims, reuse them
  safely, see why they were rejected, and receive expiry or revocation work
- a reviewer can make a revision without overwriting automation, accept risk only
  with bounded approval, and trace every effective decision to actor and evidence
- a remediation owner can manage milestones across repeated run occurrences and
  close work only with the required verification
- an auditor can request evidence and samples, see only disclosed material, request
  changes, accept responses, and receive a signed, deterministic package
- a caller can create, poll, review, diff, validate, and export tenant-scoped
  resources through semantically equivalent JSON HTTP and Connect contracts
- every result separates scope, automated outcome, design, operating effectiveness,
  evidence state, disposition, assurance, and auditor state
- missing coverage, unknown trust, incomplete collection, invalid evidence, and
  unresolved samples prevent unsupported pass claims
- all events replay into the same Postgres state, counts, revision IDs, and hashes
- every collection proves it traversed the complete input at one bounded cutoff
- schedules use recovered platform jobs, cannot overlap one logical occurrence, and
  explain why each time- or change-triggered run exists
- packages cover all included files with digests, signatures, provenance, disclosure,
  redaction, and predecessor information
- portable exchange validates before commit and round-trips canonical semantics
- existing callers use shared canonical adapters with no independent status or
  evidence-selection logic
- telemetry reports outcomes, freshness, explicit gaps, review and request latency,
  reopen rate, and verified remediation time without sensitive evidence values
- every rollout gate, rollback switch, threat-model control, and regression-matrix
  case has an automated test or an owned operational check

## Non-Goals

- No end-user web UI in this repository.
- No replacement control catalog. Catalog revisions are inputs to the compliance
  model, not a second source of definitions.
- No duplicate raw evidence blob store. The ledger references the existing
  content-addressed store or an approved external object.
- No direct provider calls from the assessment service.
- No direct Neo4j writes or graph-authoritative assessment reads.
- No second finding-rule evaluation protocol. Reuse the current orchestration and
  keep its per-rule persisted evaluation semantics.
- No general-purpose workflow engine. Explicit domain state machines and platform
  jobs are sufficient.
- No autonomous evidence approval, risk acceptance, exception approval, audit
  submission, or remediation closure.
- No silent normalization of contradictory evidence or mappings into one answer.
- No auditor access through a tenant-wide GRC read permission.
- No mutable completed run, review revision, or package artifact.
- No pass inferred from an empty finding set when coverage or evidence is missing.
- No breaking removal of existing GRC response fields during the migration window.
