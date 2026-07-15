# Assurance Platform Contracts

## Scope

This contract exposes completed compliance decisions without creating another
assessment, evidence, or work authority. It covers:

- typed public events derived from canonical compliance workflow events
- a stable semantic model for analytics and agent joins
- read-only MCP tools and resources
- the versioned legacy status adapter

Assessment runs, assurance decisions, and assessment snapshots remain under
`internal/complianceassessment`. Canonical work remains under
`internal/complianceremediation`. Postgres projections serve current reads;
JetStream workflow envelopes remain the replay boundary. Evidence fields contain
IDs and content digests only. EvidenceCAS or the approved external source retains
artifact bytes. Neo4j remains a rebuildable impact and relationship projection.

## Executable Obligations

A published assessment plan is the immutable source for executable obligations.
`CompileExecutableObligations` compiles each ordered finding-evaluation task into
an `assessment-obligation/v1` definition that binds:

- the plan revision, task, objective, and control
- the finding rule and source runtime set
- the evidence freshness limit and point-in-time evaluation mode
- the `no_active_findings` predicate and evaluator revision

Each definition has a content digest. The input manifest's
`mapping_set_digest` pins the ordered compiled definition set. The finding
evaluation collector executes the compiled definition against bounded durable
evaluation runs. Missing, stale, incomplete, or untrusted inputs produce an
indeterminate result; active findings produce a not-satisfied result; only
complete evidence with no active finding produces a satisfied result. Unknown
task kinds fail collection instead of producing an implied pass.

The plan revision remains the replay artifact. Obligation definitions are
deterministically derived from that artifact, so replay does not depend on a
second mutable obligation store.

## Evidence Claim Validity

Evidence versions continue to reference bytes in EvidenceCAS or an approved
external system. A claim may set an earlier `valid_until` than its evidence
version; it may not outlive that version. Claim validation returns
`evidence_claim_expired` with `refresh_evidence` when the claim window closes.

Validation also compares active reviewed claims over the same artifact version
and exact objective, implementation, requirement, subject, and period scope. An
approved claim conflicts with a rejected claim over that scope. Two approved
claims conflict when their linkage, strength, or limitation differs. The result
returns `evidence_claim_conflicting` with `resolve_conflict`. Invalidating the
contradictory claim removes it from current conflict evaluation without changing
historical events or snapshots.

The application composition root activates this ledger only when the configured
state store implements `ports.EvidenceLedgerStore` and the append log is
available. The HTTP contract preserves the existing `/grc/evidence`, control
packet, evidence packet, and audit packet routes and adds tenant-scoped ledger
operations:

| Operation | State change or read |
| --- | --- |
| `POST /grc/evidence-artifacts/{artifactID}/versions` | Record artifact metadata and one immutable EvidenceCAS or approved external version reference. |
| `GET /grc/evidence-versions/{versionID}` | Read version metadata after purpose and sensitivity checks. |
| `POST /grc/evidence-claims` | Record a pending scoped claim. |
| `GET /grc/evidence-claims/{claimID}` | Read the current claim projection. |
| `POST /grc/evidence-claims/{claimID}/reviews` | Record an approved or rejected review with an expected version. |
| `POST /grc/evidence-claims/{claimID}/invalidate` | Invalidate a claim with an expected version and reason. |
| `POST /grc/evidence-claims/{claimID}/validate` | Evaluate review, expiry, conflict, subject, and period state. |
| `POST /grc/evidence-claims/compatibility` | Compare exact source and target proof obligations and current claim validity. |
| `POST /grc/evidence-claims/{claimID}/reuse` | Create a separate pending claim over the same immutable version; approval is never copied. |

Compatibility uses `compliance.EvaluateEvidenceReuse`. The source and target
obligations bind framework, control, implementation and scope revisions,
population digest, subject kinds, period, method, strength, frequency, and review
policy. An exact match is reusable. A narrower period over the same semantic
inputs is partial. Any other mismatch is incompatible. Current claim validation
can still deny an otherwise compatible obligation when the claim is pending,
rejected, invalidated, expired, conflicting, outside its covered period, or does
not cover the requested subjects.

## Change-Driven Assessment Scheduling

Compliance monitors are managed through tenant-scoped HTTP routes:

| Route | Action |
| --- | --- |
| `POST /grc/compliance-monitors` | Create a time-triggered or change-triggered monitor. |
| `GET /grc/compliance-monitors` | List monitors after an optional identifier cursor. |
| `GET /grc/compliance-monitors/{monitorID}` | Read the current monitor definition and execution state. |
| `PUT /grc/compliance-monitors/{monitorID}` | Replace a monitor definition at an expected version. |

The background scheduler scans due time monitors and closed change windows every
15 seconds. It first creates a canonical assessment run and a queued platform job
that contains the run ID. After the trigger event and monitor occurrence are
recorded, it starts that job. Platform recovery can start a queued job if the
process stops after recording the occurrence.

Each monitor-triggered run retains the monitor, plan revision, occurrence, and
lease-owner binding. Completing or failing the assessment writes one immutable
monitor outcome and releases that exact plan lease in the same Postgres
transaction. A replay with the same outcome is idempotent; a different terminal
outcome for the same occurrence is a conflict. Existing monitor completion and
lease-release methods remain available for compatibility.

`complianceimpact.Scheduler` connects immutable change signals to the existing
bounded impact analyzer and compliance monitor service. It records only source
event IDs, monitor IDs, signal kinds, timestamps, and the assessment-directive
digest in monitor state.

When impact traversal is complete, the scheduler selects enabled change monitors
whose exact plan revision appears in the impact result. When traversal reaches a
node, edge, depth, or consistency limit, the directive changes to
`full_reconciliation` and selects every enabled change monitor in the tenant.
Monitor enumeration is paginated and stops before writing if the configured
10,000-monitor bound would be exceeded. Recording is idempotent by source event
and monitor. The existing debounce window and per-plan lease remain responsible
for coalescing signals and preventing overlapping assessment runs.

The production composition root now builds the monitor service from the
Postgres monitor store and append log. When the graph store implements both the
projection and bounded query ports, it also builds the compliance impact graph
projector, analyzer, scheduler, and processor. The processor projects the new
exact fact before traversal. An update traverses the exact predecessor and
binds the new fact as its replacement; an update without exact predecessor
identity is rejected instead of being treated as a create.

Assessment plan events now retain `revision_modified_at` and the complete exact
predecessor revision. The assessment service sends the already-appended event
through the impact processor before advancing the Postgres plan projection.
Retries repeat the same graph upsert and source event ID, so monitor signal
recording remains idempotent.

Before recording a plan, the Postgres capability resolves its compatibility
`scope_revision_id` and `implementation_revision_ids` to complete immutable
revision references. The original fields remain present. The additive exact
references become `plan_scope` and `plan_implementation` dependencies in the
impact graph. Resolution uses the requested revision IDs only and rejects a
missing, invalid, or ambiguous revision instead of substituting a current row.

The program impact adapter accepts already-appended scope and control
implementation events. Scope facts retain exact framework and profile
dependencies. Implementation facts retain the exact scope plus both ends of
every control mapping. Updated scope and implementation records carry a full
predecessor revision; the adapter rejects later versions that provide only a
predecessor ID.

Each projected impact node represents one exact immutable revision. Its URN
includes a digest of the full exact identity, while its attributes retain the
tenant, domain, fact kind, stable ID, revision ID, version, content digest, and
last-modified time. A dependent points to an exact dependency through a
`compliance_depends_on` edge carrying the domain relation. The projection writes
identifiers and revision metadata only.

Graph reads use tenant-scoped read-only Cypher. Fact reads count dependencies
before loading them and reject more than 2,999 edges. Reverse-dependency pages
use an exact-revision URN cursor, request one row beyond the caller limit, and
reject unordered, cross-tenant, or revision-mismatched rows. The analyzer keeps
its separate node, edge, depth, and page limits. Neo4j remains rebuildable; a
missing or inconsistent exact revision fails impact analysis instead of changing
the Postgres or JetStream authority.

## Public Event Mapping

| Canonical workflow event | Public event | Public payload |
| --- | --- | --- |
| `workflow.v1.compliance.assessment_assurance_decision_recorded` | `compliance.assurance_decision.recorded` | Decision, run, result, qualification state, and decision and record digests |
| `workflow.v1.compliance.assessment_snapshot_recorded` | `compliance.assessment_snapshot.recorded` | Snapshot, run, result-set, decision-set, and evidence-set digests |
| `workflow.v1.compliance.work_item_updated` | `compliance.work_item.updated` | Work item, state, version, and occurrence count |
| `workflow.v1.compliance.work_item_updated` with `verify_assurance` | `compliance.work_item.verified` | Work item and the exact assurance decision, run, result, and decision digest |

`agentplatform.BuildTypedComplianceEvent` is the only adapter from the canonical
workflow envelope to these public payloads. Unsupported compliance event kinds
remain unsupported until their payload contract is defined. The adapter does not
copy evidence records, source records, credentials, implementation narratives, or
artifact bytes.

## Semantic Model

`complianceassessment.SemanticModel` defines five stable entities:

- assessment run
- objective result
- assurance decision
- assessment snapshot
- compliance work item

Every join includes `tenant_id`. Immutable entities identify their record or set
digest. Current-state projections name the event log that rebuilds them. Missing,
stale, conflicting, and untrusted evidence remain separate dimensions. The legacy
status is a derived compatibility field and is never an authority.

## MCP Reads

The MCP server exposes these read-only tools:

| Tool | Read boundary |
| --- | --- |
| `cerebro.compliance_assessments.get` | One immutable snapshot and an optional bounded audience lens page |
| `cerebro.compliance_controls.explain` | One result from one immutable snapshot through a selected governed lens |
| `cerebro.compliance_work.list` | One bounded page from the canonical compliance and security work queue |

The maximum page size is 200. Tenant-scoped credentials cannot select another
tenant. Security, audit, platform, and leadership lenses retain the same field
suppression rules as HTTP reads. Resource reads expose the semantic model,
assurance decisions, snapshots, and work items through the same services.

MCP does not approve evidence, accept risk, change review state, execute
remediation, or close work.

## Compatibility

`complianceassessment.NewLegacyCompatibilityView` calls the existing shared
`LegacyStatus` precedence function and adds exact result, decision, and snapshot
IDs. Existing request-time GRC surfaces remain available. A caller can adopt the
canonical IDs without changing its existing status field in the same release.

No legacy route or field is removed by this contract.

## Rollout Gates

1. Merge and replay the assurance decision and canonical work projections before
   enabling snapshot reads.
2. Verify snapshot result, decision-set, and evidence-set digests before serving a
   lens, MCP read, or compatibility view.
3. Compare typed public event payloads with their source workflow envelopes in
   shadow delivery. A missing ID, digest, tenant, or event time blocks delivery.
4. Enable MCP reads for an internal tenant cohort. Monitor latency, tenant denials,
   invalid cursors, not-found responses, and snapshot verification conflicts.
5. Enable public event delivery only after duplicate delivery and replay tests use
   the existing event subscription idempotency contract.
6. Add Connect methods and generated SDK declarations before claiming transport
   equivalence for the new canonical resources.

## Rollback

- Disable the compliance MCP toolset and resource registration without changing
  stored assessment, decision, snapshot, or work records.
- Stop the public event adapter while retaining the canonical JetStream envelopes
  for later replay.
- Keep existing HTTP and legacy GRC reads enabled.
- Do not delete canonical events or mutate completed decisions and snapshots.
- If a snapshot commitment fails verification, return a conflict and stop serving
  that snapshot. Do not substitute current mutable state.

## Verification

```bash
go test ./internal/agentplatform ./internal/complianceassessment ./internal/mcpoperations ./internal/bootstrap
golangci-lint run --new-from-rev HEAD ./internal/agentplatform/... ./internal/complianceassessment/... ./internal/mcpoperations/... ./internal/bootstrap/...
make openapi-ts-check
```

The final command remains required whenever the OpenAPI contract changes. It must
pass before the snapshot and lens branch opens a pull request.
