# Reference Fabric And Deep-Link Compounding Plan

Status: implementation proposal

Issues: #1767, #1768, and #1769

Depends on: #1740, #1742, #1760, #1761, #1763, and #1765 where noted

## Outcome

Make every consequential Cerebro record a stable entry point into the exact
evidence, context, work, and outcome around it.

An authorized caller starting from a finding, evidence observation, graph fact,
control, report run, task, packet, proposal, execution, or external work item can
answer, without reconstructing routes or guessing tool order:

1. What is this object and which owner is authoritative for it?
2. Which evidence, source observation, and graph path support it?
3. Which finding, control, person, asset, rule, runtime, report, or work item is
   related?
4. Which exact revision or digest was cited in a delivered packet or approval?
5. What changed before and after a decision or action?
6. Which next action is allowed, blocked, expired, stale, or awaiting evidence?
7. Did the action resolve the exact finding, and did the fix last?
8. What did predicted risk reduction get right or wrong?

The target flow is:

```text
source observation
  -> graph fact / claim
  -> evidence observation and evaluation run
  -> finding and affected subjects
  -> control / policy / owner
  -> report candidate and decision packet receipt
  -> immutable action proposal
  -> approval receipt
  -> provider execution and reconciliation
  -> fresh verification
  -> outcome and finding episode
  -> recurrence / durability observation
  -> calibrated next plan
```

This is not a second graph, a fourth store, an unbounded traversal API, a new
workflow engine, or a replacement for existing domain services. It is one
resource-reference contract, a resolver over canonical owners, bounded governed
lenses, and derived read models for historical links and learning.

## Why This Is The Highest-Leverage Next Layer

Cerebro already computes most of the valuable joins. They are currently trapped
inside individual responses or repeated as untyped identifiers:

- MCP registers resource templates for findings, finding evidence, assets,
  graph facts, graph entities, source runtimes, and finding investigations.
- Findings carry runtime, rule, resource, control, ticket, evidence, event, and
  external-work references.
- Finding evidence preserves per-run observations, claims, source events, graph
  roots, graph paths, and rows.
- Evidence packets already assemble control posture, evidence lineage,
  evaluation runs, resources, findings, packet IDs, and review state.
- Risk-plan candidates already reference findings, rules, runtimes, resources,
  controls, predicted risk reduction, and model versions.
- Report runs, jobs, Ask queries, custom dashboards, questionnaire runs, and
  workflow decisions/actions/outcomes already have durable IDs.
- Graph impact reads already implement bounded breadth-first traversal with
  depth and result limits.
- Workflow projection already connects decisions, actions, outcomes, findings,
  evidence, tickets, and annotations.

The missing layer is deterministic navigation across those owners. Today:

- responses often emit naked ID arrays, object-specific `href` fields, or raw
  path strings;
- MCP prompts manually tell an agent which tools to call after reading a
  resource;
- source projection and workflow projection use overlapping but separately
  declared relation strings;
- a consumer cannot request canonical backlinks such as "which packets cited
  this evidence?" or "which verification closed this finding?";
- current-state and immutable-snapshot resources are not consistently
  distinguished;
- prediction, execution, verification, recurrence, and detector learning exist
  as disconnected records instead of a measurable episode.

Connecting those records increases the value of data Cerebro already collects.
Each new source observation can improve an investigation, packet, decision,
verification, recurrence analysis, benchmark, and future plan without copying
the observation into six new systems.

## Current Contract Inventory

| Current owner | Reusable behavior | Gap to close |
| --- | --- | --- |
| `internal/fabriccontract` | Closed, validated source-projection relation vocabulary. | Registry contains strings only. It does not define endpoint kinds, inverse relations, authority, lifecycle, provenance requirements, or traversal policy. Workflow-only relations are declared elsewhere. |
| `internal/ports.ProjectedEntity` and `ProjectedLink` | Tenant/source/runtime scoped normalized graph projection. | Links have endpoints, relation, and attributes but no first-class observation, validity, confidence, evidence, or authority contract. They remain projection records, not durable citations. |
| `internal/ports.EntityNeighborhood` and `internal/graphquery` | Bounded neighborhood and impact reads with depth/fan-out caps. | Nodes and relations are graph shapes, not cross-domain resource references. There is no named governed lens or historical revision contract. |
| `internal/bootstrap/mcp.go` | Seven useful `cerebro://` resource templates with per-resource authorization. | A manual URI switch routes each family, resource responses do not consistently emit follow-up links, and prompts prescribe tool sequences that the data should express. |
| findings and finding evidence | Stable finding identity, external refs, historical evidence observations, evaluation lineage, source events, graph roots, and paths. | Cross-object fields are mostly naked identifiers. There is no common self/reference/link response. |
| `internal/evidencepackets` | Rich control, resource, finding, evidence, packet, claim, run, path, readiness, review, and export joins. | Valuable lineage is embedded in a large packet response instead of independently addressable resources. Some packet-like routes are live views rather than immutable packets. |
| `internal/grccatalog` and custom dashboards | Bounded allowlisted sources, declared parameters, row limits, tenant-scoped visibility, layouts, widgets, filters, and schema versions. | No saved-lens contract names an entry resource, governed traversal recipe, default questions, or link policy. |
| risk plans and report runs | Persisted candidates, predicted deltas, references, model version, plan diff, and previous run linkage. | Prediction is not bound to the later proposal and verified outcome. Existing outcome adjustment is not measured calibration. |
| workflow events/projection | Durable or replayable decisions, actions, outcomes, tickets, notes, status changes, and useful relations. | Relation vocabulary is split from source fabric. Consumers cannot resolve one bounded canonical timeline across workflow and domain records. |
| graph-action workflow plan | Immutable proposal, approval, execution, reconciliation, verification, and finding closeout contract. | The records are not yet implemented. Links must remain absent rather than synthesized until the durable records land. |
| report runs, jobs, agent work, Ask queries | Durable IDs and partial parent/result references. | Accepted async work does not consistently return a canonical self link or typed input/output lineage. Synchronous attempts must not be presented as durable replayable work. |

## Non-Negotiable Boundaries

1. Existing domain stores remain authoritative. A finding link resolves the
   finding store; a report-run link resolves the report store; an approval link
   resolves the graph-action workflow store.
2. Neo4j is optional enrichment and a rebuildable projection. Graph loss may
   remove neighborhood context but cannot erase an approval, citation,
   execution, verification, or packet dependency.
3. JetStream remains the durable event log and Postgres remains the state store.
   This plan adds no fourth store.
4. A resource URI identifies a target; it does not authorize access to it.
   Resolution and every expansion reapply tenant and resource authorization.
5. An inaccessible target is not an existence oracle. Cross-tenant and
   unauthorized targets are indistinguishable from not found at the public
   boundary.
6. A link is not permission to mutate. Allowed actions are separately computed
   from authenticated scopes, record state, expected revision/digest, and policy.
7. Source-supplied URLs never become authenticated internal links. Provider
   links require an explicit provider policy and host validation.
8. All traversals are named or allowlisted and bounded by depth, fan-out, rows,
   response bytes, and time. No public free-form graph traversal is introduced.
9. Current views and immutable receipts use different kinds and routes. A
   current view cannot present a stable-looking packet ID.
10. Structural links may be derived. Historical claims such as "approved by",
    "cited by", "executed as", or "verified by" require durable evidence.
11. A broken or unavailable historical target remains visible as a typed gap to
    an authorized reader; the resolver never substitutes a newer record.
12. Existing response fields remain additive-compatible during migration.
13. Link ordering, canonical serialization, and digests are deterministic.
14. Provider success is not verification, finding closure, or realized benefit.
15. Learned ranking never crosses tenants by default and never treats a small or
    censored sample as proven effectiveness.

## Canonical Resource Contract

### Resource reference

Add a transport-neutral primitive in `proto/cerebro/v1/primitives.proto` and a
Go domain type in `internal/resourcelinks`:

```go
type ResourceRef struct {
    Kind       string            `json:"kind"`
    ID         string            `json:"id,omitempty"`
    URN        string            `json:"urn,omitempty"`
    Revision   string            `json:"revision,omitempty"`
    Digest     string            `json:"digest,omitempty"`
    Label      string            `json:"label,omitempty"`
    State      string            `json:"state,omitempty"`
    APIPath    string            `json:"api_path,omitempty"`
    MCPURI     string            `json:"mcp_uri,omitempty"`
    Attributes map[string]string `json:"attributes,omitempty"`
}
```

Rules:

- `Kind` comes from a closed registry.
- `ID` is the canonical domain ID. `URN` is used for graph-addressable entities.
- Immutable resources set `Revision`, `Digest`, or both.
- `APIPath` is relative. Absolute public URLs are derived only through the
  existing validated external-origin configuration, never request `Host`.
- `MCPURI` uses exactly one escaping pass and must round-trip through the shared
  parser.
- `State` is operator-facing: for example `current`, `immutable`, `superseded`,
  `archived`, `unavailable`, or `redacted`.
- Attributes are allowlisted by kind. They never contain evidence payloads,
  credentials, provider tokens, or arbitrary source fields.

Initial resource kinds:

```text
finding
finding_evidence
evaluation_run
source_event
source_runtime
graph_entity
graph_fact
graph_path
rule
control
evidence_packet
audit_packet
decision_packet
report_run
job
agent_task
ask_query
dashboard_lens
questionnaire_run
external_work
action_proposal
approval_receipt
action_execution
verification
workflow_outcome
finding_episode
remediation_campaign
```

Kinds whose canonical owner is not implemented remain reserved but unresolvable.
The resolver must not synthesize them from graph nodes.

### Resource link

```go
type ResourceLink struct {
    Rel          string      `json:"rel"`
    Target       ResourceRef `json:"target"`
    Authority    string      `json:"authority"`
    Direction    string      `json:"direction,omitempty"`
    ObservedAt   *time.Time  `json:"observed_at,omitempty"`
    ValidFrom    *time.Time  `json:"valid_from,omitempty"`
    ValidTo      *time.Time  `json:"valid_to,omitempty"`
    Completeness string      `json:"completeness,omitempty"`
    Confidence   *float64    `json:"confidence,omitempty"`
    ProviderHref string      `json:"provider_href,omitempty"`
}
```

`Authority` names the record that proves the relation, not the service that
serialized it. Examples: `finding_record`, `finding_evidence_observation`,
`packet_receipt`, `workflow_event`, `action_approval`, `verification_record`, or
`graph_projection`.

`Completeness` uses explicit states:

```text
complete
partial
unavailable
redacted
stale
unsupported
```

Do not expose a target ID inside an unavailable/redacted link if the caller is
not authorized to know that target exists.

### Link classes

Classify every relation:

| Class | Examples | Source | Durability requirement |
| --- | --- | --- | --- |
| Structural | finding `has_evidence`, evidence `observed_on` runtime, rule `evaluates` entity kind | Current canonical record or reviewed catalog | May be deterministically derived. |
| Projected context | entity `member_of` group, package `affected_by` vulnerability | Graph projection with evidence attributes | Optional; must disclose graph freshness/completeness. |
| Historical citation | packet `cites` evidence observation, decision `based_on` packet | Immutable receipt/event | Must be durable and revision-bound. |
| Workflow transition | proposal `approved_by` receipt, execution `verified_by` verification | Workflow record/event | Must be durable; cannot be reconstructed from current provider state. |
| External locator | finding `tracked_by` pull request or ticket | Canonical external-ref record plus source observation | Provider URL policy required. |
| Derived analytic | episode `recurred_as` episode, campaign `groups` finding | Rebuildable Postgres read model with source references | Must retain derivation version and input references. |

## Relation Registry

Extend `internal/fabriccontract` instead of creating another unrelated
vocabulary. Keep current constants compatible, then describe each relation:

```go
type RelationDefinition struct {
    Name                  string
    Inverse               string
    SourceKinds           []string
    TargetKinds           []string
    Class                 string
    DefaultDirection      string
    SafeToTraverse        bool
    RequiresEvidence      bool
    RequiresValidity      bool
    IncludeByDefault      bool
}
```

Move workflow relations currently duplicated in `internal/knowledge` and
`internal/workflowprojection` into this registry after compatibility tests:

```text
targets
based_on
executed_by
evaluates
tracked_by
annotated_with
```

Add the minimum cross-domain relations needed by the pilot:

```text
self
has_evidence / evidence_for
produced_by_run / produced
observed_on / observed
has_finding / finding_on
mapped_to_control / tested_by
planned_in / has_candidate
proposed_as / proposed_for
approved_by / approves
executed_as / execution_of
verified_by / verifies
closed_by / closed
recurred_as / recurrence_of
supersedes / superseded_by
cites / cited_by
tracked_by / tracks
provider_record
```

Do not model temporal workflow transitions as timeless graph edges without
observation identity. One stable action may have many reconciliation events;
relation derivation must preserve the distinction fixed by #1765.

## Resolver Architecture

### Package layout

```text
internal/resourcelinks/
  kinds.go             resource-kind registry
  relations.go         adapter over fabriccontract definitions
  reference.go         canonical references and serializers
  uri.go               MCP URI parse/build and escaping
  builder.go           deterministic additive link builders
  resolver.go          single-resource authorization and resolution
  expansion.go         bounded expansion and partial-result handling
  provider.go          allowlisted provider-locator policy
  errors.go            not found, unavailable, redacted, budget exhausted

internal/ports/
  resource_links.go    narrow resolver/reader interfaces

internal/bootstrap/
  resource_links.go    HTTP adapters and authorization
  mcp.go               delegate resource parsing/reads to shared resolver
```

Domain adapters live with or immediately beside canonical owners. The generic
resolver must not import every store implementation or parse arbitrary result
JSON to discover IDs.

```go
type Adapter interface {
    Kind() string
    Resolve(ctx context.Context, actor Actor, ref ResourceRef) (Resource, error)
    Links(ctx context.Context, actor Actor, resource Resource, opts LinkOptions) ([]ResourceLink, error)
}
```

### Read surfaces

First slice:

```text
GET /platform/resources/resolve?kind=finding&id={findingID}
GET /platform/resources/{kind}/{id}/links
```

After canonical adapters and budgets are proven:

```text
POST /platform/resources/expand
GET  /platform/resources/{kind}/{id}/timeline
GET  /platform/resources/{kind}/{id}/backlinks
POST /platform/resources/compare
```

`expand` accepts only registered lens IDs or relation allowlists:

```json
{
  "root": {"kind": "finding", "id": "finding-123"},
  "lens": "investigation",
  "depth": 2,
  "limits": {"resources": 100, "links": 250, "bytes": 262144}
}
```

The response reports budgets and partial states:

```json
{
  "root": {},
  "resources": [],
  "links": [],
  "completeness": "partial",
  "limits": {"depth": 2, "resources": 100, "links": 250},
  "truncation_reasons": ["resource_limit"],
  "unavailable_capabilities": ["graph"]
}
```

### MCP convergence

Keep existing resource URIs compatible. Replace the manual per-family read
switch incrementally with adapters backed by the same resolver.

Add templates only when their canonical reads exist:

```text
cerebro://rule/{rule_id}
cerebro://control/{framework}/{control_id}
cerebro://evidence-lineage/{evidence_id}
cerebro://report-run/{run_id}
cerebro://job/{job_id}
cerebro://dashboard/{dashboard_id}
cerebro://audit-packet/{packet_id}
cerebro://decision-packet/{packet_id}
cerebro://graph-action/proposal/{proposal_id}
cerebro://graph-action/execution/{execution_id}
cerebro://timeline/{kind}/{id_or_urn}
```

Every MCP resource response carries the same bounded `links` array as HTTP.
Prompts may recommend a lens, but correctness cannot depend on a prose sequence
of tool calls.

Read-only MCP resources may explain proposals, approvals, and executions. Do not
add an MCP execution shortcut around the typed graph-action workflow.

## Link Persistence And Backlinks

Do not persist every link.

### Derived structural links

Self, current finding-to-runtime, finding-to-rule, finding-to-control, and
similar links are built from the authorized canonical record. Storing them
again would create drift.

### Durable historical links

Packet citations, decision inputs, approval bindings, executions,
verifications, supersession, report lineage, and external-work observations
must survive changes to current state. Their canonical rows/events already need
to contain the target ID and revision/digest.

For efficient backlinks, build a rebuildable Postgres read index:

```text
tenant_id
source_kind
source_id
source_revision_or_digest
relation
target_kind
target_id_or_urn
target_revision_or_digest
authority_kind
authority_id
observed_at
retired_at
metadata_json
```

The index is populated from canonical Postgres records and durable events. It is
not written as an independent business fact and can be replayed. A write path
that creates a historical relation must commit the canonical relation-bearing
record and its outbox/event atomically where the owning contract requires it.

Backlink examples:

- Which packets cited this evidence observation?
- Which decisions used this packet digest?
- Which proposal did this approval authorize?
- Which provider execution resulted from this proposal?
- Which verification evaluated this execution?
- Which finding episode did that verification close?
- Which report predicted the result?
- Which dashboard lens references this governed scope?

## Correctness Gate: Immutable Packet Permalinks

Complete #1768 before representing the current GRC audit packet route as a
stable resource.

Current `buildGRCAuditPacket`:

```text
reads PathValue("packetID") into findingID
loads current finding and evidence
loads optional current graph neighborhood
sets packet ID to finding ID
sets generated time to now
```

Both read and export rebuild that live view. The same URL can therefore produce
different content while retaining the same apparent packet identity.

Separate the contracts:

```text
GET  /grc/findings/{findingID}/audit-preview  current, explicitly mutable view
POST /grc/audit-packets                      freeze an immutable receipt
GET  /grc/audit-packets/{packetID}           read exact receipt
GET  /grc/audit-packets/{packetID}/export    export exact receipt
```

The receipt records:

- packet ID, schema version, tenant, scope, generated time, and digest;
- finding ID, fingerprint, and status revision;
- exact evidence observation and evaluation-run IDs;
- graph fact/path IDs and an observation watermark, not a claim that the latest
  neighborhood is immutable evidence;
- control/framework/profile versions;
- source-runtime completeness and freshness state;
- review revision, delivery state, and supersession links;
- explicit historical gaps when a referenced record can no longer be expanded.

An immutable packet never substitutes current evidence for a missing cited
record. A new input produces a new packet revision/digest.

## Governed Lenses

A lens is a named, versioned, bounded traversal recipe over the same authorized
resource fabric. It is not a materialized graph, saved authorization decision,
or free-form query.

```go
type LensDefinition struct {
    ID               string
    Version          string
    RootKinds        []string
    Relations        []string
    MaxDepth         int
    MaxResources     int
    MaxLinks         int
    RequiredScopes   []string
    IncludeProvider  bool
    IncludeGraph     bool
    RedactionProfile string
}
```

Initial lenses:

| Lens | Root | Bounded result | Operator question |
| --- | --- | --- | --- |
| `investigation` | finding, entity, fact | evidence, observations, graph paths, runtime, related findings, owner, external work | Why does this exist and what is affected? |
| `evidence_lineage` | evidence, packet | evaluation run, claims, source events, graph facts/paths, runtime, cited packets | Why do we believe this and where did it come from? |
| `control_readiness` | control | mapped rules, open findings, resources, evidence, packets, source gaps, owners | What supports this control and what blocks review? |
| `change_blast_radius` | resource, proposal | modeled paths, findings, controls, applications, collateral warnings | What could change if this action is approved? |
| `verified_fix` | finding, execution | packet, proposal, approval, provider work, fresh verification, outcome, episode | What happened and was the finding actually fixed? |
| `identity_access` | person, identity, principal | identity assertions, access paths, applications, findings, stale/conflicting links | Which access belongs to this person and how certain is the join? |
| `audit_delivery` | audit packet | exact citations, review state, redactions, exports, supersession | What exactly was delivered? |
| `remediation_campaign` | campaign, finding | shared roots/paths, member findings, proposals, partial verification | Which symptoms can be handled together without merging lifecycles? |

### Saved lenses

Reuse custom-dashboard persistence and `grccatalog` rather than creating a new
dashboard engine. Dashboard schema v2 adds:

```json
{
  "lens_kind": "control_readiness",
  "entry_resource": {"kind": "control", "id": "SOC2:CC6.1"},
  "bindings": {"status": "open"},
  "default_question_ids": ["ask-query-123"],
  "link_policy": {"open_rows_in_context": true}
}
```

`GET /grc/dashboards/{dashboardID}/resolve` returns the authorized definition,
bounded catalog queries, and resource links. Dashboard visibility controls who
may read the definition; each resolved object is authorized independently.

Cloning preserves existing ownership behavior and resets visibility as required.
Unknown kinds, relations, sources, parameters, or tenant-invalid scope URNs are
rejected at write time.

## High-Value Compounding Products

The reference fabric is valuable on its own. The larger payoff comes from using
the same links to build products that improve as Cerebro observes more work.

### 1. Addressable evidence lineage

Add:

```text
GET /finding-evidence/{evidenceID}/lineage
cerebro://evidence-lineage/{evidence_id}
```

Resolve canonical Postgres evidence and observations first. Attach optional
graph facts/paths second. Each hop reports complete, partial, stale,
unavailable, or redacted state.

First slice: finding evidence -> observation run -> source events -> runtime ->
graph facts/paths -> cited packet.

### 2. Live control context

Add a control resource that joins the merged/versioned control catalog to mapped
rules, current findings, affected subjects, evidence observations, immutable
packets, source lanes, freshness gaps, and owners.

Counts must reconcile to emitted authorized references. Framework/version is
part of identity so overlapping control IDs cannot collide. Unmapped findings
appear as mapping gaps instead of disappearing.

### 3. Evidence-backed identity assertions

Current identity projection carries useful match type, confidence, quality,
scope, source event, and observation time. Promote identity equivalence into an
explicit assertion instead of letting `same_actor` imply certainty.

```text
assertion_id
left identity/person ref
right identity/person/principal ref
match method
confidence and quality
supporting source-event/evidence refs
counter-evidence refs
validity interval
state: proposed, confirmed, conflicted, retired
review actor/time when reviewed
```

Never authorize automated remediation through a low-confidence or conflicted
identity join. Handle reassigned email, shared mailboxes, renamed users, and two
active people claiming one identifier explicitly.

The first person dossier starts from a terminated Okta person and lists linked
GitHub/cloud principals, current access paths, findings, stale/conflicting
assertions, and source provenance.

### 4. Counterfactual remediation preview

Use existing risk-plan candidates and bounded graph paths to produce a read-only
overlay before approval:

- expected node/edge state changes;
- exact finding predicate expected to stop matching;
- affected access/attack paths;
- downstream controls and applications;
- collateral warnings and unsupported effects;
- links to every path and observation supporting the model.

The first slice is the certified Okta suspension binding from #1763. Label every
result `modeled`. Never mutate canonical or projected graph state. The same
proposal digest must produce the same preview.

### 5. Entity investigation timeline

Normalize observations across source events, finding evidence, workflow events,
provider reconciliation, and verification:

```text
HR termination observed
-> Okta account remains active
-> downstream access path observed
-> finding opened
-> packet created
-> action proposed and approved
-> provider reports completion
-> fresh Okta observation arrives
-> exact rule no longer matches
-> finding verified closed
-> 30-day durability observed or finding recurs
```

Order by observed time plus a stable tie-breaker. Preserve source clock semantics
and gaps. Absence is not evidence that an event did not occur.

### 6. Root-cause and remediation campaigns

Group related findings without merging or suppressing their canonical lifecycle:

```text
campaign_id and revision
candidate root URNs
member finding IDs
shared path IDs
control refs
confidence and reason codes
supporting and counter evidence
state
```

First slice: package/CVE findings that share a package or vulnerability URN and
bounded paths to affected assets. One patch campaign may verify only a subset;
each finding remains independently open or closed.

### 7. Durable report, job, and agent-work lineage

Accepted async work returns `Location` and a canonical self reference. Durable
records add typed input/output links, parent job/task/report, actor/trigger,
packet digest, resulting proposal/execution/verification, and
supersedes/compares-to relations.

Do not promote synchronous agent-task attempt metadata to durable replay. Link
only records that the durable job/task/report stores can resolve.

### 8. External work synchronization

Generalize existing finding external refs into a canonical locator:

```text
system
tenant-scoped connection/runtime
kind and external ID
canonical allowlisted URL
status, reason, owner
observed time and freshness
source event ID
```

Refresh state through a configured Source. Never fetch an arbitrary supplied URL
while resolving a resource. Treat provider titles and bodies as untrusted
display content.

First slice: one GitHub pull request linked to a finding, packet, proposal, and
verification, with explicit open/merged/closed/stale/inaccessible state.

## Closed-Loop Outcome Learning

Complete #1769 after the verified-fix records in #1763 exist. The purpose is to
replace name-based outcome heuristics with measured, revision-bound outcomes.

### Prediction receipt

Bind the risk-plan candidate used to create a proposal:

```go
type PredictionReceipt struct {
    ReportRunID              string
    CandidateID              string
    PlanModelVersion         string
    FindingRevisions         []FindingRevision
    PredictedRiskDelta       float64
    PredictedAttackPathDelta int
    Digest                   string
}
```

### Realized result

After fresh verification, derive:

```go
type RealizedResult struct {
    PredictionDigest       string
    VerificationID         string
    FindingsVerifiedClosed []string
    FindingsStillMatching  []string
    ActualRiskDelta         *float64
    ActualPathDelta         *int
    VerificationLatency    time.Duration
    PredictionError        *float64
    CensoredReason         string
}
```

An unavailable or incomplete graph may censor path delta without invalidating
exact-finding calibration. Stale or failed verification censors realized
benefit entirely.

### Resolution episodes and fix durability

Derive episodes from durable workflow/evaluation history, not only the mutable
finding row:

```text
open
verified_closed
durability_observing
durable_30d
durable_90d
recurred
indeterminate_source_unhealthy
```

A finding reopening under the same fingerprint creates a new episode linked by
`recurred_as`. Missed, truncated, quarantined, or failed source collections
prevent durability credit. Manual closure remains distinct from verified
closure.

### Remediation benchmarks

Aggregate only within a tenant by:

```text
rule
action
binding version
provider capability version
target kind
```

Measure:

- approval, submission, and verification latency;
- verified-resolution and verification-failure rate;
- reversal and ambiguous-submission rate;
- 30/90-day recurrence;
- collateral finding changes;
- sample size and uncertainty.

Expose benchmarks as explanations first. Ranking changes require minimum sample,
version separation, smoothing, and a feature gate. Report observed association,
not causal effectiveness, unless the strict binding and observation window
support that claim.

### Offline decision replay

Compile completed episodes into immutable evaluation cases:

- frozen packet/evidence references and hashes;
- historical analyst decision;
- proposed/approved action;
- verified or censored outcome;
- model, policy, rule, and binding versions.

Replay must use frozen inputs, panic-on-provider-call fakes, and structural
scoring. Initial measures: citation precision, freshness violations, action
agreement, unsafe executable-proposal rate, correct abstention, and confidence
calibration.

### Detector-learning suggestions

Project reviewed candidate decisions and verified episodes into existing finding
memory as suggestions, never direct rule edits:

```text
rule ID
learning type
supporting decision/finding/episode IDs
sample count
suggested fixture
candidate-run parameters
confidence
```

Require reviewed samples, tenant isolation, idempotent projection, and candidate
replay. Analyst text is untrusted. One rejection cannot suppress or rewrite a
detector.

## Verification-Demand-Driven Collection

Use the existing durable jobs surface to collect exactly the evidence required
by a pending verification:

1. translate the typed verification plan into required source/runtime/rule;
2. coalesce work by tenant, runtime, and freshness fence;
3. sync the source runtime;
4. require a successful checkpoint observed after provider acceptance;
5. evaluate the exact rule;
6. link evaluation run and evidence observation to the verification;
7. classify verified, failed, or indeterminate.

Suggested job identity:

```text
SubjectType = graph_action_verification
SubjectID   = execution_id
ResultRefs  = runtime, evaluation_run, evidence, verification
```

Duplicate provider callbacks enqueue one logical job. Runtime quarantine stops
repeated pressure. Missing or failed collection leaves verification
indeterminate rather than calling the remediation failed or successful.

## API And Compatibility Strategy

### Additive rollout

1. Add shared primitives and link builders with no public response changes.
2. Add optional `links` to finding and MCP investigation responses.
3. Add the resolver route behind a capability flag.
4. Add resource templates for already-authoritative control/rule reads.
5. Migrate one consumer at a time from naked IDs to links while retaining IDs.
6. Add immutable packet routes and rename the live preview.
7. Add historical backlink index only after canonical relation sources are
   enumerated and replay-tested.
8. Add saved lenses and higher-order products after authorization/fan-out
   telemetry is stable.

### Error semantics

Use typed states instead of collapsing partial context into 500:

| Condition | Public behavior |
| --- | --- |
| Root malformed | 400 with stable invalid-reference code. |
| Root unauthorized or absent | tenant-safe 404. |
| Optional target unauthorized | omit or return redacted gap only when existence is already authorized by the root receipt. |
| Canonical dependency unavailable | 503 with capability name for root; partial state for optional expansion. |
| Graph unavailable | return canonical links plus `unavailable_capabilities=[graph]`. |
| Budget exhausted | 200 partial result with truncation reasons and continuation when stable pagination exists. |
| Historical target deleted | return unavailable historical ref without substituting current data. |
| Provider URL rejected | omit provider href and emit provider-link policy status to authorized diagnostics. |

### Security tests

- cross-tenant root and every expansion edge;
- foreign target hidden behind an authorized root;
- malformed and double-encoded IDs/URNs;
- untrusted `Host`, forwarded headers, and provider URLs;
- credentials/query secrets/fragments in provider locators;
- private dashboard visibility before pagination;
- stale revision/digest removing allowed mutation links;
- graph partial/unavailable behavior;
- maximum depth/fan-out/bytes/time;
- redacted evidence and source events;
- replay equivalence and link ordering.

## Telemetry And Value Measurement

### Resolver health

```text
resource_resolve_total{kind,result}
resource_link_total{relation,authority,completeness}
resource_expand_duration_seconds{lens,result}
resource_expand_truncated_total{lens,reason}
resource_broken_link_total{kind,relation,reason}
resource_provider_link_rejected_total{system,reason}
```

Do not label metrics with tenant IDs, raw resource IDs, URNs, URLs, or evidence
values.

### Product value

- median calls from finding to evidence, owner, and next allowed action;
- percentage of supported resources with canonical self links;
- percentage of response ID references represented as typed links;
- time from finding open to reviewed decision;
- time from provider completion to fresh verification;
- packet citations resolving to the exact revision;
- recurring findings detected within the expected evaluation cadence;
- predicted-versus-realized risk error;
- verified fix, reversal, recurrence, and correct-abstention rates;
- investigation and audit exports completed without manual ID reconstruction.

### Guardrails

- p95 resolver latency by kind and lens;
- partial/truncated expansion rate;
- cross-tenant authorization denials without target disclosure;
- graph dependency rate for otherwise canonical reads;
- provider-link rejection rate;
- backlink replay drift;
- packet digest mismatch;
- source-unhealthy time incorrectly counted as fix durability: target zero.

## Implementation Sequence

### Phase 0: correctness and registry gates

Owner: platform contracts plus current domain owners.

- Complete #1768 route/identity separation before publishing audit packet links.
- Enumerate canonical owner, ID, revision, route, auth scope, and retention policy
  for each initial kind.
- Extend `fabriccontract` with relation definitions and unify workflow strings.
- Define URI grammar, escaping, deterministic ordering, and provider URL policy.
- Add cross-tenant and partial-capability contract fixtures.

Exit gate: no initial kind lacks a named canonical owner or authorization path.

### Phase 1: finding reference vertical

Owner: findings plus bootstrap/MCP.

- Implement `internal/resourcelinks` primitives and finding adapter.
- Add additive links to finding read and investigation resource.
- Add control/rule resource templates using existing authoritative catalogs.
- Prove HTTP/MCP parity and graph-independent link construction.

Exit gate: one finding can navigate to authorized evidence, runtime, rule,
controls, resources, investigation, and existing external work.

### Phase 2: evidence lineage and immutable packets

Owner: finding evidence, evidence packets, GRC control, decision packet.

- Add evidence-lineage resource.
- Persist immutable audit packet receipts and exact exports.
- Add decision packet references after #1742 implementation.
- Build citations/backlinks from durable receipt inputs.

Exit gate: a delivered packet remains stable after current state changes and
every citation resolves or shows an explicit historical gap.

### Phase 3: workflow timeline and verified fix

Owner: graph-action workflow and workflow events.

- Complete #1760, #1761, #1763, and #1765 prerequisites.
- Add proposal, approval, execution, verification, and outcome adapters.
- Add finding workflow timeline and allowed-action references.
- Orchestrate verification-demand-driven collection through durable jobs.

Exit gate: the Okta pilot is traversable from finding to fresh verification with
no inferred approval or provider-success shortcut.

### Phase 4: governed lenses and identity context

Owner: graph query, GRC catalog/dashboards, identity projection.

- Register bounded lenses and budgets.
- Add custom-dashboard schema v2 saved lenses.
- Add identity assertions and person dossier.
- Add counterfactual preview and entity timeline.

Exit gate: operator views reuse one fabric and disclose confidence, provenance,
partial data, and authorization boundaries.

### Phase 5: compounding outcomes

Owner: risk plan, reports, findings, remediation analytics.

- Implement prediction receipts and realized results.
- Derive resolution episodes, recurrence, and durability.
- Expose read-only benchmarks.
- Build offline decision replay and detector-learning suggestions.
- Add campaigns and portfolio planning only after calibration is measurable.

Exit gate: planning can explain measured historical performance without using
cross-tenant data, provider success as verification, or censored observations as
failures.

## PR Slices

Keep implementation reviewable and independently testable:

1. **Resource primitives and registry**: kinds, relations, URI grammar, builders,
   deterministic tests; no public API.
2. **Finding links**: additive links on HTTP and MCP finding/investigation reads.
3. **Control and rule resources**: authoritative reads and MCP templates.
4. **Evidence-lineage resource**: canonical history plus optional graph context.
5. **Immutable audit packet receipts**: fix #1768 and separate live preview.
6. **Historical backlink projection**: receipt/workflow sources and replay tests.
7. **Workflow resolver**: packet-to-proposal-to-verification after action records
   land.
8. **Verification coordinator**: durable job orchestration and fresh exact-rule
   evaluation.
9. **Governed lens registry**: investigation, control readiness, and verified fix.
10. **Saved lens schema v2**: custom dashboard and catalog integration.
11. **Identity assertions and dossier**: confidence/conflict/validity contract.
12. **Prediction and realized result**: Okta pilot calibration.
13. **Finding episodes and recurrence**: durable derived projection.
14. **Benchmarks and offline replay**: read-only explanation before ranking.
15. **Campaigns and detector suggestions**: explainable grouping and reviewed
    candidate learning.

Each PR must name:

- canonical owners touched;
- relation definitions added;
- authorization behavior;
- budgets and partial-result behavior;
- replay/durability impact;
- migration/compatibility impact;
- exact validation commands and fixtures.

## Validation Matrix

| Layer | Required validation |
| --- | --- |
| Resource primitives | deterministic serialization, URI round-trip, single escaping, relation registry validation, stable sorting |
| Authorization | root and per-expansion cross-tenant tests, existence-oracle tests, private lens visibility |
| HTTP/Connect/OpenAPI | generated contract parity, additive compatibility, typed errors, relative path correctness |
| MCP | resource-template listing, HTTP/MCP parity, byte/depth limits, partial expansion, no mutation shortcut |
| Provider links | scheme/host allowlists, enterprise origin, credential/query stripping, no arbitrary fetch |
| Graph | bounded fan-out/depth, graph unavailable/partial, no graph authority for historical links |
| Packets | deterministic digest, post-creation mutation stability, exact export, missing historical refs |
| Workflow | replay idempotency, event identity, revision/digest gates, provider success not closure |
| Verification | post-provider freshness fence, truncated/failed collection, exact rule/fingerprint, duplicate callbacks |
| Learning | tenant/version separation, censored data, minimum samples, recurrence under source gaps, panic-on-provider replay |
| Docs/repo | `make docs-drift-check`, `make oss-audit`, relevant contract/codegen checks per slice |

## Decisions Required Before Code

1. Confirm whether `ResourceRef.ID` may contain provider-native composite IDs or
   whether those must always be URNs.
2. Ratify the initial kind and relation registry; additions become public
   compatibility commitments.
3. Choose the public live-audit-preview route used while #1768 migrates the
   existing route.
4. Confirm which historical link sources already have durable rows/events and
   which must wait for #1740/#1760 implementation.
5. Set default expansion budgets and maximum server-enforced ceilings.
6. Choose whether the first resolver API is platform-wide or exposed only as
   additive links until two domain adapters are proven.
7. Define the minimum sample and uncertainty method before measured remediation
   outcomes may affect ranking.

## Definition Of Done

The reference fabric is complete enough for general adoption when:

- a finding, evidence observation, control, report run, packet, proposal,
  execution, verification, and outcome each have a canonical reference;
- HTTP and MCP serialize the same relations;
- immutable citations survive changes to current state;
- callers can request bounded investigation, control-readiness, and verified-fix
  lenses;
- authorization is applied to every target without leaking existence;
- graph loss degrades enrichment but not canonical workflow history;
- provider links are policy-generated and safe;
- one end-to-end verified fix produces a measurable resolution episode;
- the next risk plan can compare its prediction with the verified result;
- recurrence is distinguished from source-health gaps;
- and operators no longer reconstruct the decision chain from unrelated IDs.
